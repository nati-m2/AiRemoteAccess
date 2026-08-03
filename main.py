import os
import re
import sys
import json
import time
import queue
import ctypes
import shutil
import socket
import getpass
import secrets
import platform
import threading
import subprocess
import http.server
import urllib.request
from enum import Enum

import argparse

try:
    import tkinter as tk
    from tkinter import ttk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

DEFAULT_PORT = 8999
DEFAULT_CMD_TIMEOUT = 30
MAX_BODY_SIZE = 1 * 1024 * 1024
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

def enable_dpi_awareness():
    '''Make the process DPI-aware on Windows so Tkinter renders crisp, unscaled text.'''
    if os.name != 'nt':
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def get_dpi_scaling_factor():
    '''Return the display scaling factor (1.0 = 100%) for Tk scaling adjustment.'''
    if os.name != 'nt':
        return 1.0
    try:
        hdc = ctypes.windll.user32.GetDC(0)
        dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # LOGPIXELSX
        ctypes.windll.user32.ReleaseDC(0, hdc)
        return dpi / 96.0
    except Exception:
        return 1.0


def _temp_dir():
    if os.name == 'nt':
        return os.environ.get('TEMP', os.path.expanduser('~'))
    return os.environ.get('TMPDIR', '/tmp')


def _cf_download_url():
    if os.name == 'nt':
        return 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe'
    arch = platform.machine().lower()
    if arch in ('aarch64', 'arm64'):
        return 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64'
    return 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64'


TEMP_DIR = _temp_dir()
CF_DOWNLOAD_URL = _cf_download_url()
CF_EXE = os.path.join(TEMP_DIR, 'cloudflared.exe' if os.name == 'nt' else 'cloudflared')
TUNNEL_LOG_FILE = os.path.join(TEMP_DIR, 'hermes_tunnel.log')
AUDIT_LOG_FILE = os.path.join(os.getcwd(), 'hermes_audit.log')


class ConnectionMode(Enum):
    LOCAL = 'local'
    CLOUDFLARE = 'cloudflare'


MODE_LABELS = {
    ConnectionMode.LOCAL: 'Local',
    ConnectionMode.CLOUDFLARE: 'Cloudflare Tunnel',
}


class AppState:
    '''Shared runtime state between the HTTP handler, tunnel threads and UI.'''
    def __init__(self):
        self.port = DEFAULT_PORT
        self.token = secrets.token_hex(16)
        self.mode = ConnectionMode.CLOUDFLARE
        self.listen_host = '127.0.0.1'
        self.running = False
        self.cmd_timeout = DEFAULT_CMD_TIMEOUT
        self.server = None
        self.tunnel_proc = None
        self.tunnel_log_fd = None
        self.public_url = None
        self.current_user = getpass.getuser()
        self.command_queue = queue.Queue()
        self.status_queue = queue.Queue()
        self._failed_attempts = {}
        self._lockouts = {}
        self._lockout_level = {}
        self._audit_lock = threading.Lock()
        self._state_lock = threading.Lock()

    def audit_log(self, ip, cmd, status, exit_code=None):
        entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'ip': ip,
            'command': cmd,
            'status': status,
            'exit_code': exit_code,
            'user': self.current_user,
        }
        with self._audit_lock:
            try:
                with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
            except Exception:
                pass
        self.command_queue.put(entry)


def ensure_cloudflared():
    '''Download the cloudflared binary if it is not already present.'''
    if os.path.exists(CF_EXE):
        return
    print('Downloading cloudflared binary...')
    try:
        urllib.request.urlretrieve(CF_DOWNLOAD_URL, CF_EXE)
    except Exception as e:
        raise RuntimeError(f'Could not download cloudflared: {e}')
    if os.name != 'nt':
        os.chmod(CF_EXE, 0o755)


def get_local_ips():
    '''Return a list of local IPv4 addresses for LAN mode.'''
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(('8.8.8.8', 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        for addr in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM):
            ip = addr[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def copy_to_clipboard(text):
    '''Copy text to the clipboard using OS-native tools.'''
    try:
        if os.name == 'nt':
            subprocess.run('clip', input=text.encode('utf-16-le'), shell=True, check=True)
        elif sys.platform == 'darwin':
            subprocess.run('pbcopy', input=text.encode('utf-8'), shell=True, check=True)
        else:
            subprocess.run('xclip -selection clipboard', input=text.encode('utf-8'), shell=True, check=True)
    except Exception:
        pass


def kill_orphaned_cloudflared(tracked_pid):
    '''Kill any orphaned cloudflared processes.'''
    try:
        if os.name == 'nt':
            out = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq cloudflared.exe', '/FO', 'CSV', '/NH'],
                capture_output=True, text=True
            ).stdout
            for line in out.splitlines():
                parts = [p.strip('"') for p in line.split(',')]
                if len(parts) >= 2 and parts[1].isdigit():
                    pid = int(parts[1])
                    if pid != tracked_pid:
                        subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
        else:
            out = subprocess.run(['pgrep', '-f', 'cloudflared'], capture_output=True, text=True).stdout
            for line in out.splitlines():
                pid = int(line.strip())
                if pid != tracked_pid:
                    subprocess.run(['kill', '-9', str(pid)], capture_output=True)
    except Exception:
        pass


def make_handler(state):
    '''Create a RemoteHandler class bound to an AppState instance.'''
    return type('BoundHandler', (RemoteHandler,), {'state': state})


class RemoteHandler(http.server.BaseHTTPRequestHandler):
    '''HTTP request handler for remote command execution.'''
    state = None

    def _is_locked_out(self, ip):
        with self.state._state_lock:
            lockout_until = self.state._lockouts.get(ip)
            if lockout_until and time.time() < lockout_until:
                return True
            if lockout_until:
                self.state._lockouts.pop(ip, None)
                self.state._failed_attempts.pop(ip, None)
            return False

    def _register_failed_attempt(self, ip):
        with self.state._state_lock:
            count, first_ts = self.state._failed_attempts.get(ip, (0, time.time()))
            count += 1
            self.state._failed_attempts[ip] = (count, first_ts)
            if count >= MAX_FAILED_ATTEMPTS:
                level = self.state._lockout_level.get(ip, 0)
                duration = LOCKOUT_SECONDS * (2 ** level)
                self.state._lockouts[ip] = time.time() + duration
                self.state._lockout_level[ip] = level + 1
                self.state._failed_attempts.pop(ip, None)

    def _send_json(self, status, payload):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload, ensure_ascii=False).encode('utf-8'))

    def _check_auth(self):
        ip = self.client_address[0]
        if self._is_locked_out(ip):
            self._send_json(429, {'error': 'Too many failed attempts'})
            return False
        auth = self.headers.get('Authorization', '')
        if not secrets.compare_digest(auth, f'Bearer {self.state.token}'):
            self._register_failed_attempt(ip)
            self._send_json(403, {'error': 'Forbidden'})
            return False
        return True

    def do_GET(self):
        if not self._check_auth():
            return
        if self.path in ('/', '/info'):
            info = {
                'user': self.state.current_user,
                'port': self.state.port,
            }
            self._send_json(200, info)
            return
        self._send_json(404, {'error': 'Not found'})

    def do_POST(self):
        if not self._check_auth():
            return
        ip = self.client_address[0]
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length > MAX_BODY_SIZE:
                self._send_json(413, {'error': 'Request body too large'})
                return
            raw = self.rfile.read(length).decode('utf-8')
            data = json.loads(raw)
            cmd = data.get('command')
            if not cmd or not isinstance(cmd, str):
                self._send_json(400, {'error': 'Missing or invalid command'})
                return
        except Exception as e:
            self._send_json(400, {'error': f'Bad request: {e}'})
            return

        self.state.command_queue.put({
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'ip': ip,
            'command': cmd,
            'status': 'started',
            'exit_code': None,
        })

        try:
            res = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=self.state.cmd_timeout,
            )
            payload = {'stdout': res.stdout, 'stderr': res.stderr, 'exit_code': res.returncode}
            self.state.audit_log(ip, cmd, 'executed', res.returncode)
            self._send_json(200, payload)
        except subprocess.TimeoutExpired:
            self.state.audit_log(ip, cmd, 'timeout')
            self._send_json(408, {'error': f'Command timed out after {self.state.cmd_timeout}s'})
        except Exception as e:
            self.state.audit_log(ip, cmd, f'error: {e}')
            self._send_json(400, {'error': str(e)})

    def log_message(self, format, *args):
        pass


def start_http_server(state):
    '''Start the local HTTP server in a background thread.'''
    try:
        handler = make_handler(state)
        state.server = http.server.ThreadingHTTPServer((state.listen_host, state.port), handler)
        threading.Thread(target=state.server.serve_forever, daemon=True).start()
    except Exception as e:
        raise RuntimeError(f'Failed to start local server: {e}')
    state.status_queue.put({'type': 'status', 'message': f'Local server started on {state.listen_host}:{state.port}'})


def stop_http_server(state):
    '''Stop the local HTTP server if it is running.'''
    if state.server:
        try:
            state.server.shutdown()
            state.server.server_close()
        except Exception:
            pass
        state.server = None


def start_cloudflare_tunnel(state):
    '''Start a Cloudflare Quick Tunnel and return the public URL.'''
    ensure_cloudflared()
    state.tunnel_log_fd = open(TUNNEL_LOG_FILE, 'w', encoding='utf-8')
    try:
        state.tunnel_proc = subprocess.Popen(
            [CF_EXE, 'tunnel', '--url', f'http://127.0.0.1:{state.port}'],
            stdout=state.tunnel_log_fd,
            stderr=state.tunnel_log_fd,
        )
    except Exception as e:
        state.tunnel_log_fd.close()
        raise RuntimeError(f'Could not start cloudflared: {e}')
    url = None
    for _ in range(30):
        time.sleep(1)
        if os.path.exists(TUNNEL_LOG_FILE):
            try:
                with open(TUNNEL_LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    match = re.search(r'https://[-0-9a-z]+\.trycloudflare\.com', content)
                    if match:
                        url = match.group(0)
                        break
            except Exception:
                pass
        if state.tunnel_proc.poll() is not None:
            break
    if not url:
        raise RuntimeError('Failed to resolve Cloudflare Tunnel URL.')
    return url


def stop_tunnel(state):
    '''Stop the active tunnel process and clean up.'''
    proc = state.tunnel_proc
    if proc:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception:
            pass
        state.tunnel_proc = None
        if state.mode == ConnectionMode.CLOUDFLARE:
            try:
                kill_orphaned_cloudflared(proc.pid)
            except Exception:
                pass
    if state.tunnel_log_fd:
        try:
            state.tunnel_log_fd.close()
        except Exception:
            pass
        state.tunnel_log_fd = None
    if os.path.exists(TUNNEL_LOG_FILE):
        try:
            os.remove(TUNNEL_LOG_FILE)
        except Exception:
            pass


def start_connection(state, options):
    '''Start the HTTP server and the selected tunnel in a worker thread.'''
    try:
        state.mode = options['mode']
        state.port = int(options['port'])
        state.token = options['token'] or secrets.token_hex(16)
        state.cmd_timeout = int(options['timeout'])
        if state.mode == ConnectionMode.LOCAL:
            state.listen_host = '0.0.0.0'
        else:
            state.listen_host = '127.0.0.1'
        state.running = True
        start_http_server(state)
        time.sleep(0.5)
        if state.mode == ConnectionMode.LOCAL:
            ips = get_local_ips()
            urls = [f'http://{ip}:{state.port}' for ip in ips]
            state.public_url = urls[0] if urls else f'http://127.0.0.1:{state.port}'
        elif state.mode == ConnectionMode.CLOUDFLARE:
            state.public_url = start_cloudflare_tunnel(state)
        state.status_queue.put({
            'type': 'ready',
            'url': state.public_url,
            'token': state.token,
            'mode': MODE_LABELS.get(state.mode, state.mode.value),
        })
    except Exception as e:
        state.running = False
        stop_http_server(state)
        stop_tunnel(state)
        state.status_queue.put({'type': 'error', 'message': str(e)})


def stop_connection(state):
    '''Stop the HTTP server and tunnel.'''
    state.running = False
    stop_http_server(state)
    stop_tunnel(state)
    state.public_url = None
    state.status_queue.put({'type': 'stopped'})


class HermesUI:
    '''Modern Tkinter control panel for Hermes Remote Access.'''

    # Color palette for the dark, modern theme
    BG = '#161a23'
    BG_CARD = '#1f2430'
    BG_INPUT = '#262c3a'
    FG = '#e6e9f0'
    FG_MUTED = '#8b93a7'
    ACCENT = '#5b8cff'
    ACCENT_ACTIVE = '#7aa2ff'
    DANGER = '#e05561'
    DANGER_ACTIVE = '#ea7b84'
    SUCCESS = '#3ecf8e'
    BORDER = '#2b3243'

    def __init__(self, root, state):
        self.root = root
        self.state = state
        self.root.title('Ai Remote Access')
        self.root.geometry('800x740')
        self.root.minsize(560, 560)
        self.root.configure(bg=self.BG)
        self.root.protocol('WM_DELETE_WINDOW', self._on_close)

        self.mode_var = tk.StringVar(value=MODE_LABELS[ConnectionMode.LOCAL])
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        self.token_var = tk.StringVar(value=state.token)
        self.timeout_var = tk.StringVar(value=str(DEFAULT_CMD_TIMEOUT))

        self.url_var = tk.StringVar()
        self.token_info_var = tk.StringVar()
        self.status_var = tk.StringVar(value='Ready')
        self.status_dot_var = tk.StringVar(value='●')

        self._setup_style()
        self._build_ui()
        self._poll_queues()

    def _setup_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use('clam')
        except Exception:
            pass

        style.configure('.', background=self.BG, foreground=self.FG, font=('Segoe UI', 10))
        style.configure('TFrame', background=self.BG)
        style.configure('Card.TFrame', background=self.BG_CARD)
        style.configure('TLabel', background=self.BG, foreground=self.FG)
        style.configure('Card.TLabel', background=self.BG_CARD, foreground=self.FG)
        style.configure('Muted.TLabel', background=self.BG, foreground=self.FG_MUTED, font=('Segoe UI', 9))
        style.configure('CardMuted.TLabel', background=self.BG_CARD, foreground=self.FG_MUTED, font=('Segoe UI', 9))
        style.configure('Title.TLabel', background=self.BG, foreground=self.FG, font=('Segoe UI', 16, 'bold'))
        style.configure('Section.TLabel', background=self.BG, foreground=self.FG, font=('Segoe UI', 11, 'bold'))
        style.configure('StatusDot.TLabel', background=self.BG, font=('Segoe UI', 12))

        style.configure('TEntry', fieldbackground=self.BG_INPUT, foreground=self.FG,
                        insertcolor=self.FG, bordercolor=self.BORDER, lightcolor=self.BORDER,
                        darkcolor=self.BORDER, padding=6)
        style.map('TEntry', fieldbackground=[('readonly', self.BG_INPUT)], foreground=[('readonly', self.FG)])

        style.configure('TRadiobutton', background=self.BG, foreground=self.FG, font=('Segoe UI', 10))
        style.map('TRadiobutton', background=[('active', self.BG)], foreground=[('active', self.ACCENT)])

        style.configure('Accent.TButton', background=self.ACCENT, foreground='#ffffff',
                        font=('Segoe UI', 10, 'bold'), padding=(14, 8), borderwidth=0)
        style.map('Accent.TButton',
                  background=[('active', self.ACCENT_ACTIVE), ('disabled', '#3a4152')],
                  foreground=[('disabled', self.FG_MUTED)])

        style.configure('Danger.TButton', background=self.DANGER, foreground='#ffffff',
                        font=('Segoe UI', 10, 'bold'), padding=(14, 8), borderwidth=0)
        style.map('Danger.TButton',
                  background=[('active', self.DANGER_ACTIVE), ('disabled', '#3a4152')],
                  foreground=[('disabled', self.FG_MUTED)])

        style.configure('Ghost.TButton', background=self.BG_CARD, foreground=self.FG,
                        font=('Segoe UI', 9), padding=(10, 6), borderwidth=1)
        style.map('Ghost.TButton', background=[('active', self.BORDER)])

    def _build_ui(self):
        pad = {'padx': 8, 'pady': 6}

        outer = ttk.Frame(self.root, padding='20', style='TFrame')
        outer.pack(fill=tk.BOTH, expand=True)
        outer.columnconfigure(0, weight=1)

        # Header
        header = ttk.Frame(outer, style='TFrame')
        header.grid(row=0, column=0, sticky='ew', pady=(0, 16))
        ttk.Label(header, text='🛰  Ai Remote Access', style='Title.TLabel').pack(side=tk.LEFT)

        # Settings card
        settings = ttk.Frame(outer, style='Card.TFrame', padding=16)
        settings.grid(row=1, column=0, sticky='ew')
        settings.columnconfigure(1, weight=1)
        outer.rowconfigure(1, weight=0)

        ttk.Label(settings, text='Connection Settings', style='Section.TLabel', background=self.BG_CARD).grid(
            row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))

        ttk.Label(settings, text='Mode', style='Card.TLabel').grid(row=1, column=0, sticky=tk.W, **pad)
        mode_frame = ttk.Frame(settings, style='Card.TFrame')
        mode_frame.grid(row=1, column=1, columnspan=2, sticky=tk.W, **pad)
        for mode, label in MODE_LABELS.items():
            ttk.Radiobutton(mode_frame, text=label, variable=self.mode_var, value=label).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(settings, text='Port', style='Card.TLabel').grid(row=2, column=0, sticky=tk.W, **pad)
        ttk.Entry(settings, textvariable=self.port_var, width=10).grid(row=2, column=1, sticky=tk.W, **pad)

        ttk.Label(settings, text='Token', style='Card.TLabel').grid(row=3, column=0, sticky=tk.W, **pad)
        ttk.Entry(settings, textvariable=self.token_var).grid(row=3, column=1, sticky='ew', **pad)
        ttk.Button(settings, text='Regenerate', style='Ghost.TButton', command=self._regenerate_token).grid(
            row=3, column=2, sticky=tk.W, **pad)

        ttk.Label(settings, text='Timeout (s)', style='Card.TLabel').grid(row=4, column=0, sticky=tk.W, **pad)
        ttk.Entry(settings, textvariable=self.timeout_var, width=10).grid(row=4, column=1, sticky=tk.W, **pad)

        # Action buttons
        btn_frame = ttk.Frame(outer, style='TFrame')
        btn_frame.grid(row=2, column=0, sticky='ew', pady=(16, 16))
        self.start_btn = ttk.Button(btn_frame, text='▶  Start', style='Accent.TButton', command=self._on_start)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.stop_btn = ttk.Button(btn_frame, text='■  Stop', style='Danger.TButton', command=self._on_stop, state='disabled')
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_frame, text='⧉  Copy Details', style='Ghost.TButton', command=self._copy_details).pack(side=tk.LEFT)

        # Connection info card
        info = ttk.Frame(outer, style='Card.TFrame', padding=16)
        info.grid(row=3, column=0, sticky='nsew')
        info.columnconfigure(1, weight=1)
        outer.rowconfigure(3, weight=1)

        ttk.Label(info, text='Connection Info', style='Section.TLabel', background=self.BG_CARD).grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))

        ttk.Label(info, text='URL', style='Card.TLabel').grid(row=1, column=0, sticky=tk.W, **pad)
        ttk.Entry(info, textvariable=self.url_var, state='readonly').grid(row=1, column=1, sticky='ew', **pad)

        ttk.Label(info, text='Token', style='Card.TLabel').grid(row=2, column=0, sticky=tk.W, **pad)
        ttk.Entry(info, textvariable=self.token_info_var, state='readonly').grid(row=2, column=1, sticky='ew', **pad)

        status_row = ttk.Frame(info, style='Card.TFrame')
        status_row.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))
        self.status_dot = ttk.Label(status_row, textvariable=self.status_dot_var, style='StatusDot.TLabel',
                                    background=self.BG_CARD, foreground=self.FG_MUTED)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 6))
        ttk.Label(status_row, textvariable=self.status_var, style='Card.TLabel').pack(side=tk.LEFT)

    def _set_status(self, text, color=None):
        self.status_var.set(text)
        if color:
            self.status_dot.configure(foreground=color)

    def _regenerate_token(self):
        self.token_var.set(secrets.token_hex(16))

    def _collect_options(self):
        mode = {v: k for k, v in MODE_LABELS.items()}[self.mode_var.get()]
        port = int(self.port_var.get())
        if not (1 <= port <= 65535):
            raise ValueError('Port must be between 1 and 65535')
        timeout = int(self.timeout_var.get())
        if timeout < 1:
            raise ValueError('Timeout must be positive')
        return {
            'mode': mode,
            'port': port,
            'token': self.token_var.get().strip(),
            'timeout': timeout,
        }

    def _on_start(self):
        if self.state.running:
            return
        self._regenerate_token()
        try:
            options = self._collect_options()
        except ValueError as e:
            print(f'Error: {e}')
            self._set_status(f'Error: {e}', self.DANGER)
            return
        self.start_btn.config(state='disabled')
        self._set_status('Starting connection...', self.FG_MUTED)
        threading.Thread(target=start_connection, args=(self.state, options), daemon=True).start()

    def _on_stop(self):
        if not self.state.running:
            return
        self.stop_btn.config(state='disabled')
        self._set_status('Stopping connection...', self.FG_MUTED)
        threading.Thread(target=stop_connection, args=(self.state,), daemon=True).start()

    def _copy_details(self):
        url = self.url_var.get()
        token = self.token_info_var.get()
        if not url:
            return
        text = f'URL: {url}\nToken: {token}\n'
        copy_to_clipboard(text)
        self._set_status('Copied to clipboard', self.SUCCESS)

    def _poll_queues(self):
        try:
            while True:
                msg = self.state.status_queue.get_nowait()
                self._handle_status(msg)
        except queue.Empty:
            pass
        self.root.after(250, self._poll_queues)

    def _handle_status(self, msg):
        mtype = msg.get('type')
        if mtype == 'status':
            self._set_status(msg.get('message', ''), self.FG_MUTED)
        elif mtype == 'ready':
            self.url_var.set(msg.get('url', ''))
            self.token_info_var.set(msg.get('token', ''))
            self._set_status(f"{msg.get('mode', '')} active", self.SUCCESS)
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
        elif mtype == 'error':
            self._set_status('Error: ' + str(msg.get('message', '')), self.DANGER)
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
        elif mtype == 'stopped':
            self.url_var.set('')
            self.token_info_var.set('')
            self._set_status('Ready', self.FG_MUTED)
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')

    def _on_close(self):
        if self.state.running:
            self._on_stop()
            self.root.after(800, self.root.destroy)
        else:
            self.root.destroy()


def _is_console_build():
    '''True when running as the frozen console-only executable (name contains 'console').'''
    if not getattr(sys, 'frozen', False):
        return False
    exe_name = os.path.basename(sys.executable)
    return 'console' in exe_name.lower()


def build_parser():
    parser = argparse.ArgumentParser(description='Hermes Remote Access')
    parser.add_argument('--mode', choices=[ConnectionMode.LOCAL.value, ConnectionMode.CLOUDFLARE.value],
                        default=ConnectionMode.LOCAL.value, help='Connection mode')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Local HTTP port')
    parser.add_argument('--token', default='', help='Bearer token (random if empty)')
    parser.add_argument('--timeout', type=int, default=DEFAULT_CMD_TIMEOUT, help='Command timeout in seconds')
    parser.add_argument('--no-gui', action='store_true', help='Run in terminal mode')
    return parser


def cli_main(options):
    '''Run Hermes from the terminal without a GUI.'''
    state = AppState()
    print('\U0001F680 Starting Satellite Server...')
    print('\u23F3 Waiting for Tunnel URL...' if options['mode'] == ConnectionMode.CLOUDFLARE else '\u23F3 Starting local server...')
    threading.Thread(target=start_connection, args=(state, options), daemon=True).start()
    url_printed = False
    try:
        while state.running or state.tunnel_proc is not None:
            time.sleep(0.25)
            try:
                while True:
                    msg = state.status_queue.get_nowait()
                    if msg.get('type') == 'ready' and not url_printed:
                        url = msg.get('url')
                        token = msg.get('token')
                        separator = '=' * 44
                        print()
                        print(separator)
                        print('\u2705 REMOTE ACCESS READY')
                        print(f'\U0001F517 URL: {url}')
                        print(f'\U0001F511 TOKEN: {token}')
                        print(separator)
                        print()
                        copy_to_clipboard(f'URL: {url}\nToken: {token}\n')
                        print('\U0001F4CB Copied URL & TOKEN to clipboard.')
                        print('Ctrl+C to stop and clean up.')
                        url_printed = True
                    elif msg.get('type') == 'error':
                        print(f"Error: {msg.get('message')}")
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        stop_connection(state)


def main():
    parser = build_parser()
    args = parser.parse_args()
    mode = ConnectionMode(args.mode)
    options = {
        'mode': mode,
        'port': args.port,
        'token': args.token,
        'timeout': args.timeout,
    }

    if args.no_gui or not TKINTER_AVAILABLE or _is_console_build():
        cli_main(options)
        return

    state = AppState()
    state.mode = mode
    state.port = options['port']
    state.token = options['token'] or secrets.token_hex(16)
    state.cmd_timeout = options['timeout']
    enable_dpi_awareness()
    root = tk.Tk()
    root.tk.call('tk', 'scaling', get_dpi_scaling_factor() * (96.0 / 72.0))
    HermesUI(root, state)
    root.mainloop()


if __name__ == '__main__':
    main()
