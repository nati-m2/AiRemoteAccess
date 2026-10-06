import os
import re
import sys
import json
import time
import queue
import ctypes
import shutil
import socket
import ssl
import signal
import getpass
import secrets
import tempfile
import platform
import threading
import traceback
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


def _init_console_io():
    '''Make stdout/stderr safe on Windows.

    Two problems this fixes for the frozen builds:
      * A console using a non-UTF-8 code page (e.g. cp1255 on a Hebrew Windows)
        raises ``UnicodeEncodeError`` the first time we print an emoji, killing
        the process immediately. Reconfigure the streams to UTF-8 and, failing
        that, replace un-encodable characters instead of crashing.
      * A ``--windowed`` (no-console) build has ``sys.stdout``/``stderr`` set to
        ``None``; any ``print`` then raises ``AttributeError``. Swap in a sink so
        printing is always a no-op-safe operation.
    '''
    import io

    class _NullWriter(io.TextIOBase):
        def write(self, _):
            return 0

        def flush(self):
            pass

    for name in ('stdout', 'stderr'):
        stream = getattr(sys, name, None)
        if stream is None:
            setattr(sys, name, _NullWriter())
            continue
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            # Older streams without reconfigure(): best-effort wrap.
            try:
                buf = getattr(stream, 'buffer', None)
                if buf is not None:
                    setattr(sys, name, io.TextIOWrapper(
                        buf, encoding='utf-8', errors='replace', line_buffering=True))
            except Exception:
                pass


_init_console_io()

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
TUNNEL_LOG_FILE = os.path.join(TEMP_DIR, 'warp_tunnel.log')
AUDIT_LOG_FILE = os.path.join(os.getcwd(), 'warp_audit.log')


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
        self.use_tls = True
        self.fingerprint = None
        self.tunnel_proc = None
        self.tunnel_log_fd = None
        self.public_url = None
        self.last_error = None
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


def _subprocess_env():
    '''Return an environment dict for launching external programs, or None.

    PyInstaller's onefile bootloader prepends its extraction directory
    (``sys._MEIPASS``) to ``LD_LIBRARY_PATH`` so the bundled interpreter can
    find its own shared libraries. Any *system* binary we then spawn (openssl,
    cloudflared, xclip, and the user's own remote shell commands) would inherit
    that path and load our bundled ``libssl``/``libcrypto``/etc. ahead of the
    system ones. When the host's tools are built against newer libraries than
    those we bundled, they fail with errors like::

        /usr/bin/openssl: .../libssl.so.3: version `OPENSSL_3.4.0' not found

    The bootloader preserves the pre-launch value in ``<VAR>_ORIG``. Restore it
    (or drop the variable entirely if it was unset originally) so subprocesses
    use the system libraries. Returns None when not frozen, meaning "inherit the
    current environment unchanged".
    '''
    if not getattr(sys, 'frozen', False):
        return None
    env = dict(os.environ)
    for key in ('LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH'):
        orig = env.get(key + '_ORIG')
        if orig is not None:
            env[key] = orig
        else:
            env.pop(key, None)
    return env


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
    env = _subprocess_env()
    try:
        if os.name == 'nt':
            subprocess.run('clip', input=text.encode('utf-16-le'), shell=True, check=True, env=env)
        elif sys.platform == 'darwin':
            subprocess.run('pbcopy', input=text.encode('utf-8'), shell=True, check=True, env=env)
        else:
            subprocess.run('xclip -selection clipboard', input=text.encode('utf-8'), shell=True, check=True, env=env)
    except Exception:
        pass


def kill_orphaned_cloudflared(tracked_pid):
    '''Kill any orphaned cloudflared processes.'''
    env = _subprocess_env()
    try:
        if os.name == 'nt':
            out = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq cloudflared.exe', '/FO', 'CSV', '/NH'],
                capture_output=True, text=True, env=env
            ).stdout
            for line in out.splitlines():
                parts = [p.strip('"') for p in line.split(',')]
                if len(parts) >= 2 and parts[1].isdigit():
                    pid = int(parts[1])
                    if pid != tracked_pid:
                        subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True, env=env)
        else:
            out = subprocess.run(['pgrep', '-f', 'cloudflared'], capture_output=True, text=True, env=env).stdout
            for line in out.splitlines():
                pid = int(line.strip())
                if pid != tracked_pid:
                    subprocess.run(['kill', '-9', str(pid)], capture_output=True, env=env)
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
                env=_subprocess_env(),
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


def _find_openssl():
    '''Locate an openssl executable.

    ``shutil.which`` only checks ``PATH``. A frozen build launched from Explorer
    does not inherit Git Bash's ``PATH``, so a Git-bundled openssl is invisible
    there. Fall back to well-known install locations before giving up.
    '''
    found = shutil.which('openssl')
    if found:
        return found
    if os.name == 'nt':
        candidates = []
        for root in (
            os.environ.get('ProgramFiles', r'C:\Program Files'),
            os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
            os.environ.get('LOCALAPPDATA', ''),
        ):
            if not root:
                continue
            candidates += [
                os.path.join(root, 'Git', 'usr', 'bin', 'openssl.exe'),
                os.path.join(root, 'Git', 'mingw64', 'bin', 'openssl.exe'),
                os.path.join(root, 'OpenSSL-Win64', 'bin', 'openssl.exe'),
                os.path.join(root, 'OpenSSL', 'bin', 'openssl.exe'),
            ]
        for path in candidates:
            if os.path.exists(path):
                return path
    return None


def generate_tls_cert():
    '''Generate a fresh self-signed cert+key in temp files and return their paths.

    A new certificate is made on every start (via ``openssl``) so nothing is left
    on disk between runs. The caller loads them into an SSL context — which keeps
    the material in memory — and then deletes the files immediately, so they exist
    only for the moment of loading. ``mkstemp`` creates the files ``0600``.
    '''
    openssl = _find_openssl()
    if not openssl:
        raise RuntimeError(
            'openssl not found; cannot generate a TLS certificate. '
            'Install openssl or pass --no-tls.'
        )
    cert_fd, certfile = tempfile.mkstemp(suffix='.pem', prefix='warp_cert_')
    key_fd, keyfile = tempfile.mkstemp(suffix='.pem', prefix='warp_key_')
    os.close(cert_fd)
    os.close(key_fd)
    base_cmd = [
        openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', keyfile, '-out', certfile, '-days', '3650',
        '-subj', '/CN=warp',
    ]
    # SAN is nice-to-have; retry without it on older openssl that lacks -addext.
    env = _subprocess_env()
    for cmd in (base_cmd + ['-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], base_cmd):
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode == 0:
            return certfile, keyfile
    for f in (certfile, keyfile):
        try:
            os.remove(f)
        except OSError:
            pass
    raise RuntimeError(f'openssl failed to generate certificate: {result.stderr.strip()}')


def cert_fingerprint(certfile):
    '''Return the SHA-256 fingerprint of a certificate, or None if unavailable.'''
    openssl = _find_openssl()
    if not openssl:
        return None
    try:
        out = subprocess.run(
            [openssl, 'x509', '-in', certfile, '-fingerprint', '-sha256', '-noout'],
            capture_output=True, text=True, timeout=5, env=_subprocess_env(),
        ).stdout.strip()
        return out.split('=', 1)[1] if '=' in out else out or None
    except Exception:
        return None


class WarpHTTPServer(http.server.ThreadingHTTPServer):
    '''ThreadingHTTPServer that shuts down cleanly and frees its port.

    Request-handling threads are daemons so an in-flight command can never keep
    the process (and therefore the bound port) alive after a stop/Ctrl+C, and
    ``block_on_close`` is disabled so ``server_close`` never hangs waiting on
    them. ``allow_reuse_address`` lets the port be rebound immediately.
    '''
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True


def start_http_server(state):
    '''Start the local HTTP server in a background thread.'''
    try:
        handler = make_handler(state)
        state.server = WarpHTTPServer((state.listen_host, state.port), handler)
        if state.use_tls and not _find_openssl():
            # No openssl available (common when a frozen build is launched from
            # Explorer): degrade to plain HTTP rather than failing to start.
            state.use_tls = False
            state.status_queue.put({
                'type': 'status',
                'message': 'openssl not found - serving plain HTTP (install openssl or use Cloudflare mode for encryption).',
            })
        if state.use_tls:
            certfile, keyfile = generate_tls_cert()
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile, keyfile)
                state.fingerprint = cert_fingerprint(certfile)
            finally:
                # Files exist only for this load; the context keeps the cert and
                # key in memory, so nothing is left on disk while the server runs.
                for f in (certfile, keyfile):
                    try:
                        os.remove(f)
                    except OSError:
                        pass
            state.server.socket = ctx.wrap_socket(state.server.socket, server_side=True)
        threading.Thread(target=state.server.serve_forever, daemon=True).start()
    except Exception as e:
        raise RuntimeError(f'Failed to start local server: {e}')
    scheme = 'https' if state.use_tls else 'http'
    state.status_queue.put({'type': 'status', 'message': f'Local server started on {scheme}://{state.listen_host}:{state.port}'})


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
            env=_subprocess_env(),
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
            # TLS applies to local mode only. Cloudflare already encrypts the
            # public hop and reaches the origin over loopback, so no cert there.
            # The cert is generated (and its files deleted) inside start_http_server.
            state.use_tls = bool(options.get('tls', True))
        else:
            state.listen_host = '127.0.0.1'
            state.use_tls = False
        state.running = True
        start_http_server(state)
        time.sleep(0.5)
        if state.mode == ConnectionMode.LOCAL:
            scheme = 'https' if state.use_tls else 'http'
            ips = get_local_ips()
            urls = [f'{scheme}://{ip}:{state.port}' for ip in ips]
            state.public_url = urls[0] if urls else f'{scheme}://127.0.0.1:{state.port}'
        elif state.mode == ConnectionMode.CLOUDFLARE:
            state.public_url = start_cloudflare_tunnel(state)
        state.status_queue.put({
            'type': 'ready',
            'url': state.public_url,
            'token': state.token,
            'mode': MODE_LABELS.get(state.mode, state.mode.value),
            'fingerprint': state.fingerprint if state.use_tls else None,
        })
    except Exception as e:
        # Capture the full traceback and queue the error BEFORE clearing
        # ``running``: the terminal wait loop exits the instant it sees
        # ``running`` go false, so queuing afterwards loses the message.
        state.last_error = traceback.format_exc()
        state.status_queue.put({'type': 'error', 'message': str(e)})
        state.running = False
        stop_http_server(state)
        stop_tunnel(state)


def stop_connection(state):
    '''Stop the HTTP server and tunnel.'''
    state.running = False
    stop_http_server(state)
    stop_tunnel(state)
    state.public_url = None
    state.status_queue.put({'type': 'stopped'})


class WarpUI:
    '''Modern Tkinter control panel for Warp.'''

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
        self.root.title('Warp')
        self.root.geometry('800x740')
        self.root.minsize(560, 560)
        self.root.configure(bg=self.BG)
        self._set_icon()
        self.root.protocol('WM_DELETE_WINDOW', self._on_close)

        self.mode_var = tk.StringVar(value=MODE_LABELS[ConnectionMode.LOCAL])
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        self.token_var = tk.StringVar(value=state.token)
        self.timeout_var = tk.StringVar(value=str(DEFAULT_CMD_TIMEOUT))
        self.tls_var = tk.BooleanVar(value=True)

        self.url_var = tk.StringVar()
        self.token_info_var = tk.StringVar()
        self.fingerprint_var = tk.StringVar()
        self.status_var = tk.StringVar(value='Ready')
        self.status_dot_var = tk.StringVar(value='●')
        self._audit_tree = None

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
        style.configure('Card.TCheckbutton', background=self.BG_CARD, foreground=self.FG)
        style.map('Card.TCheckbutton', background=[('active', self.BG_CARD)], foreground=[('active', self.FG)])
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

        # Tabs
        style.configure('Warp.TNotebook', background=self.BG, borderwidth=0, tabmargins=(0, 0, 0, 8))
        style.configure('Warp.TNotebook.Tab', background=self.BG_CARD, foreground=self.FG_MUTED,
                        padding=(20, 9), font=('Segoe UI', 10, 'bold'), borderwidth=0)
        style.map('Warp.TNotebook.Tab',
                  background=[('selected', self.BG_INPUT), ('active', self.BORDER)],
                  foreground=[('selected', self.FG)])

        # Audit-log table
        style.configure('Audit.Treeview', background=self.BG_INPUT, fieldbackground=self.BG_INPUT,
                        foreground=self.FG, bordercolor=self.BORDER, borderwidth=0,
                        rowheight=24, font=('Segoe UI', 9))
        style.configure('Audit.Treeview.Heading', background=self.BG_CARD, foreground=self.FG_MUTED,
                        font=('Segoe UI', 9, 'bold'), relief='flat', borderwidth=0)
        style.map('Audit.Treeview.Heading', background=[('active', self.BORDER)])
        style.map('Audit.Treeview', background=[('selected', self.ACCENT)],
                  foreground=[('selected', '#ffffff')])

    def _build_ui(self):
        pad = {'padx': 8, 'pady': 6}

        outer = ttk.Frame(self.root, padding='20', style='TFrame')
        outer.pack(fill=tk.BOTH, expand=True)
        outer.columnconfigure(0, weight=1)

        # Header
        header = ttk.Frame(outer, style='TFrame')
        header.grid(row=0, column=0, sticky='ew', pady=(0, 16))
        ttk.Label(header, text='🌀  Warp', style='Title.TLabel').pack(side=tk.LEFT)

        # Tabs: Connection | Log
        nb = ttk.Notebook(outer, style='Warp.TNotebook')
        nb.grid(row=1, column=0, sticky='nsew')
        outer.rowconfigure(1, weight=1)

        conn_tab = ttk.Frame(nb, style='TFrame', padding=(0, 14))
        conn_tab.columnconfigure(0, weight=1)
        conn_tab.rowconfigure(2, weight=1)
        nb.add(conn_tab, text='  Connection  ')

        log_tab = ttk.Frame(nb, style='TFrame', padding=(0, 14))
        log_tab.columnconfigure(0, weight=1)
        log_tab.rowconfigure(0, weight=1)
        nb.add(log_tab, text='  Log  ')

        # ===== Connection tab =====
        # Settings card
        settings = ttk.Frame(conn_tab, style='Card.TFrame', padding=16)
        settings.grid(row=0, column=0, sticky='ew')
        settings.columnconfigure(1, weight=1)

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

        ttk.Checkbutton(settings, text='HTTPS (local mode)', variable=self.tls_var,
                        style='Card.TCheckbutton').grid(row=5, column=1, columnspan=2, sticky=tk.W, **pad)

        # Action buttons
        btn_frame = ttk.Frame(conn_tab, style='TFrame')
        btn_frame.grid(row=1, column=0, sticky='ew', pady=(16, 16))
        self.start_btn = ttk.Button(btn_frame, text='▶  Start', style='Accent.TButton', command=self._on_start)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.stop_btn = ttk.Button(btn_frame, text='■  Stop', style='Danger.TButton', command=self._on_stop, state='disabled')
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_frame, text='⧉  Copy Details', style='Ghost.TButton', command=self._copy_details).pack(side=tk.LEFT)

        # Connection info card
        info = ttk.Frame(conn_tab, style='Card.TFrame', padding=16)
        info.grid(row=2, column=0, sticky='new')
        info.columnconfigure(1, weight=1)

        ttk.Label(info, text='Connection Info', style='Section.TLabel', background=self.BG_CARD).grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))

        ttk.Label(info, text='URL', style='Card.TLabel').grid(row=1, column=0, sticky=tk.W, **pad)
        ttk.Entry(info, textvariable=self.url_var, state='readonly').grid(row=1, column=1, sticky='ew', **pad)

        ttk.Label(info, text='Token', style='Card.TLabel').grid(row=2, column=0, sticky=tk.W, **pad)
        ttk.Entry(info, textvariable=self.token_info_var, state='readonly').grid(row=2, column=1, sticky='ew', **pad)

        ttk.Label(info, text='Cert SHA-256', style='Card.TLabel').grid(row=3, column=0, sticky=tk.W, **pad)
        ttk.Entry(info, textvariable=self.fingerprint_var, state='readonly',
                  font=('Consolas', 9)).grid(row=3, column=1, sticky='ew', **pad)

        status_row = ttk.Frame(info, style='Card.TFrame')
        status_row.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))
        self.status_dot = ttk.Label(status_row, textvariable=self.status_dot_var, style='StatusDot.TLabel',
                                    background=self.BG_CARD, foreground=self.FG_MUTED)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 6))
        ttk.Label(status_row, textvariable=self.status_var, style='Card.TLabel').pack(side=tk.LEFT)

        # ===== Log tab =====
        log_card = ttk.Frame(log_tab, style='Card.TFrame', padding=16)
        log_card.grid(row=0, column=0, sticky='nsew')
        log_card.columnconfigure(0, weight=1)
        log_card.rowconfigure(1, weight=1)

        log_header = ttk.Frame(log_card, style='Card.TFrame')
        log_header.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        log_header.columnconfigure(0, weight=1)
        ttk.Label(log_header, text='Activity Log', style='Section.TLabel',
                  background=self.BG_CARD).grid(row=0, column=0, sticky=tk.W)
        ttk.Button(log_header, text='Clear', style='Ghost.TButton',
                   command=self._clear_audit).grid(row=0, column=1, sticky=tk.E)

        table_wrap = ttk.Frame(log_card, style='Card.TFrame')
        table_wrap.grid(row=1, column=0, sticky='nsew')
        table_wrap.columnconfigure(0, weight=1)
        table_wrap.rowconfigure(0, weight=1)

        columns = ('time', 'ip', 'user', 'command', 'status', 'exit')
        headings = {'time': 'Time', 'ip': 'IP', 'user': 'User',
                    'command': 'Command', 'status': 'Status', 'exit': 'Exit'}
        widths = {'time': 150, 'ip': 110, 'user': 90, 'command': 300, 'status': 90, 'exit': 50}
        anchors = {'exit': tk.CENTER}
        tree = ttk.Treeview(table_wrap, columns=columns, show='headings',
                            style='Audit.Treeview', selectmode='browse')
        for col in columns:
            tree.heading(col, text=headings[col])
            tree.column(col, width=widths[col], anchor=anchors.get(col, tk.W),
                        stretch=(col == 'command'))
        # Colour rows by outcome so failures stand out.
        tree.tag_configure('ok', foreground=self.SUCCESS)
        tree.tag_configure('bad', foreground=self.DANGER)
        tree.tag_configure('warn', foreground='#e0b354')
        vsb = ttk.Scrollbar(table_wrap, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        self._audit_tree = tree

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
            'tls': bool(self.tls_var.get()),
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
        fingerprint = getattr(self, '_last_fingerprint', None)
        if fingerprint:
            text += f'Cert SHA-256: {fingerprint}\n'
        copy_to_clipboard(text)
        self._set_status('Copied to clipboard', self.SUCCESS)

    def _poll_queues(self):
        try:
            while True:
                msg = self.state.status_queue.get_nowait()
                self._handle_status(msg)
        except queue.Empty:
            pass
        try:
            while True:
                entry = self.state.command_queue.get_nowait()
                self._append_audit(entry)
        except queue.Empty:
            pass
        self.root.after(250, self._poll_queues)

    def _append_audit(self, entry):
        '''Add one audit entry as a table row (skips transient 'started' events).'''
        tree = self._audit_tree
        if tree is None:
            return
        status = str(entry.get('status', ''))
        if status == 'started':
            return  # the matching terminal event (executed/timeout/error) is enough
        exit_code = entry.get('exit_code')
        if status == 'executed':
            tag = 'ok' if exit_code in (0, '0') else 'bad'
        elif status == 'timeout':
            tag = 'warn'
        elif status.startswith('error'):
            tag = 'bad'
        else:
            tag = ''
        values = (
            entry.get('timestamp', ''),
            entry.get('ip', ''),
            entry.get('user', ''),
            entry.get('command', ''),
            status,
            '' if exit_code is None else exit_code,
        )
        tree.insert('', 'end', values=values, tags=(tag,) if tag else ())
        # Keep the newest row visible and cap the table so it can't grow unbounded.
        children = tree.get_children()
        if len(children) > 500:
            tree.delete(children[0])
        tree.see(tree.get_children()[-1])

    def _clear_audit(self):
        if self._audit_tree is not None:
            self._audit_tree.delete(*self._audit_tree.get_children())

    def _handle_status(self, msg):
        mtype = msg.get('type')
        if mtype == 'status':
            self._set_status(msg.get('message', ''), self.FG_MUTED)
        elif mtype == 'ready':
            self.url_var.set(msg.get('url', ''))
            self.token_info_var.set(msg.get('token', ''))
            self._last_fingerprint = msg.get('fingerprint')
            self.fingerprint_var.set(msg.get('fingerprint') or '—')
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
            self.fingerprint_var.set('')
            self._set_status('Ready', self.FG_MUTED)
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')

    def _set_icon(self):
        icon_name = 'app_icon.ico'
        if getattr(sys, 'frozen', False):
            base = sys._MEIPASS
        else:
            base = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(base, icon_name)
        if os.path.isfile(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                pass

    def _on_close(self):
        if self.state.running:
            self._on_stop()
            self.root.after(800, self.root.destroy)
        else:
            self.root.destroy()


def _is_console_build():
    '''True when running as the frozen console-only executable.

    Detected by the executable name containing 'cli' or 'console', so the
    ``warp-cli`` build starts in terminal mode automatically (the 'console'
    match is kept for backward compatibility with older ``WarpConsole`` builds).
    '''
    if not getattr(sys, 'frozen', False):
        return False
    exe_name = os.path.basename(sys.executable).lower()
    return 'console' in exe_name or 'cli' in exe_name


def build_parser():
    parser = argparse.ArgumentParser(description='Warp Remote Access')
    parser.add_argument('--mode', choices=[ConnectionMode.LOCAL.value, ConnectionMode.CLOUDFLARE.value],
                        default=ConnectionMode.LOCAL.value, help='Connection mode')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Local HTTP port')
    parser.add_argument('--token', default='', help='Bearer token (random if empty)')
    parser.add_argument('--timeout', type=int, default=DEFAULT_CMD_TIMEOUT, help='Command timeout in seconds')
    parser.add_argument('--no-gui', action='store_true', help='Run in terminal mode')
    parser.add_argument('--no-tls', action='store_true',
                        help='Disable HTTPS in local mode (on by default; served over a persistent self-signed cert)')
    return parser


def _wait_for_quit_key(stop_flag):
    '''Request shutdown when the user presses 'q'/'Q' on an interactive terminal.

    This gives the terminal build a graceful shutdown that runs entirely on the
    main thread with no signal involved, so cleanup always finishes and the port
    is released. Falls back silently when there is no interactive TTY (piped
    input, service manager, etc.), leaving Ctrl+C/SIGTERM as the stop path.

    Only a literal 'q'/'Q' quits. Earlier versions also treated Enter and Esc as
    quit, which made the server die the instant it started: over SSH the Enter
    that launched the process can still be buffered on stdin, and terminals
    routinely send Esc-prefixed sequences (cursor reports, focus events,
    bracketed paste) on their own — any of which was being read as "quit".
    Crucially, the flag is now set ONLY when 'q' is actually read; the watcher
    returning for any other reason must never trigger a shutdown.
    '''
    quit_chars = ('q', 'Q')
    try:
        if not sys.stdin or not sys.stdin.isatty():
            return  # no interactive keyboard: rely on Ctrl+C/SIGTERM, do NOT stop
        if os.name == 'nt':
            import msvcrt
            # Discard any typeahead (e.g. the Enter that ran us) before watching.
            while msvcrt.kbhit():
                msvcrt.getwch()
            while not stop_flag['flag']:
                if msvcrt.kbhit():
                    if msvcrt.getwch() in quit_chars:
                        stop_flag['reason'] = 'q keypress'
                        stop_flag['flag'] = True
                        return
                else:
                    time.sleep(0.08)
        else:
            import termios
            import tty
            import select
            fd = sys.stdin.fileno()
            old_attrs = termios.tcgetattr(fd)
            try:
                tty.setcbreak(fd)
                # Flush pending input so the launching keystroke (and any other
                # typeahead) can't be misread the moment we start watching.
                termios.tcflush(fd, termios.TCIFLUSH)
                while not stop_flag['flag']:
                    ready, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if ready:
                        ch = sys.stdin.read(1)
                        if ch in quit_chars:
                            stop_flag['reason'] = 'q keypress'
                            stop_flag['flag'] = True
                            return
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
    except Exception:
        return


def cli_main(options):
    '''Run Warp from the terminal without a GUI.'''
    state = AppState()

    # Handle Ctrl+C by asking the main loop to exit gracefully instead of raising
    # KeyboardInterrupt at an arbitrary point (which could surface mid-cleanup as
    # an unhandled traceback and leave the port bound).
    stop_requested = {'flag': False, 'reason': None}

    def _request_stop(signum, frame):
        stop_requested['reason'] = f'signal {signum}'
        stop_requested['flag'] = True

    try:
        signal.signal(signal.SIGINT, _request_stop)
        signal.signal(signal.SIGTERM, _request_stop)
    except Exception:
        pass

    # Preferred graceful stop: a keypress handled on the main thread, so cleanup
    # never races with a signal tearing the process down mid-shutdown.
    threading.Thread(target=_wait_for_quit_key, args=(stop_requested,), daemon=True).start()

    print('\U0001F680 Starting Satellite Server...')
    print('\u23F3 Waiting for Tunnel URL...' if options['mode'] == ConnectionMode.CLOUDFLARE else '\u23F3 Starting local server...')
    # Mark running up front so the wait loop below can't exit before the worker
    # thread has had a chance to flip the flag (it only sets running=False on a
    # real startup error, which the loop then reports).
    state.running = True
    threading.Thread(target=start_connection, args=(state, options), daemon=True).start()
    url_printed = False
    try:
        while not stop_requested['flag'] and (state.running or state.tunnel_proc is not None):
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
                        fingerprint = msg.get('fingerprint')
                        if fingerprint:
                            print(f'\U0001F512 CERT SHA-256: {fingerprint}')
                        print(separator)
                        print()
                        clip = f'URL: {url}\nToken: {token}\n'
                        if fingerprint:
                            clip += f'Cert SHA-256: {fingerprint}\n'
                        copy_to_clipboard(clip)
                        print('\U0001F4CB Copied URL & TOKEN to clipboard.')
                        print("⌨️  Press 'q' to stop and clean up (Ctrl+C also works).")
                        url_printed = True
                    elif msg.get('type') == 'error':
                        print(f"Error: {msg.get('message')}")
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        stop_requested['reason'] = stop_requested['reason'] or 'KeyboardInterrupt'
    finally:
        # Ignore any further Ctrl+C while we clean up so the shutdown always runs
        # to completion and the port is released, without dumping a traceback.
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        except Exception:
            pass
        # A startup error can be queued in the same instant the worker clears
        # state.running, which exits the wait loop above before the message is
        # ever drained. Drain once more here so real failures are reported
        # instead of looking like an instant, silent shutdown.
        try:
            while True:
                msg = state.status_queue.get_nowait()
                if msg.get('type') == 'error':
                    print(f"Error: {msg.get('message')}")
        except queue.Empty:
            pass
        print('\n\U0001F6D1 Stopping and cleaning up...')
        stop_connection(state)
        print('✅ Stopped. Port released.')


def main():
    parser = build_parser()
    args = parser.parse_args()
    mode = ConnectionMode(args.mode)
    options = {
        'mode': mode,
        'port': args.port,
        'token': args.token,
        'timeout': args.timeout,
        'tls': not args.no_tls,
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
    WarpUI(root, state)
    root.mainloop()


if __name__ == '__main__':
    main()
