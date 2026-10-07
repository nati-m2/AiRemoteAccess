#!/usr/bin/env python3
"""Warp MCP server.

Exposes the machine's diagnostics, logs and command execution as native MCP
tools over the Streamable HTTP transport, so an MCP client (e.g. Hermes) can
drive the host with structured tool calls instead of hand-rolled curl + Bearer
+ JSON against a bespoke endpoint.

Two variants, chosen by flag or by executable name:
  * headless (warp-mcp / warp-mcp.exe)      -> prints a banner, serves, blocks
  * GUI      (warp-mcp-gui / *-gui.exe)      -> a control panel to start/stop it

Auth is a single static Bearer token (no OAuth). The client sends
``Authorization: Bearer <token>`` and the server validates it with FastMCP's
StaticTokenVerifier.

Run headless:
    pip install fastmcp
    WARP_MCP_TOKEN=<token> python3 mcp_server.py --port 8999
    python3 mcp_server.py --host 0.0.0.0 --port 8999      # LAN; prints real IPs
Run the GUI:
    python3 mcp_server.py --gui

Expose publicly with valid TLS (no self-signed headaches) via cloudflared:
    cloudflared tunnel --url http://127.0.0.1:8999
    -> client connects to https://<name>.trycloudflare.com/mcp

This is a prototype: ``run_command`` runs an arbitrary shell command. Keep the
token secret and prefer the structured tools; a future revision should add an
allow/deny policy and confirmation for destructive actions.
"""
import io
import os
import sys
import json
import time
import shlex
import string
import shutil
import socket
import secrets
import platform
import argparse
import threading
import subprocess


def _ensure_std_streams():
    """Guarantee sys.stdout/stderr exist, even in a windowed (no-console) build.

    A PyInstaller ``--windowed`` executable has ``sys.stdout``/``stderr`` set to
    None; any ``print`` (ours, FastMCP's banner, or uvicorn's logging) then
    raises. Swap in a sink so writing is always safe.
    """
    class _NullWriter(io.TextIOBase):
        def write(self, _):
            return 0

        def flush(self):
            pass

    for name in ("stdout", "stderr"):
        if getattr(sys, name, None) is None:
            setattr(sys, name, _NullWriter())


_ensure_std_streams()

try:
    import fastmcp
    from fastmcp import FastMCP
    from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
except ImportError:
    sys.exit(
        "error: fastmcp is not installed. Run:  pip install fastmcp\n"
        "       (Python 3.10+; on the pve use python3 -m pip install fastmcp)"
    )

FASTMCP_VERSION = getattr(fastmcp, "__version__", "?")
try:
    from mcp.types import LATEST_PROTOCOL_VERSION as MCP_PROTOCOL_VERSION
except Exception:  # noqa: BLE001 - version constant is informational only
    MCP_PROTOCOL_VERSION = "unknown"

DEFAULT_PORT = 8999
DEFAULT_TIMEOUT = 30
GRACEFUL_SHUTDOWN_SECONDS = 3  # cap uvicorn's wait for open streams so the port frees
SCOPE = "warp:use"
AUDIT_LOG = os.path.join(os.getcwd(), "warp_mcp_audit.log")
IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _subprocess_env():
    """Restore the pre-launch library path when running as a frozen build.

    PyInstaller prepends its extraction dir to LD_LIBRARY_PATH; system binaries
    we spawn would otherwise load our bundled libs and fail (e.g. the distro's
    openssl needing newer OPENSSL_3.x symbols than our bundled libssl provides).
    Returns None when not frozen -> inherit the environment unchanged.
    """
    if not getattr(sys, "frozen", False):
        return None
    env = dict(os.environ)
    for key in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        orig = env.get(key + "_ORIG")
        if orig is not None:
            env[key] = orig
        else:
            env.pop(key, None)
    return env


def _audit(tool, detail, exit_code=None):
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tool": tool,
        "detail": detail,
        "exit_code": exit_code,
    }
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _run(argv, timeout=DEFAULT_TIMEOUT, shell=False):
    """Run a command and return a structured {stdout, stderr, exit_code} dict."""
    try:
        res = subprocess.run(
            argv,
            shell=shell,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=_subprocess_env(),
        )
        return {"stdout": res.stdout, "stderr": res.stderr, "exit_code": res.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"timed out after {timeout}s", "exit_code": None}
    except FileNotFoundError as e:
        return {"stdout": "", "stderr": f"command not found: {e}", "exit_code": None}
    except Exception as e:  # noqa: BLE001 - surface any launch failure to the client
        return {"stdout": "", "stderr": str(e), "exit_code": None}


def get_local_ips():
    """Return reachable IPv4 addresses, best-guess primary first."""
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))  # no packets sent; just picks the route's src IP
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for addr in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = addr[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass
    # Drop APIPA/link-local (169.254.x) — never useful as a connect address.
    return [ip for ip in ips if not ip.startswith("169.254.")]


def endpoint_urls(host, port):
    """Return the URL(s) a client can actually connect to.

    ``0.0.0.0``/``::`` mean "all interfaces", which is not a connectable address,
    so expand it to the host's real LAN IP(s). That is what an agent needs.
    """
    if host in ("0.0.0.0", "::", ""):
        ips = get_local_ips() or ["127.0.0.1"]
        return [f"http://{ip}:{port}/mcp" for ip in ips]
    return [f"http://{host}:{port}/mcp"]


def port_in_use(host, port):
    """True if something is already listening on (host, port)."""
    probe = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((probe, port)) == 0


# --------------------------------------------------------------------------- #
# MCP tools
# --------------------------------------------------------------------------- #
mcp = FastMCP(name="warp-mcp")


@mcp.tool
def run_command(command: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run a shell command on the machine and return stdout, stderr and exit code.

    Uses the platform's shell (cmd.exe on Windows, /bin/sh elsewhere). Prefer the
    structured diagnostic tools when one fits; use this only for what they do not
    cover. ``timeout`` is in seconds.
    """
    result = _run(command, timeout=timeout, shell=True)
    _audit("run_command", command, result.get("exit_code"))
    return result


@mcp.tool
def get_system_info() -> dict:
    """Return basic host info: hostname, OS, kernel, CPU count, load and memory."""
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "addresses": get_local_ips(),
    }
    try:
        info["loadavg"] = os.getloadavg()  # (1m, 5m, 15m); POSIX only
    except (OSError, AttributeError):
        info["loadavg"] = None
    try:  # memory + uptime from /proc where available (Linux)
        with open("/proc/meminfo", encoding="utf-8") as f:
            mem = {k.strip(): v.strip() for k, _, v in (ln.partition(":") for ln in f)}
        info["mem_total"] = mem.get("MemTotal")
        info["mem_available"] = mem.get("MemAvailable")
    except OSError:
        pass
    try:
        with open("/proc/uptime", encoding="utf-8") as f:
            info["uptime_seconds"] = float(f.read().split()[0])
    except (OSError, ValueError):
        pass
    _audit("get_system_info", "")
    return info


@mcp.tool
def get_disk_usage() -> dict:
    """Return disk usage for mounted filesystems / drives (cross-platform)."""
    if IS_WINDOWS:
        rows = ["Drive  Total      Used       Free       Use%"]
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if not os.path.exists(root):
                continue
            try:
                total, used, free = shutil.disk_usage(root)
            except OSError:
                continue
            pct = (used / total * 100) if total else 0
            rows.append(f"{letter}:     {total // 2**30:>6} GB  {used // 2**30:>6} GB  "
                        f"{free // 2**30:>6} GB  {pct:4.0f}%")
        result = {"stdout": "\n".join(rows), "stderr": "", "exit_code": 0}
    else:
        result = _run(["df", "-h"], timeout=10)
    _audit("get_disk_usage", "", result.get("exit_code"))
    return result


@mcp.tool
def list_processes(limit: int = 20, sort_by: str = "cpu") -> dict:
    """List the top processes. ``sort_by`` is 'cpu' or 'mem'; ``limit`` caps rows."""
    limit = max(1, min(int(limit), 200))
    if IS_WINDOWS:
        # tasklist has no CPU sort; return the list (optionally the biggest by mem).
        result = _run(["tasklist", "/FO", "TABLE"], timeout=10)
        if result.get("stdout"):
            lines = result["stdout"].splitlines()
            result["stdout"] = "\n".join(lines[: limit + 3])  # header rows + limit
    else:
        key = "-%mem" if sort_by == "mem" else "-%cpu"
        cmd = f"ps aux --sort={shlex.quote(key)} | head -n {limit + 1}"
        result = _run(cmd, timeout=10, shell=True)
    _audit("list_processes", f"sort_by={sort_by} limit={limit}", result.get("exit_code"))
    return result


@mcp.tool
def get_service_status(name: str) -> dict:
    """Return the status of a systemd service (Linux only)."""
    if not IS_LINUX:
        return {"stdout": "", "stderr": "get_service_status requires Linux/systemd", "exit_code": None}
    result = _run(["systemctl", "status", name, "--no-pager"], timeout=10)
    _audit("get_service_status", name, result.get("exit_code"))
    return result


@mcp.tool
def get_logs(service: str = "", lines: int = 100) -> dict:
    """Return recent journald logs, optionally for one unit (Linux only).

    ``service`` is a systemd unit name (empty = whole journal); ``lines`` caps
    the trailing lines returned.
    """
    if not IS_LINUX:
        return {"stdout": "", "stderr": "get_logs requires Linux/journald", "exit_code": None}
    lines = max(1, min(int(lines), 2000))
    argv = ["journalctl", "-n", str(lines), "--no-pager"]
    if service:
        argv += ["-u", service]
    result = _run(argv, timeout=15)
    _audit("get_logs", f"service={service or '*'} lines={lines}", result.get("exit_code"))
    return result


# --------------------------------------------------------------------------- #
# Server wiring
# --------------------------------------------------------------------------- #
def tool_names():
    try:
        names = sorted(t.name for t in mcp._tool_manager._tools.values())
        if names:
            return names
    except Exception:  # noqa: BLE001 - private API; fall back to the static list
        pass
    return ["run_command", "get_system_info", "get_disk_usage",
            "list_processes", "get_service_status", "get_logs"]


def configure_auth(token):
    """Attach static Bearer-token auth to the server."""
    mcp.auth = StaticTokenVerifier(
        tokens={token: {"client_id": "hermes", "scopes": [SCOPE]}},
        required_scopes=[SCOPE],
    )


def banner_lines(host, port, token):
    urls = endpoint_urls(host, port)
    lines = [
        "=" * 60,
        f"Warp MCP server  (MCP {MCP_PROTOCOL_VERSION}, Streamable HTTP)",
        f"Exposed at : {urls[0]}",
    ]
    for extra in urls[1:]:
        lines.append(f"             {extra}")
    lines += [
        f"Auth       : Authorization: Bearer <token>   (scope: {SCOPE})",
        f"Token      : {token}",
        f"Tools      : {', '.join(tool_names())}",
        "=" * 60,
    ]
    return lines


def run_headless(host, port, token):
    if port_in_use(host, port):
        sys.exit(f"error: port {port} is already in use — stop the other instance "
                 f"or pass --port. (e.g. `pkill -f warp-mcp`)")
    configure_auth(token)
    print("\n".join(banner_lines(host, port, token)))
    sys.stdout.flush()
    # show_banner=False: FastMCP's fancy rich banner can crash while rendering in
    # a frozen/redirected console (notably the Windows onefile build). Our banner
    # above already carries everything the client/operator needs.
    #
    # timeout_graceful_shutdown: MCP Streamable HTTP keeps long-lived streaming
    # connections open. Without a cap, Ctrl+C makes uvicorn wait indefinitely for
    # those to close ("waiting for application shutdown"), so the process lingers
    # and the port stays bound until it is killed by hand. Cap it so a stuck
    # connection is dropped and the port is always released promptly.
    mcp.run(transport="http", host=host, port=port, show_banner=False,
            uvicorn_config={"timeout_graceful_shutdown": GRACEFUL_SHUTDOWN_SECONDS})


# --------------------------------------------------------------------------- #
# GUI variant
# --------------------------------------------------------------------------- #
class ServerController:
    """Start/stop the MCP server in a background thread for the GUI."""

    def __init__(self):
        self._server = None
        self._thread = None

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self, host, port, token):
        if self.is_running():
            return
        if port_in_use(host, port):
            raise RuntimeError(f"port {port} is already in use")
        import uvicorn
        configure_auth(token)
        # FastMCP exposes a Starlette ASGI app we can drive with uvicorn directly,
        # which gives us a clean stop (unlike the blocking mcp.run()).
        try:
            app = mcp.http_app()
        except AttributeError:
            app = mcp.streamable_http_app()  # older fastmcp name
        config = uvicorn.Config(app, host=host, port=port, log_level="info",
                                timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS)
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server is not None:
            # should_exit triggers a graceful stop; force_exit drops open
            # connections if they don't close within the grace period, so the
            # thread (and the bound port) can never get wedged.
            self._server.should_exit = True
            if self._thread is not None:
                self._thread.join(timeout=GRACEFUL_SHUTDOWN_SECONDS + 2)
                if self._thread.is_alive():
                    self._server.force_exit = True
                    self._thread.join(timeout=3)
        self._server = None
        self._thread = None


def run_gui(host, port, token):
    import tkinter as tk
    from tkinter import ttk

    BG, CARD, INPUT, FG, MUTED = "#161a23", "#1f2430", "#262c3a", "#e6e9f0", "#8b93a7"
    ACCENT, DANGER, OK = "#5b8cff", "#e05561", "#3ecf8e"

    controller = ServerController()
    root = tk.Tk()
    root.title("Warp MCP")
    root.geometry("720x560")
    root.minsize(560, 480)
    root.configure(bg=BG)

    host_var = tk.StringVar(value=host)
    port_var = tk.StringVar(value=str(port))
    token_var = tk.StringVar(value=token)
    status_var = tk.StringVar(value="Stopped")
    endpoint_var = tk.StringVar(value="")

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure(".", background=BG, foreground=FG, font=("Segoe UI", 10))
    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=CARD)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Card.TLabel", background=CARD, foreground=FG)
    style.configure("Muted.TLabel", background=CARD, foreground=MUTED, font=("Segoe UI", 9))
    style.configure("Title.TLabel", background=BG, foreground=FG, font=("Segoe UI", 15, "bold"))
    style.configure("TEntry", fieldbackground=INPUT, foreground=FG, insertcolor=FG, padding=5)
    style.map("TEntry", fieldbackground=[("readonly", INPUT)], foreground=[("readonly", FG)])
    style.configure("Accent.TButton", background=ACCENT, foreground="#fff",
                    font=("Segoe UI", 10, "bold"), padding=(14, 7), borderwidth=0)
    style.map("Accent.TButton", background=[("active", "#7aa2ff"), ("disabled", "#3a4152")])
    style.configure("Danger.TButton", background=DANGER, foreground="#fff",
                    font=("Segoe UI", 10, "bold"), padding=(14, 7), borderwidth=0)
    style.map("Danger.TButton", background=[("active", "#ea7b84"), ("disabled", "#3a4152")])
    style.configure("Ghost.TButton", background=CARD, foreground=FG, font=("Segoe UI", 9), padding=(10, 5))

    outer = ttk.Frame(root, padding=18, style="TFrame")
    outer.pack(fill=tk.BOTH, expand=True)
    outer.columnconfigure(0, weight=1)

    ttk.Label(outer, text="🌀  Warp MCP", style="Title.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 12))

    cfg = ttk.Frame(outer, style="Card.TFrame", padding=14)
    cfg.grid(row=1, column=0, sticky="ew")
    cfg.columnconfigure(1, weight=1)
    ttk.Label(cfg, text="Host", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=6, pady=5)
    ttk.Entry(cfg, textvariable=host_var, width=16).grid(row=0, column=1, sticky="w", padx=6, pady=5)
    ttk.Label(cfg, text="Port", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=6, pady=5)
    ttk.Entry(cfg, textvariable=port_var, width=10).grid(row=1, column=1, sticky="w", padx=6, pady=5)
    ttk.Label(cfg, text="Token", style="Card.TLabel").grid(row=2, column=0, sticky="w", padx=6, pady=5)
    ttk.Entry(cfg, textvariable=token_var).grid(row=2, column=1, sticky="ew", padx=6, pady=5)
    ttk.Button(cfg, text="Regenerate", style="Ghost.TButton",
               command=lambda: token_var.set(secrets.token_hex(16))).grid(row=2, column=2, padx=6)

    btns = ttk.Frame(outer, style="TFrame")
    btns.grid(row=2, column=0, sticky="ew", pady=12)
    start_btn = ttk.Button(btns, text="▶  Start", style="Accent.TButton")
    start_btn.pack(side=tk.LEFT, padx=(0, 8))
    stop_btn = ttk.Button(btns, text="■  Stop", style="Danger.TButton", state="disabled")
    stop_btn.pack(side=tk.LEFT)

    info = ttk.Frame(outer, style="Card.TFrame", padding=14)
    info.grid(row=3, column=0, sticky="ew")
    info.columnconfigure(1, weight=1)
    ttk.Label(info, text="Status", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=6, pady=5)
    ttk.Label(info, textvariable=status_var, style="Card.TLabel").grid(row=0, column=1, sticky="w", padx=6, pady=5)
    ttk.Label(info, text="Endpoint", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=6, pady=5)
    ttk.Entry(info, textvariable=endpoint_var, state="readonly").grid(row=1, column=1, sticky="ew", padx=6, pady=5)

    log = tk.Text(outer, height=9, bg=INPUT, fg=FG, insertbackground=FG,
                  relief="flat", font=("Consolas", 9), wrap="none")
    log.grid(row=4, column=0, sticky="nsew", pady=(12, 0))
    outer.rowconfigure(4, weight=1)

    def log_line(msg):
        log.insert("end", f"{time.strftime('%H:%M:%S')}  {msg}\n")
        log.see("end")

    def on_start():
        try:
            p = int(port_var.get())
        except ValueError:
            log_line("error: port must be a number")
            return
        try:
            controller.start(host_var.get().strip() or "127.0.0.1", p, token_var.get().strip())
        except Exception as e:  # noqa: BLE001 - show any startup failure in the GUI
            log_line(f"error: {e}")
            return
        urls = endpoint_urls(host_var.get().strip() or "127.0.0.1", p)
        endpoint_var.set("   ".join(urls))
        status_var.set("Running")
        start_btn.config(state="disabled")
        stop_btn.config(state="normal")
        log_line(f"started — {urls[0]}")
        log_line(f"token: {token_var.get().strip()}")

    def on_stop():
        controller.stop()
        status_var.set("Stopped")
        endpoint_var.set("")
        start_btn.config(state="normal")
        stop_btn.config(state="disabled")
        log_line("stopped")

    def on_close():
        controller.stop()
        root.destroy()

    start_btn.config(command=on_start)
    stop_btn.config(command=on_stop)
    root.protocol("WM_DELETE_WINDOW", on_close)

    for line in ("Warp MCP control panel.",
                 f"MCP protocol {MCP_PROTOCOL_VERSION} · fastmcp {FASTMCP_VERSION}",
                 "Set host/port/token, then Start. 0.0.0.0 binds all interfaces."):
        log_line(line)

    root.mainloop()


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _is_gui_build():
    """True when running as the frozen GUI executable (name contains 'gui')."""
    if not getattr(sys, "frozen", False):
        return False
    return "gui" in os.path.basename(sys.executable).lower()


def main():
    parser = argparse.ArgumentParser(description="Warp MCP server.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default 0.0.0.0 = all interfaces/LAN; use 127.0.0.1 for localhost-only).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port.")
    parser.add_argument("--token", default=os.environ.get("WARP_MCP_TOKEN", ""),
                        help="Static Bearer token (env WARP_MCP_TOKEN, random if unset).")
    parser.add_argument("--gui", action="store_true", help="Launch the control-panel GUI.")
    parser.add_argument("--no-gui", action="store_true", help="Force headless even for a GUI build.")
    ns = parser.parse_args()

    token = ns.token or secrets.token_hex(16)
    use_gui = (ns.gui or _is_gui_build()) and not ns.no_gui

    if use_gui:
        run_gui(ns.host, ns.port, token)
    else:
        run_headless(ns.host, ns.port, token)


if __name__ == "__main__":
    main()
