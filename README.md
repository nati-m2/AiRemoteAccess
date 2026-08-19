# Warp

A lightweight remote command execution server with a small Tkinter control panel and a terminal mode. It supports two ways to expose the local HTTP server: **Local network** and **Cloudflare Tunnel**. An authenticated client can run shell commands remotely and get back `stdout`/`stderr`/exit code as JSON.

## Features

- **GUI** — modern dark-themed Tkinter control panel to choose a connection mode and start/stop the server.
- **Local** — listen on all local interfaces and connect from the same LAN.
- **Cloudflare** — Quick Tunnel (downloads `cloudflared` automatically).
- **Terminal mode** — run the tool directly from the command line with arguments.
- **Cross-platform** — Windows and Linux (amd64 / arm64).
- **Audit log** — all executed commands are logged to `warp_audit.log`.

## How it works

1. `main.py` starts a local `ThreadingHTTPServer`.
2. In **Local** mode the server listens on all interfaces.
3. In **Cloudflare** mode it downloads `cloudflared` if missing and starts a Quick Tunnel.
4. Remote clients send `POST` requests with `Authorization: Bearer <TOKEN>` and a JSON body: `{"command": "<shell command>"}`.
5. The `/info` endpoint returns the current OS user and port when requested with a valid token.

## GUI usage

```bash
python main.py
```

Select the connection mode, set the port, token and timeout, and press **Start**. The URL and token appear in the Connection Info panel. Press **Stop** or close the window to clean up.

## Terminal usage

```bash
python main.py --no-gui --mode local --port 8999 --timeout 30
python main.py --no-gui --mode cloudflare --port 8999 --token "my-secret-token"
```

Available arguments:

| Argument | Default | Description |
|---|---|---|
| `--mode` | `local` | `local` or `cloudflare` |
| `--port` | `8999` | Local HTTP port |
| `--token` | random | Bearer token |
| `--timeout` | `30` | Max seconds a command may run |
| `--no-gui` | off | Run in terminal mode (also used automatically when tkinter is missing) |

## Client example

```bash
curl -X POST https://<url> \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"command": "echo hello"}'
```

Response:

```json
{"stdout": "hello\n", "stderr": "", "exit_code": 0}
```

## Security hardening

- **Bearer token auth** — constant-time comparison via `secrets.compare_digest`.
- **Command timeout** — commands are killed after the configured timeout (default 30s).
- **Request size limit** — bodies larger than `MAX_BODY_SIZE` (1 MB) are rejected with `413`.
- **Brute-force protection** — after `MAX_FAILED_ATTEMPTS` (5) failed auth attempts from the same IP, that IP is locked out with `429` responses. Lockout duration starts at `LOCKOUT_SECONDS` (60s) and **doubles on every subsequent lockout**.
- **ThreadingHTTPServer** — concurrent requests don't block each other.
- **Ephemeral exposure** — the tunnel URL and token only exist for the lifetime of the process; stopping it tears down the tunnel and removes the log file.

## Configuration

All tunables live at the top of `main.py`:

| Constant | Default | Description |
|---|---|---|
| `DEFAULT_PORT` | `8999` | Local port the HTTP server listens on |
| `DEFAULT_CMD_TIMEOUT` | `30` | Max seconds a remote command may run |
| `MAX_BODY_SIZE` | `1 MB` | Max accepted request body size |
| `MAX_FAILED_ATTEMPTS` | `5` | Failed auth attempts before lockout |
| `LOCKOUT_SECONDS` | `60` | Base lockout duration (doubles per repeat offense) |

## Building an executable (Windows)

Install PyInstaller and build both a windowed GUI executable and a console executable from the same script:

```bash
pip install pyinstaller

pyinstaller --onefile --windowed --name Warp --icon=app_icon.ico --add-data "app_icon.ico;." main.py
pyinstaller --onefile --console --name WarpConsole --icon=app_icon.ico --add-data "app_icon.ico;." main.py
```

Output binaries are placed in `dist/`:

- **`Warp.exe`** — no console window, launches straight into the GUI.
- **`WarpConsole.exe`** — keeps a console window, needed for `--no-gui` terminal usage.

## Requirements

- Python 3.7+ (standard library only, no external dependencies).
- Windows or Linux/macOS.
- `cloudflared` is downloaded automatically for Cloudflare mode.

## Disclaimer

This tool grants **full remote shell access** to whoever holds the URL + token. Keep the connection details private, and stop the server when you're done using it.
