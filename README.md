# Warp

A lightweight remote command execution server with a small Tkinter control panel and a terminal mode. It supports two ways to expose the local HTTP server: **Local network** and **Cloudflare Tunnel**. An authenticated client can run shell commands remotely and get back `stdout`/`stderr`/exit code as JSON.

## Why this exists

Warp is a bridge that gives a **sandboxed AI agent temporary terminal access to a specific machine** — without installing anything on that machine.

The problem it solves: an AI coding/ops agent running in its own sandbox can't reach into another server to actually run commands there. Sometimes you need it to — for example, to **debug a live issue** on a box where reproducing the problem locally isn't possible.

With Warp you:

1. Run this single, dependency-free script on the target machine (or a prebuilt binary — nothing to install).
2. Expose it over the LAN or a throwaway **Cloudflare Quick Tunnel**, which hands you a temporary public URL and a random bearer token.
3. Give that URL + token to your agent. It can now run shell commands on the machine and read back `stdout`/`stderr`/exit code to investigate and fix the problem.
4. Stop the server when you're done — the tunnel, URL and token all disappear with the process.

Because access is **token-gated and ephemeral**, the agent only has reach for as long as you keep Warp running. Every command it runs is written to an audit log so you can see exactly what it did.

> ⚠️ This grants real shell access to whoever holds the URL + token. Only run it on machines you control, hand the credentials only to your own agent, and stop it as soon as the debugging session is over. See [Disclaimer](#disclaimer).

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

| `--no-tls` | off | Disable HTTPS in local mode (HTTPS is on by default) |

To stop the terminal server, press **`q`** (or **Enter**). This shuts down gracefully on the main thread and releases the port. **Ctrl+C** also works as a fallback. A prebuilt binary whose name contains `console` or `cli` starts in terminal mode automatically, without `--no-gui`.

## Local HTTPS (TLS)

In **Local** mode the server speaks **HTTPS by default** so the bearer token and command output are encrypted on the LAN. It is fully transparent and leaves **nothing on disk**:

- On every start, Warp generates a fresh self-signed certificate with `openssl` in a temp file, loads it into the SSL context (which keeps it in memory), and **deletes the file immediately** — so no certificate is stored between runs, or even while the server is running.
- Because the cert is regenerated each run, its **SHA-256 fingerprint changes every time** (like the random token). Warp prints the fingerprint on startup and copies it to the clipboard with the URL and token, so you hand the current one to your client per session.

Because the certificate is self-signed, the client connects one of two ways:

- **Encrypt only** — skip verification (`curl -k`, or `verify=False`). This defeats passive LAN sniffing of the token, which is the main local threat.
- **Encrypt + authenticate the server** — pin the printed fingerprint (like an SSH host key), which also defends against active man-in-the-middle on the LAN:

  ```bash
  echo | openssl s_client -connect <ip>:<port> 2>/dev/null \
    | openssl x509 -fingerprint -sha256 -noout
  # compare the result to the SHA-256 Warp printed
  ```

**Cloudflare** mode is unaffected: the public hop is already TLS-terminated by Cloudflare, and Warp reaches the origin over loopback, so no local certificate is used. Pass `--no-tls` to serve plain HTTP in local mode if you really want it.

## Client example

```bash
# Cloudflare mode (public HTTPS URL):
curl -X POST https://<url> \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"command": "echo hello"}'

# Local mode (HTTPS with a self-signed cert — add -k, or pin the fingerprint):
curl -k -X POST https://<ip>:<port> \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"command": "echo hello"}'
```

Response:

```json
{"stdout": "hello\n", "stderr": "", "exit_code": 0}
```

## Security hardening

- **Encrypted transport** — local mode serves HTTPS by default via a persistent self-signed cert (see [Local HTTPS](#local-https-tls)); Cloudflare mode is TLS-terminated at the edge.
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

## Building an executable

The repo ships PyInstaller spec files. Install PyInstaller, then build from the spec (the same `main.py` powers both the GUI and CLI builds — the only difference is whether a window is attached):

```bash
pip install pyinstaller

# GUI build
pyinstaller --noconfirm AiRemoteAccess.spec        # -> dist/Warp
# CLI build
pyinstaller --noconfirm WarpCli.spec               # -> dist/warp-cli
```

> On distros with an externally-managed Python (e.g. Arch), create a venv first: `python -m venv .venv && .venv/bin/pip install pyinstaller`, then call `.venv/bin/pyinstaller`.

Output binaries are placed in `dist/`:

- **`Warp`** — no console window, launches straight into the GUI.
- **`warp-cli`** — console build; its name contains `cli`, so it starts in terminal mode automatically (no `--no-gui` needed).

The equivalent Windows one-liners (produce `Warp.exe` / `WarpConsole.exe`, both auto-detected as terminal builds by the `console`/`cli` name rule):

```bash
pyinstaller --onefile --windowed --name Warp --icon=app_icon.ico --add-data "app_icon.ico;." main.py
pyinstaller --onefile --console  --name WarpConsole --icon=app_icon.ico --add-data "app_icon.ico;." main.py
```

## Requirements

- Python 3.7+ (standard library only, no external dependencies).
- Windows or Linux/macOS.
- `cloudflared` is downloaded automatically for Cloudflare mode.

## Disclaimer

This tool grants **full remote shell access** to whoever holds the URL + token. Keep the connection details private, and stop the server when you're done using it.
