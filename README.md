# Hermes Remote Connectivity

A lightweight remote command execution server. It exposes a local machine over the internet through a [Cloudflare Tunnel](https://github.com/cloudflare/cloudflared), letting an authenticated client run shell commands remotely and get back `stdout`/`stderr`/exit code as JSON.

## How it works

1. **`main.py`** downloads the `cloudflared` binary automatically (if missing) into the system temp directory.
2. It starts a local `ThreadingHTTPServer` on `127.0.0.1:8999` (`RemoteHandler`) that accepts `POST` requests with a JSON body: `{"command": "<shell command>"}`.
3. `cloudflared` opens a **Quick Tunnel**, exposing the local server via a random `https://<random>.trycloudflare.com` URL. TLS termination happens at the Cloudflare edge, so the public endpoint is already HTTPS.
4. A random 32-character `TOKEN` (`secrets.token_hex(16)`) is generated per run. Every request must include `Authorization: Bearer <TOKEN>`.
5. Once the tunnel URL is resolved, the URL + token are printed to the console **and copied to the clipboard** automatically (`copy_to_clipboard`), prefixed with `/hermes-remote-connectivity`.
6. Press `Ctrl+C` to stop: the tunnel process is terminated, the log file is deleted, and the server shuts down cleanly.

## Usage

```bash
python main.py
```

Example request from a client:

```bash
curl -X POST https://<random>.trycloudflare.com \
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
- **Command timeout** — commands are killed after `CMD_TIMEOUT` (30s) to prevent hangs.
- **Request size limit** — bodies larger than `MAX_BODY_SIZE` (1 MB) are rejected with `413`.
- **Brute-force protection** — after `MAX_FAILED_ATTEMPTS` (5) failed auth attempts from the same IP, that IP is locked out with `429` responses. Lockout duration starts at `LOCKOUT_SECONDS` (60s) and **doubles on every subsequent lockout** (exponential backoff), and never resets for the lifetime of the process.
- **ThreadingHTTPServer** — concurrent requests don't block each other (important since commands can take up to `CMD_TIMEOUT` seconds).
- **Ephemeral exposure** — the tunnel URL and token only exist for the lifetime of the process; stopping it (`Ctrl+C`) tears down the tunnel and removes the log file.

## Configuration

All tunables live at the top of `main.py`:

| Constant | Default | Description |
|---|---|---|
| `PORT` | `8999` | Local port the HTTP server listens on |
| `CMD_TIMEOUT` | `30` | Max seconds a remote command may run |
| `MAX_BODY_SIZE` | `1 MB` | Max accepted request body size |
| `MAX_FAILED_ATTEMPTS` | `5` | Failed auth attempts before lockout |
| `LOCKOUT_SECONDS` | `60` | Base lockout duration (doubles per repeat offense) |

## Requirements

- Python 3.7+ (standard library only, no external dependencies).
- Windows or Linux/macOS (clipboard copy uses `clip`, `pbcopy`, or `xclip` respectively).

## Disclaimer

This tool grants **full remote shell access** to whoever holds the URL + token. Keep the console output private, and stop the server (`Ctrl+C`) when you're done using it.
