import os
import re
import sys
import json
import time
import secrets
import threading
import subprocess
import http.server
import urllib.request

PORT = 8999
TOKEN = secrets.token_hex(16)
TEMP_DIR = os.environ.get("TEMP", "/tmp")
CF_EXE = os.path.join(TEMP_DIR, "cloudflared.exe" if os.name == "nt" else "cloudflared")
LOG_FILE = os.path.join(TEMP_DIR, "tunnel.log")
AUDIT_LOG_FILE = os.path.join(os.getcwd(), "hermes_audit.log")

_audit_lock = threading.Lock()

CMD_TIMEOUT = 30            # seconds, kill commands that hang
MAX_BODY_SIZE = 1 * 1024 * 1024   # 1 MB request body limit
MAX_FAILED_ATTEMPTS = 5     # failed auth attempts before lockout
LOCKOUT_SECONDS = 60        # lockout duration per client IP

_failed_attempts = {}  # ip -> (count, first_attempt_ts)
_lockouts = {}          # ip -> lockout_until_ts
_lockout_level = {}     # ip -> number of times locked out (for exponential backoff)

# 1. Download cloudflared if missing
if not os.path.exists(CF_EXE):
    print("📥 Downloading cloudflared binary...")
    url = (
        "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
        if os.name == "nt"
        else "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    )
    urllib.request.urlretrieve(url, CF_EXE)
    if os.name != "nt":
        os.chmod(CF_EXE, 0o755)

# 2. Audit log helper
def audit_log(ip, cmd, status, exit_code=None):
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "command": cmd,
        "status": status,
        "exit_code": exit_code
    }
    with _audit_lock:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

# 3. HTTP Handler
class RemoteHandler(http.server.BaseHTTPRequestHandler):
    def _is_locked_out(self, ip):
        lockout_until = _lockouts.get(ip)
        if lockout_until and time.time() < lockout_until:
            return True
        if lockout_until:
            # lockout expired, reset state
            _lockouts.pop(ip, None)
            _failed_attempts.pop(ip, None)
        return False

    def _register_failed_attempt(self, ip):
        count, first_ts = _failed_attempts.get(ip, (0, time.time()))
        count += 1
        _failed_attempts[ip] = (count, first_ts)
        if count >= MAX_FAILED_ATTEMPTS:
            level = _lockout_level.get(ip, 0)
            duration = LOCKOUT_SECONDS * (2 ** level)
            _lockouts[ip] = time.time() + duration
            _lockout_level[ip] = level + 1
            _failed_attempts.pop(ip, None)

    def do_POST(self):
        ip = self.client_address[0]

        if self._is_locked_out(ip):
            self.send_response(429)
            self.end_headers()
            return

        auth = self.headers.get("Authorization", "")
        if not secrets.compare_digest(auth, f"Bearer {TOKEN}"):
            self._register_failed_attempt(ip)
            self.send_response(403)
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY_SIZE:
                self.send_response(413)
                self.end_headers()
                return

            data = json.loads(self.rfile.read(length))
            cmd = data.get("command")

            res = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=CMD_TIMEOUT
            )
            payload = {"stdout": res.stdout, "stderr": res.stderr, "exit_code": res.returncode}
            status = 200
            audit_log(ip, cmd, "executed", res.returncode)
        except subprocess.TimeoutExpired:
            payload = {"error": f"Command timed out after {CMD_TIMEOUT}s"}
            status = 408
            audit_log(ip, cmd if 'cmd' in locals() else None, "timeout")
        except Exception as e:
            payload = {"error": str(e)}
            status = 400
            audit_log(ip, cmd if 'cmd' in locals() else None, f"error: {e}")

        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def log_message(self, format, *args):
        pass

# 4. Clipboard helper
def copy_to_clipboard(text):
    try:
        if os.name == "nt":
            subprocess.run("clip", input=text.encode("utf-16-le"), shell=True, check=True)
        else:
            subprocess.run("pbcopy" if sys.platform == "darwin" else "xclip -selection clipboard",
                            input=text.encode("utf-8"), shell=True, check=True)
        print("📋 Copied URL & TOKEN to clipboard.")
    except Exception as e:
        print(f"⚠️ Could not copy to clipboard: {e}")

# 5. Kill any orphaned cloudflared processes (not just the tracked one)
def kill_orphaned_cloudflared(tracked_pid):
    try:
        if os.name == "nt":
            out = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq cloudflared.exe", "/FO", "CSV", "/NH"],
                capture_output=True, text=True
            ).stdout
            for line in out.splitlines():
                parts = [p.strip('"') for p in line.split(",")]
                if len(parts) >= 2 and parts[1].isdigit():
                    pid = int(parts[1])
                    if pid != tracked_pid:
                        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        else:
            out = subprocess.run(["pgrep", "-f", "cloudflared"], capture_output=True, text=True).stdout
            for line in out.splitlines():
                pid = int(line.strip())
                if pid != tracked_pid:
                    subprocess.run(["kill", "-9", str(pid)], capture_output=True)
    except Exception as e:
        print(f"⚠️ Could not clean up orphaned cloudflared processes: {e}")

# 6. Main runner
def main():
    print("🚀 Starting Satellite Server...")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), RemoteHandler)

    log_fd = open(LOG_FILE, "w", encoding="utf-8")
    cf_proc = subprocess.Popen([CF_EXE, "tunnel", "--url", f"http://localhost:{PORT}"], stdout=log_fd, stderr=log_fd)

    print("⏳ Waiting for Tunnel URL...")
    url = None
    for _ in range(15):
        time.sleep(1)
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    match = re.search(r"https://[-0-9a-z]+\.trycloudflare\.com", content)
                    if match:
                        url = match.group(0)
                        break
            except Exception:
                pass

    if url:
        print("\n====================================================")
        print("✅ REMOTE ACCESS READY")
        print(f"🔗 URL: {url}")
        print(f"🔑 TOKEN: {TOKEN}")
        print("====================================================")
        copy_to_clipboard("/hermes-remote-connectivity "+"\n"
                          "\n====================================================" +"\n"+
                          "✅ REMOTE ACCESS READY" + "\n" +
                          f"URL: {url}\nTOKEN: {TOKEN}"+
                          "\n"+"====================================================")


        print("Ctrl+c to stop and clean up.\n")
    else:
        print("❌ Failed to resolve Tunnel URL.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🧹 Cleaning up...")
        cf_proc.terminate()
        kill_orphaned_cloudflared(cf_proc.pid)
        log_fd.close()
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
        print("👋 Session closed.")

if __name__ == "__main__":
    main()