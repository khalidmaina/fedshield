"""Lab-only fake C2 server. Answers beacons with harmless commands and accepts
connections on a fake mining-pool port. It runs in its own container, which is not
monitored (its hostname does not start with "fs-")."""
import random
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

COMMANDS = ["id", "whoami", "uname -a", "hostname", "ls /tmp"]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = random.choice(COMMANDS).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


class Pool(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(1024)


if __name__ == "__main__":
    pool = socketserver.ThreadingTCPServer(("0.0.0.0", 3333), Pool)
    threading.Thread(target=pool.serve_forever, daemon=True).start()
    print("C2 lab server on :9000 (http) and :3333 (pool)", flush=True)
    HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
