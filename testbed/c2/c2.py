"""Lab-only fake command-and-control server for the beacon and miner attacks.

HTTP on port 9000: GET returns one harmless command, POST accepts command output.
TCP on port 3333: a fake mining pool that reads one line per connection.
Runs in the c2-server container, whose hostname does not start with "fs-", so the
collector never records it: it plays attacker infrastructure, not a monitored host.
"""
import random
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COMMANDS = ["id", "whoami", "uname -a", "hostname", "ls /tmp"]


class Beacon(BaseHTTPRequestHandler):
    def do_GET(self):
        body = random.choice(COMMANDS).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
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
    print("c2-server: http :9000, pool :3333", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 9000), Beacon).serve_forever()
