import argparse
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REGISTRY_LOCK = threading.Lock()


def load_registry(store_path: Path) -> dict:
    if not store_path.exists():
        return {}
    try:
        return json.loads(store_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_registry(store_path: Path, data: dict) -> None:
    store_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


class IPRegistryHandler(BaseHTTPRequestHandler):
    registry_path: Path = Path("registry.json")

    def _set_headers(self, status: int = 200, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()

    def do_POST(self):  # noqa: N802
        if self.path != "/report":
            self._set_headers(404)
            self.wfile.write(b"{}")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = self.rfile.read(content_length)
            data = json.loads(payload.decode("utf-8"))
        except Exception:
            self._set_headers(400)
            self.wfile.write(b"{\"error\": \"invalid json\"}")
            return

        required = {"node_id", "ips"}
        if not required.issubset(data):
            self._set_headers(400)
            self.wfile.write(b"{\"error\": \"missing fields\"}")
            return

        entry = {
            "node_id": data["node_id"],
            "ips": data.get("ips", []),
            "tcp_port": data.get("tcp_port"),
            "udp_port": data.get("udp_port"),
            "event": data.get("event", ""),
            "updated_at": time.time(),
        }

        with REGISTRY_LOCK:
            registry = load_registry(self.registry_path)
            registry[entry["node_id"]] = entry
            save_registry(self.registry_path, registry)

        self._set_headers(200)
        self.wfile.write(b"{\"status\": \"ok\"}")

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            self._set_headers(200)
            self.wfile.write(b"{\"status\": \"healthy\"}")
            return

        if not self.path.startswith("/node/"):
            self._set_headers(404)
            self.wfile.write(b"{}")
            return

        node_id = self.path.split("/node/", 1)[1]
        with REGISTRY_LOCK:
            registry = load_registry(self.registry_path)
            entry = registry.get(node_id)

        if not entry:
            self._set_headers(404)
            self.wfile.write(b"{\"error\": \"not found\"}")
            return

        self._set_headers(200)
        self.wfile.write(json.dumps(entry).encode("utf-8"))

    def log_message(self, format, *args):  # noqa: A003
        return


def main():
    parser = argparse.ArgumentParser(description="Minimal IP registry service")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", help="Path to TLS certificate (PEM)")
    parser.add_argument("--key", help="Path to TLS private key (PEM)")
    parser.add_argument("--store", default="registry.json", help="Path to registry data file")
    args = parser.parse_args()

    handler = IPRegistryHandler
    handler.registry_path = Path(args.store).resolve()

    server = ThreadingHTTPServer((args.host, args.port), handler)

    if args.cert and args.key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=args.cert, keyfile=args.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"Registry listening on {args.host}:{args.port} (TLS={'on' if args.cert else 'off'})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down registry...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
