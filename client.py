import json
import re
import socket
import ssl
import threading
import time
import platform
import subprocess
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple
from urllib import request

from pynput import mouse
from pynput.keyboard import Controller, KeyCode


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config_client.json"


def ensure_path(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


DEFAULT_CONFIG = {
    "local_id": "client",
    "remote_id": "host",
    "tcp_port": 5005,
    "remote_udp_port": 5005,
    "udp_port": 0,
    "cert_file": "certs/client_cert.pem",
    "key_file": "certs/client_key.pem",
    "trust_store": "client_trust.json",
    "fallback_remote_ips": [],
    "vps_base_url": "",
    "vps_ca_cert": None,
    "allow_insecure_vps": False,
    "ip_report_interval": 300,
    "remote_refresh_interval": 30,
    "heartbeat_interval": 2.0,
}


def load_config() -> Dict:
    if not CONFIG_PATH.exists():
        ensure_path(CONFIG_PATH)
        CONFIG_PATH.write_text(json.dumps({"local_id": "client", "remote_id": "host"}, indent=2), encoding="utf-8")
    user_cfg = load_json(CONFIG_PATH, {})
    cfg = DEFAULT_CONFIG.copy()
    if isinstance(user_cfg, dict):
        cfg.update({k: v for k, v in user_cfg.items() if v is not None})
    return cfg


CONFIG = load_config()

LOCAL_ID = CONFIG["local_id"]
REMOTE_ID = CONFIG["remote_id"]
TCP_PORT = int(CONFIG.get("tcp_port", 5005))
REMOTE_UDP_PORT = int(CONFIG.get("remote_udp_port", TCP_PORT))
LOCAL_UDP_PORT = int(CONFIG.get("udp_port", 0))
CERT_FILE = (BASE_DIR / CONFIG.get("cert_file", "certs/client_cert.pem")).resolve()
KEY_FILE = (BASE_DIR / CONFIG.get("key_file", "certs/client_key.pem")).resolve()
TRUST_PATH = (BASE_DIR / CONFIG.get("trust_store", "client_trust.json")).resolve()
FALLBACK_REMOTE_IPS = CONFIG.get("fallback_remote_ips", [])
VPS_BASE_URL = CONFIG.get("vps_base_url", "").rstrip("/")
VPS_CA_CERT = CONFIG.get("vps_ca_cert")
ALLOW_INSECURE_VPS = bool(CONFIG.get("allow_insecure_vps", False))
IP_REPORT_INTERVAL = max(60, int(CONFIG.get("ip_report_interval", 300)))
REMOTE_REFRESH_INTERVAL = max(5, int(CONFIG.get("remote_refresh_interval", 30)))
HEARTBEAT_INTERVAL = max(0.2, float(CONFIG.get("heartbeat_interval", 2.0)))


def ensure_certificates():
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    ensure_path(CERT_FILE)
    ensure_path(KEY_FILE)
    subj = f"/CN={LOCAL_ID}"
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-days",
        "365",
        "-nodes",
        "-keyout",
        str(KEY_FILE),
        "-out",
        str(CERT_FILE),
        "-subj",
        subj,
    ]
    try:
        print(f"[SECURE] 未发现证书，自动生成自签名证书: {CERT_FILE.name}")
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError("未找到 openssl，可自行安装后重新运行，或手动提供证书。") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"证书生成失败: {exc.stderr.strip() or exc.stdout.strip()}") from exc


ensure_certificates()


def load_trust_store() -> Dict[str, str]:
    if not TRUST_PATH.exists():
        return {}
    try:
        return json.loads(TRUST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


trust_store_lock = threading.Lock()
trust_store = load_trust_store()


def save_trust_store():
    ensure_path(TRUST_PATH)
    TRUST_PATH.write_text(json.dumps(trust_store, indent=2), encoding="utf-8")


def _format_fingerprint(hex_string: str) -> str:
    return ":".join(hex_string[i:i + 2] for i in range(0, len(hex_string), 2)).upper()


def _compute_fp_from_der(der_bytes: bytes) -> str:
    return hashlib.sha256(der_bytes).hexdigest()


def load_local_fingerprint() -> str:
    pem_data = CERT_FILE.read_text(encoding="utf-8")
    der = ssl.PEM_cert_to_DER_cert(pem_data)
    return _compute_fp_from_der(der)


LOCAL_FINGERPRINT = load_local_fingerprint()


def print_fingerprint_banner():
    print(f"[SECURE] 本机 {LOCAL_ID} 指纹: {_format_fingerprint(LOCAL_FINGERPRINT)}")
    expected = trust_store.get(REMOTE_ID)
    if expected:
        print(f"[SECURE] 期望 {REMOTE_ID} 指纹: {_format_fingerprint(expected)}")
    else:
        print(f"[SECURE] 未记录 {REMOTE_ID} 指纹，首次连接需人工确认。")


def ensure_peer_trust(peer_id: str, fingerprint: str):
    with trust_store_lock:
        known = trust_store.get(peer_id)
        formatted = _format_fingerprint(fingerprint)
        if known and known != fingerprint:
            raise RuntimeError(f"指纹不匹配: {peer_id} -> {formatted}")
        if not known:
            print(f"[SECURE] 检测到新的指纹 {peer_id}: {formatted}")
            answer = input("是否信任该指纹? (yes/no): ").strip().lower()
            if answer not in {"y", "yes"}:
                raise RuntimeError("用户拒绝指纹，终止连接。")
            trust_store[peer_id] = fingerprint
            save_trust_store()
            print(f"[SECURE] 已信任 {peer_id}。")


def collect_local_ips() -> List[str]:
    ips = set()
    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for info in infos:
            ip = str(info[4][0])
            if ip and not ip.startswith("127."):
                ips.add(ip)
    except socket.gaierror:
        pass

    cmd = ["ipconfig"] if platform.system().lower() == "windows" else ["ip", "-o", "addr", "show"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        ips.update(
            ip for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", result.stdout)
            if ip and not ip.startswith("127.")
        )
    except Exception:
        pass

    return sorted(ips)


if ALLOW_INSECURE_VPS:
    VPS_SSL_CONTEXT = ssl._create_unverified_context()
else:
    VPS_SSL_CONTEXT = ssl.create_default_context()
    if VPS_CA_CERT:
        VPS_SSL_CONTEXT.load_verify_locations(cafile=str((BASE_DIR / VPS_CA_CERT).resolve()))


def report_ips(event_name: str):
    if not VPS_BASE_URL:
        return
    payload = json.dumps({
        "node_id": LOCAL_ID,
        "ips": collect_local_ips(),
        "tcp_port": TCP_PORT,
        "udp_port": LOCAL_UDP_PORT,
        "event": event_name,
    }).encode("utf-8")
    try:
        req = request.Request(f"{VPS_BASE_URL}/report", data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        with request.urlopen(req, timeout=5, context=VPS_SSL_CONTEXT):
            pass
    except Exception as exc:
        print(f"[VPS] 上报失败: {exc}")


remote_cache = {
    "ips": FALLBACK_REMOTE_IPS[:],
    "tcp_port": TCP_PORT,
    "udp_port": REMOTE_UDP_PORT,
    "ts": 0.0,
}


def fetch_remote_descriptor() -> Tuple[List[str], int, int]:
    now = time.time()
    if now - remote_cache["ts"] < REMOTE_REFRESH_INTERVAL:
        return remote_cache["ips"], remote_cache["tcp_port"], remote_cache["udp_port"]

    if VPS_BASE_URL:
        try:
            with request.urlopen(f"{VPS_BASE_URL}/node/{REMOTE_ID}", timeout=5, context=VPS_SSL_CONTEXT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                ips = data.get("ips", [])
                tcp_port = int(data.get("tcp_port", TCP_PORT))
                udp_port = int(data.get("udp_port", REMOTE_UDP_PORT))
                if ips:
                    remote_cache.update({"ips": ips, "tcp_port": tcp_port, "udp_port": udp_port, "ts": now})
                    return ips, tcp_port, udp_port
        except Exception:
            pass

    return remote_cache["ips"], remote_cache["tcp_port"], remote_cache["udp_port"]


def ip_reporter_thread():
    while True:
        report_ips("periodic")
        time.sleep(IP_REPORT_INTERVAL)


ssl_context_lock = threading.Lock()
_server_ssl_context = None


def get_server_ssl_context() -> ssl.SSLContext:
    global _server_ssl_context
    with ssl_context_lock:
        if _server_ssl_context is None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            # 使用 TOFU 指纹校验，不做 CA 验证
            ctx.verify_mode = ssl.CERT_NONE
            ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
            _server_ssl_context = ctx
        return _server_ssl_context


kb = Controller()
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
last_heartbeat = 0.0


def resolve_remote_udp_target():
    ips, _, udp_port = fetch_remote_descriptor()
    if not ips:
        return None
    return ips[0], udp_port


# --- 1. UDP 发送 (鼠标信号) ---
def send_heartbeat():
    global last_heartbeat
    now = time.time()
    if now - last_heartbeat < HEARTBEAT_INTERVAL:
        return
    target = resolve_remote_udp_target()
    if not target:
        return
    try:
        payload = f"MOUSE_ACTIVE:{LOCAL_ID}".encode("utf-8")
        udp_sock.sendto(payload, target)
        last_heartbeat = now
    except OSError as exc:
        print(f"[UDP] 心跳发送失败: {exc}")


def on_move(x, y):
    send_heartbeat()


def handle_connection(raw_conn: socket.socket, addr):
    ctx = get_server_ssl_context()
    try:
        tls_conn = ctx.wrap_socket(raw_conn, server_side=True)
    except Exception as exc:
        raw_conn.close()
        print(f"[TLS] 握手失败 {addr}: {exc}")
        return

    try:
        # 若服务器未请求对端证书，则改用应用层指纹交换
        peer_der = tls_conn.getpeercert(binary_form=True)
        peer_fp = _compute_fp_from_der(peer_der) if peer_der else None

        buffer = ""
        # 首条消息应为 HELLO
        while "\n" not in buffer:
            data = tls_conn.recv(4096)
            if not data:
                raise RuntimeError("连接初始化失败：未收到 HELLO")
            buffer += data.decode()
        first_line, buffer = buffer.split("\n", 1)

        if first_line.startswith("HELLO "):
            parts = first_line.split(" ")
            if len(parts) >= 3:
                sender_id = parts[1]
                sender_fp_str = parts[2].replace(":", "").lower()
                ensure_peer_trust(sender_id, sender_fp_str)
                print(f"[TCP] 来自 {sender_id}@{addr} 指纹 {_format_fingerprint(sender_fp_str)}")
            else:
                raise RuntimeError("HELLO 格式错误")
        else:
            raise RuntimeError("未收到 HELLO 指纹交换消息")

        # 如果 TLS 提供了证书，也记录一下（可选）
        if peer_fp:
            print(f"[TLS] 对端证书指纹 {_format_fingerprint(peer_fp)}")
        report_ips("connected")

        while True:
            data = tls_conn.recv(4096)
            if not data:
                break
            buffer += data.decode()
            while "\n" in buffer:
                msg, buffer = buffer.split("\n", 1)
                if not msg:
                    continue
                try:
                    action, code_str = msg.split(':')
                    vk_code = int(code_str)
                    key = KeyCode.from_vk(vk_code)
                    if action == 'P':
                        kb.press(key)
                    elif action == 'R':
                        kb.release(key)
                except Exception:
                    pass
    except Exception as exc:
        print(f"[TCP] 连接异常: {exc}")
    finally:
        try:
            tls_conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        tls_conn.close()
        report_ips("disconnect")
        print("[TCP] 等待新的连接...")


# --- 2. TCP 接收 (键盘指令) ---
def tcp_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', TCP_PORT))
    server_sock.listen(2)
    print(f"Client: TLS 服务监听 {TCP_PORT} ...")

    while True:
        conn, addr = server_sock.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    print_fingerprint_banner()
    report_ips("startup")

    if VPS_BASE_URL:
        threading.Thread(target=ip_reporter_thread, daemon=True).start()

    t_tcp = threading.Thread(target=tcp_server, daemon=True)
    t_tcp.start()

    print("Client: 运行中... 按 Ctrl+C 退出")
    try:
        with mouse.Listener(on_move=on_move) as listener:
            listener.join()
    except KeyboardInterrupt:
        pass
    finally:
        report_ips("shutdown")