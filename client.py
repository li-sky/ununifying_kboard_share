import json
import re
import socket
import ssl
import sys
import ctypes
import threading
import time
import platform
import subprocess
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple
from urllib import request

IS_WINDOWS = platform.system().lower() == "windows"

if IS_WINDOWS:
    from pynput import mouse
    from pynput.keyboard import Controller, Key, KeyCode

    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    _user32 = ctypes.windll.user32
else:
    mouse = None
    Controller = None
    Key = None
    KeyCode = None
    try:
        from linux_input import EvdevMouseWatcher, UInputKeyboardInjector, find_mice
    except Exception:
        EvdevMouseWatcher = None
        UInputKeyboardInjector = None
        find_mice = None


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
    "auto_trust_first_seen": False,
    "require_interactive_trust": True,
    "linux_mouse_devices": None,
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
AUTO_TRUST_FIRST_SEEN = bool(CONFIG.get("auto_trust_first_seen", False))
REQUIRE_INTERACTIVE_TRUST = bool(CONFIG.get("require_interactive_trust", True))


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
            interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())
            if interactive and REQUIRE_INTERACTIVE_TRUST:
                answer = input("是否信任该指纹? (yes/no): ").strip().lower()
                if answer not in {"y", "yes"}:
                    raise RuntimeError("用户拒绝指纹，终止连接。")
            elif AUTO_TRUST_FIRST_SEEN:
                print("[SECURE] 已启用 auto_trust_first_seen，自动信任新指纹。")
            else:
                raise RuntimeError(
                    "首次连接需要人工确认指纹。请先前台运行一次，或在配置中设置 auto_trust_first_seen=true。"
                )
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
    print(f"[VPS] 正在尝试上报，payload: {payload}")
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
last_activity_ts = time.time()
last_state_sent_ts = 0.0
last_sent_state = "INACTIVE"
last_activity_log_ts = 0.0
IDLE_TO_INACTIVE_SECONDS = max(1.5, HEARTBEAT_INTERVAL * 2.0)
ACTIVITY_LOG_INTERVAL = 5.0
active_conns_lock = threading.Lock()
active_conns: List[socket.socket] = []


def _inject_windows(action: str, payload: str):
    # payload can be VK int string or Linux-style KEY_* name.
    if Controller is None:
        return

    try:
        if payload.isdigit():
            vk_code = int(payload)
            key = KeyCode.from_vk(vk_code)
            if action == "P":
                kb.press(key)
            elif action == "R":
                kb.release(key)
            return
    except Exception:
        pass

    key_name = payload
    if not isinstance(key_name, str) or not key_name.startswith("KEY_"):
        return

    # Minimal mapping for common keys.
    special_map = {
        "KEY_SPACE": Key.space if Key else None,
        "KEY_ENTER": Key.enter if Key else None,
        "KEY_TAB": Key.tab if Key else None,
        "KEY_BACKSPACE": Key.backspace if Key else None,
        "KEY_ESC": Key.esc if Key else None,
        "KEY_LEFTCTRL": Key.ctrl_l if Key else None,
        "KEY_RIGHTCTRL": Key.ctrl_r if Key else None,
        "KEY_LEFTSHIFT": Key.shift_l if Key else None,
        "KEY_RIGHTSHIFT": Key.shift_r if Key else None,
        "KEY_LEFTALT": Key.alt_l if Key else None,
        "KEY_RIGHTALT": Key.alt_r if Key else None,
        "KEY_CAPSLOCK": Key.caps_lock if Key else None,
        "KEY_UP": Key.up if Key else None,
        "KEY_DOWN": Key.down if Key else None,
        "KEY_LEFT": Key.left if Key else None,
        "KEY_RIGHT": Key.right if Key else None,
        "KEY_HOME": Key.home if Key else None,
        "KEY_END": Key.end if Key else None,
        "KEY_PAGEUP": Key.page_up if Key else None,
        "KEY_PAGEDOWN": Key.page_down if Key else None,
        "KEY_DELETE": Key.delete if Key else None,
        "KEY_INSERT": Key.insert if Key else None,
    }

    mapped = special_map.get(key_name)
    if mapped is not None:
        if action == "P":
            kb.press(mapped)
        elif action == "R":
            kb.release(mapped)
        return

    # KEY_A..KEY_Z
    if len(key_name) == 5 and key_name.startswith("KEY_"):
        ch = key_name[-1]
        if "A" <= ch <= "Z" and KeyCode is not None:
            key = KeyCode.from_char(ch.lower())
            if action == "P":
                kb.press(key)
            elif action == "R":
                kb.release(key)
            return

    # KEY_0..KEY_9
    if len(key_name) == 5 and key_name.startswith("KEY_"):
        ch = key_name[-1]
        if "0" <= ch <= "9" and KeyCode is not None:
            key = KeyCode.from_char(ch)
            if action == "P":
                kb.press(key)
            elif action == "R":
                kb.release(key)


def _inject_linux(injector: "UInputKeyboardInjector", action: str, payload: str):
    if injector is None:
        return
    if not isinstance(payload, str):
        return

    if payload.isdigit():
        # Windows VK code cannot be used on Linux reliably.
        return

    key_name = payload
    if action == "P":
        injector.press_key_name(key_name)
    elif action == "R":
        injector.release_key_name(key_name)


def mark_local_activity():
    global last_activity_ts, last_activity_log_ts
    now = time.time()
    last_activity_ts = now
    if now - last_activity_log_ts >= ACTIVITY_LOG_INTERVAL:
        print("[HB] 检测到鼠标活动")
        last_activity_log_ts = now
    send_heartbeat_state("ACTIVE", force=False)


def send_heartbeat_state(state: str, force: bool = False):
    global last_state_sent_ts, last_sent_state
    now = time.time()
    state = state.upper().strip()
    if state not in {"ACTIVE", "INACTIVE"}:
        return
    if not force and state == last_sent_state and (now - last_state_sent_ts < HEARTBEAT_INTERVAL):
        return

    payload = f"HEARTBEAT {state} {LOCAL_ID}\n".encode("utf-8")
    failed = 0
    sent = 0
    with active_conns_lock:
        conns = list(active_conns)

    if not conns:
        return

    for conn in conns:
        try:
            conn.sendall(payload)
            sent += 1
        except Exception as exc:
            failed += 1
            print(f"[HB] 心跳发送失败: {exc}")

    if sent > 0:
        print(f"[HB] 发送 {state} 到 {sent} 个连接")
        last_state_sent_ts = now
        last_sent_state = state
    if failed > 0:
        print(f"[HB] {failed} 个连接发送失败")


def heartbeat_sender_thread(stop_event: threading.Event):
    while not stop_event.is_set():
        now = time.time()
        is_active = (now - last_activity_ts) <= IDLE_TO_INACTIVE_SECONDS
        desired_state = "ACTIVE" if is_active else "INACTIVE"
        send_heartbeat_state(desired_state, force=False)
        time.sleep(0.05)


def on_move(x, y):
    mark_local_activity()


def _get_cursor_pos() -> Tuple[int, int] | None:
    if not IS_WINDOWS:
        return None
    pt = POINT()
    if _user32.GetCursorPos(ctypes.byref(pt)):
        return pt.x, pt.y
    return None


def poll_mouse_activity_windows(stop_event: threading.Event):
    if not IS_WINDOWS:
        return
    last_pos = _get_cursor_pos()
    while not stop_event.is_set():
        pos = _get_cursor_pos()
        if pos is not None and pos != last_pos:
            last_pos = pos
            mark_local_activity()
        time.sleep(0.05)


def handle_connection(raw_conn: socket.socket, addr):
    ctx = get_server_ssl_context()
    try:
        tls_conn = ctx.wrap_socket(raw_conn, server_side=True)
    except Exception as exc:
        raw_conn.close()
        print(f"[TLS] 握手失败 {addr}: {exc}")
        return

    try:
        print(f"[TCP] 入站连接: {addr}")
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
                print(f"[TCP] 指纹确认: {sender_id} -> {_format_fingerprint(sender_fp_str)}")
            else:
                raise RuntimeError("HELLO 格式错误")
        else:
            raise RuntimeError("未收到 HELLO 指纹交换消息")

        # 如果 TLS 提供了证书，也记录一下（可选）
        if peer_fp:
            print(f"[TLS] 对端证书指纹 {_format_fingerprint(peer_fp)}")
        report_ips("connected")
        with active_conns_lock:
            active_conns.append(tls_conn)
        initial_state = "ACTIVE" if (time.time() - last_activity_ts) <= IDLE_TO_INACTIVE_SECONDS else "INACTIVE"
        send_heartbeat_state(initial_state, force=True)

        injector = None
        if not IS_WINDOWS:
            if UInputKeyboardInjector is None:
                raise RuntimeError("Linux 模式需要 evdev/uinput：请安装 `pip install evdev` 并确保可访问 /dev/uinput")
            injector = UInputKeyboardInjector()

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
                    action, payload = msg.split(':', 1)
                    action = action.strip().upper()
                    payload = payload.strip()
                    if IS_WINDOWS:
                        _inject_windows(action, payload)
                    else:
                        _inject_linux(injector, action, payload)
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
        with active_conns_lock:
            try:
                active_conns.remove(tls_conn)
            except ValueError:
                pass
        global last_sent_state, last_state_sent_ts
        last_sent_state = "INACTIVE"
        last_state_sent_ts = 0.0
        report_ips("disconnect")
        print("[TCP] 等待新的连接...")


# --- 2. TCP 接收 (键盘指令) ---
def tcp_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', TCP_PORT))
    server_sock.listen(2)
    print(f"[CONF] 本机ID: {LOCAL_ID} 对端ID: {REMOTE_ID}")
    print(f"[TCP] TLS 服务监听 {TCP_PORT} ...")

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
    hb_stop_event = threading.Event()
    threading.Thread(target=heartbeat_sender_thread, args=(hb_stop_event,), daemon=True).start()

    print("Client: 运行中... 按 Ctrl+C 退出")
    try:
        if IS_WINDOWS:
            threading.Thread(target=poll_mouse_activity_windows, args=(hb_stop_event,), daemon=True).start()
            try:
                with mouse.Listener(on_move=on_move) as listener:
                    listener.join()
            except Exception as exc:
                print(f"[HB] pynput 鼠标监听失败，回退到光标轮询: {exc}")
                while True:
                    time.sleep(1)
        else:
            mouse_paths = CONFIG.get("linux_mouse_devices")
            if mouse_paths and not isinstance(mouse_paths, list):
                mouse_paths = None

            if EvdevMouseWatcher is None or find_mice is None:
                raise RuntimeError("Linux 模式需要 evdev：请安装 `pip install evdev`")

            mice = find_mice(mouse_paths)
            if not mice:
                raise RuntimeError("未找到鼠标设备。可在 config_client.json 设置 linux_mouse_devices: [\"/dev/input/eventX\"]")

            EvdevMouseWatcher(mice, on_activity=mark_local_activity).start()
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        if IS_WINDOWS:
            try:
                hb_stop_event.set()
            except Exception:
                pass
        report_ips("shutdown")