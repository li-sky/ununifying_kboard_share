import sys
import time
import socket
import threading
import ctypes
import queue
import json
import ssl
import hashlib
import subprocess
import platform
import re
from pathlib import Path
from ctypes import wintypes, c_void_p, c_int, c_longlong, c_uint, POINTER, WINFUNCTYPE, cast, byref
from typing import Dict, List, Tuple
from urllib import request
from pynput import mouse


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config_host.json"


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
    "local_id": "host",
    "remote_id": "client",
    "tcp_port": 5005,
    "udp_port": 5005,
    "window_alpha": 0,
    "cert_file": "certs/host_cert.pem",
    "key_file": "certs/host_key.pem",
    "trust_store": "host_trust.json",
    "vps_base_url": "",
    "vps_ca_cert": None,
    "allow_insecure_vps": False,
    "ip_report_interval": 300,
    "remote_refresh_interval": 30,
    "fallback_remote_ips": [],
}


def load_config() -> Dict:
    if not CONFIG_PATH.exists():
        ensure_path(CONFIG_PATH)
        CONFIG_PATH.write_text(json.dumps({"local_id": "host", "remote_id": "client"}, indent=2), encoding="utf-8")
    user_cfg = load_json(CONFIG_PATH, {})
    cfg = DEFAULT_CONFIG.copy()
    if isinstance(user_cfg, dict):
        cfg.update({k: v for k, v in user_cfg.items() if v is not None})
    return cfg


CONFIG = load_config()

LOCAL_ID = CONFIG["local_id"]
REMOTE_ID = CONFIG["remote_id"]
TCP_PORT = int(CONFIG.get("tcp_port", 5005))
UDP_PORT = int(CONFIG.get("udp_port", TCP_PORT))
WINDOW_ALPHA = int(CONFIG.get("window_alpha", 0))
CERT_FILE = (BASE_DIR / CONFIG.get("cert_file", "certs/host_cert.pem")).resolve()
KEY_FILE = (BASE_DIR / CONFIG.get("key_file", "certs/host_key.pem")).resolve()
TRUST_PATH = (BASE_DIR / CONFIG.get("trust_store", "host_trust.json")).resolve()
VPS_BASE_URL = CONFIG.get("vps_base_url", "").rstrip("/")
VPS_CA_CERT = CONFIG.get("vps_ca_cert")
ALLOW_INSECURE_VPS = bool(CONFIG.get("allow_insecure_vps", False))
IP_REPORT_INTERVAL = max(60, int(CONFIG.get("ip_report_interval", 300)))
REMOTE_REFRESH_INTERVAL = max(5, int(CONFIG.get("remote_refresh_interval", 30)))
FALLBACK_REMOTE_IPS = CONFIG.get("fallback_remote_ips", [])


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
    global trust_store
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
        "udp_port": UDP_PORT,
        "event": event_name,
    }).encode("utf-8")
    try:
        req = request.Request(f"{VPS_BASE_URL}/report", data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        with request.urlopen(req, timeout=5, context=VPS_SSL_CONTEXT):
            pass
    except Exception as exc:
        print(f"[VPS] 上报失败: {exc}")


remote_cache = {"ips": FALLBACK_REMOTE_IPS[:], "port": TCP_PORT, "ts": 0.0}


def fetch_remote_descriptor() -> Tuple[List[str], int]:
    now = time.time()
    if now - remote_cache["ts"] < REMOTE_REFRESH_INTERVAL:
        return remote_cache["ips"], remote_cache["port"]

    if not VPS_BASE_URL:
        return remote_cache["ips"], remote_cache["port"]

    try:
        with request.urlopen(f"{VPS_BASE_URL}/node/{REMOTE_ID}", timeout=5, context=VPS_SSL_CONTEXT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            ips = data.get("ips", [])
            port = int(data.get("tcp_port", TCP_PORT))
            if ips:
                remote_cache.update({"ips": ips, "port": port, "ts": now})
                return ips, port
    except Exception:
        pass

    return remote_cache["ips"], remote_cache["port"]


def ip_reporter_thread():
    while True:
        report_ips("periodic")
        time.sleep(IP_REPORT_INTERVAL)


ssl_context_lock = threading.Lock()
_client_ssl_context = None


def get_client_ssl_context() -> ssl.SSLContext:
    global _client_ssl_context
    with ssl_context_lock:
        if _client_ssl_context is None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
            _client_ssl_context = ctx
        return _client_ssl_context


# 全局变量
IS_REMOTE = False
key_queue = queue.Queue()


# --- Windows API ---
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

LRESULT = c_longlong
HHOOK = c_void_p
HOOKPROC = WINFUNCTYPE(LRESULT, c_int, wintypes.WPARAM, c_void_p)
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104

# 窗口常量
GWL_EXSTYLE = -20
WS_EX_LAYERED = 0x80000
LWA_ALPHA = 0x2
SW_HIDE = 0
SW_SHOWNORMAL = 1
SW_SHOWMINIMIZED = 2
SW_SHOW = 5
SW_MINIMIZE = 6
SW_RESTORE = 9

class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wintypes.DWORD), ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", c_void_p)]

# API 定义
user32.SetWindowsHookExA.argtypes = [c_int, HOOKPROC, c_void_p, c_int]
user32.SetWindowsHookExA.restype = HHOOK
user32.CallNextHookEx.argtypes = [HHOOK, c_int, wintypes.WPARAM, c_void_p]
user32.CallNextHookEx.restype = LRESULT
user32.GetMessageA.argtypes = [POINTER(wintypes.MSG), c_void_p, c_int, c_int]
kernel32.GetModuleHandleW.restype = c_void_p

kernel32.GetConsoleWindow.restype = c_void_p
user32.GetForegroundWindow.restype = c_void_p
user32.GetWindowThreadProcessId.argtypes = [c_void_p, POINTER(c_uint)]
user32.GetWindowThreadProcessId.restype = c_uint
kernel32.GetCurrentThreadId.restype = c_uint
user32.AttachThreadInput.argtypes = [c_uint, c_uint, c_int]
user32.SetForegroundWindow.argtypes = [c_void_p]
user32.SetForegroundWindow.restype = c_int
user32.ShowWindow.argtypes = [c_void_p, c_int]
user32.IsIconic.argtypes = [c_void_p]
user32.SetWindowLongW.argtypes = [c_void_p, c_int, c_longlong]
user32.GetWindowLongW.argtypes = [c_void_p, c_int]
user32.SetLayeredWindowAttributes.argtypes = [c_void_p, c_int, c_int, c_int]

def set_window_transparent():
    """初始化：将窗口设为透明"""
    hwnd = kernel32.GetConsoleWindow()
    if hwnd:
        style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style | WS_EX_LAYERED)
        user32.SetLayeredWindowAttributes(hwnd, 0, WINDOW_ALPHA, LWA_ALPHA)

def activate_window():
    """【切入远程模式】还原窗口并抢焦点"""
    try:
        my_hwnd = kernel32.GetConsoleWindow()
        if not my_hwnd: return
        
        curr_hwnd = user32.GetForegroundWindow()
        if my_hwnd == curr_hwnd: return

        my_tid = kernel32.GetCurrentThreadId()
        curr_tid = user32.GetWindowThreadProcessId(curr_hwnd, None)

        detached = False
        if curr_tid != my_tid:
            user32.AttachThreadInput(curr_tid, my_tid, True)
            detached = True
        
        # 还原并置顶
        user32.ShowWindow(my_hwnd, SW_RESTORE)
        user32.SetForegroundWindow(my_hwnd)
        
        if detached:
            user32.AttachThreadInput(curr_tid, my_tid, False)
            
    except:
        pass

def minimize_window():
    """【切回本地模式】最小化窗口，将焦点交还给 RDP"""
    try:
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            # 最小化后，Windows 会自动把焦点给 Z-Order 里的下一个窗口 (即 RDP)
            user32.ShowWindow(hwnd, SW_MINIMIZE)
    except:
        pass

# --- TCP 发送 ---
def tcp_sender_thread():
    ctx = get_client_ssl_context()
    while True:
        ips, port = fetch_remote_descriptor()
        print(f"[TCP] 目标IP列表: {ips} 端口: {port}")
        if not ips:
            time.sleep(5)
            continue

        for addr in ips:
            try:
                raw = socket.create_connection((addr, port), timeout=5)
                raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError as exc:
                print(f"[TCP] 无法连接 {addr}:{port}: {exc}")
                continue

            try:
                with ctx.wrap_socket(raw, server_hostname=REMOTE_ID) as tls_sock:
                    peer_der = tls_sock.getpeercert(binary_form=True)
                    if not peer_der:
                        raise RuntimeError("未收到对端证书，无法建立安全连接")
                    fingerprint = _compute_fp_from_der(peer_der)
                    ensure_peer_trust(REMOTE_ID, fingerprint)
                    print(f"[TCP] 已连接 {REMOTE_ID}@{addr}:{port} -> {_format_fingerprint(fingerprint)}")
                    report_ips("connected")
                    # 发送本端指纹以供对端校验（TOFU）
                    hello = f"HELLO {LOCAL_ID} {_format_fingerprint(LOCAL_FINGERPRINT)}\n"
                    tls_sock.sendall(hello.encode())
                    while True:
                        msg = key_queue.get()
                        # 可选：截断长队列以避免阻塞
                        if len(msg) > 64:
                            print(f"[TCP] 发送键盘事件: {msg[:64]}...")
                        else:
                            print(f"[TCP] 发送键盘事件: {msg}")
                        tls_sock.sendall((msg + "\n").encode())
            except Exception as exc:
                print(f"[TCP] 连接中断: {exc}")
                report_ips("disconnect")
            finally:
                raw.close()

        time.sleep(2)

# --- Hook 回调 ---
def hook_callback(nCode, wParam, lParam):
    global IS_REMOTE
    if nCode >= 0:
        if IS_REMOTE:
            try:
                kb_struct = cast(lParam, POINTER(KBDLLHOOKSTRUCT)).contents
                vk_code = kb_struct.vkCode
                is_down = (wParam == WM_KEYDOWN or wParam == WM_SYSKEYDOWN)
                action = "P" if is_down else "R"
                key_queue.put(f"{action}:{vk_code}")
                return 1 
            except:
                pass
    return user32.CallNextHookEx(None, nCode, wParam, lParam)

# --- 信号监听 ---
def listen_remote_signal():
    global IS_REMOTE
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('0.0.0.0', UDP_PORT))
    print(f"[UDP] 监听本地端口 {UDP_PORT}")

    while True:
        try:
            data, _ = udp_sock.recvfrom(1024)
            if not data:
                continue

            # 兼容旧格式与新格式：
            # 旧：b'MOUSE_ACTIVE'；新：'MOUSE_ACTIVE:<id>'
            if data == b'MOUSE_ACTIVE':
                if not IS_REMOTE:
                    print("[MODE] 切换到远程模式(legacy heartbeat)")
                    activate_window()
                    IS_REMOTE = True
                continue

            message = data.decode("utf-8", errors="ignore")
            if message.startswith("MOUSE_ACTIVE"):
                parts = message.split(":", 1)
                sender = parts[1] if len(parts) > 1 else ""
                if sender and sender != REMOTE_ID:
                    # 来自非预期节点的心跳，忽略
                    print(f"[UDP] 心跳来源不匹配，期望 {REMOTE_ID} 实际 {sender}")
                    continue
                if not IS_REMOTE:
                    print("[MODE] 切换到远程模式")
                    activate_window()
                    IS_REMOTE = True
        except:
            pass

def on_local_mouse_move(x, y):
    global IS_REMOTE
    if IS_REMOTE:
        IS_REMOTE = False
        print("[MODE] 切回本地模式，清空待发送队列")
        with key_queue.mutex:
            key_queue.queue.clear()
        
        # 2. 最小化 (透明窗口下去，RDP 自动获得焦点)
        minimize_window()

if __name__ == '__main__':
    print_fingerprint_banner()
    report_ips("startup")
    print(f"[CONF] 本机ID: {LOCAL_ID} 对端ID: {REMOTE_ID} TCP:{TCP_PORT} UDP:{UDP_PORT}")

    # 启动时先变透明
    set_window_transparent()
    # 启动时先最小化，不挡视野
    minimize_window()
    
    if VPS_BASE_URL:
        t_report = threading.Thread(target=ip_reporter_thread, daemon=True)
        t_report.start()

    t_tcp = threading.Thread(target=tcp_sender_thread, daemon=True)
    t_tcp.start()

    t_udp = threading.Thread(target=listen_remote_signal, daemon=True)
    t_udp.start()

    m_listener = mouse.Listener(on_move=on_local_mouse_move)
    m_listener.start()
    
    try:
        cb = HOOKPROC(hook_callback)
        h_mod = kernel32.GetModuleHandleW(None)
        hook_id = user32.SetWindowsHookExA(WH_KEYBOARD_LL, cb, h_mod, 0)
        
        msg = wintypes.MSG()
        while user32.GetMessageA(byref(msg), None, 0, 0) != 0:
            user32.TranslateMessage(byref(msg))
            user32.DispatchMessageA(byref(msg))
    except KeyboardInterrupt:
        pass
    finally:
        report_ips("shutdown")