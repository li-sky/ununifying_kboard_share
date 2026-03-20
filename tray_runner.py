import argparse
import ctypes
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    import pystray
    from pystray import MenuItem as Item
    from PIL import Image, ImageDraw
except Exception as exc:
    message = f"缺少托盘依赖，请执行: pip install pystray pillow\n\n{exc}"
    try:
        ctypes.windll.user32.MessageBoxW(0, message, "KB Share Tray", 0x10)
    except Exception:
        pass
    raise SystemExit(message)

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
SERVICE_FILES = {
    "host": BASE_DIR / "host.py",
    "client": BASE_DIR / "client.py",
}
ERROR_ALREADY_EXISTS = 183
mutex_handle = None


def acquire_single_instance(role: str):
    mutex_name = f"Local\\KBShareTray-{role}"
    handle = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
    if not handle:
        raise RuntimeError("无法创建托盘单实例锁")
    if ctypes.windll.kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        ctypes.windll.kernel32.CloseHandle(handle)
        return None
    return handle


def release_single_instance(handle):
    if handle:
        ctypes.windll.kernel32.CloseHandle(handle)


class TrayRunner:
    def __init__(self, role: str, auto_start: bool):
        self.role = role
        self.auto_start = auto_start
        self.icon = None
        self.process = None
        self.stdout_handle = None
        self.stderr_handle = None
        self.lock = threading.Lock()
        self.monitor_thread = None

    def _tray_log_path(self) -> Path:
        return LOG_DIR / f"tray.{self.role}.log"

    def _write_tray_log(self, message: str):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._tray_log_path().open("a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {message}\n")

    def is_running(self) -> bool:
        with self.lock:
            return self.process is not None and self.process.poll() is None

    def status_text(self) -> str:
        return "状态: 运行中" if self.is_running() else "状态: 已停止"

    def _pythonw_executable(self) -> str:
        exe = Path(sys.executable)
        if exe.name.lower() == "python.exe":
            pyw = exe.with_name("pythonw.exe")
            if pyw.exists():
                return str(pyw)
        return str(exe)

    def _close_logs(self):
        if self.stdout_handle:
            try:
                self.stdout_handle.close()
            except Exception:
                pass
        if self.stderr_handle and self.stderr_handle is not self.stdout_handle:
            try:
                self.stderr_handle.close()
            except Exception:
                pass
        self.stdout_handle = None
        self.stderr_handle = None

    def _monitor_process(self, proc: subprocess.Popen):
        try:
            exit_code = proc.wait()
            self._write_tray_log(f"service exited with code {exit_code}")
        except Exception as exc:
            self._write_tray_log(f"service monitor error: {exc}")
            return

        with self.lock:
            if self.process is proc:
                self.process = None
                self._close_logs()

        if self.icon:
            self.icon.update_menu()

    def start_service(self):
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                self._write_tray_log("start ignored: service already running")
                return

            script_path = SERVICE_FILES[self.role]
            if not script_path.exists():
                self._write_tray_log(f"service script missing: {script_path}")
                raise FileNotFoundError(f"未找到脚本: {script_path}")

            LOG_DIR.mkdir(parents=True, exist_ok=True)
            out_log = LOG_DIR / f"{self.role}.out.log"
            err_log = LOG_DIR / f"{self.role}.err.log"
            self.stdout_handle = out_log.open("a", encoding="utf-8", buffering=1)
            self.stderr_handle = err_log.open("a", encoding="utf-8", buffering=1)

            cmd = [self._pythonw_executable(), "-u", str(script_path)]
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            self.process = subprocess.Popen(
                cmd,
                cwd=str(BASE_DIR),
                stdin=subprocess.DEVNULL,
                stdout=self.stdout_handle,
                stderr=self.stderr_handle,
                env=env,
                creationflags=creationflags,
            )
            self._write_tray_log(f"service started pid={self.process.pid}: {' '.join(cmd)}")
            self.monitor_thread = threading.Thread(
                target=self._monitor_process,
                args=(self.process,),
                daemon=True,
            )
            self.monitor_thread.start()

        if self.icon:
            self.icon.update_menu()

    def stop_service(self):
        with self.lock:
            proc = self.process
        if proc is None:
            self._write_tray_log("stop ignored: service not running")
            return

        try:
            if proc.poll() is None:
                self._write_tray_log(f"stopping service pid={proc.pid}")
                proc.terminate()
                proc.wait(timeout=5)
        except Exception:
            try:
                self._write_tray_log(f"terminate failed, killing pid={proc.pid}")
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass

        with self.lock:
            self.process = None
            self._close_logs()

        if self.icon:
            self.icon.update_menu()

    def restart_service(self):
        self.stop_service()
        time.sleep(0.2)
        self.start_service()

    def open_project_folder(self):
        os.startfile(str(BASE_DIR))

    def open_logs_folder(self):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        os.startfile(str(LOG_DIR))

    def on_start(self, icon, item):
        self.start_service()

    def on_stop(self, icon, item):
        self.stop_service()

    def on_restart(self, icon, item):
        self.restart_service()

    def on_open_project(self, icon, item):
        self.open_project_folder()

    def on_open_logs(self, icon, item):
        self.open_logs_folder()

    def on_exit(self, icon, item):
        self.stop_service()
        icon.stop()

    def on_noop(self, icon, item):
        return

    def _icon_image(self):
        image = Image.new("RGBA", (64, 64), (32, 32, 32, 255))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((6, 10, 58, 54), radius=8, fill=(55, 125, 255, 255))
        draw.rectangle((12, 16, 52, 30), fill=(255, 255, 255, 220))
        for i in range(4):
            y = 34 + i * 5
            draw.rectangle((12, y, 52, y + 3), fill=(255, 255, 255, 210))
        return image

    def _menu(self):
        return pystray.Menu(
            Item(lambda item: f"{self.role} - {self.status_text()}", self.on_noop, enabled=False),
            Item("启动", self.on_start),
            Item("停止", self.on_stop),
            Item("重启", self.on_restart),
            Item("打开项目目录", self.on_open_project),
            Item("打开日志目录", self.on_open_logs),
            Item("退出托盘", self.on_exit),
        )

    def run(self):
        self._write_tray_log("tray runner started")
        self.icon = pystray.Icon(
            name=f"kbshare-{self.role}",
            icon=self._icon_image(),
            title=f"KB Share {self.role}",
            menu=self._menu(),
        )

        if self.auto_start:
            self.start_service()

        self.icon.run()
        self._write_tray_log("tray runner stopped")


def main():
    global mutex_handle
    parser = argparse.ArgumentParser(description="KB Share 托盘守护")
    parser.add_argument("--role", choices=["host", "client"], required=True)
    parser.add_argument("--auto-start", action="store_true")
    args = parser.parse_args()

    mutex_handle = acquire_single_instance(args.role)
    if mutex_handle is None:
        raise SystemExit(0)

    runner = TrayRunner(role=args.role, auto_start=args.auto_start)
    try:
        runner.run()
    finally:
        release_single_instance(mutex_handle)
        mutex_handle = None


if __name__ == "__main__":
    main()
