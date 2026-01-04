import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional


try:
    import evdev
    from evdev import ecodes
except Exception:  # pragma: no cover
    evdev = None
    ecodes = None


class LinuxInputUnavailable(RuntimeError):
    pass


def _require_evdev():
    if evdev is None or ecodes is None:
        raise LinuxInputUnavailable(
            "缺少依赖 evdev：请先运行 `pip install evdev`（Linux/Wayland 推荐）。"
        )


def list_input_devices() -> List[str]:
    _require_evdev()
    return list(evdev.list_devices())


def _device_has(dev: "evdev.InputDevice", event_type: int, codes: Iterable[int]) -> bool:
    caps = dev.capabilities().get(event_type, [])
    cap_set = set(caps)
    return any(code in cap_set for code in codes)


def find_keyboards(device_paths: Optional[List[str]] = None) -> List["evdev.InputDevice"]:
    """Best-effort keyboard discovery for /dev/input/event* devices."""
    _require_evdev()
    paths = device_paths or list_input_devices()
    keyboards: List[evdev.InputDevice] = []

    for path in paths:
        try:
            dev = evdev.InputDevice(path)
        except Exception:
            continue

        try:
            caps = dev.capabilities()
        except Exception:
            continue

        if ecodes.EV_KEY not in caps:
            continue

        # Heuristic: has some common keyboard keys.
        common = [
            ecodes.KEY_A,
            ecodes.KEY_Z,
            ecodes.KEY_SPACE,
            ecodes.KEY_ENTER,
            ecodes.KEY_LEFTCTRL,
            ecodes.KEY_LEFTSHIFT,
        ]
        if _device_has(dev, ecodes.EV_KEY, common):
            keyboards.append(dev)

    return keyboards


def find_mice(device_paths: Optional[List[str]] = None) -> List["evdev.InputDevice"]:
    """Best-effort mouse discovery for /dev/input/event* devices."""
    _require_evdev()
    paths = device_paths or list_input_devices()
    mice: List[evdev.InputDevice] = []

    for path in paths:
        try:
            dev = evdev.InputDevice(path)
        except Exception:
            continue

        try:
            caps = dev.capabilities()
        except Exception:
            continue

        # Typical mouse: EV_REL REL_X/REL_Y or EV_ABS ABS_X/ABS_Y.
        has_rel = ecodes.EV_REL in caps and _device_has(dev, ecodes.EV_REL, [ecodes.REL_X, ecodes.REL_Y])
        has_abs = ecodes.EV_ABS in caps and _device_has(dev, ecodes.EV_ABS, [ecodes.ABS_X, ecodes.ABS_Y])
        has_btn = ecodes.EV_KEY in caps and _device_has(dev, ecodes.EV_KEY, [ecodes.BTN_LEFT, ecodes.BTN_RIGHT])

        if (has_rel or has_abs) and has_btn:
            mice.append(dev)

    return mice


@dataclass
class EvdevKeyboardCapture:
    devices: List["evdev.InputDevice"]
    on_key: Callable[[str, str], None]

    _threads: List[threading.Thread] = None
    _stop: threading.Event = None
    _grabbed: bool = False

    def start(self) -> None:
        _require_evdev()
        if self._threads is not None:
            return
        self._stop = threading.Event()
        self._threads = []
        for dev in self.devices:
            t = threading.Thread(target=self._run_device, args=(dev,), daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        if self._stop is not None:
            self._stop.set()

    def set_grabbed(self, grabbed: bool) -> None:
        _require_evdev()
        if grabbed == self._grabbed:
            return
        for dev in self.devices:
            try:
                if grabbed:
                    dev.grab()
                else:
                    dev.ungrab()
            except Exception:
                # If permissions are missing, grabbing will fail; we still keep capture running.
                pass
        self._grabbed = grabbed

    def _run_device(self, dev: "evdev.InputDevice") -> None:
        try:
            dev.set_blocking(True)
        except Exception:
            pass

        while not self._stop.is_set():
            try:
                for event in dev.read_loop():
                    if self._stop.is_set():
                        break
                    if event.type != ecodes.EV_KEY:
                        continue
                    key_event = evdev.categorize(event)
                    if getattr(key_event, "keystate", None) is None:
                        continue

                    if key_event.keystate == key_event.key_down:
                        action = "P"
                    elif key_event.keystate == key_event.key_up:
                        action = "R"
                    else:
                        continue

                    # `key_event.keycode` can be a string or list.
                    keycode = key_event.keycode
                    if isinstance(keycode, list):
                        # Take the first for common cases.
                        keycode = keycode[0] if keycode else None
                    if not isinstance(keycode, str) or not keycode:
                        continue

                    self.on_key(action, keycode)
            except OSError:
                time.sleep(0.2)
            except Exception:
                time.sleep(0.2)


@dataclass
class EvdevMouseWatcher:
    devices: List["evdev.InputDevice"]
    on_activity: Callable[[], None]

    _threads: List[threading.Thread] = None
    _stop: threading.Event = None

    def start(self) -> None:
        _require_evdev()
        if self._threads is not None:
            return
        self._stop = threading.Event()
        self._threads = []
        for dev in self.devices:
            t = threading.Thread(target=self._run_device, args=(dev,), daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        if self._stop is not None:
            self._stop.set()

    def _run_device(self, dev: "evdev.InputDevice") -> None:
        try:
            dev.set_blocking(True)
        except Exception:
            pass

        while not self._stop.is_set():
            try:
                for event in dev.read_loop():
                    if self._stop.is_set():
                        break
                    if event.type in (ecodes.EV_REL, ecodes.EV_ABS, ecodes.EV_KEY):
                        self.on_activity()
            except OSError:
                time.sleep(0.2)
            except Exception:
                time.sleep(0.2)


class UInputKeyboardInjector:
    def __init__(self):
        _require_evdev()

        key_values = [
            v
            for k, v in ecodes.ecodes.items()
            if isinstance(k, str) and k.startswith("KEY_") and isinstance(v, int)
        ]
        key_values = sorted(set(key_values))
        self._ui = evdev.UInput({ecodes.EV_KEY: key_values}, name="kb-redirector", bustype=ecodes.BUS_USB)

    def press_key_name(self, key_name: str) -> None:
        code = ecodes.ecodes.get(key_name)
        if not isinstance(code, int):
            return
        self._ui.write(ecodes.EV_KEY, code, 1)
        self._ui.syn()

    def release_key_name(self, key_name: str) -> None:
        code = ecodes.ecodes.get(key_name)
        if not isinstance(code, int):
            return
        self._ui.write(ecodes.EV_KEY, code, 0)
        self._ui.syn()
