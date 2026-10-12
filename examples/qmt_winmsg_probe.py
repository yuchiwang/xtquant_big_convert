# coding: utf-8
"""
Big QMT WinMsg probe using ctypes + WM_COPYDATA only.

Usage outside QMT:
    python examples/qmt_winmsg_probe.py --server

Usage inside a Big QMT strategy:
    1. Start the server command above in a normal Windows terminal.
    2. Put this file's client part into a QMT strategy, or import/copy the
       whole file if your QMT editor allows it.
    3. Run the strategy. init() sends one ping; handle_bar() sends one ping
       per bar and prints the round-trip result.

The probe proves that Big QMT can call user32 via ctypes and exchange
WM_COPYDATA messages with another process in the same Windows login session.
"""

from __future__ import print_function

import argparse
import ctypes
import json
import os
import sys
import threading
import time
import uuid
from ctypes import wintypes


WINDOW_NAME = "qmt_winmsg_probe"
ACCOUNT_ID = "default"
WM_COPYDATA = 0x004A
WM_CLOSE = 0x0010
WM_DESTROY = 0x0002
SMTO_ABORTIFHUNG = 0x0002
MSG_REQUEST = 1
MSG_RESPONSE = 2


if os.name != "nt":
    raise RuntimeError("WinMsg probe is Windows-only")

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

LRESULT = getattr(wintypes, "LRESULT", ctypes.c_ssize_t)
ULONG_PTR = getattr(wintypes, "ULONG_PTR", ctypes.c_size_t)
HINSTANCE = getattr(wintypes, "HINSTANCE", wintypes.HANDLE)
HICON = getattr(wintypes, "HICON", wintypes.HANDLE)
HCURSOR = getattr(wintypes, "HCURSOR", wintypes.HANDLE)
HBRUSH = getattr(wintypes, "HBRUSH", wintypes.HANDLE)
HMENU = getattr(wintypes, "HMENU", wintypes.HANDLE)
HMODULE = getattr(wintypes, "HMODULE", wintypes.HANDLE)


class COPYDATASTRUCT(ctypes.Structure):
    _fields_ = [
        ("dwData", ULONG_PTR),
        ("cbData", wintypes.DWORD),
        ("lpData", ctypes.c_void_p),
    ]


WNDPROC = ctypes.WINFUNCTYPE(
    LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", HINSTANCE),
        ("hIcon", HICON),
        ("hCursor", HCURSOR),
        ("hbrBackground", HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
user32.RegisterClassW.restype = wintypes.ATOM
user32.CreateWindowExW.argtypes = [
    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wintypes.HWND, HMENU, HINSTANCE, ctypes.c_void_p,
]
user32.CreateWindowExW.restype = wintypes.HWND
user32.DestroyWindow.argtypes = [wintypes.HWND]
user32.DestroyWindow.restype = wintypes.BOOL
user32.DefWindowProcW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.DispatchMessageW.restype = LRESULT
user32.TranslateMessage.restype = wintypes.BOOL
user32.GetMessageW.restype = wintypes.BOOL
user32.PostQuitMessage.argtypes = [ctypes.c_int]
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND
user32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
    wintypes.UINT, wintypes.UINT, ctypes.POINTER(ULONG_PTR)]
user32.SendMessageTimeoutW.restype = ULONG_PTR
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = HMODULE


def _server_class(window_name=WINDOW_NAME, account_id=ACCOUNT_ID):
    return "QmtWinMsgProbeServer_%s_%s" % (window_name, account_id)


def _server_title(window_name=WINDOW_NAME, account_id=ACCOUNT_ID):
    return "%s:%s" % (window_name, account_id)


def _client_class(window_name=WINDOW_NAME, account_id=ACCOUNT_ID):
    return "QmtWinMsgProbeClient_%s_%s_%s" % (
        window_name, account_id, uuid.uuid4().hex)


def _json_bytes(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _last_error_message(prefix):
    return "%s failed, GetLastError=%s" % (prefix, ctypes.get_last_error())


def _send_copydata(target_hwnd, sender_hwnd, msg_type, payload, timeout_ms=2000):
    raw = _json_bytes(payload)
    buf = ctypes.create_string_buffer(raw)
    cds = COPYDATASTRUCT()
    cds.dwData = msg_type
    cds.cbData = len(raw)
    cds.lpData = ctypes.cast(buf, ctypes.c_void_p)
    result = ULONG_PTR()
    ok = user32.SendMessageTimeoutW(
        target_hwnd, WM_COPYDATA, sender_hwnd, ctypes.byref(cds),
        SMTO_ABORTIFHUNG, timeout_ms, ctypes.byref(result))
    if not ok:
        raise OSError(ctypes.get_last_error(), "SendMessageTimeoutW failed")
    return result.value


def _read_copydata(lparam):
    cds = ctypes.cast(lparam, ctypes.POINTER(COPYDATASTRUCT)).contents
    raw = ctypes.string_at(cds.lpData, cds.cbData)
    return cds.dwData, json.loads(raw.decode("utf-8"))


class HiddenWindow(object):
    def __init__(self, class_name, title, on_copydata):
        self.class_name = class_name
        self.title = title
        self.on_copydata = on_copydata
        self.hwnd = None
        self._wndproc = WNDPROC(self._handle_message)
        self._create()

    def _create(self):
        hinst = kernel32.GetModuleHandleW(None)
        cls = WNDCLASSW()
        cls.lpfnWndProc = self._wndproc
        cls.hInstance = hinst
        cls.lpszClassName = self.class_name
        atom = user32.RegisterClassW(ctypes.byref(cls))
        if not atom and ctypes.get_last_error() != 1410:
            raise OSError(ctypes.get_last_error(), "RegisterClassW failed")
        self.hwnd = user32.CreateWindowExW(
            0, self.class_name, self.title, 0,
            0, 0, 0, 0, None, None, hinst, None)
        if not self.hwnd:
            raise OSError(ctypes.get_last_error(), "CreateWindowExW failed")

    def _handle_message(self, hwnd, msg, wparam, lparam):
        if msg == WM_COPYDATA:
            try:
                msg_type, payload = _read_copydata(lparam)
                self.on_copydata(hwnd, wparam, msg_type, payload)
                return 1
            except Exception as exc:
                print("[winmsg-probe] on_copydata error: %r" % (exc,))
                return 0
        if msg == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def close(self):
        if self.hwnd:
            user32.DestroyWindow(self.hwnd)
            self.hwnd = None


class WinMsgProbeClient(object):
    def __init__(self, window_name=WINDOW_NAME, account_id=ACCOUNT_ID):
        self.window_name = window_name
        self.account_id = account_id
        self.pending = {}
        self.pending_lock = threading.RLock()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._window_loop)
        self.thread.daemon = True
        self.window = None
        self.thread.start()
        if not self.ready.wait(3.0):
            raise RuntimeError("client hidden window did not start")

    def _on_copydata(self, _hwnd, _sender, msg_type, payload):
        if msg_type != MSG_RESPONSE:
            return
        request_id = payload.get("request_id")
        with self.pending_lock:
            slot = self.pending.get(request_id)
        if slot is not None:
            slot["response"] = payload
            slot["event"].set()

    def _window_loop(self):
        self.window = HiddenWindow(
            _client_class(self.window_name, self.account_id),
            "%s:client:%s" % (_server_title(self.window_name, self.account_id), uuid.uuid4().hex),
            self._on_copydata)
        self.ready.set()
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0):
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def send_request(self, payload, timeout_seconds=3.0):
        server_hwnd = user32.FindWindowW(
            _server_class(self.window_name, self.account_id),
            _server_title(self.window_name, self.account_id))
        if not server_hwnd:
            raise RuntimeError(
                "server window not found; start: python examples/qmt_winmsg_probe.py --server")
        request_id = payload.get("request_id") or uuid.uuid4().hex
        payload = dict(payload)
        payload["request_id"] = request_id
        payload["reply_hwnd"] = int(self.window.hwnd)
        slot = {"event": threading.Event(), "response": None}
        with self.pending_lock:
            self.pending[request_id] = slot
        try:
            _send_copydata(
                server_hwnd, self.window.hwnd, MSG_REQUEST, payload,
                int(timeout_seconds * 1000))
            if not slot["event"].wait(timeout_seconds):
                raise RuntimeError("timeout waiting for WM_COPYDATA response")
            return slot["response"]
        finally:
            with self.pending_lock:
                self.pending.pop(request_id, None)

    def close(self):
        if self.window is not None:
            self.window.close()


class WinMsgProbeServer(object):
    def __init__(self, window_name=WINDOW_NAME, account_id=ACCOUNT_ID):
        self.window_name = window_name
        self.account_id = account_id
        self.window = HiddenWindow(
            _server_class(window_name, account_id),
            _server_title(window_name, account_id),
            self._on_copydata)

    def _on_copydata(self, _hwnd, sender_hwnd, msg_type, payload):
        if msg_type != MSG_REQUEST:
            return
        response = {
            "ok": True,
            "request_id": payload.get("request_id"),
            "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "echo": payload,
        }
        reply_hwnd = int(payload.get("reply_hwnd") or sender_hwnd)
        _send_copydata(reply_hwnd, self.window.hwnd, MSG_RESPONSE, response)
        print("[winmsg-probe] request %s from hwnd=%s method=%s" % (
            payload.get("request_id"), reply_hwnd, payload.get("method")))

    def run_forever(self):
        print("[winmsg-probe] server ready: class=%s title=%s hwnd=%s" % (
            _server_class(self.window_name, self.account_id),
            _server_title(self.window_name, self.account_id),
            self.window.hwnd))
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0):
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))


pipe = None


def _qmt_log(text):
    logger = globals().get("log")
    if logger is not None and hasattr(logger, "info"):
        logger.info(text)
    else:
        print(text)


def init(context):
    global pipe
    pipe = WinMsgProbeClient()
    response = pipe.send_request({"method": "init_ping", "params": {"source": "bigqmt"}})
    _qmt_log("[WinMsgProbe] init ok: %s" % response)


def handle_bar(context, bar):
    global pipe
    if pipe is None:
        pipe = WinMsgProbeClient()
    symbol = getattr(bar, "symbol", "")
    response = pipe.send_request({
        "method": "bar_ping",
        "params": {"symbol": symbol, "ts": time.time()},
    })
    _qmt_log("[WinMsgProbe] bar response: %s" % response)


def stop(context):
    global pipe
    if pipe is not None:
        pipe.close()
        pipe = None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action="store_true", help="run external echo server")
    parser.add_argument("--client", action="store_true", help="run a normal Python client ping")
    args = parser.parse_args(argv)
    if args.server:
        WinMsgProbeServer().run_forever()
    elif args.client:
        client = WinMsgProbeClient()
        try:
            print(client.send_request({"method": "cli_ping", "params": {"pid": os.getpid()}}))
        finally:
            client.close()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
