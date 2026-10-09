# coding: utf-8
"""Windows hidden-window message transport using WM_COPYDATA.

This is a same-host, same-interactive-session IPC backend for environments
where a broker QMT sandbox allows ``ctypes`` but third-party networking
packages are unavailable. It is deliberately conservative: ``WM_COPYDATA``
copies the full payload through the window manager, so large bulk data should
stay on named pipes (or a future shared-memory transport).
"""

import ctypes
import json
import os
import uuid
import threading
import time

from .base import RpcTransport, TransportError, TransportTimeout
from ..adapters.redis_common import decode_text


DEFAULT_WINDOW_NAME = "bigqmt_rpc"
DEFAULT_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024

WM_COPYDATA = 0x004A
WM_CLOSE = 0x0010
WM_DESTROY = 0x0002
PM_REMOVE = 0x0001
SMTO_ABORTIFHUNG = 0x0002

MSG_REQUEST = 1
MSG_RESPONSE = 2


def _lresult_type(wintypes):
    return getattr(wintypes, "LRESULT", ctypes.c_ssize_t)


def _ulong_ptr_type(wintypes):
    return getattr(wintypes, "ULONG_PTR", ctypes.c_size_t)


def _handle_type(wintypes, name):
    return getattr(wintypes, name, wintypes.HANDLE)


def _kernel_user32():
    if os.name != "nt":
        raise TransportError(
            "hidden-window message transport is Windows-only (os.name=%r). "
            "Use redis, zmq, or pipe for this deployment." % os.name)
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return kernel32, user32, wintypes


def _window_suffix(account_id):
    return str(account_id or "default")


def window_class_name(window_name=DEFAULT_WINDOW_NAME, account_id=""):
    return "BigQmtWinMsgRpc_%s_%s" % (
        str(window_name or DEFAULT_WINDOW_NAME), _window_suffix(account_id))


def window_title(window_name=DEFAULT_WINDOW_NAME, account_id=""):
    return "%s:%s" % (
        str(window_name or DEFAULT_WINDOW_NAME), _window_suffix(account_id))


class WinMsgTransport(RpcTransport):
    """RPC request/response over a hidden window and ``WM_COPYDATA``."""

    name = "winmsg"

    def __init__(self, account_id="", print_prefix="[bigqmt_rpc]",
                 window_name=DEFAULT_WINDOW_NAME,
                 max_payload_bytes=DEFAULT_MAX_PAYLOAD_BYTES,
                 send_timeout_seconds=None, startup_timeout_seconds=5.0,
                 **kwargs):
        super(WinMsgTransport, self).__init__(
            account_id=account_id, print_prefix=print_prefix)
        self.window_name = str(window_name or DEFAULT_WINDOW_NAME)
        self.max_payload_bytes = int(max_payload_bytes or DEFAULT_MAX_PAYLOAD_BYTES)
        self.send_timeout_seconds = send_timeout_seconds
        self.startup_timeout_seconds = float(startup_timeout_seconds or 5.0)
        base_class_name = window_class_name(self.window_name, self.account_id)
        self.class_name = "%s_server_%s" % (base_class_name, uuid.uuid4().hex)
        self.title = window_title(self.window_name, self.account_id)
        self._client_class_name = "%s_client_%s" % (
            base_class_name, uuid.uuid4().hex)
        self._client_title = "%s:client:%s" % (self.title, uuid.uuid4().hex)

        self._kernel32 = None
        self._user32 = None
        self._wintypes = None
        self._copydata_type = None
        self._wndclass_type = None
        self._wndproc_type = None
        self._wndproc = None

        self._hwnd = None
        self._thread = None
        self._thread_id = None
        self._window_ready = threading.Event()
        self._window_error = None
        self._window_lock = threading.RLock()
        self._drain_depth = 0
        self._drained_count = 0

        self._pending = {}
        self._pending_lock = threading.RLock()
        self._server_mode = False

    # -- ctypes plumbing -------------------------------------------------
    def _dlls(self):
        if self._user32 is None:
            self._kernel32, self._user32, self._wintypes = _kernel_user32()
            self._setup_types()
        return self._kernel32, self._user32, self._wintypes

    def _setup_types(self):
        wintypes = self._wintypes
        lresult = _lresult_type(wintypes)
        ulong_ptr = _ulong_ptr_type(wintypes)

        class COPYDATASTRUCT(ctypes.Structure):
            _fields_ = [
                ("dwData", ulong_ptr),
                ("cbData", wintypes.DWORD),
                ("lpData", ctypes.c_void_p),
            ]

        wndproc_type = ctypes.WINFUNCTYPE(
            lresult, wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
            wintypes.LPARAM)
        hinstance = _handle_type(wintypes, "HINSTANCE")
        hicon = _handle_type(wintypes, "HICON")
        hcursor = _handle_type(wintypes, "HCURSOR")
        hbrush = _handle_type(wintypes, "HBRUSH")
        hmenu = _handle_type(wintypes, "HMENU")
        hmodule = _handle_type(wintypes, "HMODULE")

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [
                ("style", wintypes.UINT),
                ("lpfnWndProc", wndproc_type),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", hinstance),
                ("hIcon", hicon),
                ("hCursor", hcursor),
                ("hbrBackground", hbrush),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
            ]

        self._copydata_type = COPYDATASTRUCT
        self._wndclass_type = WNDCLASSW
        self._wndproc_type = wndproc_type

        user32 = self._user32
        kernel32 = self._kernel32
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        user32.RegisterClassW.restype = wintypes.ATOM
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, hmenu, hinstance, ctypes.c_void_p,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.DestroyWindow.restype = wintypes.BOOL
        user32.DefWindowProcW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = lresult
        user32.DispatchMessageW.restype = lresult
        user32.TranslateMessage.restype = wintypes.BOOL
        user32.GetMessageW.restype = wintypes.BOOL
        user32.PeekMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT,
            wintypes.UINT, wintypes.UINT]
        user32.PeekMessageW.restype = wintypes.BOOL
        user32.PostMessageW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.PostMessageW.restype = wintypes.BOOL
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        user32.FindWindowW.restype = wintypes.HWND
        user32.SendMessageTimeoutW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
            wintypes.UINT, wintypes.UINT, ctypes.POINTER(ulong_ptr)]
        user32.SendMessageTimeoutW.restype = ulong_ptr
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = hmodule
        kernel32.GetCurrentThreadId.restype = wintypes.DWORD

    def _last_error(self):
        return ctypes.get_last_error()

    # -- window creation / pumping --------------------------------------
    def _ensure_window(self, server_mode):
        if server_mode:
            return self._ensure_server_window()
        return self._ensure_client_window()

    def _ensure_server_window(self):
        with self._window_lock:
            if self._hwnd:
                return self._hwnd
            self._server_mode = True
            kernel32, _user32, _wintypes = self._dlls()
            self._thread_id = kernel32.GetCurrentThreadId()
            self._hwnd = self._create_window(self.class_name, self.title)
            return self._hwnd

    def _ensure_client_window(self):
        with self._window_lock:
            if self._hwnd:
                return self._hwnd
            if self._thread is None or not self._thread.is_alive():
                self._server_mode = False
                self._window_ready.clear()
                self._window_error = None
                self._thread = threading.Thread(
                    target=self._window_loop, name="bigqmt-winmsg-rpc")
                self._thread.daemon = True
                self._thread.start()
        if not self._window_ready.wait(self.startup_timeout_seconds):
            raise TransportError("winmsg window did not start")
        if self._window_error is not None:
            raise self._window_error
        if not self._hwnd:
            raise TransportError("winmsg window did not create")
        return self._hwnd

    def _create_window(self, class_name, title):
        kernel32, user32, _wintypes = self._dlls()
        self._wndproc = self._wndproc_type(self._handle_message)
        hinst = kernel32.GetModuleHandleW(None)
        cls = self._wndclass_type()
        cls.style = 0
        cls.lpfnWndProc = self._wndproc
        cls.cbClsExtra = 0
        cls.cbWndExtra = 0
        cls.hInstance = hinst
        cls.hIcon = None
        cls.hCursor = None
        cls.hbrBackground = None
        cls.lpszMenuName = None
        cls.lpszClassName = class_name
        atom = user32.RegisterClassW(ctypes.byref(cls))
        if not atom and self._last_error() not in (1410,):  # class exists
            raise TransportError(
                "RegisterClassW failed (err=%s)" % self._last_error())
        hwnd = user32.CreateWindowExW(
            0, class_name, title, 0,
            0, 0, 0, 0, None, None, hinst, None)
        if not hwnd:
            raise TransportError(
                "CreateWindowExW failed (err=%s)" % self._last_error())
        return hwnd

    def _window_loop(self):
        try:
            kernel32, user32, wintypes = self._dlls()
            class_name = self.class_name if self._server_mode else self._client_class_name
            title = self.title if self._server_mode else self._client_title
            self._thread_id = kernel32.GetCurrentThreadId()
            self._hwnd = self._create_window(class_name, title)
            self._window_ready.set()

            msg = wintypes.MSG()
            while True:
                rc = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if rc == 0:
                    break
                if rc == -1:
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception as exc:
            self._window_error = exc
            self._window_ready.set()
        finally:
            self._hwnd = None

    def _handle_message(self, hwnd, msg, wparam, lparam):
        user32 = self._user32
        if msg == WM_COPYDATA:
            try:
                return self._handle_copydata(hwnd, wparam, lparam)
            except Exception:
                return 0
        if msg == WM_CLOSE:
            user32.DestroyWindow(hwnd)
            return 0
        if msg == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _handle_copydata(self, hwnd, wparam, lparam):
        cds = ctypes.cast(lparam, ctypes.POINTER(self._copydata_type)).contents
        if cds.cbData > self.max_payload_bytes:
            return 0
        raw = ctypes.string_at(cds.lpData, cds.cbData)
        payload = json.loads(decode_text(raw))
        if int(cds.dwData) == MSG_REQUEST:
            payload["_winmsg_reply_hwnd"] = int(wparam or payload.get("_winmsg_reply_hwnd") or 0)
            self.deliver(payload)
            if self._drain_depth:
                self._drained_count += 1
            return 1
        if int(cds.dwData) == MSG_RESPONSE:
            self._receive_response(payload)
            return 1
        return 0

    # -- encoding / send helpers ----------------------------------------
    def _encode_payload(self, payload):
        raw = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        if len(raw) > self.max_payload_bytes:
            raise TransportError(
                "winmsg payload too large: %d bytes > %d bytes" %
                (len(raw), self.max_payload_bytes))
        return raw

    def _send_copydata(self, target_hwnd, source_hwnd, msg_type, payload,
                       timeout_seconds):
        _kernel32, user32, _wintypes = self._dlls()
        raw = self._encode_payload(payload)
        buf = ctypes.create_string_buffer(raw)
        cds = self._copydata_type()
        cds.dwData = int(msg_type)
        cds.cbData = len(raw)
        cds.lpData = ctypes.cast(buf, ctypes.c_void_p)
        result = _ulong_ptr_type(self._wintypes)(0)
        timeout_ms = int(max(1.0, float(timeout_seconds or 1.0)) * 1000)
        ok = user32.SendMessageTimeoutW(
            target_hwnd, WM_COPYDATA, source_hwnd,
            self._wintypes.LPARAM(ctypes.addressof(cds)),
            SMTO_ABORTIFHUNG, timeout_ms, ctypes.byref(result))
        if not ok:
            err = self._last_error()
            if err == 0:
                raise TransportTimeout("winmsg send timeout")
            raise TransportError("SendMessageTimeoutW failed (err=%s)" % err)
        return int(result.value)

    def _server_hwnd(self):
        self._dlls()
        hwnd = self._user32.FindWindowW(None, self.title)
        if not hwnd:
            raise TransportError(
                "cannot find winmsg server window %r. Is the QMT-side strategy "
                "running with transport=winmsg?" % self.title)
        return hwnd

    # -- client side -----------------------------------------------------
    def send_request(self, request, timeout_seconds):
        reply_hwnd = self._ensure_window(server_mode=False)
        server_hwnd = self._server_hwnd()
        rid = str((request or {}).get("request_id") or "")
        if not rid:
            raise TransportError("winmsg request missing request_id")
        event = threading.Event()
        entry = {"event": event, "response": None}
        with self._pending_lock:
            self._pending[rid] = entry
        outbound = dict(request or {})
        outbound["_winmsg_reply_hwnd"] = int(reply_hwnd)
        outbound["_winmsg_request_id"] = rid
        try:
            send_timeout = self.send_timeout_seconds
            if send_timeout is None:
                send_timeout = timeout_seconds
            self._send_copydata(
                server_hwnd, reply_hwnd, MSG_REQUEST, outbound, send_timeout)
            if not event.wait(float(timeout_seconds or 0)):
                raise TransportTimeout("winmsg rpc timeout: %s" %
                                       outbound.get("method"))
            return entry["response"]
        finally:
            with self._pending_lock:
                self._pending.pop(rid, None)

    def _receive_response(self, response):
        rid = str((response or {}).get("request_id") or "")
        with self._pending_lock:
            entry = self._pending.get(rid)
            if entry is None:
                return
            entry["response"] = response
            entry["event"].set()

    # -- server side -----------------------------------------------------
    def start_receiving(self, on_request, **kwargs):
        super(WinMsgTransport, self).start_receiving(on_request)
        self._ensure_window(server_mode=True)
        print("%s winmsg started window=%s drain=True" % (self.print_prefix, self.title))

    def drain_request_queue(self, max_items=20):
        """Pump pending WM_COPYDATA requests on the current QMT thread.

        ``SendMessage`` traffic is delivered while this thread calls a message
        retrieval API. ``PeekMessageW`` may dispatch sent messages and still
        return False when there are no posted messages, so the processed count
        is recorded by the WndProc itself.
        """
        self._ensure_window(server_mode=True)
        _kernel32, user32, wintypes = self._dlls()
        msg = wintypes.MSG()
        before = self._drained_count
        self._drain_depth += 1
        try:
            # One PeekMessage call is enough to let Windows dispatch pending
            # sent WM_COPYDATA messages. Keep polling queued messages too, but
            # never block the adjust thread.
            while self._drained_count - before < int(max_items):
                had_queued = user32.PeekMessageW(
                    ctypes.byref(msg), None, 0, 0, PM_REMOVE)
                if not had_queued:
                    break
                if msg.message == WM_CLOSE:
                    user32.DispatchMessageW(ctypes.byref(msg))
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            self._drain_depth -= 1
        return self._drained_count - before

    def send_response(self, request, response):
        reply_hwnd = int((request or {}).get("_winmsg_reply_hwnd") or 0)
        if not reply_hwnd:
            raise TransportError("no winmsg reply window on the request")
        source = self._hwnd or self._ensure_window(server_mode=True)
        self._send_copydata(
            reply_hwnd, source, MSG_RESPONSE, response,
            self.send_timeout_seconds or 5.0)

    def stop(self):
        self._running = False
        hwnd = self._hwnd
        if hwnd:
            try:
                self._dlls()
                if self._thread is None:
                    self._user32.DestroyWindow(hwnd)
                else:
                    self._user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            except Exception:
                pass
        thread = self._thread
        if thread is not None and thread.is_alive() and \
                thread is not threading.current_thread():
            thread.join(timeout=2.0)
        with self._pending_lock:
            for entry in self._pending.values():
                entry["event"].set()
            self._pending = {}
        self._thread = None
        self._thread_id = None
        self._window_ready.clear()
        super(WinMsgTransport, self).stop()

