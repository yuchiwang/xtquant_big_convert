"""Server→client whole-quote push channel.

The RPC transport is request/response only; whole-quote data needs the opposite
direction — the server pushes each incremental tick batch to every client
subscribed to that combination. This module provides one abstract channel with
two interchangeable implementations:

* :class:`ZmqQuotePushChannel` — a ``PUB`` socket on the server, a ``SUB`` socket
  per client. Native to no-redis deployments. Fire-and-forget: a client that is
  down simply misses frames (acceptable for incremental quote pushes).
* :class:`RedisQuotePushChannel` — redis ``publish``/``subscribe`` on a
  per-account, per-combination channel, for redis deployments.

Wire encoding is msgpack when available (smaller + faster for the
``{code: {field: number}}`` payload shape), falling back to stdlib json so the
channel stays usable without the optional dependency.
"""

import ctypes
import json
import os
import threading
import time
import uuid

try:
    import msgpack

    _HAS_MSGPACK = True
except Exception:  # pragma: no cover - depends on optional dependency
    msgpack = None
    _HAS_MSGPACK = False


def encode_push_payload(payload):
    """Encode a push payload dict to bytes (msgpack preferred, json fallback)."""
    if _HAS_MSGPACK:
        return msgpack.packb(payload, use_bin_type=True)
    return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")


def decode_push_payload(blob):
    """Inverse of :func:`encode_push_payload`. Accepts bytes or str.

    Encoding is not symmetric across deployments: a server without msgpack
    falls back to json while a client with msgpack installed decodes with
    msgpack — ``msgpack.unpackb`` then raises ``ExtraData`` on the json text
    (its first byte ``{`` parses as an int, leaving trailing bytes). So try
    msgpack first, and fall back to json when the bytes are not a single
    valid msgpack object.
    """
    if blob is None:
        return None
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    if _HAS_MSGPACK:
        try:
            return msgpack.unpackb(blob, raw=False)
        except Exception:
            pass
    return json.loads(blob.decode("utf-8"))


class QuotePushChannel(object):
    """Abstract push channel. Server side: ``start_publisher`` + ``publish``.
    Client side: ``start_subscriber(topics, on_msg)``. A single instance may act
    as publisher or subscriber depending on which start method is called."""

    def start_publisher(self):
        raise NotImplementedError

    def start_subscriber(self, topics, on_msg):
        raise NotImplementedError

    def publish(self, topic, data):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError


class NullQuotePushChannel(QuotePushChannel):
    """No-op push channel for deployments with no push wire (pipe, or redis
    absent). Publishing is a silent no-op -- the alternative was
    RedisQuotePushChannel(None), whose publish raised AttributeError per event.
    """

    def start_publisher(self):
        pass

    def start_subscriber(self, topics, on_msg):
        raise NotImplementedError("no push channel on this deployment")

    def publish(self, topic, data):
        pass

    def stop(self):
        pass


WM_COPYDATA = 0x004A
WM_CLOSE = 0x0010
WM_DESTROY = 0x0002
SMTO_ABORTIFHUNG = 0x0002
WINMSG_PUSH_DATA = 3


def _winmsg_push_title_prefix(account_id=""):
    return "bigqmt:winmsg:push:%s:" % str(account_id or "default")


def _winmsg_user32():
    if os.name != "nt":
        raise RuntimeError("winmsg push channel is Windows-only")
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return kernel32, user32, wintypes


def _winmsg_ulong_ptr(wintypes):
    return getattr(wintypes, "ULONG_PTR", ctypes.c_size_t)


def _winmsg_lresult(wintypes):
    return getattr(wintypes, "LRESULT", ctypes.c_ssize_t)


def _winmsg_handle(wintypes, name):
    return getattr(wintypes, name, wintypes.HANDLE)


class WinMsgQuotePushChannel(QuotePushChannel):
    """Whole-quote / exec-event push over hidden-window ``WM_COPYDATA``.

    The server side is threadless: publishing enumerates client subscriber
    windows and sends one message to each. Only the client subscriber owns a
    message thread.
    """

    def __init__(self, account_id="", account_ids=None,
                 print_prefix="[bigqmt_quote_push]", send_timeout_seconds=1.0):
        self.account_id = str(account_id or "")
        self.account_ids = _unique_accounts([self.account_id] + list(account_ids or []))
        self.print_prefix = print_prefix
        self.send_timeout_seconds = float(send_timeout_seconds or 1.0)
        self._running = False
        self._thread = None
        self._ready = threading.Event()
        self._hwnd = None
        self._topics = set()
        self._on_msg = None
        self._error = None
        self._wndproc = None
        self._class_name = "BigQmtWinMsgPush_%s" % uuid.uuid4().hex
        self._title = _winmsg_push_title_prefix(self.account_id) + uuid.uuid4().hex
        self._kernel32 = None
        self._user32 = None
        self._wintypes = None
        self._copydata_type = None
        self._wndclass_type = None
        self._wndproc_type = None

    def _setup(self):
        if self._user32 is not None:
            return
        self._kernel32, self._user32, self._wintypes = _winmsg_user32()
        wintypes = self._wintypes
        ulong_ptr = _winmsg_ulong_ptr(wintypes)
        wndproc_type = ctypes.WINFUNCTYPE(
            _winmsg_lresult(wintypes), wintypes.HWND, wintypes.UINT,
            wintypes.WPARAM, wintypes.LPARAM)

        class COPYDATASTRUCT(ctypes.Structure):
            _fields_ = [
                ("dwData", ulong_ptr),
                ("cbData", wintypes.DWORD),
                ("lpData", ctypes.c_void_p),
            ]

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [
                ("style", wintypes.UINT),
                ("lpfnWndProc", wndproc_type),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", _winmsg_handle(wintypes, "HINSTANCE")),
                ("hIcon", _winmsg_handle(wintypes, "HICON")),
                ("hCursor", _winmsg_handle(wintypes, "HCURSOR")),
                ("hbrBackground", _winmsg_handle(wintypes, "HBRUSH")),
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
            wintypes.HWND, _winmsg_handle(wintypes, "HMENU"),
            _winmsg_handle(wintypes, "HINSTANCE"), ctypes.c_void_p,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.DestroyWindow.restype = wintypes.BOOL
        user32.DefWindowProcW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = _winmsg_lresult(wintypes)
        user32.GetMessageW.restype = wintypes.BOOL
        user32.TranslateMessage.restype = wintypes.BOOL
        user32.DispatchMessageW.restype = _winmsg_lresult(wintypes)
        user32.PostMessageW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.PostMessageW.restype = wintypes.BOOL
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.SendMessageTimeoutW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
            wintypes.UINT, wintypes.UINT, ctypes.POINTER(ulong_ptr)]
        user32.SendMessageTimeoutW.restype = ulong_ptr
        user32.EnumWindows.restype = wintypes.BOOL
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        user32.GetWindowTextW.restype = ctypes.c_int
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = _winmsg_handle(wintypes, "HMODULE")

    def start_publisher(self):
        self._running = True

    def _subscriber_titles(self):
        self._setup()
        titles = []
        prefixes = [_winmsg_push_title_prefix(a) for a in (self.account_ids or [self.account_id])]
        user32 = self._user32
        wintypes = self._wintypes

        enum_proc_type = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def enum_proc(hwnd, _lparam):
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value
            for prefix in prefixes:
                if title.startswith(prefix):
                    titles.append((hwnd, title))
                    break
            return True

        user32.EnumWindows(enum_proc_type(enum_proc), 0)
        return titles

    def _send_raw(self, hwnd, payload):
        raw = encode_push_payload(payload)
        buf = ctypes.create_string_buffer(raw)
        cds = self._copydata_type()
        cds.dwData = WINMSG_PUSH_DATA
        cds.cbData = len(raw)
        cds.lpData = ctypes.cast(buf, ctypes.c_void_p)
        result = _winmsg_ulong_ptr(self._wintypes)(0)
        timeout_ms = int(max(0.001, self.send_timeout_seconds) * 1000)
        ok = self._user32.SendMessageTimeoutW(
            hwnd, WM_COPYDATA, 0, self._wintypes.LPARAM(ctypes.addressof(cds)),
            SMTO_ABORTIFHUNG, timeout_ms, ctypes.byref(result))
        return bool(ok)

    def publish(self, topic, data):
        if not self._running:
            return
        payload = {"combo_key": topic, "data": data}
        for hwnd, _title in self._subscriber_titles():
            try:
                self._send_raw(hwnd, payload)
            except Exception as exc:
                print("%s winmsg publish failed: %s" % (self.print_prefix, exc))

    def start_subscriber(self, topics, on_msg):
        self.stop()
        self._topics = set(str(t) for t in (topics or []))
        self._on_msg = on_msg
        self._error = None
        self._running = True
        self._ready = threading.Event()
        self._thread = threading.Thread(
            target=self._sub_loop, name="bigqmt-winmsg-push-sub", daemon=True)
        self._thread.start()
        if not self._ready.wait(5.0):
            raise RuntimeError("winmsg push subscriber window did not start")
        if self._error is not None:
            raise self._error

    def _sub_loop(self):
        try:
            self._setup()
            self._wndproc = self._wndproc_type(self._handle_message)
            hinst = self._kernel32.GetModuleHandleW(None)
            cls = self._wndclass_type()
            cls.lpfnWndProc = self._wndproc
            cls.hInstance = hinst
            cls.lpszClassName = self._class_name
            atom = self._user32.RegisterClassW(ctypes.byref(cls))
            if not atom and ctypes.get_last_error() not in (1410,):
                raise RuntimeError("RegisterClassW failed")
            self._hwnd = self._user32.CreateWindowExW(
                0, self._class_name, self._title, 0,
                0, 0, 0, 0, None, None, hinst, None)
            if not self._hwnd:
                raise RuntimeError("CreateWindowExW failed")
            self._ready.set()
            msg = self._wintypes.MSG()
            while self._running:
                rc = self._user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if rc <= 0:
                    break
                self._user32.TranslateMessage(ctypes.byref(msg))
                self._user32.DispatchMessageW(ctypes.byref(msg))
        except Exception as exc:
            self._error = exc
            print("%s winmsg subscriber failed: %s" % (self.print_prefix, exc))
            self._ready.set()
        finally:
            self._hwnd = None

    def _handle_message(self, hwnd, msg, wparam, lparam):
        if msg == WM_COPYDATA:
            cds = ctypes.cast(lparam, ctypes.POINTER(self._copydata_type)).contents
            if int(cds.dwData) == WINMSG_PUSH_DATA:
                raw = ctypes.string_at(cds.lpData, cds.cbData)
                payload = decode_push_payload(raw)
                topic = str((payload or {}).get("combo_key") or "")
                if topic in self._topics:
                    try:
                        self._on_msg(topic, (payload or {}).get("data"))
                    except Exception as exc:
                        print("%s subscriber callback failed: %s" %
                              (self.print_prefix, exc))
                return 1
        if msg == WM_CLOSE:
            self._user32.DestroyWindow(hwnd)
            return 0
        if msg == WM_DESTROY:
            self._user32.PostQuitMessage(0)
            return 0
        return self._user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def stop(self):
        self._running = False
        hwnd = self._hwnd
        if hwnd:
            try:
                self._user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            except Exception:
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread() and thread.is_alive():
            thread.join(1.0)
        self._thread = None
        self._hwnd = None


class ZmqQuotePushChannel(QuotePushChannel):
    def __init__(self, bind_address=None, connect_address=None, context=None, print_prefix="[bigqmt_quote_push]", extra_bind_addresses=None):
        self.bind_address = bind_address
        self.connect_address = connect_address
        # A zmq client derives the PUB address from ITS account's RPC port
        # (+1). A multi-account bridge binds the one PUB socket to every
        # account's address as well (#315); a zmq socket may bind several.
        self.extra_bind_addresses = [str(a) for a in (extra_bind_addresses or []) if a and str(a) != str(bind_address)]
        self.print_prefix = print_prefix
        self._zmq = None
        self._context = context
        self._pub = None
        self._pub_lock = threading.Lock()
        self._sub = None
        self._sub_thread = None
        self._running = False

    def _ensure_context(self):
        if self._zmq is None:
            import zmq

            self._zmq = zmq
            if self._context is None:
                self._context = zmq.Context.instance()
        return self._zmq, self._context

    # -- server side ---------------------------------------------------------
    def start_publisher(self):
        zmq, ctx = self._ensure_context()
        if not self.bind_address:
            raise ValueError("bind_address is required to start a publisher")
        self._pub = ctx.socket(zmq.PUB)
        self._pub.bind(self.bind_address)
        for address in self.extra_bind_addresses:
            try:
                self._pub.bind(address)
            except Exception as exc:
                print("%s zmq extra bind failed address=%s: %s" % (self.print_prefix, address, exc))
        self._running = True

    def publish(self, topic, data):
        payload = encode_push_payload({"combo_key": topic, "data": data})
        frame = [str(topic).encode("utf-8"), payload]
        # PUB socket is not thread-safe; serialize under the lock and read the
        # socket inside it so a concurrent stop() (which nulls _pub) can't hand
        # us a closed socket.
        with self._pub_lock:
            pub = self._pub
            if pub is None:
                return
            try:
                pub.send_multipart(frame)
            except Exception as exc:
                print("%s zmq publish failed: %s" % (self.print_prefix, exc))

    # -- client side ---------------------------------------------------------
    def start_subscriber(self, topics, on_msg):
        zmq, ctx = self._ensure_context()
        if not self.connect_address:
            raise ValueError("connect_address is required to start a subscriber")
        sub = ctx.socket(zmq.SUB)
        sub.connect(self.connect_address)
        for topic in topics or []:
            sub.setsockopt(zmq.SUBSCRIBE, str(topic).encode("utf-8"))
        self._sub = sub
        self._running = True
        self._sub_thread = threading.Thread(
            target=self._sub_loop, args=(sub, on_msg), name="bigqmt-quote-push-sub", daemon=True
        )
        self._sub_thread.start()

    def _sub_loop(self, sub, on_msg):
        # The SUB socket is owned by THIS thread; it must be closed HERE (in a
        # finally) and never from another thread. Closing a ZMQ socket cross-
        # thread trips a Windows signaler assertion and aborts the whole QMT
        # process (the "auto-exit" users hit).
        poller = self._zmq.Poller()
        poller.register(sub, self._zmq.POLLIN)
        try:
            while self._running:
                try:
                    events = dict(poller.poll(200))
                except Exception:
                    break
                if sub not in events:
                    continue
                try:
                    frames = sub.recv_multipart(self._zmq.NOBLOCK)
                except Exception:
                    continue
                if len(frames) < 2:
                    continue
                topic = frames[0].decode("utf-8", errors="ignore")
                data = decode_push_payload(frames[-1])
                payload_data = data.get("data") if isinstance(data, dict) else data
                try:
                    on_msg(topic, payload_data)
                except Exception as exc:
                    print("%s subscriber callback failed: %s" % (self.print_prefix, exc))
        finally:
            try:
                sub.close(linger=0)
            except Exception:
                pass

    def stop(self):
        # Signal the sub thread to exit and let IT close its own socket (see
        # _sub_loop). Closing the SUB socket from this (foreign) thread would
        # trip the Windows ZMQ signaler abort and crash QMT.
        self._running = False
        thread = self._sub_thread
        if thread is not None and thread.is_alive():
            thread.join(1.0)
        self._sub_thread = None
        self._sub = None
        # The PUB socket is only touched by publisher threads under _pub_lock;
        # null it first so a racing publish() sees None and bails, then close.
        with self._pub_lock:
            pub = self._pub
            self._pub = None
        if pub is not None:
            try:
                pub.close(linger=0)
            except Exception:
                pass


def _unique_accounts(values):
    seen = []
    for value in values:
        text = str(value or "")
        if text and text not in seen:
            seen.append(text)
    return seen


class RedisQuotePushChannel(QuotePushChannel):
    def __init__(self, redis_client, account_id="", channel_template="bigqmt:quote_push:{account_id}:{topic}", print_prefix="[bigqmt_quote_push]", account_ids=None):
        self.redis = redis_client
        self.account_id = str(account_id or "")
        self.channel_template = channel_template
        self.print_prefix = print_prefix
        # Every account this publisher speaks for (#315). The channel is
        # keyed by account, and a single-instance multi-account bridge
        # (BIGQMT_ACCOUNT_TYPE_MAP) serves several: a client configured with
        # the secondary account subscribes bigqmt:quote_push:<secondary>:*,
        # its subscribe RPC lands on the shared handlers and succeeds, and
        # every push went to bigqmt:quote_push:<primary>:* -- "subscribed,
        # no callbacks". Market data is not account-specific, so publish
        # once per account. The client role uses account_id alone.
        self.account_ids = _unique_accounts([self.account_id] + list(account_ids or []))
        self._running = False
        self._pubsub = None
        self._thread = None
        self._subscriber_stop = threading.Event()

    def _channel(self, topic, account_id=None):
        return self.channel_template.format(
            account_id=self.account_id if account_id is None else account_id, topic=topic)

    # -- server side ---------------------------------------------------------
    def start_publisher(self):
        # Redis publish needs no setup; present for interface symmetry.
        self._running = True

    def publish(self, topic, data):
        payload = encode_push_payload({"combo_key": topic, "data": data})
        for account_id in self.account_ids or [self.account_id]:
            try:
                self.redis.publish(self._channel(topic, account_id), payload)
            except Exception as exc:
                print("%s redis publish failed: %s" % (self.print_prefix, exc))

    # -- client side ---------------------------------------------------------
    def start_subscriber(self, topics, on_msg):
        self.stop()
        self._running = True
        self._subscriber_stop = threading.Event()
        self._thread = threading.Thread(
            target=self._sub_loop, args=(list(topics or []), on_msg, self._subscriber_stop),
            name="bigqmt-quote-push-sub", daemon=True
        )
        self._thread.start()

    def _sub_loop(self, topics, on_msg, stopped):
        # This receiver owns reconnect and closes its own connections. Capture
        # its stop event so a later start cannot revive an old blocked receiver.
        channels = [self._channel(topic) for topic in topics]
        failures = 0          # consecutive reconnect failures, for log throttling
        last_report = 0.0
        while not stopped.is_set():
            pubsub = None
            try:
                pubsub = self.redis.pubsub(ignore_subscribe_messages=True)
                self._pubsub = pubsub
                pubsub.subscribe(*channels)
                while not stopped.is_set():
                    message = pubsub.get_message(timeout=0.2)
                    if stopped.is_set():
                        break
                    if not message or message.get("type") != "message":
                        continue
                    channel = message.get("channel")
                    if isinstance(channel, bytes):
                        channel = channel.decode("utf-8", errors="ignore")
                    topic = str(channel).rsplit(":", 1)[-1]
                    data = decode_push_payload(message.get("data"))
                    payload_data = data.get("data") if isinstance(data, dict) else data
                    try:
                        on_msg(topic, payload_data)
                    except Exception as exc:
                        print("%s subscriber callback failed: %s" % (self.print_prefix, exc))
            except Exception as exc:
                if not stopped.is_set():
                    # Retry every second -- quotes should come back fast -- but
                    # do NOT print every second. Redis down over a weekend is
                    # 3600 lines/hour, and this repo has been bitten by log
                    # volume before (#139 wrote one line 16 times; #144 grew a
                    # log without bound because rotation could never run). The
                    # zmq ROUTER rebuild backs its reporting off for the same
                    # reason (#240). Report attempts 1, 2, 4, 8 ... then at most
                    # once a minute: the first failure stays loud and a long
                    # outage stays readable.
                    failures += 1
                    now = time.time()
                    if (failures & (failures - 1)) == 0 or now - last_report >= 60.0:
                        last_report = now
                        print("%s redis subscriber reconnecting (attempt %d): %s"
                              % (self.print_prefix, failures, exc))
            else:
                failures = 0
            finally:
                if pubsub is not None:
                    try:
                        pubsub.close()
                    except Exception:
                        pass
            stopped.wait(1.0)

    def stop(self):
        self._running = False
        self._subscriber_stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread() and thread.is_alive():
            thread.join(1.0)
        self._thread = None
        self._pubsub = None
