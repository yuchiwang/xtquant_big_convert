#encoding:gbk
"""
Big QMT named-pipe probe using ctypes + kernel32 only.

Usage outside QMT:
    python examples/qmt_pipe_probe.py --server
    python examples/qmt_pipe_probe.py --client
    python examples/qmt_pipe_probe.py --stop

Usage inside a Big QMT strategy:
    1. Start the server command above in a normal Windows terminal.
    2. Put this file's client part into a QMT strategy, or import/copy the
       whole file if your QMT editor allows it.
    3. Run the strategy. init() sends one ping; handle_bar() sends one ping
       per bar and prints the round-trip result.

The probe proves that Big QMT can call kernel32 via ctypes and exchange
UTF-8 JSON messages with another process through a local Windows named pipe.
"""

from __future__ import print_function

import argparse
import ctypes
import json
import os
import threading
import time
import uuid
from ctypes import wintypes


PIPE_NAME = "qmt_pipe_probe"
ACCOUNT_ID = "default"
PIPE_ROOT = "\\\\.\\pipe\\"

PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_MESSAGE = 0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT = 0x00000000
PIPE_UNLIMITED_INSTANCES = 255
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_FILE_NOT_FOUND = 2
ERROR_INVALID_HANDLE = 6
ERROR_BROKEN_PIPE = 109
ERROR_PIPE_NOT_CONNECTED = 233
ERROR_PIPE_BUSY = 231
ERROR_MORE_DATA = 234
ERROR_OPERATION_ABORTED = 995
ERROR_PIPE_CONNECTED = 535

BUFFER_BYTES = 1 << 20
CONNECT_POLL_SECONDS = 0.05
CONNECT_TIMEOUT_SECONDS = 15.0


if os.name != "nt":
    raise RuntimeError("named-pipe probe is Windows-only")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.CreateNamedPipeW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
kernel32.ConnectNamedPipe.restype = wintypes.BOOL
kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
kernel32.FlushFileBuffers.restype = wintypes.BOOL
kernel32.SetNamedPipeHandleState.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p, ctypes.c_void_p]
kernel32.SetNamedPipeHandleState.restype = wintypes.BOOL
kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
kernel32.CancelIoEx.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def pipe_path(pipe_name=PIPE_NAME, account_id=ACCOUNT_ID):
    suffix = ("_" + str(account_id)) if account_id else ""
    return PIPE_ROOT + str(pipe_name or PIPE_NAME) + suffix


def _json_bytes(payload):
    return json.dumps(
        payload, ensure_ascii=False, default=str,
        separators=(",", ":")).encode("utf-8")


def _last_error():
    return ctypes.get_last_error()


def _write(handle, payload):
    buf = ctypes.create_string_buffer(payload)
    written = wintypes.DWORD(0)
    ok = kernel32.WriteFile(
        handle, buf, len(payload), ctypes.byref(written), None)
    if not ok:
        raise OSError(_last_error(), "WriteFile failed")
    if written.value != len(payload):
        raise IOError("short WriteFile: %s of %s" % (written.value, len(payload)))


def _read(handle):
    buf = ctypes.create_string_buffer(BUFFER_BYTES)
    read = wintypes.DWORD(0)
    chunks = []
    while True:
        ok = kernel32.ReadFile(
            handle, buf, BUFFER_BYTES, ctypes.byref(read), None)
        if read.value:
            chunks.append(ctypes.string_at(buf, read.value))
        if ok:
            break
        err = _last_error()
        if err == ERROR_MORE_DATA:
            continue
        if err in (ERROR_OPERATION_ABORTED, ERROR_INVALID_HANDLE,
                   ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED):
            return b""
        raise OSError(err, "ReadFile failed")
    return b"".join(chunks)


def _close(handle):
    if handle is not None and handle != INVALID_HANDLE_VALUE:
        try:
            kernel32.CloseHandle(handle)
        except Exception:
            pass


class PipeProbeClient(object):
    def __init__(self, pipe_name=PIPE_NAME, account_id=ACCOUNT_ID,
                 connect_timeout_seconds=CONNECT_TIMEOUT_SECONDS):
        self.path = pipe_path(pipe_name, account_id)
        self.connect_timeout_seconds = float(connect_timeout_seconds)

    def _connect(self):
        deadline = time.time() + self.connect_timeout_seconds
        while True:
            handle = kernel32.CreateFileW(
                self.path, GENERIC_READ | GENERIC_WRITE, 0, None,
                OPEN_EXISTING, 0, None)
            if handle != INVALID_HANDLE_VALUE:
                mode = wintypes.DWORD(PIPE_READMODE_MESSAGE)
                kernel32.SetNamedPipeHandleState(
                    handle, ctypes.byref(mode), None, None)
                return handle
            err = _last_error()
            if err not in (ERROR_PIPE_BUSY, ERROR_FILE_NOT_FOUND) \
                    or time.time() >= deadline:
                raise OSError(
                    err,
                    "cannot connect to named pipe %s after %.1fs; "
                    "start external server first: "
                    "python examples/qmt_pipe_probe.py --server" % (
                        self.path, self.connect_timeout_seconds))
            time.sleep(CONNECT_POLL_SECONDS)

    def _cancel_read(self, handle):
        try:
            kernel32.CancelIoEx(handle, None)
        except Exception:
            pass

    def send_request(self, payload, timeout_seconds=3.0):
        request_id = payload.get("request_id") or uuid.uuid4().hex
        payload = dict(payload)
        payload["request_id"] = request_id
        handle = self._connect()
        watchdog = None
        try:
            _write(handle, _json_bytes(payload))
            if timeout_seconds:
                watchdog = threading.Timer(
                    float(timeout_seconds), self._cancel_read, args=(handle,))
                watchdog.daemon = True
                watchdog.start()
            raw = _read(handle)
            if not raw:
                raise RuntimeError("timeout waiting for named-pipe response")
            return json.loads(raw.decode("utf-8"))
        finally:
            if watchdog is not None:
                watchdog.cancel()
            _close(handle)

    def stop_server(self):
        return self.send_request({"method": "__stop__", "params": {}}, 2.0)


class PipeProbeServer(object):
    def __init__(self, pipe_name=PIPE_NAME, account_id=ACCOUNT_ID):
        self.path = pipe_path(pipe_name, account_id)
        self.running = True
        self.handles_lock = threading.RLock()
        self.handles = []

    def _new_pipe(self):
        handle = kernel32.CreateNamedPipeW(
            self.path, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, BUFFER_BYTES, BUFFER_BYTES, 0, None)
        if handle == INVALID_HANDLE_VALUE:
            raise OSError(_last_error(), "CreateNamedPipeW failed")
        with self.handles_lock:
            self.handles.append(handle)
        return handle

    def _forget_handle(self, handle):
        with self.handles_lock:
            if handle in self.handles:
                self.handles.remove(handle)

    def _close_pipe(self, handle):
        self._forget_handle(handle)
        try:
            kernel32.CancelIoEx(handle, None)
        except Exception:
            pass
        try:
            kernel32.DisconnectNamedPipe(handle)
        except Exception:
            pass
        _close(handle)

    def _serve_one(self):
        handle = self._new_pipe()
        try:
            connected = kernel32.ConnectNamedPipe(handle, None)
            if not connected and _last_error() != ERROR_PIPE_CONNECTED:
                return
            raw = _read(handle)
            if not raw:
                return
            request = json.loads(raw.decode("utf-8"))
            method = request.get("method")
            response = {
                "ok": True,
                "request_id": request.get("request_id"),
                "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "echo": request,
            }
            if method == "__stop__":
                response["stopping"] = True
                self.running = False
            _write(handle, _json_bytes(response))
            kernel32.FlushFileBuffers(handle)
            print("[pipe-probe] request %s method=%s" % (
                request.get("request_id"), method))
        except Exception as exc:
            print("[pipe-probe] server error: %r" % (exc,))
        finally:
            self._close_pipe(handle)

    def stop(self):
        self.running = False
        with self.handles_lock:
            handles = list(self.handles)
        for handle in handles:
            self._close_pipe(handle)
        try:
            handle = kernel32.CreateFileW(
                self.path, GENERIC_READ | GENERIC_WRITE, 0, None,
                OPEN_EXISTING, 0, None)
            _close(handle)
        except Exception:
            pass

    def run_forever(self):
        print("[pipe-probe] server ready: path=%s" % self.path)
        try:
            while self.running:
                self._serve_one()
        except KeyboardInterrupt:
            self.stop()


pipe = None


def _qmt_log(text):
    logger = globals().get("log")
    if logger is not None and hasattr(logger, "info"):
        logger.info(text)
    else:
        print(text)


def init(context):
    global pipe
    pipe = PipeProbeClient()
    _qmt_log("[PipeProbe] connecting to %s" % pipe.path)
    response = pipe.send_request(
        {"method": "init_ping", "params": {"source": "bigqmt"}})
    _qmt_log("[PipeProbe] init ok: %s" % response)


def handle_bar(context, bar):
    global pipe
    if pipe is None:
        pipe = PipeProbeClient()
        _qmt_log("[PipeProbe] connecting to %s" % pipe.path)
    symbol = getattr(bar, "symbol", "")
    response = pipe.send_request({
        "method": "bar_ping",
        "params": {"symbol": symbol, "ts": time.time()},
    })
    _qmt_log("[PipeProbe] bar response: %s" % response)


def stop(context):
    global pipe
    pipe = None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action="store_true", help="run external echo server")
    parser.add_argument("--client", action="store_true", help="run a normal Python client ping")
    parser.add_argument("--stop", action="store_true", help="stop external echo server")
    args = parser.parse_args(argv)
    if args.server:
        PipeProbeServer().run_forever()
    elif args.client:
        client = PipeProbeClient()
        print(client.send_request({"method": "cli_ping", "params": {"pid": os.getpid()}}))
    elif args.stop:
        client = PipeProbeClient(connect_timeout_seconds=1.0)
        print(client.stop_server())
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
