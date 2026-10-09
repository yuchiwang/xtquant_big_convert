# coding: utf-8
"""Hidden-window WM_COPYDATA transport tests."""

import os
import sys
import threading
import time
import unittest
import uuid


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))

from bigqmt_signal_trader.transports.base import TransportError, TransportTimeout  # noqa: E402
from bigqmt_signal_trader.transports.factory import KNOWN_TRANSPORTS, build_transport  # noqa: E402
from bigqmt_signal_trader.transports.winmsg_transport import WinMsgTransport  # noqa: E402


WINDOWS_ONLY = unittest.skipUnless(os.name == "nt", "winmsg is Windows-only")


def _name(prefix):
    return "%s_%s" % (prefix, uuid.uuid4().hex)


def _request(rid="r1", method="ping", params=None):
    return {
        "schema_version": 1,
        "request_id": rid,
        "account_id": "acct",
        "method": method,
        "params": params or {},
    }


def _echo(request):
    return {
        "schema_version": 1,
        "request_id": request.get("request_id"),
        "account_id": "acct",
        "method": request.get("method"),
        "ok": True,
        "data": {"echo": request.get("params")},
        "error": "",
    }


class FactoryTest(unittest.TestCase):
    def test_winmsg_is_known(self):
        self.assertIn("winmsg", KNOWN_TRANSPORTS)

    def test_factory_builds_winmsg(self):
        transport = build_transport(
            "winmsg",
            {"winmsg": {"window_name": "custom", "max_payload_bytes": 12345}},
            account_id="acct",
        )
        self.assertEqual(transport.name, "winmsg")
        self.assertEqual(transport.window_name, "custom")
        self.assertEqual(transport.max_payload_bytes, 12345)

    def test_winmsg_defaults_to_adjust_drain(self):
        from bigqmt_signal_trader_strategy import _resolve_background_threads

        self.assertFalse(_resolve_background_threads("winmsg", None))
        self.assertFalse(_resolve_background_threads("winmsg", False))
        self.assertTrue(_resolve_background_threads("winmsg", True))


class NonWindowsTest(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "this test covers non-Windows failures")
    def test_send_fails_fast_with_clear_message(self):
        client = WinMsgTransport(account_id="acct")
        with self.assertRaises(TransportError) as caught:
            client.send_request(_request(), 0.1)
        self.assertIn("Windows-only", str(caught.exception))


class _Pair(object):
    def __init__(self, on_request=_echo, max_payload_bytes=4 * 1024 * 1024):
        self.window_name = _name("bigqmt_test_winmsg")
        self.server = WinMsgTransport(
            account_id="acct",
            window_name=self.window_name,
            max_payload_bytes=max_payload_bytes,
        )
        self.server.start_receiving(on_request)
        self.client = WinMsgTransport(
            account_id="acct",
            window_name=self.window_name,
            max_payload_bytes=max_payload_bytes,
        )

    def close(self):
        self.client.stop()
        self.server.stop()

    def call(self, request, timeout_seconds=3.0):
        result = {}

        def invoke():
            try:
                result["response"] = self.client.send_request(request, timeout_seconds)
            except Exception as exc:
                result["error"] = exc

        thread = threading.Thread(target=invoke)
        thread.daemon = True
        thread.start()
        deadline = time.time() + timeout_seconds
        while thread.is_alive() and time.time() < deadline:
            self.server.drain_request_queue(max_items=20)
            time.sleep(0.01)
        thread.join(1.0)
        if thread.is_alive():
            raise AssertionError("client did not return")
        if "error" in result:
            raise result["error"]
        return result.get("response")


@WINDOWS_ONLY
class RoundTripTest(unittest.TestCase):
    def setUp(self):
        self.pair = _Pair()
        self.addCleanup(self.pair.close)

    def test_round_trip_keeps_request_id(self):
        out = self.pair.call(
            _request("r1", params={"a": 1}), timeout_seconds=3.0)
        self.assertTrue(out["ok"])
        self.assertEqual(out["request_id"], "r1")
        self.assertEqual(out["data"]["echo"], {"a": 1})

    def test_utf8_survives(self):
        out = self.pair.call(
            _request("r2", params={"名称": "转债分钟线", "值": 3.35}),
            timeout_seconds=3.0,
        )
        self.assertEqual(out["data"]["echo"]["名称"], "转债分钟线")
        self.assertEqual(out["data"]["echo"]["值"], 3.35)

    def test_medium_payload_survives(self):
        payload = {"text": "x" * (1024 * 1024)}
        out = self.pair.call(
            _request("r3", params=payload), timeout_seconds=10.0)
        self.assertEqual(len(out["data"]["echo"]["text"]), 1024 * 1024)

    def test_handler_exception_returns_error_envelope(self):
        pair = _Pair(on_request=lambda request: (_ for _ in ()).throw(
            RuntimeError("handler exploded")))
        self.addCleanup(pair.close)
        out = pair.call(_request("boom"), timeout_seconds=3.0)
        self.assertFalse(out["ok"])
        self.assertIn("handler exploded", out["error"])

    def test_payload_limit_is_enforced(self):
        pair = _Pair(max_payload_bytes=1024)
        self.addCleanup(pair.close)
        with self.assertRaises(TransportError) as caught:
            pair.client.send_request(
                _request("too-big", params={"text": "x" * 2000}),
                timeout_seconds=3.0,
            )
        self.assertIn("payload too large", str(caught.exception))


@WINDOWS_ONLY
class TimeoutAndConcurrencyTest(unittest.TestCase):
    def test_missing_server_window_has_actionable_error(self):
        client = WinMsgTransport(
            account_id="acct",
            window_name=_name("bigqmt_test_absent_winmsg"),
            startup_timeout_seconds=1.0,
        )
        self.addCleanup(client.stop)
        with self.assertRaises(TransportError) as caught:
            client.send_request(_request("missing"), timeout_seconds=0.2)
        self.assertIn("transport=winmsg", str(caught.exception))

    def test_response_timeout(self):
        pair = _Pair(on_request=lambda request: None)
        self.addCleanup(pair.close)
        with self.assertRaises(TransportTimeout):
            pair.call(_request("timeout"), timeout_seconds=0.2)

    def test_concurrent_callers_do_not_cross_responses(self):
        pair = _Pair()
        self.addCleanup(pair.close)
        errors = []
        lock = threading.Lock()
        threads = []

        def worker(wid):
            for i in range(10):
                rid = "w%d-%d" % (wid, i)
                try:
                    out = pair.client.send_request(
                        _request(rid, params={"w": wid, "i": i}),
                        timeout_seconds=10.0,
                    )
                except Exception as exc:
                    with lock:
                        errors.append((rid, repr(exc)))
                    continue
                if out.get("request_id") != rid:
                    with lock:
                        errors.append(("crossed", rid, out.get("request_id")))
                elif out["data"]["echo"]["w"] != wid:
                    with lock:
                        errors.append(("payload", rid))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for thread in threads:
            thread.start()
        deadline = time.time() + 10.0
        while any(thread.is_alive() for thread in threads) and time.time() < deadline:
            pair.server.drain_request_queue(max_items=20)
            time.sleep(0.01)
        for thread in threads:
            thread.join(timeout=1)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors[:5], [], "winmsg concurrency errors: %r" % errors[:5])

    def test_stop_is_idempotent(self):
        pair = _Pair()
        pair.close()
        started = time.time()
        pair.close()
        self.assertLess(time.time() - started, 2.0)

    def test_same_window_name_can_restart_in_process(self):
        window_name = _name("bigqmt_test_restart_winmsg")
        first = WinMsgTransport(account_id="acct", window_name=window_name)
        first.start_receiving(_echo)
        client = WinMsgTransport(account_id="acct", window_name=window_name)
        try:
            result = {}
            thread = threading.Thread(target=lambda: result.setdefault(
                "response", client.send_request(_request("first"), 3.0)))
            thread.daemon = True
            thread.start()
            while thread.is_alive():
                first.drain_request_queue(max_items=20)
                time.sleep(0.01)
            thread.join(1.0)
            self.assertEqual(
                result["response"]["request_id"],
                "first",
            )
        finally:
            client.stop()
            first.stop()

        second = WinMsgTransport(account_id="acct", window_name=window_name)
        second.start_receiving(_echo)
        client2 = WinMsgTransport(account_id="acct", window_name=window_name)
        try:
            result = {}
            thread = threading.Thread(target=lambda: result.setdefault(
                "response", client2.send_request(_request("second"), 3.0)))
            thread.daemon = True
            thread.start()
            while thread.is_alive():
                second.drain_request_queue(max_items=20)
                time.sleep(0.01)
            thread.join(1.0)
            self.assertEqual(
                result["response"]["request_id"],
                "second",
            )
        finally:
            client2.stop()
            second.stop()


if __name__ == "__main__":
    unittest.main()

