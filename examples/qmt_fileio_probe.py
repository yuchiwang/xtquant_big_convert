#encoding:gbk
"""
Big QMT file-I/O probe using only Python built-ins.

Usage outside QMT:
    python examples/qmt_fileio_probe.py --roundtrip
    python examples/qmt_fileio_probe.py --write
    python examples/qmt_fileio_probe.py --read
    python examples/qmt_fileio_probe.py --path D:\\tmp\\qmt_fileio_probe.jsonl --roundtrip

Usage inside a Big QMT strategy:
    1. Copy/import this file into QMT.
    2. Run the strategy. init() writes one record and reads it back.
       handle_bar() appends one record per bar and verifies the file is readable.

This probe proves that Big QMT's bundled Python can write, flush, fsync, and
read local files at a known path.
"""

from __future__ import print_function

import argparse
import json
import os
import tempfile
import time
import uuid


PROBE_NAME = "qmt_fileio_probe"
DEFAULT_FILENAME = PROBE_NAME + ".jsonl"
# Set this to a known writable path inside Big QMT if you do not want to use
# the system temp directory, for example: r"D:\qmt_fileio_probe.jsonl"
PROBE_PATH = ""


def default_probe_path():
    if PROBE_PATH:
        return PROBE_PATH
    base = os.environ.get("QMT_FILEIO_PROBE_DIR")
    if not base:
        base = tempfile.gettempdir()
    return os.path.join(base, DEFAULT_FILENAME)


def _json_line(payload):
    return json.dumps(
        payload, ensure_ascii=False, default=str,
        separators=(",", ":")) + "\n"


def _ensure_parent(path):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)


def write_record(path, method="write_probe", params=None):
    _ensure_parent(path)
    record = {
        "ok": True,
        "probe": PROBE_NAME,
        "request_id": uuid.uuid4().hex,
        "method": method,
        "params": params or {},
        "pid": os.getpid(),
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "time_epoch": time.time(),
    }
    with open(path, "ab") as fp:
        raw = _json_line(record).encode("utf-8")
        fp.write(raw)
        fp.flush()
        os.fsync(fp.fileno())
    return record


def read_records(path, limit=10):
    if not os.path.exists(path):
        return []
    with open(path, "rb") as fp:
        lines = fp.readlines()
    if limit:
        lines = lines[-int(limit):]
    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line.decode("utf-8")))
    return records


def roundtrip(path, method="roundtrip_probe", params=None):
    written = write_record(path, method=method, params=params)
    records = read_records(path, limit=20)
    found = False
    for record in records:
        if record.get("request_id") == written["request_id"]:
            found = True
            break
    return {
        "ok": found,
        "path": os.path.abspath(path),
        "written": written,
        "records_read": len(records),
    }


def _qmt_log(text):
    logger = globals().get("log")
    if logger is not None and hasattr(logger, "info"):
        logger.info(text)
    else:
        print(text)


def init(context):
    path = default_probe_path()
    result = roundtrip(path, "init_fileio_ping", {"source": "bigqmt"})
    _qmt_log("[FileIOProbe] init result: %s" % result)


def handle_bar(context, bar):
    symbol = getattr(bar, "symbol", "")
    path = default_probe_path()
    result = roundtrip(path, "bar_fileio_ping", {
        "symbol": symbol,
        "ts": time.time(),
    })
    _qmt_log("[FileIOProbe] bar result: %s" % result)


def stop(context):
    _qmt_log("[FileIOProbe] stop")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=default_probe_path(), help="probe file path")
    parser.add_argument("--write", action="store_true", help="append one JSONL record")
    parser.add_argument("--read", action="store_true", help="read recent records")
    parser.add_argument("--roundtrip", action="store_true", help="write then read back")
    parser.add_argument("--limit", type=int, default=10, help="records to read")
    args = parser.parse_args(argv)

    if args.write:
        print(write_record(args.path, "cli_write", {"source": "cli"}))
    elif args.read:
        print(read_records(args.path, args.limit))
    elif args.roundtrip:
        print(roundtrip(args.path, "cli_roundtrip", {"source": "cli"}))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
