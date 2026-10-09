# coding: utf-8
"""Client-side private config for the WinMsg transport.

Copy this file to:

    src/bigqmt_signal_trader_client_config.py

or load it explicitly with:

    BIGQMT_CLIENT_CONFIG_MODULE=bigqmt_signal_trader_client_config_winmsg

The QMT-side config must also use ``transport="winmsg"``.
"""

BIGQMT_ACCOUNT_ID = "8885456416"
BIGQMT_RPC_TIMEOUT_SECONDS = 60.0
BIGQMT_DOWNLOAD_WAIT_SECONDS = 1800
BIGQMT_DOWNLOAD_POLL_INTERVAL_SECONDS = 0.5

BIGQMT_REDIS_CONFIG = {
    # 查询失败时是否用 Redis 里的旧快照兜底。WinMsg 无 Redis 部署建议保持 False。
    # "account_cache_fallback": False,
    # "account_cache_max_age_seconds": 30,

    "transport": "winmsg",
    "winmsg": {
        "window_name": "bigqmt_rpc",
        "max_payload_bytes": 4 * 1024 * 1024,
    },
}

BIGQMT_FULL_TICK_CACHE_CONFIG = {
    "enabled": False,
    "demand_ttl_seconds": 10,
    "cache_ttl_seconds": 10,
    "wait_seconds": 3.5,
    "poll_interval_seconds": 0.2,
}

BIGQMT_LOCAL_CACHE_CONFIG = {
    "enabled": True,
    "dir": None,
    "fallback_rpc": True,
    "format": "auto",
}

BIGQMT_FORMULA_SERVER_CONFIG = {
    "enabled": True,
    # "host": "127.0.0.1",
    # "port": 58600,
    # "qmt_root": r"D:\国金证券QMT交易端",
    # "timeout_seconds": 3.0,
    # "methods": [...],
    # "failure_cooldown_seconds": 30.0,
}

# Whole-quote PUSH / exec callbacks use WinMsg hidden-window push when
# transport="winmsg". Keep this id stable if you rely on replay/recovery.
BIGQMT_QUOTE_CLIENT_ID = None
# BIGQMT_QUOTE_HEARTBEAT_SECONDS = 3.0

