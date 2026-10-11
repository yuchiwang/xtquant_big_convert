# coding: utf-8
"""QMT-side private config for the WinMsg transport.

Copy this file to the QMT python directory as:

    bigqmt_signal_trader_local_config.py

The client-side config must also use ``transport="winmsg"``.
"""

BIGQMT_ACCOUNT_ID = "8885456416"
BIGQMT_ACCOUNT_TYPE = "STOCK"

BIGQMT_REDIS_CONFIG = {
    # WinMsg is for no-redis/no-socket same-session deployments. Keep Redis
    # disabled so identity/cache/download/event helpers do not try to connect.
    "redis_enabled": False,

    "transport": "winmsg",
    "winmsg": {
        "window_name": "bigqmt_rpc",
        "max_payload_bytes": 4 * 1024 * 1024,
    },

    # Keep order RPC disabled unless you explicitly want remote order/cancel.
    "rpc_allow_order_methods": True,

    # WinMsg server receives on the QMT thread via drain_request_queue().
    # Do not run QMT handlers on a background Python thread.
    "rpc_process_in_listener": True,
    "rpc_listener_methods": ("*",),
    "rpc_background_threads": False,
    "schedule_adjust": True,
    "schedule_adjust_interval": "100nMilliSecond",

    "full_tick_cache_enabled": False,
    "full_tick_demand_ttl_seconds": 10,
    "full_tick_cache_ttl_seconds": 10,
    "full_tick_refresh_interval_seconds": 0.5,
    "full_tick_market_refresh_interval_seconds": 3,
    "full_tick_refresh_max_wall_seconds": 0.3,
    "full_tick_max_requests": 8,

    # Async download jobs need Redis as the job/status store. In pure WinMsg
    # mode there is no Redis client to pump, so keep the scheduler path quiet.
    "download_jobs_enabled": False,
    "download_job_chunk_size": 10,
    "download_job_max_wall_seconds": 0.5,
    "download_job_ttl_seconds": 3600,

    # Order/deal callbacks are pushed through WinMsgQuotePushChannel when Redis
    # is disabled and transport="winmsg".
    "exec_events_enabled": True,
    "exec_events_debug_raw_fields": False,
}

