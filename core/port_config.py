"""用于解析 WireGuard 默认监听端口的实用函数。Helpers for resolving the default WireGuard listen port."""
from __future__ import annotations

import os
import random
import socket

from core.config.defaults import DEFAULT_WG_PORT, WG_PORT_FALLBACK_RANGE
from core.logging_utils import get_logger

LOGGER = get_logger(__name__)

ENV_KEYS = (
    "PRIVATETUNNEL_WG_PORT",
    "PT_WG_PORT",
    "WG_PORT",
)


def _parse_port(value: str, *, source: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"环境变量 {source} 的值必须是有效的整数端口号，当前为: {value!r}") from exc

    if not 1 <= port <= 65535:
        raise ValueError(
            f"环境变量 {source} 的值 {port} 超出有效范围 (1-65535)。"
        )
    return port


def _is_port_available(port: int) -> bool:
    """Return ``True`` if *port* is likely free on localhost."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        result = sock.connect_ex(("127.0.0.1", port))
        return result != 0


def _choose_fallback_port() -> int | None:
    """Pick an available port from :data:`WG_PORT_FALLBACK_RANGE`."""

    start, end = WG_PORT_FALLBACK_RANGE
    candidates = list(range(start, end + 1))
    random.shuffle(candidates)

    for port in candidates:
        if _is_port_available(port):
            LOGGER.info("Fallback port candidate available", extra={"port": port})
            return port
        LOGGER.debug("Fallback port candidate in use", extra={"port": port})
    return None


def resolve_listen_port() -> tuple[int, str | None]:
    """Return the listen port and the environment variable that defined it."""

    for key in ENV_KEYS:
        value = os.environ.get(key)
        if value:
            port = _parse_port(value, source=key)
            LOGGER.info("Using WireGuard port from env", extra={"port": port, "source": key})
            return port, key

    LOGGER.info("No explicit WireGuard port provided; testing default", extra={"port": DEFAULT_WG_PORT})
    if _is_port_available(DEFAULT_WG_PORT):
        LOGGER.info("WireGuard port available", extra={"port": DEFAULT_WG_PORT})
        return DEFAULT_WG_PORT, None

    LOGGER.warning(
        "Default WireGuard port unavailable; searching fallback range",
        extra={
            "default_port": DEFAULT_WG_PORT,
            "range_start": WG_PORT_FALLBACK_RANGE[0],
            "range_end": WG_PORT_FALLBACK_RANGE[1],
        },
    )
    fallback_port = _choose_fallback_port()
    if fallback_port is None:
        raise RuntimeError(
            f"无法在 {WG_PORT_FALLBACK_RANGE[0]}-{WG_PORT_FALLBACK_RANGE[1]} 找到可用端口。"
        )

    LOGGER.info(
        "Selected fallback WireGuard port",
        extra={
            "selected_port": fallback_port,
            "range_start": WG_PORT_FALLBACK_RANGE[0],
            "range_end": WG_PORT_FALLBACK_RANGE[1],
        },
    )
    return fallback_port, None


def get_default_wg_port() -> int:
    """Return the WireGuard listen port derived from environment variables.

    The helper inspects ``PRIVATETUNNEL_WG_PORT`` (preferred), ``PT_WG_PORT`` and
    ``WG_PORT``. The first non-empty variable wins. Values must be integers within
    the 1-65535 range. When no overrides are present the default ``51820`` from
    :mod:`core.config.defaults` is returned.
    """

    port, _ = resolve_listen_port()
    return port

