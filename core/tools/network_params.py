"""Helpers for deriving network parameters like keepalive and MTU."""

from __future__ import annotations

import random
from typing import Callable

from core.config.defaults import (
    DEFAULT_CLIENT_MTU,
    DEFAULT_KEEPALIVE_BASE,
    DEFAULT_KEEPALIVE_JITTER_RANGE,
    KEEPALIVE_MAX,
    KEEPALIVE_MIN,
)
from core.logging_utils import get_logger

LOGGER = get_logger(__name__)


def generate_keepalive_value(user_keepalive: int | None = None) -> int:
    """Return a keepalive value respecting user overrides and jitter."""

    if user_keepalive is not None:
        LOGGER.info(
            "Keepalive override provided; skip jitter",
            extra={"keepalive": user_keepalive},
        )
        return user_keepalive

    low, high = DEFAULT_KEEPALIVE_JITTER_RANGE
    jitter = random.randint(low, high)
    value = DEFAULT_KEEPALIVE_BASE + jitter
    final_value = max(KEEPALIVE_MIN, min(KEEPALIVE_MAX, value))
    LOGGER.info(
        "Keepalive chosen with jitter",
        extra={
            "base": DEFAULT_KEEPALIVE_BASE,
            "jitter": jitter,
            "final": final_value,
        },
    )
    return final_value


def try_probe_mtu_or_none(probe_func: Callable[[], int | None] | None = None) -> int | None:
    """Attempt to probe MTU via *probe_func* or return ``None``.

    A placeholder is kept to make it easy to hook future adaptive probing
    logic without changing callers.
    """

    if probe_func is None:
        return None

    try:
        return probe_func()
    except Exception as exc:  # noqa: BLE001 - probe failures should be non-fatal
        LOGGER.warning("MTU probe failed", extra={"error": str(exc)})
        return None


def decide_client_mtu(user_mtu: int | None = None, probe_func: Callable[[], int | None] | None = None) -> int:
    """Decide the client MTU using user, probe, then default priority."""

    if user_mtu is not None:
        LOGGER.info("Using user-provided MTU", extra={"mtu": user_mtu})
        return user_mtu

    mtu_from_probe = try_probe_mtu_or_none(probe_func)
    if mtu_from_probe is not None:
        LOGGER.info("Using probed MTU", extra={"mtu": mtu_from_probe})
        return mtu_from_probe

    LOGGER.info("Using default MTU", extra={"mtu": DEFAULT_CLIENT_MTU})
    return DEFAULT_CLIENT_MTU

