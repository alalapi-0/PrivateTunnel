"""Environment profile scaffolding.

Profiles make it possible to describe variations of default parameters
without changing call sites. Only a default profile is provided for now,
mirroring existing behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .defaults import (
    DEFAULT_CLIENT_MTU,
    DEFAULT_DNS_LIST,
    DEFAULT_KEEPALIVE_SECONDS,
    DEFAULT_WG_PORT,
)


@dataclass(frozen=True)
class EnvProfile:
    """Collection of baseline parameters for a deployment environment."""

    name: str
    wg_port: int
    dns_list: List[str]
    client_mtu: int
    keepalive_seconds: int


DEFAULT_PROFILE = EnvProfile(
    name="default",
    wg_port=DEFAULT_WG_PORT,
    dns_list=DEFAULT_DNS_LIST,
    client_mtu=DEFAULT_CLIENT_MTU,
    keepalive_seconds=DEFAULT_KEEPALIVE_SECONDS,
)
