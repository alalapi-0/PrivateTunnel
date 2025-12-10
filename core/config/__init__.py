"""Centralized configuration defaults for PrivateTunnel.

This package consolidates common constants to avoid scattered hard-coded
values across the project and to prepare for future environment profiles.
"""

from .defaults import (
    DEFAULT_ALLOWED_IPS,
    DEFAULT_CLIENT_MTU,
    DEFAULT_DESKTOP_ADDRESS,
    DEFAULT_DNS_LIST,
    DEFAULT_DNS_STRING,
    DEFAULT_IPHONE_ADDRESS,
    DEFAULT_KEEPALIVE_SECONDS,
    DEFAULT_SERVER_ADDRESS,
    DEFAULT_SUBNET_CIDR,
    DEFAULT_WG_PORT,
)
from .env_profiles import DEFAULT_PROFILE, EnvProfile

__all__ = [
    "DEFAULT_ALLOWED_IPS",
    "DEFAULT_CLIENT_MTU",
    "DEFAULT_DESKTOP_ADDRESS",
    "DEFAULT_DNS_LIST",
    "DEFAULT_DNS_STRING",
    "DEFAULT_IPHONE_ADDRESS",
    "DEFAULT_KEEPALIVE_SECONDS",
    "DEFAULT_PROFILE",
    "DEFAULT_SERVER_ADDRESS",
    "DEFAULT_SUBNET_CIDR",
    "DEFAULT_WG_PORT",
    "EnvProfile",
]
