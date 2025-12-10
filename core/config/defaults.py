"""Project-wide default values for PrivateTunnel.

These constants capture the baseline deployment settings that were
previously hard-coded across the codebase. Keeping them centralized makes
it easier to audit and adjust defaults without changing behavior.
"""

DEFAULT_WG_PORT = 443
WG_PORT_FALLBACK_RANGE = (20000, 45000)

DEFAULT_DNS_LIST = [
    "223.5.5.5",  # AliDNS
    "114.114.114.114",  # 114
    "1.1.1.1",  # Cloudflare
    "8.8.8.8",  # Google
]
DEFAULT_DNS_STRING = ", ".join(DEFAULT_DNS_LIST)
DEFAULT_CLIENT_MTU = 1420

DEFAULT_KEEPALIVE_BASE = 20
DEFAULT_KEEPALIVE_JITTER_RANGE = (-5, 10)
KEEPALIVE_MIN = 10
KEEPALIVE_MAX = 60
DEFAULT_KEEPALIVE_SECONDS = DEFAULT_KEEPALIVE_BASE
DEFAULT_SUBNET_CIDR = "10.6.0.0/24"
DEFAULT_SERVER_ADDRESS = "10.6.0.1/24"
DEFAULT_IPHONE_ADDRESS = "10.6.0.2/32"
DEFAULT_DESKTOP_ADDRESS = "10.6.0.3/32"
DEFAULT_ALLOWED_IPS = "0.0.0.0/0, ::/0"
