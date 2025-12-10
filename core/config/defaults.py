"""Project-wide default values for PrivateTunnel.

These constants capture the baseline deployment settings that were
previously hard-coded across the codebase. Keeping them centralized makes
it easier to audit and adjust defaults without changing behavior.
"""

DEFAULT_WG_PORT = 51820
DEFAULT_DNS_LIST = ["1.1.1.1", "8.8.8.8"]
DEFAULT_DNS_STRING = ", ".join(DEFAULT_DNS_LIST)
DEFAULT_CLIENT_MTU = 1280
DEFAULT_KEEPALIVE_SECONDS = 25
DEFAULT_SUBNET_CIDR = "10.6.0.0/24"
DEFAULT_SERVER_ADDRESS = "10.6.0.1/24"
DEFAULT_IPHONE_ADDRESS = "10.6.0.2/32"
DEFAULT_DESKTOP_ADDRESS = "10.6.0.3/32"
DEFAULT_ALLOWED_IPS = "0.0.0.0/0, ::/0"
