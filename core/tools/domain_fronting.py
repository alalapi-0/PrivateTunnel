from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from core.network.endpoints import Endpoint

logger = logging.getLogger(__name__)


@dataclass
class DomainFrontingConfig:
    """
    描述一次域前置配置:
    - front_domain: 客户端看到/使用的域名
    - real_domain: 真实后端 (可选)
    - enabled: 是否启用
    """

    enabled: bool
    front_domain: Optional[str] = None
    real_domain: Optional[str] = None
    notes: Optional[str] = None


class DomainFrontingManager:
    def __init__(self, ssh_client):
        self.ssh = ssh_client

    def apply_to_endpoint(self, endpoint: Endpoint, config: DomainFrontingConfig) -> Endpoint:
        """根据域前置配置, 返回一个对客户端可见的 Endpoint 副本。"""

        if not config.enabled:
            logger.debug("domain fronting disabled, returning original endpoint")
            return endpoint

        if not config.front_domain:
            logger.debug("front_domain missing while fronting enabled; returning original endpoint")
            return endpoint

        logger.info(
            "apply domain fronting: real_domain=%s front_domain=%s", config.real_domain, config.front_domain
        )
        return endpoint.with_fronting(config.front_domain, config.real_domain)
