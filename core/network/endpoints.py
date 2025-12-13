from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional


@dataclass
class Endpoint:
    """统一描述一个对外出口。

    - 可以是 WireGuard 直连
    - 也可以是 V2Ray WebSocket+TLS
    - 未来可以扩展 QUIC/其他 transport
    """

    real_ip: str
    port: int
    domain: Optional[str] = None
    front_domain: Optional[str] = None
    transport: str = "wireguard"
    ws_path: Optional[str] = None

    def with_fronting(self, front_domain: str | None, real_domain: str | None = None) -> "Endpoint":
        """Return a copy updated with domain fronting fields."""

        new_domain = real_domain if real_domain else self.domain
        return replace(self, front_domain=front_domain, domain=new_domain)


def endpoint_to_dict(ep: Endpoint) -> Dict[str, Any]:
    """Serialize an :class:`Endpoint` to a plain dictionary."""

    return {
        "real_ip": ep.real_ip,
        "port": ep.port,
        "domain": ep.domain,
        "front_domain": ep.front_domain,
        "transport": ep.transport,
        "ws_path": ep.ws_path,
    }


def endpoint_from_dict(data: Dict[str, Any]) -> Endpoint:
    """Deserialize a dictionary into an :class:`Endpoint`."""

    return Endpoint(
        real_ip=str(data.get("real_ip", "")),
        port=int(data.get("port", 0)),
        domain=data.get("domain"),
        front_domain=data.get("front_domain"),
        transport=str(data.get("transport", "wireguard")),
        ws_path=data.get("ws_path"),
    )


def load_endpoints_from_data(data: Dict[str, Any]) -> List[Endpoint]:
    """Load endpoints from a server.json-style payload with legacy fallback."""

    endpoints: list[Endpoint] = []
    for item in data.get("endpoints", []) or []:
        try:
            endpoints.append(endpoint_from_dict(item))
        except Exception:
            continue

    if endpoints:
        return endpoints

    legacy_ip = data.get("ip") or data.get("real_ip") or ""
    legacy_port = None
    endpoint_str = data.get("endpoint")
    if endpoint_str and ":" in endpoint_str:
        try:
            legacy_ip, port_str = endpoint_str.rsplit(":", 1)
            legacy_port = int(port_str)
        except (ValueError, TypeError):
            legacy_ip = data.get("ip") or legacy_ip

    if legacy_port is None:
        try:
            legacy_port = int(data.get("port")) if data.get("port") is not None else None
        except (TypeError, ValueError):
            legacy_port = None

    if legacy_ip and legacy_port:
        endpoints.append(
            Endpoint(
                real_ip=str(legacy_ip),
                port=int(legacy_port),
                transport="wireguard",
            )
        )

    return endpoints
