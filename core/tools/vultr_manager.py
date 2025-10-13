from __future__ import annotations

import json
import time
from typing import Any, Dict

import requests

API = "https://api.vultr.com/v2"
UBUNTU_22_04_OSID = 1743  # 如有差异，请在 Vultr 控制台或官方文档中查询实际 OSID


class VultrError(RuntimeError):
    """Custom exception for Vultr API operations."""


def _hdr(api_key: str) -> Dict[str, str]:
    """Build request headers for Vultr API calls."""
    if not api_key:
        raise VultrError("VULTR_API_KEY is empty")
    return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}


def create_instance(
    api_key: str,
    region: str = "nrt",
    plan: str = "vc2-1c-1gb",
    snapshot_id: str | None = None,
    label: str = "privatetunnel-oc",
) -> Dict[str, Any]:
    """Create a Vultr instance and return the raw instance payload."""

    body: Dict[str, Any] = {
        "region": region,
        "plan": plan,
        "label": label,
        "backups": "disabled",
        "enable_ipv6": True,
    }
    if snapshot_id:
        body["snapshot_id"] = snapshot_id
    else:
        body["os_id"] = UBUNTU_22_04_OSID

    try:
        response = requests.post(
            f"{API}/instances",
            headers=_hdr(api_key),
            json=body,
            timeout=30,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        message = getattr(exc.response, "text", str(exc))
        raise VultrError(f"Create instance failed: {message}") from exc

    data = response.json()
    instance = data.get("instance") or {}
    instance_id = instance.get("id")
    if not instance_id:
        raise VultrError(f"Unexpected create response: {json.dumps(data, ensure_ascii=False)}")
    return instance


def wait_instance_active(
    api_key: str,
    instance_id: str,
    timeout: int = 600,
    interval: int = 10,
) -> Dict[str, str]:
    """Poll instance status until it becomes active and returns its IP."""

    start = time.time()
    last_state: Dict[str, Any] = {}
    while time.time() - start < timeout:
        try:
            response = requests.get(
                f"{API}/instances/{instance_id}",
                headers=_hdr(api_key),
                timeout=15,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            last_state = {"error": getattr(exc.response, "text", str(exc))}
            time.sleep(interval)
            continue

        payload = response.json().get("instance", {})
        status = payload.get("status")
        ip = payload.get("main_ip")
        if status == "active" and ip:
            return {"id": instance_id, "ip": ip, "status": status}
        last_state = {"status": status, "ip": ip}
        time.sleep(interval)

    raise VultrError(f"Wait active timeout. Last state={json.dumps(last_state, ensure_ascii=False)}")


def destroy_instance(api_key: str, instance_id: str) -> None:
    """Destroy a Vultr instance."""

    try:
        response = requests.delete(
            f"{API}/instances/{instance_id}",
            headers=_hdr(api_key),
            timeout=30,
        )
        if response.status_code not in (200, 204):
            response.raise_for_status()
    except requests.RequestException as exc:
        message = getattr(exc.response, "text", str(exc))
        raise VultrError(f"Destroy failed: {message}") from exc
