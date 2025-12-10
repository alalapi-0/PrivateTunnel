"""测试工具。Test utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_test_data(filename: str) -> dict[str, Any]:
    """加载测试数据。Load test data.

    Args:
        filename: 测试数据文件名

    Returns:
        测试数据字典
    """
    test_data_dir = Path(__file__).parent / "test_data"
    test_data_file = test_data_dir / filename

    if test_data_file.exists():
        return json.loads(test_data_file.read_text(encoding="utf-8"))
    return {}


def create_mock_node(
    node_id: str = "mock-node",
    ip: str = "192.168.1.100",
    status: str = "active",
) -> dict[str, Any]:
    """创建模拟节点。Create mock node.

    Args:
        node_id: 节点 ID
        ip: 节点 IP
        status: 节点状态

    Returns:
        节点字典
    """
    return {
        "id": node_id,
        "instance_id": f"inst-{node_id}",
        "ip": ip,
        "region": "test-region",
        "plan": "test-plan",
        "priority": 1,
        "weight": 100,
        "status": status,
        "latency_ms": 50.0,
    }







