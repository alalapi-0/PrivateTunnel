"""pytest 配置和共享 fixtures。pytest configuration and shared fixtures."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Generator

import pytest

from core.tools.multi_node_manager import MultiNodeManager, Node, NodeStatus
from core.tools.node_health_checker import NodeHealthChecker
from core.tools.connection_stats import ConnectionMetrics, ConnectionSession


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """临时目录 fixture。Temporary directory fixture."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_node() -> Node:
    """示例节点 fixture。Sample node fixture."""
    return Node(
        id="test-node-1",
        instance_id="test-instance-123",
        ip="192.168.1.100",
        region="test-region",
        plan="test-plan",
        priority=1,
        weight=100,
        status=NodeStatus.ACTIVE,
        latency_ms=50.0,
    )


@pytest.fixture
def sample_nodes() -> list[Node]:
    """示例节点列表 fixture。Sample nodes fixture."""
    return [
        Node(
            id="node-1",
            instance_id="inst-1",
            ip="192.168.1.1",
            region="region-1",
            plan="plan-1",
            priority=1,
            weight=100,
            status=NodeStatus.ACTIVE,
            latency_ms=30.0,
        ),
        Node(
            id="node-2",
            instance_id="inst-2",
            ip="192.168.1.2",
            region="region-2",
            plan="plan-2",
            priority=2,
            weight=80,
            status=NodeStatus.ACTIVE,
            latency_ms=60.0,
        ),
        Node(
            id="node-3",
            instance_id="inst-3",
            ip="192.168.1.3",
            region="region-3",
            plan="plan-3",
            priority=1,
            weight=90,
            status=NodeStatus.FAILING,
            latency_ms=200.0,
        ),
    ]


@pytest.fixture
def multi_node_manager(temp_dir: Path) -> MultiNodeManager:
    """多节点管理器 fixture。Multi-node manager fixture."""
    config_path = temp_dir / "multi-node.json"
    return MultiNodeManager(config_path=config_path)


@pytest.fixture
def node_health_checker() -> NodeHealthChecker:
    """节点健康检查器 fixture。Node health checker fixture."""
    return NodeHealthChecker(timeout=2, icmp_count=1)


@pytest.fixture
def sample_metrics() -> ConnectionMetrics:
    """示例连接指标 fixture。Sample connection metrics fixture."""
    return ConnectionMetrics(
        latency_ms=50.0,
        packet_loss_rate=0.01,
        bandwidth_mbps=100.0,
        jitter_ms=5.0,
        connection_uptime=3600,
        reconnect_count=0,
        tx_bytes=1024000,
        rx_bytes=2048000,
        tx_packets=1000,
        rx_packets=2000,
    )


@pytest.fixture
def sample_session(sample_metrics: ConnectionMetrics) -> ConnectionSession:
    """示例连接会话 fixture。Sample connection session fixture."""
    session = ConnectionSession(
        session_id="test-session-1",
        node_id="test-node-1",
    )
    session.add_metrics(sample_metrics)
    return session


