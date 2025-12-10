"""连接统计数据结构。Connection statistics data structures."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from collections import deque


@dataclass
class ConnectionMetrics:
    """连接指标。Connection metrics."""

    timestamp: int = 0  # 时间戳
    latency_ms: float | None = None  # 延迟（毫秒）
    packet_loss_rate: float = 0.0  # 丢包率（0-1）
    bandwidth_mbps: float | None = None  # 带宽（Mbps）
    jitter_ms: float | None = None  # 抖动（毫秒）
    connection_uptime: int = 0  # 连接持续时间（秒）
    reconnect_count: int = 0  # 重连次数
    tx_bytes: int = 0  # 发送字节数
    rx_bytes: int = 0  # 接收字节数
    tx_packets: int = 0  # 发送包数
    rx_packets: int = 0  # 接收包数
    connection_healthy: bool | None = None  # 健康状态

    def __post_init__(self):
        if self.timestamp == 0:
            self.timestamp = int(time.time())

    def to_dict(self) -> dict[str, Any]:
        """转换为字典。Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "latency_ms": self.latency_ms,
            "packet_loss_rate": self.packet_loss_rate,
            "bandwidth_mbps": self.bandwidth_mbps,
            "jitter_ms": self.jitter_ms,
            "connection_uptime": self.connection_uptime,
            "reconnect_count": self.reconnect_count,
            "tx_bytes": self.tx_bytes,
            "rx_bytes": self.rx_bytes,
            "tx_packets": self.tx_packets,
            "rx_packets": self.rx_packets,
            "connection_healthy": self.connection_healthy,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConnectionMetrics:
        """从字典创建。Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})


@dataclass
class ConnectionSession:
    """连接会话。Connection session."""

    session_id: str
    node_id: str
    start_time: int = 0
    end_time: int | None = None
    metrics_history: list[ConnectionMetrics] = field(default_factory=list)
    total_reconnects: int = 0
    total_tx_bytes: int = 0
    total_rx_bytes: int = 0
    total_tx_packets: int = 0
    total_rx_packets: int = 0
    avg_latency_ms: float | None = None
    max_latency_ms: float | None = None
    min_latency_ms: float | None = None
    avg_packet_loss: float = 0.0
    max_packet_loss: float = 0.0

    def __post_init__(self):
        if self.start_time == 0:
            self.start_time = int(time.time())

    def add_metrics(self, metrics: ConnectionMetrics) -> None:
        """添加指标。Add metrics."""
        self.metrics_history.append(metrics)

        # 更新统计
        if metrics.latency_ms is not None:
            latencies = [m.latency_ms for m in self.metrics_history if m.latency_ms is not None]
            if latencies:
                self.avg_latency_ms = sum(latencies) / len(latencies)
                self.max_latency_ms = max(latencies)
                self.min_latency_ms = min(latencies)

        if metrics.packet_loss_rate is not None:
            losses = [m.packet_loss_rate for m in self.metrics_history if m.packet_loss_rate is not None]
            if losses:
                self.avg_packet_loss = sum(losses) / len(losses)
                self.max_packet_loss = max(losses)

        self.total_reconnects += metrics.reconnect_count
        self.total_tx_bytes += metrics.tx_bytes
        self.total_rx_bytes += metrics.rx_bytes
        self.total_tx_packets += metrics.tx_packets
        self.total_rx_packets += metrics.rx_packets

    def get_duration(self) -> int:
        """获取会话持续时间。Get session duration."""
        end = self.end_time or int(time.time())
        return end - self.start_time

    def to_dict(self) -> dict[str, Any]:
        """转换为字典。Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "node_id": self.node_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.get_duration(),
            "metrics_count": len(self.metrics_history),
            "total_reconnects": self.total_reconnects,
            "total_tx_bytes": self.total_tx_bytes,
            "total_rx_bytes": self.total_rx_bytes,
            "total_tx_packets": self.total_tx_packets,
            "total_rx_packets": self.total_rx_packets,
            "avg_latency_ms": self.avg_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "min_latency_ms": self.min_latency_ms,
            "avg_packet_loss": self.avg_packet_loss,
            "max_packet_loss": self.max_packet_loss,
            "metrics_history": [m.to_dict() for m in self.metrics_history],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConnectionSession:
        """从字典创建。Create from dictionary."""
        session = cls(
            session_id=data["session_id"],
            node_id=data["node_id"],
            start_time=data.get("start_time", 0),
            end_time=data.get("end_time"),
            total_reconnects=data.get("total_reconnects", 0),
            total_tx_bytes=data.get("total_tx_bytes", 0),
            total_rx_bytes=data.get("total_rx_bytes", 0),
            total_tx_packets=data.get("total_tx_packets", 0),
            total_rx_packets=data.get("total_rx_packets", 0),
            avg_latency_ms=data.get("avg_latency_ms"),
            max_latency_ms=data.get("max_latency_ms"),
            min_latency_ms=data.get("min_latency_ms"),
            avg_packet_loss=data.get("avg_packet_loss", 0.0),
            max_packet_loss=data.get("max_packet_loss", 0.0),
        )

        # 恢复指标历史
        for m_data in data.get("metrics_history", []):
            session.metrics_history.append(ConnectionMetrics.from_dict(m_data))

        return session







