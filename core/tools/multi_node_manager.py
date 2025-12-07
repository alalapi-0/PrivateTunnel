"""多节点管理器。Multi-node manager for PrivateTunnel."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from dataclasses import dataclass, asdict
from enum import Enum


class NodeStatus(str, Enum):
    """节点状态枚举。Node status enumeration."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    FAILING = "failing"
    MAINTENANCE = "maintenance"


@dataclass
class NodeMetadata:
    """节点元数据。Node metadata."""

    wan_interface: str | None = None
    desktop_config: str | None = None
    iphone_config: str | None = None
    v2ray_enabled: bool = False
    v2ray_port: int | None = None
    v2ray_uuid: str | None = None


@dataclass
class Node:
    """节点信息。Node information."""

    id: str
    instance_id: str
    ip: str
    region: str
    plan: str
    priority: int = 1  # 优先级，数字越小优先级越高
    weight: int = 100  # 权重，用于负载均衡
    status: NodeStatus = NodeStatus.UNKNOWN
    last_check: int = 0  # 最后检查时间戳
    latency_ms: float | None = None  # 延迟（毫秒）
    bandwidth_mbps: float | None = None  # 带宽（Mbps）
    load_average: float | None = None  # 负载平均值（可选）
    connection_count: int = 0  # 当前连接数（可选）
    server_pub: str | None = None
    endpoint: str | None = None
    created_at: int = 0
    metadata: NodeMetadata | None = None

    def to_dict(self) -> dict[str, Any]:
        """转换为字典。Convert to dictionary."""
        data = asdict(self)
        data["status"] = self.status.value
        if self.metadata:
            data["metadata"] = asdict(self.metadata)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Node:
        """从字典创建。Create from dictionary."""
        # 处理 status
        if isinstance(data.get("status"), str):
            data["status"] = NodeStatus(data["status"])
        else:
            data["status"] = NodeStatus.UNKNOWN

        # 处理 metadata
        if "metadata" in data and data["metadata"]:
            data["metadata"] = NodeMetadata(**data["metadata"])
        else:
            data["metadata"] = None

        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})


@dataclass
class MultiNodeConfig:
    """多节点配置。Multi-node configuration."""

    version: str = "1"
    nodes: list[Node] = None
    default_node_id: str | None = None
    updated_at: int = 0

    def __post_init__(self):
        if self.nodes is None:
            self.nodes = []
        if self.updated_at == 0:
            self.updated_at = int(time.time())

    def to_dict(self) -> dict[str, Any]:
        """转换为字典。Convert to dictionary."""
        return {
            "version": self.version,
            "nodes": [node.to_dict() for node in self.nodes],
            "default_node_id": self.default_node_id,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MultiNodeConfig:
        """从字典创建。Create from dictionary."""
        nodes = [Node.from_dict(node_data) for node_data in data.get("nodes", [])]
        return cls(
            version=data.get("version", "1"),
            nodes=nodes,
            default_node_id=data.get("default_node_id"),
            updated_at=data.get("updated_at", 0),
        )

    def get_node(self, node_id: str) -> Node | None:
        """根据 ID 获取节点。Get node by ID."""
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def get_default_node(self) -> Node | None:
        """获取默认节点。Get default node."""
        if self.default_node_id:
            return self.get_node(self.default_node_id)
        # 如果没有默认节点，返回优先级最高的活跃节点
        active_nodes = [n for n in self.nodes if n.status == NodeStatus.ACTIVE]
        if active_nodes:
            return min(active_nodes, key=lambda n: (n.priority, -n.weight))
        return None

    def add_node(self, node: Node) -> None:
        """添加节点。Add node."""
        # 检查是否已存在
        existing = self.get_node(node.id)
        if existing:
            # 更新现有节点
            idx = self.nodes.index(existing)
            self.nodes[idx] = node
        else:
            self.nodes.append(node)

        # 如果没有默认节点，设置第一个节点为默认
        if not self.default_node_id and self.nodes:
            self.default_node_id = self.nodes[0].id

        self.updated_at = int(time.time())

    def remove_node(self, node_id: str) -> bool:
        """删除节点。Remove node."""
        node = self.get_node(node_id)
        if node:
            self.nodes.remove(node)
            # 如果删除的是默认节点，重新选择默认节点
            if self.default_node_id == node_id:
                self.default_node_id = None
                default = self.get_default_node()
                if default:
                    self.default_node_id = default.id
            self.updated_at = int(time.time())
            return True
        return False

    def set_default_node(self, node_id: str) -> bool:
        """设置默认节点。Set default node."""
        if self.get_node(node_id):
            self.default_node_id = node_id
            self.updated_at = int(time.time())
            return True
        return False


class MultiNodeManager:
    """多节点管理器。Multi-node manager."""

    def __init__(self, config_path: Path | None = None):
        """初始化管理器。Initialize manager."""
        if config_path is None:
            # 延迟导入避免循环依赖
            root = Path(__file__).resolve().parent.parent.parent
            config_path = root / "artifacts" / "multi-node.json"
        self.config_path = config_path
        self.config: MultiNodeConfig | None = None
        self._load()

    def _load(self) -> None:
        """加载配置。Load configuration."""
        if self.config_path.exists():
            try:
                data = json.loads(self.config_path.read_text(encoding="utf-8"))
                self.config = MultiNodeConfig.from_dict(data)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                # 配置损坏，创建新配置
                self.config = MultiNodeConfig()
        else:
            self.config = MultiNodeConfig()

    def save(self) -> None:
        """保存配置。Save configuration."""
        if self.config:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(
                json.dumps(self.config.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

    def add_node_from_instance(
        self,
        instance_id: str,
        ip: str,
        region: str,
        plan: str,
        priority: int = 1,
        weight: int = 100,
        node_id: str | None = None,
    ) -> Node:
        """从实例信息创建节点。Create node from instance info."""
        if node_id is None:
            node_id = f"node-{instance_id[:8]}"

        node = Node(
            id=node_id,
            instance_id=instance_id,
            ip=ip,
            region=region,
            plan=plan,
            priority=priority,
            weight=weight,
            status=NodeStatus.UNKNOWN,
            created_at=int(time.time()),
        )

        if self.config:
            self.config.add_node(node)
            self.save()

        return node

    def update_node_info(
        self,
        node_id: str,
        server_pub: str | None = None,
        endpoint: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """更新节点信息。Update node information."""
        if not self.config:
            return False

        node = self.config.get_node(node_id)
        if not node:
            return False

        if server_pub:
            node.server_pub = server_pub
        if endpoint:
            node.endpoint = endpoint
        if metadata:
            if node.metadata is None:
                node.metadata = NodeMetadata()
            for key, value in metadata.items():
                if hasattr(node.metadata, key):
                    setattr(node.metadata, key, value)

        self.config.add_node(node)  # 更新节点
        self.save()
        return True

    def update_node_status(
        self,
        node_id: str,
        status: NodeStatus,
        latency_ms: float | None = None,
    ) -> bool:
        """更新节点状态。Update node status."""
        if not self.config:
            return False

        node = self.config.get_node(node_id)
        if not node:
            return False

        node.status = status
        node.last_check = int(time.time())
        if latency_ms is not None:
            node.latency_ms = latency_ms

        self.config.add_node(node)
        self.save()
        return True

    def get_all_nodes(self) -> list[Node]:
        """获取所有节点。Get all nodes."""
        if self.config:
            return self.config.nodes.copy()
        return []

    def get_active_nodes(self) -> list[Node]:
        """获取所有活跃节点。Get all active nodes."""
        if self.config:
            return [n for n in self.config.nodes if n.status == NodeStatus.ACTIVE]
        return []

    def get_default_node(self) -> Node | None:
        """获取默认节点。Get default node."""
        if self.config:
            return self.config.get_default_node()
        return None

    def check_node_health(
        self,
        node_id: str,
        wireguard_port: int | None = None,
    ) -> Any:
        """检查节点健康状态。Check node health status.

        Args:
            node_id: 节点 ID
            wireguard_port: WireGuard 端口

        Returns:
            健康检查指标，如果节点不存在返回 None
        """
        from core.tools.node_health_checker import NodeHealthChecker, HealthCheckMetrics

        node = self.config.get_node(node_id) if self.config else None
        if not node:
            return None

        checker = NodeHealthChecker()
        metrics = checker.check_node(
            ip=node.ip,
            wireguard_port=wireguard_port,
        )

        # 更新节点状态
        if metrics.overall_healthy:
            new_status = NodeStatus.ACTIVE
        else:
            new_status = NodeStatus.FAILING

        self.update_node_status(
            node_id=node_id,
            status=new_status,
            latency_ms=metrics.latency_ms,
        )

        return metrics

    def check_all_nodes(
        self,
        wireguard_port: int | None = None,
    ) -> dict[str, Any]:
        """检查所有节点健康状态。Check all nodes health.

        Args:
            wireguard_port: WireGuard 端口

        Returns:
            节点 ID 到健康检查指标的映射
        """
        from core.tools.node_health_checker import HealthCheckMetrics

        results = {}
        if not self.config:
            return results

        for node in self.config.nodes:
            metrics = self.check_node_health(node.id, wireguard_port)
            if metrics:
                results[node.id] = metrics

        return results

    def find_best_node(
        self,
        exclude_node_ids: list[str] | None = None,
        min_priority: int | None = None,
        routing_strategy: str | None = None,
        wireguard_port: int | None = None,
    ) -> Node | None:
        """查找最佳可用节点（支持智能选路）。Find best available node with smart routing.

        Args:
            exclude_node_ids: 要排除的节点 ID 列表
            min_priority: 最小优先级
            routing_strategy: 选路策略（latency_first, weight_first, balanced, priority_first, hybrid）
            wireguard_port: WireGuard 端口（用于延迟探测）

        Returns:
            最佳节点，如果没有可用节点返回 None
        """
        if not self.config:
            return None

        exclude_node_ids = exclude_node_ids or []

        # 筛选可用节点
        candidates = [
            node
            for node in self.config.nodes
            if node.status == NodeStatus.ACTIVE
            and node.id not in exclude_node_ids
            and (min_priority is None or node.priority <= min_priority)
        ]

        if not candidates:
            return None

        # 如果指定了智能选路策略，使用智能选路
        if routing_strategy:
            try:
                from core.tools.smart_routing import SmartRouter, RoutingStrategy

                strategy = RoutingStrategy(routing_strategy)
                router = SmartRouter(strategy=strategy)
                best_node, best_score, all_scores = router.select_best_node(
                    candidates,
                    wireguard_port=wireguard_port,
                )

                if best_node and best_score:
                    # 更新节点的延迟信息
                    if best_score.latency_score < 100:
                        # 从延迟评分反推延迟
                        estimated_latency = (100 - best_score.latency_score) * 5
                        best_node.latency_ms = estimated_latency
                        self.config.add_node(best_node)
                        self.save()

                return best_node
            except (ImportError, ValueError) as exc:
                # 智能选路失败，回退到简单策略
                pass

        # 简单策略：按优先级、权重、延迟排序
        candidates.sort(
            key=lambda n: (n.priority, -n.weight, n.latency_ms or float("inf"))
        )

        return candidates[0]

    def switch_to_backup_node(
        self,
        current_node_id: str,
        wireguard_port: int | None = None,
    ) -> Node | None:
        """切换到备用节点。Switch to backup node.

        Args:
            current_node_id: 当前节点 ID
            wireguard_port: WireGuard 端口（用于健康检查）

        Returns:
            新的节点，如果没有可用节点返回 None
        """
        # 检查当前节点健康状态
        current_metrics = self.check_node_health(current_node_id, wireguard_port)

        # 如果当前节点健康，不切换
        if current_metrics and current_metrics.overall_healthy:
            return self.config.get_node(current_node_id) if self.config else None

        # 查找备用节点
        backup = self.find_best_node(exclude_node_ids=[current_node_id])

        if backup:
            # 更新默认节点
            self.config.set_default_node(backup.id)
            self.save()
            return backup

        return None

    def switch_to_backup_node_with_retry(
        self,
        current_node_id: str,
        wireguard_port: int | None = None,
        max_retries: int = 3,
    ) -> Node | None:
        """切换到备用节点（带重试）。Switch to backup node with retry.

        Args:
            current_node_id: 当前节点 ID
            wireguard_port: WireGuard 端口
            max_retries: 最大重试次数

        Returns:
            新的节点，如果所有重试都失败返回 None
        """
        from core.tools.node_health_checker import ExponentialBackoff

        backoff = ExponentialBackoff(base_delay=2.0, max_delay=10.0)

        for attempt in range(max_retries):
            backup = self.switch_to_backup_node(current_node_id, wireguard_port)

            if backup:
                # 验证备用节点健康
                metrics = self.check_node_health(backup.id, wireguard_port)
                if metrics and metrics.overall_healthy:
                    return backup
                else:
                    # 备用节点也不健康，继续重试
                    if attempt < max_retries - 1:
                        delay = backoff.next_delay()
                        time.sleep(delay)
            else:
                # 没有备用节点，等待后重试
                if attempt < max_retries - 1:
                    delay = backoff.next_delay()
                    time.sleep(delay)

        return None

