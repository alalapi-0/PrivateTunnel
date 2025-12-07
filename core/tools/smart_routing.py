"""智能选路算法。Smart routing algorithm for multi-node scenarios."""

from __future__ import annotations

import statistics
import time
from typing import Any
from dataclasses import dataclass
from enum import Enum

from core.tools.multi_node_manager import Node, NodeStatus
from core.tools.node_health_checker import NodeHealthChecker


class RoutingStrategy(str, Enum):
    """选路策略。Routing strategy."""

    LATENCY_FIRST = "latency_first"  # 延迟优先
    WEIGHT_FIRST = "weight_first"  # 权重优先
    BALANCED = "balanced"  # 平衡模式（综合考虑）
    PRIORITY_FIRST = "priority_first"  # 优先级优先
    HYBRID = "hybrid"  # 混合模式（延迟+权重+优先级）


@dataclass
class NodeScore:
    """节点评分。Node score."""

    node_id: str
    latency_score: float = 0.0  # 延迟评分（0-100，越小越好）
    weight_score: float = 0.0  # 权重评分（0-100，越大越好）
    priority_score: float = 0.0  # 优先级评分（0-100，越小越好）
    health_score: float = 0.0  # 健康评分（0-100，越大越好）
    bandwidth_score: float = 0.0  # 带宽评分（0-100，可选）
    overall_score: float = 0.0  # 综合评分（0-100，越大越好）

    def calculate_overall(
        self,
        latency_weight: float = 0.4,
        weight_weight: float = 0.2,
        priority_weight: float = 0.2,
        health_weight: float = 0.2,
        bandwidth_weight: float = 0.0,
    ) -> None:
        """计算综合评分。Calculate overall score.

        Args:
            latency_weight: 延迟权重
            weight_weight: 权重权重
            priority_weight: 优先级权重
            health_weight: 健康权重
            bandwidth_weight: 带宽权重（如果为 0 则不使用）
        """
        total_weight = latency_weight + weight_weight + priority_weight + health_weight
        if bandwidth_weight > 0:
            total_weight += bandwidth_weight

        # 归一化权重
        if total_weight > 0:
            latency_weight /= total_weight
            weight_weight /= total_weight
            priority_weight /= total_weight
            health_weight /= total_weight
            if bandwidth_weight > 0:
                bandwidth_weight /= total_weight

        # 计算综合评分
        # 注意：延迟评分越小越好，需要反转
        self.overall_score = (
            (100 - self.latency_score) * latency_weight
            + self.weight_score * weight_weight
            + (100 - self.priority_score) * priority_weight
            + self.health_score * health_weight
            + (self.bandwidth_score * bandwidth_weight if bandwidth_weight > 0 else 0)
        )


class SmartRouter:
    """智能选路器。Smart router."""

    def __init__(
        self,
        strategy: RoutingStrategy = RoutingStrategy.BALANCED,
        latency_test_rounds: int = 3,
        enable_bandwidth_test: bool = False,
    ):
        """初始化智能选路器。Initialize smart router.

        Args:
            strategy: 选路策略
            latency_test_rounds: 延迟测试轮数（取平均值）
            enable_bandwidth_test: 是否启用带宽测试（较慢）
        """
        self.strategy = strategy
        self.latency_test_rounds = latency_test_rounds
        self.enable_bandwidth_test = enable_bandwidth_test
        self.health_checker = NodeHealthChecker()

    def probe_latency(
        self,
        ip: str,
        wireguard_port: int | None = None,
        rounds: int | None = None,
    ) -> tuple[float | None, list[float]]:
        """探测节点延迟（多轮测试）。Probe node latency with multiple rounds.

        Args:
            ip: 节点 IP
            wireguard_port: WireGuard 端口
            rounds: 测试轮数（默认使用 self.latency_test_rounds）

        Returns:
            (平均延迟, 所有延迟值列表)
        """
        if rounds is None:
            rounds = self.latency_test_rounds

        latencies = []

        for _ in range(rounds):
            metrics = self.health_checker.check_node(ip, wireguard_port)
            if metrics.latency_ms:
                latencies.append(metrics.latency_ms)
            time.sleep(0.5)  # 避免过于频繁

        if not latencies:
            return None, []

        avg_latency = statistics.mean(latencies)
        return avg_latency, latencies

    def test_bandwidth(
        self,
        ip: str,
        test_size_mb: float = 1.0,
        timeout: int = 30,
    ) -> float | None:
        """测试节点带宽（可选功能）。Test node bandwidth (optional).

        注意：这是一个简化的带宽测试，通过下载小文件测量速度。
        实际带宽测试需要服务器端支持，这里只做客户端到服务器的测试。

        Args:
            ip: 节点 IP
            test_size_mb: 测试数据大小（MB）
            timeout: 超时时间（秒）

        Returns:
            带宽（Mbps），如果测试失败返回 None
        """
        # 简化实现：通过 SSH 连接测试
        # 实际可以使用 iperf3 等工具
        # 这里暂时返回 None，表示不支持
        return None

    def calculate_node_score(
        self,
        node: Node,
        wireguard_port: int | None = None,
        latency_ms: float | None = None,
    ) -> NodeScore:
        """计算节点评分。Calculate node score.

        Args:
            node: 节点对象
            wireguard_port: WireGuard 端口
            latency_ms: 延迟（如果提供则使用，否则重新探测）

        Returns:
            节点评分
        """
        score = NodeScore(node_id=node.id)

        # 1. 延迟评分
        if latency_ms is None:
            # 重新探测延迟
            avg_latency, _ = self.probe_latency(node.ip, wireguard_port, rounds=2)
            latency_ms = avg_latency or node.latency_ms

        if latency_ms is not None:
            # 延迟评分：0-100，延迟越小分数越高
            # 假设 0ms = 100分，500ms = 0分
            score.latency_score = max(0, min(100, 100 - (latency_ms / 5)))
        else:
            score.latency_score = 50  # 未知延迟，给中等分数

        # 2. 权重评分
        # 权重范围通常是 0-100，直接映射到 0-100 分
        score.weight_score = min(100, max(0, node.weight))

        # 3. 优先级评分
        # 优先级越小越好，转换为分数：priority 1 = 100分，priority 10 = 10分
        if node.priority <= 1:
            score.priority_score = 100
        elif node.priority <= 10:
            score.priority_score = 110 - (node.priority * 10)
        else:
            score.priority_score = max(0, 100 - node.priority)

        # 4. 健康评分
        if node.status == NodeStatus.ACTIVE:
            score.health_score = 100
        elif node.status == NodeStatus.UNKNOWN:
            score.health_score = 50
        elif node.status == NodeStatus.FAILING:
            score.health_score = 0
        else:
            score.health_score = 20

        # 5. 带宽评分（如果启用）
        if self.enable_bandwidth_test:
            bandwidth = self.test_bandwidth(node.ip)
            if bandwidth:
                # 假设 100Mbps = 100分，10Mbps = 10分
                score.bandwidth_score = min(100, max(0, bandwidth))
            else:
                score.bandwidth_score = 50  # 未知带宽，给中等分数

        # 6. 根据策略计算综合评分
        if self.strategy == RoutingStrategy.LATENCY_FIRST:
            score.calculate_overall(
                latency_weight=0.7,
                weight_weight=0.1,
                priority_weight=0.1,
                health_weight=0.1,
            )
        elif self.strategy == RoutingStrategy.WEIGHT_FIRST:
            score.calculate_overall(
                latency_weight=0.2,
                weight_weight=0.6,
                priority_weight=0.1,
                health_weight=0.1,
            )
        elif self.strategy == RoutingStrategy.PRIORITY_FIRST:
            score.calculate_overall(
                latency_weight=0.2,
                weight_weight=0.2,
                priority_weight=0.5,
                health_weight=0.1,
            )
        elif self.strategy == RoutingStrategy.BALANCED:
            score.calculate_overall(
                latency_weight=0.3,
                weight_weight=0.25,
                priority_weight=0.25,
                health_weight=0.2,
            )
        elif self.strategy == RoutingStrategy.HYBRID:
            # 混合模式：综合考虑所有因素
            score.calculate_overall(
                latency_weight=0.35,
                weight_weight=0.25,
                priority_weight=0.2,
                health_weight=0.2,
            )
        else:
            # 默认平衡模式
            score.calculate_overall()

        return score

    def select_best_node(
        self,
        nodes: list[Node],
        wireguard_port: int | None = None,
        exclude_node_ids: list[str] | None = None,
    ) -> tuple[Node | None, NodeScore | None, dict[str, NodeScore]]:
        """选择最佳节点。Select best node.

        Args:
            nodes: 节点列表
            wireguard_port: WireGuard 端口
            exclude_node_ids: 要排除的节点 ID 列表

        Returns:
            (最佳节点, 最佳节点评分, 所有节点评分字典)
        """
        exclude_node_ids = exclude_node_ids or []

        # 筛选可用节点
        candidates = [
            node
            for node in nodes
            if node.status == NodeStatus.ACTIVE and node.id not in exclude_node_ids
        ]

        if not candidates:
            return None, None, {}

        # 计算所有候选节点的评分
        scores: dict[str, NodeScore] = {}
        for node in candidates:
            score = self.calculate_node_score(node, wireguard_port)
            scores[node.id] = score

        # 按综合评分排序
        sorted_candidates = sorted(
            candidates,
            key=lambda n: scores[n.id].overall_score,
            reverse=True,  # 分数越高越好
        )

        best_node = sorted_candidates[0] if sorted_candidates else None
        best_score = scores[best_node.id] if best_node else None

        return best_node, best_score, scores

    def select_best_node_for_chatgpt(
        self,
        nodes: list[Node],
        wireguard_port: int | None = None,
        exclude_node_ids: list[str] | None = None,
    ) -> tuple[Node | None, NodeScore | None, dict[str, NodeScore]]:
        """为 ChatGPT 选择最佳节点。Select best node for ChatGPT.
        
        ChatGPT 对延迟和稳定性要求高，优先选择：
        - 延迟低（< 150ms）
        - 丢包率低（< 1%）
        - 连接稳定（重连次数少）
        
        Args:
            nodes: 节点列表
            wireguard_port: WireGuard 端口
            exclude_node_ids: 要排除的节点 ID 列表
        
        Returns:
            (最佳节点, 最佳节点评分, 所有节点评分字典)
        """
        from core.tools.chatgpt_optimizer import ChatGPTOptimizer
        
        exclude_node_ids = exclude_node_ids or []
        
        # 筛选可用节点
        candidates = [
            node for node in nodes
            if node.status == NodeStatus.ACTIVE
            and node.id not in exclude_node_ids
        ]
        
        if not candidates:
            return None, None, {}
        
        # 测试每个节点的 ChatGPT 连接
        scores: dict[str, NodeScore] = {}
        optimizer = ChatGPTOptimizer(node_ip="", wireguard_port=wireguard_port)
        
        for node in candidates:
            # 测试 ChatGPT 连接
            optimizer.node_ip = node.ip
            connectivity = optimizer.test_chatgpt_connectivity()
            
            # 计算评分（ChatGPT 专用）
            score = NodeScore(node_id=node.id)
            
            # 延迟评分（ChatGPT 要求低延迟）
            if connectivity["success"] and connectivity["latency_ms"]:
                latency = connectivity["latency_ms"]
                if latency < 100:
                    score.latency_score = 20  # 延迟低，扣分少
                elif latency < 150:
                    score.latency_score = 40
                elif latency < 200:
                    score.latency_score = 60
                else:
                    score.latency_score = 80
            else:
                score.latency_score = 100  # 连接失败，扣分多
            
            # 连接成功评分
            if connectivity["success"]:
                score.health_score = 100
            else:
                score.health_score = 0
            
            # 使用 ChatGPT 专用权重计算综合评分
            score.calculate_overall(
                latency_weight=0.6,  # ChatGPT 对延迟敏感
                weight_weight=0.1,
                priority_weight=0.1,
                health_weight=0.2,
            )
            
            scores[node.id] = score
        
        # 按综合评分排序
        sorted_candidates = sorted(
            candidates,
            key=lambda n: scores[n.id].overall_score,
            reverse=True,
        )
        
        best_node = sorted_candidates[0] if sorted_candidates else None
        best_score = scores[best_node.id] if best_node else None
        
        return best_node, best_score, scores

