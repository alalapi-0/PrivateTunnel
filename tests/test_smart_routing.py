"""智能选路测试。Smart routing tests."""

from __future__ import annotations

import pytest

from core.tools.smart_routing import SmartRouter, RoutingStrategy, NodeScore
from core.tools.multi_node_manager import Node, NodeStatus
from tests.conftest import sample_nodes


class TestSmartRouter:
    """智能选路测试类。Smart routing test class."""

    def test_calculate_node_score(self, sample_nodes: list[Node]):
        """测试节点评分计算。Test node score calculation."""
        router = SmartRouter(strategy=RoutingStrategy.BALANCED)

        node = sample_nodes[0]
        score = router.calculate_node_score(node, wireguard_port=None)

        assert isinstance(score, NodeScore)
        assert score.node_id == node.id
        assert 0 <= score.overall_score <= 100

    def test_select_best_node(self, sample_nodes: list[Node]):
        """测试选择最佳节点。Test selecting best node."""
        router = SmartRouter(strategy=RoutingStrategy.LATENCY_FIRST)

        # 只使用活跃节点
        active_nodes = [n for n in sample_nodes if n.status == NodeStatus.ACTIVE]

        best_node, best_score, all_scores = router.select_best_node(
            active_nodes,
            wireguard_port=None,
        )

        assert best_node is not None
        assert best_score is not None
        assert len(all_scores) == len(active_nodes)
        # 延迟优先策略应该选择延迟最低的节点
        assert best_node.latency_ms == min(n.latency_ms for n in active_nodes if n.latency_ms)

    def test_different_strategies(self, sample_nodes: list[Node]):
        """测试不同选路策略。Test different routing strategies."""
        active_nodes = [n for n in sample_nodes if n.status == NodeStatus.ACTIVE]

        strategies = [
            RoutingStrategy.LATENCY_FIRST,
            RoutingStrategy.WEIGHT_FIRST,
            RoutingStrategy.PRIORITY_FIRST,
            RoutingStrategy.BALANCED,
        ]

        for strategy in strategies:
            router = SmartRouter(strategy=strategy)
            best_node, best_score, _ = router.select_best_node(
                active_nodes,
                wireguard_port=None,
            )
            assert best_node is not None
            assert best_score is not None

    def test_node_score_calculation(self):
        """测试节点评分计算逻辑。Test node score calculation logic."""
        score = NodeScore(node_id="test-node")
        score.latency_score = 20.0  # 低延迟，好
        score.weight_score = 80.0  # 高权重，好
        score.priority_score = 10.0  # 低优先级值，好
        score.health_score = 100.0  # 健康，好

        score.calculate_overall(
            latency_weight=0.4,
            weight_weight=0.2,
            priority_weight=0.2,
            health_weight=0.2,
        )

        assert score.overall_score > 0
        assert score.overall_score <= 100







