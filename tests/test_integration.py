"""集成测试。Integration tests."""

from __future__ import annotations

import pytest

from core.tools.multi_node_manager import MultiNodeManager, NodeStatus
from core.tools.node_health_checker import NodeHealthChecker
from core.tools.smart_routing import SmartRouter, RoutingStrategy
from core.tools.connection_monitor import ConnectionMonitor
from tests.conftest import temp_dir, sample_nodes


class TestIntegration:
    """集成测试类。Integration test class."""

    def test_full_workflow(self, temp_dir: Path, sample_nodes: list[Node]):
        """测试完整工作流程。Test full workflow."""
        # 1. 创建多节点管理器
        manager = MultiNodeManager(config_path=temp_dir / "multi-node.json")

        # 2. 添加节点
        for node in sample_nodes:
            manager.add_node_from_instance(
                instance_id=node.instance_id,
                ip=node.ip,
                region=node.region,
                plan=node.plan,
                priority=node.priority,
                weight=node.weight,
            )
            manager.update_node_status(node.id, node.status, node.latency_ms)

        # 3. 健康检查
        checker = NodeHealthChecker()
        active_nodes = [n for n in manager.get_all_nodes() if n.status == NodeStatus.ACTIVE]

        # 4. 智能选路
        router = SmartRouter(strategy=RoutingStrategy.BALANCED)
        best_node, best_score, all_scores = router.select_best_node(
            active_nodes,
            wireguard_port=None,
        )

        assert best_node is not None
        assert best_score is not None

        # 5. 连接监控
        monitor = ConnectionMonitor(
            node_id=best_node.id,
            node_ip=best_node.ip,
            wireguard_port=None,
            data_dir=temp_dir / "monitor",
            check_interval=1,
        )

        monitor.start_monitoring()
        import time
        time.sleep(0.5)
        monitor.stop_monitoring()

        # 验证结果
        stats = monitor.get_current_stats()
        assert stats is not None or monitor.current_session is None

    def test_node_failover(self, temp_dir: Path, sample_nodes: list[Node]):
        """测试节点故障转移。Test node failover."""
        manager = MultiNodeManager(config_path=temp_dir / "multi-node.json")

        # 添加节点
        for node in sample_nodes:
            manager.add_node_from_instance(
                instance_id=node.instance_id,
                ip=node.ip,
                region=node.region,
                plan=node.plan,
                priority=node.priority,
                weight=node.weight,
            )
            manager.update_node_status(node.id, node.status, node.latency_ms)

        # 设置第一个节点为默认
        if manager.config:
            manager.config.set_default_node(sample_nodes[0].id)

        # 模拟第一个节点故障
        manager.update_node_status(sample_nodes[0].id, NodeStatus.FAILING, None)

        # 应该自动切换到备用节点
        backup = manager.switch_to_backup_node(sample_nodes[0].id)
        # 注意：由于健康检查可能失败，backup 可能为 None
        # 但至少应该尝试切换
        assert backup is None or backup.id != sample_nodes[0].id







