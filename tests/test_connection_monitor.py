"""连接监控测试。Connection monitor tests."""

from __future__ import annotations

import time
import pytest

from core.tools.connection_monitor import ConnectionMonitor
from core.tools.connection_stats import ConnectionMetrics
from tests.conftest import temp_dir


class TestConnectionMonitor:
    """连接监控测试类。Connection monitor test class."""

    def test_monitor_initialization(self, temp_dir: Path):
        """测试监控器初始化。Test monitor initialization."""
        monitor = ConnectionMonitor(
            node_id="test-node",
            node_ip="127.0.0.1",
            wireguard_port=None,
            data_dir=temp_dir,
        )

        assert monitor.node_id == "test-node"
        assert monitor.node_ip == "127.0.0.1"
        assert not monitor.is_monitoring

    def test_start_stop_monitoring(self, temp_dir: Path):
        """测试启动和停止监控。Test starting and stopping monitoring."""
        monitor = ConnectionMonitor(
            node_id="test-node",
            node_ip="127.0.0.1",
            wireguard_port=None,
            data_dir=temp_dir,
            check_interval=1,
        )

        monitor.start_monitoring()
        assert monitor.is_monitoring
        assert monitor.current_session is not None

        # 等待一小段时间
        time.sleep(0.5)

        monitor.stop_monitoring()
        assert not monitor.is_monitoring

    def test_generate_report(self, temp_dir: Path):
        """测试生成报告。Test generating report."""
        monitor = ConnectionMonitor(
            node_id="test-node",
            node_ip="127.0.0.1",
            wireguard_port=None,
            data_dir=temp_dir,
        )

        # 创建测试会话
        monitor.start_monitoring()
        time.sleep(0.5)
        monitor.stop_monitoring()

        if monitor.current_session:
            report = monitor.generate_report()
            assert "session_id" in report
            assert "summary" in report
            assert "quality_score" in report

    def test_get_current_stats(self, temp_dir: Path):
        """测试获取当前统计。Test getting current stats."""
        monitor = ConnectionMonitor(
            node_id="test-node",
            node_ip="127.0.0.1",
            wireguard_port=None,
            data_dir=temp_dir,
        )

        # 未启动监控时应该返回 None
        stats = monitor.get_current_stats()
        assert stats is None

        # 启动监控后应该有统计
        monitor.start_monitoring()
        time.sleep(0.3)
        stats = monitor.get_current_stats()
        assert stats is not None
        assert "session_id" in stats
        monitor.stop_monitoring()


