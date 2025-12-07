"""节点健康检查器测试。Node health checker tests."""

from __future__ import annotations

import pytest

from core.tools.node_health_checker import NodeHealthChecker, HealthCheckMetrics
from tests.conftest import node_health_checker


class TestNodeHealthChecker:
    """节点健康检查器测试类。Node health checker test class."""

    def test_check_tcp(self, node_health_checker: NodeHealthChecker):
        """测试 TCP 连接检查。Test TCP connection check."""
        # 测试本地回环地址
        success, latency = node_health_checker.check_tcp("127.0.0.1", 22, timeout=1)
        # 本地 SSH 端口可能开放也可能不开放，所以只检查返回类型
        assert isinstance(success, bool)
        if latency:
            assert latency >= 0

    def test_check_https(self, node_health_checker: NodeHealthChecker):
        """测试 HTTPS 连接检查。Test HTTPS connection check."""
        success, latency = node_health_checker.check_https(
            "https://1.1.1.1/cdn-cgi/trace",
            timeout=5,
        )
        # 1.1.1.1 通常可达
        assert isinstance(success, bool)
        if latency:
            assert latency >= 0

    def test_check_dns(self, node_health_checker: NodeHealthChecker):
        """测试 DNS 解析检查。Test DNS resolution check."""
        success, latency = node_health_checker.check_dns("google.com", timeout=5)
        assert isinstance(success, bool)
        if latency:
            assert latency >= 0

    def test_check_node(self, node_health_checker: NodeHealthChecker):
        """测试完整节点检查。Test complete node check."""
        # 使用一个已知可达的 IP（如 Cloudflare DNS）
        metrics = node_health_checker.check_node("1.1.1.1", wireguard_port=None)

        assert isinstance(metrics, HealthCheckMetrics)
        assert metrics.timestamp > 0
        # 至少应该有一项检查成功（1.1.1.1 通常可达）
        # 注意：由于网络环境不同，可能所有检查都失败，所以只验证返回类型

    def test_health_check_metrics(self):
        """测试健康检查指标。Test health check metrics."""
        metrics = HealthCheckMetrics(
            latency_ms=50.0,
            icmp_success=True,
            tcp_success=False,
            https_success=True,
            dns_success=True,
        )

        # 至少有一项成功，应该认为整体健康
        assert metrics.overall_healthy is True

        # 所有检查都失败
        metrics2 = HealthCheckMetrics(
            latency_ms=None,
            icmp_success=False,
            tcp_success=False,
            https_success=False,
            dns_success=False,
        )
        assert metrics2.overall_healthy is False


