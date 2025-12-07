"""ChatGPT 优化器测试。ChatGPT optimizer tests."""

from __future__ import annotations

import pytest

from core.tools.chatgpt_optimizer import ChatGPTOptimizer
from tests.conftest import temp_dir


class TestChatGPTOptimizer:
    """ChatGPT 优化器测试类。ChatGPT optimizer test class."""

    def test_initialization(self, temp_dir: Path):
        """测试初始化。Test initialization."""
        optimizer = ChatGPTOptimizer(
            node_ip="192.168.1.100",
            wireguard_port=None,
            data_dir=temp_dir,
        )

        assert optimizer.node_ip == "192.168.1.100"
        assert optimizer.data_dir == temp_dir

    def test_resolve_chatgpt_domains(self, temp_dir: Path):
        """测试解析 ChatGPT 域名。Test resolving ChatGPT domains."""
        optimizer = ChatGPTOptimizer(
            node_ip="192.168.1.100",
            wireguard_port=None,
            data_dir=temp_dir,
        )

        results = optimizer.resolve_chatgpt_domains()

        assert "domains" in results
        assert "ips" in results
        assert "timestamp" in results
        assert isinstance(results["domains"], dict)
        assert isinstance(results["ips"], list)

    def test_test_chatgpt_connectivity(self, temp_dir: Path):
        """测试 ChatGPT 连接性。Test ChatGPT connectivity."""
        optimizer = ChatGPTOptimizer(
            node_ip="192.168.1.100",
            wireguard_port=None,
            data_dir=temp_dir,
        )

        # 测试连接（可能失败，取决于网络环境）
        result = optimizer.test_chatgpt_connectivity(timeout=5)

        assert "success" in result
        assert "latency_ms" in result
        assert isinstance(result["success"], bool)
        # latency_ms 可能为 None（如果连接失败）
        if result["latency_ms"] is not None:
            assert result["latency_ms"] >= 0


