"""代理配置工具模块的测试。Tests for proxy configuration utilities."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

# 添加项目根目录到路径，以便导入 core 模块
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.proxy_utils import (
    get_proxy_config,
    get_proxy_for_urllib,
    is_proxy_configured,
    log_proxy_status,
)


class TestGetProxyConfig:
    """测试 get_proxy_config() 函数。"""

    def test_all_proxy_uppercase(self):
        """测试 ALL_PROXY 环境变量（大写）。"""
        with patch.dict(os.environ, {"ALL_PROXY": "http://127.0.0.1:7890"}):
            result = get_proxy_config()
            assert result is not None
            assert result["http"] == "http://127.0.0.1:7890"
            assert result["https"] == "http://127.0.0.1:7890"

    def test_all_proxy_lowercase(self):
        """测试 all_proxy 环境变量（小写）。"""
        with patch.dict(os.environ, {"all_proxy": "http://127.0.0.1:7890"}):
            result = get_proxy_config()
            assert result is not None
            assert result["http"] == "http://127.0.0.1:7890"
            assert result["https"] == "http://127.0.0.1:7890"

    def test_https_proxy(self):
        """测试 HTTPS_PROXY 环境变量。"""
        with patch.dict(os.environ, {"HTTPS_PROXY": "https://proxy.example.com:8080"}):
            result = get_proxy_config()
            assert result is not None
            assert result["http"] == "https://proxy.example.com:8080"
            assert result["https"] == "https://proxy.example.com:8080"

    def test_http_proxy(self):
        """测试 HTTP_PROXY 环境变量。"""
        with patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.example.com:3128"}):
            result = get_proxy_config()
            assert result is not None
            assert result["http"] == "http://proxy.example.com:3128"
            assert result["https"] == "http://proxy.example.com:3128"

    def test_priority_all_proxy_over_http_proxy(self):
        """测试优先级：ALL_PROXY 优先于 HTTP_PROXY。"""
        with patch.dict(
            os.environ,
            {
                "ALL_PROXY": "http://127.0.0.1:7890",
                "HTTP_PROXY": "http://other.proxy.com:8080",
            },
        ):
            result = get_proxy_config()
            assert result is not None
            # 应该使用 ALL_PROXY 的值
            assert result["http"] == "http://127.0.0.1:7890"
            assert result["https"] == "http://127.0.0.1:7890"

    def test_priority_https_proxy_over_http_proxy(self):
        """测试优先级：HTTPS_PROXY 优先于 HTTP_PROXY。"""
        with patch.dict(
            os.environ,
            {
                "HTTPS_PROXY": "https://proxy.example.com:8080",
                "HTTP_PROXY": "http://other.proxy.com:8080",
            },
        ):
            result = get_proxy_config()
            assert result is not None
            # 应该使用 HTTPS_PROXY 的值
            assert result["http"] == "https://proxy.example.com:8080"
            assert result["https"] == "https://proxy.example.com:8080"

    def test_no_proxy_configured(self):
        """测试未配置代理时返回 None。"""
        with patch.dict(os.environ, {}, clear=True):
            result = get_proxy_config()
            assert result is None

    def test_empty_string_proxy(self):
        """测试空字符串处理。"""
        with patch.dict(os.environ, {"ALL_PROXY": ""}):
            result = get_proxy_config()
            assert result is None

    def test_whitespace_only_proxy(self):
        """测试仅包含空白字符的环境变量。"""
        with patch.dict(os.environ, {"ALL_PROXY": "   "}):
            result = get_proxy_config()
            assert result is None

    def test_auto_add_http_prefix(self):
        """测试自动添加 http:// 协议前缀。"""
        with patch.dict(os.environ, {"ALL_PROXY": "127.0.0.1:7890"}):
            result = get_proxy_config()
            assert result is not None
            assert result["http"] == "http://127.0.0.1:7890"
            assert result["https"] == "http://127.0.0.1:7890"

    def test_socks5_proxy(self):
        """测试 SOCKS5 代理协议。"""
        with patch.dict(os.environ, {"ALL_PROXY": "socks5://127.0.0.1:1080"}):
            result = get_proxy_config()
            assert result is not None
            assert result["http"] == "socks5://127.0.0.1:1080"
            assert result["https"] == "socks5://127.0.0.1:1080"

    def test_socks4_proxy(self):
        """测试 SOCKS4 代理协议。"""
        with patch.dict(os.environ, {"ALL_PROXY": "socks4://127.0.0.1:1080"}):
            result = get_proxy_config()
            assert result is not None
            assert result["http"] == "socks4://127.0.0.1:1080"
            assert result["https"] == "socks4://127.0.0.1:1080"

    def test_https_protocol_proxy(self):
        """测试 https:// 协议前缀。"""
        with patch.dict(os.environ, {"ALL_PROXY": "https://proxy.example.com:443"}):
            result = get_proxy_config()
            assert result is not None
            assert result["http"] == "https://proxy.example.com:443"
            assert result["https"] == "https://proxy.example.com:443"

    def test_case_insensitive_env_vars(self):
        """测试环境变量名大小写不敏感。"""
        # 测试混合大小写
        with patch.dict(os.environ, {"All_Proxy": "http://127.0.0.1:7890"}):
            result = get_proxy_config()
            assert result is not None
            assert result["http"] == "http://127.0.0.1:7890"

        # 测试大小写混合的 HTTPS_PROXY
        with patch.dict(os.environ, {"HtTpS_PrOxY": "http://127.0.0.1:7890"}):
            result = get_proxy_config()
            assert result is not None
            assert result["http"] == "http://127.0.0.1:7890"


class TestGetProxyForUrllib:
    """测试 get_proxy_for_urllib() 函数。"""

    def test_returns_same_as_get_proxy_config(self):
        """测试返回格式与 get_proxy_config() 相同。"""
        with patch.dict(os.environ, {"ALL_PROXY": "http://127.0.0.1:7890"}):
            urllib_result = get_proxy_for_urllib()
            config_result = get_proxy_config()
            assert urllib_result == config_result

    def test_returns_none_when_no_proxy(self):
        """测试未配置代理时返回 None。"""
        with patch.dict(os.environ, {}, clear=True):
            result = get_proxy_for_urllib()
            assert result is None


class TestIsProxyConfigured:
    """测试 is_proxy_configured() 函数。"""

    def test_returns_true_when_all_proxy_set(self):
        """测试配置了 ALL_PROXY 时返回 True。"""
        with patch.dict(os.environ, {"ALL_PROXY": "http://127.0.0.1:7890"}):
            assert is_proxy_configured() is True

    def test_returns_true_when_https_proxy_set(self):
        """测试配置了 HTTPS_PROXY 时返回 True。"""
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:7890"}):
            assert is_proxy_configured() is True

    def test_returns_true_when_http_proxy_set(self):
        """测试配置了 HTTP_PROXY 时返回 True。"""
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:7890"}):
            assert is_proxy_configured() is True

    def test_returns_false_when_no_proxy(self):
        """测试未配置代理时返回 False。"""
        with patch.dict(os.environ, {}, clear=True):
            assert is_proxy_configured() is False

    def test_returns_false_when_empty_string(self):
        """测试环境变量为空字符串时返回 False。"""
        with patch.dict(os.environ, {"ALL_PROXY": ""}):
            assert is_proxy_configured() is False

    def test_returns_false_when_whitespace_only(self):
        """测试环境变量仅包含空白字符时返回 False。"""
        with patch.dict(os.environ, {"ALL_PROXY": "   "}):
            assert is_proxy_configured() is False

    def test_case_insensitive(self):
        """测试大小写不敏感。"""
        with patch.dict(os.environ, {"all_proxy": "http://127.0.0.1:7890"}):
            assert is_proxy_configured() is True


class TestLogProxyStatus:
    """测试 log_proxy_status() 函数。"""

    def test_logs_proxy_when_configured(self, capsys):
        """测试配置了代理时记录代理信息。"""
        with patch.dict(os.environ, {"ALL_PROXY": "http://127.0.0.1:7890"}):
            log_proxy_status()
            captured = capsys.readouterr()
            assert "使用代理" in captured.out
            assert "http://127.0.0.1:7890" in captured.out
            assert "ALL_PROXY" in captured.out

    def test_logs_no_proxy_when_not_configured(self, capsys):
        """测试未配置代理时记录未配置信息。"""
        with patch.dict(os.environ, {}, clear=True):
            log_proxy_status()
            captured = capsys.readouterr()
            assert "未配置代理，将直连" in captured.out

    def test_logs_with_custom_logger(self):
        """测试使用自定义 logger。"""
        import logging

        logger = logging.getLogger("test_logger")
        logger.setLevel(logging.INFO)

        # 创建一个 StringHandler 来捕获日志
        from io import StringIO

        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        logger.addHandler(handler)

        with patch.dict(os.environ, {"ALL_PROXY": "http://127.0.0.1:7890"}):
            log_proxy_status(logger=logger)
            log_output = log_stream.getvalue()
            assert "使用代理" in log_output
            assert "http://127.0.0.1:7890" in log_output

        logger.removeHandler(handler)

    def test_logs_https_proxy_source(self, capsys):
        """测试记录 HTTPS_PROXY 来源。"""
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy.example.com:8080"}):
            log_proxy_status()
            captured = capsys.readouterr()
            assert "使用代理" in captured.out
            assert "proxy.example.com:8080" in captured.out
            assert "HTTPS_PROXY" in captured.out

    def test_logs_http_proxy_source(self, capsys):
        """测试记录 HTTP_PROXY 来源。"""
        with patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.example.com:3128"}):
            log_proxy_status()
            captured = capsys.readouterr()
            assert "使用代理" in captured.out
            assert "proxy.example.com:3128" in captured.out
            assert "HTTP_PROXY" in captured.out
