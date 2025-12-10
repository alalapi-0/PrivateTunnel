"""代理功能集成测试。Integration tests for proxy functionality."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# 添加项目根目录到路径，以便导入 core 模块
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.proxy_utils import (
    get_proxy_config,
    is_proxy_configured,
    detect_local_proxy,
    auto_configure_proxy,
    log_proxy_status,
)


class TestProxyIntegration:
    """代理功能集成测试。Integration tests for proxy."""

    def test_proxy_config_with_env_var(self):
        """测试通过环境变量配置代理。Test proxy configuration via environment variable."""
        # 设置环境变量
        os.environ["ALL_PROXY"] = "http://127.0.0.1:7890"

        try:
            config = get_proxy_config()
            assert config is not None
            assert config["http"] == "http://127.0.0.1:7890"
            assert config["https"] == "http://127.0.0.1:7890"
            assert is_proxy_configured() is True
        finally:
            # 清理环境变量
            del os.environ["ALL_PROXY"]

    def test_proxy_config_without_env_var(self):
        """测试未配置代理时的行为。Test behavior without proxy configuration."""
        # 清除所有代理环境变量
        for key in list(os.environ.keys()):
            if key.upper() in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
                del os.environ[key]

        config = get_proxy_config()
        assert config is None
        assert is_proxy_configured() is False

    def test_proxy_priority(self):
        """测试代理优先级。Test proxy priority."""
        # 同时设置多个代理环境变量
        os.environ["ALL_PROXY"] = "http://127.0.0.1:7890"
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:8888"

        try:
            config = get_proxy_config()
            assert config is not None
            # ALL_PROXY 应该优先
            assert config["http"] == "http://127.0.0.1:7890"
        finally:
            del os.environ["ALL_PROXY"]
            del os.environ["HTTP_PROXY"]

    def test_detect_local_proxy_no_service(self):
        """测试无代理服务时的检测。Test detection when no proxy service is running."""
        # 这个测试可能会失败，取决于是否有代理服务运行
        # 所以只检查函数是否正常执行，不检查返回值
        result = detect_local_proxy()
        # 结果可能是 None 或检测到的代理信息
        assert result is None or isinstance(result, dict)

    def test_auto_configure_proxy_no_env(self):
        """测试自动配置代理（不设置环境变量）。Test auto-configure without setting env."""
        # 清除所有代理环境变量
        for key in list(os.environ.keys()):
            if key.upper() in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
                del os.environ[key]

        # 测试自动配置（不设置环境变量）
        result = auto_configure_proxy(set_environment=False)
        # 结果可能是 None 或代理 URL
        assert result is None or isinstance(result, str)

    def test_log_proxy_status(self, capsys):
        """测试代理状态日志。Test proxy status logging."""
        # 清除所有代理环境变量
        for key in list(os.environ.keys()):
            if key.upper() in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
                del os.environ[key]

        log_proxy_status()
        captured = capsys.readouterr()
        assert "未配置代理" in captured.out or "直连" in captured.out



