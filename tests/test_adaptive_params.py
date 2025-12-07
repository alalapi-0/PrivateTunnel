"""自适应参数测试。Adaptive parameter tests."""

from __future__ import annotations

import pytest

from core.tools.adaptive_params import AdaptiveParameterTuner, ParameterSet, ParameterAdjustment
from core.tools.connection_stats import ConnectionSession, ConnectionMetrics
from tests.conftest import temp_dir, sample_metrics


class TestAdaptiveParameterTuner:
    """自适应参数调整器测试类。Adaptive parameter tuner test class."""

    def test_initialization(self, temp_dir: Path):
        """测试初始化。Test initialization."""
        tuner = AdaptiveParameterTuner(
            node_id="test-node",
            data_dir=temp_dir,
        )

        assert tuner.node_id == "test-node"
        assert tuner.current_params is not None
        assert tuner.current_params.keepalive > 0
        assert tuner.current_params.mtu > 0

    def test_analyze_and_suggest(self, temp_dir: Path, sample_metrics: ConnectionMetrics):
        """测试分析和建议。Test analyze and suggest."""
        tuner = AdaptiveParameterTuner(
            node_id="test-node",
            data_dir=temp_dir,
        )

        # 创建测试会话
        session = ConnectionSession(
            session_id="test-session",
            node_id="test-node",
        )
        session.add_metrics(sample_metrics)

        # 分析并建议
        suggested, reason = tuner.analyze_and_suggest(session)

        assert isinstance(suggested, ParameterSet)
        assert isinstance(reason, str)
        assert suggested.keepalive > 0
        assert suggested.mtu > 0

    def test_parameter_set(self):
        """测试参数集合。Test parameter set."""
        params = ParameterSet(keepalive=25, mtu=1280)

        assert params.keepalive == 25
        assert params.mtu == 1280
        assert params.timestamp > 0

        # 测试序列化
        data = params.to_dict()
        assert "keepalive" in data
        assert "mtu" in data

        # 测试反序列化
        params2 = ParameterSet.from_dict(data)
        assert params2.keepalive == params.keepalive
        assert params2.mtu == params.mtu

    def test_parameter_adjustment(self):
        """测试参数调整记录。Test parameter adjustment record."""
        old_params = ParameterSet(keepalive=25, mtu=1280)
        new_params = ParameterSet(keepalive=20, mtu=1200)

        adjustment = ParameterAdjustment(
            adjustment_id="adj-1",
            node_id="test-node",
            old_params=old_params,
            new_params=new_params,
            reason="测试调整",
            quality_before=80.0,
            quality_after=85.0,
            success=True,
        )

        assert adjustment.adjustment_id == "adj-1"
        assert adjustment.node_id == "test-node"
        assert adjustment.success is True

        # 测试序列化
        data = adjustment.to_dict()
        assert "adjustment_id" in data
        assert "old_params" in data
        assert "new_params" in data


