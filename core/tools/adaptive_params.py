"""自适应参数调整器。Adaptive parameter tuner."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import logging

from core.config.defaults import DEFAULT_CLIENT_MTU, DEFAULT_KEEPALIVE_SECONDS
from core.tools.connection_stats import ConnectionMetrics, ConnectionSession
from core.logging_utils import get_logger

LOGGER = get_logger(__name__)


@dataclass
class ParameterSet:
    """参数集合。Parameter set."""

    keepalive: int = DEFAULT_KEEPALIVE_SECONDS  # PersistentKeepalive（秒）
    mtu: int = DEFAULT_CLIENT_MTU  # MTU
    timestamp: int = 0  # 应用时间戳

    def __post_init__(self):
        if self.timestamp == 0:
            self.timestamp = int(time.time())

    def to_dict(self) -> dict[str, Any]:
        """转换为字典。Convert to dictionary."""
        return {
            "keepalive": self.keepalive,
            "mtu": self.mtu,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ParameterSet:
        """从字典创建。Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})


@dataclass
class ParameterAdjustment:
    """参数调整记录。Parameter adjustment record."""

    adjustment_id: str
    node_id: str
    old_params: ParameterSet
    new_params: ParameterSet
    reason: str
    quality_before: float | None = None  # 调整前的质量评分
    quality_after: float | None = None  # 调整后的质量评分
    success: bool = False  # 调整是否成功

    def to_dict(self) -> dict[str, Any]:
        """转换为字典。Convert to dictionary."""
        return {
            "adjustment_id": self.adjustment_id,
            "node_id": self.node_id,
            "old_params": self.old_params.to_dict(),
            "new_params": self.new_params.to_dict(),
            "reason": self.reason,
            "quality_before": self.quality_before,
            "quality_after": self.quality_after,
            "success": self.success,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ParameterAdjustment:
        """从字典创建。Create from dictionary."""
        return cls(
            adjustment_id=data["adjustment_id"],
            node_id=data["node_id"],
            old_params=ParameterSet.from_dict(data["old_params"]),
            new_params=ParameterSet.from_dict(data["new_params"]),
            reason=data["reason"],
            quality_before=data.get("quality_before"),
            quality_after=data.get("quality_after"),
            success=data.get("success", False),
        )


class AdaptiveParameterTuner:
    """自适应参数调整器。Adaptive parameter tuner."""

    def __init__(
        self,
        node_id: str,
        data_dir: Path | None = None,
    ):
        """初始化调整器。Initialize tuner.

        Args:
            node_id: 节点 ID
            data_dir: 数据存储目录
        """
        self.node_id = node_id

        if data_dir is None:
            # 避免循环导入，直接使用路径
            current_file = Path(__file__)
            project_root = current_file.parent.parent.parent
            artifacts_dir = project_root / "artifacts"
            data_dir = artifacts_dir / "adaptive_params"
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # 当前参数
        self.current_params = ParameterSet()

        # 参数历史
        self.adjustment_history: list[ParameterAdjustment] = []
        self._load_history()

    def _load_history(self) -> None:
        """加载调整历史。Load adjustment history."""
        history_file = self.data_dir / f"history-{self.node_id}.json"
        if history_file.exists():
            try:
                data = json.loads(history_file.read_text(encoding="utf-8"))
                self.adjustment_history = [
                    ParameterAdjustment.from_dict(item) for item in data.get("adjustments", [])
                ]
                if data.get("current_params"):
                    self.current_params = ParameterSet.from_dict(data["current_params"])
                LOGGER.info(
                    "Loaded adaptive parameter history",
                    extra={"node_id": self.node_id, "history_entries": len(self.adjustment_history)},
                )
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("Failed to load adaptive history", exc_info=exc, extra={"node_id": self.node_id})

    def _save_history(self) -> None:
        """保存调整历史。Save adjustment history."""
        history_file = self.data_dir / f"history-{self.node_id}.json"
        history_file.write_text(
            json.dumps(
                {
                    "current_params": self.current_params.to_dict(),
                    "adjustments": [adj.to_dict() for adj in self.adjustment_history],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        LOGGER.info(
            "Saved adaptive parameter history",
            extra={"node_id": self.node_id, "current_params": self.current_params.to_dict()},
        )

    def analyze_and_suggest(
        self,
        session: ConnectionSession,
        current_params: ParameterSet | None = None,
    ) -> tuple[ParameterSet, str]:
        """分析连接质量并建议参数调整。Analyze quality and suggest parameter adjustment.

        Args:
            session: 连接会话
            current_params: 当前参数（如果为 None 则使用 self.current_params）

        Returns:
            (建议的参数, 调整原因)
        """
        if current_params is None:
            current_params = self.current_params

        LOGGER.info(
            "Analyzing session for adaptive suggestions",
            extra={
                "node_id": self.node_id,
                "avg_latency": session.avg_latency_ms,
                "avg_packet_loss": session.avg_packet_loss,
                "reconnects": session.total_reconnects,
            },
        )

        suggested = ParameterSet(
            keepalive=current_params.keepalive,
            mtu=current_params.mtu,
        )
        reasons = []

        # 1. Keepalive 调整建议
        keepalive_suggestion, keepalive_reason = self._suggest_keepalive(session)
        if keepalive_suggestion != current_params.keepalive:
            suggested.keepalive = keepalive_suggestion
            reasons.append(keepalive_reason)

        # 2. MTU 调整建议
        mtu_suggestion, mtu_reason = self._suggest_mtu(session)
        if mtu_suggestion != current_params.mtu:
            suggested.mtu = mtu_suggestion
            reasons.append(mtu_reason)

        reason = "; ".join(reasons) if reasons else "无需调整"

        LOGGER.info(
            "Adaptive suggestion computed",
            extra={
                "node_id": self.node_id,
                "keepalive": suggested.keepalive,
                "mtu": suggested.mtu,
                "reason": reason,
            },
        )

        return suggested, reason

    def _suggest_keepalive(
        self,
        session: ConnectionSession,
    ) -> tuple[int, str]:
        """建议 Keepalive 值。Suggest keepalive value.

        策略：
        - 如果重连次数多，降低 Keepalive（更频繁发送）
        - 如果延迟高且稳定，可以适当提高 Keepalive（减少开销）
        - 如果丢包率高，降低 Keepalive（更快检测断线）
        - 默认范围：15-60 秒

        Args:
            session: 连接会话

        Returns:
            (建议的 Keepalive 值, 原因)
        """
        current = self.current_params.keepalive
        suggested = current

        # 计算重连频率
        duration_hours = session.get_duration() / 3600
        reconnect_rate = (
            session.total_reconnects / max(duration_hours, 0.1) if duration_hours > 0 else 0
        )

        # 策略 1：重连频繁 → 降低 Keepalive
        if reconnect_rate > 2:  # 每小时超过 2 次重连
            suggested = max(15, current - 5)
            return (
                suggested,
                f"重连频繁（{reconnect_rate:.1f}次/小时），降低 Keepalive 至 {suggested} 秒以更快检测断线",
            )

        # 策略 2：丢包率高 → 降低 Keepalive
        if session.avg_packet_loss > 0.05:  # 5% 丢包
            suggested = max(15, current - 5)
            return (
                suggested,
                f"丢包率高（{session.avg_packet_loss*100:.1f}%），降低 Keepalive 至 {suggested} 秒",
            )

        # 策略 3：延迟高且稳定 → 可以适当提高 Keepalive（减少开销）
        if session.avg_latency_ms and session.avg_latency_ms > 200:
            # 检查延迟稳定性（通过抖动）
            if session.metrics_history:
                latencies = [m.latency_ms for m in session.metrics_history if m.latency_ms]
                if len(latencies) >= 5:
                    import statistics

                    if statistics.stdev(latencies) < 50:  # 延迟稳定
                        suggested = min(60, current + 5)
                        return (
                            suggested,
                            f"延迟高但稳定（{session.avg_latency_ms:.1f}ms），提高 Keepalive 至 {suggested} 秒以减少开销",
                        )

        # 策略 4：连接稳定 → 可以适当提高 Keepalive
        if reconnect_rate < 0.1 and session.avg_packet_loss < 0.01:
            suggested = min(60, current + 5)
            return (
                suggested,
                f"连接稳定，提高 Keepalive 至 {suggested} 秒以减少开销",
            )

        return suggested, "Keepalive 无需调整"

    def _suggest_mtu(
        self,
        session: ConnectionSession,
    ) -> tuple[int, str]:
        """建议 MTU 值。Suggest MTU value.

        策略：
        - 如果丢包率高，降低 MTU（减少分片）
        - 如果延迟高，可以尝试降低 MTU（减少重传）
        - 如果连接稳定，可以尝试提高 MTU（提高效率）
        - 默认范围：1200-1420

        Args:
            session: 连接会话

        Returns:
            (建议的 MTU 值, 原因)
        """
        current = self.current_params.mtu
        suggested = current

        # 策略 1：丢包率高 → 降低 MTU
        if session.avg_packet_loss > 0.05:  # 5% 丢包
            suggested = max(1200, current - 40)
            return (
                suggested,
                f"丢包率高（{session.avg_packet_loss*100:.1f}%），降低 MTU 至 {suggested} 以减少分片",
            )

        # 策略 2：延迟高 → 可以尝试降低 MTU
        if session.avg_latency_ms and session.avg_latency_ms > 300:
            suggested = max(1200, current - 20)
            return (
                suggested,
                f"延迟高（{session.avg_latency_ms:.1f}ms），降低 MTU 至 {suggested} 以减少重传",
            )

        # 策略 3：连接稳定且延迟低 → 可以尝试提高 MTU
        if (
            session.avg_latency_ms
            and session.avg_latency_ms < 100
            and session.avg_packet_loss < 0.01
            and session.total_reconnects < 2
        ):
            suggested = min(1420, current + 20)
            return (
                suggested,
                f"连接稳定，提高 MTU 至 {suggested} 以提高效率",
            )

        return suggested, "MTU 无需调整"

    def apply_adjustment(
        self,
        new_params: ParameterSet,
        reason: str,
        quality_before: float | None = None,
    ) -> ParameterAdjustment:
        """应用参数调整。Apply parameter adjustment.

        Args:
            new_params: 新参数
            reason: 调整原因
            quality_before: 调整前的质量评分

        Returns:
            调整记录
        """
        import uuid

        adjustment = ParameterAdjustment(
            adjustment_id=str(uuid.uuid4()),
            node_id=self.node_id,
            old_params=self.current_params,
            new_params=new_params,
            reason=reason,
            quality_before=quality_before,
        )

        # 更新当前参数
        self.current_params = new_params

        # 保存历史
        self.adjustment_history.append(adjustment)
        self._save_history()

        LOGGER.info(
            "Applied adaptive adjustment",
            extra={
                "node_id": self.node_id,
                "adjustment_id": adjustment.adjustment_id,
                "old": adjustment.old_params.to_dict(),
                "new": adjustment.new_params.to_dict(),
                "reason": reason,
            },
        )

        return adjustment

    def evaluate_adjustment(
        self,
        adjustment: ParameterAdjustment,
        quality_after: float,
    ) -> None:
        """评估参数调整效果。Evaluate adjustment effectiveness.

        Args:
            adjustment: 调整记录
            quality_after: 调整后的质量评分
        """
        adjustment.quality_after = quality_after

        LOGGER.info(
            "Evaluated adaptive adjustment",
            extra={
                "node_id": adjustment.node_id,
                "adjustment_id": adjustment.adjustment_id,
                "quality_before": adjustment.quality_before,
                "quality_after": quality_after,
                "success": adjustment.success,
            },
        )

        # 判断调整是否成功
        if adjustment.quality_before is not None:
            improvement = quality_after - adjustment.quality_before
            adjustment.success = improvement > 0  # 质量提升则认为成功
        else:
            adjustment.success = quality_after > 70  # 质量评分 > 70 认为成功

        # 更新历史
        self._save_history()

    def rollback_last_adjustment(self) -> ParameterSet | None:
        """回滚最后一次调整。Rollback last adjustment.

        Returns:
            回滚后的参数，如果没有历史则返回 None
        """
        if not self.adjustment_history:
            return None

        # 找到最后一次成功的调整之前的参数
        for adj in reversed(self.adjustment_history):
            if adj.success:
                self.current_params = adj.old_params
                self._save_history()
                return self.current_params

        # 如果没有成功的调整，回滚到第一个调整之前的参数
        if self.adjustment_history:
            first_adj = self.adjustment_history[0]
            self.current_params = first_adj.old_params
            self._save_history()
            return self.current_params

        return None

    def get_recommendations(
        self,
        session: ConnectionSession,
    ) -> dict[str, Any]:
        """获取参数调整建议。Get parameter adjustment recommendations.

        Args:
            session: 连接会话

        Returns:
            建议字典
        """
        suggested, reason = self.analyze_and_suggest(session)

        recommendations = {
            "current": self.current_params.to_dict(),
            "suggested": suggested.to_dict(),
            "reason": reason,
            "changes": {
                "keepalive": suggested.keepalive != self.current_params.keepalive,
                "mtu": suggested.mtu != self.current_params.mtu,
            },
        }

        return recommendations







