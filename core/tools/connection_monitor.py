"""连接质量监控器。Connection quality monitor."""

from __future__ import annotations

import json
import statistics
import time
import uuid
from pathlib import Path
from typing import Any, Callable
from collections import deque
from threading import Thread, Event

from core.tools.connection_stats import ConnectionMetrics, ConnectionSession
from core.tools.node_health_checker import NodeHealthChecker
from core.logging_utils import get_logger

LOGGER = get_logger(__name__)


class ConnectionMonitor:
    """连接质量监控器。Connection quality monitor."""

    def __init__(
        self,
        node_id: str,
        node_ip: str,
        wireguard_port: int | None = None,
        check_interval: int = 30,
        history_size: int = 100,
        data_dir: Path | None = None,
        enable_adaptive: bool = False,
    ):
        """初始化监控器。Initialize monitor.

        Args:
            node_id: 节点 ID
            node_ip: 节点 IP
            wireguard_port: WireGuard 端口
            check_interval: 检查间隔（秒）
            history_size: 历史记录大小
            data_dir: 数据存储目录
            enable_adaptive: 是否启用自适应参数调整
        """
        self.node_id = node_id
        self.node_ip = node_ip
        self.wireguard_port = wireguard_port
        self.check_interval = check_interval
        self.history_size = history_size

        # 数据存储
        if data_dir is None:
            # 避免循环导入，直接使用路径
            # 获取项目根目录
            current_file = Path(__file__)
            project_root = current_file.parent.parent.parent
            artifacts_dir = project_root / "artifacts"
            data_dir = artifacts_dir / "connection_stats"
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # 监控状态
        self.is_monitoring = False
        self.monitor_thread: Thread | None = None
        self.stop_event = Event()

        # 当前会话
        self.current_session: ConnectionSession | None = None

        # 历史数据（内存缓存）
        self.latency_history: deque[float] = deque(maxlen=history_size)
        self.packet_loss_history: deque[float] = deque(maxlen=history_size)

        # 健康检查器
        self.health_checker = NodeHealthChecker()

        # 自适应参数调整
        self.enable_adaptive = enable_adaptive
        if enable_adaptive:
            from core.tools.adaptive_params import AdaptiveParameterTuner

            self.param_tuner = AdaptiveParameterTuner(node_id)
        else:
            self.param_tuner = None

        # 回调函数
        self.on_metrics_update: Callable[[ConnectionMetrics], None] | None = None
        self.on_quality_degraded: Callable[[ConnectionMetrics], None] | None = None
        self.on_params_adjusted: Callable[[dict[str, Any]], None] | None = None

    def start_monitoring(self) -> None:
        """开始监控。Start monitoring."""
        if self.is_monitoring:
            return

        LOGGER.info(
            "Starting connection monitoring",
            extra={
                "node_id": self.node_id,
                "node_ip": self.node_ip,
                "interval": self.check_interval,
                "adaptive": self.enable_adaptive,
            },
        )
        # 创建新会话
        session_id = str(uuid.uuid4())
        self.current_session = ConnectionSession(
            session_id=session_id,
            node_id=self.node_id,
        )

        self.is_monitoring = True
        self.stop_event.clear()

        # 启动监控线程
        self.monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self) -> None:
        """停止监控。Stop monitoring."""
        if not self.is_monitoring:
            return

        self.is_monitoring = False
        self.stop_event.set()

        LOGGER.info(
            "Stopping connection monitoring",
            extra={"node_id": self.node_id, "node_ip": self.node_ip},
        )

        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

        # 结束当前会话
        if self.current_session:
            self.current_session.end_time = int(time.time())
            self._save_session(self.current_session)
            self.current_session = None

    def _monitor_loop(self) -> None:
        """监控循环。Monitor loop."""
        last_metrics: ConnectionMetrics | None = None
        check_count = 0

        while not self.stop_event.is_set():
            try:
                # 收集指标
                metrics = self._collect_metrics(last_metrics)

                if metrics:
                    # 更新历史
                    if metrics.latency_ms:
                        self.latency_history.append(metrics.latency_ms)
                    if metrics.packet_loss_rate is not None:
                        self.packet_loss_history.append(metrics.packet_loss_rate)

                    # 添加到当前会话
                    if self.current_session:
                        self.current_session.add_metrics(metrics)

                    # 触发回调
                    if self.on_metrics_update:
                        self.on_metrics_update(metrics)

                    LOGGER.info(
                        "Connection health check",
                        extra={
                            "node_id": self.node_id,
                            "node_ip": self.node_ip,
                            "latency_ms": metrics.latency_ms,
                            "packet_loss": metrics.packet_loss_rate,
                            "jitter_ms": metrics.jitter_ms,
                            "uptime": metrics.connection_uptime,
                        },
                    )

                    # 检查质量下降
                    if self._check_quality_degraded(metrics):
                        if self.on_quality_degraded:
                            self.on_quality_degraded(metrics)
                        LOGGER.warning(
                            "Connection quality degraded",
                            extra={
                                "node_id": self.node_id,
                                "latency_ms": metrics.latency_ms,
                                "packet_loss": metrics.packet_loss_rate,
                                "jitter_ms": metrics.jitter_ms,
                            },
                        )

                    # 自适应参数调整（每 10 次检查评估一次）
                    if self.enable_adaptive and self.param_tuner and self.current_session:
                        check_count += 1
                        if check_count >= 10:  # 每 10 次检查（约 5 分钟）评估一次
                            check_count = 0
                            self._evaluate_and_adjust_params()

                    last_metrics = metrics

                # 等待下次检查
                self.stop_event.wait(self.check_interval)
            except Exception as exc:
                # 监控错误不应中断监控
                LOGGER.exception(
                    "Error occurred during connection monitoring loop",
                    exc_info=exc,
                    extra={"node_id": self.node_id, "node_ip": self.node_ip},
                )
                time.sleep(self.check_interval)

    def _collect_metrics(self, last_metrics: ConnectionMetrics | None = None) -> ConnectionMetrics | None:
        """收集指标。Collect metrics."""
        metrics = ConnectionMetrics()

        # 1. 延迟检测
        health_metrics = self.health_checker.check_node(
            self.node_ip,
            self.wireguard_port,
        )

        if health_metrics.latency_ms:
            metrics.latency_ms = health_metrics.latency_ms

        # 2. 计算抖动（如果有历史延迟）
        if self.latency_history:
            latencies = list(self.latency_history)
            if len(latencies) >= 2:
                # 抖动 = 延迟的标准差
                metrics.jitter_ms = statistics.stdev(latencies) if len(latencies) > 1 else 0.0

        # 3. 丢包率（简化实现：基于健康检查失败率）
        if len(self.latency_history) > 0:
            # 如果延迟历史中有很多高延迟，认为有丢包
            failed_checks = sum(1 for l in self.latency_history if l > 500)
            metrics.packet_loss_rate = failed_checks / len(self.latency_history)
        else:
            metrics.packet_loss_rate = 0.0

        # 4. 连接持续时间
        if self.current_session:
            metrics.connection_uptime = self.current_session.get_duration()

        # 5. 重连次数（如果有上次指标，比较会话 ID）
        if last_metrics and self.current_session:
            # 简化：如果连接时间重置，认为发生了重连
            if metrics.connection_uptime < last_metrics.connection_uptime:
                metrics.reconnect_count = 1

        # 注意：tx_bytes, rx_bytes, tx_packets, rx_packets 需要从 WireGuard 接口获取
        # 这里暂时设为 0，后续可以通过 wg show 命令获取

        return metrics

    def _check_quality_degraded(self, metrics: ConnectionMetrics) -> bool:
        """检查质量是否下降。Check if quality degraded."""
        # 延迟过高
        if metrics.latency_ms and metrics.latency_ms > 500:
            return True

        # 丢包率过高
        if metrics.packet_loss_rate > 0.1:  # 10% 丢包
            return True

        # 抖动过大
        if metrics.jitter_ms and metrics.jitter_ms > 100:
            return True

        return False

    def _save_session(self, session: ConnectionSession) -> None:
        """保存会话数据。Save session data."""
        session_file = self.data_dir / f"session-{session.session_id}.json"
        session_file.write_text(
            json.dumps(session.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def get_current_stats(self) -> dict[str, Any] | None:
        """获取当前统计。Get current statistics."""
        if not self.current_session:
            return None

        return {
            "session_id": self.current_session.session_id,
            "duration": self.current_session.get_duration(),
            "avg_latency_ms": self.current_session.avg_latency_ms,
            "max_latency_ms": self.current_session.max_latency_ms,
            "min_latency_ms": self.current_session.min_latency_ms,
            "avg_packet_loss": self.current_session.avg_packet_loss,
            "total_reconnects": self.current_session.total_reconnects,
            "total_tx_bytes": self.current_session.total_tx_bytes,
            "total_rx_bytes": self.current_session.total_rx_bytes,
            "metrics_count": len(self.current_session.metrics_history),
        }

    def generate_report(
        self,
        session_id: str | None = None,
        days: int = 7,
    ) -> dict[str, Any]:
        """生成连接质量报告。Generate connection quality report.

        Args:
            session_id: 会话 ID（如果为 None 则使用当前会话）
            days: 报告天数

        Returns:
            报告字典
        """
        if session_id:
            session_file = self.data_dir / f"session-{session_id}.json"
            if session_file.exists():
                session_data = json.loads(session_file.read_text(encoding="utf-8"))
                session = ConnectionSession.from_dict(session_data)
            else:
                return {"error": "Session not found"}
        elif self.current_session:
            session = self.current_session
        else:
            return {"error": "No active session"}

        # 生成报告
        report = {
            "session_id": session.session_id,
            "node_id": session.node_id,
            "start_time": session.start_time,
            "end_time": session.end_time,
            "duration": session.get_duration(),
            "summary": {
                "avg_latency_ms": session.avg_latency_ms,
                "max_latency_ms": session.max_latency_ms,
                "min_latency_ms": session.min_latency_ms,
                "avg_packet_loss": session.avg_packet_loss,
                "max_packet_loss": session.max_packet_loss,
                "total_reconnects": session.total_reconnects,
                "total_tx_bytes": session.total_tx_bytes,
                "total_rx_bytes": session.total_rx_bytes,
                "total_tx_packets": session.total_tx_packets,
                "total_rx_packets": session.total_rx_packets,
            },
            "quality_score": self._calculate_quality_score(session),
        }

        return report

    def _calculate_quality_score(self, session: ConnectionSession) -> float:
        """计算质量评分。Calculate quality score (0-100)."""
        score = 100.0

        # 延迟扣分（延迟越高扣分越多）
        if session.avg_latency_ms:
            if session.avg_latency_ms > 500:
                score -= 30
            elif session.avg_latency_ms > 200:
                score -= 15
            elif session.avg_latency_ms > 100:
                score -= 5

        # 丢包扣分
        if session.avg_packet_loss > 0.1:
            score -= 30
        elif session.avg_packet_loss > 0.05:
            score -= 15
        elif session.avg_packet_loss > 0.01:
            score -= 5

        # 重连扣分
        if session.total_reconnects > 10:
            score -= 20
        elif session.total_reconnects > 5:
            score -= 10
        elif session.total_reconnects > 0:
            score -= 5

        return max(0, min(100, score))

    def _evaluate_and_adjust_params(self) -> None:
        """评估并调整参数。Evaluate and adjust parameters."""
        if not self.param_tuner or not self.current_session:
            return

        # 获取建议
        recommendations = self.param_tuner.get_recommendations(self.current_session)

        # 如果有建议的调整
        if recommendations["changes"]["keepalive"] or recommendations["changes"]["mtu"]:
            # 计算当前质量评分
            quality_before = self._calculate_quality_score(self.current_session)

            # 应用调整
            from core.tools.adaptive_params import ParameterSet

            new_params = ParameterSet.from_dict(recommendations["suggested"])
            adjustment = self.param_tuner.apply_adjustment(
                new_params,
                recommendations["reason"],
                quality_before,
            )

            # 触发回调
            if self.on_params_adjusted:
                self.on_params_adjusted(
                    {
                        "adjustment": adjustment.to_dict(),
                        "recommendations": recommendations,
                    }
                )

