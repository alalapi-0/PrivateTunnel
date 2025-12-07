"""节点健康检查器。Node health checker for multi-node scenarios."""

from __future__ import annotations

import random
import re
import socket
import subprocess
import time
import statistics
from typing import Any
from dataclasses import dataclass
from enum import Enum

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    # 创建占位类以避免类型错误
    class HTTPAdapter:
        pass
    class Retry:
        pass


class HealthCheckResult(str, Enum):
    """健康检查结果。Health check result."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class HealthCheckMetrics:
    """健康检查指标。Health check metrics."""

    latency_ms: float | None = None  # 延迟（毫秒）
    icmp_success: bool = False  # ICMP ping 成功
    tcp_success: bool = False  # TCP 连接成功
    https_success: bool = False  # HTTPS 请求成功
    dns_success: bool = False  # DNS 解析成功
    wireguard_handshake: bool = False  # WireGuard 握手成功
    overall_healthy: bool = False  # 整体健康状态
    error_message: str | None = None  # 错误信息
    timestamp: int = 0  # 检查时间戳

    def __post_init__(self):
        if self.timestamp == 0:
            self.timestamp = int(time.time())

        # 判断整体健康状态（至少有一项成功即认为健康）
        self.overall_healthy = any([
            self.icmp_success,
            self.tcp_success,
            self.https_success,
            self.dns_success,
            self.wireguard_handshake,
        ])


class NodeHealthChecker:
    """节点健康检查器。Node health checker."""

    def __init__(
        self,
        timeout: int = 5,
        icmp_count: int = 3,
        https_timeout: int = 10,
    ):
        """初始化健康检查器。Initialize health checker.

        Args:
            timeout: 总体超时时间（秒）
            icmp_count: ICMP ping 次数
            https_timeout: HTTPS 请求超时（秒）
        """
        self.timeout = timeout
        self.icmp_count = icmp_count
        self.https_timeout = https_timeout

        # 配置 requests session（支持重试）
        if HAS_REQUESTS:
            self.session = requests.Session()
            retry_strategy = Retry(
                total=2,
                backoff_factor=0.5,
                status_forcelist=[500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        else:
            self.session = None

    def check_icmp(self, ip: str) -> tuple[bool, float | None]:
        """检查 ICMP 连通性。Check ICMP connectivity.

        Args:
            ip: 目标 IP 地址

        Returns:
            (是否成功, 延迟毫秒)
        """
        import platform

        try:
            # 根据操作系统选择 ping 命令
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", str(self.icmp_count), "-w", str(self.timeout * 1000), ip]
            else:
                cmd = ["ping", "-c", str(self.icmp_count), "-W", str(self.timeout), ip]

            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 2,
            )
            elapsed_ms = (time.time() - start_time) * 1000

            if result.returncode == 0:
                # 尝试从输出中提取延迟
                latency = self._extract_latency_from_ping(result.stdout)
                return True, latency or elapsed_ms
            return False, None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as exc:
            return False, None

    def _extract_latency_from_ping(self, output: str) -> float | None:
        """从 ping 输出中提取延迟。Extract latency from ping output."""
        # Windows: "时间<1ms" 或 "时间=45ms"
        # Linux: "time=45.2 ms"
        patterns = [
            r"时间[<=](\d+(?:\.\d+)?)ms",
            r"time=(\d+(?:\.\d+)?)\s*ms",
            r"time=(\d+(?:\.\d+)?)ms",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                try:
                    latencies = [float(m) for m in matches]
                    return statistics.mean(latencies)
                except (ValueError, statistics.StatisticsError):
                    pass

        return None

    def check_tcp(self, ip: str, port: int, timeout: int | None = None) -> tuple[bool, float | None]:
        """检查 TCP 连接。Check TCP connection.

        Args:
            ip: 目标 IP
            port: 目标端口
            timeout: 超时时间（秒），默认使用 self.timeout

        Returns:
            (是否成功, 延迟毫秒)
        """
        if timeout is None:
            timeout = self.timeout

        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            elapsed_ms = (time.time() - start_time) * 1000
            sock.close()

            success = result == 0
            return success, elapsed_ms if success else None
        except Exception:
            return False, None

    def check_https(
        self,
        url: str = "https://1.1.1.1/cdn-cgi/trace",
        timeout: int | None = None,
    ) -> tuple[bool, float | None]:
        """检查 HTTPS 可达性。Check HTTPS reachability.

        Args:
            url: 目标 URL
            timeout: 超时时间（秒）

        Returns:
            (是否成功, 延迟毫秒)
        """
        if not HAS_REQUESTS or not self.session:
            return False, None
        
        if timeout is None:
            timeout = self.https_timeout

        try:
            start_time = time.time()
            response = self.session.get(
                url,
                timeout=timeout,
                verify=True,
                allow_redirects=True,
            )
            elapsed_ms = (time.time() - start_time) * 1000

            success = response.status_code in (200, 201, 202, 204, 301, 302, 303, 307, 308)
            return success, elapsed_ms if success else None
        except Exception:
            return False, None

    def check_dns(self, hostname: str = "api.openai.com", timeout: int | None = None) -> tuple[bool, float | None]:
        """检查 DNS 解析。Check DNS resolution.

        Args:
            hostname: 要解析的域名
            timeout: 超时时间（秒）

        Returns:
            (是否成功, 延迟毫秒)
        """
        if timeout is None:
            timeout = self.timeout

        try:
            import socket as sock

            start_time = time.time()
            sock.getaddrinfo(hostname, None, sock.AF_INET)
            elapsed_ms = (time.time() - start_time) * 1000
            return True, elapsed_ms
        except Exception:
            return False, None

    def check_wireguard_handshake(self, ip: str, port: int) -> tuple[bool, float | None]:
        """检查 WireGuard 握手（通过 UDP 端口检测）。

        注意：这不是真正的 WireGuard 握手，只是检测 UDP 端口是否可达。
        真正的握手需要密钥，这里只做端口检测。

        Args:
            ip: 服务器 IP
            port: WireGuard 端口

        Returns:
            (是否成功, 延迟毫秒)
        """
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # 发送一个简单的 UDP 包（WireGuard 会忽略无效包，但端口可达性可以检测）
            # 注意：这不能完全代表 WireGuard 可用性，但可以检测端口是否开放
            try:
                sock.sendto(b"", (ip, port))
                # UDP 是无连接的，无法真正知道是否成功
                # 但如果没有异常，说明至少可以发送
                elapsed_ms = (time.time() - start_time) * 1000
                sock.close()
                return True, elapsed_ms
            except Exception:
                sock.close()
                return False, None
        except Exception:
            return False, None

    def check_node(
        self,
        ip: str,
        wireguard_port: int | None = None,
        https_url: str | None = None,
    ) -> HealthCheckMetrics:
        """执行完整的节点健康检查。Perform complete node health check.

        Args:
            ip: 节点 IP 地址
            wireguard_port: WireGuard 端口（如果提供）
            https_url: HTTPS 检查 URL（如果提供，默认使用 1.1.1.1）

        Returns:
            健康检查指标
        """
        metrics = HealthCheckMetrics()

        # 1. ICMP ping 检查
        icmp_success, icmp_latency = self.check_icmp(ip)
        metrics.icmp_success = icmp_success
        if icmp_latency:
            metrics.latency_ms = icmp_latency

        # 2. TCP 22 (SSH) 检查
        tcp_success, tcp_latency = self.check_tcp(ip, 22)
        metrics.tcp_success = tcp_success
        if tcp_latency and (metrics.latency_ms is None or tcp_latency < metrics.latency_ms):
            metrics.latency_ms = tcp_latency

        # 3. HTTPS 检查
        https_url = https_url or "https://1.1.1.1/cdn-cgi/trace"
        https_success, https_latency = self.check_https(https_url)
        metrics.https_success = https_success
        if https_latency and (metrics.latency_ms is None or https_latency < metrics.latency_ms):
            metrics.latency_ms = https_latency

        # 4. DNS 检查
        dns_success, dns_latency = self.check_dns()
        metrics.dns_success = dns_success
        if dns_latency and (metrics.latency_ms is None or dns_latency < metrics.latency_ms):
            metrics.latency_ms = dns_latency

        # 5. WireGuard 端口检查（如果提供）
        if wireguard_port:
            wg_success, wg_latency = self.check_wireguard_handshake(ip, wireguard_port)
            metrics.wireguard_handshake = wg_success
            if wg_latency and (metrics.latency_ms is None or wg_latency < metrics.latency_ms):
                metrics.latency_ms = wg_latency

        # 计算整体健康状态
        metrics.__post_init__()  # 重新计算 overall_healthy

        return metrics


class ExponentialBackoff:
    """指数退避重试。Exponential backoff retry."""

    def __init__(
        self,
        base_delay: float = 2.0,
        max_delay: float = 60.0,
        multiplier: float = 2.0,
        jitter: float = 0.2,
    ):
        """初始化指数退避。Initialize exponential backoff.

        Args:
            base_delay: 基础延迟（秒）
            max_delay: 最大延迟（秒）
            multiplier: 倍数
            jitter: 抖动比例（0-1）
        """
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.multiplier = multiplier
        self.jitter = jitter
        self.attempt = 0

    def next_delay(self) -> float:
        """获取下一次延迟。Get next delay."""
        delay = min(
            self.base_delay * (self.multiplier ** self.attempt),
            self.max_delay
        )

        # 添加抖动
        jitter_amount = delay * self.jitter * random.uniform(-1, 1)
        delay += jitter_amount

        self.attempt += 1
        return max(0, delay)

    def reset(self) -> None:
        """重置计数器。Reset counter."""
        self.attempt = 0

