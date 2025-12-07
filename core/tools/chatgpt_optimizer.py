"""ChatGPT 专用优化器。ChatGPT-specific optimizer."""

from __future__ import annotations

import json
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from core.tools.chatgpt_domains import get_chatgpt_domains, is_chatgpt_domain
from core.tools.node_health_checker import NodeHealthChecker


class ChatGPTOptimizer:
    """ChatGPT 专用优化器。ChatGPT-specific optimizer."""
    
    def __init__(
        self,
        node_ip: str,
        wireguard_port: int | None = None,
        data_dir: Path | None = None,
    ):
        """初始化优化器。Initialize optimizer.
        
        Args:
            node_ip: 节点 IP
            wireguard_port: WireGuard 端口
            data_dir: 数据存储目录
        """
        self.node_ip = node_ip
        self.wireguard_port = wireguard_port
        
        if data_dir is None:
            # 避免循环导入，直接使用路径
            current_file = Path(__file__)
            artifacts_dir = current_file.parent.parent.parent / "artifacts"
            data_dir = artifacts_dir / "chatgpt_optimization"
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.health_checker = NodeHealthChecker()
    
    def resolve_chatgpt_domains(self) -> dict[str, Any]:
        """解析 ChatGPT 域名到 IP。Resolve ChatGPT domains to IPs.
        
        Returns:
            解析结果字典
        """
        domains = get_chatgpt_domains()
        results = {
            "domains": {},
            "ips": set(),
            "timestamp": int(time.time()),
        }
        
        for domain in domains:
            try:
                # 使用系统 DNS 解析
                ipv4_addresses = socket.getaddrinfo(domain, None, socket.AF_INET)
                ips = [addr[4][0] for addr in ipv4_addresses]
                
                results["domains"][domain] = {
                    "ips": list(set(ips)),
                    "resolved": True,
                }
                results["ips"].update(ips)
            except Exception as exc:
                results["domains"][domain] = {
                    "ips": [],
                    "resolved": False,
                    "error": str(exc),
                }
        
        results["ips"] = list(results["ips"])
        
        # 保存结果
        result_file = self.data_dir / "resolved_domains.json"
        result_file.write_text(
            json.dumps(results, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        
        return results
    
    def test_chatgpt_connectivity(
        self,
        test_url: str = "https://api.openai.com/v1/models",
        timeout: int = 10,
    ) -> dict[str, Any]:
        """测试 ChatGPT 连接性。Test ChatGPT connectivity.
        
        Args:
            test_url: 测试 URL
            timeout: 超时时间
        
        Returns:
            测试结果
        """
        result = {
            "success": False,
            "latency_ms": None,
            "status_code": None,
            "error": None,
            "timestamp": int(time.time()),
        }
        
        if not HAS_REQUESTS:
            result["error"] = "requests 库未安装"
            return result
        
        try:
            start_time = time.time()
            response = requests.get(
                test_url,
                timeout=timeout,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
            )
            elapsed_ms = (time.time() - start_time) * 1000
            
            result["success"] = response.status_code in (200, 401, 403)  # 401/403 表示服务器可达
            result["latency_ms"] = elapsed_ms
            result["status_code"] = response.status_code
        except requests.exceptions.Timeout:
            result["error"] = "Timeout"
        except requests.exceptions.ConnectionError as exc:
            result["error"] = f"Connection error: {exc}"
        except Exception as exc:
            result["error"] = str(exc)
        
        return result
    
    def optimize_for_chatgpt(
        self,
        current_keepalive: int = 25,
        current_mtu: int = 1280,
    ) -> dict[str, Any]:
        """为 ChatGPT 优化参数。Optimize parameters for ChatGPT.
        
        ChatGPT 对连接稳定性要求高，建议：
        - Keepalive: 15-20 秒（更频繁检测）
        - MTU: 1280-1320（平衡效率和稳定性）
        - 优先选择延迟低的节点
        
        Args:
            current_keepalive: 当前 Keepalive 值
            current_mtu: 当前 MTU 值
        
        Returns:
            优化建议
        """
        # 测试 ChatGPT 连接
        connectivity = self.test_chatgpt_connectivity()
        
        recommendations = {
            "keepalive": current_keepalive,
            "mtu": current_mtu,
            "reason": "无需调整",
            "connectivity_test": connectivity,
        }
        
        # Keepalive 建议
        if connectivity["success"]:
            if connectivity["latency_ms"] and connectivity["latency_ms"] > 300:
                # 延迟高，降低 Keepalive 以更快检测问题
                recommendations["keepalive"] = max(15, current_keepalive - 5)
                recommendations["reason"] = f"延迟较高（{connectivity['latency_ms']:.1f}ms），降低 Keepalive 以提高稳定性"
            elif connectivity["latency_ms"] and connectivity["latency_ms"] < 100:
                # 延迟低，可以适当提高 Keepalive
                recommendations["keepalive"] = min(30, current_keepalive + 5)
                recommendations["reason"] = f"延迟较低（{connectivity['latency_ms']:.1f}ms），可适当提高 Keepalive"
        else:
            # 连接失败，降低 Keepalive
            recommendations["keepalive"] = max(15, current_keepalive - 5)
            recommendations["reason"] = "ChatGPT 连接失败，降低 Keepalive 以更快检测问题"
        
        # MTU 建议
        if connectivity["success"]:
            if connectivity["latency_ms"] and connectivity["latency_ms"] > 200:
                # 延迟高，降低 MTU
                recommendations["mtu"] = max(1200, current_mtu - 40)
                recommendations["reason"] += f"；降低 MTU 至 {recommendations['mtu']} 以减少重传"
            else:
                # 延迟正常，保持或略微提高 MTU
                recommendations["mtu"] = min(1320, current_mtu + 20)
        else:
            # 连接失败，降低 MTU
            recommendations["mtu"] = max(1200, current_mtu - 40)
        
        return recommendations
    
    def generate_split_config(
        self,
        output_path: Path | None = None,
    ) -> Path:
        """生成分流配置文件。Generate split routing configuration.
        
        Args:
            output_path: 输出路径（如果为 None 则使用默认路径）
        
        Returns:
            配置文件路径
        """
        if output_path is None:
            output_path = self.data_dir / "chatgpt_split.yaml"
        
        domains = get_chatgpt_domains()
        
        config = {
            "groups": {
                "chatgpt": domains,
            },
            "options": {
                "resolve_ipv6": False,
                "resolvers": ["1.1.1.1", "8.8.8.8"],
                "min_ttl_sec": 300,
                "max_workers": 4,
            },
        }
        
        # 尝试使用 yaml，如果不可用则使用 JSON
        try:
            import yaml
            output_path.write_text(
                yaml.dump(config, default_flow_style=False, allow_unicode=True),
                encoding="utf-8",
            )
        except ImportError:
            # 如果没有 yaml 库，使用 JSON
            output_path = output_path.with_suffix(".json")
            output_path.write_text(
                json.dumps(config, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        
        return output_path

