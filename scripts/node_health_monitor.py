#!/usr/bin/env python3
"""节点健康监控脚本。Node health monitoring script.

可以设置为定时任务，定期检查所有节点健康状态；保持为独立脚本以便在 CI/运维平台
运行，但同样兼容由 ``python main.py`` 生成的节点配置。
"""

import sys
import time
from pathlib import Path

# 添加项目根目录到路径
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.config.defaults import DEFAULT_WG_PORT
from core.tools.multi_node_manager import MultiNodeManager, NodeStatus
from core.tools.node_health_checker import NodeHealthChecker


def main():
    """主函数。Main function."""
    import argparse

    parser = argparse.ArgumentParser(description="节点健康监控")
    parser.add_argument(
        "--wireguard-port",
        type=int,
        default=DEFAULT_WG_PORT,
        help=f"WireGuard 端口（默认 {DEFAULT_WG_PORT}）",
    )
    parser.add_argument(
        "--update-status",
        action="store_true",
        help="更新节点状态",
    )
    parser.add_argument(
        "--auto-switch",
        action="store_true",
        help="自动切换到备用节点（如果当前节点不健康）",
    )

    args = parser.parse_args()

    manager = MultiNodeManager()
    nodes = manager.get_all_nodes()

    if not nodes:
        print("ℹ️ 没有配置任何节点")
        return 0

    print(f"🔍 开始检查 {len(nodes)} 个节点...")

    checker = NodeHealthChecker()
    results = {}

    for node in nodes:
        print(f"\n检查节点：{node.id} ({node.ip})")

        # 提取 WireGuard 端口
        wg_port = args.wireguard_port
        if node.endpoint:
            try:
                _, port_str = node.endpoint.rsplit(":", 1)
                wg_port = int(port_str)
            except (ValueError, AttributeError):
                pass

        metrics = checker.check_node(node.ip, wg_port)
        results[node.id] = metrics

        # 显示结果
        status_icon = "✅" if metrics.overall_healthy else "❌"
        print(f"  状态：{status_icon} {'健康' if metrics.overall_healthy else '不健康'}")
        if metrics.latency_ms:
            print(f"  延迟：{metrics.latency_ms:.2f}ms")
        print(f"  ICMP: {'✅' if metrics.icmp_success else '❌'}")
        print(f"  TCP: {'✅' if metrics.tcp_success else '❌'}")
        print(f"  HTTPS: {'✅' if metrics.https_success else '❌'}")
        print(f"  DNS: {'✅' if metrics.dns_success else '❌'}")
        print(f"  WireGuard: {'✅' if metrics.wireguard_handshake else '❌'}")

        # 更新状态
        if args.update_status:
            if metrics.overall_healthy:
                manager.update_node_status(node.id, NodeStatus.ACTIVE, metrics.latency_ms)
            else:
                manager.update_node_status(node.id, NodeStatus.FAILING, metrics.latency_ms)

    # 自动切换
    if args.auto_switch:
        default_node = manager.get_default_node()
        if default_node:
            default_metrics = results.get(default_node.id)
            if default_metrics and not default_metrics.overall_healthy:
                print(f"\n⚠️ 默认节点 {default_node.id} 不健康，尝试切换...")
                backup = manager.switch_to_backup_node(default_node.id, args.wireguard_port)
                if backup:
                    print(f"✅ 已切换到备用节点：{backup.id} ({backup.ip})")
                else:
                    print("❌ 未找到可用的备用节点")

    print("\n✅ 健康检查完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())







