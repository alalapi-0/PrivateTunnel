#!/usr/bin/env python3
"""SSH隧道和SOCKS代理诊断工具。SSH tunnel and SOCKS proxy diagnostic tool.

用于诊断VPS SSH隧道和FoxyProxy配置问题。
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
import shutil
from pathlib import Path
from typing import Optional, Tuple

# 添加项目根目录到路径，以便导入core模块
ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# 颜色输出
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        pass

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"


def print_success(msg: str) -> None:
    """打印成功消息。Print success message."""
    print(f"{GREEN}✓{RESET} {msg}")


def print_error(msg: str) -> None:
    """打印错误消息。Print error message."""
    print(f"{RED}✗{RESET} {msg}")


def print_warning(msg: str) -> None:
    """打印警告消息。Print warning message."""
    print(f"{YELLOW}⚠{RESET} {msg}")


def print_info(msg: str) -> None:
    """打印信息消息。Print info message."""
    print(f"{BLUE}ℹ{RESET} {msg}")


def check_ssh_installed() -> bool:
    """检查SSH是否已安装。Check if SSH is installed."""
    print_info("检查SSH是否已安装...")
    ssh_path = shutil.which("ssh")
    if ssh_path:
        print_success(f"SSH已安装: {ssh_path}")
        # 检查版本
        try:
            result = subprocess.run(
                ["ssh", "-V"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.stderr:
                print_info(f"  版本信息: {result.stderr.strip()}")
        except Exception:
            pass
        return True
    else:
        print_error("SSH未安装或不在PATH中")
        print_warning("  请安装OpenSSH客户端或Git for Windows")
        return False


def check_port_listening(host: str, port: int) -> bool:
    """检查端口是否在监听。Check if port is listening."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_socks_proxy(host: str, port: int) -> Tuple[bool, str]:
    """测试SOCKS代理是否工作。Test if SOCKS proxy is working."""
    print_info(f"测试SOCKS代理 {host}:{port}...")

    # 检查端口是否监听
    if not check_port_listening(host, port):
        return False, "端口未在监听"

    # 尝试通过SOCKS代理连接（简单的SOCKS5握手测试）
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # SOCKS5握手
        # 发送认证方法
        sock.send(b"\x05\x01\x00")  # VER=5, NMETHODS=1, NO AUTH
        response = sock.recv(2)

        if len(response) != 2 or response[0] != 5:
            sock.close()
            return False, "SOCKS5握手失败：无效响应"

        if response[1] == 0xFF:
            sock.close()
            return False, "SOCKS5握手失败：无可用认证方法"

        sock.close()
        return True, "SOCKS5代理正常工作"
    except socket.timeout:
        return False, "连接超时"
    except ConnectionRefusedError:
        return False, "连接被拒绝"
    except Exception as e:
        return False, f"测试失败: {str(e)}"


def check_ssh_process() -> Tuple[bool, list[int]]:
    """检查是否有SSH隧道进程在运行。Check if SSH tunnel process is running."""
    print_info("检查SSH隧道进程...")

    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq ssh.exe"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "ssh.exe" in result.stdout:
                lines = [line for line in result.stdout.split("\n") if "ssh.exe" in line]
                pids = []
                for line in lines:
                    parts = line.split()
                    if len(parts) > 1:
                        try:
                            pids.append(int(parts[1]))
                        except ValueError:
                            pass
                if pids:
                    print_success(
                        f"找到 {len(pids)} 个SSH进程 (PID: {', '.join(map(str, pids))})"
                    )
                    return True, pids
                else:
                    print_warning("找到SSH进程但无法解析PID")
                    return True, []
            else:
                print_error("未找到SSH隧道进程")
                return False, []
        except Exception as e:
            print_error(f"检查进程失败: {str(e)}")
            return False, []
    else:
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            ssh_lines = [
                line for line in result.stdout.split("\n") if "ssh" in line and "-D" in line
            ]
            if ssh_lines:
                print_success("找到SSH隧道进程")
                for line in ssh_lines[:3]:  # 只显示前3个
                    print_info(f"  {line.strip()}")
                return True, []
            else:
                print_error("未找到SSH隧道进程")
                return False, []
        except Exception as e:
            print_error(f"检查进程失败: {str(e)}")
            return False, []


def test_vps_connection(
    vps_ip: str, vps_port: int = 22, ssh_key: Optional[str] = None
) -> Tuple[bool, str]:
    """测试VPS SSH连接。Test VPS SSH connection."""
    print_info(f"测试VPS连接 {vps_ip}:{vps_port}...")

    # 先测试端口是否开放
    if not check_port_listening(vps_ip, vps_port):
        # 尝试ping
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "2000", vps_ip],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            else:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", vps_ip],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

            if result.returncode == 0:
                print_warning(f"VPS可ping通，但SSH端口 {vps_port} 可能被防火墙阻止")
                return False, f"SSH端口 {vps_port} 不可达"
            else:
                print_error("VPS无法ping通")
                return False, "VPS无法访问"
        except Exception:
            pass

        return False, f"SSH端口 {vps_port} 不可达"

    # 尝试SSH连接
    print_info("尝试SSH连接...")
    ssh_cmd = [
        "ssh",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
    ]

    if ssh_key:
        ssh_cmd.extend(["-i", ssh_key])

    ssh_cmd.append(f"root@{vps_ip}")
    ssh_cmd.append("echo 'SSH连接成功'")

    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            print_success("SSH连接成功")
            return True, "SSH连接正常"
        else:
            error_msg = result.stderr.strip() or result.stdout.strip()
            if "Permission denied" in error_msg:
                print_error("SSH认证失败（密码或密钥问题）")
                return False, "SSH认证失败"
            elif "Connection refused" in error_msg:
                print_error("SSH连接被拒绝")
                return False, "SSH连接被拒绝"
            else:
                print_error(f"SSH连接失败: {error_msg[:100]}")
                return False, f"SSH连接失败: {error_msg[:50]}"
    except subprocess.TimeoutExpired:
        print_error("SSH连接超时")
        return False, "SSH连接超时"
    except FileNotFoundError:
        print_error("SSH命令未找到")
        return False, "SSH未安装"
    except Exception as e:
        print_error(f"SSH连接测试异常: {str(e)}")
        return False, f"测试异常: {str(e)}"


def check_local_port(port: int) -> Tuple[bool, Optional[str]]:
    """检查本地端口是否被占用。Check if local port is in use."""
    print_info(f"检查本地端口 {port}...")

    if check_port_listening("127.0.0.1", port):
        print_success(f"端口 {port} 正在监听")

        # 尝试确定是什么进程在使用
        if sys.platform == "win32":
            try:
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                for line in result.stdout.split("\n"):
                    if f":{port}" in line and "LISTENING" in line:
                        parts = line.split()
                        if len(parts) > 4:
                            pid = parts[-1]
                            try:
                                task_result = subprocess.run(
                                    ["tasklist", "/FI", f"PID eq {pid}"],
                                    capture_output=True,
                                    text=True,
                                    timeout=5,
                                )
                                if pid in task_result.stdout:
                                    for task_line in task_result.stdout.split("\n"):
                                        if pid in task_line:
                                            print_info(f"  使用进程: {task_line.strip()}")
                                            break
                            except Exception:
                                pass
                        break
            except Exception:
                pass
        return True, None
    else:
        print_error(f"端口 {port} 未在监听")
        return False, f"端口 {port} 未被占用"


def get_vps_instances() -> Tuple[bool, list[dict], Optional[str]]:
    """从Vultr API获取VPS实例列表。Get VPS instances from Vultr API."""
    try:
        from core.tools.vultr_manager import VultrError, list_instances
    except ImportError:
        return False, [], "无法导入vultr_manager模块"

    api_key = os.environ.get("VULTR_API_KEY", "").strip()
    if not api_key:
        return False, [], "未设置环境变量 VULTR_API_KEY"

    try:
        instances = list_instances(api_key)
        return True, instances, None
    except VultrError as e:
        return False, [], f"获取实例列表失败: {str(e)}"
    except Exception as e:
        return False, [], f"未知错误: {str(e)}"


def select_vps_instance(vps_ip: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """选择VPS实例。Select VPS instance."""
    if vps_ip:
        return vps_ip, None

    print_info("尝试从Vultr账户获取VPS实例...")
    success, instances, error = get_vps_instances()

    if not success:
        if error and "VULTR_API_KEY" in error:
            print_warning(f"  {error}")
            print_warning("  将使用默认IP地址或手动指定的--vps-ip")
        else:
            print_warning(f"  {error}")
        return None, error

    if not instances:
        print_warning("  账户中没有VPS实例")
        return None, "账户中没有VPS实例"

    # 过滤出有IP地址且状态为active的实例
    active_instances = [
        inst
        for inst in instances
        if inst.get("main_ip") and inst.get("status") == "active"
    ]

    if not active_instances:
        print_warning("  没有找到活跃的VPS实例")
        return None, "没有活跃的VPS实例"

    # 如果只有一个实例，直接使用
    if len(active_instances) == 1:
        selected = active_instances[0]
        ip = selected.get("main_ip")
        label = selected.get("label") or selected.get("id", "")
        print_success(f"  自动选择唯一实例: {label} ({ip})")
        return ip, None

    # 多个实例，显示列表让用户选择
    print_info(f"  找到 {len(active_instances)} 个活跃实例:")
    for idx, inst in enumerate(active_instances, 1):
        instance_id = inst.get("id", "")
        label = inst.get("label") or "-"
        region = inst.get("region")
        if isinstance(region, dict):
            region_code = region.get("code") or region.get("id") or ""
        else:
            region_code = str(region or "")
        main_ip = inst.get("main_ip") or "-"
        status = inst.get("status") or "-"
        power_status = inst.get("power_status") or "-"
        print_info(
            f"    {idx}) {label} | {region_code} | {main_ip} | {status}/{power_status}"
        )

    # 默认选择第一个
    selected = active_instances[0]
    ip = selected.get("main_ip")
    label = selected.get("label") or selected.get("id", "")
    print_info(f"  使用第一个实例: {label} ({ip})")
    print_info("  (如需选择其他实例，请使用 --vps-ip 参数指定IP地址)")

    return ip, None


def generate_ssh_command(
    vps_ip: str,
    local_port: int = 1080,
    ssh_key: Optional[str] = None,
    ssh_user: str = "root",
) -> str:
    """生成SSH隧道命令。Generate SSH tunnel command."""
    cmd_parts = ["ssh"]

    if ssh_key:
        cmd_parts.extend(["-i", ssh_key])

    cmd_parts.extend(
        [
            "-D",
            str(local_port),
            "-N",
            "-f",
            f"{ssh_user}@{vps_ip}",
        ]
    )

    return " ".join(cmd_parts)


def main() -> int:
    """主函数。Main function."""
    parser = argparse.ArgumentParser(
        description="SSH隧道和SOCKS代理诊断工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 自动从Vultr账户获取实例（需要设置VULTR_API_KEY环境变量）
  python diagnose_socks_proxy.py
  
  # 手动指定VPS IP地址
  python diagnose_socks_proxy.py --vps-ip 108.160.135.80
  
  # 指定端口和SSH密钥
  python diagnose_socks_proxy.py --vps-ip 108.160.135.80 --local-port 1080 --ssh-key ~/.ssh/id_rsa
        """,
    )

    parser.add_argument(
        "--vps-ip",
        type=str,
        default=None,
        help="VPS IP地址 (如果不指定，将尝试从Vultr账户自动获取)",
    )

    parser.add_argument(
        "--local-port",
        type=int,
        default=1080,
        help="本地SOCKS代理端口 (默认: 1080)",
    )

    parser.add_argument(
        "--ssh-port",
        type=int,
        default=22,
        help="VPS SSH端口 (默认: 22)",
    )

    parser.add_argument(
        "--ssh-key",
        type=str,
        help="SSH私钥文件路径（可选）",
    )

    parser.add_argument(
        "--ssh-user",
        type=str,
        default="root",
        help="SSH用户名 (默认: root)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("SSH隧道和SOCKS代理诊断工具")
    print("=" * 60)
    print()

    # 获取VPS IP地址
    vps_ip, ip_error = select_vps_instance(args.vps_ip)
    if not vps_ip:
        if ip_error and "VULTR_API_KEY" not in ip_error:
            print_error(f"无法获取VPS IP地址: {ip_error}")
            print()
            print_warning("请使用 --vps-ip 参数手动指定VPS IP地址")
            print("  例如: python diagnose_socks_proxy.py --vps-ip 108.160.135.80")
            print()
            print_warning("或者设置环境变量 VULTR_API_KEY 以自动获取实例")
            return 1
        else:
            # 如果用户没有指定IP且无法从API获取，使用默认值
            if not args.vps_ip:
                print_error("未指定VPS IP地址且无法从Vultr账户获取")
                print()
                print_warning("请使用以下方式之一:")
                print("  1. 设置环境变量 VULTR_API_KEY 以自动获取实例")
                print("  2. 使用 --vps-ip 参数手动指定IP地址")
                print("     例如: python diagnose_socks_proxy.py --vps-ip 108.160.135.80")
                return 1
            vps_ip = args.vps_ip

    print_info(f"使用VPS IP: {vps_ip}")
    print()

    issues = []

    # 1. 检查SSH是否安装
    if not check_ssh_installed():
        issues.append("SSH未安装")
    print()

    # 2. 检查VPS连接
    vps_ok, vps_msg = test_vps_connection(vps_ip, args.ssh_port, args.ssh_key)
    if not vps_ok:
        issues.append(f"VPS连接失败: {vps_msg}")
    print()

    # 3. 检查SSH隧道进程
    has_ssh_process, pids = check_ssh_process()
    if not has_ssh_process:
        issues.append("SSH隧道进程未运行")
    print()

    # 4. 检查本地端口
    port_ok, port_msg = check_local_port(args.local_port)
    if not port_ok:
        issues.append(f"本地端口 {args.local_port} 未监听")
    print()

    # 5. 测试SOCKS代理
    if port_ok:
        socks_ok, socks_msg = check_socks_proxy("127.0.0.1", args.local_port)
        if not socks_ok:
            issues.append(f"SOCKS代理测试失败: {socks_msg}")
        else:
            print_success(socks_msg)
    else:
        issues.append("无法测试SOCKS代理（端口未监听）")
    print()

    # 总结
    print("=" * 60)
    if not issues:
        print_success("所有检查通过！SOCKS代理应该可以正常使用。")
        print()
        print_info("FoxyProxy配置:")
        print(f"  类型: SOCKS5")
        print(f"  主机: 127.0.0.1")
        print(f"  端口: {args.local_port}")
    else:
        print_error("发现问题:")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
        print()

        if not has_ssh_process:
            print_warning("建议操作:")
            print("  1. 启动SSH隧道:")
            ssh_cmd = generate_ssh_command(
                vps_ip, args.local_port, args.ssh_key, args.ssh_user
            )
            print(f"     {ssh_cmd}")
            print()
            if args.ssh_key:
                print(f"  2. 如果使用密钥，确保密钥路径正确: {args.ssh_key}")
                if not Path(args.ssh_key).exists():
                    print_error(f"    密钥文件不存在: {args.ssh_key}")
            print()

    print("=" * 60)

    return 0 if not issues else 1


if __name__ == "__main__":
    sys.exit(main())
