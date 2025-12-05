# 快速检查远程实例状态
import subprocess
import socket
import json
import sys
from pathlib import Path

def check_instance_status():
    """检查远程实例是否还在运行"""
    
    # 获取脚本所在目录的父目录（项目根目录）
    script_dir = Path(__file__).parent.parent.parent
    instance_file = script_dir / "artifacts" / "instance.json"
    
    if not instance_file.exists():
        print(f"❌ 未找到实例信息文件：{instance_file}")
        print(f"   当前工作目录：{Path.cwd()}")
        return
    
    with open(instance_file, 'r', encoding='utf-8') as f:
        instance = json.load(f)
    
    ip = instance.get("ip")
    if not ip:
        print("❌ 实例信息中缺少IP地址")
        return
    
    print(f"📡 检查实例状态：{ip}")
    print("=" * 50)
    
    # 1. Ping测试
    print("\n1️⃣ Ping测试...")
    try:
        # Windows使用-n，Linux/Mac使用-c
        ping_cmd = ["ping", "-n", "2", ip] if sys.platform == "win32" else ["ping", "-c", "2", ip]
        result = subprocess.run(
            ping_cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print("✅ Ping成功 - 实例网络可达")
        else:
            print("❌ Ping失败 - 实例可能已停止或网络不通")
            print("   注意：某些网络环境可能屏蔽ICMP，这不代表实例已停止")
    except Exception as e:
        print(f"⚠️ Ping测试异常：{e}")
    
    # 2. SSH端口测试
    print("\n2️⃣ SSH端口(22)测试...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip, 22))
        sock.close()
        if result == 0:
            print("✅ SSH端口开放 - 可以尝试SSH连接")
        else:
            print("❌ SSH端口不可达 - 实例可能已停止或防火墙阻止")
    except Exception as e:
        print(f"⚠️ 端口测试异常：{e}")
    
    # 3. SSH连接测试
    print("\n3️⃣ SSH连接测试...")
    key_path = Path.home() / ".ssh" / "id_ed25519"
    if not key_path.exists():
        key_path = Path.home() / ".ssh" / "id_rsa"
    
    if key_path.exists():
        try:
            # Windows上ssh命令可能是ssh.exe
            ssh_cmd = "ssh.exe" if sys.platform == "win32" else "ssh"
            result = subprocess.run(
                [
                    ssh_cmd,
                    "-i", str(key_path),
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=10",
                    "-o", "StrictHostKeyChecking=no",
                    f"root@{ip}",
                    "echo 'SSH连接成功'"
                ],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                print("✅ SSH连接成功 - 可以执行远程命令")
                print(f"   输出：{result.stdout.strip()}")
            else:
                print("❌ SSH连接失败")
                if result.stderr:
                    print(f"   错误：{result.stderr.strip()}")
        except Exception as e:
            print(f"⚠️ SSH测试异常：{e}")
    else:
        print(f"⚠️ 未找到SSH私钥（查找路径：{key_path}），跳过SSH连接测试")
    
    # 4. 检查部署脚本是否还在运行
    print("\n4️⃣ 检查部署脚本状态...")
    if key_path.exists():
        try:
            ssh_cmd = "ssh.exe" if sys.platform == "win32" else "ssh"
            result = subprocess.run(
                [
                    ssh_cmd,
                    "-i", str(key_path),
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=10",
                    "-o", "StrictHostKeyChecking=no",
                    f"root@{ip}",
                    "ps aux | grep -E 'privatetunnel-wireguard|wireguard' | grep -v grep || echo '未找到运行中的部署脚本'"
                ],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                if output and "未找到" not in output:
                    print("⚠️ 发现运行中的WireGuard相关进程：")
                    print(f"   {output}")
                else:
                    print("ℹ️ 未发现运行中的部署脚本")
        except Exception as e:
            print(f"⚠️ 检查脚本状态异常：{e}")
    
    # 5. 检查WireGuard服务状态
    print("\n5️⃣ 检查WireGuard服务状态...")
    if key_path.exists():
        try:
            ssh_cmd = "ssh.exe" if sys.platform == "win32" else "ssh"
            result = subprocess.run(
                [
                    ssh_cmd,
                    "-i", str(key_path),
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=10",
                    "-o", "StrictHostKeyChecking=no",
                    f"root@{ip}",
                    "systemctl is-active wg-quick@wg0 2>/dev/null || echo '服务未运行'"
                ],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=15
            )
            if result.returncode == 0 and result.stdout:
                status = result.stdout.strip()
                if "active" in status:
                    print(f"✅ WireGuard服务状态：{status}")
                else:
                    print(f"ℹ️ WireGuard服务状态：{status}")
            else:
                print("ℹ️ 无法获取WireGuard服务状态（可能服务未安装或未运行）")
        except Exception as e:
            print(f"⚠️ 检查服务状态异常：{e}")
    
    print("\n" + "=" * 50)
    print("检查完成！")

if __name__ == "__main__":
    check_instance_status()