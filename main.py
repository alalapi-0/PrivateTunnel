from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def create_vps() -> None:
    from core.tools.vultr_manager import (  # pylint: disable=import-outside-toplevel
        VultrError,
        create_instance,
        wait_instance_active,
    )

    api_key = os.environ.get("VULTR_API_KEY", "")
    if not api_key:
        print("❌ 未检测到环境变量 VULTR_API_KEY。请先设置后重试。")
        return

    region = input("region [nrt]: ").strip() or "nrt"
    plan = input("plan [vc2-1c-1gb]: ").strip() or "vc2-1c-1gb"
    snapshot_id = input("snapshot_id (可留空): ").strip() or None

    try:
        print("→ 创建实例中...")
        inst = create_instance(api_key, region=region, plan=plan, snapshot_id=snapshot_id)
        iid = inst["id"]
        print(f"实例已创建，id={iid}，等待 active ...")
        ready = wait_instance_active(api_key, iid, timeout=600, interval=10)
        ip = ready["ip"]
        print(f"✅ 实例就绪：id={iid}  ip={ip}")

        Path("artifacts").mkdir(exist_ok=True)
        Path("artifacts/instance.json").write_text(
            json.dumps(
                {
                    "id": iid,
                    "ip": ip,
                    "region": region,
                    "plan": plan,
                    "snapshot_id": snapshot_id or "",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        print("已写入 artifacts/instance.json")
    except VultrError as e:
        print(f"❌ 失败：{e}")
        print(
            "排查建议：\n- 检查 VULTR_API_KEY 是否正确且 Access Control 放行当前公网 IP\n"
            "- 检查 region/plan/snapshot_id 是否可用\n- 查看 Vultr 控制台是否有配额/余额限制"
        )


def run_doctor() -> None:
    code = subprocess.call([sys.executable, "scripts/project_doctor.py"])
    if code == 0:
        print("\n✅ 体检通过。详见 PROJECT_HEALTH_REPORT.md")
    else:
        print("\n⚠️ 体检发现问题，请按报告修复后再继续。")


def run_prune() -> None:
    code = subprocess.call([sys.executable, "scripts/prune_non_windows_only.py"])
    if code == 0:
        print("\n🧹 精简完成。请查看 PROJECT_PRUNE_REPORT.md")
    else:
        print("\n⚠️ 精简脚本返回异常，请查看输出。")
from core.ssh_utils import (
    SmartSSHError,
    ask_key_path,
    pick_default_key,
    smart_push_script,
    smart_ssh,
    wait_port_open,
)


def deploy_wireguard() -> None:
    inst_path = Path("artifacts/instance.json")
    if not inst_path.exists():
        print("❌ 未找到 artifacts/instance.json，请先创建 VPS。")
        return

    try:
        instance = json.loads(inst_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"❌ 解析实例信息失败：{exc}")
        return

    ip = instance.get("ip")
    if not ip:
        print("❌ 实例信息缺少 IP 字段，请重新创建或检查 artifacts/instance.json。")
        return

    print(f"发现实例 {ip}")
    mode = input("选择认证方式: [Enter=私钥] / p=密码: ").strip().lower()
    if mode == "p":
        print("⚠️ 建议使用私钥方式进行自动化部署。")
        return

    default_key = pick_default_key()
    key_path = Path(ask_key_path(default_key)).expanduser()
    print(f"✓ 使用私钥：{key_path}")

    print("→ 等待 SSH 端口 22 就绪 ...")
    if not wait_port_open(ip, 22, timeout=120):
        print("❌ SSH 端口未就绪（实例可能还在初始化或防火墙未放行 22）。")
        return

    print("→ 校验远端连通性 ...")
    try:
        check_result = smart_ssh(ip, "root", key_path, "uname -a")
    except SmartSSHError as exc:
        details = []
        for attempt in exc.attempts:
            detail = " ".join(filter(None, [attempt.error, attempt.stderr, attempt.stdout])).strip()
            details.append(f"{attempt.backend}: {detail}")
        hint = "\n".join(filter(None, details))
        message = "无法通过 SSH 测试远端通性。请确认私钥有效且放行了 22 端口。"
        if hint:
            message = f"{message}\n排查信息：\n{hint}"
        print(f"❌ {message}")
        return

    if check_result.returncode != 0:
        output = (check_result.stderr or check_result.stdout or "").strip()
        print(
            f"❌ 远端命令执行失败，退出码：{check_result.returncode}。输出：{output}"
        )
        return

    print("✅ 远端连通性正常，开始执行 WireGuard 安装脚本 ...")

    wg_install_script = r"""#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt update -y
apt install -y wireguard wireguard-tools qrencode iptables-persistent

mkdir -p /etc/wireguard
umask 077

# 生成服务端密钥
wg genkey | tee /etc/wireguard/server.private | wg pubkey > /etc/wireguard/server.public
SERVER_PRIV=$(cat /etc/wireguard/server.private)

# 写配置
cat >/etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address = 10.6.0.1/24
ListenPort = 51820
PrivateKey = __SERVER_PRIV__
SaveConfig = true
EOF
sed -i "s|__SERVER_PRIV__|${SERVER_PRIV}|" /etc/wireguard/wg0.conf

# 开启转发 & NAT
sysctl -w net.ipv4.ip_forward=1 >/dev/null
WAN_IF=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
iptables -t nat -C POSTROUTING -s 10.6.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.6.0.0/24 -o "$WAN_IF" -j MASQUERADE
# 持久化（容错）
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save || true
elif [ -d /etc/iptables ]; then
  iptables-save > /etc/iptables/rules.v4 || true
fi

systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

echo "=== wg0 status ==="
wg show || true
"""

    rc = smart_push_script(ip, str(key_path), wg_install_script)
    if rc != 0:
        print(f"❌ 远端执行部署脚本失败，退出码：{rc}")
        return

    print("→ WireGuard 服务已部署，继续添加客户端 ...")

    add_peer_script = r"""#!/usr/bin/env bash
set -euo pipefail

apt install -y qrencode

CLIENT_NAME="iphone"
CLIENT_DIR="/etc/wireguard/clients/${CLIENT_NAME}"
mkdir -p "${CLIENT_DIR}"
umask 077

wg genkey | tee "${CLIENT_DIR}/${CLIENT_NAME}.private" | wg pubkey > "${CLIENT_DIR}/${CLIENT_NAME}.public"
CLIENT_PRIV=$(cat "${CLIENT_DIR}/${CLIENT_NAME}.private")
CLIENT_PUB=$(cat "${CLIENT_DIR}/${CLIENT_NAME}.public")

# 取服务端公钥与对外地址
SERVER_PUB=$(cat /etc/wireguard/server.public)
ENDPOINT="$(curl -4 -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}'):51820"

# 将客户端作为 peer 加到服务器
wg set wg0 peer "${CLIENT_PUB}" allowed-ips 10.6.0.2/32
wg-quick save wg0 || true

# 生成客户端配置
cat > "${CLIENT_DIR}/${CLIENT_NAME}.conf" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = 10.6.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = ${SERVER_PUB}
AllowedIPs = 0.0.0.0/0
Endpoint = ${ENDPOINT}
PersistentKeepalive = 25
EOF

echo "=== QR below ==="
qrencode -t ANSIUTF8 < "${CLIENT_DIR}/${CLIENT_NAME}.conf" || true
"""

    rc2 = smart_push_script(ip, str(key_path), add_peer_script)
    if rc2 != 0:
        print(f"❌ 添加客户端/生成二维码失败，退出码：{rc2}")
        return

    artifacts_dir = Path("artifacts")
    artifacts_dir.mkdir(exist_ok=True)

    server_pub = ""
    try:
        pub_result = smart_ssh(ip, "root", key_path, "cat /etc/wireguard/server.public")
    except SmartSSHError as exc:  # pragma: no cover - network dependent
        print(f"⚠️ 读取服务端公钥失败：{exc}")
    else:
        if pub_result.returncode == 0:
            server_pub = (pub_result.stdout or "").strip()
        else:
            output = (pub_result.stderr or pub_result.stdout or "").strip()
            print(f"⚠️ 读取服务端公钥失败：{output}")

    if server_pub:
        server_path = artifacts_dir / "server.json"
        server_payload = {"server_pub": server_pub, "port": 51820, "ip": ip}
        server_path.write_text(
            json.dumps(server_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"🗂  已写入 {server_path}")

    try:
        subprocess.run(
            [
                "scp",
                "-i",
                str(key_path),
                f"root@{ip}:/etc/wireguard/clients/iphone/iphone.conf",
                str(artifacts_dir / "iphone.conf"),
            ],
            check=False,
        )
        print("ℹ️ 已尝试下载到 artifacts/iphone.conf")
    except FileNotFoundError:
        print("⚠️ 未找到 scp，可手动复制 /etc/wireguard/clients/iphone/iphone.conf")

    print("✅ WireGuard 部署完成，并已生成 iPhone 客户端二维码（见上方输出）。")


def main() -> None:
    while True:
        print("\n=== PrivateTunnel (Windows Only) ===")
        print("1) 运行体检")
        print("2) 创建 VPS（Vultr）")
        print("3) 部署 WireGuard（到已创建 VPS）")
        print("4) 执行项目精简（移除/归档非 Windows 代码与 CI）")
        print("q) 退出")
        choice = input("请选择: ").strip().lower()
        if choice == "1":
            run_doctor()
        elif choice == "2":
            create_vps()
        elif choice == "3":
            deploy_wireguard()
        elif choice == "4":
            run_prune()
        elif choice == "q":
            break
        else:
            print("无效选项，请重试。")


if __name__ == "__main__":
    main()
