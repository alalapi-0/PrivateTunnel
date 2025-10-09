#!/usr/bin/env bash
# 这是占位实现：此脚本提供 PrivateTunnel 服务器侧的一键安装脚手架骨架。
# 实际部署逻辑需要在后续迭代中根据生产环境进行补充和验证。
# 脚本仅输出提示信息，不会修改任何系统配置。请在执行前阅读脚本并手动确认每一步。

set -euo pipefail

show_help() {
  cat <<'USAGE'
PrivateTunnel Provision Script (占位版)

用法:
  install.sh [命令] [选项]

命令:
  --help            显示本帮助信息
  plan              打印即将执行的步骤清单
  scaffold          创建必要的目录与占位配置

示例:
  ./install.sh plan
  ./install.sh scaffold

注意:
  - 本脚本不会对系统做出任何更改，仅输出提示。
  - 请在实际环境中手工审核、逐步执行真实安装步骤。
USAGE
}

plan_steps() {
  cat <<'PLAN'
[计划] PrivateTunnel WireGuard 服务器安装步骤:
  1. 更新系统并安装 WireGuard（请手动执行 `sudo apt update && sudo apt install wireguard`）。
  2. 生成服务器私钥/公钥，配置 /etc/wireguard/wg0.conf。
  3. 设置防火墙规则与内核转发 (sysctl)。
  4. 配置 systemd 服务并启用 `wg-quick@wg0`。
  5. 验证服务状态并导出客户端配置。
PLAN
}

scaffold_structure() {
  cat <<'SCAFFOLD'
[脚手架] 将创建以下路径（请手动确认创建操作）:
  - /etc/wireguard/
  - /var/lib/privatetunnel/backups/
  - /var/log/privatetunnel/

[脚手架] 请使用 core/generate_wg_conf.py 根据 JSON 配置生成 wg0.conf，并手动复制到 /etc/wireguard/
SCAFFOLD
}

main() {
  if [[ $# -eq 0 ]]; then
    show_help
    exit 0
  fi

  case "$1" in
    --help|-h)
      show_help
      ;;
    plan)
      plan_steps
      ;;
    scaffold)
      scaffold_structure
      ;;
    *)
      echo "[错误] 未知命令: $1" >&2
      echo "使用 --help 查看可用命令" >&2
      exit 1
      ;;
  esac
}

main "$@"
