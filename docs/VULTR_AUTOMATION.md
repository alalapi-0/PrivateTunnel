# 使用 Vultr API 自动开通 WireGuard 节点

本文介绍如何利用 `scripts/vultr_provision.py` 调用 Vultr API v2，自动创建 VPS 并为 PrivateTunnel 的服务器脚本做好准备。脚本仅依赖 Python 标准库，可直接在大多数 macOS/Linux 环境运行。

## 前置条件

- 有效的 Vultr 账号与 API Token。进入 [Vultr 控制台](https://my.vultr.com/) → *Account* → *API* 获取或创建 Token。
- 已在 Vultr 创建 SSH 公钥（`Products → SSH Keys`），并记下对应的 `SSH Key ID`。
- 本地安装 `python3`、`ssh`、`rsync`。
- 克隆仓库，并确保 `server/provision` 目录完整保留。

## 环境变量

脚本通过环境变量读取敏感信息，避免写入磁盘：

```bash
export VULTR_API_TOKEN="your-token-here"
```

建议在 Shell Session 内临时导出，或使用密码管理器/CI Secret 注入。

## 基本用法

最常见的流程是：指定地区、套餐、镜像，等待实例启动并检测 SSH，就绪后同步仓库自带的 WireGuard 部署脚本。

```bash
python scripts/vultr_provision.py \
  --region "sgp" \
  --plan "vc2-1c-1gb" \
  --os-id 2136 \
  --label "private-tunnel-node" \
  --ssh-key-id "01234567-89ab-cdef-0123-456789abcdef" \
  --wait-ssh \
  --sync-provision
```

参数说明：

- `--region`、`--plan`：参考 [Vultr 官方文档](https://www.vultr.com/api/) 选择地区及套餐代码。
- `--os-id`：常用的 64 位 Ubuntu LTS 是 `2136`（随 Vultr 更新可能变化）。
- `--ssh-key-id`：重复多次可注入多个公钥。也可改用 `--image-id`、`--app-id`。
- `--wait-ssh`：轮询 SSH 端口，确保系统完成初始化。
- `--sync-provision`：使用 `rsync` 将 `server/provision` 同步到远端主机（默认存放于 `~/private-tunnel/server/provision`）。

命令执行成功后会输出实例 ID 与公网 IPv4 地址。若同步完成，即可 SSH 登录并运行 `wg-install.sh`。

## 其他选项

- `--user-data-file path/to/file`：上传 cloud-init/user-data，在实例首次启动时自动执行（可填充自动安装脚本、配置 `WG_ENDPOINT` 等）。
- `--enable-ipv6`、`--enable-private-network`、`--vpc-id`：根据 Vultr 项目设置启用 IPv6、私有网络或 VPC。
- `--firewall-group-id`、`--tag`、`--hostname`、`--label`：自定义实例标签，方便在控制台识别。
- `--remote-path`、`--local-path`、`--ssh-user`、`--ssh-port`：自定义同步路径、账号及端口。
- `--rsync-arg`：向 rsync 传入额外参数（重复使用以追加多个参数）。

完整参数列表可通过 `python scripts/vultr_provision.py --help` 查看。

## 常见变量与注意事项

- **API Token**：只通过环境变量传递；不要写入脚本或仓库。
- **SSH Key**：必须在 Vultr 端预先创建，脚本只负责引用其 ID。
- **VPS 配额**：确保 Vultr 账户余额与配额充足，避免 API 返回 503/412 等错误。
- **计费提醒**：脚本创建的实例会立即计费，完成测试后记得在 Vultr 控制台或通过 API 删除。

## 下一步自动化

当实例就绪并复制了 `server/provision` 后，可使用现有脚本继续自动化：

```bash
ssh root@<instance-ip> "cd ~/private-tunnel/server/provision && sudo ./wg-install.sh --yes"
```

也可以在 `--user-data-file` 中嵌入 cloud-init，实现无人值守的 WireGuard 安装。至此，即完成“创建 Vultr 实例 → WireGuard 配置脚本”的自动化闭环。
