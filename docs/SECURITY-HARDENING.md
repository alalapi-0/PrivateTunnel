# PrivateTunnel Security Hardening Guide

## Threat Model

PrivateTunnel targets single-user deployments on dedicated VPS hosts or
self-managed home gateways. The primary risks are:

- **Key compromise** – Leakage of WireGuard private keys, API tokens or
  provisioning secrets.
- **Port exposure** – Unrestricted UDP/TCP ports allowing brute-force or DoS.
- **DNS / IPv6 leaks** – Misconfigured routing allowing traffic to escape the
  tunnel.
- **Clock drift** – Unsynchronised time breaking TLS, WireGuard handshakes or
  audit trails.

## Baseline Principles

- Store keys only on the server and the iOS Keychain (never in plain text).
- Lock down `/etc/wireguard`, `server_private.key` and client bundles with
  `700/600` style permissions.
- Expose a predictable set of UDP ports (WireGuard and/or the toy gateway).
- Enforce outbound routing through the tunnel; rely on server-side ipset rules
  for split-mode policies.
- Keep system time accurate with `chronyd` or `systemd-timesyncd`.

## Hardening Steps

The `server/security/harden.sh` helper can apply the minimum baseline. Run with
`--dry-run` first to review the plan:

```bash
sudo bash server/security/harden.sh --dry-run
```

### 1. Apply Kernel Parameters

The script writes `/etc/sysctl.d/90-privatetunnel.conf` with:

- `net.ipv4.ip_forward = 1`
- `net.ipv4.conf.all.rp_filter = 1`
- `net.ipv4.tcp_congestion_control = bbr`
- `net.core.default_qdisc = fq`

Backups are stored as `*.bak.<timestamp>`. Use `sysctl --system` to reload.

### 2. Time Synchronisation

If neither `chronyd` nor `systemd-timesyncd` is active, the script offers to
install `chrony` via `apt-get` or `yum` (honouring `--yes` for automation).

### 3. Logging & Rotation

- Creates `/var/log/private-tunnel` with `750` permissions.
- Symlinks logrotate examples (`toy-gateway`, `wireguard`) into
  `/etc/logrotate.d/`.
- Provides a journald drop-in at
  `server/security/journald/20-private-tunnel.conf` to persist logs with
  sensible size limits.

### 4. Firewall Hints

The script prints suggested `ufw` rules and points to
`server/security/firewall/README.md` for nftables templates. Review and adapt to
match your upstream provider.

## Auditing & Rollback

- Run `server/security/audit.sh` to verify configuration and obtain an A/B/C
  grade. Use `--json` for CI pipelines.
- Revert kernel changes by restoring the backup file and rerunning
  `sysctl --system`.
- Disable chrony with `systemctl disable --now chronyd` if required.
- Remove logrotate symlinks from `/etc/logrotate.d/` to stop rotation.

## Enterprise / Special Cases

- Enterprise signing profiles or jailbroken devices weaken key protection—avoid
  unless you control the entire chain of custody.
- Always deliver updated profiles via secure channels; revocation/rotation is
  not automated.
- For fleets or multi-tenant deployments, integrate with a configuration
  manager (Ansible, Terraform) and apply additional hardening (intrusion
  detection, patch management, monitoring).
