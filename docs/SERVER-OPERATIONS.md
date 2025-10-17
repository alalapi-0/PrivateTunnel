# Server Operations Guide

This guide documents the WireGuard automation scripts shipped in
`server/provision/`. They are designed to provision a new Ubuntu 20.04+/22.04+
or Debian 11/12 host end-to-end, manage peers safely, and expose predictable
artifacts for auditing or rollback.

## Quick Start

1. **Inspect the plan**
   ```bash
   cd server/provision
   sudo bash wg-install.sh --dry-run
   ```
   Review the rendered configuration, sysctl changes, and firewall actions. No
   files are written during a dry run.

2. **Install the server**
   ```bash
   sudo bash wg-install.sh --port 443 --ifname wg0 --wan-if eth0
   ```
   The script installs dependencies, generates `/etc/wireguard/wg0.conf`, enables
   `wg-quick@wg0`, and prints your public key plus connectivity details. Rerun
   the installer at any time—changes are applied idempotently with backups under
   `/etc/wireguard/wg0.conf.bak-*`.

3. **Onboard a client (example: iPhone)**
   ```bash
   sudo bash wg-add-peer.sh --name iphone --qrcode
   ```
   The script creates `/etc/wireguard/clients/iphone/iphone.conf`, appends the
   peer to `wg0.conf`, hot-reloads the interface, and renders an ASCII QR code.
   Open the official WireGuard app on iOS, tap the “+” button, choose *Scan From
   QR Code*, and point it at the terminal output.

## Configuration Model

All scripts obey the same precedence rules when resolving settings:

1. Command-line flag (`--port=443`)
2. `.env` values in `server/provision/.env`
3. Built-in defaults (see `env.example`)

Copy `server/provision/env.example` to `.env` to persist organization-wide
preferences such as `WG_PORT`, `WG_SUBNET`, `WG_SUBNET_V6`, `WG_ENDPOINT`, or
`WG_KEEPALIVE`.

### `wg-install.sh`

| Flag / Env                     | Description |
| ------------------------------ | ----------- |
| `--dry-run`                    | Print actions without touching the system. |
| `--yes`                        | Skip confirmations when replacing existing config. |
| `--port`, `WG_PORT`            | UDP listen port (default `443`). 若该端口被封锁，可改用 `51820` 或其它值。 |
| `--ifname`, `WG_IF`            | WireGuard interface name (default `wg0`). |
| `--wan-if`, `WAN_IF`           | Outbound NIC used for NAT (default `eth0`). |
| `--subnet`, `WG_SUBNET`        | IPv4 tunnel network (default `10.6.0.0/24`). |
| `--subnet6`, `WG_SUBNET_V6`    | Optional IPv6 ULA prefix (e.g. `fd86:ea04:1115::/64`). |
| `--ipv6`/`WG_IPV6`             | Enable IPv6 forwarding and sysctl tuning. Requires `WG_SUBNET_V6`. |
| `--firewall`, `WG_FIREWALL`    | `auto`, `ufw`, `iptables`, or `nftables`. Auto prefers UFW when present. |
| `--wan-if`, `WAN_IF`           | Interface used for NAT masquerade. |
| `--mtu`, `WG_MTU`              | Recommended MTU (displayed in summary). |
| `--dns`, `WG_DNS`              | Default resolver(s) for new peers. |
| `--endpoint`, `WG_ENDPOINT`    | Public endpoint `host:port` embedded in client templates. |

Key behaviours:

- Installs `wireguard`, `qrencode`, and firewall packages as needed.
- Generates `/etc/wireguard/server_private.key` and `server_public.key` with
  `chmod 600`; regenerates only when missing.
- Renders `wg0.conf` from `templates/wg0.conf.template`, backing up the previous
  file to `wg0.conf.bak-YYYYmmdd-HHMMSS` before changes.
- Applies kernel tuning (`net.ipv4.ip_forward=1`, optional IPv6 forwarding,
  BBR congestion control, MTU probing) via `/etc/sysctl.d/99-privatetunnel.conf`.
- Configures NAT/firewall rules:
  - **iptables/auto**: injects PostUp/PostDown commands that add MASQUERADE and
    UDP input rules when the interface comes up.
  - **ufw**: adds `ufw allow <port>/udp` while still using PostUp iptables
    commands for NAT, keeping ufw rule persistence.
  - **nftables**: writes `/etc/wireguard/privatetunnel-nat.nft` and loads it via
    PostUp.
- Enables and restarts `wg-quick@<ifname>` with rollback on failure.
- Detects port conflicts using `ss -lun` and warns if the WAN interface name
  differs from the default.

### `wg-add-peer.sh`

| Flag / Env                         | Description |
| ---------------------------------- | ----------- |
| `--name` *(required)*              | Client identifier (`[A-Za-z0-9_-]+`). |
| `--ip`                             | Force a specific IPv4 address inside `WG_SUBNET`. Accepts bare IP or `/32`. |
| `--dns`, `WG_DNS`                  | Override DNS servers for this peer. |
| `--mtu`, `WG_MTU`                  | Client MTU override (helps with LTE/ISP issues). |
| `--keepalive`, `WG_KEEPALIVE`      | Persistent keepalive in seconds (default `25`). |
| `--allowed-ips`, `WG_ALLOWED_IPS`  | Routes pushed to the client (`0.0.0.0/0, ::/0` by default for full-tunnel). |
| `--ifname`, `WG_IF`                | Interface to modify. |
| `--qrcode`                         | Render QR code via `wg-qrcode.sh`. |
| `--force`                          | Replace existing peer with the same name (prompts unless `--yes`). |
| `--yes`                            | Auto-confirm destructive prompts. |

Behaviour highlights:

- Allocates the next free IPv4 address inside the server subnet by scanning
  `wg0.conf` and existing client configs. Manual `--ip` is validated and refuses
  collisions unless `--force`.
- Generates `private.key` / `public.key` under
  `/etc/wireguard/clients/<name>/`, sets permissions to `600`, and writes the
  rendered client profile to `<name>.conf`.
- Annotates `wg0.conf` with `# Client <name>` comments, backs up the prior file,
  and applies the new peer with `wg addconf` for in-place updates. Errors trigger
  automatic rollback to the backup.
- Summarises key material paths, assigned IP, endpoint, AllowedIPs, and keepalive
  at the end. **Never share the printed private-key path.**

### `wg-list-peers.sh`

- Supports table (`stdout`) or JSON output via `--json`.
- Uses `wg show <ifname> dump` and pretty-prints latest handshake age plus byte
  counters. Handy for monitoring scripts.

### `wg-revoke-peer.sh`

- Removes the peer block (identified by `# Client <name>` or public key) from
  `wg0.conf`, keeping a timestamped backup.
- Runs `wg set <ifname> peer <publickey> remove` to evict the peer from the live
  interface when possible.
- Moves client files to `/etc/wireguard/clients-archive/` by default so you can
  audit or restore later. Pass `--keep-files=false` to delete them permanently.

### `wg-uninstall.sh`

- Stops and disables `wg-quick@<ifname>`.
- Archives the active configuration, client directory, nftables rules, and
  sysctl drop-in under `/etc/wireguard/archive/<timestamp>/` before removal.
- Removes `/etc/sysctl.d/99-privatetunnel.conf` and resets key sysctl values.
- Optional `--purge` flag deletes `/etc/wireguard/clients` after creating a
  compressed archive.

### `wg-qrcode.sh`

- Converts any WireGuard config into a QR code. Default output is UTF-8 ASCII in
  the terminal; `--png` writes `<client>.png` alongside the config.

## Troubleshooting & FAQ

**UDP port appears blocked**
- `wg-install.sh` warns when `ss -lun` shows an existing listener. Either stop
  the conflicting service or rerun with `--port 443` (commonly open even on
  restrictive clouds).
- Remember to open the UDP port in your cloud provider’s firewall or security
  group. Many providers block UDP by default.

**Clients connect but no traffic flows**
- Ensure the correct WAN interface is specified. If the installer warns that
  `eth0` was not found, rerun with `--wan-if <actual-interface>`.
- Verify NAT rules were applied: `sudo wg show` followed by
  `sudo iptables -t nat -L -n | grep MASQUERADE` should include the WireGuard
  subnet.

**Latest handshake is `never`**
- Confirm the client imported the correct configuration (private key must match
  the generated file).
- Check that UDP traffic is not filtered by a corporate firewall or hotel Wi-Fi.
  TCP-only environments may require re-running the installer with `--port 443`.

**MTU/packet loss issues**
- Mobile networks often require a lower MTU (1380 or 1280). Regenerate the client
  with `wg-add-peer.sh --name <device> --mtu 1380` or edit the config manually.

**IPv6 considerations**
- Set `WG_SUBNET_V6` in `.env` and run `wg-install.sh --ipv6=true` to enable
  dual-stack tunnels. Clients will automatically receive `AllowedIPs` covering
  IPv6 if configured in `.env` (default remains IPv4-only until custom templates
  are provided).
- When IPv6 is unnecessary, keep `--ipv6=false` to avoid accidental leaks.

**Rolling back**
- Every change to `wg0.conf` creates `wg0.conf.bak-YYYYmmdd-HHMMSS`. To roll
  back, stop the service, copy a backup over `/etc/wireguard/wg0.conf`, and
  restart `wg-quick@wg0`.
- `wg-uninstall.sh` performs a structured teardown and records backups under
  `/etc/wireguard/archive/`—ideal before decommissioning a server.

## Security Best Practices

- **Key handling**: Private keys (`/etc/wireguard/server_private.key` and
  `/etc/wireguard/clients/*/private.key`) are `chmod 600` and owned by root. Do
  not email or paste them into chat tools. Use QR codes for air-gapped transfer.
- **DNS & WebRTC leaks**: Clients default to full-tunnel `AllowedIPs = 0.0.0.0/0,
  ::/0` and a configurable DNS resolver. Instruct users to disable WebRTC in
  browsers (via settings or extensions) and avoid ISP DoH resolvers that might
  bypass the tunnel.
- **Kill switch**: Encourage clients to enable “On-Demand” / “Block connections
  outside the tunnel” features in their WireGuard apps or enforce firewall rules
  on desktops so traffic drops if the tunnel falls.
- **Update hygiene**: Re-run `wg-install.sh` after system upgrades; it is safe to
  execute repeatedly and will only modify files when the rendered output changes.

## Operational Notes

- Use `wg-list-peers.sh --json` to integrate with monitoring dashboards, alerting
  when a device has not handshaked recently or bandwidth spikes.
- `server/split/` is reserved for advanced split-tunnelling logic scheduled for
  Round 8.
- Journal review: `journalctl -u wg-quick@wg0 --since "1 hour ago"` is the
  fastest way to inspect interface events.

With these scripts and practices, you can provision WireGuard hosts quickly,
maintain consistent backups, and give end-users a smooth onboarding experience.
