# Round 8 — Domain Split Routing with ipset/nftables

This guide documents the server automation and iOS client workflow for the
"only specific domains should exit via the tunnel" scenario. The key principle
is to keep the client configuration simple (still routing `0.0.0.0/0` into the
WireGuard tunnel) while letting the server decide which destinations deserve
NAT and public egress.

```
┌─────────────┐     ┌──────────────────────┐     ┌────────────────────────┐
│ iOS Client  │====>│ WireGuard Server     │====>│ Public Internet         │
│ AllowedIPs: │     │ pt_split_v4 ipset    │     │ (only split domains)    │
│ 0.0.0.0/0   │     │ └─ NAT when dst ∈ set│     │                          │
└─────────────┘     └──────────────────────┘     └────────────────────────┘
                         ↑            │
                         └────────────┴─> Non-split traffic never leaves,
                                          packets keep private RFC1918 source
```

## Repository layout

```
server/split/
├── domains.yaml           # Domain groups to proxy
├── resolve_domains.py     # Resolves domains into A/AAAA + CIDR state
├── ipset_apply.sh         # Apply CIDRs to ipset + iptables
├── nft_apply.sh           # nftables equivalent helper
├── cron-install.sh        # Install/remove systemd timer
└── state/
    ├── cidr.txt           # Latest collapsed IPv4 CIDRs
    ├── resolved.json      # Verbose resolution result + diagnostics
    └── ipset.snapshot     # Saved ipset (and nft.snapshot for nftables)
```

The scripts are idempotent and safe to run repeatedly. Failed lookups are
reported but never clear the currently active ipset/nftables set, preventing
traffic outages due to transient DNS issues.

## 1. Populate `domains.yaml`

Edit `server/split/domains.yaml` to organise domains into logical groups.
Comment out groups that should stay inactive; the resolver only consumes
non-empty lists. Options include:

- `resolvers`: ordered list of DNS resolvers for `dig`. When empty, the system
  resolver is used.
- `resolve_ipv6`: set to `true` to record AAAA answers (stored in
  `resolved.json` but not yet pushed to ipset).
- `min_ttl_sec` and `max_workers`: guidance for scheduling and parallelism.

## 2. Resolve domains into state files

Run the resolver manually on first deployment:

```bash
cd server/split
python3 resolve_domains.py --log-level INFO
```

Outputs:

- `state/resolved.json`: Per-domain breakdown (IPv4, IPv6, TTL, resolver used,
  errors). Review this file when debugging DNS changes.
- `state/cidr.txt`: Collapsed IPv4 CIDR list suitable for ipset/nftables. Each
  run rewrites the file with a timestamp header so it can be inspected or
  version controlled if desired.

> Tip: `--groups openai,github` resolves a subset of groups, making staged
> rollouts easy during maintenance windows.

## 3. Apply to ipset/iptables (default backend)

```bash
sudo bash ipset_apply.sh --apply --wan-if eth0 --wg-cidr 10.6.0.0/24
```

The script performs:

1. `ipset save pt_split_v4 > state/ipset.snapshot` (rollback safety).
2. Atomic refresh of the `pt_split_v4` set using a temporary hash:net set.
3. Ensures a single `iptables -t nat -A POSTROUTING ... -m set --match-set
   pt_split_v4 dst -j MASQUERADE` rule exists. Supply `WAN_IF` and `WG_CLIENT_CIDR`
   via CLI arguments or environment variables (also compatible with
   `/etc/privatetunnel/split.env`).

### Rollback

If a bad resolution caused unwanted behaviour:

```bash
sudo bash ipset_apply.sh --rollback
```

The snapshot is restored immediately. You can also edit `state/cidr.txt` and
re-run `--apply` to enforce a hotfix.

### nftables users

If the host already migrated to nftables, use:

```bash
sudo bash nft_apply.sh --apply --wan-if eth0 --wg-cidr 10.6.0.0/24
```

The helper maintains `table inet pt_split`, set `pt_split_v4`, and a NAT
`postrouting` chain with `masquerade` bound to the same domain list. Snapshot
restoration uses `state/nft.snapshot`.

## 4. Automate refreshes via systemd timer

```bash
sudo bash cron-install.sh --install --backend ipset
```

The timer executes the resolver + backend every 10 minutes with a 2-minute
post-boot delay. Adjust cadence by editing the generated timer under
`/etc/systemd/system/pt-split-resolver.timer`.

To inspect or remove:

```bash
sudo bash cron-install.sh --status
sudo bash cron-install.sh --remove
```

Environment overrides (interfaces, CIDRs, alternative resolvers) can be stored
in `/etc/privatetunnel/split.env`:

```
WAN_IF=eth0
WG_CLIENT_CIDR=10.6.0.0/24
PYTHONUNBUFFERED=1
```

## 5. Verifying behaviour

1. Confirm the ipset contents: `sudo ipset list pt_split_v4` or
   `sudo nft list set inet pt_split pt_split_v4`.
2. Monitor NAT hits: `sudo iptables -t nat -L POSTROUTING -v` or
   `sudo nft list chain inet pt_split postrouting -n`.
3. From a connected client in **Whitelist** mode, visit a known split domain
   (e.g., `api.openai.com`) and a non-split domain. The latter should fail to
   reach the Internet because the server returns packets without masquerading.

## 6. Integrating with existing provisioning

`server/provision/wg-install.sh` continues to configure WireGuard with global
`AllowedIPs`. When enabling split routing:

- Export `WAN_IF` and `WG_CLIENT_CIDR` according to your deployment before
  running `ipset_apply.sh`.
- Ensure the WireGuard interface (default `wg0`) is allowed to forward traffic
  via the host firewall. No additional routing table changes are needed; the
  lack of SNAT for non-whitelisted destinations prevents egress automatically.

## 7. Optional: pushing precise `AllowedIPs`

This iteration keeps iOS clients simple by still routing `0.0.0.0/0` through
WireGuard. Advanced setups may prefer to distribute the resolved CIDR list to
clients as `AllowedIPs`. To experiment:

1. Take `state/cidr.txt` and inject the CIDRs into client config generation.
2. Update the iOS app (or other clients) to refresh configuration when the
   list changes—note that the iOS Network Extension requires disconnect/reconnect
   to apply new AllowedIPs.
3. Maintain a secure channel for distributing updates (e.g., MDM or config
   management). This path offers less centralised control and is therefore kept
   optional.

## 8. Troubleshooting

- **DNS failed / domain missing**: Check `state/resolved.json` and the resolver
  logs (`python3 resolve_domains.py --log-level DEBUG`). The script never deletes
  the active ipset on failure; you can re-run later without downtime.
- **iptables rule missing**: Export `WAN_IF`/`WG_CLIENT_CIDR` or edit
  `/etc/privatetunnel/split.env`, then re-run `ipset_apply.sh --apply`.
- **Timer not firing**: `sudo systemctl list-timers pt-split-resolver.timer` to
  inspect schedule; ensure the timer is `enabled` and the service path matches
  the repository location.
- **Unexpected traffic leak**: Validate that the ipset only contains the desired
  networks. Remove suspicious entries from `state/cidr.txt` and re-apply.
- **IPv6**: AAAA records are captured in `resolved.json` but not yet enforced.
  Extend `ipset_apply.sh` / `nft_apply.sh` with IPv6 sets when your server
  supports IPv6 routing and NAT66.

## 9. Client UX notes

The iOS container app exposes a **Global** / **Whitelist** toggle. In whitelist
mode the app keeps `AllowedIPs=0.0.0.0/0` so Round 7's health checker and kill
switch continue to function unchanged. The Network Extension emits explicit log
messages when whitelist mode is active and suggests falling back to Global if
connectivity probes fail repeatedly.

Refer back to this guide whenever adjusting domain groups or when onboarding a
new server. The scripts are purposefully self-contained and avoid third-party
Python dependencies, simplifying maintenance on constrained VPS hosts.
