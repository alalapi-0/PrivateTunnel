# Round 7 – Health Check, Auto Reconnect & Kill Switch

Round 7 introduces an end-to-end health monitoring pipeline across the iOS
Network Extension, the container app, and server-side watchdog scripts. The
mechanism works with the Round 6 toy UDP/TUN engine today and will be shared by
future WireGuard integrations.

## Health Check Strategy

The PacketTunnel extension runs `HealthChecker`, which evaluates the tunnel
according to three concurrent probes (success of any probe marks the tunnel as
healthy):

1. **UDP ping** – Uses the engine's `sendPing()` to send a Toy frame and waits
   for a pong. WireGuard engines can implement this by checking keepalive or
   handshake timestamps.
2. **HTTPS probe** – Performs an HTTP GET against `https://1.1.1.1/cdn-cgi/trace`
   and `https://api.openai.com/robots.txt` (configurable via
   `providerConfiguration`). Only TLS handshake and a 2xx/3xx response are
   required; the body is discarded.
3. **DNS resolution** – Resolves `api.openai.com` via the tunnel's DNS servers
   using `getaddrinfo`.

Thresholds (also configurable via `providerConfiguration`):

- `probeIntervalSec` (default 10 seconds)
- `failThreshold` (default 3 consecutive failures trigger reconnect)
- `successThreshold` (default 2 consecutive successes restore "healthy")

Every probe updates a snapshot exposed to the container app via
`sendProviderMessage`. Transitions to *healthy* emit `EVT_HEALTH_PASS`, while
transitions to *unhealthy* emit `EVT_HEALTH_FAIL` and kick off the backoff
sequence.

## Automatic Reconnect & Backoff

When health is deemed unhealthy, the extension:

1. Pauses the health checker.
2. Stops the engine and (if enabled) engages the kill switch to drop in-flight
   packets.
3. Schedules a reconnect using an exponential backoff policy starting at two
   seconds (base 2, max 60 seconds) with 0–20% jitter.
4. After the delay the engine restarts and health probes resume. When success is
   detected, the backoff counter resets.

Reconnect statistics (attempt count, last attempt timestamp, pending retry) are
returned to the container app for display.

## Kill Switch Behaviour

iOS lacks a system-wide firewall API, so the project implements a **soft** kill
switch:

- When enabled in the configuration, the PacketTunnel provider pauses
  `NEPacketTunnelFlow` traffic by instructing the engine to drop packets while a
  reconnect is in progress.
- The container app surfaces a banner and suggests enabling Airplane Mode or
  manually disabling Wi-Fi/cellular if a full system-level kill switch is
  required.
- Disabling the kill switch immediately resumes packet forwarding.

> **Important:** True OS-wide kill switch capabilities require Apple-managed
> configurations (e.g. supervised devices/MDM). This project cannot guarantee
> zero leakage outside the tunnel.

## Server-Side Watchdogs

The new `server/watchdog` directory contains:

- `endpoint_probe.sh` – Cron/systemd-timer friendly script that verifies ICMP and
  HTTPS reachability and optionally restarts the gateway process.
- `toy-watchdog.service` – systemd unit that restarts `toy_tun_gateway.py` when
  it crashes.
- `wg-watchdog.service` – Placeholder for WireGuard deployment. Replace the
  `ExecStart` once the WireGuard engine lands.

These tools complement the client probes by ensuring the VPS uplink remains
stable.

## Testing & Troubleshooting

1. Deploy the toy gateway (Round 6) and launch the iOS client.
2. Observe health snapshots in the container app (updated every ~5 seconds).
3. Stop `toy_tun_gateway.py` on the server. The iOS UI should transition from
   Healthy → Probing → Unhealthy, engage the kill switch (if enabled), and begin
   exponential backoff retries (2s, 4s, 8s...).
4. Restart the gateway. After consecutive successful probes the tunnel returns
   to Healthy, the kill switch disengages, and the backoff counter resets.

If probes continuously fail:

- Confirm the VPS can reach upstream hosts using `endpoint_probe.sh`.
- Inspect DNS resolution, MTU settings, and ISP firewall rules.
- Use the event log in the container app to identify failure codes
  (`ERR_PING_TIMEOUT`, `ERR_HTTPS_UNREACHABLE`, `ERR_DNS_FAILURE`).

## Integration with Future WireGuard Engine

`EngineProtocol` defines the interface (`start`, `stop`, `sendPing`, `stats`,
`setTrafficBlocked`) that both the toy engine and the upcoming WireGuard engine
must implement. As long as the new engine reports stats and implements
`sendPing`, the same health/backoff/kill-switch stack will work without further
changes to the provider or the container app.
