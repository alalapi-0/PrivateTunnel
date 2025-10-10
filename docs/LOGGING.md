# Logging & Diagnostics

## Log Levels

Both the iOS Network Extension and the server components use a common four-level
scheme:

- `INFO` – Lifecycle events (connect, disconnect, health pass).
- `WARN` – Transient issues (retries, whitelist reminders, client port changes).
- `ERROR` – Failures requiring user intervention (configuration errors, MTU/TUN
  write failures).
- `SECURITY` – Sensitive or security-relevant events (kill switch changes,
  audit checkpoints, potential tampering).

Event codes follow the `EVT_*`, `ERR_*`, or `SEC_*` naming used in
`PacketTunnelProvider/Logger.swift` and `toy_tun_gateway.py`.

## iOS Diagnostics

- The container app mirrors extension logs via `TunnelManager` and stores them
  in a `LogRingBuffer` (500 entries by default).
- Tapping **导出诊断包** prompts the user, then collects:
  - Recent extension events (redacted by the extension).
  - Container events (connect/disconnect UI actions).
  - A redacted copy of the active configuration (`DiagnosticsRedactor`).
  - Environment metadata (app version, device model, iOS version).
- The exporter writes a ZIP archive (FileManager `zipItem`) into the temporary
  directory and opens the iOS share sheet. Private keys, tokens and endpoint
  hostnames are masked (first two characters + TLD only).

## Server Logging

- `toy_tun_gateway.py` uses Python `logging` and supports:
  - `--log-file` (default `/var/log/private-tunnel/toy-gateway.log`)
  - `--log-level INFO|WARN|ERROR|DEBUG`
  - `--syslog` for `/dev/log`
- Security events include client source changes, invalid frames and PONG
  timeouts.
- `server/security/logrotate/toy-gateway` rotates the log daily, keeping seven
  compressed copies. The WireGuard example exports `journalctl` output weekly.
- Journald persistence defaults live in
  `server/security/journald/20-private-tunnel.conf`.

## Redaction

| Data Type                | Redaction Rule                                |
|--------------------------|-----------------------------------------------|
| Private/Public Keys      | `***KEY_REDACTED***`                          |
| Tokens/Authorization     | `<PREFIX> ***TOKEN***`                        |
| Endpoint Hostnames       | First 2 characters preserved, rest `*`, keep TLD |
| IPv4 Addresses           | Mask first two octets `***.***.X.Y`           |
| File Paths               | Only the filename retained                    |

Rules are implemented in both Swift (`Security/Redactor.swift` and
`Diagnostics/DiagnosticsRedactor.swift`) and Python (`server/security/redact.py`).
Unit tests live alongside each implementation.

## Optional Upload Placeholder

For automated collection, operators may copy the exported ZIP or redacted logs
into `/tmp/diag.zip` before transferring them to secure storage (S3/WebDAV).
Network uploads are intentionally omitted to avoid introducing third-party
dependencies. Ensure any manual upload respects the privacy constraints in
`docs/PRIVACY.md`.
