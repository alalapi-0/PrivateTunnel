# Privacy & Data Minimisation

## Default Behaviour

- PrivateTunnel does **not** collect session metadata, payload data or analytics
  by default. The iOS app stores WireGuard profiles locally using the Keychain
  for private keys.
- The Packet Tunnel extension only logs operational events; sensitive fields are
  redacted before reaching the system log or the container app.
- Server-side scripts focus on health and security; no traffic inspection or
  accounting is performed.

## Diagnostics Export

- Users may opt to export a diagnostics ZIP from the iOS app. The package
  contains redacted logs, configuration snapshots and device/app metadata needed
  for troubleshooting.
- Private keys, tokens and endpoints are masked; the bundle avoids contact
  lists, messages or other personal data.
- The archive is generated on-device and shared via the standard iOS share
  sheet. Developers are responsible for handling the exported file securely.

## Third-Party Services

- No third-party analytics, crash reporting or remote logging endpoints are
  integrated. Any future upload pipeline must be opt-in and follow the same
  redaction rules.

## Recommendations for Operators

- Limit access to exported diagnostics and server logs to trusted staff.
- Rotate keys periodically and revoke credentials immediately if compromise is
  suspected.
- Document retention periods (e.g. 7–14 days) and delete logs after the window
  expires.
- Monitor your hosting provider's compliance requirements to ensure VPN usage
  aligns with acceptable use policies.
