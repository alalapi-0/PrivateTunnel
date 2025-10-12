#!/bin/bash
set -Eeuo pipefail

LOG_FILE="/root/user-data.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

WG_IFNAME="${WG_IFNAME:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_SUBNET="${WG_SUBNET:-10.6.0.0/24}"
WG_SVR_ADDR="${WG_SVR_ADDR:-10.6.0.1/24}"
CLIENT_NAME="${CLIENT_NAME:-iphone}"
CLIENT_ADDR="${CLIENT_ADDR:-10.6.0.2/32}"
CLIENT_DNS="${CLIENT_DNS:-1.1.1.1}"
KEEPALIVE="${KEEPALIVE:-25}"
AUTHORIZED_SSH_PUBKEY="${AUTHORIZED_SSH_PUBKEY:-}"

log() {
  echo "[user-data] $*"
}

log "Starting WireGuard bootstrap"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  wireguard wireguard-tools qrencode iptables-persistent \
  curl git ca-certificates jq iproute2

mkdir -p /root/.ssh
chmod 700 /root/.ssh
if [ -n "$AUTHORIZED_SSH_PUBKEY" ]; then
  if ! grep -qxF "$AUTHORIZED_SSH_PUBKEY" /root/.ssh/authorized_keys 2>/dev/null; then
    log "Installing provided SSH public key"
    printf '%s\n' "$AUTHORIZED_SSH_PUBKEY" >> /root/.ssh/authorized_keys
  fi
fi
chmod 600 /root/.ssh/authorized_keys || true

WAN_IF="$(ip -o -4 route show to default | awk '{print $5}' | head -n1)"
if [ -z "$WAN_IF" ]; then
  echo "No WAN_IF" >&2
  exit 1
fi
log "Detected WAN interface: $WAN_IF"

mkdir -p /etc/wireguard /var/lib/wireguard/clients
chmod 700 /etc/wireguard

SERVER_PRIV_KEY_FILE="/etc/wireguard/server_private.key"
SERVER_PUB_KEY_FILE="/etc/wireguard/server_public.key"
if [ ! -s "$SERVER_PRIV_KEY_FILE" ]; then
  log "Generating server key pair"
  umask 077
  wg genkey | tee "$SERVER_PRIV_KEY_FILE" | wg pubkey > "$SERVER_PUB_KEY_FILE"
else
  log "Reusing existing server key pair"
fi
SERVER_PRIV_KEY="$(cat "$SERVER_PRIV_KEY_FILE")"
SERVER_PUB_KEY="$(cat "$SERVER_PUB_KEY_FILE")"

WG_CONF="/etc/wireguard/${WG_IFNAME}.conf"
cat <<CFG > "$WG_CONF.tmp"
[Interface]
Address = ${WG_SVR_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
SaveConfig = true
CFG
mv "$WG_CONF.tmp" "$WG_CONF"
chmod 600 "$WG_CONF"

log "Applying sysctl and firewall settings"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-privatetunnel.conf
sysctl -p /etc/sysctl.d/99-privatetunnel.conf || true

iptables -t nat -C POSTROUTING -s "${WG_SUBNET}" -o "${WAN_IF}" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "${WG_SUBNET}" -o "${WAN_IF}" -j MASQUERADE
iptables -C FORWARD -i "${WAN_IF}" -o "${WG_IFNAME}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "${WAN_IF}" -o "${WG_IFNAME}" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -i "${WG_IFNAME}" -o "${WAN_IF}" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "${WG_IFNAME}" -o "${WAN_IF}" -j ACCEPT
netfilter-persistent save || true

systemctl enable wg-quick@"${WG_IFNAME}".service
systemctl restart wg-quick@"${WG_IFNAME}".service || systemctl start wg-quick@"${WG_IFNAME}".service

CLIENT_KEY_DIR="/var/lib/wireguard/clients"
CLIENT_PRIV_KEY_FILE="${CLIENT_KEY_DIR}/${CLIENT_NAME}.key"
CLIENT_PUB_KEY_FILE="${CLIENT_KEY_DIR}/${CLIENT_NAME}.pub"
if [ ! -s "$CLIENT_PRIV_KEY_FILE" ]; then
  log "Generating client key pair for ${CLIENT_NAME}"
  umask 077
  wg genkey | tee "$CLIENT_PRIV_KEY_FILE" | wg pubkey > "$CLIENT_PUB_KEY_FILE"
else
  log "Reusing existing client key pair for ${CLIENT_NAME}"
fi
CLIENT_PRIV_KEY="$(cat "$CLIENT_PRIV_KEY_FILE")"
CLIENT_PUB_KEY="$(cat "$CLIENT_PUB_KEY_FILE")"

if ! wg show "${WG_IFNAME}" allowed-ips 2>/dev/null | grep -q "${CLIENT_ADDR}"; then
  log "Adding client peer to WireGuard"
  wg set "${WG_IFNAME}" peer "$CLIENT_PUB_KEY" allowed-ips "$CLIENT_ADDR" persistent-keepalive "$KEEPALIVE"
  wg-quick save "${WG_IFNAME}"
else
  log "Client peer already configured"
fi

PUBLIC_IP="$(ip -o -4 addr show dev "${WAN_IF}" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
if [ -z "$PUBLIC_IP" ]; then
  PUBLIC_IP="$(curl -fsS https://ifconfig.me || true)"
fi
if [ -z "$PUBLIC_IP" ]; then
  log "Warning: unable to determine public IPv4 address automatically; please update client Endpoint manually"
  PUBLIC_IP="0.0.0.0"
fi

CLIENT_CONF="/root/${CLIENT_NAME}.conf"
log "Writing client config for ${CLIENT_NAME} with endpoint ${PUBLIC_IP}:${WG_PORT}"
cat <<CLIENTCFG > "$CLIENT_CONF.tmp"
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_ADDR}
DNS = ${CLIENT_DNS}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${PUBLIC_IP}:${WG_PORT}
PersistentKeepalive = ${KEEPALIVE}
CLIENTCFG
mv "$CLIENT_CONF.tmp" "$CLIENT_CONF"
chmod 600 "$CLIENT_CONF"

PNG_PATH="/root/${CLIENT_NAME}.png"
qrencode -t png -o "$PNG_PATH" < "$CLIENT_CONF"
chmod 600 "$PNG_PATH"

log "Enabling BBR congestion control"
echo "net.core.default_qdisc=fq" > /etc/sysctl.d/99-privatetunnel-bbr.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-privatetunnel-bbr.conf
sysctl -p /etc/sysctl.d/99-privatetunnel-bbr.conf || true

log "[DONE] Ready. PNG at $PNG_PATH"
