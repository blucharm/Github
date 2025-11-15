#!/bin/sh
# =============================================================================
# OPENVPN VPS SETUP - PATCHED FOR OpenWrt 24.10.4 (AUTO-FIX WAN MAPPING + NFT RULES)
# - Auto-detect WAN interface from routing table and ensure UCI network.wan.device
# - Clean/replace /etc/firewall.user with idempotent rules using detected WAN iface
# - Add nft/iptables NAT & forwarding rules for VPN subnet
# =============================================================================

set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║    OPENVPN VPS SETUP - PATCHED FOR OpenWrt 24.10.4    ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# ==================== AUTO-DETECT CONFIGURATION ====================
# Detect VPS IP (prefer public, fallback to first non-loopback)
VPS_IP=$(ip -4 addr show | awk '/inet/ {print $2}' | cut -d'/' -f1 | \
         grep -vE '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' | head -n1 || true)

if [ -z "$VPS_IP" ]; then
    VPS_IP=$(ip -4 addr show | awk '/inet/ {print $2}' | cut -d'/' -f1 | grep -v '^127\.' | head -n1 || true)
fi
VPS_IP=$(echo "$VPS_IP" | tr -d '\r' | awk '{print $1}')

if [ -z "$VPS_IP" ]; then
    echo "⚠ WARNING: VPS IP could not be auto-detected (empty)."
    echo "   Will try UCI 'network.wan' fallback when creating client config."
fi

# Detect gateway and active interface
VPS_GATEWAY=$(ip route | awk '/default/ {print $3; exit}' || true)
ACTIVE_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk -F"dev " '{ if (NF>1) print $2 }' | awk '{print $1; exit}' || true)
if [ -z "$ACTIVE_IFACE" ]; then
    ACTIVE_IFACE=$(ip -o -4 addr show | awk '{print $2}' | grep -v lo | head -n1 || true)
fi

# Determine WAN_IF from default route (this is authoritative)
WAN_IF=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')
WAN_IF=${WAN_IF:-$ACTIVE_IFACE}
# Determine a LAN bridge iface fallback (if present)
if ip link show br-lan >/dev/null 2>&1; then
    BR_IFACE="br-lan"
else
    BR_IFACE="$ACTIVE_IFACE"
fi

# Ensure UCI network.wan.device points to actual WAN_IF (so fw4 regenerates rules correctly)
CURRENT_WAN_DEVICE=$(uci get network.wan.device 2>/dev/null || true)
if [ "$CURRENT_WAN_DEVICE" != "$WAN_IF" ]; then
    echo "⚙ Updating network.wan.device from '$CURRENT_WAN_DEVICE' -> '$WAN_IF'"
    # Use delete then set to ensure no conflicting option device/ifname entries remain
    uci delete network.wan.device 2>/dev/null || true
    uci set network.wan.device="$WAN_IF"
    uci commit network
    /etc/init.d/network reload || true
    # firewall will be restarted later after config updates
fi

# OpenVPN config defaults
OVPN_SERVER_PORT="1194"
OVPN_SERVER_SUBNET="10.9.0.0"
DNS_UPSTREAM="${DNS_UPSTREAM:-1.1.1.1}"

echo "📊 Configuration:"
echo "   VPS IP:       ${VPS_IP:-<not-detected>}"
echo "   Gateway:      $VPS_GATEWAY"
echo "   Interface:    $ACTIVE_IFACE"
echo "   WAN_IF:       $WAN_IF"
echo "   Bridge iface: $BR_IFACE"
echo "   VPN Subnet:   $OVPN_SERVER_SUBNET/24"
echo "   VPN Port:     $OVPN_SERVER_PORT"
echo "   DNS:          $DNS_UPSTREAM"
echo ""
read -p "Press ENTER to continue or Ctrl+C to abort..."

# ==================== 1. INSTALL PACKAGES ====================
echo ""
echo "==> [1/10] Installing recommended packages for OpenWrt 24.10.4..."
opkg update
opkg install luci luci-ssl uhttpd luci-app-openvpn \
    openvpn-openssl openvpn-easy-rsa openssl-util \
    ip-full iptables-nft kmod-nft-nat kmod-tun \
    vpn-policy-routing luci-app-vpn-policy-routing \
    curl ca-certificates || true

# ==================== 2. NETWORK INTERFACES ====================
echo "==> [2/10] Configuring network..."
uci set network.vpnserver=interface
uci set network.vpnserver.proto='none'
uci set network.vpnserver.device='tun1'
uci set network.vpnserver.auto='0'
uci commit network
/etc/init.d/network reload || true

# ==================== 3. PKI & CERTIFICATES ====================
echo "==> [3/10] Setting up PKI..."
mkdir -p /etc/easy-rsa
cd /etc/easy-rsa

EASYRSA_CMD="$(command -v easyrsa || true)"
if [ -z "$EASYRSA_CMD" ] && [ -x /usr/share/easy-rsa/easyrsa ]; then
    EASYRSA_CMD="/usr/share/easy-rsa/easyrsa"
fi

if [ -z "$EASYRSA_CMD" ]; then
    echo "⚠ easyrsa not found. Ensure package openvpn-easy-rsa or easy-rsa is installed."
else
    if [ ! -f /etc/easy-rsa/pki/ca.crt ]; then
        "$EASYRSA_CMD" init-pki
        EASYRSA_BATCH=1 "$EASYRSA_CMD" build-ca nopass
        "$EASYRSA_CMD" gen-dh
        EASYRSA_BATCH=1 "$EASYRSA_CMD" build-server-full server nopass
        EASYRSA_BATCH=1 "$EASYRSA_CMD" build-client-full client1 nopass
        openvpn --genkey secret /etc/easy-rsa/pki/ta.key
    fi
fi
cd /

# ==================== 4. OPENVPN SERVER CONFIG ====================
echo "==> [4/10] Configuring OpenVPN Server..."
mkdir -p /etc/openvpn /var/log

cat > /etc/openvpn/server.conf <<EOF
port $OVPN_SERVER_PORT
proto udp
dev tun1
dev-type tun

ca /etc/easy-rsa/pki/ca.crt
cert /etc/easy-rsa/pki/issued/server.crt
key /etc/easy-rsa/pki/private/server.key
dh /etc/easy-rsa/pki/dh.pem
tls-auth /etc/easy-rsa/pki/ta.key 0

server $OVPN_SERVER_SUBNET 255.255.255.0
topology subnet

push "dhcp-option DNS 10.9.0.1"
push "redirect-gateway def1 bypass-dhcp"
push "block-outside-dns"

cipher AES-128-GCM
auth SHA256
compress lz4-v2
push "compress lz4-v2"

keepalive 10 60
persist-key
persist-tun

sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"

user nobody
group nogroup

status /var/log/openvpn-server-status.log
log-append /var/log/openvpn-server.log
verb 3
mute 10
explicit-exit-notify 1
EOF

uci delete openvpn.server 2>/dev/null || true
uci set openvpn.server=openvpn
uci set openvpn.server.enabled='1'
uci set openvpn.server.config='/etc/openvpn/server.conf'
uci commit openvpn

# ==================== 5. SSL CERTIFICATE FOR UHTTPD ====================
echo "==> [5/10] Generating SSL certificate..."
mkdir -p /etc/uhttpd/certs
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/uhttpd/certs/luci.key \
    -out /etc/uhttpd/certs/luci.crt \
    -subj "/CN=${VPS_IP:-localhost}" 2>/dev/null || true

# ==================== 6. CONFIGURE UHTTPD ====================
echo "==> [6/10] Configuring uhttpd..."
uci delete uhttpd.main.listen_http 2>/dev/null || true
uci delete uhttpd.main.listen_https 2>/dev/null || true
uci add_list uhttpd.main.listen_http="0.0.0.0:80"
uci add_list uhttpd.main.listen_https="0.0.0.0:443"
uci set uhttpd.main.cert='/etc/uhttpd/certs/luci.crt'
uci set uhttpd.main.key='/etc/uhttpd/certs/luci.key'
uci set uhttpd.main.rfc1918_filter='0'
uci set uhttpd.main.script_timeout='30'
uci set uhttpd.main.network_timeout='10'
uci set uhttpd.main.no_ipv6='1' 2>/dev/null || true
uci delete uhttpd.main.redirect_https 2>/dev/null || true
uci commit uhttpd

# ==================== 7. FIREWALL CONFIG (UCI) ====================
echo "==> [7/10] Configuring firewall..."
cp /etc/config/firewall /etc/config/firewall.backup 2>/dev/null || true

# Ensure vpnserver zone exists and forwards to wan
if ! uci show firewall.@zone 2>/dev/null | grep -q "vpnserver"; then
    uci add firewall zone
    uci set firewall.@zone[-1].name='vpnserver'
    uci set firewall.@zone[-1].input='ACCEPT'
    uci set firewall.@zone[-1].output='ACCEPT'
    uci set firewall.@zone[-1].forward='REJECT'
    uci add_list firewall.@zone[-1].network='vpnserver'
    uci set firewall.@zone[-1].masq='1'
fi

# Ensure forwarding vpnserver -> wan exists
if ! uci show firewall.@forwarding 2>/dev/null | grep -q "src='vpnserver'"; then
    uci add firewall forwarding
    uci set firewall.@forwarding[-1].src='vpnserver'
    uci set firewall.@forwarding[-1].dest='wan'
fi

uci commit firewall

# ==================== 8. CUSTOM FIREWALL RULES (clean, idempotent) ====================
echo "==> [8/10] Creating custom firewall rules..."
cat > /etc/firewall.user <<'FWUSER'
#!/bin/sh
# Custom firewall rules - runs after fw4 initialization
sleep 3

# Detect WAN interface from routing table
WAN_IF="$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')"
WAN_IF="${WAN_IF:-br-lan}"
TUN_IF="tun1"
OVPN_NET="10.9.0.0/24"

# Use nft if available (preferred)
if command -v nft >/dev/null 2>&1; then
    nft add table inet fw4 2>/dev/null || true
    nft add chain inet fw4 srcnat { type nat hook postrouting priority 100 \; } 2>/dev/null || true
    nft add chain inet fw4 forward_vpnserver { type filter hook forward priority 0 \; } 2>/dev/null || true

    # NAT for VPN clients (idempotent: add rule, ignore errors)
    nft add rule inet fw4 srcnat oifname "$WAN_IF" ip saddr $OVPN_NET counter masquerade 2>/dev/null || true

    # Forwarding accept for VPN <-> WAN
    nft add rule inet fw4 forward_vpnserver iifname "$TUN_IF" oifname "$WAN_IF" counter accept 2>/dev/null || true
    nft add rule inet fw4 forward_vpnserver iifname "$WAN_IF" oifname "$TUN_IF" ct state related,established counter accept 2>/dev/null || true
fi

# iptables fallback
if ! command -v nft >/dev/null 2>&1; then
    iptables -t nat -C POSTROUTING -s $OVPN_NET -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s $OVPN_NET -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true

    iptables -C FORWARD -i "$TUN_IF" -o "$WAN_IF" -s $OVPN_NET -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$TUN_IF" -o "$WAN_IF" -s $OVPN_NET -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null || true

    iptables -C FORWARD -i "$WAN_IF" -o "$TUN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$WAN_IF" -o "$TUN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
fi

# Optional: TCP MSS clamp
if command -v iptables >/dev/null 2>&1; then
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null || \
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null || true
fi

logger "OpenVPN custom firewall rules applied"
FWUSER

chmod +x /etc/firewall.user

# Restart firewall so fw4 regenerates using updated network.wan.device
/etc/init.d/firewall restart || true

# ==================== 9. DNS CONFIG ====================
echo "==> [9/10] Configuring DNS..."
cat > /etc/resolv.conf <<EOF
nameserver $DNS_UPSTREAM
nameserver 1.1.1.1
options timeout:1
options attempts:1
EOF

if ! uci get dhcp.@dnsmasq[0] >/dev/null 2>&1; then
    uci add dhcp dnsmasq
fi
uci set dhcp.@dnsmasq[0].noresolv='1'
uci set dhcp.@dnsmasq[0].cachesize='10000'
uci set dhcp.@dnsmasq[0].min_cache_ttl='3600'
uci set dhcp.@dnsmasq[0].localise_queries='1'
uci set dhcp.@dnsmasq[0].rebind_protection='0'
uci delete dhcp.@dnsmasq[0].server 2>/dev/null || true
uci add_list dhcp.@dnsmasq[0].server="$DNS_UPSTREAM"
uci delete dhcp.@dnsmasq[0].interface 2>/dev/null || true
uci add_list dhcp.@dnsmasq[0].interface='tun1'
uci commit dhcp

# ==================== 10. SYSTEM OPTIMIZATIONS ====================
echo "==> [10/10] System optimizations..."
sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true

BBR_AVAILABLE="no"
if [ -f /proc/sys/net/ipv4/tcp_available_congestion_control ]; then
    if grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        BBR_AVAILABLE="yes"
    fi
fi

cat >> /etc/sysctl.conf <<EOF

# OpenVPN optimizations
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_mtu_probing=1
net.core.default_qdisc=fq
net.ipv4.ip_forward=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF

if [ "$BBR_AVAILABLE" = "yes" ]; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
fi
sysctl -p 2>&1 | grep -v "No such file or directory" || true

# ==================== 11. GENERATE CLIENT CONFIG (remote line fixed) ====================
echo "==> Generating client config..."
# Fallback VPS_IP from UCI if undetected
if [ -z "$VPS_IP" ]; then
    WAN_IP="$(uci get network.wan.ipaddr 2>/dev/null || true)"
    if [ -n "$WAN_IP" ]; then
        VPS_IP="$WAN_IP"
        echo "Using fallback VPS IP from UCI: $VPS_IP"
    fi
fi
VPS_IP=$(echo "$VPS_IP" | tr -d '\r' | awk '{print $1}')
OVPN_SERVER_PORT=$(echo "$OVPN_SERVER_PORT" | tr -d '\r' | awk '{print $1}')

if [ -f /etc/easy-rsa/pki/ca.crt ] && [ -f /etc/easy-rsa/pki/issued/client1.crt ] && [ -f /etc/easy-rsa/pki/private/client1.key ] && [ -f /etc/easy-rsa/pki/ta.key ]; then
    cat > /root/client1.ovpn <<EOF
# OpenVPN Client Config for Windows
client
dev tun
proto udp
remote ${VPS_IP:-127.0.0.1} ${OVPN_SERVER_PORT:-1194}
resolv-retry infinite
nobind
persist-key
persist-tun

cipher AES-128-GCM
auth SHA256
compress lz4-v2
sndbuf 393216
rcvbuf 393216

remote-cert-tls server
key-direction 1
block-outside-dns

verb 3
mute 10

<ca>
$(cat /etc/easy-rsa/pki/ca.crt)
</ca>

<cert>
$(cat /etc/easy-rsa/pki/issued/client1.crt)
</cert>

<key>
$(cat /etc/easy-rsa/pki/private/client1.key)
</key>

<tls-auth>
$(cat /etc/easy-rsa/pki/ta.key)
</tls-auth>
EOF
    chmod 600 /root/client1.ovpn
    echo "✓ /root/client1.ovpn generated. Check 'remote' entry:"
    grep -n '^remote ' /root/client1.ovpn || true
else
    echo "⚠ Client certificate/key files missing, skipping /root/client1.ovpn generation."
fi

# ==================== 12. START SERVICES ====================
echo ""
echo "==> Starting services..."
/etc/init.d/uhttpd restart || true
/etc/init.d/openvpn enable || true
/etc/init.d/openvpn restart || true
/etc/init.d/dnsmasq restart || true
/etc/init.d/firewall restart || true

sleep 3
if [ -x /etc/firewall.user ]; then
    /etc/firewall.user || true
fi

sleep 2

# ==================== 13. VERIFICATION ====================
echo ""
echo "==> Verifying setup..."
/etc/init.d/openvpn status >/dev/null 2>&1 && echo "  ✓ OpenVPN running" || echo "  ✗ OpenVPN failed"
/etc/init.d/uhttpd status >/dev/null 2>&1 && echo "  ✓ uhttpd running" || echo "  ✗ uhttpd failed"
ip addr show tun1 >/dev/null 2>&1 && echo "  ✓ tun1 interface UP" || echo "  ✗ tun1 interface DOWN"

# Check nft NAT rules presence
RULES_COUNT=0
if command -v nft >/dev/null 2>&1; then
    RULES_COUNT=$(nft list chain inet fw4 srcnat 2>/dev/null | grep -c "$OVPN_SERVER_SUBNET" || echo "0")
fi

if [ "$RULES_COUNT" -ge 1 ]; then
    echo "  ✓ Firewall NAT rules applied ($RULES_COUNT rules)"
else
    echo "  ⚠ Firewall NAT rules not found in srcnat -- check /etc/firewall.user and nft list ruleset"
fi

# Final summary
echo ""
echo "Setup finished at $(date). Please test VPN client internet access. If client still has no internet,"
echo "run: nft list ruleset | sed -n '1,240p'  and paste output here for further analysis."
echo ""
