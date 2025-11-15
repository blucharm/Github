#!/bin/sh
# =============================================================================
# OPENVPN VPS SETUP - PATCHED FOR OpenWrt 24.10.4
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

# fallback to any non-loopback IPv4 if above returned empty
if [ -z "$VPS_IP" ]; then
    VPS_IP=$(ip -4 addr show | awk '/inet/ {print $2}' | cut -d'/' -f1 | grep -v '^127\.' | head -n1 || true)
fi

# Trim CR/LF and spaces just in case
VPS_IP=$(echo "$VPS_IP" | tr -d '\r' | awk '{print $1}')

if [ -z "$VPS_IP" ]; then
    echo "⚠ WARNING: VPS IP could not be auto-detected (empty)."
    echo "   Will try UCI 'network.wan' fallback when creating client config."
fi

# Detect gateway
VPS_GATEWAY=$(ip route | awk '/default/ {print $3; exit}' || true)

# Detect active interface used for outbound
ACTIVE_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk -F"dev " '{ if (NF>1) print $2 }' | awk '{print $1; exit}' || true)
if [ -z "$ACTIVE_IFACE" ]; then
    ACTIVE_IFACE=$(ip -o -4 addr show | awk '{print $2}' | grep -v lo | head -n1 || true)
fi

# Determine a LAN bridge iface fallback (if present)
if ip link show br-lan >/dev/null 2>&1; then
    BR_IFACE="br-lan"
else
    BR_IFACE="$ACTIVE_IFACE"
fi

# OpenVPN config
OVPN_SERVER_PORT="1194"
OVPN_SERVER_SUBNET="10.9.0.0"
DNS_UPSTREAM="${DNS_UPSTREAM:-1.1.1.1}"

echo "📊 Configuration:"
echo "   VPS IP:       ${VPS_IP:-<not-detected>}"
echo "   Gateway:      $VPS_GATEWAY"
echo "   Interface:    $ACTIVE_IFACE"
echo "   Bridge iface: $BR_IFACE"
echo "   VPN Subnet:   $OVPN_SERVER_SUBNET/24"
echo "   VPN Port:     $OVPN_SERVER_PORT"
echo "   DNS:          $DNS_UPSTREAM"
echo ""
read -p "Press ENTER to continue or Ctrl+C to abort..."

# ==================== 1. INSTALL PACKAGES (OpenWrt 24.10.4 recommended) ====================
echo ""
echo "==> [1/10] Installing recommended packages for OpenWrt 24.10.4..."
opkg update
# Recommended packages: openvpn-openssl, openvpn-easy-rsa (or easy-rsa), uhttpd, luci, luci-app-openvpn, nft/iptables modules
opkg install luci luci-ssl uhttpd luci-app-openvpn \
    openvpn-openssl openvpn-easy-rsa openssl-util \
    ip-full iptables-nft kmod-nft-nat kmod-tun \
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

# Try to find easyrsa binary (packages differ; openvpn-easy-rsa provides easyrsa)
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

# UCI config
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

# ==================== 7. FIREWALL CONFIG ====================
echo "==> [7/10] Configuring firewall..."
cp /etc/config/firewall /etc/config/firewall.backup 2>/dev/null || true
WAN_EXISTS=$(uci show firewall 2>/dev/null | grep -c "zone.*wan" || echo "0")

if [ "$WAN_EXISTS" -eq 0 ]; then
    cat > /etc/config/firewall <<EOF
config defaults
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option synflood_protect '1'

config zone
	option name 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option masq '1'
	list network 'lan'

config zone
	option name 'vpnserver'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option masq '1'
	list network 'vpnserver'

config forwarding
	option src 'vpnserver'
	option dest 'lan'

config rule
	option name 'Allow-SSH'
	option src 'lan'
	option proto 'tcp'
	option dest_port '22'
	option target 'ACCEPT'

config rule
	option name 'Allow-HTTP'
	option src 'lan'
	option proto 'tcp'
	option dest_port '80'
	option target 'ACCEPT'

config rule
	option name 'Allow-HTTPS'
	option src 'lan'
	option proto 'tcp'
	option dest_port '443'
	option target 'ACCEPT'

config rule
	option name 'Allow-OpenVPN'
	option src 'lan'
	option proto 'udp'
	option dest_port '$OVPN_SERVER_PORT'
	option target 'ACCEPT'
EOF
else
    cat > /etc/config/firewall <<EOF
config defaults
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option synflood_protect '1'

config zone
	option name 'wan'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'
	list network 'wan'

config zone
	option name 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	list network 'lan'

config zone
	option name 'vpnserver'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option masq '1'
	list network 'vpnserver'

config forwarding
	option src 'lan'
	option dest 'wan'

config forwarding
	option src 'vpnserver'
	option dest 'wan'

config rule
	option name 'Allow-SSH'
	option src 'wan'
	option proto 'tcp'
	option dest_port '22'
	option target 'ACCEPT'

config rule
	option name 'Allow-HTTP'
	option src 'wan'
	option proto 'tcp'
	option dest_port '80'
	option target 'ACCEPT'

config rule
	option name 'Allow-HTTPS'
	option src 'wan'
	option proto 'tcp'
	option dest_port '443'
	option target 'ACCEPT'

config rule
	option name 'Allow-OpenVPN'
	option src 'wan'
	option proto 'udp'
	option dest_port '$OVPN_SERVER_PORT'
	option target 'ACCEPT'
EOF
fi

# ==================== 8. CUSTOM FIREWALL RULES ====================
echo "==> [8/10] Creating custom firewall rules..."
cat > /etc/firewall.user <<FWUSER
#!/bin/sh
sleep 3

# Use nft if available
if command -v nft >/dev/null 2>&1; then
    nft add table inet fw4 2>/dev/null || true
    nft add chain inet fw4 srcnat { type nat hook postrouting priority 100 \; } 2>/dev/null || true
    nft add chain inet fw4 forward_vpnserver { type filter hook forward priority 0 \; } 2>/dev/null || true

    nft add rule inet fw4 srcnat oifname "$BR_IFACE" ip saddr $OVPN_SERVER_SUBNET/24 counter masquerade 2>/dev/null || true
    nft add rule inet fw4 srcnat oifname "$ACTIVE_IFACE" ip saddr $OVPN_SERVER_SUBNET/24 counter masquerade 2>/dev/null || true

    nft add rule inet fw4 forward_vpnserver oifname "$BR_IFACE" counter accept 2>/dev/null || true
    nft add rule inet fw4 forward_vpnserver oifname "$ACTIVE_IFACE" counter accept 2>/dev/null || true
fi

# iptables fallback NAT
if ! command -v nft >/dev/null 2>&1; then
    iptables -t nat -C POSTROUTING -s $OVPN_SERVER_SUBNET/24 -o "$BR_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s $OVPN_SERVER_SUBNET/24 -o "$BR_IFACE" -j MASQUERADE 2>/dev/null || true

    iptables -t nat -C POSTROUTING -s $OVPN_SERVER_SUBNET/24 -o "$ACTIVE_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s $OVPN_SERVER_SUBNET/24 -o "$ACTIVE_IFACE" -j MASQUERADE 2>/dev/null || true
fi

# TTL spoofing (be careful, only add if you need it)
iptables -t mangle -C POSTROUTING -o "$ACTIVE_IFACE" -j TTL --ttl-set 128 2>/dev/null || \
iptables -t mangle -A POSTROUTING -o "$ACTIVE_IFACE" -j TTL --ttl-set 128 2>/dev/null || true

iptables -t mangle -C POSTROUTING -o "$BR_IFACE" -j TTL --ttl-set 128 2>/dev/null || \
iptables -t mangle -A POSTROUTING -o "$BR_IFACE" -j TTL --ttl-set 128 2>/dev/null || true

iptables -t mangle -C POSTROUTING -o tun1 -j TTL --ttl-set 128 2>/dev/null || \
iptables -t mangle -A POSTROUTING -o tun1 -j TTL --ttl-set 128 2>/dev/null || true

# TCP MSS clamp
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null || \
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null || true

# DNS leak protection -- allow only to resolver 10.9.0.1
iptables -C FORWARD -p tcp --dport 53 -j REJECT 2>/dev/null || iptables -I FORWARD -p tcp --dport 53 -j REJECT 2>/dev/null || true
iptables -C FORWARD -p udp --dport 53 -j REJECT 2>/dev/null || iptables -I FORWARD -p udp --dport 53 -j REJECT 2>/dev/null || true

iptables -C FORWARD -s $OVPN_SERVER_SUBNET/24 -d 10.9.0.1 -p tcp --dport 53 -j ACCEPT 2>/dev/null || \
iptables -I FORWARD -s $OVPN_SERVER_SUBNET/24 -d 10.9.0.1 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -C FORWARD -s $OVPN_SERVER_SUBNET/24 -d 10.9.0.1 -p udp --dport 53 -j ACCEPT 2>/dev/null || \
iptables -I FORWARD -s $OVPN_SERVER_SUBNET/24 -d 10.9.0.1 -p udp --dport 53 -j ACCEPT 2>/dev/null || true

logger "OpenVPN custom firewall rules applied"
FWUSER

chmod +x /etc/firewall.user

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

# ==================== 11. GENERATE CLIENT CONFIG (FIXED remote line) ====================
echo "==> Generating client config..."

# If VPS_IP empty, try to get it from UCI network.wan (if available)
if [ -z "$VPS_IP" ]; then
    # try common uci path (may vary). This is a best-effort fallback.
    WAN_IP="$(uci get network.wan.ipaddr 2>/dev/null || true)"
    if [ -n "$WAN_IP" ]; then
        VPS_IP="$WAN_IP"
        echo "Using fallback VPS IP from UCI: $VPS_IP"
    fi
fi

# final guard: ensure values trimmed
VPS_IP=$(echo "$VPS_IP" | tr -d '\r' | awk '{print $1}')
OVPN_SERVER_PORT=$(echo "$OVPN_SERVER_PORT" | tr -d '\r' | awk '{print $1}')

# check certificates/keys exist before writing inline .ovpn
if [ -f /etc/easy-rsa/pki/ca.crt ] && [ -f /etc/easy-rsa/pki/issued/client1.crt ] && [ -f /etc/easy-rsa/pki/private/client1.key ] && [ -f /etc/easy-rsa/pki/ta.key ]; then
    cat > /root/client1.ovpn <<EOF
# OpenVPN Client Config for Windows
client
dev tun
proto udp
# remote line uses explicit variable expansion and fallbacks
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
    echo "   Ensure /etc/easy-rsa/pki/ca.crt, issued/client1.crt, private/client1.key and ta.key exist."
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

# ==================== 13. VERIFICATION (brief) ====================
echo ""
echo "==> Verifying critical items..."
/etc/init.d/openvpn status >/dev/null 2>&1 && echo "  ✓ OpenVPN status ok" || echo "  ⚠ OpenVPN status check failed/unknown"
if [ -f /root/client1.ovpn ]; then
    echo "  ✓ client file present: /root/client1.ovpn"
    echo "  -> remote line:"
    grep '^remote ' /root/client1.ovpn || true
else
    echo "  ✗ client file not present"
fi

echo ""
echo "Done."
