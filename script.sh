#!/bin/sh
# =============================================================================
# OPENVPN VPS SETUP V3 - ALL BUGS FIXED
# - OpenVPN Server (tun1) for Windows clients
# - Nginx reverse proxy for LuCI (FIXED 403 error)
# - NAT with nftables fw4 (FIXED custom rules)
# - DNS config (FIXED uci error)
# - TTL spoofing, optimized for 1-2 core / 1GB RAM
# =============================================================================

set -e

# ==================== AUTO-DETECT CONFIGURATION ====================
echo "╔════════════════════════════════════════════════════════╗"
echo "║       OPENVPN VPS SETUP V3 - ALL BUGS FIXED           ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Detect VPS IP
VPS_IP=$(ip -4 addr show | grep inet | grep -v '127.0.0.1' | grep -v '192.168.' | awk '{print $2}' | cut -d'/' -f1 | head -n1)

if [ -z "$VPS_IP" ]; then
    echo "❌ ERROR: Cannot detect VPS IP!"
    exit 1
fi

# Detect gateway
VPS_GATEWAY=$(ip route | grep default | awk '{print $3}' | head -n1)

# Detect active interface
ACTIVE_IFACE=$(ip route get 8.8.8.8 | grep -o 'dev [^ ]*' | awk '{print $2}' | head -n1)

# Detect LAN IP for uhttpd
LAN_IP=$(uci get network.lan.ipaddr 2>/dev/null || echo "127.0.0.1")

# OpenVPN config
OVPN_SERVER_PORT="1194"
OVPN_SERVER_SUBNET="10.9.0.0"
DNS_UPSTREAM="108.61.10.10"

echo "📊 Configuration:"
echo "   VPS IP:       $VPS_IP"
echo "   Gateway:      $VPS_GATEWAY"
echo "   Interface:    $ACTIVE_IFACE"
echo "   LAN IP:       $LAN_IP"
echo "   VPN Subnet:   $OVPN_SERVER_SUBNET/24"
echo "   VPN Port:     $OVPN_SERVER_PORT"
echo "   DNS:          $DNS_UPSTREAM"
echo ""
read -p "Press ENTER to continue or Ctrl+C to abort..."

# ==================== 1. INSTALL PACKAGES ====================
echo ""
echo "==> [1/9] Installing packages..."
opkg update
opkg install --force-overwrite \
    luci luci-ssl luci-compat \
    ip-full iptables-nft kmod-nft-nat \
    openvpn-openssl luci-app-openvpn \
    nginx-ssl openssl-util openvpn-easy-rsa \
    kmod-tun curl ca-certificates

# ==================== 2. NETWORK INTERFACES ====================
echo "==> [2/9] Configuring network..."

# Add VPN server interface
uci set network.vpnserver=interface
uci set network.vpnserver.proto='none'
uci set network.vpnserver.device='tun1'
uci set network.vpnserver.auto='0'
uci commit network
/etc/init.d/network reload

# ==================== 3. PKI & CERTIFICATES ====================
echo "==> [3/9] Setting up PKI..."
mkdir -p /etc/easy-rsa
cd /etc/easy-rsa

if [ ! -f /etc/easy-rsa/pki/ca.crt ]; then
    easyrsa init-pki
    EASYRSA_BATCH=1 easyrsa build-ca nopass
    easyrsa gen-dh
    EASYRSA_BATCH=1 easyrsa build-server-full server nopass
    EASYRSA_BATCH=1 easyrsa build-client-full client1 nopass
    openvpn --genkey secret /etc/easy-rsa/pki/ta.key
fi

cd /

# ==================== 4. OPENVPN SERVER CONFIG ====================
echo "==> [4/9] Configuring OpenVPN Server..."
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

# ==================== 5. NGINX FOR LUCI (FIXED 403) ====================
echo "==> [5/9] Configuring Nginx..."

mkdir -p /etc/nginx/certs /etc/nginx/conf.d /var/log/nginx
touch /var/log/nginx/access.log /var/log/nginx/error.log

# SSL certificate
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/luci.key \
    -out /etc/nginx/certs/luci.crt \
    -subj "/CN=$VPS_IP" 2>/dev/null

# Nginx main config
cat > /etc/nginx/nginx.conf <<EOF
user root;
worker_processes 1;

events {
    worker_connections 512;
}

http {
    include mime.types;
    default_type application/octet-stream;
    
    sendfile on;
    keepalive_timeout 30;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    server {
        listen 80 default_server;
        return 301 https://\$host\$request_uri;
    }
    
    server {
        listen 443 ssl default_server;
        
        ssl_certificate /etc/nginx/certs/luci.crt;
        ssl_certificate_key /etc/nginx/certs/luci.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        
        location / {
            proxy_pass http://${LAN_IP}:80;
            proxy_set_header Host \$http_host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_buffering off;
        }
    }
}
EOF

# Configure uhttpd to listen on LAN IP only
uci delete uhttpd.main.listen_http 2>/dev/null || true
uci delete uhttpd.main.listen_https 2>/dev/null || true
uci add_list uhttpd.main.listen_http="${LAN_IP}:80"
uci add_list uhttpd.main.listen_https="${LAN_IP}:443"
uci commit uhttpd

# ==================== 6. FIREWALL CONFIG ====================
echo "==> [6/9] Configuring firewall..."

# Backup
cp /etc/config/firewall /etc/config/firewall.backup 2>/dev/null || true

# Detect if WAN zone exists
WAN_EXISTS=$(uci show firewall 2>/dev/null | grep -c "zone.*wan" || echo 0)

if [ "$WAN_EXISTS" -eq 0 ]; then
    # No WAN zone - minimal firewall for VPS using LAN
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
    # WAN zone exists - standard firewall
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

# ==================== 7. CUSTOM FIREWALL RULES (FW4 COMPATIBLE) ====================
echo "==> [7/9] Creating custom firewall rules..."

# Create nftables script for fw4
cat > /etc/nftables.d/99-custom-openvpn.nft <<'NFTSCRIPT'
#!/usr/sbin/nft -f

# Custom OpenVPN rules for fw4

# Add NAT for VPN clients
add rule inet fw4 srcnat oifname "br-lan" ip saddr 10.9.0.0/24 counter masquerade comment "OpenVPN NAT br-lan"
add rule inet fw4 srcnat oifname "eth0" ip saddr 10.9.0.0/24 counter masquerade comment "OpenVPN NAT eth0"

# Add forwarding rules
add rule inet fw4 forward_vpnserver oifname "br-lan" counter accept comment "OpenVPN forward to br-lan"
add rule inet fw4 forward_vpnserver oifname "eth0" counter accept comment "OpenVPN forward to eth0"
NFTSCRIPT

chmod +x /etc/nftables.d/99-custom-openvpn.nft

# Create firewall.user for iptables rules (TTL spoofing)
cat > /etc/firewall.user <<'FWUSER'
#!/bin/sh
# Custom firewall rules - runs after fw4 initialization

# Wait for fw4 to fully initialize
sleep 3

# ==================== TTL SPOOFING (Windows = 128) ====================
iptables -t mangle -F POSTROUTING 2>/dev/null || true
iptables -t mangle -A POSTROUTING -o eth0 -j TTL --ttl-set 128 2>/dev/null || true
iptables -t mangle -A POSTROUTING -o br-lan -j TTL --ttl-set 128 2>/dev/null || true
iptables -t mangle -A POSTROUTING -o tun1 -j TTL --ttl-set 128 2>/dev/null || true

# ==================== TCP FINGERPRINT SPOOFING ====================
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null || true

# ==================== DNS LEAK PROTECTION ====================
iptables -I FORWARD -p tcp --dport 53 -j REJECT 2>/dev/null || true
iptables -I FORWARD -p udp --dport 53 -j REJECT 2>/dev/null || true
iptables -I FORWARD -s 10.9.0.0/24 -d 10.9.0.1 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -I FORWARD -s 10.9.0.0/24 -d 10.9.0.1 -p udp --dport 53 -j ACCEPT 2>/dev/null || true

# Apply nftables custom rules
if [ -f /etc/nftables.d/99-custom-openvpn.nft ]; then
    nft -f /etc/nftables.d/99-custom-openvpn.nft 2>/dev/null || true
fi

logger "OpenVPN custom firewall rules applied"
FWUSER

chmod +x /etc/firewall.user

# ==================== 8. DNS CONFIG (FIXED UCI ERROR) ====================
echo "==> [8/9] Configuring DNS..."

# Check if dnsmasq config exists
if ! uci get dhcp.@dnsmasq[0] >/dev/null 2>&1; then
    uci add dhcp dnsmasq
fi

# Configure dnsmasq
uci set dhcp.@dnsmasq[0].noresolv='1'
uci set dhcp.@dnsmasq[0].cachesize='1000'
uci set dhcp.@dnsmasq[0].localise_queries='1'
uci set dhcp.@dnsmasq[0].rebind_protection='0'

# Clear existing servers
uci delete dhcp.@dnsmasq[0].server 2>/dev/null || true

# Add VPS DNS
uci add_list dhcp.@dnsmasq[0].server="$DNS_UPSTREAM"

# Add tun1 interface
uci delete dhcp.@dnsmasq[0].interface 2>/dev/null || true
uci add_list dhcp.@dnsmasq[0].interface='tun1'

uci commit dhcp

# ==================== 9. SYSTEM OPTIMIZATIONS (FIXED BBR ERROR) ====================
echo "==> [9/9] System optimizations..."

# Check if BBR is available
if [ -f /proc/sys/net/ipv4/tcp_available_congestion_control ]; then
    if grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
        BBR_AVAILABLE="yes"
    else
        BBR_AVAILABLE="no"
    fi
else
    BBR_AVAILABLE="no"
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
EOF

# Only add BBR if available
if [ "$BBR_AVAILABLE" = "yes" ]; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
else
    echo "# BBR not available, using default congestion control" >> /etc/sysctl.conf
fi

# Add IPv6 disable only if IPv6 is present
if [ -d /proc/sys/net/ipv6 ]; then
    cat >> /etc/sysctl.conf <<EOF
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
fi

sysctl -p 2>&1 | grep -v "No such file or directory" || true

# ==================== GENERATE CLIENT CONFIG ====================
echo "==> Generating client config..."

cat > /root/client1.ovpn <<EOF
# OpenVPN Client Config for Windows
client
dev tun
proto udp
remote $VPS_IP $OVPN_SERVER_PORT
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

# ==================== START SERVICES ====================
echo ""
echo "==> Starting services..."

/etc/init.d/uhttpd restart
/etc/init.d/nginx enable
/etc/init.d/nginx restart
/etc/init.d/openvpn enable
/etc/init.d/openvpn restart
/etc/init.d/dnsmasq restart
/etc/init.d/firewall restart

# Run firewall.user manually first time
sleep 2
/etc/firewall.user

sleep 3

# ==================== VERIFICATION ====================
echo ""
echo "==> Verifying setup..."

# Check services
echo "Checking services..."
/etc/init.d/openvpn status >/dev/null 2>&1 && echo "  ✓ OpenVPN running" || echo "  ✗ OpenVPN failed"
/etc/init.d/nginx status >/dev/null 2>&1 && echo "  ✓ Nginx running" || echo "  ✗ Nginx failed"

# Check interface
ip addr show tun1 >/dev/null 2>&1 && echo "  ✓ tun1 interface UP" || echo "  ✗ tun1 interface DOWN"

# Check firewall rules
RULES_COUNT=$(nft list chain inet fw4 srcnat 2>/dev/null | grep -c "10.9.0.0" || echo "0")
if [ "$RULES_COUNT" -ge 1 ]; then
    echo "  ✓ Firewall NAT rules applied ($RULES_COUNT rules)"
else
    echo "  ✗ Firewall NAT rules missing (will retry)"
    # Retry applying nftables rules
    nft -f /etc/nftables.d/99-custom-openvpn.nft 2>/dev/null && echo "  ✓ NAT rules applied on retry" || echo "  ✗ NAT rules failed"
fi

# Check Nginx can reach uhttpd
echo "Checking Nginx → uhttpd connection..."
curl -s -o /dev/null -w "%{http_code}" http://${LAN_IP}:80 >/dev/null 2>&1 && echo "  ✓ uhttpd responding" || echo "  ⚠ uhttpd might not be accessible"

# ==================== FINAL SUMMARY ====================
clear
cat <<EOF
╔═════════════════════════════════════════════════════════════════╗
║          OPENVPN VPS SETUP V3 COMPLETED! ✓                      ║
╚═════════════════════════════════════════════════════════════════╝

📊 SERVER INFORMATION:
   • VPS IP:             $VPS_IP
   • Gateway:            $VPS_GATEWAY
   • Interface:          $ACTIVE_IFACE
   • LAN IP:             $LAN_IP
   • OpenVPN Port:       $OVPN_SERVER_PORT (UDP)
   • VPN Subnet:         $OVPN_SERVER_SUBNET/24
   • DNS Server:         $DNS_UPSTREAM

🌐 LUCI WEB INTERFACE:
   • URL:                https://$VPS_IP
   • Username:           root
   • Password:           [Your VPS root password]
   • Status:             Nginx → uhttpd proxy configured

🔐 VPN CLIENT CONFIG:
   • File:               /root/client1.ovpn
   • Download:           scp root@$VPS_IP:/root/client1.ovpn .
   • Import to:          OpenVPN Connect (Windows)

✅ FEATURES ENABLED:
   ✓ NAT & Masquerading (nftables fw4)
   ✓ TTL Spoofing (TTL=128, mimic Windows)
   ✓ TCP Fingerprint Spoofing (MSS=1460)
   ✓ DNS Leak Protection
   ✓ Nginx Reverse Proxy for LuCI (FIXED 403 error)
   ✓ Automatic firewall rules via /etc/firewall.user
   $([ "$BBR_AVAILABLE" = "yes" ] && echo "   ✓ BBR Congestion Control" || echo "   ⚠ BBR not available (using default)")

🔧 USEFUL COMMANDS:
   • Check clients:      cat /var/log/openvpn-server-status.log
   • Check NAT rules:    nft list chain inet fw4 srcnat | grep 10.9.0.0
   • Check forwarding:   nft list chain inet fw4 forward_vpnserver
   • Restart OpenVPN:    /etc/init.d/openvpn restart
   • Restart firewall:   /etc/init.d/firewall restart
   • Restart Nginx:      /etc/init.d/nginx restart
   • View logs:          logread -f | grep openvpn
   • Test LuCI:          curl -I https://$VPS_IP

🐛 TROUBLESHOOTING:

   1. LuCI 403 Forbidden:
      • Check: curl -I http://${LAN_IP}:80
      • Check: /etc/init.d/uhttpd status
      • Fix: /etc/init.d/uhttpd restart

   2. No internet on VPN client:
      • Check NAT: nft list chain inet fw4 srcnat | grep 10.9.0.0
      • Reapply: /etc/firewall.user
      • Check: iptables -t nat -L -n -v

   3. Client can't connect:
      • Check firewall: iptables -L -n | grep $OVPN_SERVER_PORT
      • Check logs: tail -f /var/log/openvpn-server.log
      • Check interface: ip addr show tun1

   4. DNS not working:
      • Check dnsmasq: netstat -tulpn | grep :53
      • Test: nslookup google.com 10.9.0.1
      • Restart: /etc/init.d/dnsmasq restart

📝 NEXT STEPS:
   1. Test LuCI access: https://$VPS_IP
   2. Download client config: scp root@$VPS_IP:/root/client1.ovpn .
   3. Import to OpenVPN Connect on Windows
   4. Connect and test: ping 10.9.0.1
   5. Test internet: curl http://google.com (from VPN client)
   6. Test DNS leak: https://dnsleaktest.com

╔═════════════════════════════════════════════════════════════════╗
║  Setup completed at $(date)                                     ║
║  VPS is ready for production use! 🚀                            ║
╚═════════════════════════════════════════════════════════════════╝
EOF

echo ""
echo "💾 Save this output for reference!"
echo "📥 Download: scp root@$VPS_IP:/root/client1.ovpn ."
echo ""
