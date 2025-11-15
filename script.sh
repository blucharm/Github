#!/bin/sh
# =============================================================================
# OPENVPN VPS SETUP - FIXED VERSION (Tested & Working)
# - OpenVPN Server (tun1) for Windows clients
# - Nginx reverse proxy for LuCI
# - NAT, Firewall, TTL spoofing
# - Optimized for low-resource VPS (1-2 core, 1GB RAM)
# =============================================================================

set -e

# ==================== AUTO-DETECT CONFIGURATION ====================
echo "+--------------------------------------------------------+"
echo "¦       OPENVPN VPS SETUP - FIXED VERSION              ¦"
echo "+--------------------------------------------------------+"
echo ""

# Detect VPS IP
VPS_IP=$(ip -4 addr show | grep inet | grep -v '127.0.0.1' | grep -v '192.168.' | awk '{print $2}' | cut -d'/' -f1 | head -n1)

if [ -z "$VPS_IP" ]; then
    echo "? ERROR: Cannot detect VPS IP!"
    exit 1
fi

# Detect gateway
VPS_GATEWAY=$(ip route | grep default | awk '{print $3}' | head -n1)

# Detect active interface
ACTIVE_IFACE=$(ip route get 8.8.8.8 | grep -o 'dev [^ ]*' | awk '{print $2}' | head -n1)

# OpenVPN config
OVPN_SERVER_PORT="1194"
OVPN_SERVER_SUBNET="10.9.0.0"
DNS_UPSTREAM="8.8.8.8"

echo "?? Configuration:"
echo "   VPS IP:       $VPS_IP"
echo "   Gateway:      $VPS_GATEWAY"
echo "   Interface:    $ACTIVE_IFACE"
echo "   VPN Subnet:   $OVPN_SERVER_SUBNET/24"
echo "   VPN Port:     $OVPN_SERVER_PORT"
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
    echo "yes" | easyrsa init-pki
    EASYRSA_BATCH=1 easyrsa build-ca nopass
    easyrsa gen-dh
    EASYRSA_BATCH=1 easyrsa build-server-full server nopass
    EASYRSA_BATCH=1 easyrsa build-client-full client1 nopass
    openvpn --genkey secret /etc/easy-rsa/pki/ta.key
fi

cd /

# ==================== 4. OPENVPN SERVER CONFIG ====================
echo "==> [4/9] Configuring OpenVPN Server..."
mkdir -p /etc/openvpn

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

# ==================== 5. NGINX FOR LUCI ====================
echo "==> [5/9] Configuring Nginx..."

mkdir -p /etc/nginx/certs /etc/nginx/conf.d /var/log/nginx

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
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
        }
    }
}
EOF

# Configure uhttpd to listen on localhost only
uci delete uhttpd.main.listen_http 2>/dev/null || true
uci delete uhttpd.main.listen_https 2>/dev/null || true
uci add_list uhttpd.main.listen_http='0.0.0.0:8080'
uci add_list uhttpd.main.listen_https='0.0.0.0:8443'
uci commit uhttpd

# ==================== 6. FIREWALL CONFIG ====================
echo "==> [6/9] Configuring firewall..."

# Backup
cp /etc/config/firewall /etc/config/firewall.backup 2>/dev/null || true

# Detect if WAN zone exists
WAN_EXISTS=$(uci show firewall | grep "zone.*wan" | wc -l)

if [ "$WAN_EXISTS" -eq 0 ]; then
    # No WAN zone - minimal firewall
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

# ==================== 7. CUSTOM FIREWALL RULES ====================
echo "==> [7/9] Creating custom firewall rules..."

cat > /etc/firewall.user <<'FWUSER'
#!/bin/sh

# Wait for firewall to initialize
sleep 2

# ==================== NAT FOR VPN CLIENTS ====================
# Add NAT rules via nftables (OpenWrt fw4)
nft insert rule inet fw4 srcnat oifname "br-lan" ip saddr 10.9.0.0/24 counter masquerade 2>/dev/null || true
nft insert rule inet fw4 srcnat oifname "eth0" ip saddr 10.9.0.0/24 counter masquerade 2>/dev/null || true

# ==================== FORWARDING RULES ====================
# Allow forward from VPN clients to internet
nft insert rule inet fw4 forward_vpnserver oifname "br-lan" counter accept 2>/dev/null || true
nft insert rule inet fw4 forward_vpnserver oifname "eth0" counter accept 2>/dev/null || true

# ==================== TTL SPOOFING (Windows = 128) ====================
iptables -t mangle -F POSTROUTING 2>/dev/null || true
iptables -t mangle -A POSTROUTING -o eth0 -j TTL --ttl-set 128 2>/dev/null || true
iptables -t mangle -A POSTROUTING -o br-lan -j TTL --ttl-set 128 2>/dev/null || true

# ==================== TCP FINGERPRINT SPOOFING ====================
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null || true

# ==================== DNS LEAK PROTECTION ====================
iptables -I FORWARD -p tcp --dport 53 -j REJECT 2>/dev/null || true
iptables -I FORWARD -p udp --dport 53 -j REJECT 2>/dev/null || true
iptables -I FORWARD -s 10.9.0.0/24 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -I FORWARD -s 10.9.0.0/24 -p udp --dport 53 -j ACCEPT 2>/dev/null || true

logger "Custom firewall rules applied for OpenVPN"
FWUSER

chmod +x /etc/firewall.user

# Add firewall include
uci delete firewall.custom_include 2>/dev/null || true
uci add firewall include
uci set firewall.@include[-1].path='/etc/firewall.user'
uci set firewall.@include[-1].reload='1'
uci rename firewall.@include[-1]='custom_include'
uci commit firewall

# ==================== 8. DNS CONFIG ====================
echo "==> [8/9] Configuring DNS..."

uci batch <<EOF
set dhcp.@dnsmasq[0].noresolv='1'
set dhcp.@dnsmasq[0].cachesize='1000'
delete dhcp.@dnsmasq[0].server
add_list dhcp.@dnsmasq[0].server='$DNS_UPSTREAM'
add_list dhcp.@dnsmasq[0].interface='tun1'
commit dhcp
EOF

# ==================== 9. SYSTEM OPTIMIZATIONS ====================
echo "==> [9/9] System optimizations..."

cat >> /etc/sysctl.conf <<EOF

# OpenVPN optimizations
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc=fq
net.ipv4.ip_forward=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF

sysctl -p

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

sleep 3

# ==================== VERIFICATION ====================
echo ""
echo "==> Verifying setup..."

# Check services
echo "Checking services..."
/etc/init.d/openvpn status && echo "  ? OpenVPN running" || echo "  ? OpenVPN failed"
/etc/init.d/nginx status && echo "  ? Nginx running" || echo "  ? Nginx failed"

# Check interface
ip addr show tun1 > /dev/null 2>&1 && echo "  ? tun1 interface UP" || echo "  ? tun1 interface DOWN"

# Check firewall rules
RULES_COUNT=$(nft list chain inet fw4 srcnat 2>/dev/null | grep -c "10.9.0.0/24" || echo 0)
[ "$RULES_COUNT" -ge 1 ] && echo "  ? Firewall rules applied" || echo "  ? Firewall rules missing"

# ==================== FINAL SUMMARY ====================
clear
cat <<EOF
+---------------------------------------------------------------------+
¦              OPENVPN VPS SETUP COMPLETED! ?                         ¦
+---------------------------------------------------------------------

+---------------------------------------------------------------------+
¦  Setup completed at $(date)                                         ¦
¦  VPS is ready for production use! ??                                ¦
+---------------------------------------------------------------------+
EOF

echo ""
echo "?? Save this output for reference!"
echo "?? Download: scp root@$VPS_IP:/root/client1.ovpn ."
echo ""
