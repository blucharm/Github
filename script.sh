#!/bin/sh
# =============================================================================
# OPENVPN FULL SETUP (REVISED)
# - Configures OpenVPN Server, Nginx Proxy, TTL Spoofing, DNS Leak Fix
# - Assumes WAN Static IP is configured from PART 1.
# =============================================================================

set -e

# ==================== USER CONFIGURATION (DO NOT CHANGE IF SET IN PART 1) ====================
VPS_IP="45.63.92.69"
VPS_NETMASK="255.255.254.0"
DNS_UPSTREAM="108.61.10.10"
NIC_WAN="eth0"
# ===========================================================================================

echo "Starting full setup for VPS $VPS_IP..."

# ==================== 1. INSTALL PACKAGES ====================
opkg update
opkg install --force-overwrite \
    luci luci-ssl luci-compat \
    ip-full ipset \
    iptables-nft nftables nftables-json \
    iptables-mod-ttl iptables-mod-ipopt iptables-mod-nat-extra \
    openvpn-openssl luci-app-openvpn \
    nginx-ssl openssl-util \
    fail2ban kmod-tun \
    curl ca-certificates

# ==================== 2. LAN BRIDGE CONFIG (FOR NGINX PROXY) ====================
# We ensure the LAN bridge exists and is configured to 192.168.1.1
uci batch <<EOF
# LAN IP must be set for uhttpd to bind correctly for Nginx proxying
set network.lan=interface
set network.lan.proto='static'
set network.lan.ipaddr='192.168.1.1'
set network.lan.netmask='255.255.255.0'
set network.lan.device='br-lan'
commit network
EOF

# ==================== 3. OPENVPN KEY & CERTIFICATES ====================
mkdir -p /etc/easy-rsa/pki
if [ ! -f /etc/easy-rsa/pki/ca.crt ]; then
    easyrsa init-pki 2>/dev/null || true
    echo | easyrsa build-ca nopass
    easyrsa gen-dh
    easyrsa build-server-full server nopass
    easyrsa build-client-full client nopass
fi

# ==================== 4. OPENVPN SERVER CONFIG ====================
uci delete openvpn.myvpn_server 2>/dev/null || true
uci set openvpn.myvpn_server=openvpn
uci set openvpn.myvpn_server.enabled='1'
uci set openvpn.myvpn_server.dev='tun0'
uci set openvpn.myvpn_server.proto='udp'
uci set openvpn.myvpn_server.port='1194'
uci set openvpn.myvpn_server.server='10.8.0.0 255.255.255.0'
uci set openvpn.myvpn_server.cipher='none'
uci set openvpn.myvpn_server.auth='none'
uci set openvpn.myvpn_server.keepalive='10 120'
uci set openvpn.myvpn_server.persist_key='1'
uci set openvpn.myvpn_server.persist_tun='1'
uci set openvpn.myvpn_server.user='nobody'
uci set openvpn.myvpn_server.group='nogroup'
uci set openvpn.myvpn_server.ca='/etc/easy-rsa/pki/ca.crt'
uci set openvpn.myvpn_server.cert='/etc/easy-rsa/pki/issued/server.crt'
uci set openvpn.myvpn_server.key='/etc/easy-rsa/pki/private/server.key'
uci set openvpn.myvpn_server.dh='/etc/easy-rsa/pki/dh.pem'
uci add_list openvpn.myvpn_server.push='dhcp-option DNS 10.8.0.1'
uci add_list openvpn.myvpn_server.push='redirect-gateway def1 bypass-dhcp'
uci add_list openvpn.myvpn_server.push='block-outside-dns'
uci commit openvpn


# ==================== 5. LUCI VIA NGINX PROXY (FIXED NGINX.CONF STRUCTURE) ====================
# SSL Certs
mkdir -p /etc/nginx/certs
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/luci.key \
    -out /etc/nginx/certs/luci.crt \
    -subj "/CN=$VPS_IP" >/dev/null 2>&1

# NGINX MAIN CONFIG (FIXED STRUCTURE - KHẮC PHỤC LỖI KHÔNG CÓ KHỐI HTTP)
cat > /etc/nginx/nginx.conf <<EOF
user root;
worker_processes auto;
events {
    worker_connections 1024;
}
http {
    include mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    include /etc/nginx/conf.d/luci.conf;
}
EOF

# Nginx LuCI Proxy CONFIG
cat > /etc/nginx/conf.d/luci.conf <<EOF
server {
    listen 80;
    listen 443 ssl;
    server_name $VPS_IP;
    ssl_certificate /etc/nginx/certs/luci.crt;
    ssl_certificate_key /etc/nginx/certs/luci.key;
    location / {
        proxy_pass http://192.168.1.1:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# uhttpd config (bind to LAN IP)
uci set uhttpd.main.listen_http='192.168.1.1:80'
uci set uhttpd.main.listen_https='192.168.1.1:443'
uci commit uhttpd


# ==================== 6. FIREWALL: PORTS + ZONES + DNS BLOCK + SPOOF ====================
# OpenVPN Port Rule
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-OpenVPN'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='1194'
uci set firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].target='ACCEPT'

# OpenVPN Zone (tun0)
uci add firewall zone
uci set firewall.@zone[-1].name='vpn_out'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='ACCEPT'
uci set firewall.@zone[-1].masq='1'
uci set firewall.@zone[-1].network='tun0'

uci add firewall forwarding
uci set firewall.@forwarding[-1].src='vpn_out'
uci set firewall.@forwarding[-1].dest='wan'

# DNS no-leak (Drop all DNS traffic not going to the VPN/Local DNS)
uci add firewall rule
uci set firewall.@rule[-1].name='Block_DNS_Leak'
uci set firewall.@rule[-1].src='lan vpn_out'
uci set firewall.@rule[-1].dest_port='53'
uci set firewall.@rule[-1].proto='tcp udp'
uci set firewall.@rule[-1].target='DROP'

uci add firewall rule
uci set firewall.@rule[-1].name='Allow_DNS_to_VPN_Server'
uci set firewall.@rule[-1].src='lan vpn_out'
uci set firewall.@rule[-1].dest_ip='10.8.0.1'
uci set firewall.@rule[-1].dest_port='53'
uci set firewall.@rule[-1].proto='tcp udp'
uci set firewall.@rule[-1].target='ACCEPT'

# Spoof Windows TTL (Using firewall.user for direct iptables commands)
cat > /etc/firewall.user <<EOF
# Spoof Windows TTL
iptables -t mangle -A POSTROUTING -o eth0 -j TTL --ttl-set 128
iptables -t mangle -A POSTROUTING -o tun0 -j TTL --ttl-set 128
EOF

uci commit firewall

# ==================== 7. FAIL2BAN BRUTE-FORCE ====================
uci set fail2ban.@jail[0].enabled='1'
uci set fail2ban.@jail[0].name='luci'
uci set fail2ban.@jail[0].port='80,443'
uci set fail2ban.@jail[0].logtarget='/var/log/fail2ban.log'
uci set fail2ban.@jail[0].maxretry='5'
uci set fail2ban.@jail[0].bantime='3600'
uci commit fail2ban

# ==================== 8. DNSMASQ: UPSTREAM ====================
uci set dhcp.@dnsmasq[0].cachesize='0'
uci commit dhcp

# ==================== 9. FILE CLIENT.OPVN ====================
cat > /root/client.ovpn <<EOF
client
dev tun
proto udp
remote $VPS_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher none
auth none
remote-cert-tls server
block-outside-dns
verb 3
<ca>
$(cat /etc/easy-rsa/pki/ca.crt)
</ca>
<cert>
$(cat /etc/easy-rsa/pki/issued/client.crt)
</cert>
<key>
$(cat /etc/easy-rsa/pki/private/client.key)
</key>
EOF

# ==================== 10. End: Restart Services ====================
/etc/init.d/network restart
/etc/init.d/uhttpd restart
/etc/init.d/nginx enable
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/firewall restart
/etc/init.d/dnsmasq restart
/etc/init.d/fail2ban enable
/etc/init.d/fail2ban start

# Final Output
echo "=============================================="
echo "FULL SETUP SUCCESSFUL!"
echo "VPS IP: $VPS_IP"
echo ""
echo "1. LUCI ACCESS: http://$VPS_IP or https://$VPS_IP"
echo "   User: root | Password: [Your Console Password]"
echo ""
echo "2. OPENVPN CLIENT FILE: /root/client.ovpn (Download this file)"
echo "=============================================="
