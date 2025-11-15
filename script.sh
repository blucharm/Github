#!/bin/sh
# =============================================================================
# OPENWRT VPS: FULL SETUP - NO PUBLIC DNS, WIREGUARD SERVER, OPENVPN CLIENT
# Automated network configuration (Static WAN) -> package install -> VPN setup.
# Features: Single Host DNS, TTL Spoofing (Windows 128), DNS Leak Protection.
# Author: Gemini | Date: November 15, 2025
# =============================================================================

echo "Starting FULL OpenWrt VPS Setup..."

# ==================== 3. INSTALL PACKAGES ====================
opkg update
opkg install --force-overwrite \
    nano \
    luci luci-ssl luci-compat luci-app-wireguard luci-app-openvpn \
    wireguard-tools kmod-wireguard \
    openvpn-openssl \
    nftables iptables iptables-nft \
    iptables-mod-ttl iptables-mod-ipopt iptables-mod-nat-extra \
    nginx-ssl openssl-util \
    fail2ban \
    curl ca-certificates \
    dnsmasq-full

# ==================== 4. GENERATE WIREGUARD KEYS & CONFIG ====================
WG_SERVER_KEY=$(wg genkey)
WG_SERVER_PUB=$(echo "$WG_SERVER_KEY" | wg pubkey)
WG_CLIENT_KEY=$(wg genkey)
WG_CLIENT_PUB=$(echo "$WG_CLIENT_KEY" | wg pubkey)
WG_PORT="51820"

# Configure WireGuard Interface (wg0)
uci delete network.wg0 >/dev/null 2>&1
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key="$WG_SERVER_KEY"
uci set network.wg0.listen_port="$WG_PORT"
uci set network.wg0.addresses='10.8.0.1/24'
uci set network.wg0.mtu='1420'

# Configure Peer (PC Win 10)
uci add_list network.wg0.wireguard_wg0=wireguard_wg0
uci set network.@wireguard_wg0[-1].public_key="$WG_CLIENT_PUB"
uci set network.@wireguard_wg0[-1].allowed_ips='10.8.0.2/32'
uci set network.@wireguard_wg0[-1].persistent_keep_alive='25'

uci commit network

# ==================== 5. CONFIGURE OPENVPN CLIENT ====================
mkdir -p /etc/openvpn

cat > /etc/openvpn/us_client.conf <<'EOF'
# PASTE YOUR US VPN PROVIDER CONFIG HERE LATER
# Ensure this config does NOT contain conflicting routing directives (e.g., 'redirect-gateway def1')
EOF

# Configure OpenVPN Interface (us_vpn)
uci delete network.us_vpn >/dev/null 2>&1
uci set network.us_vpn=interface
uci set network.us_vpn.proto='vpn'
uci set network.us_vpn.ifname='tun1'
uci set network.us_vpn.auto='0' # DO NOT AUTO-START

# Configure OpenVPN Instance
uci delete openvpn.us_client >/dev/null 2>&1
uci set openvpn.us_client=openvpn
uci set openvpn.us_client.enabled='0' # Disabled by default
uci set openvpn.us_client.config='/etc/openvpn/us_client.conf'
uci set openvpn.us_client.interface='us_vpn'
uci commit openvpn

# ==================== 6. LUCI OVER WAN (NGINX REVERSE PROXY) ====================
mkdir -p /etc/nginx/certs
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/luci.key \
    -out /etc/nginx/certs/luci.crt \
    -subj "/CN=$IP_ADDR" >/dev/null 2>&1

cat > /etc/nginx/conf.d/luci.conf <<EOF
server {
    listen 80;
    listen 443 ssl;
    server_name $IP_ADDR;
    ssl_certificate /etc/nginx/certs/luci.crt;
    ssl_certificate_key /etc/nginx/certs/luci.key;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

# Shift uhttpd to internal port and disable its SSL
uci set uhttpd.main.listen_http='127.0.0.1:8080'
uci set uhttpd.main.listen_https='127.0.0.1:8443'
uci set uhttpd.main.ssl='0'
uci commit uhttpd

# ==================== 7. FIREWALL (ZONE, FORWARDING, RULES) ====================
# A. CREATE ZONES AND FORWARDING
uci delete firewall.wg_out >/dev/null 2>&1
uci add firewall zone
uci set firewall.@zone[-1].name='wg_out'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='ACCEPT'
uci set firewall.@zone[-1].masq='1'
uci set firewall.@zone[-1].network='wg0'

uci add firewall zone
uci set firewall.@zone[-1].name='us_vpn_zone'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='ACCEPT'
uci set firewall.@zone[-1].network='us_vpn' # Interface 'tun1'

# Forwarding: WireGuard (wg_out) to outside (WAN or VPN)
uci delete firewall.wg_to_wan >/dev/null 2>&1
uci add firewall forwarding
uci set firewall.@forwarding[-1].src='wg_out'
uci set firewall.@forwarding[-1].dest='wan'

# B. ACCESS RULES
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-WireGuard'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port="$WG_PORT"
uci set firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].target='ACCEPT'

uci add firewall rule
uci set firewall.@rule[-1].name='Allow-LuCI-HTTP'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='80'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'

uci add firewall rule
uci set firewall.@rule[-1].name='Allow-LuCI-HTTPS'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='443'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].target='ACCEPT'

# C. DNS POLICY: NO PUBLIC DNS & ANTI-LEAK
# 1. ALLOW DNS TO VPS (PRIORITY): Allows wg client to use VPS DNS (10.8.0.1)
uci add firewall rule
uci set firewall.@rule[-1].name='Allow_DNS_to_VPS'
uci set firewall.@rule[-1].src='wg_out'
uci set firewall.@rule[-1].dest_ip='10.8.0.1'
uci set firewall.@rule[-1].dest_port='53'
uci set firewall.@rule[-1].proto='tcp udp'
uci set firewall.@rule[-1].target='ACCEPT'

# 2. DROP ALL OTHER DNS: Blocks any other DNS query from escaping (leak)
uci add firewall rule
uci set firewall.@rule[-1].name='Block_DNS_Leak'
uci set firewall.@rule[-1].src='wg_out'
uci set firewall.@rule[-1].dest='!'
uci set firewall.@rule[-1].dest_port='53'
uci set firewall.@rule[-1].proto='tcp udp'
uci set firewall.@rule[-1].target='DROP'

# D. SPOOF TTL (Windows 10 TTL = 128)
uci add firewall iptables
uci set firewall.@iptables[-1].name='Spoof_TTL_Win10'
uci set firewall.@iptables[-1].target='mangle'
uci set firewall.@iptables[-1].chain='POSTROUTING'
uci set firewall.@iptables[-1].out_interface='wan us_vpn' 
uci set firewall.@iptables[-1].extra='-j TTL --ttl-set 128'

uci commit firewall

# ==================== 8. FAIL2BAN CONFIGURATION ====================
# Enable default SSH jail
uci set fail2ban.default.enabled='1'
uci set fail2ban.default.bantime='3600'
uci set fail2ban.default.maxretry='3'

# Configure Nginx/LuCI jail (Assumes nginx log configuration is default)
uci set fail2ban.luci=jail
uci set fail2ban.luci.enabled='1'
uci set fail2ban.luci.port='80,443'
uci set fail2ban.luci.logpath='/var/log/nginx/access.log'
uci set fail2ban.luci.filter='nginx-http-auth' # Use appropriate filter
uci set fail2ban.luci.maxretry='5'
uci set fail2ban.luci.bantime='3600'
uci commit fail2ban

# ==================== 9. DNSMASQ CONFIGURATION ====================
# Configure DNSMASQ to listen on wg0 (for 10.8.0.1)
uci set dhcp.wg0=dhcp
uci set dhcp.wg0.interface='wg0'
uci set dhcp.wg0.start='100'
uci set dhcp.wg0.limit='150'
uci set dhcp.wg0.leasetime='12h'
uci add_list dhcp.@dnsmasq[0].interface='wg0'
uci commit dhcp

# ==================== 10. CLIENT CONFIG FILE ====================
cat > /root/wg-client.conf <<EOF
[Interface]
PrivateKey = $WG_CLIENT_KEY
Address = 10.8.0.2/32
# DNS is 10.8.0.1 (the VPS itself, which uses the Host's DNS)
DNS = 10.8.0.1

[Peer]
PublicKey = $WG_SERVER_PUB
Endpoint = $IP_ADDR:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

# ==================== 11. START SERVICES ====================
/etc/init.d/network restart
/etc/init.d/uhttpd restart
/etc/init.d/nginx enable
/etc/init.d/nginx restart
/etc/init.d/firewall restart
/etc/init.d/dnsmasq restart
/etc/init.d/fail2ban enable
/etc/init.d/fail2ban start

echo "=============================================="
echo "SETUP COMPLETE!"
echo "LuCI Web Interface: https://$IP_ADDR"
echo "WireGuard Client Config File: /root/wg-client.conf"
echo "Next Steps:"
echo "1. Paste US OpenVPN config into /etc/openvpn/us_client.conf."
echo "2. Go to LuCI -> VPN -> OpenVPN -> us_client -> Enable to activate the VPN."
echo "=============================================="
