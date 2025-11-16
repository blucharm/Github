#!/bin/bash

###############################################################################
# Auto Setup Script
# OpenVPN
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect gateway from IP
detect_gateway() {
    local ip=$1
    local netmask=$2
    
    # Calculate network address
    IFS=. read -r i1 i2 i3 i4 <<< "$ip"
    IFS=. read -r m1 m2 m3 m4 <<< "$netmask"
    
    # Network address
    net1=$((i1 & m1))
    net2=$((i2 & m2))
    net3=$((i3 & m3))
    net4=$((i4 & m4))
    
    # Gateway is usually first IP in subnet (network + 1)
    gw4=$((net4 + 1))
    
    echo "$net1.$net2.$net3.$gw4"
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ((octet > 255)); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

###############################################################################
# STEP 1: Gather Information
###############################################################################

print_info "=== OpenWRT VPS Setup Script ==="
echo ""

# WAN IP Address
while true; do
    read -p "Enter WAN IP Address (e.g., 45.76.233.172): " WAN_IP
    if validate_ip "$WAN_IP"; then
        break
    else
        print_error "Invalid IP address format. Please try again."
    fi
done

# WAN Netmask
read -p "Enter WAN Netmask [default: 255.255.254.0]: " WAN_NETMASK
WAN_NETMASK=${WAN_NETMASK:-255.255.254.0}

# Auto-detect gateway
WAN_GATEWAY=$(detect_gateway "$WAN_IP" "$WAN_NETMASK")
read -p "WAN Gateway [auto-detected: $WAN_GATEWAY]: " WAN_GATEWAY_INPUT
WAN_GATEWAY=${WAN_GATEWAY_INPUT:-$WAN_GATEWAY}

# LAN/VPC IP Address
read -p "Enter LAN/VPC IP Address (e.g., 10.3.96.3) or press Enter to skip: " LAN_IP
if [ -n "$LAN_IP" ]; then
    read -p "Enter LAN Netmask [default: 255.255.240.0]: " LAN_NETMASK
    LAN_NETMASK=${LAN_NETMASK:-255.255.240.0}
    SETUP_LAN=true
else
    SETUP_LAN=false
fi

# DNS Server
read -p "Enter DNS Server [default: 108.61.10.10]: " DNS_SERVER
DNS_SERVER=${DNS_SERVER:-108.61.10.10}

# VPN Subnet
read -p "Enter VPN Subnet [default: 10.8.0.0]: " VPN_SUBNET
VPN_SUBNET=${VPN_SUBNET:-10.8.0.0}

# Summary
echo ""
print_info "=== Configuration Summary ==="
echo "WAN IP:       $WAN_IP"
echo "WAN Netmask:  $WAN_NETMASK"
echo "WAN Gateway:  $WAN_GATEWAY"
echo "DNS Server:   $DNS_SERVER"
if [ "$SETUP_LAN" = true ]; then
    echo "LAN IP:       $LAN_IP"
    echo "LAN Netmask:  $LAN_NETMASK"
fi
echo "VPN Subnet:   $VPN_SUBNET/24"
echo ""

read -p "Continue with installation? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ]; then
    print_error "Installation cancelled."
    exit 1
fi

###############################################################################
# STEP 2: Update and Install Packages
###############################################################################

print_info "Updating package lists..."
opkg update

print_info "Installing required packages..."
opkg install luci-app-ttyd luci-app-filemanager openvpn-easy-rsa openvpn-openssl luci-app-openvpn

###############################################################################
# STEP 3: Configure Network
###############################################################################

print_info "Configuring network..."

cat > /etc/config/network << EOF
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config interface 'wan'
	option device 'eth0'
	option proto 'static'
	option ipaddr '$WAN_IP'
	option netmask '$WAN_NETMASK'
	option gateway '$WAN_GATEWAY'
	option dns '$DNS_SERVER'
EOF

if [ "$SETUP_LAN" = true ]; then
    cat >> /etc/config/network << EOF

config interface 'lan'
	option device 'eth1'
	option proto 'static'
	option ipaddr '$LAN_IP'
	option netmask '$LAN_NETMASK'
EOF
fi

cat >> /etc/config/network << EOF

config interface 'vpn0'
	option proto 'none'
	option device 'tun0'
EOF

print_info "Network configuration completed."

###############################################################################
# STEP 4: Configure Dropbear (SSH)
###############################################################################

print_info "Configuring SSH..."

cat > /etc/config/dropbear << EOF
config dropbear 'main'
	option enable '1'
	option PasswordAuth 'on'
	option RootPasswordAuth 'on'
	option Port '22'
EOF

###############################################################################
# STEP 5: Configure Firewall
###############################################################################

print_info "Configuring firewall..."

cat > /etc/config/firewall << 'EOF'
config defaults
	option syn_flood '1'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option flow_offloading '1'
	option flow_offloading_hw '1'
	option fullcone '1'
	option fullcone6 '0'

config zone
	option name 'wan'
	list network 'wan'
	list network 'wan6'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'

config rule
	option name 'Allow-DHCP-Renew'
	option src 'wan'
	option proto 'udp'
	option dest_port '68'
	option target 'ACCEPT'
	option family 'ipv4'

config rule
	option name 'Allow-Ping'
	option src 'wan'
	option proto 'icmp'
	option icmp_type 'echo-request'
	option family 'ipv4'
	option target 'ACCEPT'

config rule
	option name 'Allow-SSH'
	option src 'wan'
	option dest_port '22'
	option proto 'tcp'
	option target 'ACCEPT'

config rule
	option name 'Allow-HTTP'
	option src 'wan'
	option dest_port '80'
	option proto 'tcp'
	option target 'ACCEPT'

config rule
	option name 'Allow-HTTPS'
	option src 'wan'
	option dest_port '443'
	option proto 'tcp'
	option target 'ACCEPT'

config zone 'vpn'
	option name 'vpn'
	option input 'ACCEPT'
	option forward 'ACCEPT'
	option output 'ACCEPT'
	option masq '1'
	option network 'vpn0'
	option device 'tun0'

config forwarding
	option src 'vpn'
	option dest 'wan'

config rule 'openvpn'
	option name 'Allow-OpenVPN'
	option src 'wan'
	option dest_port '1194'
	option proto 'udp'
	option target 'ACCEPT'
EOF

if [ "$SETUP_LAN" = true ]; then
    cat >> /etc/config/firewall << 'EOF'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config forwarding
	option src 'lan'
	option dest 'wan'

config forwarding
	option src 'vpn'
	option dest 'lan'

config forwarding
	option src 'lan'
	option dest 'vpn'
EOF
fi

print_info "Firewall configuration completed."

###############################################################################
# STEP 6: Generate OpenVPN Certificates
###############################################################################

print_info "Generating OpenVPN certificates (this may take a while)..."

cd /etc/easy-rsa

print_info "Initializing PKI..."
easyrsa init-pki

print_info "Building CA..."
easyrsa build-ca nopass << EOFCA


EOFCA

print_info "Building server certificate..."
easyrsa build-server-full server nopass << EOFSERVER


EOFSERVER

print_info "Building client certificate..."
easyrsa build-client-full client1 nopass << EOFCLIENT


EOFCLIENT

print_info "Generating DH parameters..."
easyrsa gen-dh

print_info "Generating TLS auth key..."
openvpn --genkey secret /etc/easy-rsa/pki/ta.key

###############################################################################
# STEP 7: Configure OpenVPN Server
###############################################################################

print_info "Configuring OpenVPN server..."

cat > /etc/config/openvpn << EOF
config openvpn 'vpnserver'
	option enabled '1'
	option verb '3'
	option proto 'udp'
	option port '1194'
	option dev 'tun0'
	option dev_type 'tun'
	
	option server '$VPN_SUBNET 255.255.255.0'
	option topology 'subnet'
	
	option ca '/etc/easy-rsa/pki/ca.crt'
	option cert '/etc/easy-rsa/pki/issued/server.crt'
	option key '/etc/easy-rsa/pki/private/server.key'
	option dh '/etc/easy-rsa/pki/dh.pem'
	
	option cipher 'AES-256-GCM'
	option data_ciphers 'AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305'
	option auth 'SHA256'
	option tls_server '1'
	
	option sndbuf '393216'
	option rcvbuf '393216'
	option push 'sndbuf 393216'
	option push 'rcvbuf 393216'
	option keepalive '10 60'
	option persist_key '1'
	option persist_tun '1'
	option fast_io '1'
	option tun_mtu '1500'
	option mssfix '1450'
	option txqueuelen '1000'
	
	list push 'redirect-gateway def1'
	list push 'route-gateway ${VPN_SUBNET%.*}.1'
	list push 'dhcp-option DNS ${VPN_SUBNET%.*}.1'
	list push 'block-outside-dns'
EOF

if [ "$SETUP_LAN" = true ]; then
    # Extract LAN network from LAN_IP and LAN_NETMASK
    IFS=. read -r i1 i2 i3 i4 <<< "$LAN_IP"
    IFS=. read -r m1 m2 m3 m4 <<< "$LAN_NETMASK"
    net1=$((i1 & m1))
    net2=$((i2 & m2))
    net3=$((i3 & m3))
    net4=$((i4 & m4))
    LAN_NETWORK="$net1.$net2.$net3.$net4"
    
    cat >> /etc/config/openvpn << EOF
	list push 'route $LAN_NETWORK $LAN_NETMASK ${VPN_SUBNET%.*}.1'
EOF
fi

###############################################################################
# STEP 8: Generate Client Config
# Note: IP forwarding is automatically enabled by OpenWRT firewall
###############################################################################

print_info "Generating client configuration..."

cat > /root/client1.ovpn << EOF
client
dev tun
proto udp
remote $WAN_IP 1194
resolv-retry infinite
nobind

cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
remote-cert-tls server

sndbuf 393216
rcvbuf 393216
keepalive 10 60
persist-key
persist-tun

tun-mtu 1500
mssfix 1450

block-outside-dns

verb 3

<ca>
$(cat /etc/easy-rsa/pki/ca.crt)
</ca>

<cert>
$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' /etc/easy-rsa/pki/issued/client1.crt)
</cert>

<key>
$(cat /etc/easy-rsa/pki/private/client1.key)
</key>

<tls-auth>
$(cat /etc/easy-rsa/pki/ta.key)
</tls-auth>
key-direction 1
EOF

###############################################################################
# STEP 9: Restart Services
###############################################################################

print_info "Restarting services..."

/etc/init.d/network restart
sleep 5
/etc/init.d/firewall restart
/etc/init.d/dropbear restart
/etc/init.d/openvpn restart

# Enable services on boot
/etc/init.d/openvpn enable
/etc/init.d/firewall enable
/etc/init.d/dropbear enable

###############################################################################
# STEP 10: Installation Complete
###############################################################################

echo ""
print_info "==================================================================="
print_info "              OpenWRT VPS Setup Completed Successfully!"
print_info "==================================================================="
echo ""
echo "Network Configuration:"
echo "  - WAN IP:      $WAN_IP"
echo "  - WAN Gateway: $WAN_GATEWAY"
if [ "$SETUP_LAN" = true ]; then
echo "  - LAN IP:      $LAN_IP"
fi
echo "  - DNS Server:  $DNS_SERVER"
echo ""
echo "OpenVPN Configuration:"
echo "  - Server IP:   $WAN_IP:1194"
echo "  - VPN Subnet:  $VPN_SUBNET/24"
echo "  - Protocol:    UDP"
echo ""
echo "Client Configuration File:"
echo "  - Location: /root/client1.ovpn"
echo "  - Download: scp root@$WAN_IP:/root/client1.ovpn ."
echo ""
echo "LuCI Web Interface:"
echo "  - HTTP:  http://$WAN_IP"
echo "  - HTTPS: https://$WAN_IP"
echo ""
echo "Services Status:"
/etc/init.d/openvpn status
echo ""
print_info "Next steps:"
echo "  1. Download client config: /root/client1.ovpn"
echo "  2. Import to OpenVPN client"
echo "  3. Connect and test!"
echo ""
print_warn "Remember to change the root password: passwd"
echo ""
print_info "==================================================================="
