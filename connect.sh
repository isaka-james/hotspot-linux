#!/bin/bash

# Script: connect.sh
# Purpose: Create hotspot with internet sharing from eth0 to wlan0
# Usage: sudo ./connect.sh [--ssid NAME] [--password PASS]
#        sudo ./connect.sh --ssid "MyHotspot" --password "SecurePass123"
#        sudo ./connect.sh  # Uses defaults

set -e  # Exit on any error

echo "========================================="
echo "   Hotspot with Internet Sharing"
echo "   (eth0 → wlan0)"
echo "========================================="

# Default Configuration
WIFI_INTERFACE="wlan0"
INTERNET_INTERFACE="eth0"
SUBNET="192.168.4.1/24"
AP_CONF="/etc/hostapd/hostapd.conf"
DNSMASQ_CONF="/etc/dnsmasq.conf"
LOG_FILE="/tmp/hotspot-share.log"

# Default SSID and Password (fallback if not provided)
DEFAULT_SSID="Hotspot-$(hostname | cut -c1-8)"
DEFAULT_PASSWORD="HotspotPassword123"

# Variables for SSID and Password
SSID=""
PASSWORD=""

# Function to display usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --ssid NAME      Set WiFi network name (SSID)"
    echo "  --password PASS  Set WiFi password (8-63 characters)"
    echo "  --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --ssid \"MyNetwork\" --password \"MyPass123\""
    echo "  sudo $0 --ssid \"MyNetwork\"  # Password will be prompted"
    echo "  sudo $0                       # Uses default SSID and password"
    echo ""
}

# Function to validate password
validate_password() {
    local pass="$1"
    
    # Check minimum length
    if [ ${#pass} -lt 8 ]; then
        echo "Error: Password must be at least 8 characters long"
        return 1
    fi
    
    # Check maximum length (WPA2 max is 63 characters)
    if [ ${#pass} -gt 63 ]; then
        echo "Error: Password cannot exceed 63 characters"
        return 1
    fi
    
    # Check for invalid characters (basic check)
    if [[ "$pass" =~ [\<\>\"\'\\] ]]; then
        echo "Error: Password contains invalid characters"
        return 1
    fi
    
    return 0
}

# Function to validate SSID
validate_ssid() {
    local ssid="$1"
    
    # Check minimum length
    if [ ${#ssid} -lt 1 ]; then
        echo "Error: SSID cannot be empty"
        return 1
    fi
    
    # Check maximum length (32 characters for SSID)
    if [ ${#ssid} -gt 32 ]; then
        echo "Error: SSID cannot exceed 32 characters"
        return 1
    fi
    
    # Check for problematic characters
    if [[ "$ssid" =~ [\\] ]]; then
        echo "Error: SSID contains invalid backslash character"
        return 1
    fi
    
    return 0
}

# Function to prompt for password securely
prompt_for_password() {
    local password
    local password_confirm
    
    while true; do
        echo -n "Enter WiFi password (8-63 characters): "
        read -s password
        echo
        
        validate_password "$password"
        if [ $? -ne 0 ]; then
            continue
        fi
        
        echo -n "Confirm WiFi password: "
        read -s password_confirm
        echo
        
        if [ "$password" != "$password_confirm" ]; then
            echo "Error: Passwords do not match. Please try again."
            echo
        else
            PASSWORD="$password"
            break
        fi
    done
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --ssid)
            SSID="$2"
            shift 2
            ;;
        --password)
            PASSWORD="$2"
            shift 2
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate or prompt for SSID
if [ -n "$SSID" ]; then
    validate_ssid "$SSID"
    if [ $? -ne 0 ]; then
        echo "Using default SSID instead"
        SSID="$DEFAULT_SSID"
    fi
else
    read -p "Enter WiFi network name (SSID) [default: $DEFAULT_SSID]: " input_ssid
    if [ -n "$input_ssid" ]; then
        validate_ssid "$input_ssid"
        if [ $? -eq 0 ]; then
            SSID="$input_ssid"
        else
            echo "Invalid SSID. Using default: $DEFAULT_SSID"
            SSID="$DEFAULT_SSID"
        fi
    else
        SSID="$DEFAULT_SSID"
    fi
fi

# Validate or prompt for password
if [ -n "$PASSWORD" ]; then
    validate_password "$PASSWORD"
    if [ $? -ne 0 ]; then
        echo "Password validation failed. Please enter a valid password."
        prompt_for_password
    fi
else
    # Check if we're running in interactive mode
    if [ -t 0 ]; then
        # Interactive mode - prompt for password
        prompt_for_password
    else
        # Non-interactive mode - use default
        echo "No password provided and not in interactive mode. Using default password."
        PASSWORD="$DEFAULT_PASSWORD"
    fi
fi

# Function to log messages with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to check if command succeeded
check_status() {
    if [ $? -eq 0 ]; then
        log "✓ $1"
    else
        log "✗ $1 failed!"
        exit 1
    fi
}

# Function to check internet connectivity
check_internet() {
    if ping -c 2 -I $INTERNET_INTERFACE 8.8.8.8 >/dev/null 2>&1; then
        log "Internet connection on $INTERNET_INTERFACE is working"
        return 0
    else
        log "Warning: No internet on $INTERNET_INTERFACE"
        return 1
    fi
}

# Start logging
echo "Hotspot with internet sharing started at $(date)" > "$LOG_FILE"
log "Starting hotspot with internet sharing..."
log "SSID: $SSID"
log "Password: ${PASSWORD:0:3}*****"  # Log masked password for security

# Display configuration
echo ""
echo "Configuration Summary:"
echo "  WiFi Network: $SSID"
echo "  Password: ${PASSWORD:0:3}*****"  # Show masked password
echo "  Subnet: 192.168.4.0/24"
echo "  Gateway: 192.168.4.1"
echo "  DHCP Range: 192.168.4.2 - 192.168.4.100"
echo "  Interface: $WIFI_INTERFACE (AP) ← $INTERNET_INTERFACE (Internet)"
echo ""

# 1. Check prerequisites
log "Checking prerequisites..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Check if interfaces exist
if ! ip link show "$WIFI_INTERFACE" >/dev/null 2>&1; then
    log "Error: WiFi interface $WIFI_INTERFACE not found!"
    echo "Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' '
    exit 1
fi

if ! ip link show "$INTERNET_INTERFACE" >/dev/null 2>&1; then
    log "Error: Internet interface $INTERNET_INTERFACE not found!"
    echo "Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' '
    exit 1
fi

# Check internet connectivity
check_internet

# 2. Kill all related processes
log "Stopping conflicting services..."
sudo pkill -9 hostapd 2>/dev/null || true
sudo pkill -9 dnsmasq 2>/dev/null || true
sudo systemctl stop NetworkManager 2>/dev/null || true
sudo systemctl stop systemd-resolved 2>/dev/null || true
sudo systemctl stop wpa_supplicant 2>/dev/null || true

# Make sure no wpa_supplicant is running on wlan0
sudo wpa_cli -i "$WIFI_INTERFACE" terminate 2>/dev/null || true

check_status "Conflicting services stopped"

# 3. Wait for processes to fully stop
sleep 2

# 4. Reset WiFi interface
log "Configuring $WIFI_INTERFACE for AP mode..."

# Unblock WiFi
sudo rfkill unblock wifi 2>/dev/null || true
sudo rfkill unblock all 2>/dev/null || true

# Remove all IP addresses from WiFi interface
sudo ip addr flush dev "$WIFI_INTERFACE" 2>/dev/null || true
sudo ip link set "$WIFI_INTERFACE" down 2>/dev/null || true

# Set to AP mode
if sudo iw dev "$WIFI_INTERFACE" set type __ap 2>/dev/null; then
    log "Set interface type to __ap"
elif sudo iw dev "$WIFI_INTERFACE" set type ap 2>/dev/null; then
    log "Set interface type to ap"
else
    log "Warning: Could not set AP mode, trying to continue..."
    # Check if interface supports AP mode
    if ! sudo iw phy | grep -q "AP$"; then
        log "Error: Interface does not support AP mode!"
        echo "Checking supported modes:"
        sudo iw phy | grep -A 10 "Supported interface modes"
        exit 1
    fi
fi

# Configure IP address
log "Setting up subnet $SUBNET on $WIFI_INTERFACE..."
sudo ip addr add "$SUBNET" dev "$WIFI_INTERFACE"
sudo ip link set "$WIFI_INTERFACE" up

check_status "WiFi interface configured"

# 5. Enable IP forwarding and NAT
log "Setting up NAT and IP forwarding..."

# Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Clear existing iptables rules
log "Configuring iptables rules for NAT..."
sudo iptables -t nat -F
sudo iptables -F
sudo iptables -t mangle -F
sudo iptables -X

# Set default policies
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Enable NAT (MASQUERADE) - this is the key for internet sharing
sudo iptables -t nat -A POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE

# Allow established connections
sudo iptables -A FORWARD -i "$INTERNET_INTERFACE" -o "$WIFI_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT

# Allow all outgoing from hotspot
sudo iptables -A FORWARD -i "$WIFI_INTERFACE" -o "$INTERNET_INTERFACE" -j ACCEPT

# Allow DNS (port 53) and DHCP (port 67,68) through firewall
sudo iptables -A INPUT -i "$WIFI_INTERFACE" -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -i "$WIFI_INTERFACE" -p udp --dport 67:68 -j ACCEPT
sudo iptables -A INPUT -i "$WIFI_INTERFACE" -p tcp --dport 53 -j ACCEPT

check_status "NAT and firewall configured"

# 6. Configure and start dnsmasq
log "Setting up DHCP server (dnsmasq)..."

# Create dnsmasq configuration
sudo tee "$DNSMASQ_CONF" > /dev/null << EOF
# Interface to serve DHCP
interface=$WIFI_INTERFACE

# DHCP range
dhcp-range=192.168.4.2,192.168.4.100,255.255.255.0,24h

# Gateway and DNS
dhcp-option=3,192.168.4.1  # Gateway
dhcp-option=6,192.168.4.1  # DNS server

# Use upstream DNS
dhcp-option=option:dns-server,8.8.8.8,8.8.4.4

# Logging
log-queries
log-dhcp

# Don't forward private addresses
domain-needed
bogus-priv

# Speed up DHCP
dhcp-authoritative

# Cache DNS queries
cache-size=1000
EOF

# Kill any existing dnsmasq
sudo pkill -9 dnsmasq 2>/dev/null || true

# Start dnsmasq
sudo dnsmasq -C "$DNSMASQ_CONF" --no-daemon 2>&1 | tee -a "$LOG_FILE" &
DNSMASQ_PID=$!
sleep 2

if kill -0 $DNSMASQ_PID 2>/dev/null; then
    log "✓ dnsmasq started (PID: $DNSMASQ_PID)"
else
    log "✗ dnsmasq failed to start"
    exit 1
fi

# 7. Configure and start hostapd
log "Setting up WiFi access point with SSID: $SSID"

# Escape special characters in SSID and password for hostapd config
# hostapd requires SSID to be quoted if it contains spaces
ESCAPED_SSID="$SSID"
if [[ "$SSID" =~ [[:space:]] ]]; then
    ESCAPED_SSID="\"$SSID\""
fi

# Create hostapd configuration
sudo tee "$AP_CONF" > /dev/null << EOF
# Interface
interface=$WIFI_INTERFACE

# Driver
driver=nl80211

# SSID
ssid=$ESCAPED_SSID

# WiFi mode and channel
hw_mode=g
channel=6
country_code=US

# 802.11n support
ieee80211n=1
ht_capab=[HT40][SHORT-GI-20][DSSS_CCK-40]

# Security
wpa=2
wpa_passphrase=$PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
auth_algs=1
macaddr_acl=0

# Beacon interval
beacon_int=100

# DTIM period
dtim_period=2

# Maximum number of stations
max_num_sta=20

# Rate control
ignore_broadcast_ssid=0
wmm_enabled=1

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
EOF

log "WiFi configuration saved to $AP_CONF"

# Test hostapd config
log "Testing hostapd configuration..."
if sudo hostapd -d "$AP_CONF" 2>&1 | grep -q "Configuration file"; then
    log "✓ hostapd config test passed"
else
    log "Warning: hostapd config test had issues, but continuing..."
fi

# Kill any existing hostapd
sudo pkill -9 hostapd 2>/dev/null || true

# Start hostapd
log "Starting hostapd..."
sudo hostapd -B "$AP_CONF" 2>&1 | tee -a "$LOG_FILE" &
HOSTAPD_PID=$!
sleep 5

if kill -0 $HOSTAPD_PID 2>/dev/null; then
    log "✓ hostapd started (PID: $HOSTAPD_PID)"
else
    log "✗ hostapd failed to start"
    exit 1
fi

# 8. Setup DNS forwarding
log "Setting up DNS forwarding..."

# Stop systemd-resolved if it's interfering
sudo systemctl stop systemd-resolved 2>/dev/null || true

# Create resolv.conf for the hotspot
sudo tee /etc/resolv.hotspot.conf > /dev/null << EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
EOF

# 9. Verify everything is working
log "Verifying setup..."
sleep 3

echo ""
echo "--- Verification ---"
echo ""

# Check interfaces
echo "1. Interface status:"
echo "   $WIFI_INTERFACE:"
ip addr show "$WIFI_INTERFACE" | grep -E "inet|state" | sed 's/^/     /'
echo ""
echo "   $INTERNET_INTERFACE:"
ip addr show "$INTERNET_INTERFACE" | grep -E "inet|state" | sed 's/^/     /'
echo ""

# Check iptables
echo "2. NAT rules:"
sudo iptables -t nat -L POSTROUTING -vn | sed 's/^/     /'
echo ""

# Check processes
echo "3. Running hotspot processes:"
ps aux | grep -E "hostapd|dnsmasq" | grep -v grep | sed 's/^/     /'
echo ""

# Check wireless mode
echo "4. Wireless mode:"
sudo iw dev "$WIFI_INTERFACE" info | grep -E "type|channel" | sed 's/^/     /'
echo ""

# Test DHCP
echo "5. DHCP status:"
if sudo netstat -anu | grep -q ":67 "; then
    echo "     ✓ DHCP server listening on port 67"
else
    echo "     ✗ DHCP server not listening"
fi
echo ""

# Check IP forwarding
echo "6. IP forwarding:"
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
    echo "     ✓ IP forwarding is enabled"
else
    echo "     ✗ IP forwarding is disabled"
fi
echo ""

log "Setup completed successfully!"
echo "========================================="
echo "HOTSPOT IS NOW ACTIVE"
echo "========================================="
echo "Connect to: $SSID"
echo "Password: ${PASSWORD:0:3}*****"  # Show masked password
echo ""
echo "Network Configuration:"
echo "  IP Range:   192.168.4.2 - 192.168.4.100"
echo "  Gateway:    192.168.4.1"
echo "  Subnet:     255.255.255.0"
echo "  DNS:        8.8.8.8, 8.8.4.4"
echo ""
echo "Internet Sharing:"
echo "  From: $INTERNET_INTERFACE → To: $WIFI_INTERFACE"
echo ""
echo "Configuration files:"
echo "  WiFi: $AP_CONF"
echo "  DHCP: $DNSMASQ_CONF"
echo "  Log:  $LOG_FILE"
echo "========================================="
echo "Run 'sudo $0 --help' for usage information"
echo "========================================="

# 10. Optional: Show connected clients
echo ""
read -p "Show connected clients? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Monitoring for connected clients (Ctrl+C to stop)..."
    echo "Clients will appear here when they connect."
    sudo tail -f /var/log/syslog 2>/dev/null | grep -i "dnsmasq-dhcp.*bound" || \
    sudo tail -f "$LOG_FILE" 2>/dev/null | grep -i "AP-STA"
fi
