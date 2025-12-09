#!/bin/bash

# Script: clean.sh
# Purpose: Clean shutdown of hotspot and restore normal networking
# Usage: sudo ./clean.sh [--full] [--help]
#        sudo ./clean.sh --full  # Also restores NetworkManager
#        sudo ./clean.sh         # Basic cleanup

set -e  # Exit on any error

echo "========================================="
echo "   Hotspot Cleanup & Network Restore"
echo "========================================="

# Configuration
WIFI_INTERFACE="wlan0"
INTERNET_INTERFACE="eth0"
AP_CONF="/etc/hostapd/hostapd.conf"
DNSMASQ_CONF="/etc/dnsmasq.conf"
LOG_FILE="/tmp/hotspot-cleanup.log"
FULL_CLEANUP=false

# Function to display usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --full          Also restart NetworkManager and restore DHCP"
    echo "  --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --full    # Complete cleanup including NetworkManager"
    echo "  sudo $0           # Basic cleanup (keep NetworkManager stopped)"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            FULL_CLEANUP=true
            shift
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

# Function to log messages with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to check if command succeeded
check_status() {
    if [ $? -eq 0 ]; then
        log "✓ $1"
    else
        log "⚠ $1 (non-critical)"
    fi
}

# Start logging
echo "Hotspot cleanup started at $(date)" > "$LOG_FILE"
log "Starting cleanup process..."

# Display operation mode
if [ "$FULL_CLEANUP" = true ]; then
    log "Performing FULL cleanup (including NetworkManager restore)"
else
    log "Performing BASIC cleanup (NetworkManager will remain stopped)"
fi

echo ""

# 1. Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# 2. Stop hotspot services
log "Stopping hotspot services..."

# Kill processes
log "Killing hostapd..."
sudo pkill -9 hostapd 2>/dev/null || true
check_status "hostapd stopped"

log "Killing dnsmasq..."
sudo pkill -9 dnsmasq 2>/dev/null || true
check_status "dnsmasq stopped"

# Stop services if they're running as services
log "Stopping service daemons..."
sudo systemctl stop hostapd 2>/dev/null || true
sudo systemctl stop dnsmasq 2>/dev/null || true
check_status "services stopped"

# 3. Clean up wpa_supplicant
log "Cleaning up wpa_supplicant..."
sudo pkill -9 wpa_supplicant 2>/dev/null || true
sudo wpa_cli -i "$WIFI_INTERFACE" terminate 2>/dev/null || true
check_status "wpa_supplicant cleaned"

# 4. Reset WiFi interface
log "Resetting $WIFI_INTERFACE interface..."

# Bring interface down
sudo ip link set "$WIFI_INTERFACE" down 2>/dev/null || true
check_status "interface brought down"

# Remove all IP addresses
log "Removing IP addresses from $WIFI_INTERFACE..."
sudo ip addr flush dev "$WIFI_INTERFACE" 2>/dev/null || true
check_status "IP addresses removed"

# Set back to managed mode
log "Setting $WIFI_INTERFACE to managed mode..."
if sudo iw dev "$WIFI_INTERFACE" set type managed 2>/dev/null; then
    log "✓ Interface set to managed mode"
elif sudo iw dev "$WIFI_INTERFACE" set type station 2>/dev/null; then
    log "✓ Interface set to station mode"
else
    log "⚠ Could not set managed mode (interface might not exist)"
fi

# 5. Clean up iptables rules
log "Cleaning up iptables rules..."

# List rules before cleanup (for debugging)
log "Current NAT rules before cleanup:"
sudo iptables -t nat -L POSTROUTING -n 2>/dev/null | tail -n +3 || true

# Remove hotspot-specific NAT rules
log "Removing MASQUERADE rules..."
sudo iptables -t nat -D POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE 2>/dev/null || true

# Remove forwarding rules
log "Removing forwarding rules..."
sudo iptables -D FORWARD -i "$INTERNET_INTERFACE" -o "$WIFI_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
sudo iptables -D FORWARD -i "$WIFI_INTERFACE" -o "$INTERNET_INTERFACE" -j ACCEPT 2>/dev/null || true

# Remove input rules for DHCP/DNS
log "Removing DHCP/DNS firewall rules..."
sudo iptables -D INPUT -i "$WIFI_INTERFACE" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
sudo iptables -D INPUT -i "$WIFI_INTERFACE" -p udp --dport 67:68 -j ACCEPT 2>/dev/null || true
sudo iptables -D INPUT -i "$WIFI_INTERFACE" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true

# Flush all chains if they're empty (optional safety check)
log "Checking for remaining hotspot rules..."
HOTSPOT_RULES=$(sudo iptables-save | grep -c "WIFI_INTERFACE\|192.168.4" || true)
if [ "$HOTSPOT_RULES" -eq 0 ]; then
    log "✓ No remaining hotspot rules in iptables"
else
    log "⚠ $HOTSPOT_RULES hotspot-related rules remain in iptables"
    log "You may want to run: sudo iptables -F && sudo iptables -t nat -F"
fi

check_status "iptables cleaned"

# 6. Disable IP forwarding
log "Disabling IP forwarding..."
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null
sudo sysctl -w net.ipv4.ip_forward=0 >/dev/null
check_status "IP forwarding disabled"

# 7. Clean up configuration files (optional backup)
log "Backing up configuration files..."
BACKUP_DIR="/tmp/hotspot-backup-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p "$BACKUP_DIR" 2>/dev/null || true

if [ -f "$AP_CONF" ]; then
    sudo cp "$AP_CONF" "$BACKUP_DIR/" 2>/dev/null || true
    log "✓ Backed up $AP_CONF"
fi

if [ -f "$DNSMASQ_CONF" ]; then
    sudo cp "$DNSMASQ_CONF" "$BACKUP_DIR/" 2>/dev/null || true
    log "✓ Backed up $DNSMASQ_CONF"
fi

# 8. FULL cleanup mode: Restore normal networking
if [ "$FULL_CLEANUP" = true ]; then
    log "Performing full network restore..."
    
    # Restart NetworkManager
    log "Restarting NetworkManager..."
    sudo systemctl start NetworkManager 2>/dev/null || true
    sleep 2
    
    # Restart systemd-resolved
    log "Restarting systemd-resolved..."
    sudo systemctl start systemd-resolved 2>/dev/null || true
    
    # Bring WiFi interface back up with NetworkManager
    log "Bringing $WIFI_INTERFACE up with NetworkManager..."
    sudo nmcli device connect "$WIFI_INTERFACE" 2>/dev/null || true
    
    # Request DHCP on eth0 if needed
    log "Restoring DHCP on $INTERNET_INTERFACE..."
    sudo dhclient -r "$INTERNET_INTERFACE" 2>/dev/null || true
    sudo dhclient "$INTERNET_INTERFACE" 2>/dev/null || true
    
    check_status "Network services restored"
else
    log "Skipping NetworkManager restore (use --full to enable)"
fi

# 9. Bring interfaces up (basic mode)
if [ "$FULL_CLEANUP" = false ]; then
    log "Bringing interfaces up in basic mode..."
    sudo ip link set "$WIFI_INTERFACE" up 2>/dev/null || true
    sudo ip link set "$INTERNET_INTERFACE" up 2>/dev/null || true
    check_status "Interfaces brought up"
fi

# 10. Verify cleanup
log "Verifying cleanup..."
sleep 2

echo ""
echo "--- Cleanup Verification ---"
echo ""

# Check processes
echo "1. Running hotspot processes:"
if ps aux | grep -E "hostapd|dnsmasq" | grep -v grep >/dev/null; then
    echo "   ✗ Hotspot processes still running:"
    ps aux | grep -E "hostapd|dnsmasq" | grep -v grep | sed 's/^/     /'
else
    echo "   ✓ No hotspot processes running"
fi
echo ""

# Check interface mode
echo "2. Interface $WIFI_INTERFACE mode:"
if sudo iw dev "$WIFI_INTERFACE" info 2>/dev/null | grep -q "type AP"; then
    echo "   ✗ Still in AP mode"
elif sudo iw dev "$WIFI_INTERFACE" info 2>/dev/null | grep -q "type managed"; then
    echo "   ✓ In managed mode"
elif sudo iw dev "$WIFI_INTERFACE" info 2>/dev/null | grep -q "type station"; then
    echo "   ✓ In station mode"
else
    echo "   ⚠ Could not determine interface mode"
fi
echo ""

# Check IP addresses
echo "3. IP addresses on $WIFI_INTERFACE:"
IPS=$(ip addr show "$WIFI_INTERFACE" 2>/dev/null | grep -o 'inet [0-9\.\/]*' | wc -l)
if [ "$IPS" -eq 0 ]; then
    echo "   ✓ No IP addresses assigned"
else
    echo "   ⚠ $IPS IP address(es) still assigned:"
    ip addr show "$WIFI_INTERFACE" 2>/dev/null | grep 'inet ' | sed 's/^/     /' || true
fi
echo ""

# Check IP forwarding
echo "4. IP forwarding:"
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "0" ]; then
    echo "   ✓ IP forwarding disabled"
else
    echo "   ⚠ IP forwarding still enabled"
fi
echo ""

# Check NetworkManager (if full cleanup)
if [ "$FULL_CLEANUP" = true ]; then
    echo "5. NetworkManager status:"
    if systemctl is-active NetworkManager >/dev/null 2>&1; then
        echo "   ✓ NetworkManager is running"
    else
        echo "   ⚠ NetworkManager is not running"
    fi
    echo ""
fi

# Summary
log "Cleanup completed!"
echo "========================================="
echo "CLEANUP SUMMARY"
echo "========================================="
echo "WiFi Interface:      $WIFI_INTERFACE"
echo "Internet Interface:  $INTERNET_INTERFACE"
echo "Cleanup Mode:        $( [ "$FULL_CLEANUP" = true ] && echo "FULL" || echo "BASIC" )"
echo ""
echo "What was done:"
echo "  ✓ Stopped hostapd and dnsmasq"
echo "  ✓ Removed IP addresses from $WIFI_INTERFACE"
echo "  ✓ Set $WIFI_INTERFACE to managed mode"
echo "  ✓ Cleaned iptables rules"
echo "  ✓ Disabled IP forwarding"
if [ "$FULL_CLEANUP" = true ]; then
    echo "  ✓ Restarted NetworkManager"
    echo "  ✓ Restored DHCP on $INTERNET_INTERFACE"
else
    echo "  ℹ NetworkManager remains stopped"
    echo "  ℹ Run with --full to restore normal networking"
fi
echo ""
echo "Backup saved to:     $BACKUP_DIR"
echo "Log file:            $LOG_FILE"
echo "========================================="
echo "Next steps:"
if [ "$FULL_CLEANUP" = true ]; then
    echo "  • Your network should now be back to normal"
    echo "  • Use 'nmcli device wifi' to scan for networks"
else
    echo "  • Run '$0 --full' to completely restore networking"
    echo "  • Or run your hotspot script again to restart"
fi
echo "========================================="

# 11. Optional: Show interface status
read -p "Show detailed interface status? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "--- Detailed Interface Status ---"
    echo ""
    echo "$WIFI_INTERFACE:"
    ip addr show "$WIFI_INTERFACE" 2>/dev/null || echo "  Interface not found"
    echo ""
    echo "$INTERNET_INTERFACE:"
    ip addr show "$INTERNET_INTERFACE" 2>/dev/null || echo "  Interface not found"
    echo ""
    echo "Routing table:"
    ip route show | head -20
fi
