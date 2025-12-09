#!/bin/bash
# Script: kill.sh
# Purpose: Emergency termination of hotspot (no cleanup)
# Usage: sudo ./kill.sh

echo "EMERGENCY HOTSPOT KILL"
echo "======================"

# Kill everything immediately
sudo pkill -9 hostapd
sudo pkill -9 dnsmasq
sudo pkill -9 wpa_supplicant

# Reset interface
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed 2>/dev/null || true

# Disable forwarding
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null

echo "✓ Hotspot forcefully terminated"
echo "⚠ No cleanup performed - run cleanup script to restore networking"
