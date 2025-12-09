# WiFi Hotspot Tools

## Files
connect.sh - start AP (eth0→wlan0)  
clean.sh  - stop AP, restore network  
kill.sh   - force kill AP (emergency)

## Usage
```
sudo bash ./connect.sh --ssid NAME --password PASS

sudo bash ./clean.sh --full

sudo bash ./kill.sh
```

## Examples
```
# Start AP
sudo bash ./connect.sh --ssid "office" --password "secret123"

# Clean stop
sudo bash ./clean.sh --full

# Emergency
sudo bash ./kill.sh
```

## Requirements
Linux, iw, hostapd, dnsmasq  
eth0 (net), wlan0 (AP capable)  
root

## Notes
AP: 192.168.4.1/24  
DHCP: 192.168.4.2-100  
Logs: /tmp/hotspot-*.log  

End.
