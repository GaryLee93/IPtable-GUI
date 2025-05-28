#!/bin/bash

# Listen to each line from rsyslog
iptables -t nat -F OUTPUT
journalctl -kf | while read line; do
  IP=$(echo "$line" | grep -oP 'DST=\K[\d.]+')
  if echo "$line" | grep -q "QUOTA_EXCEEDED"; then
    echo "QUOTA EXCEEDED!!!!!!!!!!!!!!!!!!!!!!!!!! $IP"
    iptables -t nat -C OUTPUT -p tcp -d "$IP" --dport 443 -j REDIRECT --to-ports 8000 2>/dev/null || \
    iptables -t nat -I OUTPUT -p tcp -d "$IP" --dport 443 -j REDIRECT --to-destination 127.0.0.1 --to-port 8000
    iptables -t nat -C OUTPUT -p tcp -d "$IP" --dport 80 -j REDIRECT --to-ports 8000 2>/dev/null || \
    iptables -t nat -I OUTPUT -p tcp -d "$IP" --dport 80 -j REDIRECT --to-destination 127.0.0.1 --to-port 8000

  fi
  if echo "$line" | grep -q "QUOTA_RESET"; then
    iptables -t nat -F OUTPUT 
  fi
done

