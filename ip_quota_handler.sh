#!/bin/bash

# Listen to each line from rsyslog
iptables -t nat -F OUTPUT
iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 -j ACCEPT
journalctl -kf --since now | while read line; do
  IP=$(echo "$line" | grep -oP 'DST=\K[\d.]+')
  echo "$line"
  if echo "$line" | grep -q "QUOTA_EXCEEDED"; then
    iptables -t nat -C OUTPUT -p tcp -d "$IP" --dport 443 -j REDIRECT --to-port 8000 2>/dev/null || \
    iptables -t nat -A OUTPUT -p tcp -d "$IP" --dport 443 -j REDIRECT --to-port 8000
    iptables -t nat -C OUTPUT -p tcp -d "$IP" --dport 80 -j REDIRECT --to-port 8000 2>/dev/null || \
    iptables -t nat -A OUTPUT -p tcp -d "$IP" --dport 80 -j REDIRECT --to-port 8000

  fi
  if echo "$line" | grep -q "QUOTAHTTP_EXCEEDED"; then
    if echo "$line" | grep -oP 'DPT=443'; then
      iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:8000
    fi
    if echo "$line" | grep -oP 'DPT=80'; then
      iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8000
    fi
  fi
done

