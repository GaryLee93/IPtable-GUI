#!/bin/bash

# Listen to each line from rsyslog
iptables -t nat -F OUTPUT
journalctl -kf | while read line; do
  IP=$(echo "$line" | grep -oP 'SRC=\K[\d.]+')
  if echo "$line" | grep -q "QUOTA_EXCEEDED"; then
    echo "QUOTA EXCEEDED!!!!!!!!!!!!!!!!!!!!!!!!!! $IP"
    # iptables -t nat -I OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8000

    # Or: Run a custom script, send a signal, log to DB, etc.
  fi
done

