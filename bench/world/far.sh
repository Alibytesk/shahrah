#!/bin/sh
if [ -n "$FAR" ]; then
  count=1
  for pair in $FAR; do count=$((count+1)); done
  map=""
  i=0
  while [ $i -lt 16 ]; do map="$map 0"; i=$((i+1)); done
  tc qdisc add dev eth0 root handle 1: prio bands $count priomap $map 2>/dev/null
  band=2
  for pair in $FAR; do
    host=${pair%%:*}; delay=${pair##*:}
    ip=$(getent hosts "$host" | awk '{print $1; exit}')
    [ -z "$ip" ] && continue
    tc qdisc add dev eth0 parent 1:$band handle ${band}0: \
      netem delay "${delay}ms" 1ms distribution normal 2>/dev/null
    tc filter add dev eth0 protocol ip parent 1: prio 1 u32 \
      match ip dst "$ip"/32 flowid 1:$band 2>/dev/null
    echo "this proxy is ${delay}ms from $host ($ip)"
    band=$((band+1))
  done
fi
exec /usr/local/bin/shahrah-proxy "$@"
