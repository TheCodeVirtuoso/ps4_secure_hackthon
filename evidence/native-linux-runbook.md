# Native-Linux validation runbook

Goal: on a **native Linux** host (not Docker Desktop), prove the **switch-level**
controls that Docker Desktop's kernel couldn't run — turning the report's
"Implemented; pending validation" rows into **Validated**.

Why it's needed: Docker Desktop's LinuxKit kernel has no bridge-netfilter, so
`ebtables`/nftables-bridge rules can't load. A normal Linux distro's kernel does,
so `mitigation/bridge_rules.sh` runs for real and drops forged ARP + rogue DHCP
**at the bridge**.

Run everything from the repo root. Save all outputs into
`evidence/native-linux/` and commit them.

## 0. Bring up the lab
```bash
docker compose up -d --build
docker compose ps | tee evidence/native-linux/00_compose_ps.txt
# confirm the bridge is visible in THIS host's namespace (unlike Docker Desktop):
ip -br link show type bridge | tee evidence/native-linux/00_bridges.txt
```

## 1. Baseline (before mitigation)
```bash
docker compose exec victim ip neigh show 172.30.0.2 | tee evidence/native-linux/10_arp_before.txt
```

## 2. Apply the switch-level controls and capture the ruleset
```bash
sudo ./mitigation/bridge_rules.sh apply   | tee evidence/native-linux/20_apply.txt
sudo ./mitigation/bridge_rules.sh status  | tee evidence/native-linux/21_status.txt
# the actual installed L2 ruleset + hit counters (THE key evidence):
sudo ebtables -L FORWARD --Lc            | tee evidence/native-linux/22_ebtables.txt
```

## 3. Prove ARP poisoning is dropped at the bridge
```bash
# start the attack in another terminal:
docker compose exec attacker python3 /lab/attack/arp_spoof.py
# while it runs, the victim cache must stay on the REAL gateway MAC:
docker compose exec victim ip neigh show 172.30.0.2 | tee evidence/native-linux/30_arp_blocked.txt
# capture the forged replies being dropped (counter climbs on the ARP rule):
sudo ebtables -L FORWARD --Lc | tee evidence/native-linux/31_ebtables_hits.txt
```

## 4. Prove the rogue DHCP offer is dropped at the bridge (the real win)
```bash
# start rogue DHCP on the attacker:
docker compose exec -d attacker dnsmasq --no-daemon --log-dhcp \
   --conf-file=/lab/attack/rogue_dhcp/dnsmasq.conf
# victim asks for a lease; snoop rule drops the rogue's frames at the bridge:
docker compose exec victim dhclient -v eth0 | tee evidence/native-linux/40_dhcp.txt
# EXPECT: offer only from 172.30.0.3, NOT 172.30.0.66
```

## 5. Before/after packet captures (optional but strong)
```bash
BR=$(ip -br addr | awk '/172.30.0.1/{print $1}')   # the lab bridge
sudo tcpdump -i "$BR" -w evidence/native-linux/before_after.pcap 'arp or port 67 or port 80'
# run the attack then the mitigation while this captures; Ctrl-C to stop.
```

## 6. Commit the evidence
```bash
git add evidence/native-linux && git commit -m "Add native-Linux validation evidence"
git push
```

Then tell the team: the report's `ebtables DAI + DHCP snooping` row can change from
**"Implemented; pending validation"** to **"Validated (native Linux) — see evidence/"**.
