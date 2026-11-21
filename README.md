# PS4 "Trust Issues" — Runbook

Layer-2/3 attack → detect → mitigate lab. Follow top to bottom; each block is
copy-paste. **Run everything from WSL (Ubuntu), from the Linux home copy** — not
from `/mnt/f`, to dodge the file-permission issues:

```bash
cp -r /mnt/f/ps4-trust-issues ~/ps4-trust-issues   # if it's on the Windows side
cd ~/ps4-trust-issues
chmod +x mitigation/bridge_rules.sh
```

## 0. Build & start the lab
```bash
docker compose up -d --build
docker compose ps          # all 5 containers Up
```

## 1. Baseline capture (BEFORE)
```bash
# Host-side capture of the whole segment:
sudo tcpdump -i br-trust -w captures/before_arp.pcap &   # Ctrl-C later
# Victim's clean state:
docker compose exec victim ip neigh            # 172.30.0.2 = REAL gateway MAC
docker compose exec victim curl -s http://172.30.0.2/    # payroll page works
```

## 2. Start the detector (separate terminal, keep it visible)
```bash
docker compose exec detector python3 /lab/detector/detector.py
```

## 3. Attack A — ARP spoof (T1557.002)
```bash
docker compose exec attacker python3 /lab/attack/arp_spoof.py
# -> detector should ALERT within ~1s. Note the time.
# In another terminal, confirm the poison + sniff:
docker compose exec victim ip neigh                       # gateway now = ATTACKER MAC
docker compose exec attacker tcpdump -i eth0 -A port 80   # see victim's plaintext
```
Save: `sudo tcpdump -i br-trust -w captures/after_arp.pcap` (run during attack).
Ctrl-C the attacker script → ARP caches auto-restore.

## 4. Attack B — Rogue DHCP (T1557.003)
```bash
# Start the rogue server:
docker compose exec -d attacker dnsmasq --no-daemon --log-dhcp \
    --conf-file=/lab/attack/rogue_dhcp/dnsmasq.conf
# Force the victim to re-lease:
docker compose exec victim dhclient -v eth0
# -> detector ALERTS "ROGUE DHCP". Confirm the poisoned gateway:
docker compose exec victim ip route        # default via 172.30.0.66 (attacker)
```
Save `captures/before_dhcp.pcap` / `after_dhcp.pcap` around this step.

## 5. Mitigate (switch controls + static ARP)
```bash
sudo ./mitigation/bridge_rules.sh apply
sudo ./mitigation/bridge_rules.sh status
```

## 6. Prove it's blocked (AFTER)
```bash
# Re-run ARP spoof — victim cache must stay on the REAL gateway MAC:
docker compose exec attacker python3 /lab/attack/arp_spoof.py &
docker compose exec victim ip neigh        # still REAL gateway MAC ✅
docker compose exec attacker tcpdump -i eth0 port 80   # silent — no intercept ✅
# Re-run rogue DHCP — victim keeps the REAL gateway:
docker compose exec victim dhclient -v eth0
docker compose exec victim ip route        # default via 172.30.0.2 ✅
```

## 7. Stretch — auto-quarantine the attacker port
```bash
sudo ./mitigation/bridge_rules.sh quarantine
docker compose exec attacker ping -c2 172.30.0.10   # fails — isolated ✅
```

## Reset
```bash
sudo ./mitigation/bridge_rules.sh clear
docker compose down
```

---
## Running on native Linux (recommended for the switch-level mitigation)
On **Windows/WSL + Docker Desktop** the bridge lives inside Desktop's VM and its
kernel has **no bridge-netfilter**, so `ebtables`/nftables-bridge rules can't load
(`"kernel doesn't support the ebtables 'filter' table"`). We fell back to static
ARP + nftables (host) + port isolation there.

On a **native Linux host** the kernel supports it, so `mitigation/bridge_rules.sh`
runs for real and drops forged ARP + rogue DHCP **at the bridge**:
```bash
git clone https://github.com/TheCodeVirtuoso/ps4_secure_hackthon.git
cd ps4_secure_hackthon
docker compose up -d --build
sudo ./mitigation/bridge_rules.sh apply      # switch-level DAI + DHCP snooping
sudo ./mitigation/bridge_rules.sh status
```
To validate and capture evidence, follow **`evidence/native-linux-runbook.md`** —
it turns the report's "pending validation" rows into **Validated**. The dashboards
and the detector also benefit: the lab bridge is visible in the host namespace, so
host-side `tcpdump -i <bridge>` works directly.

---
### If host ebtables isn't available in your WSL kernel
Check with `sudo ebtables -L`. If it errors, load the module
(`sudo modprobe ebtables ebtable_filter br_netfilter`). If your WSL kernel
lacks it entirely, run the same DAI/snooping logic from **inside** the victim
and gateway containers using ebtables on the `INPUT` chain (they have
NET_ADMIN) — same rules, `-A INPUT` instead of `-A FORWARD`. The static-ARP
step alone (`nud permanent`) already defeats the ARP attack with no kernel deps.
