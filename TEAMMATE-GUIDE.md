# Teammate Guide — run the "Trust Issues" lab

Everything you need to clone, run, and demo the PS4 Trust Issues project on your
**Ubuntu** laptop. No prior context needed. ~10 min to a working demo.

> What this is: a safe, containerised lab where an "attacker" box intercepts a
> "victim's" traffic via ARP poisoning + rogue DHCP, a detector alerts in <10 s,
> and mitigations stop it. Two web dashboards show it live.
>
> ⚠️ Only run this against the containers in this repo. Never point the attacks
> at a real network or anyone else's device.

---

## 0. Prerequisites (one-time)
```bash
# Docker Engine + the compose plugin:
docker compose version      # must print a version. If "not found":
sudo apt update && sudo apt install -y docker-compose-plugin
# (if docker itself is missing, install Docker Engine from docs.docker.com)

# You also need: python3 (for the dashboards) and sudo (for ebtables/tcpdump).
python3 --version
```
If `docker` needs sudo every time, add yourself to the docker group:
`sudo usermod -aG docker $USER` then log out/in.

---

## 1. Clone and build
```bash
git clone https://github.com/TheCodeVirtuoso/ps4_secure_hackthon.git
cd ps4_secure_hackthon
docker compose up -d --build        # ~1-2 min first time
docker compose ps                   # expect 5 containers "Up":
# trust-gateway  trust-dhcp  trust-victim  trust-attacker  trust-detector
```

Quick sanity check (victim reaches the gateway, note the REAL gateway MAC):
```bash
docker compose exec victim curl -s http://172.30.0.2/ ; echo
docker compose exec victim ip neigh show 172.30.0.2     # remember this MAC
```

---

## 2. Easiest demo — the two web consoles
Open **two terminals**, both in the repo folder:
```bash
# terminal A — defender console
python3 dashboard/dashboard.py        #  http://localhost:8080
# terminal B — attacker view
python3 dashboard/attacker_view.py    #  http://localhost:8081
```
Open both URLs in a browser, side by side (attacker left, defender right).

**Drive it from the defender console buttons** (turn AUTO-DEFENSE **off** first to
watch the attack land):
1. **↺ Reset** → defender SECURE, attacker BLINDED.
2. **🎯 ARP attack** → attacker screen fills with the victim's stolen cookie /
   token / password / secret; defender goes UNDER ATTACK.
3. **📡 DHCP attack** → attacker becomes the victim's DNS, shows the forged
   `payroll.corp` + a FAKE page redirect.
4. **💀 Bypass attack** → poisons an un-pinned host (shows a defense gap).
5. **🛡️ Mitigate** → attacker goes BLINDED, defender MITIGATED.
6. **⛔ Quarantine** → attacker port OFFLINE.
Then flip **AUTO-DEFENSE on** and hit **🎯 ARP attack** to see hands-free
detect→respond with the latency in ms.

> The dashboards are real: they read/drive the lab with `docker` under the hood.

---

## 3. Manual demo (terminal, for understanding the mechanics)
```bash
# detector (leave running, run ON the victim where the poison lands):
docker compose cp detector/detector.py victim:/tmp/detector.py
docker compose exec victim python3 /tmp/detector.py        # terminal 1

# attack (terminal 2):
docker compose exec attacker python3 /lab/attack/arp_spoof.py
#   -> detector alerts "ARP SPOOF — GATEWAY HIJACK" within ~2s

# confirm the MITM (terminal 3):
docker compose exec victim ip neigh show 172.30.0.2        # now = attacker MAC
docker compose exec attacker sh -c "tcpdump -i eth0 -A -n 'tcp port 80' -c 20"
#   -> you SEE the victim's GET + credentials in cleartext
```
Ctrl-C the spoof to auto-restore the ARP caches.

---

## 4. ⭐ Your special job: the native-Linux mitigation (the big one)
On Windows/Docker Desktop the bridge firewall couldn't load (kernel limitation).
**Your native Ubuntu CAN run it** — this is the evidence we need:
```bash
sudo ./mitigation/bridge_rules.sh apply      # real switch-level DAI + DHCP snooping
sudo ./mitigation/bridge_rules.sh status
```
Follow **`evidence/native-linux-runbook.md`** step by step — it captures the
`ebtables` ruleset, the ARP poison failing, and the rogue DHCP offer being
dropped, into `evidence/native-linux/`. Then:
```bash
git add evidence/native-linux && git commit -m "native-linux validation evidence" && git push
```
Tell the team once done — it upgrades the report from "pending validation" to
**Validated**.

---

## 5. Reset / stop
```bash
# from the dashboard: click ↺ Reset. Or manually:
docker compose exec attacker pkill -f arp_spoof.py 2>/dev/null
sudo ./mitigation/bridge_rules.sh clear
docker compose down          # stop everything
```

---

## 6. Troubleshooting (issues we actually hit)
| Symptom | Fix |
|---|---|
| `docker compose: not found` | `sudo apt install docker-compose-plugin` |
| `cannot connect to the Docker daemon` | `sudo systemctl start docker`; add self to docker group |
| a container shows **Restarting/Exited** | `docker compose logs <name>` (e.g. `gateway`) and share it |
| attack says **`eth0 not found`** | attacker got detached — `docker compose up -d attacker` |
| dashboard shows **"docker unreachable"** | run it from the repo root; ensure `docker ps` works without sudo |
| `bridge_rules.sh` says ebtables table missing | `sudo modprobe ebtables ebtable_filter br_netfilter` |
| legit DHCP not offering | `docker compose restart dhcp-server` (the compose fix is already in this repo) |

---

## 7. What's where
```
docker-compose.yml / Dockerfile   the lab (5 boxes on one bridge)
attack/arp_spoof.py               Scapy ARP poisoning (MITM)
attack/rogue_dhcp/dnsmasq.conf    rogue DHCP + forging DNS
detector/detector.py              Scapy detector (<10s alerts)
mitigation/mitigate.sh            static ARP + nftables (works anywhere)
mitigation/bridge_rules.sh        ebtables bridge rules (native Linux)
dashboard/dashboard.py            defender SOC console  (:8080)
dashboard/attacker_view.py        attacker live view    (:8081)
report/                           writeup.md + one-pager.pdf + report.pdf
evidence/native-linux-runbook.md  YOUR validation steps
```

Stuck? Grab the exact error output and send it to the team — most issues are in
the table above.
