# Setup guide — PS4 "Trust Issues"

Gets you from a fresh machine to **five containers Up**. For *running* the
attacks/demo afterwards, see `TEAMMATE-GUIDE.md`; for the full command runbook,
`README.md`.

Pick the path that matches your machine:
- **Path A — Native Linux (Ubuntu)** — recommended; the switch-level mitigation works here.
- **Path B — Windows 11 + WSL2 + Docker Desktop** — works, minus host bridge rules.

---

## 0. What you need
| Requirement | Why |
|---|---|
| Linux (native or WSL2 Ubuntu) | the lab uses Linux networking (ARP/DHCP, bridges) |
| Docker Engine **+ Compose v2 plugin** | builds and runs the containers |
| Python 3 | the two dashboards (stdlib only — no pip installs) |
| `sudo` | `bridge_rules.sh` (ebtables) and host-side `tcpdump` |
| ~2 GB disk, internet | first image build pulls `python:3.12-slim` + apt packages |

Verify the essentials:
```bash
docker --version
docker compose version        # MUST print a version (v2). If "not found", see Troubleshooting.
python3 --version
```

---

## Path A — Native Linux (Ubuntu)

### A1. Install Docker + Compose plugin (if missing)
```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
# run docker without sudo (log out/in afterwards):
sudo usermod -aG docker $USER
```

### A2. (optional) kernel modules for switch-level rules
```bash
sudo modprobe br_netfilter ebtables ebtable_filter 2>/dev/null || true
```
These let `mitigation/bridge_rules.sh` load bridge ebtables rules. If they're
missing you can still run everything except that one script (static ARP still
defends).

Continue to **"Common steps"** below.

---

## Path B — Windows 11 + WSL2 + Docker Desktop

### B1. Enable WSL integration
Docker Desktop → **Settings → Resources → WSL Integration** → toggle **ON** for
your Ubuntu distro → **Apply & Restart**. Open a **new** WSL terminal so the PATH
updates, then confirm:
```bash
docker compose version
```
If it still says "not found", your distro is using a bare `docker.io` without the
plugin — run `sudo apt install -y docker-compose-plugin`.

### B2. Work from the Linux home directory, not /mnt/c or /mnt/f
Windows-mounted paths cause permission/line-ending issues. Copy the project into
your WSL home first:
```bash
cp -r /mnt/f/ps4-trust-issues ~/ps4-trust-issues    # or git clone (below)
cd ~/ps4-trust-issues
```

> Note: on Docker Desktop the lab bridge lives inside Desktop's VM, so host-side
> `tcpdump -i <bridge>` and `bridge_rules.sh` won't work. Everything else does;
> use `mitigation/mitigate.sh` (static ARP + nftables) for mitigation here.

Continue to **"Common steps"** below.

---

## Common steps (both paths)

### 1. Get the code
```bash
git clone https://github.com/TheCodeVirtuoso/ps4_secure_hackthon.git
cd ps4_secure_hackthon
```

### 2. Build and start
```bash
docker compose up -d --build      # ~1–2 min first time
docker compose ps                 # expect 5 containers "Up"
```
You want to see:
```
trust-gateway   trust-dhcp   trust-victim   trust-attacker   trust-detector    ... Up
```

### 3. Verify the lab is healthy
```bash
docker compose exec victim curl -s http://172.30.0.2/ ; echo
docker compose exec victim ip -br addr          # eth0 = 172.30.0.10
```
The curl should return the payroll HTML. If so, **setup is complete** — go to
`TEAMMATE-GUIDE.md` to run the demo.

---

## Troubleshooting (issues we actually hit)
| Symptom | Fix |
|---|---|
| `docker compose: not found` | `sudo apt install -y docker-compose-plugin`; on Windows enable WSL integration + open a new terminal |
| `unknown shorthand flag: 'd'` / `unknown command: docker compose` | same as above — you have docker without the Compose v2 plugin |
| `cannot connect to the Docker daemon` | `sudo systemctl start docker`; or start Docker Desktop |
| `permission denied` running docker | add yourself to the docker group (A1) and re-login, or prefix `sudo` |
| container shows **Restarting/Exited** | `docker compose logs <name>` (e.g. `docker compose logs gateway`) |
| `./mitigation/*.sh: Permission denied` | `chmod +x mitigation/*.sh` (clones from this repo are already executable) |
| scripts fail with `bad interpreter: ...^M` | CRLF line endings — the repo forces LF via `.gitattributes`; if you copied from Windows, run `sed -i 's/\r$//' mitigation/*.sh` |
| `bridge_rules.sh`: "kernel doesn't support the ebtables filter table" | Docker Desktop limitation — use `mitigate.sh` instead, or run on native Linux (Path A) |
| legit DHCP not offering | `docker compose restart dhcp-server` (the compose fix is already in this repo) |

---

## What runs where
| Capability | Native Linux (A) | Windows/WSL Desktop (B) |
|---|---|---|
| Build + run lab | ✅ | ✅ |
| Attacks (ARP, DHCP, bypass) | ✅ | ✅ |
| Detector + dashboards | ✅ | ✅ |
| `mitigate.sh` (static ARP + nftables) | ✅ | ✅ |
| `bridge_rules.sh` (ebtables switch rules) | ✅ | ❌ (kernel lacks bridge-netfilter) |
| host-side `tcpdump -i <bridge>` | ✅ | ❌ (bridge in Desktop VM) |

### Reset / stop
```bash
./mitigation/mitigate.sh clear          # remove mitigation
docker compose down                     # stop + remove containers
docker compose down --rmi all -v        # also remove the built image + network
```
