# PS4 "Trust Issues" — Attack, Detect, Mitigate (Full Report)

**Event:** Secure Networks Hackathon  **Level:** Intermediate
**Scenario:** An insider on the office LAN intercepts a colleague's traffic. We
reproduce it (Layer 2 ARP + Layer 3 DHCP/DNS), detect it in <10 s, and stop it.

> Environment note: the lab ran on **Windows 11 + WSL2 + Docker Desktop**. One
> finding below is specifically about that backend's kernel; we also document
> what changes on **native Linux**, where the full switch-level controls run.

---

## 1. Lab topology

One custom Docker bridge (`trust-lan`, `br-trust`, `172.30.0.0/24`) = the office switch.
All boxes share the same image (`trust-lab`), differing only by command.

| Host | IP | Real MAC (this run) | Role |
|---|---|---|---|
| gateway | 172.30.0.2 | `6e:c7:be:52:e1:67` | office router + plain-HTTP page |
| dhcp-server | 172.30.0.3 | `ba:60:59:4f:92:fe` | legitimate DHCP (dnsmasq) |
| victim | 172.30.0.10 | (varies) | colleague being intercepted |
| attacker | 172.30.0.66 | `92:9b:a5:63:88:4d` | malicious insider |
| detector | 172.30.0.50 | — | monitoring box |

Bring up: `docker compose up -d --build`.

---

## 2. What we built (attacks) — and exactly what the attacker sees

### 2.1 ARP cache poisoning — T1557.002  → enables T1040
`attack/arp_spoof.py` (Scapy). Sends unsolicited ARP replies telling the victim
"gateway 172.30.0.2 is-at **attacker MAC**" and the gateway the reverse, every 2 s.
IP-forwarding on the attacker relays traffic so nothing breaks.

**Proof (real):** victim's cache flipped
`172.30.0.2 → 6e:c7:be:52:e1:67` **→** `172.30.0.2 → 92:9b:a5:63:88:4d`.

**What the attacker then sees (plaintext HTTP MITM):** full request/response —
URLs, `Host`, `User-Agent`, the session **`Cookie`**, the **`Authorization: Bearer`**
token, the **POST login body** (`user=jdoe&password=Hunter2!`), and the response
body (`SECRET: wire $50k…`). Verified live in the attacker console.

### 2.2 Rogue DHCP + DNS hijack — T1557.003
`attack/rogue_dhcp/dnsmasq.conf`. The rogue answers DHCP faster/authoritatively,
handing the victim gateway **and** DNS = `172.30.0.66` (the attacker). It also runs
as a **forging DNS server** (`address=/payroll.corp/172.30.0.66`).

**Proof (real):** `DHCPOFFER/ACK ... from 172.30.0.66`; victim lease server-id = `.66`.

**What the attacker sees/does (beyond ARP):**
- **Every DNS query** the victim makes (a map of what they do).
- **Forges answers** → `payroll.corp` resolves to the attacker, redirecting the
  victim to a **FAKE payroll page** (pharming), while the name looks legitimate.
- As the victim's gateway, all **off-subnet** traffic routes through the attacker.

> ARP vs DHCP: ARP intercepts two hosts *on the same subnet*; DHCP spoofing
> intercepts the victim's path *off* the subnet **and** grants DNS control.

### 2.3 Bypass attack (defense-gap demo) — T1557.002
`arp_spoof.py --gateway 172.30.0.3` poisons the victim's entry for the **DHCP
server**, a host our mitigation did **not** pin. It succeeds *even after* mitigation,
proving static ARP/DAI only protects the hosts you explicitly cover.

### 2.4 Sniffing — T1040
With either MITM in place, `tcpdump`/the attacker console reads the above in cleartext.

---

## 3. Detection — `detector/detector.py` (alerts in <10 s; measured ~1–2 s)

Event-driven Scapy sniffer, run **on the victim** (where the unicast poison actually
arrives — a passive box on another port never sees it; that's why switches need SPAN).

- **ARP:** learns the real gateway MAC; alerts on gateway-MAC mismatch / IP-MAC
  conflict; counts gratuitous-ARP floods (stretch goal).
- **DHCP:** alerts on any OFFER/ACK from a server ≠ `172.30.0.3`, printing the rogue's
  advertised gateway/DNS.

**Measured latency: ~2 s from the first spoofed packet to the console alert**
(requirement <10 s ✅). It re-alerts every 2 s, proving persistent re-poisoning.
(On a real switched network a passive detector needs a SPAN/mirror port or a
switch-side check; here we co-locate it on the victim.)

---

## 4. How we stop it (mitigation) — layered

| Layer | Control | Stops | Status on Docker Desktop |
|---|---|---|---|
| L2 host | **Static ARP** `ip neigh … nud permanent` | ARP poisoning | ✅ works — poison ignored |
| L2 host | **nftables DAI** (arp family) on victim | forged gateway ARP | ✅ where kernel supports it |
| L2 switch | **ebtables DAI + DHCP snooping** on the bridge (`bridge_rules.sh`) | ARP + rogue DHCP at the switch | **Implemented; pending validation** — kernel lacks bridge-netfilter, validate on native Linux |
| L3/port | **Port isolation (incident response)** (`docker compose stop attacker`) | all attacks from that port *after detection* | ✅ works (this is isolation/response, not MAC-pinning port security) |
| Host cfg | **DHCP client discipline** (critical hosts static) | rogue lease impact | ✅ |

**Proof the attacker is blocked (real):**
- ARP: cache held `172.30.0.2 … 6e:c7:be:52:e1:67 PERMANENT` while the spoof ran;
  attacker `tcpdump` = **`0 packets captured`** (was full `GET /` + secret before).
- DHCP: after quarantine, victim re-leases from `172.30.0.3`, route via `172.30.0.2`.

**Auto-defense (SOAR):** the SOC console can auto-run mitigate + quarantine the
instant it detects an attack, reporting detect→respond latency in ms.

---

## 5. What we did NOT do / honest limitations

1. **No bridge-level L2 filtering on Docker Desktop.** Its LinuxKit kernel reports
   *"kernel doesn't support the ebtables 'filter' table"* — no bridge-netfilter. So on
   this backend we used static ARP + nftables (host) + port quarantine. The
   switch-level `bridge_rules.sh` (ebtables DAI/snooping) is the correct control and
   **runs on native Linux** (teammate's laptop) — documented, not hand-waved.
2. **Host nftables can't stop `dhclient`.** `dhclient` uses a raw packet socket
   (`LPF`) that taps below nftables, so host DHCP-snooping is bypassed — DHCP snooping
   genuinely belongs on the switch/bridge.
3. **Exposure window is non-zero.** Detection+response shrink but can't eliminate it;
   data sent in plaintext during the window (we saw the secret + creds) is already
   compromised. See §6.
4. **Static ARP must cover every critical host.** The bypass attack (§2.3) poisons an
   unpinned host — a real limitation we chose to demonstrate rather than hide.
5. **Compose bug found & fixed:** a YAML folded block (`>`) with deeper-indented
   continuation lines preserved newlines, splitting the dnsmasq args so the legit
   server silently came up **DNS-only**. Fixed by putting the command on one line.

---

## 6. Encryption — what we use, and the M1041 story

**In the lab today: none — deliberately.** The test server serves **plain HTTP**, and
the victim sends credentials/tokens in cleartext, *specifically so the attack is
visible*. That is the vulnerable baseline, by design.

**The recommended defense — MITRE M1041 (Encrypt Sensitive Information):** serve the
app over **TLS/HTTPS**. Then, even during a *successful* MITM, the attacker captures
only ciphertext — the `Cookie`, `Bearer` token, password POST and page secret are
unreadable. Encryption is the layer that protects data **during** the breach window,
where prevention (stop the MITM) and detection (shrink the window) cannot.

> Status: HTTPS is **proposed/optional**, not yet wired into the lab. A 1-file add
> (self-signed TLS on the test server) would let the attacker console show encrypted
> bytes mid-attack — a strong closing demo if time allows.

**Layered conclusion:** Prevent (static ARP/DAI/snooping) + Detect/Respond (detector +
auto-quarantine) + **Encrypt (M1041)** — each layer shrinks the attacker's success at
a different stage.

---

## 7. Bonus / stretch delivered
- **Live SOC console** (`dashboard/dashboard.py`, :8080): reads the real lab via
  `docker`, drives all attacks/defenses with buttons, **AUTO-DEFENSE** auto-responds
  with ms latency, defense-layers panel, event timeline.
- **Attacker view** (`dashboard/attacker_view.py`, :8081): streams real `tcpdump` —
  shows the stolen creds/secret live, and goes **BLINDED** the instant we mitigate.
- **Auto-quarantine** of the offending port; **gratuitous-ARP flood** detection.

---

## 8. ATT&CK / D3FEND / Mitigations

| Technique | In this lab | Detection (D3FEND: Network Traffic Analysis) | Mitigation |
|---|---|---|---|
| **T1557.002** ARP Cache Poisoning | `arp_spoof.py` (+bypass) | detector ARP rules | Static ARP + DAI (M1031) |
| **T1557.003** DHCP Spoofing / DNS hijack | rogue dnsmasq + forged DNS | detector DHCP rule | DHCP snooping + quarantine (M1030/M1031) |
| **T1040** Network Sniffing | attacker `tcpdump`/console | (prevented upstream) | **Encrypt — M1041** |

**D3FEND:** Network Traffic Analysis, Inbound Traffic Filtering, Network Isolation.
**Mitigations:** M1030 (Segmentation), M1031 (Intrusion Prevention),
M1037 (Filter Network Traffic), M1041 (Encrypt Sensitive Information).

---

## 9. How to run (quick)
```bash
docker compose up -d --build
# attacks/mitigation via terminal (README) OR the consoles:
python3 dashboard/dashboard.py        # defender  -> http://localhost:8080
python3 dashboard/attacker_view.py    # attacker  -> http://localhost:8081
# native-Linux only, real switch-level controls:
sudo ./mitigation/bridge_rules.sh apply
```
See `README.md` for the full step-by-step runbook and before/after capture commands.
