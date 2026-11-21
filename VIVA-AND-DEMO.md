# Viva prep & demo script — PS4 "Trust Issues"

Keep this open while presenting. Part 1 is the live demo (what to click, what to
say). Part 2 is a Q&A bank for the viva, grouped by topic, with short answers you
can say out loud.

---

## PART 1 — Demo script (~5 minutes)

**Before judges arrive:**
```bash
docker compose up -d --build            # lab Up
python3 dashboard/dashboard.py          # terminal A -> localhost:8080 (defender)
python3 dashboard/attacker_view.py      # terminal B -> localhost:8081 (attacker)
```
Open both URLs side by side (attacker left, defender right). **Turn AUTO-DEFENSE OFF** to start.

**One-line intro:** "An insider on the office LAN intercepts a colleague's traffic. We reproduce it, detect it in under 10 seconds, and stop it — live, on two screens."

| Beat | Click / do | Say |
|---|---|---|
| 1. Baseline | **↺ Reset** | "Both sides clean — attacker blind, defender SECURE." |
| 2. ARP attack | **🎯 ARP attack** | "Forged ARP makes the victim's gateway point at the attacker. Watch the left screen — we're now reading the victim's **cookie, token, password and the secret** in cleartext." (point at the red SECRET line) |
| 3. Detect | (defender already red) | "The detector flagged it in ~2 seconds — gateway-MAC mismatch." |
| 4. Mitigate | **🛡️ Mitigate** | "Static ARP pins the real gateway MAC as PERMANENT. The attack is still firing, but the attacker's feed just went **BLINDED** — zero packets. The thief is blind." |
| 5. DHCP attack | **↺ Reset**, then **📡 DHCP attack** | "Different attack: a rogue DHCP makes us the victim's DNS. We forge payroll.corp and redirect them to a **fake login page** — pharming." |
| 6. Bypass (honesty) | **🛡️ Mitigate**, then **💀 Bypass** | "We're honest about limits: static ARP only covers hosts we pin. Poison an *un-pinned* host and it still lands — which is why real DAI lives on the switch." |
| 7. Auto-defense | flip **AUTO-DEFENSE ON**, **🎯 ARP attack** | "Hands-free: it detects and auto-mitigates in milliseconds — a mini SOAR loop." |

**"Is this real or a mock-up?" (if asked):** run, next to the browser,
```bash
docker compose exec victim ip neigh show 172.30.0.2   # the cached MAC the dashboard reads
```
"The dashboard just runs `docker` and `ip neigh` under the hood — same data, live."

**Closing line:** "Prevent, detect-and-respond, and encrypt — three layers that shrink the attacker's success at every stage. Code, a 32-page report and a one-pager are all in the repo."

---

## PART 2 — Viva questions & model answers

### A. ARP
**Q: What is ARP and why is it exploitable?**
Maps an IP to a MAC on a LAN. It has no authentication and hosts accept unsolicited ("gratuitous") replies, overwriting the cache — so anyone can claim to be the gateway.

**Q: What exactly does your ARP attack send?**
Unicast ARP *replies* (op=2) every 2s: to the victim, "gateway 172.30.0.2 is-at <attacker MAC>"; to the gateway, the reverse. Both caches then point at us.

**Q: Why every 2 seconds?**
Real replies and cache timeouts would heal the entry; re-sending keeps us in the middle.

**Q: Why does the victim keep working during the attack?**
We enable `ip_forward` on the attacker, so we relay packets on to the real gateway — a transparent MITM.

**Q: How does static ARP stop it?**
`ip neigh ... nud permanent` marks the gateway entry permanent; the kernel never overwrites it from an ARP reply, so the poison is ignored.

**Q: What's Dynamic ARP Inspection (DAI)?**
A switch feature that checks each ARP reply against a trusted IP↔MAC table (from DHCP snooping) and drops mismatches. We emulate it with nftables/ebtables.

### B. DHCP & DNS
**Q: How does the rogue DHCP attack work?**
DHCP is first-offer-wins with no server auth. Our rogue answers authoritatively and hands the victim a lease where gateway (option 3) and DNS (option 6) are the attacker.

**Q: What does DHCP spoofing give you that ARP doesn't?**
DNS control. As the resolver we see every lookup and can forge answers — redirect a legit hostname to our fake page (pharming). ARP can't do that.

**Q: What is DHCP snooping?**
A switch control that only trusts DHCP server replies (UDP sport 67) from an authorized port/MAC and drops all others — killing the rogue.

**Q: Why couldn't host nftables stop dhclient?**
`dhclient` uses a raw packet socket (LPF) that taps below the netfilter hook, so host rules never see those frames. DHCP snooping must be on the switch/bridge, dropping the frame on the wire.

### C. Detection
**Q: How does your detector work and how fast is it?**
Event-driven Scapy sniffer: learns the real gateway MAC, then alerts on a gateway-MAC mismatch, an IP-MAC change, an ARP flood, or a DHCP offer from an untrusted server. ~2s from first spoofed packet to alert (<10s required).

**Q: Why run the detector on the victim, not a separate box?**
ARP poison is *unicast* to the victim; a bridge only forwards unicast to the destination port, so a passive box elsewhere never sees it. On real hardware you'd use a SPAN/mirror port or switch-side DAI logging.

**Q: What's a gratuitous-ARP flood and how do you catch it?**
A burst of unsolicited ARP replies. We count replies in a sliding window and alert past a threshold (stretch goal).

### D. Mitigation & architecture
**Q: What's the difference between port security and what you did?**
Port security = bind one MAC per switch port and drop unexpected source MACs. We did *port isolation* — stop the attacker container after detection (incident response). We're explicit about that distinction.

**Q: Why does the bridge mitigation only run on native Linux?**
Docker Desktop's LinuxKit kernel has no bridge-netfilter — `ebtables` reports "kernel doesn't support the filter table." A normal Linux kernel supports it, so `bridge_rules.sh` runs there for real.

**Q: What is auto-defense / SOAR here?**
The console's monitor loop detects the attack and automatically applies mitigation + isolation, reporting detect→respond latency in ms — security orchestration & automated response.

### E. The honest / tricky ones
**Q: After you mitigated, the attacker had already grabbed the secret — so what did you actually stop?**
We stopped the *ongoing* interception — a persistent MITM would read **all** future traffic and could tamper/redirect. We cut it from "permanent tap" to a brief window, and detection triggers rotating the leaked secret. Encryption (next) closes the window entirely.

**Q: Why is the lab plain HTTP?**
By design, so the theft is visible. The recommended fix is M1041 — TLS/HTTPS — which makes even a successful MITM yield only ciphertext.

**Q: Your DHCP "proof" just removed the attacker — did you prove in-line rejection?**
Honestly, on Docker Desktop we proved the attacker was *isolated* and the victim re-leased from the legit server. In-line bridge rejection of the rogue offer is the native-Linux result (runbook provided, pending validation). We don't overclaim it.

**Q: What are the limitations?**
Host controls cover only pinned hosts (the bypass proves it); dhclient bypasses host nftables; bridge rules pending native-Linux validation; no HTTPS demo yet; two-host scale.

### F. Concepts a judge may probe
**Q: ARP vs DHCP spoofing in one line?**
ARP intercepts two hosts on the same subnet; DHCP spoofing intercepts the off-subnet path and grants DNS control.

**Q: Which MITRE techniques and mitigations?**
T1557.002 (ARP), T1557.003 (DHCP), T1040 (Sniffing). Mitigations M1030, M1031, M1037, M1041. D3FEND: Network Traffic Analysis, Inbound Traffic Filtering, Network Isolation.

**Q: How would you deploy this defense in a real office?**
Managed switches with DHCP snooping + DAI + port security, VLAN segmentation (M1030), 802.1X for port auth, and TLS everywhere so interception yields nothing.

**Q: What would you add with more time?**
Validate bridge rules on native Linux with PCAP evidence, true MAC-pinning port security, the HTTPS demo, and multi-victim/VLAN scale.
