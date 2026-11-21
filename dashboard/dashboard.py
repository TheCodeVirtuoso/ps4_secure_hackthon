#!/usr/bin/env python3
"""
dashboard.py  --  live auto-defending SOC console for the Trust Issues lab
==========================================================================
Zero-dependency (stdlib only). Runs on the WSL host, READS the real lab via
`docker` and can DRIVE it (ARP attack / DHCP attack / mitigate / quarantine /
reset) from on-screen buttons or fully automatically (AUTO-DEFENSE).

Run from ~/ps4-trust-issues so ./mitigation/mitigate.sh resolves:
    python3 dashboard/dashboard.py   ->  http://localhost:8080
"""
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 8080
GATEWAY_IP = "172.30.0.2"
ATTACKER_IP = "172.30.0.66"
LEGIT_DHCP = "172.30.0.3"

LOCK = threading.Lock()
STATE, EVENTS = {}, []
AUTO = False
LAST_RESPONSE_MS = None
_attack_seen_at = None


def log_event(kind, text):
    with LOCK:
        # store epoch seconds; the browser formats it in the viewer's local TZ
        EVENTS.append({"ts": time.time(), "kind": kind, "text": text})
        del EVENTS[:-40]


def _run(args, timeout=6):
    try:
        return subprocess.check_output(args, stderr=subprocess.DEVNULL,
                                       timeout=timeout).decode(errors="replace").strip()
    except Exception:
        return ""


def sh(args, timeout=30):
    try:
        subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        pass


# ============================ reading the lab ===============================
def container_running(name):
    return _run(["docker", "inspect", "-f", "{{.State.Running}}", name]) == "true"


def real_mac(container):
    return _run(["docker", "inspect", "-f",
                 "{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}",
                 container]).lower()


def real_gateway_mac():
    return real_mac("trust-gateway")


def victim_arp(ip):
    """Victim's cached MAC + state for any IP (e.g. gateway .2 or dhcp .3)."""
    toks = _run(["docker", "exec", "trust-victim", "ip", "neigh", "show", ip]).split()
    mac = toks[toks.index("lladdr") + 1].lower() if "lladdr" in toks else ""
    flag = next((s for s in ("PERMANENT", "REACHABLE", "STALE", "DELAY", "FAILED") if s in toks), "")
    return mac, flag


def victim_default_route():
    toks = _run(["docker", "exec", "trust-victim", "ip", "route", "show", "default"]).split()
    return toks[toks.index("via") + 1] if "via" in toks else ""


def victim_dhcp_server():
    """Server-identifier from the victim's most recent DHCP lease (who leased it)."""
    out = _run(["docker", "exec", "trust-victim", "sh", "-c",
                "grep -h dhcp-server-identifier /var/lib/dhcp/dhclient*.leases 2>/dev/null | tail -1"])
    for tok in out.replace(";", " ").split():
        if tok.count(".") == 3:
            return tok
    return ""


def gather():
    attacker_up = container_running("trust-attacker")
    gw_mac = real_gateway_mac()
    dhcp_mac = real_mac("trust-dhcp")
    vic_mac, arp_flag = victim_arp(GATEWAY_IP)
    sec_mac, sec_flag = victim_arp(LEGIT_DHCP)          # the UN-pinned critical host
    route_via = victim_default_route()
    dhcp_srv = victim_dhcp_server()

    # --- ARP on the gateway (the host we DO pin) ---------------------------
    static_arp = (arp_flag == "PERMANENT")
    if vic_mac and gw_mac and vic_mac != gw_mac:
        arp = {"state": "POISONED", "detail": f"gateway {GATEWAY_IP} → {vic_mac} (attacker's MAC)"}
    elif static_arp:
        arp = {"state": "PROTECTED", "detail": f"pinned to {vic_mac or gw_mac} · PERMANENT"}
    elif vic_mac:
        arp = {"state": "CLEAN", "detail": f"gateway {GATEWAY_IP} = {vic_mac} (real)"}
    else:
        arp = {"state": "UNKNOWN", "detail": "no ARP entry yet"}

    # --- ARP on the DHCP server (the host we DID NOT pin = the bypass gap) --
    sec_static = (sec_flag == "PERMANENT")
    bypassed = bool(sec_mac and dhcp_mac and sec_mac != dhcp_mac)
    if bypassed:
        sec = {"state": "POISONED", "detail": f"host {LEGIT_DHCP} → {sec_mac} — UNPINNED host poisoned!"}
    elif sec_static:
        sec = {"state": "PROTECTED", "detail": f"pinned to {sec_mac} · PERMANENT"}
    elif sec_mac:
        sec = {"state": "CLEAN", "detail": f"host {LEGIT_DHCP} = {sec_mac} (real)"}
    else:
        sec = {"state": "UNKNOWN", "detail": "no ARP entry yet"}

    # --- DHCP ---------------------------------------------------------------
    rogue_lease = (dhcp_srv == ATTACKER_IP)
    if route_via == ATTACKER_IP or rogue_lease:
        dhcp = {"state": "HIJACKED", "detail": f"lease from rogue {ATTACKER_IP}"
                + (f", route via {route_via}" if route_via == ATTACKER_IP else "")}
    elif route_via:
        dhcp = {"state": "CLEAN", "detail": f"route via {route_via}"
                + (f", lease from {dhcp_srv}" if dhcp_srv else "")}
    else:
        dhcp = {"state": "UNKNOWN", "detail": "no default route"}

    quarantine = {"state": "ONLINE" if attacker_up else "OFFLINE",
                  "detail": "attacker container running" if attacker_up
                            else "attacker stopped · port quarantined"}

    attacked = arp["state"] == "POISONED" or dhcp["state"] == "HIJACKED" or bypassed
    if attacked:
        overall = "UNDER ATTACK"
    elif arp["state"] == "PROTECTED" or not attacker_up:
        overall = "MITIGATED"
    else:
        overall = "SECURE"

    defenses = [
        {"name": "Static ARP / DAI (gateway)", "att": "M1031", "active": static_arp,
         "desc": "Gateway MAC pinned PERMANENT — forged gateway ARP replies are ignored."},
        {"name": "DHCP snooping", "att": "M1031", "active": (not attacker_up),
         "desc": f"Rogue DHCP server isolated — only {LEGIT_DHCP} may hand out leases."},
        {"name": "Port security / quarantine", "att": "M1030", "active": (not attacker_up),
         "desc": "Attacker's switch port administratively shut down (container stopped)."},
        {"name": "ARP coverage — ALL critical hosts", "att": "gap", "active": (static_arp and sec_static),
         "desc": f"Every critical host must be pinned. The DHCP server ({LEGIT_DHCP}) is NOT pinned → a bypass gap the '💀 Bypass' attack exploits."},
    ]

    return {"overall": overall, "arp": arp, "dhcp": dhcp, "secondary": sec,
            "quarantine": quarantine, "real_gateway_mac": gw_mac, "defenses": defenses}


# ============================ driving the lab ===============================
def ensure_legit_dhcp():
    # Start a known-good DHCP-only dnsmasq on the legit server (idempotent:
    # a duplicate just fails to bind :67 and exits). Guarantees .3 can lease.
    sh(["docker", "compose", "exec", "-d", "dhcp-server", "dnsmasq", "--log-dhcp",
        "--port=0", "--interface=eth0", "--bind-interfaces", "--dhcp-authoritative",
        "--dhcp-range=172.30.0.100,172.30.0.150,12h",
        "--dhcp-option=3,172.30.0.2", "--dhcp-option=6,172.30.0.2"])


def do_attack():
    sh(["docker", "compose", "up", "-d", "attacker"])
    sh(["docker", "compose", "exec", "-d", "attacker", "python3", "/lab/attack/arp_spoof.py"])
    log_event("attack", "ARP spoof launched (T1557.002) — poisoning victim↔gateway")


def do_dhcp_attack():
    sh(["docker", "compose", "up", "-d", "attacker"])
    # stand up a FAKE payroll page on the attacker so the DNS redirect lands
    sh(["docker", "compose", "exec", "-d", "attacker", "sh", "-c",
        "mkdir -p /tmp/fake && printf "
        "'<h1>FAKE Payroll Login</h1><form>user<input>pass<input></form>' "
        "> /tmp/fake/index.html && cd /tmp/fake && python3 -m http.server 80"])
    # rogue DHCP + forging DNS
    sh(["docker", "compose", "exec", "-d", "attacker", "dnsmasq", "--no-daemon",
        "--log-dhcp", "--conf-file=/lab/attack/rogue_dhcp/dnsmasq.conf"])
    sh(["docker", "compose", "exec", "victim", "dhclient", "-r", "eth0"], timeout=10)
    sh(["docker", "compose", "exec", "victim", "dhclient", "-v", "eth0"], timeout=18)
    # what the rogue lease's DNS option does: make the rogue the victim's resolver
    sh(["docker", "compose", "exec", "victim", "sh", "-c",
        "echo 'nameserver 172.30.0.66' > /etc/resolv.conf"])
    log_event("attack", "Rogue DHCP + DNS hijack: victim resolver → attacker, payroll.corp forged (T1557.003)")


def do_bypass_attack():
    # Poison a host our mitigation did NOT pin (the DHCP server .3). arp_spoof.py
    # already parameterises the target via --gateway, so we aim it at .3. Static
    # ARP only covers the gateway, so this poison LANDS even after 'Mitigate'.
    sh(["docker", "compose", "up", "-d", "attacker"])
    # seed a live ARP entry for .3 so the poison has something to overwrite
    sh(["docker", "compose", "exec", "victim", "ping", "-c", "1", "172.30.0.3"], timeout=6)
    sh(["docker", "compose", "exec", "-d", "attacker", "python3",
        "/lab/attack/arp_spoof.py", "--gateway", "172.30.0.3"])
    log_event("attack", "BYPASS: poisoning unpinned host 172.30.0.3 (static ARP only covers the gateway)")


def do_mitigate():
    sh(["./mitigation/mitigate.sh", "apply"])
    log_event("defend", "Static ARP pinned + nftables DAI/snoop applied")


def do_quarantine():
    sh(["docker", "compose", "stop", "attacker"])
    log_event("defend", "Attacker port quarantined (switch port shut down)")
    # If the victim is holding a rogue lease, refresh it from the legit server.
    if victim_dhcp_server() == ATTACKER_IP:
        ensure_legit_dhcp()
        sh(["docker", "compose", "exec", "victim", "dhclient", "-r", "eth0"], timeout=10)
        sh(["docker", "compose", "exec", "victim", "dhclient", "-v", "eth0"], timeout=18)
        log_event("defend", "Victim re-leased from legit server (172.30.0.3)")


def do_reset():
    sh(["docker", "compose", "exec", "attacker", "pkill", "-f", "arp_spoof.py"])
    sh(["docker", "compose", "exec", "attacker", "pkill", "dnsmasq"])
    sh(["docker", "compose", "exec", "attacker", "pkill", "-f", "http.server"])
    sh(["./mitigation/mitigate.sh", "clear"])
    sh(["docker", "compose", "up", "-d", "attacker"])
    sh(["docker", "compose", "restart", "victim"])   # also restores victim's real resolv.conf
    ensure_legit_dhcp()
    with LOCK:
        globals()["_attack_seen_at"] = None
        globals()["LAST_RESPONSE_MS"] = None
    log_event("reset", "Lab reset to clean, vulnerable baseline")


CONTROLS = {"attack": do_attack, "dhcp": do_dhcp_attack, "bypass": do_bypass_attack,
            "mitigate": do_mitigate, "quarantine": do_quarantine, "reset": do_reset}


# ========================= background monitor ===============================
def monitor_loop():
    global STATE, _attack_seen_at, LAST_RESPONSE_MS
    prev = None
    while True:
        snap = gather()
        with LOCK:
            STATE = snap
        o = snap["overall"]
        if o != prev:
            if o == "UNDER ATTACK":
                _attack_seen_at = time.time()
                if snap["arp"]["state"] == "POISONED":
                    which = "gateway ARP cache poisoned"
                elif snap["secondary"]["state"] == "POISONED":
                    which = "BYPASS — unpinned host (172.30.0.3) poisoned despite mitigation"
                else:
                    which = "rogue DHCP lease"
                log_event("alert", f"⚠ ATTACK DETECTED — {which}")
            elif o == "MITIGATED":
                log_event("ok", "Defenses holding — attack neutralized")
            elif o == "SECURE":
                log_event("ok", "All clear — segment secure")
            prev = o
        if AUTO and o == "UNDER ATTACK" and _attack_seen_at:
            t0 = _attack_seen_at
            log_event("auto", "AUTO-DEFENSE engaged → mitigate + quarantine")
            do_mitigate()
            do_quarantine()
            LAST_RESPONSE_MS = int((time.time() - t0) * 1000)
            log_event("auto", f"AUTO-DEFENSE complete in {LAST_RESPONSE_MS} ms")
            _attack_seen_at = None
        time.sleep(1.0)


# ================================ web ========================================
PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<title>Trust Issues — SOC Console</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#070b16;--card:#101a33;--card2:#0c1529;--ink:#eef3ff;--mut:#7f93bf;
  --red:#ff4d5e;--amber:#ffb020;--green:#2ecd7a;--blue:#4c8dff;--line:#1f2d4d;--line2:#2a3c63}
*{box-sizing:border-box}
body{margin:0;color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,Segoe UI,Roboto,Arial;
  background:
    radial-gradient(900px 500px at 80% -15%,rgba(76,141,255,.10),transparent 60%),
    radial-gradient(700px 500px at 0% 0%,rgba(46,205,122,.06),transparent 55%),
    linear-gradient(#070b16,#070b16)}
.wrap{max-width:1120px;margin:0 auto;padding:22px 16px 60px}
h1{font-size:20px;margin:0 0 2px}.sub{color:var(--mut);margin:0;font-size:13px}
code{background:#0b1427;padding:1px 6px;border-radius:5px;color:#b9c7ef;font-size:.92em}

.banner{position:relative;overflow:hidden;border-radius:16px;padding:24px 26px;margin:18px 0 6px;
  border:1px solid var(--line2);transition:background .5s ease}
.banner h2{margin:0;font-size:30px;font-weight:800;letter-spacing:.6px;display:flex;align-items:center;gap:14px}
.banner p{margin:7px 0 0;color:#c7d3f0;font-size:13.5px;opacity:.9}
.dot{width:16px;height:16px;border-radius:50%}
.b-attack{background:linear-gradient(120deg,#43121d,#2a0f24)}.b-attack .dot{background:var(--red);animation:pulse 1s infinite}
.b-mit{background:linear-gradient(120deg,#33280f,#122a24)}.b-mit .dot{background:var(--amber);animation:pulse 1.6s infinite}
.b-safe{background:linear-gradient(120deg,#0f3324,#0e2130)}.b-safe .dot{background:var(--green)}
@keyframes pulse{0%{box-shadow:0 0 0 0 currentColor;opacity:1}70%{box-shadow:0 0 0 13px rgba(0,0,0,0);opacity:.6}100%{opacity:1}}
.flash{animation:flash .9s ease}@keyframes flash{0%{filter:brightness(2)}100%{filter:brightness(1)}}
.scan{position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.07),transparent);transform:translateX(-100%)}
.b-attack .scan{animation:scan 2.1s linear infinite}@keyframes scan{to{transform:translateX(100%)}}

.bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:14px 0 4px}
button{cursor:pointer;border:1px solid var(--line2);background:#111c37;color:var(--ink);
  padding:9px 14px;border-radius:10px;font-weight:600;font-size:13.5px;transition:.15s}
button:hover{transform:translateY(-1px)}button:active{transform:translateY(0)}
.ba:hover{border-color:var(--red);box-shadow:0 0 0 3px rgba(255,77,94,.12)}
.bd:hover{border-color:var(--green);box-shadow:0 0 0 3px rgba(46,205,122,.12)}
.br:hover{border-color:var(--blue);box-shadow:0 0 0 3px rgba(76,141,255,.12)}
.spin{opacity:.45;pointer-events:none}
.toggle{margin-left:auto;display:flex;align-items:center;gap:10px;color:var(--mut);font-size:12.5px;font-weight:600}
.sw{width:46px;height:26px;border-radius:999px;background:#25324e;position:relative;transition:.2s}
.sw b{position:absolute;top:3px;left:3px;width:20px;height:20px;border-radius:50%;background:#fff;transition:.2s}
.sw.on{background:var(--green)}.sw.on b{left:23px}

.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(235px,1fr));gap:13px;margin-top:12px}
.card{background:linear-gradient(180deg,var(--card),var(--card2));border:1px solid var(--line);
  border-radius:14px;padding:15px;position:relative}
.card:before{content:"";position:absolute;inset:0 0 auto 0;height:1px;border-radius:14px 14px 0 0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.14),transparent)}
.card h3{font-size:11.5px;letter-spacing:.7px;text-transform:uppercase;color:#aebbdd;margin:0 0 3px}
.att{font-size:10px;color:#6177a7;margin:0 0 10px;font-family:ui-monospace,monospace}
.pill{display:inline-block;padding:3px 11px;border-radius:999px;font-weight:700;font-size:13px;transition:.3s}
.p-bad{background:rgba(255,77,94,.16);color:var(--red)}.p-warn{background:rgba(255,176,32,.16);color:var(--amber)}
.p-ok{background:rgba(46,205,122,.16);color:var(--green)}.p-mut{background:rgba(142,160,200,.16);color:var(--mut)}
.detail{color:var(--mut);margin-top:9px;font-size:12.5px;word-break:break-word}
.why{margin-top:10px;font-size:11.5px;color:#718ab8;border-top:1px dashed var(--line2);padding-top:8px}

.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:16px}
@media(max-width:820px){.cols{grid-template-columns:1fr}}
.panel{background:linear-gradient(180deg,var(--card),var(--card2));border:1px solid var(--line);border-radius:14px;padding:16px}
.panel h3{margin:0 0 12px;font-size:13px;letter-spacing:.4px;display:flex;align-items:center;gap:8px}

/* defense layers */
.layer{display:flex;gap:11px;padding:10px 0;border-bottom:1px solid #16213c}
.layer:last-child{border-bottom:0}
.led{flex:0 0 12px;width:12px;height:12px;border-radius:50%;margin-top:4px;background:#30405f;transition:.3s}
.layer.on .led{background:var(--green);box-shadow:0 0 10px rgba(46,205,122,.7)}
.layer .nm{font-weight:700;font-size:13px}.layer.on .nm{color:#bdf0d4}
.layer .st{font-size:10.5px;font-weight:700;color:#5f7093;margin-left:6px}
.layer.on .st{color:var(--green)}
.layer .ds{font-size:11.5px;color:#8698c2;margin-top:2px}

.stat{display:flex;gap:12px;margin:0 0 12px;flex-wrap:wrap}
.stat .b{background:#0c1730;border:1px solid var(--line);border-radius:10px;padding:9px 13px;min-width:116px}
.stat .n{font-size:21px;font-weight:800}.stat .l{font-size:10.5px;color:var(--mut)}
.tl{list-style:none;margin:0;padding:0;max-height:240px;overflow:auto}
.tl li{display:flex;gap:10px;padding:6px 0;border-bottom:1px solid #16213c;animation:slide .35s ease}
@keyframes slide{from{opacity:0;transform:translateX(-8px)}to{opacity:1}}
.tl time{color:#6177a7;font-family:ui-monospace,monospace;font-size:12px;flex:0 0 62px}
.tl .k{flex:0 0 8px;width:8px;height:8px;border-radius:50%;margin-top:5px}
.k-alert,.k-attack{background:var(--red)}.k-defend,.k-ok,.k-auto{background:var(--green)}.k-reset{background:var(--blue)}
.tl .tx{font-size:12.5px}
.foot{color:#4f638f;font-size:11.5px;margin-top:20px;text-align:center}
</style></head><body><div class=wrap>
 <div><h1>🛡️ Trust Issues — Live SOC Console</h1>
   <p class=sub>Reads &amp; drives the real lab via <code>docker</code> · ARP T1557.002 · DHCP T1557.003 · Sniffing T1040</p></div>

 <div id=banner class=banner><div class=scan></div>
   <h2><span class=dot></span><span id=bannertext>…</span></h2><p id=bannersub></p></div>

 <div class=bar>
   <button class=ba onclick="ctl('attack',this)">🎯 ARP attack</button>
   <button class=ba onclick="ctl('dhcp',this)">📡 DHCP attack</button>
   <button class=ba onclick="ctl('bypass',this)">💀 Bypass attack</button>
   <button class=bd onclick="ctl('mitigate',this)">🛡️ Mitigate</button>
   <button class=bd onclick="ctl('quarantine',this)">⛔ Quarantine</button>
   <button class=br onclick="ctl('reset',this)">↺ Reset</button>
   <div class=toggle>AUTO-DEFENSE <div id=sw class=sw onclick="toggleAuto()"><b></b></div></div>
 </div>

 <div class=grid>
   <div class=card><h3>ARP — gateway integrity</h3><p class=att>T1557.002 · ARP Cache Poisoning</p>
     <span id=arp class=pill>…</span><div id=arpd class=detail></div>
     <div class=why>Is the victim's cached MAC for the gateway real, or the attacker's? <code>PERMANENT</code> = static-ARP lock.</div></div>
   <div class=card><h3>DHCP — default route</h3><p class=att>T1557.003 · DHCP Spoofing</p>
     <span id=dhcp class=pill>…</span><div id=dhcpd class=detail></div>
     <div class=why>Who leased the victim its address &amp; gateway? <code>172.30.0.66</code> = a rogue server won the race.</div></div>
   <div class=card><h3>Secondary host — DHCP .3</h3><p class=att>T1557.002 · bypass target</p>
     <span id=sec class=pill>…</span><div id=secd class=detail></div>
     <div class=why>We pinned the <b>gateway</b> but not the DHCP server. The <code>💀 Bypass</code> attack poisons this host — it stays red even after Mitigate, showing static ARP must cover <i>every</i> critical host.</div></div>
   <div class=card><h3>Attacker port</h3><p class=att>Port Security</p>
     <span id=q class=pill>…</span><div id=qd class=detail></div>
     <div class=why>Stopping the container = administratively disabling the malicious switch port.</div></div>
   <div class=card><h3>Trusted baseline</h3><p class=att>ground truth</p>
     <div class=detail>Real gateway MAC<br><b id=gwmac>…</b></div>
     <div class=why>Read from the gateway container — the value every ARP reply is checked against.</div></div>
 </div>

 <div class=cols>
   <div class=panel><h3>🛡️ Defense layers — how we're blocking it</h3><div id=layers></div></div>
   <div class=panel><h3>📜 Event timeline</h3>
     <div class=stat>
       <div class=b><div class=n id=resp>—</div><div class=l>auto-response latency</div></div>
       <div class=b><div class=n id=mode>OFF</div><div class=l>auto-defense</div></div>
     </div><ul class=tl id=tl></ul></div>
 </div>
 <p class=foot>PS4 Secure Networks Hackathon · local console · executes docker on your host</p>
</div><script>
const cls={POISONED:'p-bad',HIJACKED:'p-bad',ONLINE:'p-warn',PROTECTED:'p-ok',OFFLINE:'p-ok',CLEAN:'p-ok',SECURE:'p-ok',UNKNOWN:'p-mut'};
const sub={'UNDER ATTACK':'An insider is intercepting the victim’s traffic.',
  'MITIGATED':'Attack detected and neutralized — defenses holding.',
  'SECURE':'Segment healthy — no interception detected.'};
let last='', lastLen=-1;
async function tick(){
  let s; try{ s=await (await fetch('/api/state')).json(); }
  catch(e){ document.getElementById('bannertext').textContent='docker unreachable'; return; }
  const b=document.getElementById('banner'),bt=document.getElementById('bannertext');
  if(s.overall!==last){ b.classList.add('flash'); setTimeout(()=>b.classList.remove('flash'),900); last=s.overall; }
  bt.textContent=s.overall; document.getElementById('bannersub').textContent=sub[s.overall]||'';
  b.className='banner '+(s.overall=='UNDER ATTACK'?'b-attack':s.overall=='MITIGATED'?'b-mit':'b-safe');
  const set=(id,o)=>{const e=document.getElementById(id);e.textContent=o.state;
    e.className='pill '+(cls[o.state]||'p-mut');document.getElementById(id+'d').textContent=o.detail;};
  set('arp',s.arp);set('dhcp',s.dhcp);set('sec',s.secondary);set('q',s.quarantine);
  document.getElementById('gwmac').textContent=s.real_gateway_mac||'(unknown)';
  document.getElementById('resp').textContent=s.last_response_ms==null?'—':(s.last_response_ms+' ms');
  document.getElementById('mode').textContent=s.auto?'ON':'OFF';
  document.getElementById('sw').className='sw'+(s.auto?' on':'');
  // defense layers
  const L=document.getElementById('layers');L.innerHTML='';
  s.defenses.forEach(d=>{const el=document.createElement('div');el.className='layer'+(d.active?' on':'');
    el.innerHTML=`<span class=led></span><div><div class=nm>${d.name}<span class=st>${d.active?'ACTIVE':'INACTIVE'}</span></div><div class=ds>${d.desc}</div></div>`;
    L.appendChild(el);});
  // timeline
  if(s.events.length!==lastLen){ lastLen=s.events.length;const tl=document.getElementById('tl');tl.innerHTML='';
    s.events.slice().reverse().forEach(ev=>{const li=document.createElement('li');
      const tm=new Date(ev.ts*1000).toLocaleTimeString();
      li.innerHTML=`<time>${tm}</time><span class="k k-${ev.kind}"></span><span class=tx>${ev.text}</span>`;tl.appendChild(li);});}
}
async function ctl(a,btn){btn.classList.add('spin');try{await fetch('/api/control?action='+a);}catch(e){}
  setTimeout(()=>btn.classList.remove('spin'),1400);tick();}
async function toggleAuto(){await fetch('/api/auto?t=1');tick();}
tick();setInterval(tick,1200);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global AUTO
        u = urlparse(self.path)
        if u.path == "/api/state":
            with LOCK:
                snap = dict(STATE) if STATE else gather()
                snap["events"] = list(EVENTS); snap["auto"] = AUTO
                snap["last_response_ms"] = LAST_RESPONSE_MS
            return self._json(snap)
        if u.path == "/api/auto":
            with LOCK:
                AUTO = not AUTO
            log_event("auto", f"Auto-defense turned {'ON' if AUTO else 'OFF'}")
            return self._json({"auto": AUTO})
        if u.path == "/api/control":
            action = parse_qs(u.query).get("action", [""])[0]
            fn = CONTROLS.get(action)
            if fn:
                threading.Thread(target=fn, daemon=True).start()
                return self._json({"ok": True})
            return self._json({"ok": False})
        body = PAGE.encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    threading.Thread(target=monitor_loop, daemon=True).start()
    log_event("ok", "SOC console started")
    print(f"[*] Trust Issues SOC console -> http://localhost:{PORT}")
    print("[*] Buttons drive the lab; AUTO-DEFENSE auto-responds. Ctrl-C to stop.")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
