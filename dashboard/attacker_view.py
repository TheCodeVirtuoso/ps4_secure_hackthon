#!/usr/bin/env python3
"""
attacker_view.py  --  the ATTACKER's screen (companion to dashboard.py)
=======================================================================
Shows, live, what the insider actually sees while the MITM is active: the
victim's plaintext HTTP flowing through the attacker (T1040 Network Sniffing).
It streams REAL `tcpdump` from the attacker container — nothing is simulated.

The whole point for the demo: with the ARP MITM running, the victim's traffic
is routed through the attacker, so this feed fills with the victim's requests
and the secret on the payroll page. The instant you MITIGATE (static ARP), the
victim's traffic stops flowing through the attacker and this screen goes DARK —
"BLINDED". That side-by-side with the defender console is the proof.

USAGE (WSL host):  python3 dashboard/attacker_view.py   ->  http://localhost:8081
Run it next to dashboard.py (port 8080): attacker screen left, defender right.
"""
import json, subprocess, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8081
LOCK = threading.Lock()
FEED = []            # [{ts, text}]
LAST_SEEN = 0.0
REQ_COUNT = 0
ARP_ACTIVE = False   # is the ARP spoof process running in the attacker?
DHCP_ACTIVE = False  # is the rogue dnsmasq running in the attacker?
KEYS = ("GET ", "POST ", "Host:", "User-Agent", "SECRET", "Payroll", "HTTP/1",
        "Cookie:", "Authorization", "Bearer", "password", "user=", "login", "account=",
        "payroll.corp", "A?", "FAKE")   # DNS queries + the forged/fake-page hit


def _proc_running(pattern):
    """True if a process matching `pattern` is alive inside the attacker."""
    try:
        subprocess.check_output(["docker", "exec", "trust-attacker", "pgrep", "-f", pattern],
                                stderr=subprocess.DEVNULL, timeout=4)
        return True
    except Exception:
        return False


def status_loop():
    """Poll which attacks the insider is actively running (ARP + rogue DHCP)."""
    global ARP_ACTIVE, DHCP_ACTIVE
    while True:
        ARP_ACTIVE = _proc_running("arp_spoof.py")
        DHCP_ACTIVE = _proc_running("dnsmasq")
        time.sleep(1.5)


def sniff_loop():
    """Continuously stream tcpdump from the attacker; retry if the container
    goes away (e.g. after quarantine). Keeps only human-readable HTTP lines."""
    global LAST_SEEN, REQ_COUNT
    while True:
        try:
            p = subprocess.Popen(
                ["docker", "exec", "trust-attacker", "tcpdump", "-i", "eth0",
                 "-l", "-n", "-A", "tcp port 80 or udp port 53"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except Exception:
            time.sleep(2); continue
        try:
            for line in p.stdout:
                line = line.rstrip()
                if any(k in line for k in KEYS):
                    with LOCK:
                        FEED.append({"ts": time.time(), "text": line[:200]})
                        del FEED[:-60]
                        LAST_SEEN = time.time()
                        # the tcpdump summary line "… HTTP: GET / HTTP/1.1" = 1 request
                        if "HTTP: GET" in line or "HTTP: POST" in line:
                            REQ_COUNT += 1
        except Exception:
            pass
        time.sleep(1.5)   # tcpdump ended (container stopped?) -> loop + retry


PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<title>Attacker View — Intercept</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#120608;--panel:#1c0b0f;--ink:#ffe9ec;--mut:#c98b94;--red:#ff3b50;--grey:#7a6a6d;--line:#3a1620}
*{box-sizing:border-box}
body{margin:0;color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,Arial;
  background:radial-gradient(800px 400px at 80% -10%,rgba(255,59,80,.14),transparent 60%),#120608}
.wrap{max-width:900px;margin:0 auto;padding:22px 16px 50px}
h1{font-size:19px;margin:0 0 2px}.sub{color:var(--mut);margin:0;font-size:13px}
.banner{border-radius:16px;padding:22px 24px;margin:16px 0;border:1px solid var(--line);
  display:flex;align-items:center;gap:14px;transition:.4s}
.banner h2{margin:0;font-size:26px;font-weight:800;letter-spacing:.5px}
.banner p{margin:4px 0 0;color:var(--mut);font-size:13px}
.dot{width:16px;height:16px;border-radius:50%}
.live{background:linear-gradient(120deg,#430f17,#2a0a12)}.live .dot{background:var(--red);animation:pulse 1s infinite}
.blind{background:linear-gradient(120deg,#1c1416,#140d0f)}.blind .dot{background:var(--grey)}
@keyframes pulse{0%{box-shadow:0 0 0 0 var(--red);opacity:1}70%{box-shadow:0 0 0 13px rgba(0,0,0,0);opacity:.5}100%{opacity:1}}
.acts{display:flex;gap:10px;margin:0 0 14px;flex-wrap:wrap}
.act{padding:6px 12px;border-radius:999px;font-size:12.5px;font-weight:700;border:1px solid var(--line);
  background:#1a0e11;color:var(--grey);transition:.3s}
.act.on{color:#fff;background:rgba(255,59,80,.22);border-color:var(--red);box-shadow:0 0 12px rgba(255,59,80,.35)}
.stat{display:flex;gap:12px;margin:0 0 14px;flex-wrap:wrap}
.stat .b{background:#1a0a0e;border:1px solid var(--line);border-radius:10px;padding:9px 14px;min-width:130px}
.stat .n{font-size:22px;font-weight:800}.stat .l{font-size:10.5px;color:var(--mut)}
.feed{background:#0c0406;border:1px solid var(--line);border-radius:12px;padding:14px;
  font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px;height:420px;overflow:auto}
.feed div{padding:2px 0;white-space:pre-wrap;word-break:break-all;animation:fin .3s ease}
@keyframes fin{from{opacity:0;transform:translateX(-6px)}to{opacity:1}}
.secret{color:#fff;background:rgba(255,59,80,.28);font-weight:700;border-radius:4px;padding:2px 4px}
.req{color:#ff9aa6}.hdr{color:#c98b94}.t{color:#6f5156;margin-right:8px}
.foot{color:#7a5a60;font-size:11.5px;margin-top:16px;text-align:center}
.empty{color:var(--grey);text-align:center;padding:40px 0}
</style></head><body><div class=wrap>
 <h1>🩸 Attacker View — Live Intercept</h1>
 <p class=sub>Real <code>tcpdump</code> from the attacker container · T1040 Network Sniffing</p>
 <div id=banner class=banner><span class=dot></span>
   <div><h2 id=bt>…</h2><p id=bs></p></div></div>
 <div class=acts>
   <span id=aarp class=act>🎯 ARP spoof: idle</span>
   <span id=adhcp class=act>📡 Rogue DHCP: idle</span>
 </div>
 <div class=stat>
   <div class=b><div class=n id=cnt>0</div><div class=l>requests intercepted</div></div>
   <div class=b><div class=n id=seen>—</div><div class=l>last seen</div></div>
 </div>
 <div class=feed id=feed><div class=empty>waiting for victim traffic…</div></div>
 <p class=foot>When defenders pin static ARP, the victim's traffic stops flowing through here — this screen goes dark.</p>
</div><script>
function esc(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
async function tick(){
  let s; try{ s=await (await fetch('/api/intercept')).json(); }catch(e){ return; }
  const live=s.intercepting, b=document.getElementById('banner');
  b.className='banner '+(live?'live':'blind');
  document.getElementById('bt').textContent=live?'INTERCEPTING VICTIM TRAFFIC':'BLINDED — no visibility';
  document.getElementById('bs').textContent=live
    ?'The victim’s traffic is routed through the attacker — reading it in cleartext.'
    :'Traffic no longer flows through the attacker. Defenses are holding.';
  document.getElementById('cnt').textContent=s.count;
  document.getElementById('seen').textContent=s.last_seen? new Date(s.last_seen*1000).toLocaleTimeString():'—';
  const aa=document.getElementById('aarp'),ad=document.getElementById('adhcp');
  aa.className='act'+(s.arp_active?' on':'');aa.textContent='🎯 ARP spoof: '+(s.arp_active?'ACTIVE':'idle');
  ad.className='act'+(s.dhcp_active?' on':'');ad.textContent='📡 Rogue DHCP: '+(s.dhcp_active?'ACTIVE':'idle');
  const f=document.getElementById('feed');
  if(!s.lines.length){ f.innerHTML='<div class=empty>waiting for victim traffic…</div>'; return; }
  f.innerHTML='';
  s.lines.forEach(ln=>{let t=esc(ln.text);
    let cl=/SECRET|password|Bearer|Cookie:|user=|account=|FAKE/.test(ln.text)?'secret'
          :(/HTTP: (GET|POST)|A\? |payroll\.corp/.test(ln.text))?'req':'hdr';
    const d=document.createElement('div');
    d.innerHTML=`<span class=t>${new Date(ln.ts*1000).toLocaleTimeString()}</span><span class=${cl}>${t}</span>`;
    f.appendChild(d);});
  f.scrollTop=f.scrollHeight;
}
tick();setInterval(tick,1000);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/api/intercept"):
            with LOCK:
                obj = {"intercepting": (time.time() - LAST_SEEN) < 6 and LAST_SEEN > 0,
                       "lines": list(FEED), "count": REQ_COUNT,
                       "last_seen": LAST_SEEN or None,
                       "arp_active": ARP_ACTIVE, "dhcp_active": DHCP_ACTIVE}
            body = json.dumps(obj).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body); return
        body = PAGE.encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    threading.Thread(target=sniff_loop, daemon=True).start()
    threading.Thread(target=status_loop, daemon=True).start()
    print(f"[*] Attacker view -> http://localhost:{PORT}")
    print("[*] Streams real tcpdump from trust-attacker. Ctrl-C to stop.")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
