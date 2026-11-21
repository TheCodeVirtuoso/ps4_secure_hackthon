#!/usr/bin/env bash
# ============================================================================
#  mitigate.sh  --  Docker-Desktop-compatible L2/L3 defenses (runs IN containers)
# ============================================================================
#  Why this exists: on the Docker Desktop backend the lab bridge lives inside
#  Desktop's VM, so host-side ebtables on the bridge can't see it. Instead we
#  push the SAME defenses INTO the victim/gateway containers (they have
#  NET_ADMIN), using static ARP + nftables. Same security outcome.
#
#  Maps to real managed-switch features:
#     static ARP (nud permanent)        == the gold standard vs ARP poisoning
#     nftables arp-reply filter         == Dynamic ARP Inspection (T1557.002)
#     nftables udp-sport-67 filter      == DHCP Snooping          (T1557.003)
#     drop attacker IP (quarantine)     == Port Security / isolation
#
#  MITRE Mitigations: M1030, M1031, M1041.  D3FEND: Inbound Traffic Filtering,
#  Network Isolation, Network Traffic Analysis.
#
#  USAGE (run on the WSL host, from ~/ps4-trust-issues):
#     ./mitigation/mitigate.sh apply        # turn defenses ON
#     ./mitigation/mitigate.sh status       # show what's installed
#     ./mitigation/mitigate.sh quarantine   # STRETCH: isolate attacker on victim
#     ./mitigation/mitigate.sh clear        # remove everything (back to vulnerable)
# ============================================================================
set -euo pipefail

GW_IP=172.30.0.2
DHCP_IP=172.30.0.3
VICTIM_IP=172.30.0.10
ATTACKER_IP=172.30.0.66

mac_of() { docker exec "$1" cat /sys/class/net/eth0/address; }

apply() {
  GW_MAC=$(mac_of trust-gateway)
  VICTIM_MAC=$(mac_of trust-victim)
  DHCP_MAC=$(mac_of trust-dhcp)
  echo "[*] Real MACs: gateway=$GW_MAC  victim=$VICTIM_MAC  dhcp=$DHCP_MAC"

  # ---------------------------------------------------------------------
  # 1) STATIC ARP  (the reliable anti-poisoning control)
  #    nud permanent = the kernel will NEVER overwrite this from an ARP reply.
  #    The attacker can shout "gateway is-at me" forever; the victim ignores it.
  # ---------------------------------------------------------------------
  echo "[*] Pinning static ARP (victim->gateway, gateway->victim)..."
  docker exec trust-victim  ip neigh replace "$GW_IP"     lladdr "$GW_MAC"     nud permanent dev eth0
  docker exec trust-gateway ip neigh replace "$VICTIM_IP" lladdr "$VICTIM_MAC" nud permanent dev eth0

  # ---------------------------------------------------------------------
  # 2) DYNAMIC ARP INSPECTION via nftables (arp family) on the victim.
  #    Drop any ARP *reply* that claims the gateway IP but carries a MAC
  #    other than the real gateway MAC. (Belt-and-suspenders with #1.)
  # ---------------------------------------------------------------------
  echo "[*] Installing Dynamic ARP Inspection (nftables arp) on victim..."
  docker exec -i trust-victim nft -f - <<EOF 2>/dev/null \
    && echo "    [+] DAI active" \
    || echo "    [!] nft arp family unavailable in this kernel -> static ARP (#1) still fully protects"
flush table arp dai 2>/dev/null
table arp dai {
  chain input {
    type filter hook input priority 0; policy accept;
    arp operation reply arp saddr ip $GW_IP arp saddr ether != $GW_MAC drop
  }
}
EOF

  # ---------------------------------------------------------------------
  # 3) DHCP SNOOPING via nftables (ip family) on the victim.
  #    A DHCP server answers FROM udp source port 67. Only the trusted
  #    server IP may do so; drop server replies from anyone else = rogue.
  # ---------------------------------------------------------------------
  echo "[*] Installing DHCP snooping (nftables ip) on victim..."
  docker exec -i trust-victim nft -f - <<EOF 2>/dev/null \
    && echo "    [+] DHCP snooping active (only $DHCP_IP may serve DHCP)" \
    || echo "    [!] nft ip filter unavailable in this kernel"
flush table ip dhcpsnoop 2>/dev/null
table ip dhcpsnoop {
  chain input {
    type filter hook input priority 0; policy accept;
    udp sport 67 ip saddr != $DHCP_IP drop
  }
}
EOF

  echo "[+] Mitigation applied. Re-run the attacks: they should now FAIL."
}

quarantine() {
  echo "[*] QUARANTINE: victim now drops ALL traffic from attacker $ATTACKER_IP..."
  docker exec -i trust-victim nft -f - <<EOF 2>/dev/null \
    && echo "    [+] attacker isolated at the victim" \
    || echo "    [!] nft unavailable"
flush table ip quarantine 2>/dev/null
table ip quarantine {
  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr $ATTACKER_IP drop
  }
}
EOF
}

status() {
  echo "=== victim ARP cache (look for 'PERMANENT' on 172.30.0.2) ==="
  docker exec trust-victim ip neigh show dev eth0 || true
  echo
  echo "=== victim nftables rulesets ==="
  docker exec trust-victim nft list ruleset 2>/dev/null || echo "(no nft rules / nft unavailable)"
}

clear_rules() {
  echo "[*] Removing static ARP + nftables rules from victim/gateway..."
  docker exec trust-victim  ip neigh del "$GW_IP" dev eth0 2>/dev/null || true
  docker exec trust-gateway ip neigh del "$VICTIM_IP" dev eth0 2>/dev/null || true
  for t in "arp dai" "ip dhcpsnoop" "ip quarantine"; do
    docker exec trust-victim nft delete table $t 2>/dev/null || true
  done
  echo "[+] Cleared. Lab is back to the vulnerable baseline."
}

case "${1:-}" in
  apply)      apply ;;
  quarantine) quarantine ;;
  status)     status ;;
  clear)      clear_rules ;;
  *) echo "usage: $0 {apply|status|quarantine|clear}"; exit 1 ;;
esac
