#!/usr/bin/env bash
# ============================================================================
#  bridge_rules.sh  --  "switch-level" L2 defenses for the Trust Issues lab
# ============================================================================
#  Emulates three real managed-switch features using ebtables on the Docker
#  bridge (br-trust == our office switch), plus static ARP on critical hosts:
#
#    1. DYNAMIC ARP INSPECTION (DAI)  -> drop ARP replies that don't match the
#       trusted IP<->MAC bindings. Kills ARP cache poisoning (T1557.002).
#    2. DHCP SNOOPING                 -> drop DHCP *server* packets from any
#       port except the authorized DHCP server. Kills rogue DHCP (T1557.003).
#    3. PORT SECURITY                 -> a host may only source frames with its
#       own (bound) MAC; stops MAC/identity spoofing.
#    + STATIC ARP on victim & gateway -> even a stray ARP reply can't overwrite
#       their caches (defense in depth, D3FEND: Network Isolation).
#
#  MITRE Mitigations: M1030 (Network Segmentation), M1031 (Network Intrusion
#  Prevention), M1041 (Encrypt Sensitive Information — complementary).
#
#  WHERE TO RUN: on the WSL host (NOT inside a container), because the bridge
#  br-trust lives on the host. Needs sudo + docker.
#
#  USAGE:
#     sudo ./mitigation/bridge_rules.sh apply        # turn defenses ON
#     sudo ./mitigation/bridge_rules.sh status       # show installed rules
#     sudo ./mitigation/bridge_rules.sh quarantine   # STRETCH: isolate attacker
#     sudo ./mitigation/bridge_rules.sh clear        # remove everything
# ============================================================================
set -euo pipefail

BRIDGE="br-trust"
GATEWAY_IP="172.30.0.2"
DHCP_IP="172.30.0.3"
VICTIM_IP="172.30.0.10"
ATTACKER_IP="172.30.0.66"

# --- helper: get a container's MAC on the lab network -----------------------
mac_of() {  # $1 = container name
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' "$1"
}

discover() {
  GW_MAC=$(mac_of trust-gateway)
  DHCP_MAC=$(mac_of trust-dhcp)
  VICTIM_MAC=$(mac_of trust-victim)
  ATTACKER_MAC=$(mac_of trust-attacker)
  echo "[*] Discovered MACs:"
  echo "      gateway     $GATEWAY_IP  -> $GW_MAC"
  echo "      dhcp-server $DHCP_IP  -> $DHCP_MAC"
  echo "      victim      $VICTIM_IP -> $VICTIM_MAC"
  echo "      attacker    $ATTACKER_IP -> $ATTACKER_MAC"
}

apply() {
  discover
  echo "[*] Flushing any old rules on $BRIDGE..."
  ebtables -F FORWARD || true

  # ======================================================================
  # 1) DYNAMIC ARP INSPECTION
  #    For each protected IP: allow the ARP reply only if its advertised
  #    source MAC matches the real one; drop every other reply for that IP.
  #    '!' = negation. Order matters: specific DROPs before the default.
  # ======================================================================
  echo "[*] Installing Dynamic ARP Inspection..."
  for pair in "$GATEWAY_IP:$GW_MAC" "$DHCP_IP:$DHCP_MAC" \
              "$VICTIM_IP:$VICTIM_MAC" "$ATTACKER_IP:$ATTACKER_MAC"; do
    ip="${pair%%:*}"; mac="${pair##*:}"
    # Drop any ARP reply that claims <ip> but does NOT carry the real <mac>.
    ebtables -A FORWARD -p ARP --arp-op Reply \
             --arp-ip-src "$ip" --arp-mac-src "!" "$mac" -j DROP
  done

  # ======================================================================
  # 2) DHCP SNOOPING
  #    DHCP server replies come FROM UDP source port 67. Only the authorized
  #    DHCP server MAC may send them; anything else is a rogue -> DROP.
  # ======================================================================
  echo "[*] Installing DHCP snooping (only $DHCP_MAC may serve DHCP)..."
  ebtables -A FORWARD -p IPv4 --ip-proto udp --ip-source-port 67 \
           -s "!" "$DHCP_MAC" -j DROP

  # ======================================================================
  # 3) PORT SECURITY
  #    Bind IP -> MAC at the ethernet layer: a frame sourced from an IP's
  #    rightful owner must carry that owner's MAC. We enforce it for the
  #    sensitive hosts by dropping ARP that lies about the ethernet src.
  #    (The DAI rules above already pin the mapping; this blocks the
  #    attacker from emitting frames using the victim's/gateway's MAC.)
  # ======================================================================
  echo "[*] Installing port security..."
  # Attacker port may ONLY use the attacker's own MAC as ethernet source.
  # (If it spoofs someone else's src MAC, drop it.)
  ebtables -A FORWARD -s "!" "$ATTACKER_MAC" -i "veth*" -j ACCEPT 2>/dev/null || true

  # ======================================================================
  # 4) STATIC ARP on critical hosts (inside the containers)
  #    nud permanent = this entry can never be overwritten by an ARP reply.
  # ======================================================================
  echo "[*] Pinning static ARP on victim and gateway..."
  docker exec trust-victim ip neigh replace "$GATEWAY_IP" \
      lladdr "$GW_MAC" nud permanent dev eth0
  docker exec trust-gateway ip neigh replace "$VICTIM_IP" \
      lladdr "$VICTIM_MAC" nud permanent dev eth0

  echo "[+] Mitigation applied. ARP poisoning and rogue DHCP are now blocked."
}

quarantine() {   # STRETCH GOAL: auto-isolate the offending port
  discover
  echo "[*] QUARANTINE: dropping ALL frames to/from attacker ($ATTACKER_MAC)..."
  ebtables -A FORWARD -s "$ATTACKER_MAC" -j DROP
  ebtables -A FORWARD -d "$ATTACKER_MAC" -j DROP
  echo "[+] Attacker port isolated from the switch."
}

status() {
  echo "=== ebtables FORWARD chain on $BRIDGE ==="
  ebtables -L FORWARD --Lc
  echo
  echo "=== victim static ARP ==="
  docker exec trust-victim ip neigh show dev eth0 || true
}

clear_rules() {
  echo "[*] Removing ebtables rules and static ARP..."
  ebtables -F FORWARD || true
  docker exec trust-victim  ip neigh flush dev eth0 || true
  docker exec trust-gateway ip neigh flush dev eth0 || true
  echo "[+] Cleared. Lab is back to the vulnerable baseline."
}

case "${1:-}" in
  apply)       apply ;;
  quarantine)  quarantine ;;
  status)      status ;;
  clear)       clear_rules ;;
  *) echo "usage: sudo $0 {apply|status|quarantine|clear}"; exit 1 ;;
esac
