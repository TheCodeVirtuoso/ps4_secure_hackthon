# One image, many roles. victim / gateway / dhcp-server / attacker / detector
# all run from this same image and only differ by their `command:` in compose.
#
# Debian slim is deliberate: Scapy is a pure-Python wheel here, so there is NONE
# of the gcc / musl-dev / linux-headers build pain you get on Alpine. It just installs.
FROM python:3.12-slim

# Lab toolbox:
#   iproute2        -> `ip`, `ip neigh` (view/set ARP cache)
#   net-tools       -> `arp`, `ifconfig` (familiar output for the writeup)
#   iputils-ping    -> ping (generate traffic / prove reachability)
#   tcpdump         -> packet captures (the before/after pcaps judges want)
#   ebtables        -> Layer-2 bridge firewall = our "switch" mitigation
#   nftables        -> modern alternative, handy for rate-limiting ARP
#   isc-dhcp-client -> `dhclient` so the victim can actually pull a DHCP lease
#   dnsmasq         -> the DHCP *server* (legit one, and the attacker's rogue one)
#   curl            -> victim fetches the plain-HTTP test page
#   procps          -> ps/kill for managing background attack processes
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 net-tools iputils-ping tcpdump ebtables nftables \
        isc-dhcp-client dnsmasq curl procps tini \
    && rm -rf /var/lib/apt/lists/*

# Scapy = our ARP spoofer + detector engine. Pure-python install, no compiler needed.
RUN pip install --no-cache-dir scapy

# dnsmasq ships enabled; we never want it auto-starting. We launch it by hand per-role.
RUN rm -f /etc/dnsmasq.d/* 2>/dev/null || true

WORKDIR /lab

# tini = clean PID 1 so Ctrl-C / `docker compose down` kills child processes properly.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sleep", "infinity"]
