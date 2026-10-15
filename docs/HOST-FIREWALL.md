# Host firewalls

Limbo's per-guest nftables table (package `policy`) hooks at priority -10 and only drops or accepts
inside itself. An `accept` there ends that table; it does not override a `drop` in another table. So a
host whose firewall drops by default never lets the guest's DHCP request reach the host's dnsmasq, and
the guest never gets an address.

## UFW (supported)

UFW sets `input` and `forward` policy to drop. When UFW is installed and `ENABLED=yes` in
`/etc/ufw/ufw.conf`, `limbo up` loads the guest's own table first and then opens the guest's bridge
(`lb-NAME`) in UFW (`internal/hostfw`):

    ufw allow in on lb-NAME to any port 67 proto udp   comment limbo
    ufw allow in on lb-NAME to any port 53 proto udp   comment limbo
    ufw allow in on lb-NAME to any port 53 proto tcp   comment limbo
    ufw route allow in on lb-NAME                      comment limbo

`limbo down` (and a failed `up`) removes them (`ufw --force delete ...`, and
`ufw --force route delete ...` for the route rule). This widens nothing: Limbo's table runs before
UFW's and its drops are final, so what a guest can do is still exactly what its manifest says. If Limbo
is killed mid-run the rules stay; list them with `ufw status numbered` (they carry the comment `limbo`).

Verified on Labyrinth OS (UFW enabled) with real guests: `scripts/integration-linux-guest.sh`, 43 of 43.

## Other firewalls

firewalld and hand-written nftables/iptables policies are not handled. On those, allow DHCP (udp 67)
and DNS (53) in on the guest bridge and forwarding from it, or the guest will not get an address
(`limbo up` still succeeds; the guest just never answers).
