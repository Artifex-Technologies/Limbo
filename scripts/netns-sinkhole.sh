#!/bin/sh
# The release check "no analysis profile reaches the home connection" (docs/SINKHOLE.md "The isolation test"): a guest
# in network mode sinkhole or none, behind its real nftables table and, for sinkhole, the real responder, sends DNS,
# HTTP, TLS, UDP and connections to the outside, the home router and the host; nothing may arrive outside, the DNS
# answers must point at the sinkhole and the connections must be in its log. internet-only is the control (it does get
# out). Runs inside a throwaway user and network namespace (unshare -rn, as Heimdall's packaging/tests/netns-rogue.sh):
# no root, nothing reaches the real network, the real nftables or any Limbo socket.
#
#   sh scripts/netns-sinkhole.sh
#
# Needs: cargo, iproute2, nftables, util-linux (unshare, nsenter), python3, unprivileged user namespaces, and the
# kernel's bridge, veth and nftables NAT modules loaded (a user namespace cannot load them; on a host that has run a
# Limbo guest they are). The build is capped like every build here (rust/scripts/nicecargo.sh: nice).
set -eu
cd "$(dirname "$0")/../rust"
out=$(scripts/nicecargo.sh test --locked --offline --test sinkhole_netns --no-run 2>&1) || { echo "$out"; exit 1; }
bin=$(echo "$out" | sed -n 's/.*Executable tests\/sinkhole_netns\.rs (\(.*\))/\1/p' | tail -n 1)
[ -x "$bin" ] || { echo "$out"; echo "netns-sinkhole: no test binary found"; exit 1; }
# the responder is the test build of limbo-rs (cargo builds it for the integration test); inside the namespace the
# test is root of that namespace only, which the responder tells from real root
LIMBO_NETNS_TEST=1 unshare -rn "$bin" --exact analysis_modes_reach_nothing_but_the_sinkhole --nocapture --test-threads=1
