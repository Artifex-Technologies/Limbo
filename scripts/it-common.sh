# shellcheck shell=bash
# Sourced by the real-guest scripts that need Sarina or local ports (integration-chain.sh, integration-sarina.sh).

# pick_sarina sets SARINA_BIN to Sarina's Go binary: the one given, else the installed /usr/bin/sarina. Sarina is Go
# since 2026-11; when neither exists SARINA_BIN stays empty and the scripts fall back to the old Python service, which
# needs the Sarina repo's Python package (gone from the repo, so that path fails loudly rather than quietly).
pick_sarina() {
  if [ -z "${SARINA_BIN:-}" ] && [ -x /usr/bin/sarina ]; then SARINA_BIN=/usr/bin/sarina; fi
  if [ -n "${SARINA_BIN:-}" ]; then
    [ -x "$SARINA_BIN" ] || { echo "SARINA_BIN=$SARINA_BIN is not an executable"; exit 2; }
    echo "== Sarina: $SARINA_BIN service"
  else
    echo "== Sarina: no Go binary (set SARINA_BIN); trying the old Python service from $SARINA_REPO"
  fi
}

# need_free_ports stops the script when a port it is about to use for its own services is taken: a program already
# listening there (the installed sarina-service on 8899, a local model on 8000) would answer in their place and the
# results would be about it, not about the test's own services.
need_free_ports() {
  for p in "$@"; do
    if ss -Hltn "sport = :$p" 2>/dev/null | grep -q .; then
      echo "port $p is already in use on this computer (ss -ltnp 'sport = :$p'); the test needs it for its own service"
      exit 2
    fi
  done
}

# stop_test_heimdalld stops every heimdalld of the test user itq-heimdall (a user of these tests alone, never the real
# heimdall). Run it before a script starts its own and at exit: a leftover from an earlier run watches the same event
# log and control socket with its old configuration and answers first (2026-11-11: an advisory that never came).
stop_test_heimdalld() {
  id itq-heimdall >/dev/null 2>&1 || return 0
  pkill -u itq-heimdall -x heimdalld 2>/dev/null
  for _ in $(seq 1 20); do pgrep -u itq-heimdall -x heimdalld >/dev/null || return 0; sleep 0.5; done
  pkill -KILL -u itq-heimdall -x heimdalld 2>/dev/null
}

# heimdall_isolation prints the heimdalld config keys that keep a test heimdalld in its own folder ($1): every state and
# intelligence path Heimdall's internal/config defaults to /var/lib/heimdall or /etc/heimdall, and the host-wide
# watchers off. Add a key here when Heimdall gains a default path.
heimdall_isolation() {
  local H=$1
  cat <<JSON
  "conn_watch": false, "listen_watch": false, "firewall": false, "fim_paths": [], "vault_dirs": [], "ip_databases": [],
  "grant_requests_path": "$H/grant-requests.json", "rule_drafts_path": "$H/rule-drafts.json",
  "fim_state_path": "$H/fim.json", "conn_state_path": "$H/connections-state.json",
  "app_network_policy": "$H/app-network.json", "threat_list_dir": "$H/intel",
  "security_tracker": "$H/intel/arch-security.json", "kernel_vulns": "$H/intel/linux-kernel.json",
  "package_audit_state_path": "$H/package-audit.json", "kernel_audit_state_path": "$H/kernel-audit.json",
  "hardening_state_path": "$H/hardening.json", "agent_state_path": "$H/agent-sessions.json",
  "vault_state_path": "$H/vault-notes.json", "wifi_results": "$H/wifi/results.jsonl", "lan_dir": "$H/lan",
  "firewall_cursor_path": "$H/firewall.cursor", "maintenance_path": "$H/maintenance.json",
  "agent_baseline_state_path": "$H/agent-baseline.json", "mesh_dir": "$H/mesh", "mesh_peers_path": "$H/mesh-peers.json"
JSON
}
