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
