# Sourced by the integration scripts: the limbo binary under test. Since the Go build left the repository
# (docs/RUST_PORT.md) it is limbo-rs: $LIMBO_BIN when set (any build: the Go limbo from the pinned commit makes a
# baseline), else the repository's release build. Build it first as yourself: the scripts run as root and never run
# cargo, so the repository's rust/target never gets root's files. LIMBO_RS, the old name, is read too.
#
#   (cd rust && cargo build --release --locked) && sudo bash scripts/integration-quarantine.sh
#   sudo LIMBO_BIN=/tmp/limbo-go bash scripts/integration-quarantine.sh

install_limbo() { # DEST
  local src="${LIMBO_BIN:-${LIMBO_RS:-$REPO/rust/target/release/limbo-rs}}"
  [ -x "$src" ] || { echo "no limbo build at $src: run (cd rust && cargo build --release --locked) first, or set LIMBO_BIN"; exit 2; }
  install -Dm755 "$src" "$1" || exit 2
  echo "== limbo under test: $src ($("$1" version 2>/dev/null))"
}
