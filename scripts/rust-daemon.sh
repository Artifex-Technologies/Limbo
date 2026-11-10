# Sourced by the integration scripts. With LIMBO_RS=/path/to/limbo-rs they run against the Rust daemon
# (docs/RUST_PORT.md): `limbo serve` is the Rust binary, and every other command goes on, unchanged, to the Go build,
# which is kept beside it as limbo-go (limbo-rs runs a `limbo-go` next to itself). Without LIMBO_RS nothing changes.
#
#   sudo LIMBO_RS="$PWD/rust/target/release/limbo-rs" bash scripts/integration-quarantine.sh

use_rust_daemon() {
  [ -n "${LIMBO_RS:-}" ] || return 0
  [ -x "$LIMBO_RS" ] || { echo "LIMBO_RS=$LIMBO_RS is not an executable"; exit 2; }
  mv "$LIMBO" "$(dirname "$LIMBO")/limbo-go" || exit 2
  install -m 755 "$LIMBO_RS" "$LIMBO" || exit 2
  echo "== limbo serve is the Rust daemon ($LIMBO_RS); every other command runs the Go build ($(dirname "$LIMBO")/limbo-go)"
  "$LIMBO" rs-version
}
