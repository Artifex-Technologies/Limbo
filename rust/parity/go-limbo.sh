#!/bin/sh
# The Go limbo the differential runs compare limbo-rs with. Its sources left this repository on 2026-11-15; they are
# read from the last commit that had them (GO_REV below), so every proof stays reproducible. The current VERSION is
# put over the old one, so both binaries report the same version (`limbo version`, GET /v1/status). Nothing is
# installed. Needs Go 1.27 and the full history (a shallow clone: git fetch --depth=1 origin GO_REV first).
#
#   sh rust/parity/go-limbo.sh /tmp/limbo-go
#
# The fixtures in testdata/parity were written by that commit's Go tests; to write them again after a deliberate
# change, check that commit out elsewhere and run LIMBO_PARITY_UPDATE=1 go test ./internal/... ./cmd/limbo -run Parity
# there (docs/RUST_PORT.md "The Go side").
set -eu
GO_REV=86a479fbc33cca7aaa6c9e4d943562b0825ad8ba
[ $# -eq 1 ] || { echo "usage: sh rust/parity/go-limbo.sh OUT"; exit 2; }
REPO=$(cd "$(dirname "$0")/../.." && pwd)
case $1 in /*) OUT=$1 ;; *) OUT=$PWD/$1 ;; esac
SRC=$(mktemp -d "${TMPDIR:-/tmp}/limbo-go-src.XXXXXX")
trap 'rm -rf "$SRC"' EXIT
git -C "$REPO" archive "$GO_REV" go.mod version.go VERSION cmd internal | tar -x -C "$SRC"
cp "$REPO/VERSION" "$SRC/VERSION"
cd "$SRC" && CGO_ENABLED=0 go build -trimpath -o "$OUT" ./cmd/limbo
echo "$OUT: the Go limbo of $GO_REV (VERSION $(cat "$REPO/VERSION"))"
