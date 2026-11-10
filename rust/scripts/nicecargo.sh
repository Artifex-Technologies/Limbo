#!/bin/sh
# Cargo at nice 15, so a build or test run never competes with games or the local model.
cd "$(dirname "$0")/.." || exit 2
exec nice -n 15 cargo "$@"
