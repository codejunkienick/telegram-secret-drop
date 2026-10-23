#!/bin/sh
set -eu
pack=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd -P)
exec python3 "$pack/secret_drop.py" status "$@"
