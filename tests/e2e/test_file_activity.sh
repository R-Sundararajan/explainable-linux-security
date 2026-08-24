#!/usr/bin/env bash
set -Eeuo pipefail
exec "$(dirname -- "$0")/_run.sh" file_activity
