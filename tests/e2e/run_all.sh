#!/usr/bin/env bash
set -Eeuo pipefail

TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
for test_script in \
    test_simple_activity.sh \
    test_file_activity.sh \
    test_benign_activity.sh \
    test_suspicious_activity.sh \
    test_malicious_simulation.sh \
    test_kill_stop.sh; do
    "${TEST_DIR}/${test_script}"
done
