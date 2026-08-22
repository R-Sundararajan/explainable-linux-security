import json
import sys


records = [json.loads(line) for line in sys.stdin if line.strip()]

# 21 meaningful processes must be transported as two batches:
# 20 + 1. The value 20 is a per-batch transport limit, not a
# per-window process visibility limit.
assert len(records) == 2

assert [record["process_batch"]["index"] for record in records] == [0, 1]
assert all(record["process_batch"]["count"] == 2 for record in records)

# Explicitly verify that 20 is only the transport batch size.
assert all(
    record["process_batch"]["max_records_per_batch"] == 20
    for record in records
)

assert all(len(record["processes"]) <= 20 for record in records)

assert all(
    record["window_start_ns"] == 1 and record["window_end_ns"] == 2
    for record in records
)

# Every expected process must cross the JSON boundary exactly once.
pids = [
    process["pid"]
    for record in records
    for process in record["processes"]
]

expected_pids = set(range(100000, 100021))

assert len(pids) == 21
assert len(set(pids)) == 21
assert set(pids) == expected_pids

# The first batch contains 20 records and the second contains 1.
assert [
    record["data_quality"]["process_records_emitted"]
    for record in records
] == [20, 1]

# Window-wide coverage must be reported consistently in every batch.
assert all(
    record["data_quality"]["window_process_records_emitted"] == 21
    for record in records
)

# No meaningful process was suppressed by the old top-20 selection logic.
assert all(
    record["data_quality"]["process_records_suppressed"] == 0
    for record in records
)

assert all(
    record["data_quality"]["tracked_processes"] == 21
    and record["data_quality"]["meaningful_processes"] == 21
    and record["data_quality"]["process_records_filtered_low_signal"] == 0
    and record["data_quality"]["transport_batches"] == 2
    and record["data_quality"]["process_state_attribution_drops"] == 0
    and record["data_quality"]["resource_sampled_processes"] == 0
    and record["data_quality"]["resource_unsampled_processes"] == 21
    for record in records
)

# Resource sampling is separate from process visibility.
# These processes must remain visible even without fresh resource data.
assert all(
    process["resources"] is None
    and process["sampled_this_window"] is False
    for record in records
    for process in record["processes"]
)

print("JSON coverage validation: PASS")