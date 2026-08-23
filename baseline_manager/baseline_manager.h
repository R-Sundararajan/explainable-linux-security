#ifndef BASELINE_MANAGER_H
#define BASELINE_MANAGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../feature_engineering/feature_types.h"

#define BM_DEFAULT_CAPACITY 4096U
#define BM_DEFAULT_TTL_NS (UINT64_C(86400) * UINT64_C(1000000000))
#define BM_NORMAL_ALPHA 0.10
#define BM_ANOMALOUS_ALPHA 0.01
#define BM_SCALE_BETA 0.10
#define BM_ANOMALOUS_SCALE_BETA 0.01
#define BM_ADAPTATION_BOUNDARY 3.0
#define BM_INITIAL_SCALE_FRACTION 0.10
#define BM_INITIAL_SCALE_FLOOR 0.001
#define BM_COLD_MAX_SAMPLES 2U
#define BM_WARMING_MAX_SAMPLES 9U

typedef enum {
    BASELINE_COLD = 0,
    BASELINE_WARMING,
    BASELINE_MATURE
} baseline_maturity_t;

typedef struct baseline_manager baseline_manager_t;

typedef struct {
    size_t capacity;
    uint64_t ttl_ns;
    double normal_alpha;
    double anomalous_alpha;
    double scale_beta;
    double anomalous_scale_beta;
    double adaptation_boundary;
    double initial_scale_fraction;
    double initial_scale_floor;
    uint32_t cold_max_samples;
    uint32_t warming_max_samples;
} baseline_config_t;

typedef struct {
    size_t entry_index;
    uint64_t generation;
    bool first_observation;
    uint32_t observation_count;
    baseline_maturity_t maturity;
    double delta[BASELINE_FEATURE_COUNT];
    uint32_t valid_mask;
} baseline_comparison_t;

typedef struct {
    double ewma;
    double scale;
    uint32_t sample_count;
} baseline_stat_snapshot_t;

void baseline_config_default(baseline_config_t *config);
baseline_manager_t *baseline_manager_create(const baseline_config_t *config);
void baseline_manager_destroy(baseline_manager_t *manager);

/* Compare never updates an existing baseline. New keys are cold-started. */
int baseline_manager_compare(baseline_manager_t *manager,
                             const char *host_id,
                             const char *exe,
                             const double values[BASELINE_FEATURE_COUNT],
                             uint32_t valid_mask,
                             uint64_t now_ns,
                             baseline_comparison_t *comparison);

/* Must be called only after scoring the comparison returned above. */
int baseline_manager_update(baseline_manager_t *manager,
                            const baseline_comparison_t *comparison,
                            const double values[BASELINE_FEATURE_COUNT],
                            uint32_t valid_mask,
                            uint64_t now_ns);

size_t baseline_manager_size(const baseline_manager_t *manager);
size_t baseline_manager_memory_bytes(const baseline_manager_t *manager);
bool baseline_manager_contains(const baseline_manager_t *manager,
                               const char *host_id,
                               const char *exe);
int baseline_manager_snapshot(const baseline_manager_t *manager,
                              const char *host_id,
                              const char *exe,
                              size_t feature_index,
                              baseline_stat_snapshot_t *snapshot);
const char *baseline_maturity_name(baseline_maturity_t maturity);

#endif
