#include "anomaly_classifier.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Weights sum to 1.0. Generic resources are deliberately kept at 0.06 total. */
static const feature_config_t feature_configs[FEATURE_COUNT] = {
    {F01_SYSCALL_RATE, "F01 syscall_rate", 0.050, INCREASE_ONLY, SCORE_EXECUTABLE_BASELINE},
    {F02_FILE_WRITE_RATE, "F02 file_write_rate", 0.060, INCREASE_ONLY, SCORE_EXECUTABLE_BASELINE},
    {F03_FILE_WRITE_BYTES_RATE, "F03 file_write_bytes_rate", 0.040, INCREASE_ONLY, SCORE_EXECUTABLE_BASELINE},
    {F04_FILE_CREATE_RATE, "F04 file_create_rate", 0.050, INCREASE_ONLY, SCORE_EXECUTABLE_BASELINE},
    {F05_FILE_DELETE_RATE, "F05 file_delete_rate", 0.090, INCREASE_ONLY, SCORE_EXECUTABLE_BASELINE},
    {F06_FILE_RENAME_RATE, "F06 file_rename_rate", 0.080, INCREASE_ONLY, SCORE_EXECUTABLE_BASELINE},
    {F07_NETWORK_EVENT_RATE, "F07 network_event_rate", 0.040, INCREASE_ONLY, SCORE_EXECUTABLE_BASELINE},
    {F08_PRIVILEGE_CHANGE_RATE, "F08 privilege_change_rate", 0.110, INCREASE_ONLY, SCORE_EXECUTABLE_BASELINE},
    {F09_AVERAGE_WRITE_SIZE, "F09 average_write_size", 0.025, TWO_SIDED, SCORE_EXECUTABLE_BASELINE},
    {F10_DESTRUCTIVE_FILE_RATIO, "F10 destructive_file_ratio", 0.070, TWO_SIDED, SCORE_EXECUTABLE_BASELINE},
    {F11_FILE_ACTIVITY_SYSCALL_RATIO, "F11 file_activity_syscall_ratio", 0.030, TWO_SIDED, SCORE_EXECUTABLE_BASELINE},
    {F12_NETWORK_SYSCALL_RATIO, "F12 network_syscall_ratio", 0.025, TWO_SIDED, SCORE_EXECUTABLE_BASELINE},
    {F13_PRIVILEGE_SYSCALL_RATIO, "F13 privilege_syscall_ratio", 0.055, TWO_SIDED, SCORE_EXECUTABLE_BASELINE},
    {F14_CPU_UTILIZATION, "F14 cpu_utilization", 0.020, INCREASE_ONLY, SCORE_EXECUTABLE_BASELINE},
    {F15_MEMORY_BYTES, "F15 memory_bytes", 0.015, TWO_SIDED, SCORE_EXECUTABLE_BASELINE},
    {F16_IO_BYTES_PER_SEC, "F16 io_bytes_per_sec", 0.025, INCREASE_ONLY, SCORE_EXECUTABLE_BASELINE},
    {F17_CPU_TEMPORAL_DEVIATION, "F17 cpu_temporal_deviation", 0.015, INCREASE_ONLY, SCORE_TEMPORAL_DEVIATION},
    {F18_MEMORY_TEMPORAL_DEVIATION, "F18 memory_temporal_deviation", 0.010, TWO_SIDED, SCORE_TEMPORAL_DEVIATION},
    {F19_SYSCALL_TEMPORAL_DEVIATION, "F19 syscall_temporal_deviation", 0.020, INCREASE_ONLY, SCORE_TEMPORAL_DEVIATION},
    {F20_FILE_TEMPORAL_DEVIATION, "F20 file_temporal_deviation", 0.025, INCREASE_ONLY, SCORE_TEMPORAL_DEVIATION},
    {F21_NETWORK_TEMPORAL_DEVIATION, "F21 network_temporal_deviation", 0.020, INCREASE_ONLY, SCORE_TEMPORAL_DEVIATION},
    {F22_ACTIVITY_BURST_SCORE, "F22 activity_burst_score", 0.060, INCREASE_ONLY, SCORE_BURST_RATIO},
    {F23_PROCESS_AGE_SECONDS, "F23 process_age_seconds", 0.000, TWO_SIDED, SCORE_INFORMATION_ONLY},
    {F24_SHORT_LIVED_PROCESS, "F24 short_lived_process", 0.000, INCREASE_ONLY, SCORE_INFORMATION_ONLY},
    {F25_LIFECYCLE_ACTIVITY, "F25 lifecycle_activity", 0.015, INCREASE_ONLY, SCORE_CONTEXT_FRACTION},
    {F26_PROCESS_SYSCALL_SHARE, "F26 process_syscall_share", 0.010, INCREASE_ONLY, SCORE_CONTEXT_FRACTION},
    {F27_PROCESS_FILE_SHARE, "F27 process_file_share", 0.015, INCREASE_ONLY, SCORE_CONTEXT_FRACTION},
    {F28_PROCESS_NETWORK_SHARE, "F28 process_network_share", 0.010, INCREASE_ONLY, SCORE_CONTEXT_FRACTION},
    {F29_PROCESS_PRIVILEGE_SHARE, "F29 process_privilege_share", 0.015, INCREASE_ONLY, SCORE_CONTEXT_FRACTION},
    {F30_TELEMETRY_COVERAGE, "F30 telemetry_coverage", 0.000, DECREASE_ONLY, SCORE_INFORMATION_ONLY}
};

static double directional_delta(double delta, feature_direction_t direction)
{
    switch (direction) {
    case INCREASE_ONLY:
        return delta > 0.0 ? delta : 0.0;
    case DECREASE_ONLY:
        return delta < 0.0 ? -delta : 0.0;
    case TWO_SIDED:
        return fabs(delta);
    default:
        return 0.0;
    }
}

static void add_attribution(anomaly_result_t *result,
                            feature_id_t feature,
                            double delta,
                            double weight,
                            double contribution)
{
    feature_attribution_t item;
    size_t position;
    size_t limit;
    if (contribution <= 0.0 || !isfinite(contribution))
        return;
    item.feature = feature;
    item.delta = delta;
    item.weight = weight;
    item.contribution = contribution;
    limit = result->top_feature_count < AC_TOP_FEATURE_COUNT ?
            result->top_feature_count : AC_TOP_FEATURE_COUNT;
    for (position = 0; position < limit; position++) {
        if (contribution > result->top_features[position].contribution)
            break;
    }
    if (position >= AC_TOP_FEATURE_COUNT)
        return;
    if (limit < AC_TOP_FEATURE_COUNT)
        result->top_feature_count++;
    for (size_t i = result->top_feature_count - 1U; i > position; i--)
        result->top_features[i] = result->top_features[i - 1U];
    result->top_features[position] = item;
}

static int compare_results(const void *left, const void *right)
{
    const anomaly_result_t *a = left;
    const anomaly_result_t *b = right;
    if (a->anomaly_score < b->anomaly_score)
        return 1;
    if (a->anomaly_score > b->anomaly_score)
        return -1;
    return strcmp(a->process_instance_id, b->process_instance_id);
}

void anomaly_classifier_config_default(anomaly_classifier_config_t *config)
{
    if (!config)
        return;
    config->threshold = AC_ANOMALY_THRESHOLD;
    config->delta_cap = AC_DELTA_CAP;
    config->warming_multiplier = AC_WARMING_MULTIPLIER;
}

const feature_config_t *anomaly_feature_configs(size_t *count)
{
    if (count)
        *count = FEATURE_COUNT;
    return feature_configs;
}

double anomaly_feature_weight_sum(void)
{
    double total = 0.0;
    size_t i;
    for (i = 0; i < FEATURE_COUNT; i++)
        total += feature_configs[i].weight;
    return total;
}

int anomaly_classifier_score(baseline_manager_t *baselines,
                             const anomaly_classifier_config_t *requested,
                             const feature_vector_t *vector,
                             anomaly_result_t *result,
                             bool *is_anomalous)
{
    anomaly_classifier_config_t config;
    baseline_comparison_t comparison;
    double baseline_values[BASELINE_FEATURE_COUNT] = {0.0};
    uint32_t baseline_valid = 0;
    double maturity_multiplier;
    size_t i;

    if (!baselines || !vector || !result || !is_anomalous)
        return -1;
    anomaly_classifier_config_default(&config);
    if (requested)
        config = *requested;
    if (!isfinite(config.threshold) || config.threshold < 0.0 ||
        !isfinite(config.delta_cap) || config.delta_cap <= 0.0 ||
        !isfinite(config.warming_multiplier) ||
        config.warming_multiplier < 0.0 || config.warming_multiplier > 1.0)
        return -1;

    memset(result, 0, sizeof(*result));
    (void)snprintf(result->process_instance_id,
                   sizeof(result->process_instance_id), "%s",
                   vector->process_instance_id);
    (void)snprintf(result->exe, sizeof(result->exe), "%s", vector->exe);
    result->pid = vector->pid;
    result->suppression_ratio = vector->suppression_ratio;
    result->ringbuf_drops = vector->ringbuf_drops;
    result->ipc_drops = vector->ipc_drops;
    if ((vector->valid_mask & FE_FEATURE_BIT(F30_TELEMETRY_COVERAGE)) != 0)
        result->telemetry_coverage = vector->values[F30_TELEMETRY_COVERAGE];

    for (i = 0; i < BASELINE_FEATURE_COUNT; i++) {
        baseline_values[i] = vector->values[i];
        if ((vector->valid_mask & FE_FEATURE_BIT(i)) != 0)
            baseline_valid |= UINT32_C(1) << i;
    }
    if (baseline_manager_compare(baselines, vector->host_id, vector->exe,
                                 baseline_values, baseline_valid,
                                 vector->observed_ns, &comparison) < 0)
        return -1;
    result->baseline_maturity = comparison.maturity;
    result->baseline_observations = comparison.observation_count;
    maturity_multiplier = comparison.maturity == BASELINE_MATURE ? 1.0 :
        (comparison.maturity == BASELINE_WARMING ?
         config.warming_multiplier : 0.0);

    for (i = 0; i < FEATURE_COUNT; i++) {
        const feature_config_t *metadata = &feature_configs[i];
        double delta;
        double transformed;
        double contribution;
        if (metadata->weight <= 0.0 ||
            (vector->valid_mask & FE_FEATURE_BIT(i)) == 0)
            continue;
        switch (metadata->score_mode) {
        case SCORE_EXECUTABLE_BASELINE:
            if ((comparison.valid_mask & (UINT32_C(1) << i)) == 0)
                continue;
            delta = comparison.delta[i];
            break;
        case SCORE_TEMPORAL_DEVIATION:
            delta = vector->values[i];
            break;
        case SCORE_BURST_RATIO:
            delta = vector->values[i] - 1.0;
            break;
        case SCORE_CONTEXT_FRACTION:
            delta = vector->values[i] * config.delta_cap;
            break;
        case SCORE_INFORMATION_ONLY:
        default:
            continue;
        }
        if (!isfinite(delta))
            continue;
        transformed = directional_delta(delta, metadata->direction);
        transformed = fmin(transformed, config.delta_cap);
        contribution = metadata->weight * transformed * maturity_multiplier;
        if (!isfinite(contribution) || contribution < 0.0)
            continue;
        result->anomaly_score += contribution;
        add_attribution(result, metadata->id, delta, metadata->weight,
                        contribution);
    }
    if (!isfinite(result->anomaly_score) || result->anomaly_score < 0.0)
        result->anomaly_score = 0.0;
    if (baseline_manager_update(baselines, &comparison, baseline_values,
                                baseline_valid, vector->observed_ns) < 0)
        return -1;
    *is_anomalous = result->anomaly_score >= config.threshold;
    return 0;
}

int anomaly_classifier_rank_window(baseline_manager_t *baselines,
                                   const anomaly_classifier_config_t *config,
                                   const feature_vector_t *vectors,
                                   size_t vector_count,
                                   anomaly_result_t *results,
                                   size_t result_capacity,
                                   size_t *result_count)
{
    size_t i;
    if (!baselines || (!vectors && vector_count != 0) || !results ||
        !result_count)
        return -1;
    *result_count = 0;
    for (i = 0; i < vector_count; i++) {
        anomaly_result_t candidate;
        bool anomalous = false;
        if (anomaly_classifier_score(baselines, config, &vectors[i],
                                     &candidate, &anomalous) < 0)
            continue;
        if (!anomalous)
            continue;
        if (*result_count >= result_capacity)
            return -1;
        results[(*result_count)++] = candidate;
    }
    qsort(results, *result_count, sizeof(*results), compare_results);
    return 0;
}
