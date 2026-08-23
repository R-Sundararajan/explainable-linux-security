#ifndef ANOMALY_CLASSIFIER_H
#define ANOMALY_CLASSIFIER_H

#include <stdbool.h>
#include <stddef.h>

#include "../baseline_manager/baseline_manager.h"
#include "../feature_engineering/feature_types.h"

#define AC_DELTA_CAP 10.0
#define AC_ANOMALY_THRESHOLD 2.0
#define AC_WARMING_MULTIPLIER 0.5
#define AC_TOP_FEATURE_COUNT 3U

typedef enum {
    INCREASE_ONLY = 0,
    TWO_SIDED,
    DECREASE_ONLY
} feature_direction_t;

typedef enum {
    SCORE_EXECUTABLE_BASELINE = 0,
    SCORE_TEMPORAL_DEVIATION,
    SCORE_BURST_RATIO,
    SCORE_CONTEXT_FRACTION,
    SCORE_INFORMATION_ONLY
} feature_score_mode_t;

typedef struct {
    feature_id_t id;
    const char *name;
    double weight;
    feature_direction_t direction;
    feature_score_mode_t score_mode;
} feature_config_t;

typedef struct {
    double threshold;
    double delta_cap;
    double warming_multiplier;
} anomaly_classifier_config_t;

typedef struct {
    feature_id_t feature;
    double delta;
    double weight;
    double contribution;
} feature_attribution_t;

typedef struct {
    char process_instance_id[FE_PROCESS_ID_LEN];
    char exe[FE_EXE_LEN];
    uint32_t pid;
    double anomaly_score;
    baseline_maturity_t baseline_maturity;
    uint32_t baseline_observations;
    double telemetry_coverage;
    double suppression_ratio;
    uint64_t ringbuf_drops;
    uint64_t ipc_drops;
    size_t top_feature_count;
    feature_attribution_t top_features[AC_TOP_FEATURE_COUNT];
} anomaly_result_t;

void anomaly_classifier_config_default(anomaly_classifier_config_t *config);
const feature_config_t *anomaly_feature_configs(size_t *count);
double anomaly_feature_weight_sum(void);

/* Scores against the old baseline, then updates it. */
int anomaly_classifier_score(baseline_manager_t *baselines,
                             const anomaly_classifier_config_t *config,
                             const feature_vector_t *vector,
                             anomaly_result_t *result,
                             bool *is_anomalous);

/* Scores all inputs, retains threshold matches, and sorts score descending. */
int anomaly_classifier_rank_window(baseline_manager_t *baselines,
                                   const anomaly_classifier_config_t *config,
                                   const feature_vector_t *vectors,
                                   size_t vector_count,
                                   anomaly_result_t *results,
                                   size_t result_capacity,
                                   size_t *result_count);

#endif
