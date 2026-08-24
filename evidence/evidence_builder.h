#ifndef EVIDENCE_BUILDER_H
#define EVIDENCE_BUILDER_H

#include <stdbool.h>

#include "evidence_types.h"

int evidence_builder_build(const fe_host_window_t *window,
                           const fe_process_record_t *process,
                           const feature_vector_t *features,
                           const anomaly_result_t *anomaly,
                           double configured_threshold,
                           bool threshold_crossed,
                           process_evidence_t *evidence);

#endif
