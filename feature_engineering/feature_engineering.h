#ifndef FEATURE_ENGINEERING_H
#define FEATURE_ENGINEERING_H

#include <stddef.h>
#include <stdint.h>

#include "feature_types.h"

#define FE_DEFAULT_TEMPORAL_CAPACITY 8192U
#define FE_DEFAULT_TEMPORAL_TTL_NS (UINT64_C(300) * UINT64_C(1000000000))
#define FE_DEFAULT_TEMPORAL_ALPHA 0.20
#define FE_DEFAULT_SHORT_LIVED_SECONDS 30.0

typedef struct fe_engine fe_engine_t;

typedef struct {
    size_t temporal_capacity;
    uint64_t temporal_ttl_ns;
    double temporal_alpha;
    double short_lived_seconds;
} fe_config_t;

void fe_config_default(fe_config_t *config);
fe_engine_t *fe_engine_create(const fe_config_t *config);
void fe_engine_destroy(fe_engine_t *engine);

/* Converts every emitted process in one host window to F01-F30. */
int fe_engine_process_window(fe_engine_t *engine,
                             const fe_host_window_t *window,
                             feature_vector_t *vectors,
                             size_t vector_capacity,
                             size_t *vector_count);

size_t fe_engine_memory_bytes(const fe_engine_t *engine);
size_t fe_engine_temporal_size(const fe_engine_t *engine);

const char *fe_feature_name(feature_id_t id);

#endif
