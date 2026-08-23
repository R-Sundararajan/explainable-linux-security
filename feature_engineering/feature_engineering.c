#include "feature_engineering.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEMPORAL_METRIC_COUNT 6U
#define INDEX_NONE SIZE_MAX

enum temporal_metric {
    TM_CPU = 0,
    TM_MEMORY,
    TM_SYSCALL,
    TM_FILE,
    TM_NETWORK,
    TM_ACTIVITY
};

typedef struct {
    bool used;
    char key[FE_PROCESS_ID_LEN];
    uint64_t last_seen_ns;
    double ewma[TEMPORAL_METRIC_COUNT];
    uint32_t initialized_mask;
    uint32_t sample_count;
    size_t hash_next;
    size_t lru_prev;
    size_t lru_next;
} temporal_entry_t;

struct fe_engine {
    fe_config_t config;
    temporal_entry_t *entries;
    size_t *buckets;
    size_t capacity;
    size_t bucket_count;
    size_t size;
    size_t free_head;
    size_t lru_head;
    size_t lru_tail;
};

static const char *const feature_names[FEATURE_COUNT] = {
    "F01 syscall_rate", "F02 file_write_rate",
    "F03 file_write_bytes_rate", "F04 file_create_rate",
    "F05 file_delete_rate", "F06 file_rename_rate",
    "F07 network_event_rate", "F08 privilege_change_rate",
    "F09 average_write_size", "F10 destructive_file_ratio",
    "F11 file_activity_syscall_ratio", "F12 network_syscall_ratio",
    "F13 privilege_syscall_ratio", "F14 cpu_utilization",
    "F15 memory_bytes", "F16 io_bytes_per_sec",
    "F17 cpu_temporal_deviation", "F18 memory_temporal_deviation",
    "F19 syscall_temporal_deviation", "F20 file_temporal_deviation",
    "F21 network_temporal_deviation", "F22 activity_burst_score",
    "F23 process_age_seconds", "F24 short_lived_process",
    "F25 lifecycle_activity", "F26 process_syscall_share",
    "F27 process_file_share", "F28 process_network_share",
    "F29 process_privilege_share", "F30 telemetry_coverage"
};

static uint64_t hash_string(const char *s)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        hash ^= *p++;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static size_t next_power_of_two(size_t value)
{
    size_t result = 1;
    while (result < value && result <= SIZE_MAX / 2U)
        result *= 2U;
    return result;
}

static void lru_remove(fe_engine_t *engine, size_t index)
{
    temporal_entry_t *entry = &engine->entries[index];
    if (entry->lru_prev != INDEX_NONE)
        engine->entries[entry->lru_prev].lru_next = entry->lru_next;
    else
        engine->lru_head = entry->lru_next;
    if (entry->lru_next != INDEX_NONE)
        engine->entries[entry->lru_next].lru_prev = entry->lru_prev;
    else
        engine->lru_tail = entry->lru_prev;
    entry->lru_prev = INDEX_NONE;
    entry->lru_next = INDEX_NONE;
}

static void lru_push_front(fe_engine_t *engine, size_t index)
{
    temporal_entry_t *entry = &engine->entries[index];
    entry->lru_prev = INDEX_NONE;
    entry->lru_next = engine->lru_head;
    if (engine->lru_head != INDEX_NONE)
        engine->entries[engine->lru_head].lru_prev = index;
    else
        engine->lru_tail = index;
    engine->lru_head = index;
}

static void hash_remove(fe_engine_t *engine, size_t index)
{
    size_t bucket = (size_t)(hash_string(engine->entries[index].key) &
                             (engine->bucket_count - 1U));
    size_t *cursor = &engine->buckets[bucket];
    while (*cursor != INDEX_NONE) {
        if (*cursor == index) {
            *cursor = engine->entries[index].hash_next;
            return;
        }
        cursor = &engine->entries[*cursor].hash_next;
    }
}

static void release_entry(fe_engine_t *engine, size_t index)
{
    temporal_entry_t *entry = &engine->entries[index];
    hash_remove(engine, index);
    lru_remove(engine, index);
    memset(entry, 0, sizeof(*entry));
    entry->hash_next = engine->free_head;
    entry->lru_prev = INDEX_NONE;
    entry->lru_next = INDEX_NONE;
    engine->free_head = index;
    engine->size--;
}

static void expire_entries(fe_engine_t *engine, uint64_t now_ns)
{
    while (engine->lru_tail != INDEX_NONE) {
        temporal_entry_t *entry = &engine->entries[engine->lru_tail];
        if (now_ns < entry->last_seen_ns ||
            now_ns - entry->last_seen_ns <= engine->config.temporal_ttl_ns)
            break;
        release_entry(engine, engine->lru_tail);
    }
}

static temporal_entry_t *temporal_get(fe_engine_t *engine,
                                      const char *key,
                                      uint64_t now_ns)
{
    uint64_t hash;
    size_t bucket;
    size_t index;

    expire_entries(engine, now_ns);
    hash = hash_string(key);
    bucket = (size_t)(hash & (engine->bucket_count - 1U));
    for (index = engine->buckets[bucket]; index != INDEX_NONE;
         index = engine->entries[index].hash_next) {
        temporal_entry_t *entry = &engine->entries[index];
        if (strcmp(entry->key, key) == 0) {
            entry->last_seen_ns = now_ns;
            lru_remove(engine, index);
            lru_push_front(engine, index);
            return entry;
        }
    }

    if (engine->free_head == INDEX_NONE)
        release_entry(engine, engine->lru_tail);
    index = engine->free_head;
    engine->free_head = engine->entries[index].hash_next;
    memset(&engine->entries[index], 0, sizeof(engine->entries[index]));
    engine->entries[index].used = true;
    engine->entries[index].last_seen_ns = now_ns;
    engine->entries[index].hash_next = engine->buckets[bucket];
    engine->entries[index].lru_prev = INDEX_NONE;
    engine->entries[index].lru_next = INDEX_NONE;
    (void)snprintf(engine->entries[index].key,
                   sizeof(engine->entries[index].key), "%s", key);
    engine->buckets[bucket] = index;
    lru_push_front(engine, index);
    engine->size++;
    return &engine->entries[index];
}

static bool counter_valid(const fe_activity_t *activity, fe_counter_id_t id)
{
    return (activity->valid_mask & FE_COUNTER_BIT(id)) != 0;
}

static void set_feature(feature_vector_t *vector, feature_id_t id, double value)
{
    if (!isfinite(value))
        return;
    vector->values[id] = value;
    vector->valid_mask |= FE_FEATURE_BIT(id);
}

static double safe_ratio(double numerator, double denominator)
{
    double safe_denominator = denominator > FEATURE_EPSILON ?
                              denominator : FEATURE_EPSILON;
    double value = numerator / safe_denominator;
    return isfinite(value) ? value : 0.0;
}

static bool file_activity_value(const fe_activity_t *activity, double *value)
{
    if (!counter_valid(activity, FE_COUNTER_FILE_WRITE_EVENTS) ||
        !counter_valid(activity, FE_COUNTER_FILE_CREATE) ||
        !counter_valid(activity, FE_COUNTER_FILE_DELETE) ||
        !counter_valid(activity, FE_COUNTER_FILE_RENAME))
        return false;
    *value = (double)activity->file_write_events +
             (double)activity->file_create +
             (double)activity->file_delete +
             (double)activity->file_rename;
    return isfinite(*value);
}

static bool total_activity_value(const fe_activity_t *activity, double *value)
{
    double file_activity;
    if (!counter_valid(activity, FE_COUNTER_SYSCALL_EVENTS) ||
        !counter_valid(activity, FE_COUNTER_NET_STATE) ||
        !counter_valid(activity, FE_COUNTER_UID_CHANGE) ||
        !counter_valid(activity, FE_COUNTER_CAPSET) ||
        !counter_valid(activity, FE_COUNTER_PROCESS_EXEC) ||
        !counter_valid(activity, FE_COUNTER_PROCESS_EXIT) ||
        !file_activity_value(activity, &file_activity))
        return false;
    *value = (double)activity->syscall_events + file_activity +
             (double)activity->net_state + (double)activity->uid_change +
             (double)activity->capset + (double)activity->process_exec +
             (double)activity->process_exit;
    return isfinite(*value);
}

static void derive_temporal(fe_engine_t *engine,
                            const fe_process_record_t *process,
                            feature_vector_t *vector,
                            uint64_t now_ns)
{
    temporal_entry_t *state;
    double metric[TEMPORAL_METRIC_COUNT] = {0.0};
    bool valid[TEMPORAL_METRIC_COUNT] = {false};
    const feature_id_t output_id[TEMPORAL_METRIC_COUNT] = {
        F17_CPU_TEMPORAL_DEVIATION, F18_MEMORY_TEMPORAL_DEVIATION,
        F19_SYSCALL_TEMPORAL_DEVIATION, F20_FILE_TEMPORAL_DEVIATION,
        F21_NETWORK_TEMPORAL_DEVIATION, F22_ACTIVITY_BURST_SCORE
    };
    size_t i;

    state = temporal_get(engine, process->process_instance_id, now_ns);
    if (process->resources_present && process->resource_sample_fresh) {
        metric[TM_CPU] = process->cpu_utilization;
        metric[TM_MEMORY] = (double)process->memory_bytes;
        valid[TM_CPU] = isfinite(metric[TM_CPU]) && metric[TM_CPU] >= 0.0;
        valid[TM_MEMORY] = isfinite(metric[TM_MEMORY]);
    }
    if (counter_valid(&process->activity, FE_COUNTER_SYSCALL_EVENTS)) {
        metric[TM_SYSCALL] = (double)process->activity.syscall_events;
        valid[TM_SYSCALL] = true;
    }
    valid[TM_FILE] = file_activity_value(&process->activity, &metric[TM_FILE]);
    if (counter_valid(&process->activity, FE_COUNTER_NET_STATE)) {
        metric[TM_NETWORK] = (double)process->activity.net_state;
        valid[TM_NETWORK] = true;
    }
    valid[TM_ACTIVITY] = total_activity_value(&process->activity,
                                              &metric[TM_ACTIVITY]);

    for (i = 0; i < TEMPORAL_METRIC_COUNT; i++) {
        uint32_t bit = UINT32_C(1) << i;
        double old;
        double result;
        if (!valid[i] || !isfinite(metric[i]))
            continue;
        if ((state->initialized_mask & bit) == 0) {
            state->ewma[i] = metric[i];
            state->initialized_mask |= bit;
            continue;
        }
        old = state->ewma[i];
        if (i == TM_ACTIVITY)
            result = safe_ratio(metric[i], fabs(old));
        else
            result = safe_ratio(metric[i] - old, fabs(old));
        set_feature(vector, output_id[i], result);
        state->ewma[i] = engine->config.temporal_alpha * metric[i] +
                         (1.0 - engine->config.temporal_alpha) * old;
        if (!isfinite(state->ewma[i]))
            state->ewma[i] = old;
    }
    if (state->sample_count != UINT32_MAX)
        state->sample_count++;
}

static void derive_process_features(fe_engine_t *engine,
                                    const fe_host_window_t *window,
                                    const fe_process_record_t *process,
                                    feature_vector_t *vector)
{
    const fe_activity_t *a = &process->activity;
    const fe_activity_t *h = &window->host_activity;
    double seconds = 0.0;
    double file_activity = 0.0;
    double privilege = 0.0;
    double host_privilege = 0.0;
    double denominator;

    memset(vector, 0, sizeof(*vector));
    (void)snprintf(vector->host_id, sizeof(vector->host_id), "%s",
                   window->host_id);
    (void)snprintf(vector->process_instance_id,
                   sizeof(vector->process_instance_id), "%s",
                   process->process_instance_id);
    (void)snprintf(vector->exe, sizeof(vector->exe), "%s", process->exe);
    vector->pid = process->pid;
    vector->observed_ns = window->window_end_ns;
    vector->ringbuf_drops = window->ringbuf_drops;
    vector->ipc_drops = window->ipc_drops;
    vector->resource_sample_fresh = process->resource_sample_fresh;

    if (window->window_end_ns >= window->window_start_ns)
        seconds = (double)(window->window_end_ns - window->window_start_ns) /
                  1000000000.0;

    if (seconds > FEATURE_EPSILON) {
        if (counter_valid(a, FE_COUNTER_SYSCALL_EVENTS))
            set_feature(vector, F01_SYSCALL_RATE,
                        safe_ratio((double)a->syscall_events, seconds));
        if (counter_valid(a, FE_COUNTER_FILE_WRITE_EVENTS))
            set_feature(vector, F02_FILE_WRITE_RATE,
                        safe_ratio((double)a->file_write_events, seconds));
        if (counter_valid(a, FE_COUNTER_FILE_WRITE_BYTES))
            set_feature(vector, F03_FILE_WRITE_BYTES_RATE,
                        safe_ratio((double)a->file_write_bytes, seconds));
        if (counter_valid(a, FE_COUNTER_FILE_CREATE))
            set_feature(vector, F04_FILE_CREATE_RATE,
                        safe_ratio((double)a->file_create, seconds));
        if (counter_valid(a, FE_COUNTER_FILE_DELETE))
            set_feature(vector, F05_FILE_DELETE_RATE,
                        safe_ratio((double)a->file_delete, seconds));
        if (counter_valid(a, FE_COUNTER_FILE_RENAME))
            set_feature(vector, F06_FILE_RENAME_RATE,
                        safe_ratio((double)a->file_rename, seconds));
        if (counter_valid(a, FE_COUNTER_NET_STATE))
            set_feature(vector, F07_NETWORK_EVENT_RATE,
                        safe_ratio((double)a->net_state, seconds));
        if (counter_valid(a, FE_COUNTER_UID_CHANGE) &&
            counter_valid(a, FE_COUNTER_CAPSET)) {
            privilege = (double)a->uid_change + (double)a->capset;
            set_feature(vector, F08_PRIVILEGE_CHANGE_RATE,
                        safe_ratio(privilege, seconds));
        }
    }

    if (counter_valid(a, FE_COUNTER_FILE_WRITE_BYTES) &&
        counter_valid(a, FE_COUNTER_FILE_WRITE_EVENTS))
        set_feature(vector, F09_AVERAGE_WRITE_SIZE,
                    safe_ratio((double)a->file_write_bytes,
                               (double)a->file_write_events));
    if (counter_valid(a, FE_COUNTER_FILE_DELETE) &&
        counter_valid(a, FE_COUNTER_FILE_RENAME) &&
        counter_valid(a, FE_COUNTER_FILE_CREATE) &&
        counter_valid(a, FE_COUNTER_FILE_WRITE_EVENTS))
        set_feature(vector, F10_DESTRUCTIVE_FILE_RATIO,
                    safe_ratio((double)a->file_delete +
                               (double)a->file_rename,
                               (double)a->file_create +
                               (double)a->file_write_events));
    if (file_activity_value(a, &file_activity) &&
        counter_valid(a, FE_COUNTER_SYSCALL_EVENTS))
        set_feature(vector, F11_FILE_ACTIVITY_SYSCALL_RATIO,
                    safe_ratio(file_activity, (double)a->syscall_events));
    if (counter_valid(a, FE_COUNTER_NET_STATE) &&
        counter_valid(a, FE_COUNTER_SYSCALL_EVENTS))
        set_feature(vector, F12_NETWORK_SYSCALL_RATIO,
                    safe_ratio((double)a->net_state,
                               (double)a->syscall_events));
    if (counter_valid(a, FE_COUNTER_UID_CHANGE) &&
        counter_valid(a, FE_COUNTER_CAPSET) &&
        counter_valid(a, FE_COUNTER_SYSCALL_EVENTS)) {
        privilege = (double)a->uid_change + (double)a->capset;
        set_feature(vector, F13_PRIVILEGE_SYSCALL_RATIO,
                    safe_ratio(privilege, (double)a->syscall_events));
    }

    if (process->resources_present && process->resource_sample_fresh) {
        if (isfinite(process->cpu_utilization) &&
            process->cpu_utilization >= 0.0)
            set_feature(vector, F14_CPU_UTILIZATION,
                        process->cpu_utilization);
        set_feature(vector, F15_MEMORY_BYTES, (double)process->memory_bytes);
        if (isfinite(process->io_bytes_per_sec) &&
            process->io_bytes_per_sec >= 0.0)
            set_feature(vector, F16_IO_BYTES_PER_SEC,
                        process->io_bytes_per_sec);
    }

    derive_temporal(engine, process, vector, window->window_end_ns);

    if (process->start_boottime_ns > 0 &&
        window->window_end_ns >= process->start_boottime_ns) {
        double age = (double)(window->window_end_ns -
                              process->start_boottime_ns) / 1000000000.0;
        set_feature(vector, F23_PROCESS_AGE_SECONDS, age);
        set_feature(vector, F24_SHORT_LIVED_PROCESS,
                    age <= engine->config.short_lived_seconds ? 1.0 : 0.0);
    }
    if (counter_valid(a, FE_COUNTER_PROCESS_EXEC) &&
        counter_valid(a, FE_COUNTER_PROCESS_EXIT)) {
        double lifecycle = (double)a->process_exec +
                           (double)a->process_exit +
                           (process->exit_seen ? 1.0 : 0.0);
        set_feature(vector, F25_LIFECYCLE_ACTIVITY,
                    lifecycle > 0.0 ? 1.0 : 0.0);
    }

    if (counter_valid(a, FE_COUNTER_SYSCALL_EVENTS) &&
        counter_valid(h, FE_COUNTER_SYSCALL_EVENTS))
        set_feature(vector, F26_PROCESS_SYSCALL_SHARE,
                    safe_ratio((double)a->syscall_events,
                               (double)h->syscall_events));
    if (counter_valid(a, FE_COUNTER_FILE_WRITE_EVENTS) &&
        counter_valid(h, FE_COUNTER_FILE_WRITE_EVENTS))
        set_feature(vector, F27_PROCESS_FILE_SHARE,
                    safe_ratio((double)a->file_write_events,
                               (double)h->file_write_events));
    if (counter_valid(a, FE_COUNTER_NET_STATE) &&
        counter_valid(h, FE_COUNTER_NET_STATE))
        set_feature(vector, F28_PROCESS_NETWORK_SHARE,
                    safe_ratio((double)a->net_state,
                               (double)h->net_state));
    if (counter_valid(a, FE_COUNTER_UID_CHANGE) &&
        counter_valid(a, FE_COUNTER_CAPSET) &&
        counter_valid(h, FE_COUNTER_UID_CHANGE) &&
        counter_valid(h, FE_COUNTER_CAPSET)) {
        privilege = (double)a->uid_change + (double)a->capset;
        host_privilege = (double)h->uid_change + (double)h->capset;
        set_feature(vector, F29_PROCESS_PRIVILEGE_SHARE,
                    safe_ratio(privilege, host_privilege));
    }

    if (window->quality_present) {
        denominator = (double)window->process_records_emitted +
                      (double)window->process_records_suppressed;
        set_feature(vector, F30_TELEMETRY_COVERAGE,
                    safe_ratio((double)window->process_records_emitted,
                               denominator));
        vector->suppression_ratio =
            safe_ratio((double)window->process_records_suppressed,
                       denominator);
    }
}

void fe_config_default(fe_config_t *config)
{
    if (!config)
        return;
    config->temporal_capacity = FE_DEFAULT_TEMPORAL_CAPACITY;
    config->temporal_ttl_ns = FE_DEFAULT_TEMPORAL_TTL_NS;
    config->temporal_alpha = FE_DEFAULT_TEMPORAL_ALPHA;
    config->short_lived_seconds = FE_DEFAULT_SHORT_LIVED_SECONDS;
}

fe_engine_t *fe_engine_create(const fe_config_t *requested)
{
    fe_engine_t *engine;
    fe_config_t config;
    size_t i;

    fe_config_default(&config);
    if (requested)
        config = *requested;
    if (config.temporal_capacity == 0 || config.temporal_ttl_ns == 0 ||
        config.temporal_capacity > SIZE_MAX / 2U ||
        config.temporal_capacity > SIZE_MAX / sizeof(*engine->entries) ||
        !isfinite(config.temporal_alpha) || config.temporal_alpha <= 0.0 ||
        config.temporal_alpha > 1.0 ||
        !isfinite(config.short_lived_seconds) ||
        config.short_lived_seconds < 0.0)
        return NULL;
    engine = calloc(1, sizeof(*engine));
    if (!engine)
        return NULL;
    engine->config = config;
    engine->capacity = config.temporal_capacity;
    engine->bucket_count = next_power_of_two(config.temporal_capacity * 2U);
    engine->entries = calloc(engine->capacity, sizeof(*engine->entries));
    engine->buckets = malloc(engine->bucket_count * sizeof(*engine->buckets));
    if (!engine->entries || !engine->buckets) {
        fe_engine_destroy(engine);
        return NULL;
    }
    for (i = 0; i < engine->bucket_count; i++)
        engine->buckets[i] = INDEX_NONE;
    for (i = 0; i < engine->capacity; i++) {
        engine->entries[i].hash_next = i + 1U < engine->capacity ?
                                       i + 1U : INDEX_NONE;
        engine->entries[i].lru_prev = INDEX_NONE;
        engine->entries[i].lru_next = INDEX_NONE;
    }
    engine->free_head = 0;
    engine->lru_head = INDEX_NONE;
    engine->lru_tail = INDEX_NONE;
    return engine;
}

void fe_engine_destroy(fe_engine_t *engine)
{
    if (!engine)
        return;
    free(engine->buckets);
    free(engine->entries);
    free(engine);
}

int fe_engine_process_window(fe_engine_t *engine,
                             const fe_host_window_t *window,
                             feature_vector_t *vectors,
                             size_t vector_capacity,
                             size_t *vector_count)
{
    size_t i;
    if (!engine || !window || !vectors || !vector_count ||
        window->process_count > vector_capacity)
        return -1;
    *vector_count = 0;
    for (i = 0; i < window->process_count; i++) {
        const fe_process_record_t *process = &window->processes[i];
        if (process->process_instance_id[0] == '\0' ||
            process->exe[0] == '\0')
            continue;
        derive_process_features(engine, window, process,
                                &vectors[*vector_count]);
        (*vector_count)++;
    }
    return 0;
}

size_t fe_engine_memory_bytes(const fe_engine_t *engine)
{
    if (!engine)
        return 0;
    return sizeof(*engine) + engine->capacity * sizeof(*engine->entries) +
           engine->bucket_count * sizeof(*engine->buckets);
}

size_t fe_engine_temporal_size(const fe_engine_t *engine)
{
    return engine ? engine->size : 0;
}

const char *fe_feature_name(feature_id_t id)
{
    return (unsigned)id < FEATURE_COUNT ? feature_names[id] : "unknown";
}
