#include "baseline_manager.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BM_KEY_LEN (FE_HOST_ID_LEN + FE_EXE_LEN + 2U)
#define INDEX_NONE SIZE_MAX
#define ROBUST_SCALE_FACTOR 1.4826

typedef struct {
    double ewma;
    double scale;
    uint32_t sample_count;
    bool initialized;
} baseline_stat_t;

typedef struct {
    bool used;
    char key[BM_KEY_LEN];
    uint64_t last_seen_ns;
    uint64_t generation;
    uint32_t observation_count;
    baseline_stat_t stats[BASELINE_FEATURE_COUNT];
    size_t hash_next;
    size_t lru_prev;
    size_t lru_next;
} baseline_entry_t;

struct baseline_manager {
    baseline_config_t config;
    baseline_entry_t *entries;
    size_t *buckets;
    size_t capacity;
    size_t bucket_count;
    size_t size;
    size_t free_head;
    size_t lru_head;
    size_t lru_tail;
    uint64_t next_generation;
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

static int make_key(char key[BM_KEY_LEN], const char *host_id, const char *exe)
{
    int written;
    if (!key || !host_id || !exe || host_id[0] == '\0' || exe[0] == '\0')
        return -1;
    written = snprintf(key, BM_KEY_LEN, "%s|%s", host_id, exe);
    return written >= 0 && (size_t)written < BM_KEY_LEN ? 0 : -1;
}

static size_t lookup_index(const baseline_manager_t *manager, const char *key)
{
    size_t bucket = (size_t)(hash_string(key) & (manager->bucket_count - 1U));
    size_t index;
    for (index = manager->buckets[bucket]; index != INDEX_NONE;
         index = manager->entries[index].hash_next) {
        if (strcmp(manager->entries[index].key, key) == 0)
            return index;
    }
    return INDEX_NONE;
}

static void lru_remove(baseline_manager_t *manager, size_t index)
{
    baseline_entry_t *entry = &manager->entries[index];
    if (entry->lru_prev != INDEX_NONE)
        manager->entries[entry->lru_prev].lru_next = entry->lru_next;
    else
        manager->lru_head = entry->lru_next;
    if (entry->lru_next != INDEX_NONE)
        manager->entries[entry->lru_next].lru_prev = entry->lru_prev;
    else
        manager->lru_tail = entry->lru_prev;
    entry->lru_prev = INDEX_NONE;
    entry->lru_next = INDEX_NONE;
}

static void lru_push_front(baseline_manager_t *manager, size_t index)
{
    baseline_entry_t *entry = &manager->entries[index];
    entry->lru_prev = INDEX_NONE;
    entry->lru_next = manager->lru_head;
    if (manager->lru_head != INDEX_NONE)
        manager->entries[manager->lru_head].lru_prev = index;
    else
        manager->lru_tail = index;
    manager->lru_head = index;
}

static void hash_remove(baseline_manager_t *manager, size_t index)
{
    size_t bucket = (size_t)(hash_string(manager->entries[index].key) &
                             (manager->bucket_count - 1U));
    size_t *cursor = &manager->buckets[bucket];
    while (*cursor != INDEX_NONE) {
        if (*cursor == index) {
            *cursor = manager->entries[index].hash_next;
            return;
        }
        cursor = &manager->entries[*cursor].hash_next;
    }
}

static void release_entry(baseline_manager_t *manager, size_t index)
{
    baseline_entry_t *entry = &manager->entries[index];
    hash_remove(manager, index);
    lru_remove(manager, index);
    memset(entry, 0, sizeof(*entry));
    entry->hash_next = manager->free_head;
    entry->lru_prev = INDEX_NONE;
    entry->lru_next = INDEX_NONE;
    manager->free_head = index;
    manager->size--;
}

static void expire_entries(baseline_manager_t *manager, uint64_t now_ns)
{
    while (manager->lru_tail != INDEX_NONE) {
        baseline_entry_t *entry = &manager->entries[manager->lru_tail];
        if (now_ns < entry->last_seen_ns ||
            now_ns - entry->last_seen_ns <= manager->config.ttl_ns)
            break;
        release_entry(manager, manager->lru_tail);
    }
}

static baseline_maturity_t maturity_for(const baseline_manager_t *manager,
                                        uint32_t count)
{
    if (count <= manager->config.cold_max_samples)
        return BASELINE_COLD;
    if (count <= manager->config.warming_max_samples)
        return BASELINE_WARMING;
    return BASELINE_MATURE;
}

static void initialize_stat(const baseline_manager_t *manager,
                            baseline_stat_t *stat,
                            double value)
{
    stat->ewma = value;
    stat->scale = fmax(fabs(value) * manager->config.initial_scale_fraction,
                       manager->config.initial_scale_floor);
    stat->sample_count = 1;
    stat->initialized = true;
}

void baseline_config_default(baseline_config_t *config)
{
    if (!config)
        return;
    config->capacity = BM_DEFAULT_CAPACITY;
    config->ttl_ns = BM_DEFAULT_TTL_NS;
    config->normal_alpha = BM_NORMAL_ALPHA;
    config->anomalous_alpha = BM_ANOMALOUS_ALPHA;
    config->scale_beta = BM_SCALE_BETA;
    config->anomalous_scale_beta = BM_ANOMALOUS_SCALE_BETA;
    config->adaptation_boundary = BM_ADAPTATION_BOUNDARY;
    config->initial_scale_fraction = BM_INITIAL_SCALE_FRACTION;
    config->initial_scale_floor = BM_INITIAL_SCALE_FLOOR;
    config->cold_max_samples = BM_COLD_MAX_SAMPLES;
    config->warming_max_samples = BM_WARMING_MAX_SAMPLES;
}

baseline_manager_t *baseline_manager_create(const baseline_config_t *requested)
{
    baseline_manager_t *manager;
    baseline_config_t config;
    size_t i;
    baseline_config_default(&config);
    if (requested)
        config = *requested;
    if (config.capacity == 0 || config.ttl_ns == 0 ||
        config.capacity > SIZE_MAX / 2U ||
        config.capacity > SIZE_MAX / sizeof(*manager->entries) ||
        !isfinite(config.normal_alpha) || config.normal_alpha <= 0.0 ||
        config.normal_alpha > 1.0 || !isfinite(config.anomalous_alpha) ||
        config.anomalous_alpha <= 0.0 || config.anomalous_alpha > 1.0 ||
        !isfinite(config.scale_beta) || config.scale_beta <= 0.0 ||
        config.scale_beta > 1.0 || !isfinite(config.anomalous_scale_beta) ||
        config.anomalous_scale_beta <= 0.0 ||
        config.anomalous_scale_beta > 1.0 ||
        !isfinite(config.adaptation_boundary) ||
        config.adaptation_boundary <= 0.0 ||
        !isfinite(config.initial_scale_fraction) ||
        config.initial_scale_fraction <= 0.0 ||
        !isfinite(config.initial_scale_floor) ||
        config.initial_scale_floor <= 0.0 ||
        config.cold_max_samples == 0 ||
        config.warming_max_samples <= config.cold_max_samples)
        return NULL;

    manager = calloc(1, sizeof(*manager));
    if (!manager)
        return NULL;
    manager->config = config;
    manager->capacity = config.capacity;
    manager->bucket_count = next_power_of_two(config.capacity * 2U);
    manager->entries = calloc(manager->capacity, sizeof(*manager->entries));
    manager->buckets = malloc(manager->bucket_count * sizeof(*manager->buckets));
    if (!manager->entries || !manager->buckets) {
        baseline_manager_destroy(manager);
        return NULL;
    }
    for (i = 0; i < manager->bucket_count; i++)
        manager->buckets[i] = INDEX_NONE;
    for (i = 0; i < manager->capacity; i++) {
        manager->entries[i].hash_next = i + 1U < manager->capacity ?
                                        i + 1U : INDEX_NONE;
        manager->entries[i].lru_prev = INDEX_NONE;
        manager->entries[i].lru_next = INDEX_NONE;
    }
    manager->free_head = 0;
    manager->lru_head = INDEX_NONE;
    manager->lru_tail = INDEX_NONE;
    manager->next_generation = 1;
    return manager;
}

void baseline_manager_destroy(baseline_manager_t *manager)
{
    if (!manager)
        return;
    free(manager->buckets);
    free(manager->entries);
    free(manager);
}

int baseline_manager_compare(baseline_manager_t *manager,
                             const char *host_id,
                             const char *exe,
                             const double values[BASELINE_FEATURE_COUNT],
                             uint32_t valid_mask,
                             uint64_t now_ns,
                             baseline_comparison_t *comparison)
{
    char key[BM_KEY_LEN];
    size_t index;
    baseline_entry_t *entry;
    size_t i;

    if (!manager || !values || !comparison || make_key(key, host_id, exe) < 0)
        return -1;
    memset(comparison, 0, sizeof(*comparison));
    comparison->entry_index = INDEX_NONE;
    expire_entries(manager, now_ns);
    index = lookup_index(manager, key);
    if (index == INDEX_NONE) {
        size_t bucket;
        if (manager->free_head == INDEX_NONE)
            release_entry(manager, manager->lru_tail);
        index = manager->free_head;
        manager->free_head = manager->entries[index].hash_next;
        entry = &manager->entries[index];
        memset(entry, 0, sizeof(*entry));
        entry->used = true;
        entry->generation = manager->next_generation++;
        if (manager->next_generation == 0)
            manager->next_generation = 1;
        entry->last_seen_ns = now_ns;
        entry->observation_count = 1;
        entry->lru_prev = INDEX_NONE;
        entry->lru_next = INDEX_NONE;
        (void)snprintf(entry->key, sizeof(entry->key), "%s", key);
        bucket = (size_t)(hash_string(key) & (manager->bucket_count - 1U));
        entry->hash_next = manager->buckets[bucket];
        manager->buckets[bucket] = index;
        lru_push_front(manager, index);
        manager->size++;
        for (i = 0; i < BASELINE_FEATURE_COUNT; i++) {
            if ((valid_mask & (UINT32_C(1) << i)) != 0 &&
                isfinite(values[i]))
                initialize_stat(manager, &entry->stats[i], values[i]);
        }
        comparison->entry_index = index;
        comparison->generation = entry->generation;
        comparison->first_observation = true;
        comparison->observation_count = 1;
        comparison->maturity = BASELINE_COLD;
        return 0;
    }

    entry = &manager->entries[index];
    entry->last_seen_ns = now_ns;
    lru_remove(manager, index);
    lru_push_front(manager, index);
    comparison->entry_index = index;
    comparison->generation = entry->generation;
    comparison->observation_count = entry->observation_count == UINT32_MAX ?
                                    UINT32_MAX : entry->observation_count + 1U;
    comparison->maturity = maturity_for(manager,
                                         comparison->observation_count);
    for (i = 0; i < BASELINE_FEATURE_COUNT; i++) {
        baseline_stat_t *stat = &entry->stats[i];
        double denominator;
        double delta;
        if ((valid_mask & (UINT32_C(1) << i)) == 0 ||
            !isfinite(values[i]) || !stat->initialized)
            continue;
        denominator = fmax(ROBUST_SCALE_FACTOR * stat->scale,
                           FEATURE_EPSILON);
        delta = (values[i] - stat->ewma) / denominator;
        if (!isfinite(delta))
            continue;
        comparison->delta[i] = delta;
        comparison->valid_mask |= UINT32_C(1) << i;
    }
    return 0;
}

int baseline_manager_update(baseline_manager_t *manager,
                            const baseline_comparison_t *comparison,
                            const double values[BASELINE_FEATURE_COUNT],
                            uint32_t valid_mask,
                            uint64_t now_ns)
{
    baseline_entry_t *entry;
    size_t i;
    if (!manager || !comparison || !values ||
        comparison->entry_index >= manager->capacity)
        return -1;
    entry = &manager->entries[comparison->entry_index];
    if (!entry->used || entry->generation != comparison->generation)
        return -1;
    if (comparison->first_observation) {
        entry->last_seen_ns = now_ns;
        return 0;
    }
    for (i = 0; i < BASELINE_FEATURE_COUNT; i++) {
        baseline_stat_t *stat = &entry->stats[i];
        double alpha;
        double beta;
        double old_mean;
        double absolute_deviation;
        bool anomalous;
        if ((valid_mask & (UINT32_C(1) << i)) == 0 || !isfinite(values[i]))
            continue;
        if (!stat->initialized) {
            initialize_stat(manager, stat, values[i]);
            continue;
        }
        anomalous = (comparison->valid_mask & (UINT32_C(1) << i)) != 0 &&
                    fabs(comparison->delta[i]) >
                    manager->config.adaptation_boundary;
        alpha = anomalous ? manager->config.anomalous_alpha :
                             manager->config.normal_alpha;
        beta = anomalous ? manager->config.anomalous_scale_beta :
                            manager->config.scale_beta;
        old_mean = stat->ewma;
        absolute_deviation = fabs(values[i] - old_mean);
        stat->scale = beta * absolute_deviation +
                      (1.0 - beta) * stat->scale;
        stat->ewma = alpha * values[i] + (1.0 - alpha) * old_mean;
        if (!isfinite(stat->scale) || stat->scale < FEATURE_EPSILON)
            stat->scale = manager->config.initial_scale_floor;
        if (!isfinite(stat->ewma))
            stat->ewma = old_mean;
        if (stat->sample_count != UINT32_MAX)
            stat->sample_count++;
    }
    if (entry->observation_count != UINT32_MAX)
        entry->observation_count++;
    entry->last_seen_ns = now_ns;
    return 0;
}

size_t baseline_manager_size(const baseline_manager_t *manager)
{
    return manager ? manager->size : 0;
}

size_t baseline_manager_memory_bytes(const baseline_manager_t *manager)
{
    if (!manager)
        return 0;
    return sizeof(*manager) + manager->capacity * sizeof(*manager->entries) +
           manager->bucket_count * sizeof(*manager->buckets);
}

bool baseline_manager_contains(const baseline_manager_t *manager,
                               const char *host_id,
                               const char *exe)
{
    char key[BM_KEY_LEN];
    return manager && make_key(key, host_id, exe) == 0 &&
           lookup_index(manager, key) != INDEX_NONE;
}

int baseline_manager_snapshot(const baseline_manager_t *manager,
                              const char *host_id,
                              const char *exe,
                              size_t feature_index,
                              baseline_stat_snapshot_t *snapshot)
{
    char key[BM_KEY_LEN];
    size_t index;
    const baseline_stat_t *stat;
    if (!manager || !snapshot || feature_index >= BASELINE_FEATURE_COUNT ||
        make_key(key, host_id, exe) < 0)
        return -1;
    index = lookup_index(manager, key);
    if (index == INDEX_NONE)
        return -1;
    stat = &manager->entries[index].stats[feature_index];
    if (!stat->initialized)
        return -1;
    snapshot->ewma = stat->ewma;
    snapshot->scale = stat->scale;
    snapshot->sample_count = stat->sample_count;
    return 0;
}

const char *baseline_maturity_name(baseline_maturity_t maturity)
{
    switch (maturity) {
    case BASELINE_COLD: return "COLD";
    case BASELINE_WARMING: return "WARMING";
    case BASELINE_MATURE: return "MATURE";
    default: return "UNKNOWN";
    }
}
