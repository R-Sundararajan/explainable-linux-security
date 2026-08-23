#include "telemetry_reader.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) || defined(__unix__) || defined(__APPLE__)
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#define TR_HAS_UNIX_SOCKET 1
#else
#define TR_HAS_UNIX_SOCKET 0
#endif

#define JSON_TOKEN_CAPACITY 2048U

typedef enum {
    JT_UNDEFINED = 0,
    JT_OBJECT,
    JT_ARRAY,
    JT_STRING,
    JT_PRIMITIVE
} json_token_type_t;

typedef struct {
    json_token_type_t type;
    int start;
    int end;
    int parent;
} json_token_t;

typedef struct {
    size_t position;
    size_t next_token;
    int parent;
} json_parser_t;

static void skip_json_space(const char *json, size_t length, size_t *position)
{
    while (*position < length &&
           (json[*position] == ' ' || json[*position] == '\t' ||
            json[*position] == '\r' || json[*position] == '\n'))
        (*position)++;
}

static int validate_json_string(const char *json, size_t length,
                                size_t *position)
{
    if (*position >= length || json[*position] != '"')
        return -1;
    (*position)++;
    while (*position < length) {
        unsigned char c = (unsigned char)json[(*position)++];
        if (c == '"')
            return 0;
        if (c < 0x20)
            return -1;
        if (c == '\\') {
            size_t i;
            if (*position >= length)
                return -1;
            c = (unsigned char)json[(*position)++];
            if (c == 'u') {
                if (*position + 4U > length)
                    return -1;
                for (i = 0; i < 4U; i++) {
                    char h = json[(*position)++];
                    if (!((h >= '0' && h <= '9') ||
                          (h >= 'a' && h <= 'f') ||
                          (h >= 'A' && h <= 'F')))
                        return -1;
                }
            } else if (!strchr("\"\\/bfnrt", (int)c)) {
                return -1;
            }
        }
    }
    return -1;
}

static int validate_json_value(const char *json, size_t length,
                               size_t *position, unsigned depth);

static int validate_json_number(const char *json, size_t length,
                                size_t *position)
{
    size_t p = *position;
    if (p < length && json[p] == '-')
        p++;
    if (p >= length)
        return -1;
    if (json[p] == '0') {
        p++;
    } else {
        if (json[p] < '1' || json[p] > '9')
            return -1;
        while (p < length && json[p] >= '0' && json[p] <= '9')
            p++;
    }
    if (p < length && json[p] == '.') {
        p++;
        if (p >= length || json[p] < '0' || json[p] > '9')
            return -1;
        while (p < length && json[p] >= '0' && json[p] <= '9')
            p++;
    }
    if (p < length && (json[p] == 'e' || json[p] == 'E')) {
        p++;
        if (p < length && (json[p] == '+' || json[p] == '-'))
            p++;
        if (p >= length || json[p] < '0' || json[p] > '9')
            return -1;
        while (p < length && json[p] >= '0' && json[p] <= '9')
            p++;
    }
    *position = p;
    return 0;
}

static int validate_json_array(const char *json, size_t length,
                               size_t *position, unsigned depth)
{
    (*position)++;
    skip_json_space(json, length, position);
    if (*position < length && json[*position] == ']') {
        (*position)++;
        return 0;
    }
    for (;;) {
        if (validate_json_value(json, length, position, depth + 1U) < 0)
            return -1;
        skip_json_space(json, length, position);
        if (*position >= length)
            return -1;
        if (json[*position] == ']') {
            (*position)++;
            return 0;
        }
        if (json[*position] != ',')
            return -1;
        (*position)++;
        skip_json_space(json, length, position);
    }
}

static int validate_json_object(const char *json, size_t length,
                                size_t *position, unsigned depth)
{
    (*position)++;
    skip_json_space(json, length, position);
    if (*position < length && json[*position] == '}') {
        (*position)++;
        return 0;
    }
    for (;;) {
        if (validate_json_string(json, length, position) < 0)
            return -1;
        skip_json_space(json, length, position);
        if (*position >= length || json[*position] != ':')
            return -1;
        (*position)++;
        if (validate_json_value(json, length, position, depth + 1U) < 0)
            return -1;
        skip_json_space(json, length, position);
        if (*position >= length)
            return -1;
        if (json[*position] == '}') {
            (*position)++;
            return 0;
        }
        if (json[*position] != ',')
            return -1;
        (*position)++;
        skip_json_space(json, length, position);
    }
}

static int validate_json_value(const char *json, size_t length,
                               size_t *position, unsigned depth)
{
    if (depth > 64U)
        return -1;
    skip_json_space(json, length, position);
    if (*position >= length)
        return -1;
    if (json[*position] == '{')
        return validate_json_object(json, length, position, depth);
    if (json[*position] == '[')
        return validate_json_array(json, length, position, depth);
    if (json[*position] == '"')
        return validate_json_string(json, length, position);
    if (json[*position] == '-' ||
        (json[*position] >= '0' && json[*position] <= '9'))
        return validate_json_number(json, length, position);
    if (*position + 4U <= length &&
        memcmp(json + *position, "true", 4U) == 0) {
        *position += 4U;
        return 0;
    }
    if (*position + 5U <= length &&
        memcmp(json + *position, "false", 5U) == 0) {
        *position += 5U;
        return 0;
    }
    if (*position + 4U <= length &&
        memcmp(json + *position, "null", 4U) == 0) {
        *position += 4U;
        return 0;
    }
    return -1;
}

static int validate_json_document(const char *json, size_t length)
{
    size_t position = 0;
    if (validate_json_value(json, length, &position, 0) < 0)
        return -1;
    skip_json_space(json, length, &position);
    return position == length ? 0 : -1;
}

static int allocate_token(json_parser_t *parser, json_token_t *tokens,
                          size_t capacity)
{
    json_token_t *token;
    if (parser->next_token >= capacity)
        return -1;
    token = &tokens[parser->next_token];
    token->type = JT_UNDEFINED;
    token->start = -1;
    token->end = -1;
    token->parent = -1;
    return (int)parser->next_token++;
}

static int parse_string_token(json_parser_t *parser, const char *json,
                              size_t length, json_token_t *tokens,
                              size_t capacity)
{
    size_t start = parser->position + 1U;
    size_t i;
    for (i = start; i < length; i++) {
        unsigned char c = (unsigned char)json[i];
        if (c == '"') {
            int index = allocate_token(parser, tokens, capacity);
            if (index < 0)
                return -1;
            tokens[index].type = JT_STRING;
            tokens[index].start = (int)start;
            tokens[index].end = (int)i;
            tokens[index].parent = parser->parent;
            parser->position = i;
            return 0;
        }
        if (c == '\\') {
            i++;
            if (i >= length)
                return -1;
            if (json[i] == 'u') {
                size_t j;
                if (i + 4U >= length)
                    return -1;
                for (j = 1; j <= 4U; j++) {
                    char h = json[i + j];
                    if (!((h >= '0' && h <= '9') ||
                          (h >= 'a' && h <= 'f') ||
                          (h >= 'A' && h <= 'F')))
                        return -1;
                }
                i += 4U;
            } else if (!strchr("\"\\/bfnrt", json[i])) {
                return -1;
            }
        } else if (c < 0x20) {
            return -1;
        }
    }
    return -1;
}

static bool primitive_delimiter(char c)
{
    return c == '\0' || c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
           c == ',' || c == ']' || c == '}';
}

static int parse_primitive_token(json_parser_t *parser, const char *json,
                                 size_t length, json_token_t *tokens,
                                 size_t capacity)
{
    size_t start = parser->position;
    size_t i = start;
    int index;
    while (i < length && !primitive_delimiter(json[i])) {
        unsigned char c = (unsigned char)json[i];
        if (c < 0x20 || c >= 0x7f || c == ':' || c == '[' || c == '{' ||
            c == '"')
            return -1;
        i++;
    }
    if (i == start)
        return -1;
    index = allocate_token(parser, tokens, capacity);
    if (index < 0)
        return -1;
    tokens[index].type = JT_PRIMITIVE;
    tokens[index].start = (int)start;
    tokens[index].end = (int)i;
    tokens[index].parent = parser->parent;
    parser->position = i - 1U;
    return 0;
}

static int tokenize_json(const char *json, size_t length,
                         json_token_t *tokens, size_t capacity)
{
    json_parser_t parser = {0, 0, -1};
    size_t i;
    for (i = 0; i < capacity; i++) {
        tokens[i].start = -1;
        tokens[i].end = -1;
        tokens[i].parent = -1;
        tokens[i].type = JT_UNDEFINED;
    }
    for (parser.position = 0; parser.position < length; parser.position++) {
        char c = json[parser.position];
        if (c == '{' || c == '[') {
            int index = allocate_token(&parser, tokens, capacity);
            if (index < 0)
                return -1;
            tokens[index].type = c == '{' ? JT_OBJECT : JT_ARRAY;
            tokens[index].start = (int)parser.position;
            tokens[index].parent = parser.parent;
            parser.parent = index;
        } else if (c == '}' || c == ']') {
            json_token_type_t expected = c == '}' ? JT_OBJECT : JT_ARRAY;
            int current = parser.parent;
            if (current < 0 || tokens[current].type != expected)
                return -1;
            tokens[current].end = (int)parser.position + 1;
            parser.parent = tokens[current].parent;
        } else if (c == '"') {
            if (parse_string_token(&parser, json, length, tokens, capacity) < 0)
                return -1;
        } else if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
                   c == ':' || c == ',') {
            continue;
        } else if (parse_primitive_token(&parser, json, length, tokens,
                                         capacity) < 0) {
            return -1;
        }
    }
    if (parser.parent != -1 || parser.next_token == 0)
        return -1;
    return (int)parser.next_token;
}

static bool token_equals(const char *json, const json_token_t *token,
                         const char *text)
{
    size_t length;
    if (!token || token->type != JT_STRING || token->start < 0 ||
        token->end < token->start)
        return false;
    length = (size_t)(token->end - token->start);
    return strlen(text) == length &&
           memcmp(json + token->start, text, length) == 0;
}

static int object_value(const char *json, const json_token_t *tokens,
                        int token_count, int object_index, const char *key)
{
    int i;
    if (object_index < 0 || object_index >= token_count ||
        tokens[object_index].type != JT_OBJECT)
        return -1;
    for (i = object_index + 1; i + 1 < token_count; i++) {
        if (tokens[i].parent == object_index &&
            token_equals(json, &tokens[i], key) &&
            tokens[i + 1].parent == object_index)
            return i + 1;
    }
    return -1;
}

static int copy_json_string(const char *json, const json_token_t *token,
                            char *output, size_t capacity)
{
    size_t source;
    size_t used = 0;
    if (!token || token->type != JT_STRING || !output || capacity == 0)
        return -1;
    for (source = (size_t)token->start; source < (size_t)token->end; source++) {
        char c = json[source];
        if (c == '\\') {
            source++;
            if (source >= (size_t)token->end)
                return -1;
            switch (json[source]) {
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u':
                if (source + 4U >= (size_t)token->end)
                    return -1;
                source += 4U;
                c = '?';
                break;
            default: return -1;
            }
        }
        if (used + 1U >= capacity)
            return -1;
        output[used++] = c;
    }
    output[used] = '\0';
    return 0;
}

static int token_to_u64(const char *json, const json_token_t *token,
                        uint64_t *value)
{
    char buffer[32];
    size_t length;
    char *end = NULL;
    unsigned long long parsed;
    if (!token || token->type != JT_PRIMITIVE || !value ||
        token->start < 0 || token->end <= token->start)
        return -1;
    length = (size_t)(token->end - token->start);
    if (length >= sizeof(buffer))
        return -1;
    memcpy(buffer, json + token->start, length);
    buffer[length] = '\0';
    if (buffer[0] < '0' || buffer[0] > '9')
        return -1;
    errno = 0;
    parsed = strtoull(buffer, &end, 10);
    if (errno != 0 || end != buffer + length)
        return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int token_to_double(const char *json, const json_token_t *token,
                           double *value)
{
    char buffer[64];
    size_t length;
    char *end = NULL;
    double parsed;
    if (!token || token->type != JT_PRIMITIVE || !value ||
        token->start < 0 || token->end <= token->start)
        return -1;
    length = (size_t)(token->end - token->start);
    if (length >= sizeof(buffer))
        return -1;
    memcpy(buffer, json + token->start, length);
    buffer[length] = '\0';
    errno = 0;
    parsed = strtod(buffer, &end);
    if (errno != 0 || end != buffer + length || !isfinite(parsed))
        return -1;
    *value = parsed;
    return 0;
}

static int token_to_bool(const char *json, const json_token_t *token,
                         bool *value)
{
    size_t length;
    if (!token || token->type != JT_PRIMITIVE || !value)
        return -1;
    length = (size_t)(token->end - token->start);
    if (length == 4U && memcmp(json + token->start, "true", 4U) == 0) {
        *value = true;
        return 0;
    }
    if (length == 5U && memcmp(json + token->start, "false", 5U) == 0) {
        *value = false;
        return 0;
    }
    return -1;
}

static int get_u64_field(const char *json, const json_token_t *tokens,
                         int count, int object, const char *key,
                         uint64_t *value)
{
    int index = object_value(json, tokens, count, object, key);
    return index < 0 ? -1 : token_to_u64(json, &tokens[index], value);
}

static int get_double_field(const char *json, const json_token_t *tokens,
                            int count, int object, const char *key,
                            double *value)
{
    int index = object_value(json, tokens, count, object, key);
    return index < 0 ? -1 : token_to_double(json, &tokens[index], value);
}

static void parse_activity(const char *json, const json_token_t *tokens,
                           int count, int object, fe_activity_t *activity)
{
#define PARSE_COUNTER(field, id) do { \
    if (get_u64_field(json, tokens, count, object, #field, \
                      &activity->field) == 0) \
        activity->valid_mask |= FE_COUNTER_BIT(id); \
} while (0)
    if (object < 0 || tokens[object].type != JT_OBJECT)
        return;
    PARSE_COUNTER(process_exec, FE_COUNTER_PROCESS_EXEC);
    PARSE_COUNTER(process_exit, FE_COUNTER_PROCESS_EXIT);
    PARSE_COUNTER(syscall_events, FE_COUNTER_SYSCALL_EVENTS);
    PARSE_COUNTER(file_write_events, FE_COUNTER_FILE_WRITE_EVENTS);
    PARSE_COUNTER(file_write_bytes, FE_COUNTER_FILE_WRITE_BYTES);
    PARSE_COUNTER(file_create, FE_COUNTER_FILE_CREATE);
    PARSE_COUNTER(file_delete, FE_COUNTER_FILE_DELETE);
    PARSE_COUNTER(file_rename, FE_COUNTER_FILE_RENAME);
    PARSE_COUNTER(net_state, FE_COUNTER_NET_STATE);
    PARSE_COUNTER(uid_change, FE_COUNTER_UID_CHANGE);
    PARSE_COUNTER(capset, FE_COUNTER_CAPSET);
#undef PARSE_COUNTER
}

static int parse_process(const char *json, const json_token_t *tokens,
                         int count, int object, fe_process_record_t *process)
{
    int index;
    int activity;
    int resources;
    uint64_t integer;
    bool fresh = false;
    bool exit_seen = false;

    memset(process, 0, sizeof(*process));
    if (get_u64_field(json, tokens, count, object, "pid", &integer) == 0 &&
        integer <= UINT32_MAX)
        process->pid = (uint32_t)integer;
    if (get_u64_field(json, tokens, count, object, "ppid", &integer) == 0 &&
        integer <= UINT32_MAX)
        process->ppid = (uint32_t)integer;
    if (get_u64_field(json, tokens, count, object, "uid", &integer) == 0 &&
        integer <= UINT32_MAX)
        process->uid = (uint32_t)integer;
    (void)get_u64_field(json, tokens, count, object, "start_boottime_ns",
                        &process->start_boottime_ns);
    index = object_value(json, tokens, count, object, "process_instance_id");
    if (index >= 0)
        (void)copy_json_string(json, &tokens[index],
                               process->process_instance_id,
                               sizeof(process->process_instance_id));
    index = object_value(json, tokens, count, object, "comm");
    if (index >= 0)
        (void)copy_json_string(json, &tokens[index], process->comm,
                               sizeof(process->comm));
    index = object_value(json, tokens, count, object, "exe");
    if (index >= 0)
        (void)copy_json_string(json, &tokens[index], process->exe,
                               sizeof(process->exe));
    index = object_value(json, tokens, count, object, "exit_seen");
    if (index >= 0 && token_to_bool(json, &tokens[index], &exit_seen) == 0)
        process->exit_seen = exit_seen;

    activity = object_value(json, tokens, count, object, "activity");
    parse_activity(json, tokens, count, activity, &process->activity);
    resources = object_value(json, tokens, count, object, "resources");
    if (resources >= 0 && tokens[resources].type == JT_OBJECT &&
        get_double_field(json, tokens, count, resources, "cpu_utilization",
                         &process->cpu_utilization) == 0 &&
        process->cpu_utilization >= 0.0 &&
        get_u64_field(json, tokens, count, resources, "memory_bytes",
                      &process->memory_bytes) == 0 &&
        get_double_field(json, tokens, count, resources, "io_bytes_per_sec",
                         &process->io_bytes_per_sec) == 0 &&
        process->io_bytes_per_sec >= 0.0)
        process->resources_present = true;

    index = object_value(json, tokens, count, object, "sampled_this_window");
    if (index < 0 && resources >= 0)
        index = object_value(json, tokens, count, resources,
                             "sampled_this_window");
    if (index >= 0 && token_to_bool(json, &tokens[index], &fresh) == 0)
        process->resource_sample_fresh = fresh;
    return 0;
}

int telemetry_parse_json(const char *json, size_t length,
                         fe_host_window_t *window)
{
    json_token_t tokens[JSON_TOKEN_CAPACITY];
    int count;
    int index;
    int telemetry;
    int processes;
    int quality;
    uint64_t integer;
    size_t process_count = 0;

    if (!json || !window || length == 0 || length >= TELEMETRY_MAX_JSON_LINE)
        return -1;
    if (validate_json_document(json, length) < 0)
        return -1;
    count = tokenize_json(json, length, tokens, JSON_TOKEN_CAPACITY);
    if (count <= 0 || tokens[0].type != JT_OBJECT)
        return -1;
    memset(window, 0, sizeof(*window));
    if (get_u64_field(json, tokens, count, 0, "schema_version", &integer) < 0 ||
        integer != 2 || integer > UINT32_MAX)
        return -1;
    window->schema_version = (uint32_t)integer;
    (void)get_u64_field(json, tokens, count, 0, "timestamp_ns",
                        &window->timestamp_ns);
    index = object_value(json, tokens, count, 0, "host_id");
    if (index < 0 || copy_json_string(json, &tokens[index], window->host_id,
                                      sizeof(window->host_id)) < 0 ||
        window->host_id[0] == '\0')
        return -1;
    if (get_u64_field(json, tokens, count, 0, "window_start_ns",
                      &window->window_start_ns) < 0 ||
        get_u64_field(json, tokens, count, 0, "window_end_ns",
                      &window->window_end_ns) < 0)
        return -1;

    telemetry = object_value(json, tokens, count, 0, "telemetry");
    parse_activity(json, tokens, count, telemetry, &window->host_activity);
    quality = object_value(json, tokens, count, 0, "data_quality");
    if (quality >= 0 && tokens[quality].type == JT_OBJECT) {
        bool emitted = get_u64_field(json, tokens, count, quality,
                                     "process_records_emitted",
                                     &window->process_records_emitted) == 0;
        bool suppressed = get_u64_field(json, tokens, count, quality,
                                        "process_records_suppressed",
                                        &window->process_records_suppressed) == 0;
        (void)get_u64_field(json, tokens, count, quality, "ringbuf_drops",
                            &window->ringbuf_drops);
        (void)get_u64_field(json, tokens, count, quality, "ipc_drops",
                            &window->ipc_drops);
        window->quality_present = emitted && suppressed;
    }

    processes = object_value(json, tokens, count, 0, "processes");
    if (processes < 0 || tokens[processes].type != JT_ARRAY)
        return -1;
    for (index = processes + 1; index < count; index++) {
        if (tokens[index].parent != processes)
            continue;
        if (tokens[index].type != JT_OBJECT || process_count >= FE_MAX_PROCESSES)
            return -1;
        (void)parse_process(json, tokens, count, index,
                            &window->processes[process_count]);
        process_count++;
    }
    window->process_count = process_count;
    return 0;
}

void telemetry_stream_init(telemetry_stream_t *stream)
{
    if (stream)
        memset(stream, 0, sizeof(*stream));
}

static void consume_line(telemetry_stream_t *stream,
                         telemetry_record_callback_t callback,
                         void *context)
{
    fe_host_window_t window;
    size_t length = stream->used;
    if (length > 0 && stream->buffer[length - 1U] == '\r')
        length--;
    if (length == 0) {
        stream->used = 0;
        return;
    }
    if (telemetry_parse_json(stream->buffer, length, &window) == 0) {
        stream->records_parsed++;
        if (callback)
            callback(&window, context);
    } else {
        stream->malformed_records++;
    }
    stream->used = 0;
}

int telemetry_stream_consume(telemetry_stream_t *stream,
                             const char *bytes,
                             size_t length,
                             telemetry_record_callback_t callback,
                             void *context)
{
    size_t i;
    if (!stream || (!bytes && length != 0))
        return -1;
    for (i = 0; i < length; i++) {
        char c = bytes[i];
        if (stream->discarding_oversize) {
            if (c == '\n')
                stream->discarding_oversize = false;
            continue;
        }
        if (c == '\n') {
            consume_line(stream, callback, context);
            continue;
        }
        if (stream->used + 1U >= sizeof(stream->buffer)) {
            stream->used = 0;
            stream->discarding_oversize = true;
            stream->oversize_records++;
            continue;
        }
        stream->buffer[stream->used++] = c;
    }
    return 0;
}

void telemetry_reader_init(telemetry_reader_t *reader, const char *socket_path)
{
    const char *selected_path;
    if (!reader)
        return;
    memset(reader, 0, sizeof(*reader));
    reader->fd = -1;
    selected_path = socket_path && socket_path[0] ? socket_path :
                    TELEMETRY_SOCKET_PATH;
    if (strlen(selected_path) < sizeof(reader->socket_path))
        (void)snprintf(reader->socket_path, sizeof(reader->socket_path), "%s",
                       selected_path);
    telemetry_stream_init(&reader->stream);
}

int telemetry_reader_connect(telemetry_reader_t *reader)
{
#if TR_HAS_UNIX_SOCKET
    struct sockaddr_un address;
    int fd;
    if (!reader || reader->fd >= 0 || reader->socket_path[0] == '\0') {
        if (reader && reader->socket_path[0] == '\0')
            errno = ENAMETOOLONG;
        return reader && reader->fd >= 0 ? 0 : -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                 reader->socket_path) < 0 ||
        strlen(reader->socket_path) >= sizeof(address.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    reader->fd = fd;
    return 0;
#else
    (void)reader;
    errno = ENOTSUP;
    return -1;
#endif
}

int telemetry_reader_pump(telemetry_reader_t *reader,
                          telemetry_record_callback_t callback,
                          void *context)
{
#if TR_HAS_UNIX_SOCKET
    char buffer[8192];
    ssize_t received;
    if (!reader || reader->fd < 0)
        return -1;
    do {
        received = recv(reader->fd, buffer, sizeof(buffer), 0);
    } while (received < 0 && errno == EINTR);
    if (received == 0) {
        telemetry_reader_close(reader);
        return 0;
    }
    if (received < 0)
        return -1;
    return telemetry_stream_consume(&reader->stream, buffer, (size_t)received,
                                    callback, context) == 0 ? 1 : -1;
#else
    (void)reader;
    (void)callback;
    (void)context;
    errno = ENOTSUP;
    return -1;
#endif
}

void telemetry_reader_close(telemetry_reader_t *reader)
{
    if (!reader)
        return;
#if TR_HAS_UNIX_SOCKET
    if (reader->fd >= 0)
        close(reader->fd);
#endif
    reader->fd = -1;
    reader->stream.used = 0;
    reader->stream.discarding_oversize = false;
}
