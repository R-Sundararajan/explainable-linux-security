#ifndef EVIDENCE_JSON_H
#define EVIDENCE_JSON_H

#include <stddef.h>

#include "evidence_types.h"

int evidence_json_serialize(const process_evidence_t *evidence,
                            char *buffer, size_t capacity,
                            size_t *serialized_length);

#endif
