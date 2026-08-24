CC ?= cc
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Werror
CPPFLAGS ?= -Ifeature_engineering -Ibaseline_manager -Ianomaly_classifier -Ievidence
LDLIBS ?= -lm

CORE_SOURCES = \
	feature_engineering/feature_engineering.c \
	feature_engineering/telemetry_reader.c \
	baseline_manager/baseline_manager.c \
	anomaly_classifier/anomaly_classifier.c

EVIDENCE_SOURCES = \
	evidence/evidence_builder.c \
	evidence/evidence_json.c \
	evidence/evidence_sink.c

.PHONY: all clean test check

all: anomaly_pipeline

anomaly_pipeline: anomaly_pipeline.c $(CORE_SOURCES) $(EVIDENCE_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LDLIBS)

tests/test_pipeline: tests/test_pipeline.c $(CORE_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LDLIBS)

tests/test_evidence: tests/test_evidence.c $(CORE_SOURCES) $(EVIDENCE_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LDLIBS)

test: tests/test_pipeline tests/test_evidence
	./tests/test_pipeline
	python3 tests/validate_evidence_schema.py

check: test

clean:
	rm -f anomaly_pipeline tests/test_pipeline tests/test_evidence
