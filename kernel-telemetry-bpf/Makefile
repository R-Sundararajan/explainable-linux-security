CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

CFLAGS := -O2 -g -Wall -Wextra
BPF_CFLAGS := -O2 -g -target bpf
LIBBPF_CFLAGS :=
LIBBPF_LIBS := -lbpf -lelf -lz

.PHONY: all test clean

all: telemetry

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

telemetry.bpf.o: telemetry.bpf.c telemetry_types.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) \
		-c telemetry.bpf.c \
		-o telemetry.bpf.o

telemetry.skel.h: telemetry.bpf.o
	$(BPFTOOL) gen skeleton telemetry.bpf.o > telemetry.skel.h

telemetry: telemetry.c telemetry_socket.c telemetry_socket.h telemetry_types.h telemetry.skel.h
	$(CC) $(CFLAGS) \
		$(LIBBPF_CFLAGS) \
		telemetry.c telemetry_socket.c \
		-o telemetry \
		$(LIBBPF_LIBS)

tests/test_process_coverage: tests/test_process_coverage.c telemetry.c telemetry_types.h
	$(CC) $(CFLAGS) -std=c11 \
		tests/test_process_coverage.c \
		-o tests/test_process_coverage

test: tests/test_process_coverage
	./tests/test_process_coverage | python3 tests/validate_process_coverage.py

clean:
	rm -f telemetry telemetry.bpf.o telemetry.skel.h vmlinux.h \
		tests/test_process_coverage tests/test_process_coverage.exe
