#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static void consume_input(void)
{
    char buffer[4096];
    while (fread(buffer, 1, sizeof(buffer), stdin) > 0) { }
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "valid";
    int network_socket;
    struct sockaddr_in remote;
    consume_input();
    if (geteuid() != 65534 || access("/bin/sh", F_OK) == 0)
        return 21;
    network_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (network_socket >= 0) {
        memset(&remote, 0, sizeof(remote));
        remote.sin_family = AF_INET;
        remote.sin_port = htons(53);
        (void)inet_pton(AF_INET, "1.1.1.1", &remote.sin_addr);
        if (connect(network_socket, (struct sockaddr *)&remote,
                    sizeof(remote)) == 0) {
            close(network_socket);
            return 22;
        }
        close(network_socket);
    }
    if (strcmp(mode, "timeout") == 0) {
        sleep(30);
        return 0;
    }
    if (strcmp(mode, "spawn") == 0) {
        int index;
        for (index = 0; index < 4; index++) {
            if (fork() == 0) {
                sleep(30);
                _exit(0);
            }
        }
        sleep(30);
        return 0;
    }
    if (strcmp(mode, "oversized") == 0) {
        int index;
        for (index = 0; index < 40000; index++)
            putchar('x');
        return 0;
    }
    if (strcmp(mode, "malformed") == 0) {
        puts("not-json");
        return 0;
    }
    if (strcmp(mode, "ungrounded") == 0) {
        puts("{\"verdict\":\"SUSPICIOUS\",\"hypotheses\":[],"
             "\"supporting_evidence_ids\":[\"invented\"],"
             "\"contradicting_evidence_ids\":[],\"missing_evidence\":[],"
             "\"suspected_patterns\":[],\"reasoning_summary\":\"Invalid reference.\"}");
        return 0;
    }
    if (strcmp(mode, "duplicate") == 0) {
        puts("{\"verdict\":\"BENIGN\",\"verdict\":\"MALICIOUS\","
             "\"hypotheses\":[],\"supporting_evidence_ids\":[],"
             "\"contradicting_evidence_ids\":[],\"missing_evidence\":[],"
             "\"suspected_patterns\":[],\"reasoning_summary\":\"Duplicate key.\"}");
        return 0;
    }
    puts("{\"verdict\":\"INDETERMINATE\",\"hypotheses\":[],"
         "\"supporting_evidence_ids\":[],\"contradicting_evidence_ids\":[],"
         "\"missing_evidence\":[],\"suspected_patterns\":[],"
         "\"reasoning_summary\":\"Insufficient context for a grounded classification.\"}");
    if (strcmp(mode, "trailer") == 0)
        puts("[end of text]");
    return 0;
}
