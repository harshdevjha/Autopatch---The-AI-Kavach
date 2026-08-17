/*
 * buggy.c
 * A tiny "message parser" service.
 * It reads a line from stdin (simulating a network packet) and copies the
 * payload into a fixed-size buffer without checking the length.
 *
 * This mirrors the kind of bug the project targets: a classic CWE-121
 * stack-based buffer overflow, the sort a fuzzer trips over in seconds
 * and a static analyzer can flag by pattern (unchecked strcpy).
 */
#include <stdio.h>
#include <string.h>

void parse_input(char *packet) {
    char buffer[64];        // fixed-size stack buffer
    strcpy(buffer, packet); // VULNERABLE: no bounds check -> overflow
    printf("Parsed packet: %s\n", buffer);
}

int main(void) {
    char packet[4096];
    if (fgets(packet, sizeof(packet), stdin) == NULL) {
        return 0;
    }
    // strip trailing newline
    packet[strcspn(packet, "\n")] = '\0';
    parse_input(packet);
    return 0;
}
