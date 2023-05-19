#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "decoder.h"

int main(int argc, const char **argv) {
    if (argc < 2)  {
        fprintf(stderr, "[NO_ARG_ERR]: no file arg provided\n");
        return -1;
    }

    const char* filepath = argv[1];
    u32 nread = init_from_file(filepath);
    if (!nread) {
        return -1;
    }

    char* out[OUT_BUFSIZE];
    for (u32 i=0; i<OUT_BUFSIZE; i++) {
        out[i] = malloc(sizeof(char) * 64);
        memset(out[i], 0, sizeof(char) * 64);
    }

    u32 out_cursor = 0;
    strcat(out[out_cursor], "bits 16\n\n");
    out_cursor += 1;

    u32 *ip_to_cursor = malloc(sizeof(u32) * nread);
    memset(ip_to_cursor, 0, sizeof(u32) * nread);

    for (u32 ip=0; ip<nread; ip+=2) {
        char line[64];

        ip = decode(buf, ip, line);

        // Keep tracks of ip -> line
        ip_to_cursor[ip] = out_cursor;

        assert(strlen(line) != 0);
        strcat(line, "\n");
        strcpy(out[out_cursor++], line);
#ifdef DEBUG
        printf("\n==================\nLINE: %s==================\n", line);
#endif
    }

    for (u32 i=0; i<OUT_BUFSIZE; i++) {
        fprintf(stdout, "%s", out[i]);
        for (u32 label_location=0;
             label_location<jmp_locations.len; 
             label_location++) {
            if (ip_to_cursor[jmp_locations.buf[label_location]] == i) {
                fprintf(stdout, "%s\n", jmp_locations.labels[label_location]);
            }
        }
    }

    return 0;
}
