#include <stdlib.h>
#include <stdio.h>

#include "instruction.h"
#include "processor.h"
#include "decoder.h"

i32 main(i32 argc, char *argv[]) {
    if (argc < 2)  {
        fprintf(stderr, "[NO_ARG_ERR]: no file arg provided\n");
        return EXIT_FAILURE;
    }

    processor_t cpu = { 0 };
    decoder_context_t decoder_ctx;

    const char* filepath = argv[1];
    FILE *file = fopen(filepath, "r");
    if (file == NULL)
        goto bad_path_error;

    fseek(file, 0, SEEK_END);
    u32 file_size = ftell(file);
    rewind(file);

    u8 *program = malloc(file_size * sizeof(u8));

    u32 bytes_read = 0;
    for (u32 nread=0;
        (nread = fread(program, sizeof(u8), file_size, file)) > 0;
        ) {
        bytes_read += nread;
    }
    if (ferror(file))
        goto read_error;

    fclose(file);

    if (!processor_init(&cpu, program, bytes_read))
        goto processor_error;

    while (1) {
        u32 old_ip = cpu.ip;
        instruction_t instruction = { 0 };

        char line[32] = {0};
        if (!processor_fetch_instruction(&cpu, &instruction, (char *)line)) {
            break;
        }

        printf("%s\n", line);

        u32 exec_err = processor_exec(&cpu, instruction);
        if (exec_err) {
            fprintf(stderr, "Failed execution of instruction at PC: %d\n", decoder_ctx.pc);
            break;
        }
    }

    processor_state_dump(&cpu, stdout);

    return EXIT_SUCCESS;

processor_error: 
    fprintf(stderr, "[PROCESSOR_ERR]: Couldn't initialize processor data\n");
    return EXIT_FAILURE;
bad_path_error: 
    fprintf(stderr, "[BAD_PATH_ERR]: path %s might not exist\n", filepath);
    return EXIT_FAILURE;
read_error:
    fprintf(stderr, "[READ_FILE_ERR]: error reading file!\n");
    fclose(file);
    return EXIT_FAILURE;
}
