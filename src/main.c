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

        if (!processor_fetch_instruction(&cpu, &instruction)) {
            break;
        }

        u32 exec_err = processor_exec(&cpu, instruction);
        if (exec_err) {
            fprintf(stderr, "Failed execution of instruction at PC: %d\n", decoder_ctx.pc);
            break;
        }
    }

    u8 i = 0;
    printf("CPU mem state:\n\tax\tbx\tcx\tdx\tsp\tbp\tsi\tdi\n"
                           "\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n\n", 
            cpu.registers[REG_AX],
            cpu.registers[REG_BX],
            cpu.registers[REG_CX],
            cpu.registers[REG_DX],
            cpu.registers[REG_SP],
            cpu.registers[REG_BP],
            cpu.registers[REG_SI],
            cpu.registers[REG_DI]);

    printf("CPU flags:\n\tZ\tS\tO\tC\tP\n\t%d\t%d\t%d\t%d\t%d\n",
            (cpu.flags & FLAG_ZERO)     != 0,
            (cpu.flags & FLAG_SIGN)     != 0,
            (cpu.flags & FLAG_OVERFLOW) != 0,
            (cpu.flags & FLAG_CARRY)    != 0,
            (cpu.flags & FLAG_PARITY)   != 0);

    printf("\nCPU ip: %d\n", cpu.ip);

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
