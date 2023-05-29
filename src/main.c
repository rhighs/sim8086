#include <stdlib.h>
#include <stdio.h>

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
    u32 nread = init_from_file(&decoder_ctx, filepath);
    if (!nread) {
        return EXIT_FAILURE;
    }

    for (u32 cursor=0; cursor<nread; cursor+=2) {
        instruction_t decoded = { 0 };

        cursor = decode(&decoder_ctx, &decoded, cursor, NULL);

        if (processor_exec(&cpu, decoded)) {
            fprintf(stderr, "Failed exection of instruction at PC: %d\n", decoder_ctx.pc);
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

    printf("CPU flags:\n\tZ\tS\n\t%d\t%d\n",
            (cpu.flags & FLAG_ZERO) != 0,
            (cpu.flags & FLAG_SIGN) != 0);

    return EXIT_SUCCESS;
}
