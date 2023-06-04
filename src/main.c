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

    u32 n_instructions = processor_init(&cpu, &decoder_ctx);

    while (1) {
        if (cpu.ip == cpu.ip2instrno_len) {
            break;
        }

        // Fetch instruction
        instruction_t instruction = cpu.instructions[cpu.ip2instrno[cpu.ip]];

        u32 old_ip = cpu.ip;
        u32 exec_err = processor_exec(&cpu, instruction);

        if (exec_err) {
            fprintf(stderr, "Failed execution of instruction at PC: %d\n", decoder_ctx.pc);
            break;
        }

        if (old_ip == cpu.ip) {
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

    return EXIT_SUCCESS;
}
