#include <stdlib.h>
#include <stdio.h>

#include "decoder.h"

typedef struct {
    u16 registers[8];
} processor_t;

u32 processor_exec(processor_t *cpu, const instruction_t instruction) {
    operand_t **operands = instruction.operands;
    switch (instruction.op_code) {
        case MOV:
            if (instruction.operands[1]->type == OperandImmediate) {
                u32 reg = operands[0]->reg.index;
                u16 value = operands[1]->imm.value;
                cpu->registers[reg] = value;
            } else if (operands[1]->type == OperandRegister) {
                u32 reg_dst = operands[0]->reg.index;
                u16 reg_src = operands[1]->reg.index;
                cpu->registers[reg_dst] = cpu->registers[reg_src];
            }
            break;
    }

    return 0;
}

i32 main(i32 argc, char *argv[]) {
    if (argc < 2)  {
        fprintf(stderr, "[NO_ARG_ERR]: no file arg provided\n");
        return EXIT_FAILURE;
    }

    processor_t cpu = { 0 };
    decoder_context_t *decoder_ctx;

    const char* filepath = argv[1];
    u32 nread = init_from_file(decoder_ctx, filepath);
    if (!nread) {
        return EXIT_FAILURE;
    }

    for (u32 cursor=0; cursor<nread; cursor+=2) {
        instruction_t decoded = { 0 };

        cursor = decode(decoder_ctx, &decoded, cursor, NULL);

        if (!processor_exec(&cpu, decoded)) {
            fprintf(stderr, "Failed exection of instruction at PC: %d\n", decoder_ctx->pc);
            break;
        }
    }

    return EXIT_SUCCESS;
}
