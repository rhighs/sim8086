#include <stdlib.h>
#include <stdio.h>

#include "decoder.h"

typedef struct {
    u16 registers[8];
} processor_t;

#define REG_AX 0
#define REG_BX 3
#define REG_CX 1
#define REG_DX 2
#define REG_SP 4
#define REG_BP 5
#define REG_SI 6
#define REG_DI 7

u32 processor_exec(processor_t *cpu, const instruction_t instruction) {
    const operand_t *operands = instruction.operands;
    switch (instruction.op_code) {
        case OP_MOV:
        case OP_MOV_IMM2REG:
        case OP_MOV_ACC2MEM:
        case OP_MOV_IMM2REGMEM:
        case OP_MOV_MEM2ACC:
            if (instruction.operands[1].type == OperandImmediate) {
                u8 reg = operands[0].reg.index;
                u16 value = operands[1].imm.value;
                cpu->registers[reg] = value;
            } else if (operands[1].type == OperandRegister) {
                u8 reg_dst = operands[0].reg.index;
                u8 reg_src = operands[1].reg.index;
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
    printf("CPU mem state:\nax\tbx\tcx\tdx\tsp\tbp\tsi\tdi\n"
                           "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", 
            cpu.registers[REG_AX],
            cpu.registers[REG_BX],
            cpu.registers[REG_CX],
            cpu.registers[REG_DX],
            cpu.registers[REG_SP],
            cpu.registers[REG_BP],
            cpu.registers[REG_SI],
            cpu.registers[REG_DI]);

    return EXIT_SUCCESS;
}
