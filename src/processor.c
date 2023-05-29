#include <assert.h>

#include "processor.h"
#include "instruction.h"
#include "opcode.h"
#include "types.h"

void processor_set_flags(processor_t *cpu, u16 value) {
    u8 flags = 0;
    if (value & U16_SIGN_BIT) {
        flags |= FLAG_SIGN;
    } else if (value == 0) {
        flags |= FLAG_ZERO;
    }

    u16 xor_value = value;
    xor_value ^= xor_value >> 8;
    xor_value ^= xor_value >> 4;
    xor_value ^= xor_value >> 2;
    xor_value ^= xor_value >> 1;
    if (~xor_value & 1) {
        flags |= FLAG_PARITY;
    }

    cpu->flags = flags;
}

u32 processor_exec(processor_t *cpu, const instruction_t instruction) {
    const operand_t *operands = instruction.operands;

    switch (instruction.op_code) {
        case OP_MOV:
            if(operands[1].type == OperandRegister) {
                u8 reg_dst = operands[0].reg.index;
                u8 reg_src = operands[1].reg.index;
                cpu->registers[reg_dst] = cpu->registers[reg_src];
                // processor_set_flags(cpu, cpu->registers[reg_dst]);
            }
            break;
        case OP_MOV_IMM2REG:
            if (instruction.operands[1].type == OperandImmediate) {
                u8 reg = operands[0].reg.index;
                u16 value = operands[1].imm.value;
                cpu->registers[reg] = value;
                // processor_set_flags(cpu, value);
            }
            break;
        case OP_MOV_ACC2MEM:
        case OP_MOV_IMM2REGMEM:
        case OP_MOV_MEM2ACC:
            goto unimplemented;

        case OP_ADD:
            if(operands[1].type == OperandRegister) {
                u8 reg_dst = operands[0].reg.index;
                u8 reg_src = operands[1].reg.index;
                u16 sum = cpu->registers[reg_dst] + cpu->registers[reg_src];
                cpu->registers[reg_dst] = sum;
                processor_set_flags(cpu, sum);
            }
            break;

        case OP_ADD_IMM2ACC:
        case OP_ADD_IMM2REGMEM:
            if(operands[1].type == OperandImmediate) {
                u8 reg = operands[0].reg.index;
                u16 value = cpu->registers[reg] + operands[1].imm.value;
                cpu->registers[reg] = value;
                processor_set_flags(cpu, value);
            }
            break;

        case OP_SUB:
            if(operands[1].type == OperandRegister) {
                u8 reg_dst = operands[0].reg.index;
                u8 reg_src = operands[1].reg.index;
                u16 sum = cpu->registers[reg_dst] - cpu->registers[reg_src];
                cpu->registers[reg_dst] = sum;
                processor_set_flags(cpu, sum);
            }
            break;

        case OP_SUB_IMM_FROM_ACC:
        case OP_SUB_IMM_FROM_REGMEM:
            if(operands[1].type == OperandImmediate) {
                u8 reg = operands[0].reg.index;
                u16 value = cpu->registers[reg] - operands[1].imm.value;
                cpu->registers[reg] = value;
                processor_set_flags(cpu, value);
            }
            break;

        case OP_CMP_IMM_WITH_ACC:
        case OP_CMP_IMM_WITH_REGMEM:
            if(operands[1].type == OperandRegister) {
                u8 reg = operands[0].reg.index;
                u16 sum = cpu->registers[reg] - operands[1].imm.value;
                processor_set_flags(cpu, sum);
            }
            break;

        case OP_CMP_REGMEM_REG:
            if(operands[0].type == OperandRegister) {
                u8 reg_dst = operands[0].reg.index;
                u8 reg_src = operands[1].reg.index;
                u16 sum = cpu->registers[reg_dst] - cpu->registers[reg_src];
                processor_set_flags(cpu, sum);
            }
            break;
    }

    return 0;

unimplemented:
    assert(0 && "Unimplemented instruction interpretation!");
    return 1;
}
