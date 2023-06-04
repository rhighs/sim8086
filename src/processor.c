#include <assert.h>
#include <stdlib.h>
#include <memory.h>

#include "decoder.h"
#include "processor.h"
#include "instruction.h"
#include "opcode.h"
#include "types.h"

u32 processor_init(processor_t *cpu, decoder_context_t *decoder_ctx) {
    u32 instructions_size = decoder_ctx->buflen * sizeof(instruction_t);

    cpu->instructions = (instruction_t *)malloc(instructions_size);
    memset(cpu->instructions, 0, instructions_size);

    u32 ip2instrno_size = decoder_ctx->buflen* sizeof(u32);
    cpu->ip2instrno = (u32 *)malloc(ip2instrno_size);

    u32 n_decoded = 0;
    for (u32 ip=0;
         ip < decoder_ctx->buflen;
         ip += 2) {

        instruction_t decoded = { 0 };
        ip = decode(decoder_ctx, &decoded, ip, NULL);
        assert(ip < decoder_ctx->buflen && "new IP value must be within buffer bounds");

        cpu->instructions[n_decoded] = decoded;
        cpu->ip2instrno[ip] = n_decoded;
        n_decoded += 1;
    }

    return n_decoded;
}

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
            }
            break;
        case OP_MOV_IMM2REG:
            if (instruction.operands[1].type == OperandImmediate) {
                u8 reg = operands[0].reg.index;
                u16 value = operands[1].imm.value;
                cpu->registers[reg] = value;
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
        case OP_JE:
        case OP_JL:
        case OP_JLE:
        case OP_JB:
        case OP_JBE:
        case OP_JP:
        case OP_JO:
        case OP_JS:
        case OP_JNE:
        case OP_JNL:
        case OP_JNLE:
        case OP_JNB:
        case OP_JNBE:
        case OP_JNP:
        case OP_JNO:
        case OP_JNS:
        case OP_JCXZ:
            goto unimplemented;
            break;
    }

    return 0;

unimplemented:
    assert(0 && "Unimplemented instruction interpretation!");
    return 1;
}
