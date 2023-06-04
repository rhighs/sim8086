#include <assert.h>
#include <stdlib.h>
#include <memory.h>

#include "decoder.h"
#include "processor.h"
#include "instruction.h"
#include "opcode.h"
#include "types.h"

static
u32 processor_next_ip(processor_t *cpu) {
    for (u32 i = cpu->ip + 1;
        i < cpu->ip2instrno_len;
        i++) {
        if (cpu->ip2instrno[i] != __CPU_IP2ISNTRNO_NONE) 
            return i;
    }

    // No instruction was found? we must be at the end
    return cpu->ip2instrno_len;
}

u32 processor_init(processor_t *cpu, decoder_context_t *decoder_ctx) {
    const u32 instructions_size = decoder_ctx->buflen * sizeof(instruction_t);

    cpu->instructions = (instruction_t *)malloc(instructions_size);
    memset(cpu->instructions, 0, instructions_size);

    const u32 ip2instrno_size = decoder_ctx->buflen * sizeof(u32);
    cpu->ip2instrno = (u32 *)malloc(ip2instrno_size);
    memset(cpu->ip2instrno, __CPU_IP2ISNTRNO_NONE, ip2instrno_size);
    cpu->ip2instrno_len = decoder_ctx->buflen;

    instruction_t decoded = { 0 };

    u32 n_decoded = 0;
    u32 ip = 0;
    for (; ip < cpu->ip2instrno_len; ip += 2) {
        u32 new_ip = decode(decoder_ctx, &decoded, ip, NULL);
        assert(new_ip < decoder_ctx->buflen && "new IP value must be within buffer bounds");

        cpu->instructions[n_decoded] = decoded;
        cpu->ip2instrno[ip] = n_decoded;
        n_decoded += 1;

        ip = new_ip;
    }

    cpu->ip = 0;

    return n_decoded;
}

void processor_set_flags(processor_t *cpu, u16 value) {
    u8 flags = 0;
    if (value & __CPU_U16_SIGN_BIT) {
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

    cpu->ip = processor_next_ip(cpu);

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

                u32 sum = 0;
                if (instruction.is_wide) {
                    const u16 value = cpu->registers[reg_src];
                    const i16 value_sgn = operands[1].imm.value;
                    sum = value_sgn < 0
                        ? (u32)(cpu->registers[reg_dst])
                                - (u32)(abs(value_sgn))
                        : (u32)(cpu->registers[reg_dst])
                                + (u32)(value);
                } else {
                    const u8 value = operands[1].imm.value;
                    const i8 value_sgn = operands[1].imm.value;
                    sum = value_sgn < 0
                        ? (u32)(cpu->registers[reg_dst])
                                - (u32)(abs((i8)(value_sgn)))
                        : (u32)(cpu->registers[reg_dst])
                                + (u32)(value);
                }

                cpu->registers[reg_dst] = (u16)sum;
                processor_set_flags(cpu, (u16)sum);

                if (sum & 0xFF00) { 
                    cpu->flags |= FLAG_CARRY;
                    cpu->flags |= FLAG_OVERFLOW;
                }
            }
            break;

        case OP_ADD_IMM2ACC:
        case OP_ADD_IMM2REGMEM:
            if(operands[1].type == OperandImmediate) {
                u8 reg = operands[0].reg.index;

                u32 sum = 0;
                if (instruction.is_wide) {
                    const u16 value = operands[1].imm.value;
                    const i16 value_sgn = operands[1].imm.value;
                    sum = value_sgn < 0
                        ? (u32)(cpu->registers[reg])
                                - (u32)(abs(value_sgn))
                        : (u32)(cpu->registers[reg])
                                + (u32)(value);
                } else {
                    const u8 value = operands[1].imm.value;
                    const i8 value_sgn = operands[1].imm.value;
                    sum = value_sgn < 0
                        ? (u32)(cpu->registers[reg])
                                - (u32)(abs((i8)(value_sgn)))
                        : (u32)(cpu->registers[reg])
                                + (u32)(value);
                }

                cpu->registers[reg] = (u16)sum;
                processor_set_flags(cpu, (u16)sum);

                if (sum & 0xFF00) { 
                    cpu->flags |= FLAG_CARRY;
                    cpu->flags |= FLAG_OVERFLOW;
                }
            }
            break;

        case OP_SUB:
            if(operands[1].type == OperandRegister) {
                u8 reg_dst = operands[0].reg.index;
                u8 reg_src = operands[1].reg.index;
                u16 a = cpu->registers[reg_dst];
                u16 b = cpu->registers[reg_src];
                u16 sum = a - b;

                cpu->registers[reg_dst] = sum;
                processor_set_flags(cpu, sum);

                if (b > a) {
                    cpu->flags |= FLAG_CARRY;
                }
            }
            break;

        case OP_SUB_IMM_FROM_ACC:
        case OP_SUB_IMM_FROM_REGMEM:
            if(operands[1].type == OperandImmediate) {
                u8 reg = operands[0].reg.index;
                u16 a = cpu->registers[reg];
                u16 b = operands[1].imm.value;;
                u16 value = a - b;
                cpu->registers[reg] = value;
                processor_set_flags(cpu, value);

                if (b > a) {
                    cpu->flags |= FLAG_CARRY;
                }
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
        case OP_JZ:
            assert(operands[0].type == OperandImmediate);
            if (cpu->flags & FLAG_ZERO) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JL:
        case OP_JNGE:
            assert(operands[0].type == OperandImmediate);
            if ((cpu->flags & FLAG_SIGN ? 1 : 0)
                    ^ (cpu->flags & FLAG_OVERFLOW ? 1 : 0)) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JNL:
        case OP_JGE:
            assert(operands[0].type == OperandImmediate);
            if ((cpu->flags & FLAG_SIGN ? 1 : 0)
                    == (cpu->flags & FLAG_OVERFLOW ? 1 : 0)) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JB:
        case OP_JNAE:
        // case OP_JC:
            assert(operands[0].type == OperandImmediate);
            if (cpu->flags & FLAG_CARRY) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JBE:
        case OP_JNA:
            assert(operands[0].type == OperandImmediate);
            if ((cpu->flags & FLAG_CARRY) || (cpu->flags & FLAG_ZERO)) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JP:
        case OP_JPE:
            assert(operands[0].type == OperandImmediate);
            if (cpu->flags & FLAG_PARITY) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JO:
            assert(operands[0].type == OperandImmediate);
            if (cpu->flags & FLAG_OVERFLOW) {
                __CPU_JUMP(operands[0].imm.value);
            }
        case OP_JNO:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_OVERFLOW)) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JS:
            assert(operands[0].type == OperandImmediate);
            if (cpu->flags & FLAG_SIGN) {
                __CPU_JUMP(operands[0].imm.value);
            }
        case OP_JNS:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_SIGN)) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JNZ:
        case OP_JNE:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_ZERO)) {
                __CPU_JUMP(operands[0].imm.value);
            }
        break;

        case OP_JLE:
        case OP_JNG:
            assert(operands[0].type == OperandImmediate);
            if ((cpu->flags & FLAG_ZERO) ||
                ((cpu->flags & FLAG_SIGN ? 1 : 0)
                ^ (cpu->flags & FLAG_OVERFLOW ? 1 : 0))) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;
        case OP_JG:
        case OP_JNLE:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_ZERO) &&
                (cpu->flags & FLAG_SIGN ? 1 : 0)
                == (cpu->flags & FLAG_OVERFLOW ? 1 : 0)) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JNBE:
        case OP_JA:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_CARRY) && !(cpu->flags & FLAG_ZERO)) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JNP:
        case OP_JPO:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_PARITY)) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;

        case OP_JCXZ:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->registers[REG_CX])) {
                __CPU_JUMP(operands[0].imm.value);
            }
            break;
        default:
            goto unimplemented;
    }

    return 0;

unimplemented:
    assert(0 && "Unimplemented instruction interpretation!");
    return 1;
}
