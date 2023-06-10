#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "decoder.h"
#include "processor.h"
#include "instruction.h"
#include "opcode.h"
#include "types.h"

u8 __cpu_memory[__CPU_MEM_SIZE];

static
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

static
u8 processor_mov_memory(processor_t *cpu, const instruction_t instruction) {
    return TRUE;
}

static
u8 processor_exec_mov(processor_t *cpu, const op_code_t op_code, 
        const operand_t destination_operand, const operand_t source_operand) {
    if (op_code == OP_MOV) {
        assert(source_operand.type == OperandRegister);

        u8 reg_dst = destination_operand.reg.index;
        u8 reg_src = source_operand.reg.index;
        cpu->registers[reg_dst] = cpu->registers[reg_src];
    } else if (op_code == OP_MOV_IMM2REG) {
        assert(source_operand.type == OperandImmediate);

        u8 reg = destination_operand.reg.index;
        u16 value = source_operand.imm.value;
        cpu->registers[reg] = value;
    } else if (op_code == OP_MOV_ACC2MEM) {
        assert(destination_operand.type == OperandMemory);
        assert(source_operand.type == OperandRegister);

        u32 offset = destination_operand.offset.regs[0];
        u32 reg = source_operand.reg.index;
        cpu->memory[offset] = cpu->registers[reg];
    } else if (op_code == OP_MOV_IMM2REGMEM) {
        assert(source_operand.type == OperandImmediate);
        assert(destination_operand.type == OperandRegister
                || destination_operand.type == OperandMemory
                || destination_operand.type == OperandMemoryOffset
                || destination_operand.type == OperandMemoryOffset8
                || destination_operand.type == OperandMemoryOffset16);

        u32 value = source_operand.imm.value;

        if (destination_operand.type == OperandRegister) {
            u32 reg = destination_operand.reg.index;
            cpu->registers[reg] = value;
        } else if (destination_operand.type == OperandMemory) {
            u32 offset = destination_operand.offset.offset;
            cpu->memory[offset] = value;
        } else if (destination_operand.type == OperandMemoryOffset) {
            u32 offset = 0;
            offset += destination_operand.offset.regs[0];
            offset += destination_operand.offset.n_regs > 1
                ? destination_operand.offset.regs[1]
                : 0;
            cpu->memory[offset] = value;
        } else if (destination_operand.type == OperandMemoryOffset8) {
            u32 offset = 0;
            offset += destination_operand.offset.regs[0];
            offset += destination_operand.offset.n_regs > 1
                ? destination_operand.offset.regs[1]
                : 0;
            offset += destination_operand.offset.offset & 0xF;
            cpu->memory[offset] = value;
        } else if (destination_operand.type == OperandMemoryOffset16) {
            u32 offset = 0;
            offset += destination_operand.offset.regs[0];
            offset += destination_operand.offset.n_regs > 1
                ? destination_operand.offset.regs[1]
                : 0;
            offset += destination_operand.offset.offset;
            cpu->memory[offset] = value;
        }
    } else if (op_code == OP_MOV_MEM2ACC) {
        assert(source_operand.type == OperandMemory);
        assert(destination_operand.type == OperandRegister);

        u32 reg = destination_operand.reg.index;
        u32 offset = source_operand.offset.regs[0];
        cpu->registers[reg] = cpu->memory[offset];
    }

    return TRUE;
}

u32 processor_init(processor_t *cpu, const u8 *program, const u32 size) {
    assert(cpu != NULL && program != NULL);
    assert(size < __CPU_MEM_SIZE && "Executable must be less than 64KB");

    // Zero init
    int *err;
    if ((err = (int *)memset(cpu, 0, sizeof(processor_t))) == NULL) {
        fprintf(stderr, "Failed zero memset on processor data\n");
        return 0;
    }

    // Load program data
    cpu->program_size = size;
    cpu->memory = (u8 *)__cpu_memory;
    if ((err = (int *)memcpy(cpu->memory, program, size)) == NULL) {
        fprintf(stderr, "Failed allocating processor program data\n");
        return 0;
    }

    if (!decoder_init((&cpu->decoder_ctx), cpu->memory, size)) {
        fprintf(stderr, "Processor decoder initialization has failed\n");
        return 0;
    }

    return 1;
}

u32 processor_fetch_instruction(processor_t *cpu, instruction_t *instruction) {
    const u32 ip = cpu->ip;
    const u32 new_ip = decode(&(cpu->decoder_ctx), instruction, ip, NULL);
    assert(new_ip < __CPU_MEM_SIZE
            && "new IP value must be within buffer bounds");
    if (new_ip > cpu->program_size) {
        cpu->ip -= 2;
        return 0;
    }

    cpu->ip = new_ip + 2;

    return 1;
}

u32 processor_exec(processor_t *cpu, const instruction_t instruction) {
    const operand_t *operands = instruction.operands;

    switch (instruction.op_code) {
        case OP_MOV:
        case OP_MOV_IMM2REG:
        case OP_MOV_ACC2MEM:
        case OP_MOV_IMM2REGMEM:
        case OP_MOV_MEM2ACC:
            if (!processor_exec_mov(cpu, instruction.op_code,
                        instruction.operands[0], instruction.operands[1])) {
                goto unimplemented;
            }

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
