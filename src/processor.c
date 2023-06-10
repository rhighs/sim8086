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

static inline
void processor_write_reg_2_mem(processor_t *cpu,
        const u32 mem_offset, const u16 reg) {
    cpu->memory[mem_offset] = cpu->registers[reg];
#ifdef CPU_DEBUG
    printf("[CPU] wrotereg %d to mem location %d\n", reg, mem_offset);
    processor_state_dump(cpu, stdout);
#endif
}

static inline
void processor_write_imm_2_mem(processor_t *cpu,
        const u32 mem_offset, const u16 immediate) {
    cpu->memory[mem_offset] = immediate;
#ifdef CPU_DEBUG
    printf("[CPU] wrote immediate %d to mem location %d\n", immediate, mem_offset);
    processor_state_dump(cpu, stdout);
#endif
}

static inline
void processor_write_mem_2_reg(processor_t *cpu,
        const u32 mem_offset, const u16 reg) {
    cpu->registers[reg] = cpu->memory[mem_offset];
#ifdef CPU_DEBUG
    printf("[CPU] wrote mem location %d to reg %d\n", mem_offset, reg);
    processor_state_dump(cpu, stdout);
#endif
}

static inline
void processor_write_imm_2_reg(processor_t *cpu,
        const u16 reg, const u16 immediate) {
    cpu->registers[reg] = immediate;
#ifdef CPU_DEBUG
    printf("[CPU] wrote immediate %d to reg %d\n", immediate, reg);
    processor_state_dump(cpu, stdout);
#endif
}

static inline
void processor_write_reg_2_reg(processor_t *cpu,
        const u16 reg_dst, const u16 reg_src) {
    cpu->registers[reg_dst] = cpu->registers[reg_src];
#ifdef DEBUG
    printf("[CPU] wrote reg %d to reg %d\n", reg_src, reg_dst);
    processor_state_dump(cpu, stdout);
#endif
}

static
u8 processor_exec_mov(processor_t *cpu, const op_code_t op_code, 
        const operand_t destination_operand, const operand_t source_operand) {
    const u8 source_offset_reg_1 = source_operand.offset.regs[0];
    const u8 source_offset_reg_2 = source_operand.offset.regs[1];
    const u8 destination_offset_reg_1 = destination_operand.offset.regs[0];
    const u8 destination_offset_reg_2 = destination_operand.offset.regs[1];
    const u8 reg_dst = destination_operand.reg.index;
    const u8 reg_src = source_operand.reg.index;
    const u16 source_offset = source_operand.offset.offset;
    const u16 destination_offset = destination_operand.offset.offset;
    const u16 source_immediate = source_operand.imm.value;

    if (op_code == OP_MOV) {
        assert(source_operand.type == OperandRegister
                || source_operand.type == OperandMemory
                || source_operand.type == OperandMemoryOffset);

        if (source_operand.type == OperandRegister) {
            if (destination_operand.type == OperandRegister) {
                processor_write_reg_2_reg(cpu, reg_dst, reg_src);
            } else if (destination_operand.type == OperandMemoryOffset) {
                u32 offset = 0;
                offset += cpu->registers[destination_offset_reg_1];
                offset += destination_operand.offset.n_regs > 1
                    ? cpu->registers[destination_offset_reg_2]
                    : 0;
                processor_write_reg_2_mem(cpu, offset, reg_src);
            }
        } else if (source_operand.type == OperandMemory) {
            if (destination_operand.type == OperandRegister) {
                processor_write_mem_2_reg(cpu, source_offset, reg_dst);
            }
        } else if (source_operand.type == OperandMemoryOffset) {
            u32 offset = 0;
            offset += cpu->registers[destination_offset_reg_1];
            offset += destination_operand.offset.n_regs > 1
                ? cpu->registers[destination_offset_reg_2]
                : 0;

            processor_write_mem_2_reg(cpu, offset, reg_dst);
        }
    } else if (op_code == OP_MOV_IMM2REG) {
        assert(source_operand.type == OperandImmediate);
        processor_write_imm_2_reg(cpu, reg_dst, source_immediate);
    } else if (op_code == OP_MOV_ACC2MEM) {
        assert(destination_operand.type == OperandMemory);
        assert(source_operand.type == OperandRegister);
        processor_write_reg_2_mem(cpu, destination_offset, reg_src);
    } else if (op_code == OP_MOV_IMM2REGMEM) {
        assert(source_operand.type == OperandImmediate);
        assert(destination_operand.type == OperandRegister
                || destination_operand.type == OperandMemory
                || destination_operand.type == OperandMemoryOffset
                || destination_operand.type == OperandMemoryOffset8
                || destination_operand.type == OperandMemoryOffset16);

        if (destination_operand.type == OperandRegister) {
            processor_write_imm_2_reg(cpu, reg_dst, source_immediate);
        } else if (destination_operand.type == OperandMemory) {
            processor_write_imm_2_mem(cpu, destination_offset, source_immediate);
        } else if (destination_operand.type == OperandMemoryOffset) {
            u32 offset = 0;
            offset += cpu->registers[destination_offset_reg_1];
            offset += destination_operand.offset.n_regs > 1
                ? cpu->registers[destination_offset_reg_2]
                : 0;
            processor_write_imm_2_mem(cpu, offset, source_immediate);
        } else if (destination_operand.type == OperandMemoryOffset8) {
            u32 offset = 0;
            offset += cpu->registers[destination_offset_reg_1];
            offset += destination_operand.offset.n_regs > 1
                ? cpu->registers[destination_offset_reg_2]
                : 0;
            offset += destination_offset & 0xF;
            processor_write_imm_2_mem(cpu, offset, source_immediate);
        } else if (destination_operand.type == OperandMemoryOffset16) {
            u32 offset = 0;
            offset += cpu->registers[destination_offset_reg_1];
            offset += destination_operand.offset.n_regs > 1
                ? cpu->registers[destination_offset_reg_2]
                : 0;
            offset += destination_offset;
            processor_write_imm_2_mem(cpu, offset, source_immediate);
        }
    } else if (op_code == OP_MOV_MEM2ACC) {
        assert(source_operand.type == OperandMemory);
        assert(destination_operand.type == OperandRegister);
        processor_write_mem_2_reg(cpu, source_offset, reg_dst);
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
    const u32 new_ip = decode(&(cpu->decoder_ctx), instruction, cpu->ip, NULL);
    assert(new_ip < __CPU_MEM_SIZE
            && "new IP value must be within buffer bounds");
    instruction->ip = cpu->ip; // Hacky stuff for jumps
    if (new_ip > cpu->program_size) {
        cpu->ip -= 2;
        return 0;
    }
    cpu->ip = new_ip + 2;

    printf("{CPU} advanced %d ip's\n", cpu->ip - instruction->ip);

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
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JL:
        case OP_JNGE:
            assert(operands[0].type == OperandImmediate);
            if ((cpu->flags & FLAG_SIGN ? 1 : 0)
                    ^ (cpu->flags & FLAG_OVERFLOW ? 1 : 0)) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JNL:
        case OP_JGE:
            assert(operands[0].type == OperandImmediate);
            if ((cpu->flags & FLAG_SIGN ? 1 : 0)
                    == (cpu->flags & FLAG_OVERFLOW ? 1 : 0)) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JB:
        case OP_JNAE:
        // case OP_JC:
            assert(operands[0].type == OperandImmediate);
            if (cpu->flags & FLAG_CARRY) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JBE:
        case OP_JNA:
            assert(operands[0].type == OperandImmediate);
            if ((cpu->flags & FLAG_CARRY) || (cpu->flags & FLAG_ZERO)) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JP:
        case OP_JPE:
            assert(operands[0].type == OperandImmediate);
            if (cpu->flags & FLAG_PARITY) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JO:
            assert(operands[0].type == OperandImmediate);
            if (cpu->flags & FLAG_OVERFLOW) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
        case OP_JNO:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_OVERFLOW)) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JS:
            assert(operands[0].type == OperandImmediate);
            if (cpu->flags & FLAG_SIGN) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
        case OP_JNS:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_SIGN)) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JNZ:
        case OP_JNE:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_ZERO)) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
        break;

        case OP_JLE:
        case OP_JNG:
            assert(operands[0].type == OperandImmediate);
            if ((cpu->flags & FLAG_ZERO) ||
                ((cpu->flags & FLAG_SIGN ? 1 : 0)
                ^ (cpu->flags & FLAG_OVERFLOW ? 1 : 0))) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;
        case OP_JG:
        case OP_JNLE:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_ZERO) &&
                (cpu->flags & FLAG_SIGN ? 1 : 0)
                == (cpu->flags & FLAG_OVERFLOW ? 1 : 0)) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JNBE:
        case OP_JA:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_CARRY) && !(cpu->flags & FLAG_ZERO)) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JNP:
        case OP_JPO:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->flags & FLAG_PARITY)) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
            }
            break;

        case OP_JCXZ:
            assert(operands[0].type == OperandImmediate);
            if (!(cpu->registers[REG_CX])) {
                __CPU_JUMP(operands[0].imm.value + (cpu->ip - instruction.ip));
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

void processor_state_dump(processor_t *cpu, FILE *dump_file) {
    if (dump_file == NULL)
        dump_file = stdout;

    fprintf(dump_file, "CPU mem state:\n\tax\tbx\tcx\tdx\tsp\tbp\tsi\tdi\n"
            "\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n\n", 
            cpu->registers[REG_AX],
            cpu->registers[REG_BX],
            cpu->registers[REG_CX],
            cpu->registers[REG_DX],
            cpu->registers[REG_SP],
            cpu->registers[REG_BP],
            cpu->registers[REG_SI],
            cpu->registers[REG_DI]);

    fprintf(dump_file, "CPU flags:\n\tZ\tS\tO\tC\tP\n\t%d\t%d\t%d\t%d\t%d\n",
            (cpu->flags & FLAG_ZERO)     != 0,
            (cpu->flags & FLAG_SIGN)     != 0,
            (cpu->flags & FLAG_OVERFLOW) != 0,
            (cpu->flags & FLAG_CARRY)    != 0,
            (cpu->flags & FLAG_PARITY)   != 0);

    fprintf(dump_file, "\nCPU ip: %d\n", cpu->ip);
}
