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
u8 processor_short_reg_get(processor_t *cpu, u8 reg) {
    switch (reg) {
     case REG_AL: return cpu->registers[REG_AX];
     case REG_BL: return cpu->registers[REG_BX];
     case REG_CL: return cpu->registers[REG_CX];
     case REG_DL: return cpu->registers[REG_DX];
     case REG_AH: return cpu->registers[REG_AX] >> 8;
     case REG_BH: return cpu->registers[REG_BX] >> 8;
     case REG_CH: return cpu->registers[REG_CX] >> 8;
     case REG_DH: return cpu->registers[REG_DX] >> 8;
     default:
     assert(FALSE && "Unreachable condition!");
    }
}

static
void processor_short_reg_set(processor_t *cpu, u8 reg, u8 value) {
    switch (reg) {
     case REG_AH:
        cpu->registers[REG_AX] &= 0x00FF;
        cpu->registers[REG_AX] |= (((u16)value) << 8);
        break;
     case REG_BH:
        cpu->registers[REG_BX] &= 0x00FF;
        cpu->registers[REG_BX] |= (((u16)value) << 8);
        break;
     case REG_CH:
        cpu->registers[REG_CX] &= 0x00FF;
        cpu->registers[REG_CX] |= (((u16)value) << 8);
        break;
     case REG_DH:
        cpu->registers[REG_DX] &= 0x00FF;
        cpu->registers[REG_DX] |= (((u16)value) << 8);
        break;
     case REG_AL:
        cpu->registers[REG_AX] &= 0xFF00;
        cpu->registers[REG_AX] |= value;
     case REG_BL:
        cpu->registers[REG_BX] &= 0xFF00;
        cpu->registers[REG_BX] |= value;
     case REG_CL:
        cpu->registers[REG_CX] &= 0xFF00;
        cpu->registers[REG_CX] |= value;
     case REG_DL:
        cpu->registers[REG_DX] &= 0xFF00;
        cpu->registers[REG_DX] |= value;
     default:
     assert(FALSE && "Unreachable condition!");
    }
}

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
u8 processor_mov_memory(processor_t *cpu,
    const instruction_t instruction) {
    return TRUE;
}

static inline
void processor_write_reg_2_mem(processor_t *cpu,
        const u32 mem_offset, const u16 reg, const u8 is_wide) {
    assert(mem_offset > cpu->program_size && "Can't write program memory");
    if (!is_wide) {
        cpu->memory[mem_offset] = processor_short_reg_get(cpu, reg);
    } else {
        cpu->memory[mem_offset] = cpu->registers[reg];
    }
#ifdef CPU_DEBUG
    printf("[CPU] wrotereg %d to mem location %d\n", reg, mem_offset);
    processor_state_dump(cpu, stdout);
#endif
}

static inline
void processor_write_imm_2_mem(processor_t *cpu,
        const u32 mem_offset, const u16 immediate) {
    assert(mem_offset > cpu->program_size && "Can't write program memory");
    cpu->memory[mem_offset] = immediate;
#ifdef CPU_DEBUG
    printf("[CPU] wrote immediate %d to mem location %d\n",
        immediate, mem_offset);
    processor_state_dump(cpu, stdout);
#endif
}

static inline
void processor_write_mem_2_reg(processor_t *cpu,
        const u32 mem_offset, const u16 reg, const u8 is_wide) {
    if (!is_wide) {
        processor_short_reg_set(cpu, reg, cpu->memory[mem_offset]);
    } else {
        cpu->registers[reg] = cpu->memory[mem_offset];
    }
#ifdef CPU_DEBUG
    printf("[CPU] wrote mem location %d to reg %d\n", mem_offset, reg);
    processor_state_dump(cpu, stdout);
#endif
}

static inline
void processor_write_imm_2_reg(processor_t *cpu,
        const u16 reg, const u16 immediate, const u8 is_wide) {
    cpu->registers[reg] = immediate;
    if (!is_wide) {
        processor_short_reg_set(cpu, reg, immediate);
    } else {
        cpu->registers[reg] = immediate;
    }
#ifdef CPU_DEBUG
    printf("[CPU] wrote immediate %d to reg %d\n", immediate, reg);
    processor_state_dump(cpu, stdout);
#endif
}

static inline
void processor_write_reg_2_reg(processor_t *cpu,
        const u16 reg_dst, const u16 reg_src, const u8 is_wide) {
    cpu->registers[reg_dst] = cpu->registers[reg_src];
    if (!is_wide) {
        processor_short_reg_set(cpu, reg_dst,
            processor_short_reg_get(cpu, reg_src));
    } else {
        cpu->registers[reg_dst] = cpu->registers[reg_src];
    }
#ifdef DEBUG
    printf("[CPU] wrote reg %d to reg %d\n", reg_src, reg_dst);
    processor_state_dump(cpu, stdout);
#endif
}

static
u8 processor_exec_mov(processor_t *cpu, const op_code_t op_code, 
        const operand_t destination_operand,const operand_t source_operand,
        const u8 is_wide) {
    const u8 source_offset_reg_1 = source_operand.offset.regs[0];
    const u8 source_offset_reg_2 = source_operand.offset.regs[1];
    const u8 destination_offset_reg_1 = destination_operand.offset.regs[0];
    const u8 destination_offset_reg_2 = destination_operand.offset.regs[1];
    const u8 reg_dst = destination_operand.reg.index;
    const u8 reg_src = source_operand.reg.index;
    const u16 source_offset = source_operand.offset.offset;
    const u16 destination_offset = destination_operand.offset.offset;
    const u16 source_immediate = source_operand.imm.value;

#define MEM_REGS_OFFSET \
    (cpu->registers[destination_offset_reg_1] \
     + (destination_operand.offset.n_regs > 1 \
        ? cpu->registers[destination_offset_reg_2] \
        : 0))
#define MEM_REGS_OFFSET8 \
     (cpu->registers[destination_offset_reg_1] \
     + (destination_operand.offset.n_regs > 1 \
         ? cpu->registers[destination_offset_reg_2] \
         : 0) + (destination_offset & 0xFF))
#define MEM_REGS_OFFSET16 \
     (cpu->registers[destination_offset_reg_1] \
     + (destination_operand.offset.n_regs > 1 \
         ? cpu->registers[destination_offset_reg_2] \
         : 0) + destination_offset)

    if (op_code == OP_MOV) {
        assert(source_operand.type == OperandRegister
                || source_operand.type == OperandMemory
                || source_operand.type == OperandMemoryOffset
                || source_operand.type == OperandMemoryOffset8
                || source_operand.type == OperandMemoryOffset16);

        if (source_operand.type == OperandRegister) {
            if (destination_operand.type == OperandRegister) {
                processor_write_reg_2_reg(cpu, reg_dst, reg_src, is_wide);
            } else if (destination_operand.type == OperandMemoryOffset) {
                u32 offset = MEM_REGS_OFFSET;
                processor_write_reg_2_mem(cpu, offset, reg_src, is_wide);
            } else if (destination_operand.type == OperandMemoryOffset8) {
                u32 offset = MEM_REGS_OFFSET8;
                processor_write_reg_2_mem(cpu, offset, reg_src, is_wide);
            } else if (destination_operand.type == OperandMemoryOffset16) {
                u32 offset = MEM_REGS_OFFSET16;
                processor_write_reg_2_mem(cpu, offset, reg_src, is_wide);
            }
        } else if (source_operand.type == OperandMemory) {
            if (destination_operand.type == OperandRegister) {
                processor_write_mem_2_reg(cpu, source_offset, reg_dst, is_wide);
            }
        } else if (source_operand.type == OperandMemoryOffset) {
            assert(destination_operand.type == OperandRegister);
            u32 offset = MEM_REGS_OFFSET;
            processor_write_mem_2_reg(cpu, offset, reg_dst, is_wide);
        } else if (source_operand.type == OperandMemoryOffset8) {
            assert(destination_operand.type == OperandRegister);
            u32 offset = MEM_REGS_OFFSET8;
            processor_write_mem_2_reg(cpu, offset, reg_dst, is_wide);
        } else if (source_operand.type == OperandMemoryOffset16) {
            assert(destination_operand.type == OperandRegister);
            u32 offset = MEM_REGS_OFFSET16;
            processor_write_mem_2_reg(cpu, offset, reg_dst, is_wide);
        }
    } else if (op_code == OP_MOV_IMM2REG) {
        assert(source_operand.type == OperandImmediate);
        processor_write_imm_2_reg(cpu, reg_dst, source_immediate, is_wide);
    } else if (op_code == OP_MOV_ACC2MEM) {
        assert(destination_operand.type == OperandMemory);
        assert(source_operand.type == OperandRegister);
        processor_write_reg_2_mem(cpu, destination_offset, reg_src, is_wide);
    } else if (op_code == OP_MOV_IMM2REGMEM) {
        assert(source_operand.type == OperandImmediate);
        assert(destination_operand.type == OperandRegister
                || destination_operand.type == OperandMemory
                || destination_operand.type == OperandMemoryOffset
                || destination_operand.type == OperandMemoryOffset8
                || destination_operand.type == OperandMemoryOffset16);

        if (destination_operand.type == OperandRegister) {
            processor_write_imm_2_reg(cpu, reg_dst, source_immediate, is_wide);
        } else if (destination_operand.type == OperandMemory) {
            processor_write_imm_2_mem(cpu,
                destination_offset, source_immediate);
        } else if (destination_operand.type == OperandMemoryOffset) {
            u32 offset = MEM_REGS_OFFSET;
            processor_write_imm_2_mem(cpu, offset, source_immediate);
        } else if (destination_operand.type == OperandMemoryOffset8) {
            u32 offset = MEM_REGS_OFFSET8;
            processor_write_imm_2_mem(cpu, offset, source_immediate);
        } else if (destination_operand.type == OperandMemoryOffset16) {
            u32 offset = MEM_REGS_OFFSET16;
            processor_write_imm_2_mem(cpu, offset, source_immediate);
        }
    } else if (op_code == OP_MOV_MEM2ACC) {
        assert(source_operand.type == OperandMemory);
        assert(destination_operand.type == OperandRegister);
        processor_write_mem_2_reg(cpu, source_offset, reg_dst, is_wide);
    }

#undef MEM_REGS_OFFSET
#undef MEM_REGS_OFFSET8
#undef MEM_REGS_OFFSET16

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

static
void __print_bits(const u32 n) {
    u8 len = sizeof(n) * 8;
    while (len--) {
        if ((len+1) % 8 == 0 && (len+1) < sizeof(n) * 8) {
            printf(" ");
        }
        printf("%c", ((n >> len) & 0x1) ? '1' : '0');
    }
    printf("\n");
}

u32 processor_fetch_instruction(processor_t *cpu,
    instruction_t *instruction, char *out) {
#ifdef DEBUG
    printf("[INSTR_HI] Next instruction: ");
    __print_bits(cpu->memory[cpu->ip]);
#endif
    const u32 new_ip = decode(&(cpu->decoder_ctx), instruction, cpu->ip, out);
    assert(new_ip < __CPU_MEM_SIZE
            && "new IP value must be within buffer bounds");
    instruction->ip = cpu->ip; // Hacky stuff for jumps
    if (new_ip >= cpu->program_size) {
        cpu->ip -= 2;
        return 0;
    }
    cpu->ip = new_ip + 2;

    return 1;
}

u32 processor_exec(processor_t *cpu, const instruction_t instruction) {
    const operand_t destination_operand = instruction.operands[0];
    const operand_t source_operand = instruction.operands[1];

    const u8 source_offset_reg_1 = source_operand.offset.regs[0];
    const u8 source_offset_reg_2 = source_operand.offset.regs[1];
    const u8 destination_offset_reg_1 = destination_operand.offset.regs[0];
    const u8 destination_offset_reg_2 = destination_operand.offset.regs[1];
    const u8 reg_dst = destination_operand.reg.index;
    const u8 reg_src = source_operand.reg.index;
    const u16 source_offset = source_operand.offset.offset;
    const u16 destination_offset = destination_operand.offset.offset;
    const u16 source_immediate = source_operand.imm.value;
    const u8 instr_width = cpu->ip - instruction.ip;

#define MEM_REGS_OFFSET \
    (cpu->registers[destination_offset_reg_1] \
     + destination_operand.offset.n_regs > 1 \
        ? cpu->registers[destination_offset_reg_2] \
        : 0)
#define MEM_REGS_OFFSET8 \
     (cpu->registers[destination_offset_reg_1] \
     + (destination_operand.offset.n_regs > 1 \
         ? cpu->registers[destination_offset_reg_2] \
         : 0) + destination_offset & 0xFF)
#define MEM_REGS_OFFSET16 \
     (cpu->registers[destination_offset_reg_1] \
     + (destination_operand.offset.n_regs > 1 \
         ? cpu->registers[destination_offset_reg_2] \
         : 0) + destination_offset)

    switch (instruction.op_code) {
        case OP_MOV:
        case OP_MOV_IMM2REG:
        case OP_MOV_ACC2MEM:
        case OP_MOV_IMM2REGMEM:
        case OP_MOV_MEM2ACC:
            if (!processor_exec_mov(cpu, instruction.op_code,
                        destination_operand, source_operand,
                        instruction.is_wide)) {
                goto unimplemented;
            }
            break;

        case OP_ADD:
            if (source_operand.type == OperandRegister) {
                assert(destination_operand.type == OperandRegister
                    || destination_operand.type == OperandMemoryOffset
                    || destination_operand.type == OperandMemoryOffset8
                    || destination_operand.type == OperandMemoryOffset16);

                if (destination_operand.type == OperandRegister) {
                    u8 reg_dst = destination_operand.reg.index;
                    u8 reg_src = source_operand.reg.index;

                    u32 sum = 0;
                    if (instruction.is_wide) {
                        const u16 value = cpu->registers[reg_src];
                        const i16 value_sgn = source_operand.imm.value;
                        sum = value_sgn < 0
                            ? (u32)(cpu->registers[reg_dst])
                                    - (u32)(abs(value_sgn))
                            : (u32)(cpu->registers[reg_dst])
                                    + (u32)(value);
                    } else {
                        const u8 value = source_operand.imm.value;
                        const i8 value_sgn = source_operand.imm.value;
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
                } else if (destination_operand.type == OperandMemoryOffset) {
                    u32 offset = MEM_REGS_OFFSET;

                    u32 sum = 0;
                    if (instruction.is_wide) {
                        const u16 value = cpu->registers[reg_src];
                        const i16 value_sgn = source_operand.imm.value;
                        sum = value_sgn < 0
                            ? (u32)(cpu->memory[offset])
                                    - (u32)(abs(value_sgn))
                            : (u32)(cpu->memory[offset])
                                    + (u32)(value);
                    } else {
                        const u8 value = source_operand.imm.value;
                        const i8 value_sgn = source_operand.imm.value;
                        sum = value_sgn < 0
                            ? (u32)(cpu->memory[offset])
                                    - (u32)(abs((i8)(value_sgn)))
                            : (u32)(cpu->memory[offset])
                                    + (u32)(value);
                    }

                    cpu->registers[reg_dst] = (u16)sum;
                    processor_set_flags(cpu, (u16)sum);
                    if (sum & 0xFF00) { 
                        cpu->flags |= FLAG_CARRY;
                        cpu->flags |= FLAG_OVERFLOW;
                    }
                } else if (destination_operand.type == OperandMemoryOffset8) {
                    u32 offset = MEM_REGS_OFFSET8;

                    u32 sum = 0;
                    if (instruction.is_wide) {
                        const u16 value = cpu->registers[reg_src];
                        const i16 value_sgn = source_operand.imm.value;
                        sum = value_sgn < 0
                            ? (u32)(cpu->memory[offset])
                                    - (u32)(abs(value_sgn))
                            : (u32)(cpu->memory[offset])
                                    + (u32)(value);
                    } else {
                        const u8 value = source_operand.imm.value;
                        const i8 value_sgn = source_operand.imm.value;
                        sum = value_sgn < 0
                            ? (u32)(cpu->memory[offset])
                                    - (u32)(abs((i8)(value_sgn)))
                            : (u32)(cpu->memory[offset])
                                    + (u32)(value);
                    }

                    cpu->registers[reg_dst] = (u16)sum;
                    processor_set_flags(cpu, (u16)sum);
                    if (sum & 0xFF00) { 
                        cpu->flags |= FLAG_CARRY;
                        cpu->flags |= FLAG_OVERFLOW;
                    }
                } else if (destination_operand.type == OperandMemoryOffset16) {
                    u32 offset = MEM_REGS_OFFSET16;

                    u32 sum = 0;
                    if (instruction.is_wide) {
                        const u16 value = cpu->registers[reg_src];
                        const i16 value_sgn = source_operand.imm.value;
                        sum = value_sgn < 0
                            ? (u32)(cpu->memory[offset])
                                    - (u32)(abs(value_sgn))
                            : (u32)(cpu->memory[offset])
                                    + (u32)(value);
                    } else {
                        const u8 value = source_operand.imm.value;
                        const i8 value_sgn = source_operand.imm.value;
                        sum = value_sgn < 0
                            ? (u32)(cpu->memory[offset])
                                    - (u32)(abs((i8)(value_sgn)))
                            : (u32)(cpu->memory[offset])
                                    + (u32)(value);
                    }

                    cpu->registers[reg_dst] = (u16)sum;
                    processor_set_flags(cpu, (u16)sum);
                    if (sum & 0xFF00) { 
                        cpu->flags |= FLAG_CARRY;
                        cpu->flags |= FLAG_OVERFLOW;
                    }
                }
            }
            break;

        case OP_ADD_IMM2ACC:
        case OP_ADD_IMM2REGMEM:
            if (source_operand.type == OperandImmediate) {
                u8 reg = destination_operand.reg.index;

                u32 sum = 0;
                if (instruction.is_wide) {
                    const u16 value = source_operand.imm.value;
                    const i16 value_sgn = source_operand.imm.value;
                    sum = value_sgn < 0
                        ? (u32)(cpu->registers[reg])
                                - (u32)(abs(value_sgn))
                        : (u32)(cpu->registers[reg])
                                + (u32)(value);
                } else {
                    const u8 value = source_operand.imm.value;
                    const i8 value_sgn = source_operand.imm.value;
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
            if (source_operand.type == OperandRegister) {
                assert(destination_operand.type == OperandRegister);
                u8 reg_dst = destination_operand.reg.index;
                u8 reg_src = source_operand.reg.index;
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
            if (source_operand.type == OperandImmediate) {
                assert(destination_operand.type == OperandRegister);
                u8 reg = destination_operand.reg.index;
                u16 a = cpu->registers[reg];
                u16 b = source_operand.imm.value;
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
            if (source_operand.type == OperandImmediate) {
                assert(destination_operand.type == OperandRegister);
                u8 reg = destination_operand.reg.index;
                u16 sum = cpu->registers[reg] - source_operand.imm.value;
                processor_set_flags(cpu, sum);
            }
            break;

        case OP_CMP_REGMEM_REG:
            if (destination_operand.type == OperandRegister) {
                assert(source_operand.type == OperandRegister);
                u8 reg_dst = destination_operand.reg.index;
                u8 reg_src = source_operand.reg.index;
                u16 sum = cpu->registers[reg_dst] - cpu->registers[reg_src];
                processor_set_flags(cpu, sum);
            }
            break;

        case OP_NOT:
            assert(destination_operand.type == OperandRegister
                    || destination_operand.type == OperandMemory
                    || destination_operand.type == OperandMemoryOffset
                    || destination_operand.type == OperandMemoryOffset8
                    || destination_operand.type == OperandMemoryOffset16);
            if (destination_operand.type == OperandRegister) {
                u16 value = !cpu->registers[reg_dst];
                processor_write_imm_2_reg(cpu, reg_dst,
                    !source_immediate, instruction.is_wide);
            } else if (destination_operand.type == OperandMemory) {
                u16 offset = destination_offset;
                u16 value = !cpu->memory[offset];
                processor_write_imm_2_mem(cpu, offset, value);
            } else if (destination_operand.type == OperandMemoryOffset) {
                u32 offset = MEM_REGS_OFFSET;
                u16 value = !cpu->memory[offset];
                processor_write_imm_2_mem(cpu, offset, value);
            } else if (destination_operand.type == OperandMemoryOffset8) {
                u32 offset = MEM_REGS_OFFSET8;
                u16 value = !cpu->memory[offset];
                processor_write_imm_2_mem(cpu, offset, value);
            } else if (destination_operand.type == OperandMemoryOffset16) {
                u32 offset = MEM_REGS_OFFSET16;
                u16 value = !cpu->memory[offset];
                processor_write_imm_2_mem(cpu, offset, value);
            }
            break;

        case OP_SHL:
        case OP_SAL: {
            assert(destination_operand.type == OperandRegister
                    || destination_operand.type == OperandMemory
                    || destination_operand.type == OperandMemoryOffset
                    || destination_operand.type == OperandMemoryOffset8
                    || destination_operand.type == OperandMemoryOffset16);
            u32 shift_amount = source_operand.type == OperandRegister
                ? processor_short_reg_get(cpu, REG_CL)
                : source_operand.imm.value;
            if (destination_operand.type == OperandRegister) {
                u16 value = cpu->registers[reg_dst] << shift_amount;
                processor_write_imm_2_reg(cpu, reg_dst, value,
                    instruction.is_wide);
            } else if (destination_operand.type == OperandMemory) {
                u32 offset = destination_offset;
                u16 value = cpu->memory[offset] << shift_amount;
                processor_write_imm_2_mem(cpu, offset, value);
            } else if (destination_operand.type == OperandMemoryOffset) {
                u32 offset = MEM_REGS_OFFSET;
                u16 value = cpu->memory[offset] << shift_amount;
                processor_write_imm_2_mem(cpu, offset, value);
            } else if (destination_operand.type == OperandMemoryOffset8) {
                u32 offset = MEM_REGS_OFFSET8;
                u16 value = cpu->memory[offset] << shift_amount;
                processor_write_imm_2_mem(cpu, offset, value);
            } else if (destination_operand.type == OperandMemoryOffset16) {
                u32 offset = MEM_REGS_OFFSET16;
                u16 value = cpu->memory[offset] << shift_amount;
                processor_write_imm_2_mem(cpu, offset, value);
            }
            break;
        }

        case OP_SHR:
        case OP_SAR: {
            assert(destination_operand.type == OperandRegister
                    || destination_operand.type == OperandMemory
                    || destination_operand.type == OperandMemoryOffset
                    || destination_operand.type == OperandMemoryOffset8
                    || destination_operand.type == OperandMemoryOffset16);
            u32 shift_amount = source_operand.type == OperandRegister
                ? processor_short_reg_get(cpu, REG_CL)
                : source_operand.imm.value;
            if (destination_operand.type == OperandRegister) {
                u16 value = __CPU_RIGHT_SHIFT_16(cpu->registers[reg_dst],
                    shift_amount);
                processor_write_imm_2_reg(cpu, reg_dst, value,
                    instruction.is_wide);
            } else if (destination_operand.type == OperandMemory) {
                u32 offset = destination_offset;
                u16 value = __CPU_RIGHT_SHIFT_16(cpu->memory[offset],
                    shift_amount);
                processor_write_imm_2_mem(cpu, offset, value);
            } else if (destination_operand.type == OperandMemoryOffset) {
                u32 offset = MEM_REGS_OFFSET;
                u16 value = __CPU_RIGHT_SHIFT_16(cpu->memory[offset],
                    shift_amount);
                processor_write_imm_2_mem(cpu, offset, value);
            } else if (destination_operand.type == OperandMemoryOffset8) {
                u32 offset = MEM_REGS_OFFSET8;
                u16 value = __CPU_RIGHT_SHIFT_16(cpu->memory[offset],
                    shift_amount);
                processor_write_imm_2_mem(cpu, offset, value);
            } else if (destination_operand.type == OperandMemoryOffset16) {
                u32 offset = MEM_REGS_OFFSET16;
                u16 value = __CPU_RIGHT_SHIFT_16(cpu->memory[offset],
                    shift_amount);
                processor_write_imm_2_mem(cpu, offset, value);
            }
            break;
        }

        case OP_JE:
        case OP_JZ:
            assert(destination_operand.type == OperandImmediate);
            if (cpu->flags & FLAG_ZERO)
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JL:
        case OP_JNGE:
            assert(destination_operand.type == OperandImmediate);
            if ((cpu->flags & FLAG_SIGN ? 1 : 0) ^ (cpu->flags & FLAG_OVERFLOW ? 1 : 0))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JNL:
        case OP_JGE:
            assert(destination_operand.type == OperandImmediate);
            if ((cpu->flags & FLAG_SIGN ? 1 : 0) == (cpu->flags & FLAG_OVERFLOW ? 1 : 0))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JB:
        case OP_JNAE:
            // case OP_JC:
            assert(destination_operand.type == OperandImmediate);
            if (cpu->flags & FLAG_CARRY)
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JBE:
        case OP_JNA:
            assert(destination_operand.type == OperandImmediate);
            if ((cpu->flags & FLAG_CARRY) || (cpu->flags & FLAG_ZERO))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JP:
        case OP_JPE:
            assert(destination_operand.type == OperandImmediate);
            if (cpu->flags & FLAG_PARITY)
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JO:
            assert(destination_operand.type == OperandImmediate);
            if (cpu->flags & FLAG_OVERFLOW)
                __CPU_JUMP(destination_operand.imm.value, instr_width);
        case OP_JNO:
            assert(destination_operand.type == OperandImmediate);
            if (!(cpu->flags & FLAG_OVERFLOW))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JS:
            assert(destination_operand.type == OperandImmediate);
            if (cpu->flags & FLAG_SIGN)
                __CPU_JUMP(destination_operand.imm.value, instr_width);
        case OP_JNS:
            assert(destination_operand.type == OperandImmediate);
            if (!(cpu->flags & FLAG_SIGN))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JNZ:
        case OP_JNE:
            assert(destination_operand.type == OperandImmediate);
            if (!(cpu->flags & FLAG_ZERO))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JLE:
        case OP_JNG:
            assert(destination_operand.type == OperandImmediate);
            if ((cpu->flags & FLAG_ZERO) ||
                ((cpu->flags & FLAG_SIGN ? 1 : 0) ^ (cpu->flags & FLAG_OVERFLOW ? 1 : 0)))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;
        case OP_JG:
        case OP_JNLE:
            assert(destination_operand.type == OperandImmediate);
            if (!(cpu->flags & FLAG_ZERO) &&
                (cpu->flags & FLAG_SIGN ? 1 : 0) == (cpu->flags & FLAG_OVERFLOW ? 1 : 0))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JNBE:
        case OP_JA:
            assert(destination_operand.type == OperandImmediate);
            if (!(cpu->flags & FLAG_CARRY) && !(cpu->flags & FLAG_ZERO))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JNP:
        case OP_JPO:
            assert(destination_operand.type == OperandImmediate);
            if (!(cpu->flags & FLAG_PARITY))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_JCXZ:
            assert(destination_operand.type == OperandImmediate);
            if (!(cpu->registers[REG_CX]))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_LOOP:
            assert(destination_operand.type == OperandImmediate);
            if (cpu->registers[REG_CX] - 1> 0) {
                cpu->registers[REG_CX]--;
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            }
            break;

        case OP_LOOPZ:
            assert(destination_operand.type == OperandImmediate);
            if (cpu->flags & FLAG_ZERO)
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_LOOPNZ:
            assert(destination_operand.type == OperandImmediate);
            if (!(cpu->flags & FLAG_ZERO))
                __CPU_JUMP(destination_operand.imm.value, instr_width);
            break;

        case OP_MUL:
            assert(destination_operand.type == OperandRegister);
            if (source_operand.type == OperandImmediate) {
                u16 value = cpu->registers[reg_dst]
                    * source_immediate;
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandRegister) {
                u16 value = cpu->registers[reg_dst]
                    * cpu->registers[reg_src];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemory) {
                u32 offset = source_offset;
                u16 value = cpu->registers[reg_dst]
                    * cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset) {
                u32 offset = MEM_REGS_OFFSET;
                u16 value = cpu->registers[reg_dst]
                    * cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset8) {
                u32 offset = MEM_REGS_OFFSET8;
                u16 value = cpu->registers[reg_dst]
                    * cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset16) {
                u32 offset = MEM_REGS_OFFSET16;
                u16 value = cpu->registers[reg_dst]
                    * cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            }
            break;

        case OP_IMUL:
            assert(destination_operand.type == OperandRegister);
            if (source_operand.type == OperandImmediate) {
                i16 value = (i16)cpu->registers[reg_dst]
                    * (i16)source_immediate;
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandRegister) {
                i16 value = (i16)cpu->registers[reg_dst]
                    * (i16)cpu->registers[reg_src];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemory) {
                u32 offset = source_offset;
                i16 value = (i16)cpu->registers[reg_dst]
                    * (i8)cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset) {
                u32 offset = MEM_REGS_OFFSET;
                i16 value = (i16)cpu->registers[reg_dst]
                    * (i8)cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset8) {
                u32 offset = MEM_REGS_OFFSET8;
                i16 value = (i16)cpu->registers[reg_dst]
                    * (i8)cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset16) {
                u32 offset = MEM_REGS_OFFSET16;
                i16 value = (i16)cpu->registers[reg_dst]
                    * (i8)cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            }
            break;

        case OP_DIV:
            assert(destination_operand.type == OperandRegister);
            if (source_operand.type == OperandImmediate) {
                u16 value = cpu->registers[reg_dst]
                    / source_immediate;
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandRegister) {
                u16 value = cpu->registers[reg_dst]
                    / cpu->registers[reg_src];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemory) {
                u32 offset = source_offset;
                u16 value = cpu->registers[reg_dst]
                    / cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset) {
                u32 offset = MEM_REGS_OFFSET;
                u16 value = cpu->registers[reg_dst] 
                    / cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset8) {
                u32 offset = MEM_REGS_OFFSET8;
                u16 value = cpu->registers[reg_dst]
                    / cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset16) {
                u32 offset = MEM_REGS_OFFSET16;
                u16 value = cpu->registers[reg_dst]
                    / cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            }
            break;

        case OP_IDIV:
            assert(destination_operand.type == OperandRegister);
            if (source_operand.type == OperandImmediate) {
                i16 value = (i16)cpu->registers[reg_dst]
                    / (i16)source_immediate;
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandRegister) {
                i16 value = (i16)cpu->registers[reg_dst]
                    / (i16)cpu->registers[reg_src];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemory) {
                u32 offset = source_offset;
                i16 value = (i16)cpu->registers[reg_dst]
                    / (i8)cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset) {
                u32 offset = MEM_REGS_OFFSET;
                i16 value = (i16)cpu->registers[reg_dst]
                    / (i8)cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset8) {
                u32 offset = MEM_REGS_OFFSET8;
                i16 value = (i16)cpu->registers[reg_dst]
                    / (i8)cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            } else if (source_operand.type == OperandMemoryOffset16) {
                u32 offset = MEM_REGS_OFFSET16;
                i16 value = (i16)cpu->registers[reg_dst]
                    / (i8)cpu->memory[offset];
                processor_set_flags(cpu, value);
                processor_write_imm_2_reg(cpu, reg_dst,
                    value, instruction.is_wide);
            }
            break;

        case OP_POP:
        case OP_POP_REGMEM:
        case OP_PUSH:
        case OP_PUSH_REGMEM:
        case OP_ROR:
        case OP_ROL:
        default:
            goto unimplemented;
    }

#undef MEM_REGS_OFFSET
#undef MEM_REGS_OFFSET8
#undef MEM_REGS_OFFSET16

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

void processor_mem_dump(processor_t *cpu, FILE *dump_file) {
    if (dump_file == NULL) 
        dump_file = stdout;
    u32 written = fwrite(cpu->memory, sizeof(u8), __CPU_MEM_SIZE, dump_file);

    if (written != __CPU_MEM_SIZE) {
        fprintf(stderr,
                "processor_mem_dump wrote less than expected, ignoring...\n");
    }
}

static
u32 ea_clocks(const operand_t operand) {
    operand_register_type_t op_type = operand.type;
    u8 reg_1 = operand.offset.regs[0];
    u8 reg_2 = operand.offset.regs[0];

    assert(op_type == OperandMemory
            || op_type == OperandMemoryOffset
            || op_type == OperandMemoryOffset8
            || op_type == OperandMemoryOffset16);

    switch (op_type) {
    case OperandMemory:
        return 6;
    case OperandMemoryOffset:
    case OperandMemoryOffset8:
    case OperandMemoryOffset16:
        if (operand.offset.n_regs == 1) {
            return operand.offset.offset == 0 ? 5 : 9;
        } else if (operand.offset.offset == 0) {
            if (
               (reg_1 == REG_BP && reg_2 == REG_DI)
               || (reg_1 == REG_BX && reg_2 == REG_SI)
               )
                return 7;
            else
                return 9;
        } else {
            if (
               (reg_1 == REG_BP && reg_2 == REG_DI)
               || (reg_1 == REG_BX && reg_2 == REG_SI)
               )
                return 11;
            else
                return 12;
        }
    default: 
        assert(FALSE && "unreachable");
    }

    return NONE;
}

u32 processor_clocks_for(const instruction_t instruction) {
    operand_register_type_t dst_type = instruction.operands[0].type;
    operand_register_type_t src_type = instruction.operands[1].type;

    u8 dst_is_mem = dst_type == OperandMemory
                          || dst_type == OperandMemoryOffset
                          || dst_type == OperandMemoryOffset8
                          || dst_type == OperandMemoryOffset16;
    u8 src_is_mem = src_type == OperandMemory
                          || src_type == OperandMemoryOffset
                          || src_type == OperandMemoryOffset8
                          || src_type == OperandMemoryOffset16;
    u8 dst_is_reg = dst_type == OperandRegister;
    u8 src_is_reg = src_type == OperandRegister;
    u8 src_is_imm = src_type == OperandImmediate;
    u8 src_imm = instruction.operands[1].imm.value;

    u32 clocks = 0;

    switch (instruction.op_code) {
    case OP_MOV:
        if (dst_is_mem) {
            clocks += 8;
        } else if (src_is_mem) {
            clocks += 9;
        } else if (src_is_reg && dst_is_reg) {
            clocks += 2;
        }
        break;
    case OP_MOV_IMM2REG: clocks += 4; break;
    case OP_MOV_IMM2REGMEM: if (dst_is_mem) {
                                clocks += 10;
                            } else {
                                clocks += 4;
                            }
                            break;
    case OP_MOV_MEM2ACC: clocks += 10; break;
    case OP_MOV_ACC2MEM: clocks += 10; break;

    case OP_CMP_REGMEM_REG: 
        if (dst_is_mem) {
            clocks += 9;
        } else if (src_is_mem) {
            clocks += 9;
        } else if (src_is_reg && dst_is_reg) {
            clocks += 3;
        }
        break;
    case OP_CMP_IMM_WITH_ACC:
        clocks += 4; break;
    case OP_CMP_IMM_WITH_REGMEM:
        if (dst_is_mem) {
            clocks += 10;
        } else {
            clocks += 4;
        }
        break;

    case OP_SUB: 
    case OP_ADD: 
    case OP_AND_REGMEM2REG:
    case OP_XOR_REGMEM2REG:
    case OP_OR_REGMEM2REG:
        if (dst_is_mem) {
            clocks += 16;
        } else if (src_is_mem) {
            clocks += 9;
        } else if (src_is_reg && dst_is_reg) {
            clocks += 3;
        }
        break;
    case OP_SUB_IMM_FROM_REGMEM:
    case OP_ADD_IMM2REGMEM:
    case OP_AND_IMM2REGMEM:
    case OP_XOR_IMM2REGMEM:
    case OP_OR_IMM2REGMEM:
        if (dst_is_mem) {
            clocks += 17;
        } else {
            clocks += 4;
        }
        break;
    case OP_SUB_IMM_FROM_ACC:
    case OP_XOR_IMM2ACC:
    case OP_OR_IMM2ACC:
    case OP_AND_IMM2ACC:
    case OP_ADD_IMM2ACC:
    case OP_TEST_IMM2ACC:
        clocks += 4;
        break;

    case OP_TEST_REGMEM2REG:
        if (src_is_mem) {
            clocks += 9;
        } else if (src_is_reg && dst_is_reg) {
            clocks += 3;
        }
        break;
    case OP_TEST_IMM2REGMEM:
        if (dst_is_mem) {
            clocks += 11;
        } else {
            clocks += 5;
        }
        break;

    case OP_MUL:
        if (src_is_mem && instruction.is_wide) {
            clocks += 130;
        } else if (src_is_mem) {
            clocks += 80;
        } else if (src_is_reg && instruction.is_wide) {
            clocks += 120;
        } else if (src_is_reg) {
            clocks += 74;
        }
        break;
    case OP_IMUL:
        if (src_is_mem && instruction.is_wide) {
            clocks += 145;
        } else if (src_is_mem) {
            clocks += 98;
        } else if (src_is_reg && instruction.is_wide) {
            clocks += 135;
        } else if (src_is_reg) {
            clocks += 89;
        }
        break;

    case OP_DIV:
        if (src_is_mem && instruction.is_wide) {
            clocks += 159;
        } else if (src_is_mem) {
            clocks += 91;
        } else if (src_is_reg && instruction.is_wide) {
            clocks += 153;
        } else if (src_is_reg) {
            clocks += 85;
        }
        break;
    case OP_IDIV:
        if (src_is_mem && instruction.is_wide) {
            clocks += 180;
        } else if (src_is_mem) {
            clocks += 112;
        } else if (src_is_reg && instruction.is_wide) {
            clocks += 172;
        } else if (src_is_reg) {
            clocks += 107;
        }
        break;

    case OP_POP:
        clocks += 11;
        break;
    case OP_POP_REGMEM:
        if (dst_is_mem) {
            clocks += 17;
        } else {
            clocks += 8;
        }
        break;

    case OP_PUSH:
        clocks += 11;
        break;
    case OP_PUSH_REGMEM:
        if (dst_is_mem) {
            clocks += 16;
        } else {
            clocks += 11;
        }
        break;

    case OP_NOT:
        if (dst_is_mem) {
            clocks += 16;
        } else {
            clocks += 3;
        }
        break;

    case OP_ROL:
    case OP_ROR:
    case OP_SHR:
    case OP_SAR:
    case OP_SHL:
    case OP_SAL:
        if (dst_is_mem && src_is_imm && src_imm == 1) {
            clocks += 15;
        } else if (dst_is_reg && src_is_imm && src_imm == 1) {
            clocks += 2;
        } else if (dst_is_mem) {
            clocks += 24;
        } else if (dst_is_reg) {
            clocks += 12;
        }
        break;

    case OP_JMP_DIRECT_SEG:
    case OP_JMP_DIRECT_SEG_SHORT:
    case OP_JMP_INDIRECT_SEG:
    case OP_JMP_DIRECT_INTER_SEG:
    case OP_JMP_INDIRECT_INTER_SEG:
    case OP_JE:
    case OP_JZ:
    case OP_JL:
    case OP_JNGE:
    case OP_JLE:
    case OP_JNG:
    case OP_JB:
    case OP_JNAE:
    case OP_JBE:
    case OP_JNA:
    case OP_JP:
    case OP_JPE:
    case OP_JO:
    case OP_JS:
    case OP_JNE:
    case OP_JNZ:
    case OP_JNL:
    case OP_JGE:
    case OP_JNLE:
    case OP_JG:
    case OP_JNB:
    case OP_JAE:
    case OP_JNBE:
    case OP_JA:
    case OP_JNP:
    case OP_JPO:
    case OP_JNO:
    case OP_JNS:
    case OP_JCXZ:
        clocks += 4; // TODO: +16 in some case
        break;
    case OP_LOOP:
        clocks += 5; // TODO: +17 in some case
        break;
    case OP_LOOPE:
    case OP_LOOPZ:
        clocks += 6; // TODO: +18 in some case
        break;
    case OP_LOOPNE:
    case OP_LOOPNZ:
        clocks += 5; // TODO: +19 in some case
        break;
    default:
        break;
    }

    if (dst_is_mem) {
        clocks += ea_clocks(instruction.operands[0]);
    } else if (src_is_mem) {
        clocks += ea_clocks(instruction.operands[1]);
    }

    return clocks;
}
