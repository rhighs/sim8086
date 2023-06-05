#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include "opcode.h"
#include "types.h"

typedef enum {
    OperandRegister,
    OperandImmediate,
    OperandMemory, 
    OperandMemoryOffset,
    OperandMemoryOffset8,
    OperandMemoryOffset16,
} operand_register_type_t;

typedef struct {
    operand_register_type_t type;
    union {
        struct { u16 value; } imm;
        struct { u8 index; } reg;
        struct {
            u8 n_regs;
            u16 offset;
            u8 regs[2];
        } offset;
    };
} operand_t;

typedef struct {
    operand_t operands[2];
    u8 is_wide;
    op_code_t op_code;
} instruction_t;

#endif
