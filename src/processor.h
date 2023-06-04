#ifndef PROCESSOR_H
#define PROCESSOR_H

#include "decoder.h"
#include "types.h"
#include "opcode.h"
#include "instruction.h"

#define REG_AX 0
#define REG_BX 3
#define REG_CX 1
#define REG_DX 2
#define REG_SP 4
#define REG_BP 5
#define REG_SI 6
#define REG_DI 7

#define U16_SIGN_BIT 0x8000

typedef enum {
    FLAG_ZERO       = 0x1 << 0,
    FLAG_SIGN       = 0x1 << 1,
    FLAG_PARITY     = 0x1 << 2,
    FLAG_OVERFLOW   = 0x1 << 2,
} flag_t;

typedef struct {
    u16 registers[8];
    u8 flags;
    instruction_t *instructions;
    u32 *ip2instrno;
} processor_t;

/**
* Interpret and execute the given instruction mutating the
* cpu context.
*
*   instruction:    A decoded instruction
*   *cpu:           A pointer to a processor context
*   returns:        Whether or not the execution has failed (bool)
*/
u32 processor_exec(processor_t *cpu, const instruction_t instruction);

/**
* Initializes the processor struct with some initial assumptions,
* such as an ip to instruction number table, useful for interpretation
* of conditional jumps as well as decoding the entire program all at once
* so that there's no need to decode the same instruction twice or more.
*
*   *decoder_ctx:    A pointer to decoder context that's already initialized
*   *cpu:            A pointer to a processor context
*   returns:         The number of instructions decoded
*/
u32 processor_init(processor_t *cpu, decoder_context_t *decoder_ctx);

#endif
