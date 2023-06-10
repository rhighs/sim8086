#ifndef PROCESSOR_H
#define PROCESSOR_H

#include <stdint.h>
#include <stdio.h>

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

#define __CPU_MEM_SIZE 1024 * 1024

#define __CPU_U8_SIGN_BIT 0x80

#define __CPU_U16_SIGN_BIT 0x8000

#define __CPU_IP2ISNTRNO_NONE UINT32_MAX

#define __CPU_JUMP(__DISP, __INSTR_DISPL)\
    if (__DISP&__CPU_U8_SIGN_BIT) {cpu->ip-=abs((i8)(__DISP)) + __INSTR_DISPL;} \
    else {cpu->ip+=__DISP + __INSTR_DISPL;}

typedef enum {
    FLAG_ZERO       = 0x1 << 0,
    FLAG_SIGN       = 0x1 << 1,
    FLAG_PARITY     = 0x1 << 2,
    FLAG_OVERFLOW   = 0x1 << 3,
    FLAG_CARRY      = 0x1 << 4,
} flag_t;

typedef struct {
    u16 registers[8];
    u8 flags;
    decoder_context_t decoder_ctx;

    u32 program_size;
    u8 *memory;

    // Stuff related to ip state tracking
    u32 ip;
} processor_t;

/*
* Interpret and execute the given instruction mutating the
* cpu context.
*
*   instruction:    A decoded instruction
*   *cpu:           A pointer to a processor context
*   returns:        Whether or not the execution has failed (bool)
*/
u32 processor_exec(processor_t *cpu, const instruction_t instruction);

/*
* Initializes the processor copying program to processor memory
*
*   *cpu:            A pointer to a processor context
*   *program:        Program data array
*   *size:           size of the array
*   returns:         Whether or not the initialization has failed (bool)
*/
u32 processor_init(processor_t *cpu, const u8 *program, const u32 size);

/*
 * Decodes and returns the instruction at the current IP, mutates the ip
 * to the next instruction
 *
 * *cpu:             A pointer to a processor context
 * *instruction      A pointer to where to store the decoded instruction
 * returns           Whether there is more instructions or not
 */
u32 processor_fetch_instruction(processor_t *cpu, instruction_t *instruction);

/*
 * Dumps the processor state into a file
 *
 * *cpu:             A pointer to a processor context
 * *dump_file:       A pointer to a file
 */
void processor_state_dump(processor_t *cpu, FILE *dump_file);

#endif
