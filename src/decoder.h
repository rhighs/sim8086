#ifndef DECODER_H
#define DECODER_H

#include "types.h"
#include "instruction.h"

#define __D_RM_BX_SI    0x0
#define __D_RM_BX_DI    0x1
#define __D_RM_BP_SI    0x2
#define __D_RM_BP_DI    0x3
#define __D_RM_SI       0x4
#define __D_RM_DI       0x5
#define __D_RM_BP       0x6
#define __D_RM_BX       0x7

#define __D_REG_AL 0x0
#define __D_REG_CL 0x1
#define __D_REG_DL 0x2
#define __D_REG_BL 0x3
#define __D_REG_AH 0x4
#define __D_REG_CH 0x5
#define __D_REG_DH 0x6
#define __D_REG_BH 0x7
#define __D_REG_AX 0x0
#define __D_REG_CX 0x1
#define __D_REG_DX 0x2
#define __D_REG_BX 0x3
#define __D_REG_SP 0x4
#define __D_REG_BP 0x5
#define __D_REG_SI 0x6
#define __D_REG_DI 0x7

#define __D_RM_DIRECT 0x6

#define __D_MOD_RM 0x0
#define __D_MOD_RM_OFF8 0x1
#define __D_MOD_RM_OFF16 0x2
#define __D_MOD_R2R 0x3

#define __D_NO_LABELS 64

#define TEST_OP(OPCODE, AGAINST) ((OPCODE>>(8-opcode_len(AGAINST)))==(AGAINST>>(8-opcode_len(AGAINST))))

/**
 * Defines common parameters placements in opcodes such as mov, sub, add
 * (all of which share the same memory patterns)
 */
typedef enum {
    OPV_JMP,
    OPV_BASE,
    OPV_IMM2REG,
    OPV_MEM2ACC,
    OPV_IMM2ACC,
    OPV_ACC2MEM,
    OPV_IMM2REGMEM,
    OPV_IMM2REGMEM_SOURCEBIT, // Terrible, terrible decision
} op_variants_t;

typedef struct {
    const u8 *buf;
    u32 buflen;

    u32 *cursor2pc;
    u32 pc;
} decoder_context_t;

u32 decoder_init(decoder_context_t *context, const u8 *program, const u32 size);

void decoder_destroy(decoder_context_t *context);

u32 decode(decoder_context_t *context, instruction_t *decoded_construct,
        const u32 cursor, char *out);

#endif
