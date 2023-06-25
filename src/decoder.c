#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "types.h"
#include "opcode.h"
#include "decoder.h"
#include "instruction.h"

static
u8 opcode_len(u8 opcode) {
    u8 len = 8;

    switch (opcode) {

    case IMOV_IMM2REG:      len=4; break;

    case SAME_OPCODE_OPS:   
    case IMOV:              
    case IADD:              
    case IADD_IMM2ACC:      
    case ISUB:              
    case ICMP_REGMEM_REG:   len=6; break;

    case ICMP_IMM_WITH_ACC:
    case IMOV_IMM2REGMEM:
    case IMOV_MEM2ACC:
    case IMOV_ACC2MEM:
    case ISUB_IMM_FROM_ACC: len=7; break;

    case IJMP_DIRECT_SEG:
    case IJMP_DIRECT_SEG_SHORT:
    case IJMP_INDIRECT_SEG:
    case IJMP_DIRECT_INTER_SEG: 
    case IJE:
    case IJL:
    case IJLE:
    case IJB:
    case IJNA:
    case IJP:
    case IJO:
    case IJS:
    case IJNE:
    case IJNL:
    case IJG:
    case IJNB:
    case IJA:
    case IJNP:
    case IJNO:
    case IJNS:
    case IJCXZ:
    case ILOOP:
    case ILOOPZ:
    case ILOOPNZ:           len = 8; break;
    }

    return len;
}

static
const char* instr2str(const u8 instruction, const u8 opt_pattern) {
    switch (instruction) {
    case SAME_OPCODE_OPS:
        switch (opt_pattern) {
        case 0b000: return "add";
        case 0b101: return "sub";
        case 0b111: return "cmp";
        }
    case IMOV:
    case IMOV_IMM2REG:
    case IMOV_IMM2REGMEM :
    case IMOV_MEM2ACC:
    case IMOV_ACC2MEM:
        return "mov";
    case IADD:
    case IADD_IMM2ACC:
        return "add";
    case ISUB:
    case ISUB_IMM_FROM_ACC:
        return "sub";
    case ICMP_REGMEM_REG:
    case ICMP_IMM_WITH_ACC:
        return "cmp";
    case IJMP_DIRECT_SEG:
    case IJMP_DIRECT_SEG_SHORT:
    case IJMP_INDIRECT_SEG:
    case IJMP_DIRECT_INTER_SEG:
        return "jmp";
    case IJE:        return "je";
    case IJL:        return "jl";
    case IJLE:       return "jle";
    case IJB:        return "jb";
    case IJBE:       return "jbe";
    case IJP:        return "jp";
    case IJO:        return "jo";
    case IJS:        return "js";
    case IJNE:       return "jne";
    case IJNL:       return "jnl";
    case IJNLE:      return "jnle";
    case IJNB:       return "jnb";
    case IJNBE:      return "jnbe";
    case IJNP:       return "jnp";
    case IJNO:       return "jno";
    case IJNS:       return "jns";
    case IJCXZ:      return "jcxz";
    case ILOOP:      return "loop";
    case ILOOPZ:     return "loopz";
    case ILOOPNZ:    return "loopnz";
    }
    return "unreachable";
}

static
const char* opv_str(op_variants_t opv) {
    switch (opv) {
    case OPV_BASE: return "OPV_BASE";
    case OPV_IMM2REG: return "OPV_IMM2REG";
    case OPV_IMM2REGMEM: return "OPV_IMM2REGMEM";
    case OPV_IMM2REGMEM_SOURCEBIT: return "OPV_IMM2REGMEM_SOURCEBIT";
    case OPV_MEM2ACC: return "OPV_ACC2MEM";
    case OPV_ACC2MEM: return "OPV_ACC2MEM";
    case OPV_IMM2ACC: return "OPV_IMM2ACC";
    case OPV_JMP: return "OPV_JMP";
    }
    return "";
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

static
void regcode_to_str(const u8 code, const u8 w_bit, char *out) {
    char *__out;
    if (!w_bit) switch (code) {
        case __D_REG_AL: __out = "al"; break;
        case __D_REG_CL: __out = "cl"; break;
        case __D_REG_DL: __out = "dl"; break;
        case __D_REG_BL: __out = "bl"; break;
        case __D_REG_AH: __out = "ah"; break;
        case __D_REG_CH: __out = "ch"; break;
        case __D_REG_DH: __out = "dh"; break;
        case __D_REG_BH: __out = "bh"; break;
    } else switch (code) {
        case __D_REG_AX: __out = "ax"; break;
        case __D_REG_CX: __out = "cx"; break;
        case __D_REG_DX: __out = "dx"; break;
        case __D_REG_BX: __out = "bx"; break;
        case __D_REG_SP: __out = "sp"; break;
        case __D_REG_BP: __out = "bp"; break;
        case __D_REG_SI: __out = "si"; break;
        case __D_REG_DI: __out = "di"; break;
    }
    strcpy(out, __out);
}

const char *ops[8] = {
    "bx + si",
    "bx + di",
    "bp + si",
    "bp + di",
    "si",
    "di",
    "bp",
    "bx",
};

typedef struct {
    u32 len;
    u32 cap;
    u32* buf;
    char** labels;
} jmp_locations_t;
jmp_locations_t jmp_locations;

static
u32 jmp_loc2label(const decoder_context_t *context, char *dst,
        const u32 location) {
    for (u32 label_location=0;
         label_location<jmp_locations.len; 
         label_location++) {
        if (context->cursor2pc[jmp_locations.buf[label_location]] == location) {
            strcpy(dst, jmp_locations.labels[label_location]);
            return strlen(dst);
        }
    }
    return 0;
}

static
void init_jmp(const u32 len) {
    jmp_locations.buf = (u32 *)malloc(sizeof(u32) * len);
    jmp_locations.cap = len;
    jmp_locations.len = 0;
    memset(jmp_locations.buf,
        0, sizeof(u32) * len);
    jmp_locations.labels = 
       (char**)malloc(sizeof(char*) * len);
    for (u32 i=0; i<__D_NO_LABELS; i++) {
        jmp_locations.labels[i] =
            (char*)malloc(sizeof(char) * 64);
    }
}

static
u8 check_jmp(u32 location) {
    for (u32 i=0; i < jmp_locations.len; i++) {
        if(jmp_locations.buf[i] == location)
            return 1;
    }
    return 0;
}

static
void jmp_set(u32 location) {
    assert(jmp_locations.len < jmp_locations.cap);
    jmp_locations.buf[jmp_locations.len] = location;
    sprintf(jmp_locations.labels[jmp_locations.len],
            "test_label_%d:", jmp_locations.len);
    jmp_locations.len += 1;
}

static
u32 decode_jmps(decoder_context_t *context, instruction_t *decoded,
        const u32 cursor, const u8 jmp_code, char *out) { 

    const u8 *buf = context->buf;

    u32 new_cursor = cursor;

    op_code_t op_code = OP_NOOP;

    switch(jmp_code) {
    case IJMP_DIRECT_SEG:       if (op_code==OP_NOOP) op_code=OP_JMP_DIRECT_SEG;
    case IJMP_DIRECT_SEG_SHORT: if (op_code==OP_NOOP) op_code=OP_JMP_DIRECT_SEG_SHORT;
    case IJMP_INDIRECT_SEG:     if (op_code==OP_NOOP) op_code=OP_JMP_INDIRECT_SEG;
    // case IJMP_INDIRECT_INTER_SEG:
    case IJMP_DIRECT_INTER_SEG: 
        assert(0 && "Unimplemented!");
        break;
    case ILOOP:   if (op_code==OP_NOOP) op_code=OP_LOOP;
    case ILOOPZ:  if (op_code==OP_NOOP) op_code=OP_LOOPZ;
    case ILOOPNZ: if (op_code==OP_NOOP) op_code=OP_LOOPNZ;
    case IJE:     if (op_code==OP_NOOP) op_code=OP_JE;
    case IJL:     if (op_code==OP_NOOP) op_code=OP_JL;
    case IJLE:    if (op_code==OP_NOOP) op_code=OP_JLE;
    case IJB:     if (op_code==OP_NOOP) op_code=OP_JB;
    case IJBE:    if (op_code==OP_NOOP) op_code=OP_JBE;
    case IJP:     if (op_code==OP_NOOP) op_code=OP_JP;
    case IJO:     if (op_code==OP_NOOP) op_code=OP_JO;
    case IJS:     if (op_code==OP_NOOP) op_code=OP_JS;
    case IJNE:    if (op_code==OP_NOOP) op_code=OP_JNE;
    case IJNL:    if (op_code==OP_NOOP) op_code=OP_JNL;
    case IJNLE:   if (op_code==OP_NOOP) op_code=OP_JNLE;
    case IJNB:    if (op_code==OP_NOOP) op_code=OP_JNB;
    case IJNBE:   if (op_code==OP_NOOP) op_code=OP_JNBE;
    case IJNP:    if (op_code==OP_NOOP) op_code=OP_JNP;
    case IJNO:    if (op_code==OP_NOOP) op_code=OP_JNO;
    case IJNS:    if (op_code==OP_NOOP) op_code=OP_JNS;
    case IJCXZ: { if (op_code==OP_NOOP) op_code=OP_JCXZ;
        u32 location = 0;
        i8 displacement_sgn = buf[cursor+1];
        u32 displacement = abs((i32)displacement_sgn);
        location = displacement_sgn < 0
            ? cursor - displacement
            : cursor + displacement;
        if (!check_jmp(location)) {
            jmp_set(location);
        }
        u32 label_idx = 0;
        for (; label_idx<jmp_locations.len
                && jmp_locations.buf[label_idx]!=location;
                label_idx++);
        if (out != NULL)
            sprintf(out, "%s", jmp_locations.labels[label_idx]);

        decoded->operands[0].type = OperandImmediate;
        decoded->operands[0].imm.value = displacement_sgn;
        decoded->is_wide = 0;
        break;
    }
    default: return new_cursor;
    }

    decoded->op_code = op_code;

    return new_cursor;
}

static
void decode_rm_complex_operand(operand_t *operand, const u8 RM,
        const u8 has_direct) {
    switch (RM) {
    case __D_RM_BX_SI:
        operand->offset.n_regs = 2;
        operand->offset.regs[0] = __D_REG_BX;
        operand->offset.regs[1] = __D_REG_SI;
        break;
    case __D_RM_BX_DI:
        operand->offset.n_regs = 2;
        operand->offset.regs[0] = __D_REG_BX;
        operand->offset.regs[1] = __D_REG_DI;
        break;
    case __D_RM_BP_SI:
        operand->offset.n_regs = 2;
        operand->offset.regs[0] = __D_REG_BP;
        operand->offset.regs[1] = __D_REG_SI;
        break;
    case __D_RM_BP_DI:
        operand->offset.n_regs = 2;
        operand->offset.regs[0] = __D_REG_BP;
        operand->offset.regs[1] = __D_REG_DI;
        break;
    case __D_RM_SI:
        operand->offset.n_regs = 1;
        operand->offset.regs[0] = __D_REG_SI;
        break;
    case __D_RM_DI:
        operand->offset.n_regs = 1;
        operand->offset.regs[0] = __D_REG_DI;
        break;
    case __D_RM_BX:
        operand->offset.n_regs = 1;
        operand->offset.regs[0] = __D_REG_BX;
        break;
    default:
        if (!has_direct && RM == __D_RM_BP) {
            operand->offset.n_regs = 1;
            operand->offset.regs[0] = __D_REG_BP;
            break;
        }
    }
}

static
u32 decode_params(decoder_context_t *context, instruction_t *decoded,
        op_variants_t variant, const u32 cursor, char *out) {

    const u8 *buf = context->buf;
    const u16 hi = (u16)(buf[cursor]) << 8;
    const u16 lo = (u16)(buf[cursor+1]);
    const u16 instr = hi | lo;
    const u8 INSTR_HI = (instr >> 8);
    const u8 INSTR_LO = (instr & 0xFF);

    u32 new_cursor = cursor;
    char reg[32] = { 0 }, rm[32] = { 0 };

#ifdef DEBUG
    printf("\n[DECODE_VARIANT]:%s\n", opv_str(variant));
#endif

    if (variant == OPV_IMM2ACC) {
        const u8 W = (instr & 0b0000000100000000) >> 8;

#ifdef DEBUG
        printf("INSTR_HI: "); __print_bits(INSTR_HI);
        printf("W:        "); __print_bits(W);
        printf("\n");
#endif
        i8 data8   = instr & 0b0000000011111111;
        i16 data16 = instr & 0b0000000011111111;
        if (W) {
            data16 = ((i16)(buf[cursor + 2] << 8)) | data16;
            new_cursor += 1;
        }

        operand_t *source_operand = &(decoded->operands[1]);
        operand_t *destination_operand = &(decoded->operands[0]);

        destination_operand->type = OperandRegister;
        destination_operand->reg.index = __D_REG_AX;
        source_operand->type = OperandImmediate;
        source_operand->imm.value = data16;
        decoded->is_wide = W;

        if (out != NULL)
            sprintf(out, "%s, %d", W ? "ax" : "al", W ? data16 : data8);
    } else if (variant == OPV_IMM2REG) {
        const u8 W = (instr & 0b0000100000000000) >> 11;
        const u8 REG = (instr & 0b0000011100000000) >> 8;

#ifdef DEBUG
        printf("INSTR_HI: "); __print_bits(INSTR_HI);
        printf("W:        "); __print_bits(W);
        printf("REG:      "); __print_bits(REG);
        printf("\n");
#endif

        u8 data8   = instr & 0b0000000011111111;
        i16 data16 = instr & 0b0000000011111111;
        if (W) {
            data16 = ((i16)(buf[cursor + 2] << 8)) | data16;
            new_cursor += 1;
        }

        decoded->is_wide = W;

        operand_t *source_operand = &(decoded->operands[1]);
        operand_t *destination_operand = &(decoded->operands[0]);

        destination_operand->type = OperandRegister;
        destination_operand->reg.index = REG;
        source_operand->type = OperandImmediate;
        source_operand->imm.value = data16;

#ifdef DEBUG
        printf("DATA-8: "); __print_bits(data8);
#endif
        if (out != NULL)
            sprintf(out, "%s, %d", reg, W ? data16 : data8);
    } else if (variant == OPV_ACC2MEM) {
        const u8 W        = (instr & 0b0000000100000000) >> 8;
        const u16 addr_lo = (instr & 0b0000000011111111);
        u16 addr = addr_lo;
        if (W) {
            const u16 addr_hi = (u16)(buf[cursor + 2] << 8);
            addr = addr_hi | addr_lo;
            new_cursor += 1;
        }

        operand_t *source_operand = &(decoded->operands[1]);
        operand_t *destination_operand = &(decoded->operands[0]);

        decoded->is_wide = W;
        destination_operand->type = OperandMemory;
        destination_operand->offset.n_regs = 0;
        destination_operand->offset.offset = addr;
        source_operand->type = OperandRegister;
        source_operand->reg.index = __D_REG_AX;

        if (out != NULL)
            sprintf(out, "[%d], ax", addr);
    } else if (variant == OPV_MEM2ACC) {
        const u8 W        = (instr & 0b0000000100000000) >> 8;
        const u16 addr_lo = (instr & 0b0000000011111111);
        const u16 addr_hi = (u16)(buf[cursor + 2] << 8);
        u16 addr = addr_lo;
        if (W) {
            addr = addr_hi | addr_lo;
            new_cursor += 1;
        }

        operand_t *source_operand = &(decoded->operands[1]);
        operand_t *destination_operand = &(decoded->operands[0]);

        decoded->is_wide = W;
        destination_operand->type = OperandRegister;
        destination_operand->reg.index = __D_REG_AX;
        source_operand->type = OperandMemory;
        source_operand->offset.n_regs = 0;
        source_operand->offset.offset = addr;

        if (out != NULL)
            sprintf(out, "ax, [%d]", addr);
    } else if (variant == OPV_IMM2REGMEM) {
        const u8 D   = (instr & 0b0000001000000000) >> 9;
        const u8 REG = (instr & 0b0000000000111000) >> 3;
        const u8 W   = (instr & 0b0000000100000000) >> 8;
        const u8 MOD = (instr & 0b0000000011000000) >> 6;
        const u8 RM  = (instr & 0b0000000000000111);

        const u16 OPT_1 = (u16)(buf[cursor + 2]);
        const u16 OPT_2 = (u16)(buf[cursor + 3]);
        const u16 OPT_3 = (u16)(buf[cursor + 4]);
        const u16 OPT_4 = (u16)(buf[cursor + 5]);

#ifdef DEBUG
        printf("INSTR_HI: "); __print_bits(INSTR_HI);
        printf("INSTR_LO: "); __print_bits(INSTR_LO);
        printf("W:        "); __print_bits(W);
        printf("REG:      "); __print_bits(REG);
        printf("D:        "); __print_bits(D);
        printf("MOD:      "); __print_bits(MOD);
        printf("RM:       "); __print_bits(RM);
        printf("OPT_1:    "); __print_bits(OPT_1);
        printf("OPT_2:    "); __print_bits(OPT_2);
        printf("OPT_3:    "); __print_bits(OPT_3);
        printf("OPT_4:    "); __print_bits(OPT_4);
        printf("\n");
#endif

        i16 data = 0;
        if (W) {
            // One more byte of data
            new_cursor += 1;
        }

        decoded->is_wide = W;


        operand_t *destination_operand = &(decoded->operands[0]);
        operand_t *source_operand = &(decoded->operands[1]);

        // Handle this edge case by skipping to the end
        u8 cmp_decoding = TEST_OP(INSTR_HI, ICMP_IMM_WITH_ACC);
        if (cmp_decoding) 
            goto decode_cmp;

        switch (MOD) {
        case __D_MOD_RM: {
            if (RM == __D_RM_DIRECT) {
                i16 addr = OPT_2 << 8 | OPT_1;
                data = W ? OPT_4 << 8 | OPT_3 : OPT_3;
                if (out != NULL)
                    sprintf(rm, "[%d]", addr);

                destination_operand->type = OperandMemory;
                destination_operand->offset.n_regs = 0;
                destination_operand->offset.offset = addr;
            } else {
                data = W ? OPT_2 << 8 | OPT_1 : OPT_1;
                if (out != NULL)
                    sprintf(rm, "[%s]", ops[RM]);

                destination_operand->type = OperandMemoryOffset;
                decode_rm_complex_operand(destination_operand, RM, TRUE);
            }
            break;
        }
        case __D_MOD_RM_OFF8: {
            i8 addr = OPT_1;
            data = W ? OPT_3 << 8 | OPT_2 : OPT_2;
            char addr_sign = addr < 0 ? '-' : '+';
            if (out != NULL)
                sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));

            destination_operand->type = OperandMemoryOffset8;
            decode_rm_complex_operand(destination_operand, RM, FALSE);
            destination_operand->offset.offset = addr;

            new_cursor += 1; break;
        }
        case __D_MOD_RM_OFF16: {
            i16 addr = OPT_2 << 8 | OPT_1;
            data = W ? OPT_4 << 8 | OPT_3 : OPT_3;
            char addr_sign = addr < 0 ? '-' : '+';
            if (out != NULL)
                sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));

            destination_operand->type = OperandMemoryOffset16;
            decode_rm_complex_operand(destination_operand, RM, FALSE);
            destination_operand->offset.offset = addr;

            new_cursor += 2; break;
        }
        case __D_MOD_R2R: {
            data = W ? OPT_2 << 8 | OPT_1 : OPT_1;
            if (out != NULL)
                regcode_to_str(RM, W, rm);

            destination_operand->type = OperandRegister;
            destination_operand->reg.index = RM;
            break;
        }
        }

        source_operand->type = OperandImmediate;
        source_operand->imm.value = data;

        if (out != NULL)
            sprintf(out, "%s, %s %d", rm, W ? "word" : "byte", data);

        // There's always at least one additinal byte for 8-bit [data]
        new_cursor += 1;
        goto done;

decode_cmp:
        i8 data8 = (i8)INSTR_LO;
        i16 data16 = (i16)INSTR_LO;
        if (W) {
            data16 = ((i16)OPT_1) << 8 | data16;
        }

        if (out != NULL) {
            sprintf(out, "%s, %d",
                    W ? "ax" : "al",
                    W ? (((i16)OPT_1) << 8 | INSTR_LO) : (i8)INSTR_LO);
        }

        destination_operand->type = OperandRegister;
        destination_operand->reg.index = __D_REG_AX;
        source_operand->type = OperandImmediate;
        source_operand->imm.value = data16;
    } else if (variant == OPV_IMM2REGMEM_SOURCEBIT) {
        const u8 S   = (instr & 0b0000001000000000) >> 9;
        const u8 W   = (instr & 0b0000000100000000) >> 8;
        const u8 MOD = (instr & 0b0000000011000000) >> 6;
        const u8 REG = (instr & 0b0000000000111000) >> 3;
        const u8 RM  = (instr & 0b0000000000000111);

        const u16 OPT_1 = (u16)(buf[cursor + 2]);
        const u16 OPT_2 = (u16)(buf[cursor + 3]);
        const u16 OPT_3 = (u16)(buf[cursor + 4]);
        const u16 OPT_4 = (u16)(buf[cursor + 5]);

#ifdef DEBUG
        printf("INSTR_HI: "); __print_bits(INSTR_HI);
        printf("W:        "); __print_bits(W);
        printf("REG:      "); __print_bits(REG);
        printf("S:        "); __print_bits(S);
        printf("MOD:      "); __print_bits(MOD);
        printf("RM:       "); __print_bits(RM);
        printf("OPT_1:    "); __print_bits(OPT_1);
        printf("OPT_2:    "); __print_bits(OPT_2);
        printf("OPT_3:    "); __print_bits(OPT_3);
        printf("OPT_4:    "); __print_bits(OPT_4);
        printf("\n");
#endif

        u8 is_wide_data = (W == 1 && S == 0);
        if (is_wide_data) {
            // One more byte of data
            new_cursor += 1;
        }

        decoded->is_wide = W;

        operand_t *destination_operand = &(decoded->operands[0]);
        operand_t *source_operand = &(decoded->operands[1]);

        i16 data = 0;
        switch (MOD) {
        case __D_MOD_RM: {
            if (RM == __D_RM_DIRECT) {
                new_cursor += 2;
                i16 addr = OPT_2 << 8 | OPT_1;
                data = is_wide_data ? OPT_4 << 8 | OPT_3 : OPT_3;
                if (out != NULL)
                    sprintf(rm, "[%d]", addr);

                destination_operand->type = OperandMemory;
                destination_operand->offset.n_regs = 0;
                destination_operand->offset.offset = addr;
            } else {
                data = is_wide_data ? OPT_2 << 8 | OPT_1 : OPT_1;
                if (out != NULL)
                    sprintf(rm, "[%s]", ops[RM]);

                destination_operand->type = OperandMemoryOffset;
                decode_rm_complex_operand(destination_operand, RM, TRUE);
            }
            break;
        }
        case __D_MOD_RM_OFF8: {
            i8 addr = OPT_1;
            data = is_wide_data ? OPT_3 << 8 | OPT_2 : OPT_2;
            char addr_sign = addr < 0 ? '-' : '+';
            if (out != NULL)
                sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));

            destination_operand->type = OperandMemoryOffset8;
            decode_rm_complex_operand(destination_operand, RM, FALSE);
            destination_operand->offset.offset = addr;
            new_cursor += 1;
            break;
        }
        case __D_MOD_RM_OFF16: {
            i16 addr = OPT_2 << 8 | OPT_1;
            data = is_wide_data ? OPT_4 << 8 | OPT_3 : OPT_3;
            char addr_sign = addr < 0 ? '-' : '+';
            if (out != NULL)
                sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));

            destination_operand->type = OperandMemoryOffset16;
            decode_rm_complex_operand(destination_operand, RM, FALSE);
            destination_operand->offset.offset = addr;
            new_cursor += 2;
            break;
        }
        case __D_MOD_R2R: {
            data = is_wide_data ? OPT_2 << 8 | OPT_1 : OPT_1;
            if (out != NULL)
                regcode_to_str(RM, W, rm);

            destination_operand->type = OperandRegister;
            destination_operand->reg.index = RM;
            break;
        }
        }

        source_operand->type = OperandImmediate;
        source_operand->imm.value = data;

        if (out != NULL)
            sprintf(out, "%s, %s %d", rm, W ? "word" : "byte", data);

        // There's always at least one additinal byte for 8-bit [data]
        new_cursor += 1;
    } else if (variant == OPV_BASE) {
        const u8 D   = (instr & 0b0000001000000000) >> 9;
        const u8 W   = (instr & 0b0000000100000000) >> 8;
        const u8 MOD = (instr & 0b0000000011000000) >> 6;
        const u8 REG = (instr & 0b0000000000111000) >> 3;
        const u8 RM  = (instr & 0b0000000000000111);

#ifdef DEBUG
        printf("INSTR_HI: "); __print_bits(INSTR_HI);
        printf("W:        "); __print_bits(W);
        printf("REG:      "); __print_bits(REG);
        printf("D:        "); __print_bits(D);
        printf("MOD:      "); __print_bits(MOD);
        printf("RM:       "); __print_bits(RM);
        printf("\n");
#endif

        decoded->is_wide = W;

        operand_t *destination_operand = &(decoded->operands[0]);
        operand_t *source_operand = &(decoded->operands[1]);

        switch (MOD) {
        case __D_MOD_R2R: {
            regcode_to_str(REG, W, reg);
            regcode_to_str(RM, W, rm);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            if (out != NULL)
                sprintf(out, "%s, %s", destination, source);

            u8 to = D ? REG : RM;
            u8 from = D ? RM : REG;

            destination_operand->type = OperandRegister;
            destination_operand->reg.index = to;
            source_operand->type = OperandRegister;
            source_operand->reg.index = from;
            decoded->is_wide = W;

            break;
        }
        
        case __D_MOD_RM: {
            operand_t memory_operand;
            operand_t register_operand;

            if (RM == __D_RM_DIRECT) {
                u16 hi = (u16)(buf[cursor + 3]) << 8;
                u16 lo = (u16)(buf[cursor + 2]);
                u16 addr = hi | lo;
                if (out != NULL)
                    sprintf(rm, "[%d]", addr);

                memory_operand.type = OperandMemory;
                memory_operand.offset.n_regs = 0;
                memory_operand.offset.offset = addr;
                new_cursor += 2;
            } else {
                if (out != NULL)
                    sprintf(rm, "[%s]", ops[RM]);

                memory_operand.type = OperandMemoryOffset;
                decode_rm_complex_operand(&memory_operand, RM, TRUE);
            }

            regcode_to_str(REG, W, reg);

            register_operand.type = OperandRegister;
            register_operand.reg.index = REG;

            const operand_t source_operand_value = D
                ? memory_operand
                : register_operand;
            const operand_t destination_operand_value = D
                ? register_operand
                : memory_operand;

            *destination_operand = destination_operand_value;
            *source_operand = source_operand_value;

            if (out != NULL) {
                const char* source = D ? rm : reg;
                const char* destination = D ? reg : rm;
                sprintf(out, "%s, %s", destination, source);
            }

            break;
        }

        case __D_MOD_RM_OFF8: {
            operand_t memory_operand;
            operand_t register_operand;

            const i8 byte = (u16)(buf[cursor + 2]);
            new_cursor += 1;

            memory_operand.type = OperandMemoryOffset8;
            decode_rm_complex_operand(&memory_operand, RM, FALSE);
            memory_operand.offset.offset = byte;

            register_operand.type = OperandRegister;
            register_operand.reg.index = REG;

            const operand_t source_operand_value = D
                ? memory_operand
                : register_operand;
            const operand_t destination_operand_value = D
                ? register_operand
                : memory_operand;

            *destination_operand  = destination_operand_value;
            *source_operand = source_operand_value;

            if (out != NULL) {
                regcode_to_str(REG, W, reg);

                if (byte == 0) {
                    sprintf(rm, "[%s]", ops[RM]);
                } else {
                    char byte_sign = byte < 0 ? '-' : '+';
                    sprintf(rm, "[%s %c %d]", ops[RM], byte_sign, abs(byte));
                }

                const char* source = D ? rm : reg;
                const char* destination = D ? reg : rm;
                sprintf(out, "%s, %s", destination, source);
            }

            break;
        }

        case __D_MOD_RM_OFF16: {
            operand_t memory_operand;
            operand_t register_operand;

            i16 hi = (u16)(buf[cursor + 3]) << 8;
            i16 lo = (u16)(buf[cursor + 2]);
            i16 data = hi | lo;
            const i16 wide = (data >> 8) | (data << 8);
            char wide_sign = wide < 0 ? '-' : '+';
            new_cursor += 2;

            memory_operand.type = OperandMemoryOffset16;
            decode_rm_complex_operand(&memory_operand, RM, FALSE);
            memory_operand.offset.offset = data;

            register_operand.type = OperandRegister;
            register_operand.reg.index = REG;

            const operand_t source_operand_value = D
                ? memory_operand
                : register_operand;
            const operand_t destination_operand_value = D
                ? register_operand
                : memory_operand;

            *destination_operand = destination_operand_value;
            *source_operand = source_operand_value;

            if (out != NULL) {
                const char* source = D ? rm : reg;
                const char* destination = D ? reg : rm;
                regcode_to_str(REG, W, reg);
                sprintf(rm, "[%s %c %d]", ops[RM], wide_sign, abs(wide));
                sprintf(out, "%s, %s", destination, source);
            }

            break;
        }
        }

    }

done:
    return new_cursor;
}

u32 decode(decoder_context_t *context, instruction_t *decoded,
        const u32 cursor, char *out) {

    const u8 *buf = context->buf;
    const u16 hi = (u16)(buf[cursor]) << 8;
    const u16 lo = (u16)(buf[cursor+1]);
    const u16 instr = hi | lo;
    const u8 INSTR_HI = (instr >> 8);
    const u8 INSTR_LO = (instr & 0xFF);
    const u8 bits_432 = (INSTR_LO >> 3) & 0b111;
    u32 new_cursor = cursor;

#ifdef DEBUG
    printf("INSTR_HI: "); __print_bits(INSTR_HI);
    printf("TEST_OP(INSTR_HI, IMOV_IMM2REG):  %d\n",
            TEST_OP(INSTR_HI, IMOV_IMM2REG));
    printf("TEST_OP(INSTR_HI, IMOV_ACC2MEM):  %d\n",
            TEST_OP(INSTR_HI, IMOV_ACC2MEM));
    printf("TEST_OP(INSTR_HI, IMOV_MEM2ACC):  %d\n",
            TEST_OP(INSTR_HI, IMOV_MEM2ACC));
    printf("TEST_OP(INSTR_HI, IMOV_IMM2REGM): %d\n",
            TEST_OP(INSTR_HI, IMOV_IMM2REGMEM));
    printf("TEST_OP(INSTR_HI, IMOV):          %d\n", TEST_OP(INSTR_HI, IMOV));
#endif

    char params[32] = {0};
    op_variants_t matched_variant;
    if (   (decoded->op_code=OP_MOV_IMM2REG,
                matched_variant=OPV_IMM2REG, TEST_OP(INSTR_HI, IMOV_IMM2REG))   
        || (decoded->op_code=OP_MOV_ACC2MEM, 
                matched_variant=OPV_ACC2MEM, TEST_OP(INSTR_HI, IMOV_ACC2MEM))  
        || (decoded->op_code=OP_MOV_MEM2ACC, 
                matched_variant=OPV_MEM2ACC, TEST_OP(INSTR_HI, IMOV_MEM2ACC))  
        || (decoded->op_code=OP_MOV_IMM2REGMEM,
                matched_variant=OPV_IMM2REGMEM, TEST_OP(INSTR_HI, IMOV_IMM2REGMEM))
        || (decoded->op_code=OP_MOV, 
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, IMOV))           
        ) {
#ifdef DEBUG
        printf("[MOV] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded,
                matched_variant, cursor, params);
        if (out != NULL) 
            sprintf(out, "mov %s", params);

        context->pc++;

        return new_cursor;
    }

#ifdef DEBUG
    printf("TEST_OP(INSTR_HI, IADD_IMM2ACC):    %d\n",
            TEST_OP(INSTR_HI, IADD_IMM2ACC));
    printf("TEST_OP(INSTR_HI, IADD_IMM2REGMEM): %d\n",
            TEST_OP(INSTR_HI, IADD_IMM2REGMEM));
    printf("TEST_OP(INSTR_HI, IADD):            %d\n",
            TEST_OP(INSTR_HI, IADD));
#endif

    if (   (decoded->op_code=OP_ADD_IMM2ACC,
                matched_variant=OPV_IMM2ACC, TEST_OP(INSTR_HI, IADD_IMM2ACC))
        || (decoded->op_code=OP_ADD,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, IADD))
        ) {
#ifdef DEBUG
        printf("[ADD] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded, matched_variant, cursor, params);
        if (out != NULL) 
            sprintf(out, "add %s", params);

        context->pc++;

        return new_cursor;
    }

#ifdef DEBUG
    printf("TEST_OP(INSTR_HI, ISUB_IMM_FROM_ACC):     %d\n", TEST_OP(INSTR_HI, ISUB_IMM_FROM_ACC));
    printf("TEST_OP(INSTR_HI, ISUB_IMM_FROM_REGMEM):  %d\n", TEST_OP(INSTR_HI, ISUB_IMM_FROM_REGMEM));
    printf("TEST_OP(INSTR_HI, ISUB):                  %d\n", TEST_OP(INSTR_HI, ISUB));
#endif

    if (   (decoded->op_code=OP_SUB_IMM_FROM_ACC,
                matched_variant=OPV_IMM2ACC, TEST_OP(INSTR_HI, ISUB_IMM_FROM_ACC))
        || (decoded->op_code=OP_SUB,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, ISUB))
        ) {
#ifdef DEBUG
        printf("[SUB] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded, matched_variant, cursor, params);
        if (out != NULL) 
            sprintf(out, "sub %s", params);

        context->pc++;

        return new_cursor;
    }

#ifdef DEBUG
    printf("TEST_OP(INSTR_HI, ICMP_IMM_WITH_ACC):     %d\n", TEST_OP(INSTR_HI, ICMP_IMM_WITH_ACC));
    printf("TEST_OP(INSTR_HI, ICMP_REGMEM_REG):       %d\n", TEST_OP(INSTR_HI, ICMP_REGMEM_REG));
    printf("TEST_OP(INSTR_HI, ICMP_IMM_WITH_REGMEM):  %d\n", TEST_OP(INSTR_HI, ICMP_IMM_WITH_REGMEM));
#endif

    if (   (decoded->op_code=OP_CMP_IMM_WITH_ACC,
                matched_variant=OPV_IMM2REGMEM, TEST_OP(INSTR_HI, ICMP_IMM_WITH_ACC))
        || (decoded->op_code=OP_CMP_REGMEM_REG,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, ICMP_REGMEM_REG))
        ) {
#ifdef DEBUG
        printf("[CMP] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded, matched_variant, cursor, params);
        if (out != NULL) 
            sprintf(out, "cmp %s", params);

        context->pc++;

        return new_cursor;
    }

    u8 matched_jmp_code;
    if (   (decoded->op_code=OP_JMP_DIRECT_SEG,
                TEST_OP(INSTR_HI, IJMP_DIRECT_SEG))
        || (decoded->op_code=OP_JMP_DIRECT_SEG_SHORT,
                TEST_OP(INSTR_HI, IJMP_DIRECT_SEG_SHORT))
        || (decoded->op_code=OP_JMP_INDIRECT_SEG,
                TEST_OP(INSTR_HI, IJMP_INDIRECT_SEG))
        || (decoded->op_code=OP_JMP_DIRECT_INTER_SEG,
                TEST_OP(INSTR_HI, IJMP_DIRECT_INTER_SEG))
        || (decoded->op_code=OP_JE,      TEST_OP(INSTR_HI, IJE))
        || (decoded->op_code=OP_JL,      TEST_OP(INSTR_HI, IJL))
        || (decoded->op_code=OP_JLE,     TEST_OP(INSTR_HI, IJLE))
        || (decoded->op_code=OP_JB,      TEST_OP(INSTR_HI, IJB))
        || (decoded->op_code=OP_JBE,     TEST_OP(INSTR_HI, IJBE))
        || (decoded->op_code=OP_JP,      TEST_OP(INSTR_HI, IJP))
        || (decoded->op_code=OP_JO,      TEST_OP(INSTR_HI, IJO))
        || (decoded->op_code=OP_JS,      TEST_OP(INSTR_HI, IJS))
        || (decoded->op_code=OP_JNE,     TEST_OP(INSTR_HI, IJNE))
        || (decoded->op_code=OP_JNL,     TEST_OP(INSTR_HI, IJNL))
        || (decoded->op_code=OP_JNLE,    TEST_OP(INSTR_HI, IJNLE))
        || (decoded->op_code=OP_JNB,     TEST_OP(INSTR_HI, IJNB))
        || (decoded->op_code=OP_JNBE,    TEST_OP(INSTR_HI, IJNBE))
        || (decoded->op_code=OP_JNP,     TEST_OP(INSTR_HI, IJNP))
        || (decoded->op_code=OP_JNO,     TEST_OP(INSTR_HI, IJNO))
        || (decoded->op_code=OP_JNS,     TEST_OP(INSTR_HI, IJNS))
        || (decoded->op_code=OP_JCXZ,    TEST_OP(INSTR_HI, IJCXZ))) {
        // decode jumps
#ifdef DEBUG
        printf("[JUMPS] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        char params[32];
        const char* instr_str = instr2str(INSTR_HI, NONE);
        assert((instr_str[0] == 'j' || instr_str[0] == 'n')
                && "instruction name must start with either 'j' or 'n'");
        new_cursor = decode_jmps(context, decoded, cursor, INSTR_HI, params);
        if (out != NULL) 
            sprintf(out, "%s %s", instr2str(INSTR_HI, 0), params);

        context->pc++;

        return new_cursor;
    }

    if (   TEST_OP(INSTR_HI, ISAL)
        || TEST_OP(INSTR_HI, ISHL)
        || TEST_OP(INSTR_HI, ISAR)
        || TEST_OP(INSTR_HI, ISHR)
        || TEST_OP(INSTR_HI, ISHR)
        || TEST_OP(INSTR_HI, IROL)
        || TEST_OP(INSTR_HI, IROR)
       ) {
        new_cursor = decode_params(context, decoded, OPV_BASE,
            new_cursor, params);

        switch (bits_432) {
            case 0b100: // SAL/SHL (they're the same)
#ifdef DEBUG
        printf("[SAL] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_SAL;
            if (out != NULL) 
                sprintf(out, "sal %s", params);
            break;

            case 0b101: // SHR
#ifdef DEBUG
        printf("[SHR] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_SHR;
            if (out != NULL) 
                sprintf(out, "shr %s", params);
            break;

            case 0b111: // SAR
#ifdef DEBUG
        printf("[SAR] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_SAR;
            if (out != NULL) 
                sprintf(out, "sar %s", params);
            break;

            case 0b000: // ROL
#ifdef DEBUG
        printf("[ROL] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_ROL;
            if (out != NULL) 
                sprintf(out, "rol %s", params);
            break;

            case 0b001: // ROR
#ifdef DEBUG
        printf("[ROR] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_ROR;
            if (out != NULL) 
                sprintf(out, "ror %s", params);
            break;
        }

        context->pc++;

        return new_cursor;
    }

    if (   (decoded->op_code=OP_XOR_REGMEM2REG,
                matched_variant=OPV_IMM2ACC, TEST_OP(INSTR_HI, IOR_IMM2ACC))
        || (decoded->op_code=OP_OR_REGMEM2REG,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, IOR_REGMEM2REG))
       ) {
#ifdef DEBUG
        printf("[OR] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded, matched_variant, cursor, params);
        if (out != NULL) 
            sprintf(out, "or %s", params);

        context->pc++;

        return new_cursor;
    }

    if (   (decoded->op_code=OP_OR_IMM2ACC,
                matched_variant=OPV_IMM2ACC, TEST_OP(INSTR_HI, IOR_IMM2ACC))
        || (decoded->op_code=OP_OR_REGMEM2REG,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, IOR_REGMEM2REG))
       ) {
#ifdef DEBUG
        printf("[OR] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded, matched_variant, cursor, params);
        if (out != NULL) 
            sprintf(out, "or %s", params);

        context->pc++;

        return new_cursor;
    }

    if (   TEST_OP(INSTR_HI, INOT)
        || TEST_OP(INSTR_HI, IMUL)
        || TEST_OP(INSTR_HI, IIMUL)
        || TEST_OP(INSTR_HI, IDIV)
        || TEST_OP(INSTR_HI, IIDIV)) {
        new_cursor = decode_params(context, decoded, OPV_BASE, new_cursor, params);

        switch (bits_432) {
            case 0b010:
#ifdef DEBUG
        printf("[NOT] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_NOT;
            if (out != NULL) 
                sprintf(out, "not %s", params);
            break;

            case 0b100: // MUL
#ifdef DEBUG
        printf("[MOV] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_MUL;
            if (out != NULL) 
                sprintf(out, "mov %s", params);
            break;

            case 0b101: // IMUL
#ifdef DEBUG
        printf("[IMOV] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_IMUL;
            if (out != NULL) 
                sprintf(out, "imov %s", params);
            break;

            case 0b110: // DIV
#ifdef DEBUG
        printf("[DIV] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_DIV;
            if (out != NULL) 
                sprintf(out, "div %s", params);
            break;

            case 0b111: // IDIV
#ifdef DEBUG
        printf("[IDIV] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_IDIV;
            if (out != NULL) 
                sprintf(out, "idiv %s", params);
            break;
        }

        context->pc++;

        return new_cursor;
    }

    if (   (decoded->op_code=OP_AND_IMM2ACC,
                matched_variant=OPV_IMM2ACC, TEST_OP(INSTR_HI, IAND_IMM2ACC))
        || (decoded->op_code=OP_AND_REGMEM2REG,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, IAND_REGMEM2REG))
       ) {
#ifdef DEBUG
        printf("[AND] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded, matched_variant, cursor, params);
        if (out != NULL) 
            sprintf(out, "and %s", params);

        context->pc++;

        return new_cursor;
    }

    if (   (decoded->op_code=OP_XOR_REGMEM2REG,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, IXOR_REGMEM2REG))
        || (decoded->op_code=OP_XOR_IMM2ACC,
                matched_variant=OPV_IMM2ACC, TEST_OP(INSTR_HI, IXOR_IMM2ACC))
       ) {
#ifdef DEBUG
        printf("[XOR] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded, matched_variant, cursor, params);
        if (out != NULL) 
            sprintf(out, "xor %s", params);

        context->pc++;

        return new_cursor;
    }

    if (   (decoded->op_code=OP_TEST_REGMEM2REG,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, ITEST_REGMEM2REG))
        || (decoded->op_code=OP_TEST_IMM2REGMEM,
                matched_variant=OPV_IMM2REGMEM, TEST_OP(INSTR_HI, ITEST_IMM2REGMEM))
        || (decoded->op_code=OP_TEST_IMM2ACC,
                matched_variant=OPV_IMM2ACC, TEST_OP(INSTR_HI, ITEST_IMM2ACC))
       ) {
#ifdef DEBUG
        printf("[TEST] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded, matched_variant, cursor, params);
        if (out != NULL) 
            sprintf(out, "test %s", params);

        context->pc++;

        return new_cursor;
    }

    if (   (decoded->op_code=OP_LOOP,
                matched_variant=OPV_JMP, TEST_OP(INSTR_HI, ILOOP))
        || (decoded->op_code=OP_LOOPZ,
                matched_variant=OPV_JMP, TEST_OP(INSTR_HI, ILOOPZ))
        || (decoded->op_code=OP_LOOPNZ,
                matched_variant=OPV_JMP, TEST_OP(INSTR_HI, ILOOPNZ))
       ) {
#ifdef DEBUG
        printf("[LOOPS] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        // decode loops
        char params[32];
        const char* instr_str = instr2str(INSTR_HI, NONE);
        new_cursor = decode_jmps(context, decoded, cursor, INSTR_HI, params);
        assert(instr_str[0] == 'l' && "instruction name must start with 'l'");
        if (out != NULL) 
            sprintf(out, "%s %s", instr_str, params);

        context->pc++;

        decoded->operands[0].type = OperandImmediate;
        decoded->operands[0].imm.value = buf[cursor+1];

        context->pc++;

        return new_cursor;
    }

    // Check for opcodes with the same value (other flags must differ)
    if (   TEST_OP(INSTR_HI, IADD_IMM2REGMEM)
        || TEST_OP(INSTR_HI, ISUB_IMM_FROM_REGMEM)
        || TEST_OP(INSTR_HI, IAND_IMM2REGMEM)
        || TEST_OP(INSTR_HI, IXOR_IMM2REGMEM)
        || TEST_OP(INSTR_HI, IOR_IMM2REGMEM)
        || TEST_OP(INSTR_HI, ICMP_IMM_WITH_REGMEM)) {
        new_cursor = decode_params(context, decoded, OPV_IMM2REGMEM_SOURCEBIT, new_cursor, params);

#ifdef DEBUG
        printf("[CONFLICT_CASE]: "); __print_bits(bits_432);
#endif

        switch (bits_432) {
        case 0b000: // ADD
#ifdef DEBUG
        printf("[ADD] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
        decoded->op_code=OP_ADD_IMM2REGMEM;
            if (out != NULL)
                sprintf(out, "add %s", params);
            break;
        case 0b101: // SUB
#ifdef DEBUG
        printf("[SUB] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
        decoded->op_code=OP_SUB_IMM_FROM_REGMEM;
            if (out != NULL) 
                sprintf(out, "sub %s", params);
            break;
        case 0b111: // CMP 
#ifdef DEBUG
        printf("[CMP] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_CMP_IMM_WITH_REGMEM;
            if (out != NULL) 
                sprintf(out, "cmp %s", params);
            break;
        case 0b100: // AND
#ifdef DEBUG
        printf("[AND] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_AND_IMM2REGMEM;
            if (out != NULL) 
                sprintf(out, "and %s", params);
            break;
        case 0b001: // OR
#ifdef DEBUG
        printf("[OR] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_OR_IMM2REGMEM;
            if (out != NULL) 
                sprintf(out, "or %s", params);
            break;
        case 0b110: // XOR
#ifdef DEBUG
        printf("[XOR] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            decoded->op_code=OP_XOR_IMM2REGMEM;
            if (out != NULL) 
                sprintf(out, "xor %s", params);
            break;
        }

        context->pc++;

        return new_cursor;
    }

    assert(0 && "No decode matched");
    return -1;
}

u32 decoder_init(decoder_context_t *context,
        const u8 *program, const u32 size) {
    assert(context != NULL && program != NULL);

    context->buflen = size;
    context->buf = program;

    init_jmp(size);
    context->cursor2pc = (u32*)malloc(size / 2);

    return 1;
}

void decoder_destroy(decoder_context_t *context) {
    assert(context != NULL);
    free((void *)context->buf);
    free((void *)context->cursor2pc);
    context->cursor2pc = NULL;
    context->buf = NULL;
    context->buflen = 0;
}
