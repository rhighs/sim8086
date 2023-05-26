#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "op_code.h"
#include "decoder.h"

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

u8 check_jmp(u32 location) {
    for (u32 i=0; i < jmp_locations.len; i++) {
        if(jmp_locations.buf[i] == location)
            return 1;
    }
    return 0;
}

void jmp_set(u32 location) {
    assert(jmp_locations.len < jmp_locations.cap);
    jmp_locations.buf[jmp_locations.len] = location;
    sprintf(jmp_locations.labels[jmp_locations.len],
            "test_label_%d:", jmp_locations.len);
    jmp_locations.len += 1;
}

u32 decode_jmps(decoder_context_t *context, instruction_t *decoded_construct,
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
        break;
    }
    default: return new_cursor;
    }

    decoded_construct->op_code = op_code;

    return new_cursor;
}

// TOOD: implementation
u32 decode_loops(const u8 *buf, const u32 cursor,
        op_variants_t variant, char *out) {
    return cursor;
}

u32 decode_params(decoder_context_t *context, instruction_t *decoded_construct,
        op_variants_t variant, const u32 cursor, char *out) {

    const u8 *buf = context->buf;

    u16 hi = (u16)(buf[cursor]) << 8;
    u16 lo = (u16)(buf[cursor+1]);
    u16 instr = hi | lo;
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

        decoded_construct->operands[0].type = OperandRegister;
        decoded_construct->operands[0].reg.index = REG;
        decoded_construct->is_wide = W;
        decoded_construct->operands[1].type = OperandImmediate;
        decoded_construct->operands[1].imm.value = data16;

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

        // Handle this edge case by skipping to the end
        u8 cmp_decoding = TEST_OP(INSTR_HI, ICMP_IMM_WITH_ACC);
        if (cmp_decoding) 
            goto decode_cmp;

        switch (MOD) {
        case __D_MOD_RM: {
            if (RM == __D_RM_DIRECT) {
                new_cursor += 2;
                i16 addr = OPT_2 << 8 | OPT_1;
                data = W ? OPT_4 << 8 | OPT_3 : OPT_3;
                if (out != NULL)
                    sprintf(rm, "[%d]", addr);
            } else {
                data = W ? OPT_2 << 8 | OPT_1 : OPT_1;
                if (out != NULL)
                    sprintf(rm, "[%s]", ops[RM]);
            }
            break;
        }
        case __D_MOD_RM_OFF8: {
            i8 addr = OPT_1;
            data = W ? OPT_3 << 8 | OPT_2 : OPT_2;
            char addr_sign = addr < 0 ? '-' : '+';
            if (out != NULL)
                sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));
            new_cursor += 1; break;
        }
        case __D_MOD_RM_OFF16: {
            i16 addr = OPT_2 << 8 | OPT_1;
            data = W ? OPT_4 << 8 | OPT_3 : OPT_3;
            char addr_sign = addr < 0 ? '-' : '+';
            if (out != NULL)
                sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));
            new_cursor += 2; break;
        }
        case __D_MOD_R2R: {
            data = W ? OPT_2 << 8 | OPT_1 : OPT_1;
            if (out != NULL)
                sprintf(rm, "%s", ops[RM]);
            break;
        }
        }
        if (out != NULL)
            sprintf(out, "%s, %s %d", rm, W ? "word" : "byte", data);
        // There's always at least one additinal byte for 8-bit [data]
        new_cursor += 1;

decode_cmp:
        if (out != NULL) {
            sprintf(out, "%s, %d",
                    W ? "ax" : "al",
                    W ? (((i16)OPT_1) << 8 | INSTR_LO) : (i8)INSTR_LO);
        }
    } else if (variant == OPV_IMM2REGMEM_SOURCEBIT) {
        const u8 S   = (instr & 0b0000001000000000) >> 9;
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

        i16 data = 0;
        switch (MOD) {
        case __D_MOD_RM: {
            if (RM == __D_RM_DIRECT) {
                new_cursor += 2;
                i16 addr = OPT_2 << 8 | OPT_1;
                data = is_wide_data ? OPT_4 << 8 | OPT_3 : OPT_3;
                if (out != NULL)
                    sprintf(rm, "[%d]", addr);
            } else {
                data = is_wide_data ? OPT_2 << 8 | OPT_1 : OPT_1;
                if (out != NULL)
                    sprintf(rm, "[%s]", ops[RM]);
            }
            break;
        }
        case __D_MOD_RM_OFF8: {
            i8 addr = OPT_1;
            data = is_wide_data ? OPT_3 << 8 | OPT_2 : OPT_2;
            char addr_sign = addr < 0 ? '-' : '+';
            if (out != NULL)
                sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));
            new_cursor += 1; break;
        }
        case __D_MOD_RM_OFF16: {
            i16 addr = OPT_2 << 8 | OPT_1;
            data = is_wide_data ? OPT_4 << 8 | OPT_3 : OPT_3;
            char addr_sign = addr < 0 ? '-' : '+';
            if (out != NULL)
                sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));
            new_cursor += 2; break;
        }
        case __D_MOD_R2R: {
            data = is_wide_data ? OPT_2 << 8 | OPT_1 : OPT_1;
            if (out != NULL)
                sprintf(rm, "%s", ops[RM]);
            break;
        }
        }

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

            decoded_construct->operands[0].type = OperandRegister;
            decoded_construct->operands[0].reg.index = to;
            decoded_construct->operands[1].type = OperandRegister;
            decoded_construct->operands[1].reg.index = from;
            decoded_construct->is_wide = W;

            break;
        }
        
        case __D_MOD_RM: {
            if (RM == __D_RM_DIRECT) {
                u16 hi = (u16)(buf[cursor + 3]) << 8;
                u16 lo = (u16)(buf[cursor + 2]);
                u16 wide = hi | lo;
                if (out != NULL)
                    sprintf(rm, "[%d]", wide);
                new_cursor += 2;
            } else {
                if (out != NULL)
                    sprintf(rm, "[%s]", ops[RM]);
            }

            regcode_to_str(REG, W, reg);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            if (out != NULL)
                sprintf(out, "%s, %s", destination, source);
            break;
        }

        case __D_MOD_RM_OFF8: {
            const i8 byte = (u16)(buf[cursor + 2]);
            if (out != NULL) {
                if (byte == 0) {
                    sprintf(rm, "[%s]", ops[RM]);
                } else {
                    char byte_sign = byte < 0 ? '-' : '+';
                    sprintf(rm, "[%s %c %d]", ops[RM], byte_sign, abs(byte));
                }
            }
            new_cursor += 1;

            regcode_to_str(REG, W, reg);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            if (out != NULL)
                sprintf(out, "%s, %s", destination, source);
            break;
        }

        case __D_MOD_RM_OFF16: {
            i16 hi = (u16)(buf[cursor + 3]) << 8;
            i16 lo = (u16)(buf[cursor + 2]);
            i16 data = hi | lo;
            const i16 wide = (data >> 8) | (data << 8);
            char wide_sign = wide < 0 ? '-' : '+';
            if (out != NULL)
                sprintf(rm, "[%s %c %d]", ops[RM], wide_sign, abs(wide));
            new_cursor += 2;

            regcode_to_str(REG, W, reg);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            if (out != NULL)
                sprintf(out, "%s, %s", destination, source);
            break;
        }
        }

    }

    return new_cursor;
}

u32 decode(decoder_context_t *context, instruction_t *decoded_construct,
        const u32 cursor, char *out) {

    const u8 *buf = context->buf;

    u16 hi = (u16)(buf[cursor]) << 8;
    u16 lo = (u16)(buf[cursor+1]);
    u16 instr = hi | lo;
    const u8 INSTR_HI = (instr >> 8);
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
    if (   (decoded_construct->op_code=OP_MOV_IMM2REG,
                matched_variant=OPV_IMM2REG, TEST_OP(INSTR_HI, IMOV_IMM2REG))   
        || (decoded_construct->op_code=OP_MOV_ACC2MEM, 
                matched_variant=OPV_ACC2MEM, TEST_OP(INSTR_HI, IMOV_ACC2MEM))  
        || (decoded_construct->op_code=OP_MOV_MEM2ACC, 
                matched_variant=OPV_MEM2ACC, TEST_OP(INSTR_HI, IMOV_MEM2ACC))  
        || (decoded_construct->op_code=OP_MOV_IMM2REGMEM,
                matched_variant=OPV_IMM2REGMEM, TEST_OP(INSTR_HI, IMOV_IMM2REGMEM))
        || (decoded_construct->op_code=OP_MOV, 
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, IMOV))           
        ) {
#ifdef DEBUG
        printf("[MOV] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded_construct,
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

    if (   (decoded_construct->op_code=OP_ADD_IMM2ACC,
                matched_variant=OPV_IMM2ACC, TEST_OP(INSTR_HI, IADD_IMM2ACC))
        || (decoded_construct->op_code=OP_ADD,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, IADD))
        ) {
#ifdef DEBUG
        printf("[ADD] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded_construct, matched_variant, cursor, params);
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

    if (   (decoded_construct->op_code=OP_SUB_IMM_FROM_ACC,
                matched_variant=OPV_IMM2ACC, TEST_OP(INSTR_HI, ISUB_IMM_FROM_ACC))
        || (decoded_construct->op_code=OP_SUB,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, ISUB))
        ) {
#ifdef DEBUG
        printf("[SUB] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded_construct, matched_variant, cursor, params);
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

    const u8 bits_432 = (buf[cursor+1] >> 3) & 0b111;

    if (   (decoded_construct->op_code=OP_CMP_IMM_WITH_ACC,
                matched_variant=OPV_IMM2REGMEM, TEST_OP(INSTR_HI, ICMP_IMM_WITH_ACC))
        || (decoded_construct->op_code=OP_CMP_REGMEM_REG,
                matched_variant=OPV_BASE, TEST_OP(INSTR_HI, ICMP_REGMEM_REG))
        ) {
#ifdef DEBUG
        printf("[CMP] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_cursor = decode_params(context, decoded_construct, matched_variant, cursor, params);
        if (out != NULL) 
            sprintf(out, "cmp %s", params);

        context->pc++;

        return new_cursor;
    }

    u8 matched_jmp_code;
    if (   (decoded_construct->op_code=OP_JMP_DIRECT_SEG,
                TEST_OP(INSTR_HI, IJMP_DIRECT_SEG))
        || (decoded_construct->op_code=OP_JMP_DIRECT_SEG_SHORT,
                TEST_OP(INSTR_HI, IJMP_DIRECT_SEG_SHORT))
        || (decoded_construct->op_code=OP_JMP_INDIRECT_SEG,
                TEST_OP(INSTR_HI, IJMP_INDIRECT_SEG))
        || (decoded_construct->op_code=OP_JMP_DIRECT_INTER_SEG,
                TEST_OP(INSTR_HI, IJMP_DIRECT_INTER_SEG))
        || (decoded_construct->op_code=OP_JE,      TEST_OP(INSTR_HI, IJE))
        || (decoded_construct->op_code=OP_JL,      TEST_OP(INSTR_HI, IJL))
        || (decoded_construct->op_code=OP_JLE,     TEST_OP(INSTR_HI, IJLE))
        || (decoded_construct->op_code=OP_JB,      TEST_OP(INSTR_HI, IJB))
        || (decoded_construct->op_code=OP_JBE,     TEST_OP(INSTR_HI, IJBE))
        || (decoded_construct->op_code=OP_JP,      TEST_OP(INSTR_HI, IJP))
        || (decoded_construct->op_code=OP_JO,      TEST_OP(INSTR_HI, IJO))
        || (decoded_construct->op_code=OP_JS,      TEST_OP(INSTR_HI, IJS))
        || (decoded_construct->op_code=OP_JNE,     TEST_OP(INSTR_HI, IJNE))
        || (decoded_construct->op_code=OP_JNL,     TEST_OP(INSTR_HI, IJNL))
        || (decoded_construct->op_code=OP_JNLE,    TEST_OP(INSTR_HI, IJNLE))
        || (decoded_construct->op_code=OP_JNB,     TEST_OP(INSTR_HI, IJNB))
        || (decoded_construct->op_code=OP_JNBE,    TEST_OP(INSTR_HI, IJNBE))
        || (decoded_construct->op_code=OP_JNP,     TEST_OP(INSTR_HI, IJNP))
        || (decoded_construct->op_code=OP_JNO,     TEST_OP(INSTR_HI, IJNO))
        || (decoded_construct->op_code=OP_JNS,     TEST_OP(INSTR_HI, IJNS))
        || (decoded_construct->op_code=OP_JCXZ,    TEST_OP(INSTR_HI, IJCXZ))) {
        // decode jumps
#ifdef DEBUG
        printf("[JUMPS] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        char params[32];
        const char* instr_str = instr2str(INSTR_HI, NONE);
        assert((instr_str[0] == 'j' || instr_str[0] == 'n')
                && "instruction name must start with either 'j' or 'n'");
        new_cursor = decode_jmps(context, decoded_construct, cursor, INSTR_HI, params);
        if (out != NULL) 
            sprintf(out, "%s %s", instr2str(INSTR_HI, 0), params);

        context->pc++;

        return new_cursor;
    }

    if (   (matched_variant=OPV_JMP,  TEST_OP(INSTR_HI, ILOOP))
        || (matched_variant=OPV_JMP,  TEST_OP(INSTR_HI, ILOOPZ))
        || (matched_variant=OPV_JMP,  TEST_OP(INSTR_HI, ILOOPNZ))
       ) {
#ifdef DEBUG
        printf("[LOOPS] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        // decode loops
        char params[32];
        const char* instr_str = instr2str(INSTR_HI, NONE);
        assert(instr_str[0] == 'l' && "instruction name must start with 'l'");
        new_cursor = decode_loops(buf, cursor, matched_variant, params);

        context->pc++;

        return new_cursor;
    }

    // Check for opcodes with the same value (other flags must differ)
    if (   TEST_OP(INSTR_HI, IADD_IMM2REGMEM)
        || TEST_OP(INSTR_HI, ISUB_IMM_FROM_REGMEM)
        || TEST_OP(INSTR_HI, ICMP_IMM_WITH_REGMEM)) {
        new_cursor = decode_params(context, decoded_construct, OPV_IMM2REGMEM_SOURCEBIT, new_cursor, params);
        const u8 bits_432 = (buf[cursor+1] >> 3) & 0b111;

#ifdef DEBUG
        printf("[CONFLICT_CASE]: "); __print_bits(bits_432);
#endif

        switch (bits_432) {
        case 0b000: // ADD
#ifdef DEBUG
        printf("[ADD] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            sprintf(out, "add %s", params);
            decoded_construct->op_code = OP_ADD_IMM2REGMEM;
            break;
        case 0b101: // SUB
#ifdef DEBUG
        printf("[SUB] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            if (out != NULL) 
                sprintf(out, "sub %s", params);
            decoded_construct->op_code = OP_SUB_IMM_FROM_REGMEM;
            break;
        case 0b111: // CMP 
#ifdef DEBUG
        printf("[CMP] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            if (out != NULL) 
                sprintf(out, "cmp %s", params);
            decoded_construct->op_code = OP_CMP_IMM_WITH_REGMEM;
            break;
        }

        context->pc++;

        return new_cursor;
    }

    assert(0 && "No decode matched");
    return -1;
}

u32 init_from_file(decoder_context_t *context, const char* filepath) {
    assert(context != NULL);

    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        goto bad_path_error;
    }

    fseek(file, 0, SEEK_END);
    u32 file_size = ftell(file);
    rewind(file);

    context->buflen = file_size;
    context->buf = (u8*)malloc(file_size);
    u32 nread = 0;
    u32 bytes_read = 0;
    while ((nread = fread(context->buf, sizeof(u8), file_size, file)) > 0) {
        bytes_read += nread;
    }
    init_jmp(bytes_read);
    if (ferror(file)) {
        goto read_error;
    }
    fclose(file);

    context->cursor2pc = (u32*)malloc(file_size / 2);

    return file_size;

bad_path_error: 
    fprintf(stderr, "[BAD_PATH_ERR]: path %s might not exist\n", filepath);
    return 0;
read_error:
    fprintf(stderr, "[READ_FILE_ERR]: error reading file!\n");
    fclose(file);
    return 0;
}

void destroy(decoder_context_t *context) {
    assert(context != NULL);
    free(context->buf);
    free(context->cursor2pc);
    context->cursor2pc = NULL;
    context->buf = NULL;
    context->buflen = 0;
}

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

