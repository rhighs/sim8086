#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define NONE 0
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define REG_AL 0x0
#define REG_CL 0x1
#define REG_DL 0x2
#define REG_BL 0x3
#define REG_AH 0x4
#define REG_CH 0x5
#define REG_DH 0x6
#define REG_BH 0x7
#define REG_AX 0x0
#define REG_CX 0x1
#define REG_DX 0x2
#define REG_BX 0x3
#define REG_SP 0x4
#define REG_BP 0x5
#define REG_SI 0x6
#define REG_DI 0x7

#define RM_DIRECT 0x6

#define MOD_RM 0x0
#define MOD_RM_OFF8 0x1
#define MOD_RM_OFF16 0x2
#define MOD_R2R 0x3

#define IMOV            0b10001000
#define IMOV_IMM2REG    0b10110000
#define IMOV_IMM2REGMEM 0b11000110
#define IMOV_MEM2ACC    0b10100000
#define IMOV_ACC2MEM    0b10100010

#define IADD            0b00000000
#define IADD_IMM2REGMEM 0b10000000 // Must check bits 2-3-4 from 2nd byte
#define IADD_IMM2ACC    0b00000100

#define ISUB                 0b00101000
#define ISUB_IMM_FROM_REGMEM 0b10000000 // Must check bits 2-3-4 from 2nd byte
#define ISUB_IMM_FROM_ACC    0b00101100

#define ICMP_REGMEM_REG      0b00111000
#define ICMP_IMM_WITH_REGMEM 0b10000000 // Must check bits 2-3-4 from 2nd byte
#define ICMP_IMM_WITH_ACC    0b00111100

#define IJMP_DIRECT_SEG          0b11101001
#define IJMP_DIRECT_SEG_SHORT    0b11101011
#define IJMP_INDIRECT_SEG        0b11111111 // Must check bits 2-3-4 from 2nd byte
#define IJMP_DIRECT_INTER_SEG    0b11101010 
#define IJMP_INDIRECT_INTER_SEG  0b11111111 // Must check bits 2-3-4 from 2nd byte

#define IJE   0b01110100
#define IJZ   0b01110100
#define IJL   0b01111100
#define IJNGE 0b01111100
#define IJLE  0b01111110
#define IJNG  0b01111110
#define IJB   0b01110010
#define IJNAE 0b01110010
#define IJBE  0b01110110
#define IJNA  0b01110110
#define IJP   0b01111010
#define IJPE  0b01111010
#define IJO   0b01110000
#define IJS   0b01111000
#define IJNE  0b01110101
#define IJNZ  0b01110101
#define IJNL  0b01111101
#define IJGE  0b01111101
#define IJNLE 0b01111111
#define IJG   0b01111111
#define IJNB  0b01110011
#define IJAE  0b01110011
#define IJNBE 0b01110111
#define IJA   0b01110111
#define IJNP  0b01111011
#define IJPO  0b01111011
#define IJNO  0b01110001
#define IJNS  0b01111001
#define IJCXZ 0b11100011

#define ILOOP   0b11100010
#define ILOOPZ  0b11100001
#define ILOOPE  0b11100001
#define ILOOPNZ 0b11100000
#define ILOOPNE 0b11100000

#define OUT_BUFSIZE 2048
#define NO_LABELS 64

#define SAME_OPCODE_OPS 0b10000000

#define TEST_OP(OPCODE, AGAINST) ((OPCODE>>(8-opcode_len(AGAINST)))==(AGAINST>>(8-opcode_len(AGAINST))))

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
        case REG_AL: __out = "al"; break;
        case REG_CL: __out = "cl"; break;
        case REG_DL: __out = "dl"; break;
        case REG_BL: __out = "bl"; break;
        case REG_AH: __out = "ah"; break;
        case REG_CH: __out = "ch"; break;
        case REG_DH: __out = "dh"; break;
        case REG_BH: __out = "bh"; break;
    } else switch (code) {
        case REG_AX: __out = "ax"; break;
        case REG_CX: __out = "cx"; break;
        case REG_DX: __out = "dx"; break;
        case REG_BX: __out = "bx"; break;
        case REG_SP: __out = "sp"; break;
        case REG_BP: __out = "bp"; break;
        case REG_SI: __out = "si"; break;
        case REG_DI: __out = "di"; break;
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
    for (u32 i=0; i<NO_LABELS; i++) {
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

u32 decode_jmps(const u8 *buf, const u32 ip,
        const u8 jmp_code, char *out) {
    u32 new_ip = ip;

    switch(jmp_code) {
    case IJMP_DIRECT_SEG:
    case IJMP_DIRECT_SEG_SHORT:
    case IJMP_INDIRECT_SEG:
    // case IJMP_INDIRECT_INTER_SEG:
    case IJMP_DIRECT_INTER_SEG: 
        assert(0 && "Unimplemented!");
        break;
    case IJE:
    case IJL:
    case IJLE:
    case IJB:
    case IJBE:
    case IJP:
    case IJO:
    case IJS:
    case IJNE:
    case IJNL:
    case IJNLE:
    case IJNB:
    case IJNBE:
    case IJNP:
    case IJNO:
    case IJNS:
    case IJCXZ: {
        u32 location = 0;
        i8 displacement_sgn = buf[ip+1];
        u32 displacement = abs((i32)displacement_sgn);
        location = displacement_sgn < 0
            ? ip - displacement
            : ip + displacement;
        if (!check_jmp(location)) {
            jmp_set(location);
        }
        u32 label_idx = 0;
        for (; label_idx<jmp_locations.len
                && jmp_locations.buf[label_idx]!=location;
                label_idx++);
        sprintf(out, "%s", jmp_locations.labels[label_idx]);
        break;
    }
    default: return new_ip;
    }

    return new_ip;
}

u32 decode_loops(const u8 *buf, const u32 ip,
        op_variants_t variant, char *out) {
    return ip;
}

u32 decode_params(const u8 *buf, const u32 ip,
        op_variants_t variant, char *out) {
    u16 hi = (u16)(buf[ip]) << 8;
    u16 lo = (u16)(buf[ip+1]);
    u16 instr = hi | lo;
    const u8 INSTR_HI = (instr >> 8);
    const u8 INSTR_LO = (instr & 0xFF);

    u32 new_ip = ip;
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
            data16 = ((i16)(buf[ip + 2] << 8)) | data16;
            new_ip += 1;
        }

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
            data16 = ((i16)(buf[ip + 2] << 8)) | data16;
            new_ip += 1;
        }

#ifdef DEBUG
       printf("DATA-8: "); __print_bits(data8);
#endif
       sprintf(out, "%s, %d", reg, W ? data16 : data8);
    } else if (variant == OPV_ACC2MEM) {
        const u8 W        = (instr & 0b0000000100000000) >> 8;
        const u16 addr_lo = (instr & 0b0000000011111111);
        u16 addr = addr_lo;
        if (W) {
            const u16 addr_hi = (u16)(buf[ip + 2] << 8);
            addr = addr_hi | addr_lo;
            new_ip += 1;
        }
        sprintf(out, "[%d], ax", addr);
    } else if (variant == OPV_MEM2ACC) {
        const u8 W        = (instr & 0b0000000100000000) >> 8;
        const u16 addr_lo = (instr & 0b0000000011111111);
        const u16 addr_hi = (u16)(buf[ip + 2] << 8);
        u16 addr = addr_lo;
        if (W) {
            addr = addr_hi | addr_lo;
            new_ip += 1;
        }
        sprintf(out, "ax, [%d]", addr);
    } else if (variant == OPV_IMM2REGMEM) {
        const u8 D   = (instr & 0b0000001000000000) >> 9;
        const u8 REG = (instr & 0b0000000000111000) >> 3;
        const u8 W   = (instr & 0b0000000100000000) >> 8;
        const u8 MOD = (instr & 0b0000000011000000) >> 6;
        const u8 RM  = (instr & 0b0000000000000111);

        const u16 OPT_1 = (u16)(buf[ip + 2]);
        const u16 OPT_2 = (u16)(buf[ip + 3]);
        const u16 OPT_3 = (u16)(buf[ip + 4]);
        const u16 OPT_4 = (u16)(buf[ip + 5]);

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
            new_ip += 1;
        }

        // Handle this edge case by skipping to the end
        u8 cmp_decoding = TEST_OP(INSTR_HI, ICMP_IMM_WITH_ACC);
        if (cmp_decoding) 
            goto decode_cmp;

        switch (MOD) {
        case MOD_RM: {
            if (RM == RM_DIRECT) {
                new_ip += 2;
                i16 addr = OPT_2 << 8 | OPT_1;
                data = W ? OPT_4 << 8 | OPT_3 : OPT_3;
                sprintf(rm, "[%d]", addr);
            } else {
                data = W ? OPT_2 << 8 | OPT_1 : OPT_1;
                sprintf(rm, "[%s]", ops[RM]);
            }
            break;
        }
        case MOD_RM_OFF8: {
            i8 addr = OPT_1;
            data = W ? OPT_3 << 8 | OPT_2 : OPT_2;
            char addr_sign = addr < 0 ? '-' : '+';
            sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));
            new_ip += 1; break;
        }
        case MOD_RM_OFF16: {
            i16 addr = OPT_2 << 8 | OPT_1;
            data = W ? OPT_4 << 8 | OPT_3 : OPT_3;
            char addr_sign = addr < 0 ? '-' : '+';
            sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));
            new_ip += 2; break;
        }
        case MOD_R2R: {
            data = W ? OPT_2 << 8 | OPT_1 : OPT_1;
            sprintf(rm, "%s", ops[RM]);
            break;
        }
        }
        sprintf(out, "%s, %s %d", rm, W ? "word" : "byte", data);
        // There's always at least one additinal byte for 8-bit [data]
        new_ip += 1;

decode_cmp:
        sprintf(out, "%s, %d",
                W ? "ax" : "al",
                W ? (((i16)OPT_1) << 8 | INSTR_LO) : (i8)INSTR_LO);
    } else if (variant == OPV_IMM2REGMEM_SOURCEBIT) {
        const u8 S   = (instr & 0b0000001000000000) >> 9;
        const u8 REG = (instr & 0b0000000000111000) >> 3;
        const u8 W   = (instr & 0b0000000100000000) >> 8;
        const u8 MOD = (instr & 0b0000000011000000) >> 6;
        const u8 RM  = (instr & 0b0000000000000111);

        const u16 OPT_1 = (u16)(buf[ip + 2]);
        const u16 OPT_2 = (u16)(buf[ip + 3]);
        const u16 OPT_3 = (u16)(buf[ip + 4]);
        const u16 OPT_4 = (u16)(buf[ip + 5]);

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
            new_ip += 1;
        }

        i16 data = 0;
        switch (MOD) {
        case MOD_RM: {
            if (RM == RM_DIRECT) {
                new_ip += 2;
                i16 addr = OPT_2 << 8 | OPT_1;
                data = is_wide_data ? OPT_4 << 8 | OPT_3 : OPT_3;
                sprintf(rm, "[%d]", addr);
            } else {
                data = is_wide_data ? OPT_2 << 8 | OPT_1 : OPT_1;
                sprintf(rm, "[%s]", ops[RM]);
            }
            break;
        }
        case MOD_RM_OFF8: {
            i8 addr = OPT_1;
            data = is_wide_data ? OPT_3 << 8 | OPT_2 : OPT_2;
            char addr_sign = addr < 0 ? '-' : '+';
            sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));
            new_ip += 1; break;
        }
        case MOD_RM_OFF16: {
            i16 addr = OPT_2 << 8 | OPT_1;
            data = is_wide_data ? OPT_4 << 8 | OPT_3 : OPT_3;
            char addr_sign = addr < 0 ? '-' : '+';
            sprintf(rm, "[%s %c %d]", ops[RM], addr_sign, abs(addr));
            new_ip += 2; break;
        }
        case MOD_R2R: {
            data = is_wide_data ? OPT_2 << 8 | OPT_1 : OPT_1;
            sprintf(rm, "%s", ops[RM]);
            break;
        }
        }

        sprintf(out, "%s, %s %d", rm, W ? "word" : "byte", data);

        // There's always at least one additinal byte for 8-bit [data]
        new_ip += 1;
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
        case MOD_R2R: {
            regcode_to_str(REG, W, reg);
            regcode_to_str(RM, W, rm);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            sprintf(out, "%s, %s", destination, source);
            break;
        }
        
        case MOD_RM: {
            if (RM == RM_DIRECT) {
                u16 hi = (u16)(buf[ip + 3]) << 8;
                u16 lo = (u16)(buf[ip + 2]);
                u16 wide = hi | lo;
                sprintf(rm, "[%d]", wide);
                new_ip += 2;
            } else {
                sprintf(rm, "[%s]", ops[RM]);
            }

            regcode_to_str(REG, W, reg);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            sprintf(out, "%s, %s", destination, source);
            break;
        }

        case MOD_RM_OFF8: {
            const i8 byte = (u16)(buf[ip + 2]);
            if (byte == 0) {
                sprintf(rm, "[%s]", ops[RM]);
            } else {
                char byte_sign = byte < 0 ? '-' : '+';
                sprintf(rm, "[%s %c %d]", ops[RM], byte_sign, abs(byte));
            }
            new_ip += 1;

            regcode_to_str(REG, W, reg);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            sprintf(out, "%s, %s", destination, source);
            break;
        }

        case MOD_RM_OFF16: {
            i16 hi = (u16)(buf[ip + 3]) << 8;
            i16 lo = (u16)(buf[ip + 2]);
            i16 data = hi | lo;
            const i16 wide = (data >> 8) | (data << 8);
            char wide_sign = wide < 0 ? '-' : '+';
            sprintf(rm, "[%s %c %d]", ops[RM], wide_sign, abs(wide));
            new_ip += 2;

            regcode_to_str(REG, W, reg);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            sprintf(out, "%s, %s", destination, source);
            break;
        }
        }

    }

    return new_ip;
}

u32 decode(const u8 *buf, const u32 ip, char *out) {
    u16 hi = (u16)(buf[ip]) << 8;
    u16 lo = (u16)(buf[ip+1]);
    u16 instr = hi | lo;
    const u8 INSTR_HI = (instr >> 8);
    u32 new_ip = ip;

#ifdef DEBUG
    printf("INSTR_HI: "); __print_bits(INSTR_HI);
    printf("TEST_OP(INSTR_HI, IMOV_IMM2REG):  %d\n", TEST_OP(INSTR_HI, IMOV_IMM2REG));
    printf("TEST_OP(INSTR_HI, IMOV_ACC2MEM):  %d\n", TEST_OP(INSTR_HI, IMOV_ACC2MEM));
    printf("TEST_OP(INSTR_HI, IMOV_MEM2ACC):  %d\n", TEST_OP(INSTR_HI, IMOV_MEM2ACC));
    printf("TEST_OP(INSTR_HI, IMOV_IMM2REGM): %d\n", TEST_OP(INSTR_HI, IMOV_IMM2REGMEM));
    printf("TEST_OP(INSTR_HI, IMOV):          %d\n", TEST_OP(INSTR_HI, IMOV));
#endif

    char params[32] = {0};
    op_variants_t matched_variant;
    if (   (matched_variant=OPV_IMM2REG,    TEST_OP(INSTR_HI, IMOV_IMM2REG))
        || (matched_variant=OPV_ACC2MEM,    TEST_OP(INSTR_HI, IMOV_ACC2MEM))
        || (matched_variant=OPV_MEM2ACC,    TEST_OP(INSTR_HI, IMOV_MEM2ACC))
        || (matched_variant=OPV_IMM2REGMEM, TEST_OP(INSTR_HI, IMOV_IMM2REGMEM))
        || (matched_variant=OPV_BASE,       TEST_OP(INSTR_HI, IMOV))
        ) {
#ifdef DEBUG
        printf("[MOV] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_ip = decode_params(buf, ip, matched_variant, params);
        sprintf(out, "mov %s", params);
        return new_ip;
    }

#ifdef DEBUG
    printf("TEST_OP(INSTR_HI, IADD_IMM2ACC):     %d\n", TEST_OP(INSTR_HI, IADD_IMM2ACC));
    printf("TEST_OP(INSTR_HI, IADD_IMM2REGMEM):  %d\n", TEST_OP(INSTR_HI, IADD_IMM2REGMEM));
    printf("TEST_OP(INSTR_HI, IADD):             %d\n", TEST_OP(INSTR_HI, IADD));
#endif

    if (   (matched_variant=OPV_IMM2ACC,    TEST_OP(INSTR_HI, IADD_IMM2ACC))
        || (matched_variant=OPV_BASE,       TEST_OP(INSTR_HI, IADD))
        ) {
#ifdef DEBUG
        printf("[ADD] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_ip = decode_params(buf, ip, matched_variant, params);
        sprintf(out, "add %s", params);
        return new_ip;
    }

#ifdef DEBUG
    printf("TEST_OP(INSTR_HI, ISUB_IMM_FROM_ACC):     %d\n", TEST_OP(INSTR_HI, ISUB_IMM_FROM_ACC));
    printf("TEST_OP(INSTR_HI, ISUB_IMM_FROM_REGMEM):  %d\n", TEST_OP(INSTR_HI, ISUB_IMM_FROM_REGMEM));
    printf("TEST_OP(INSTR_HI, ISUB):                  %d\n", TEST_OP(INSTR_HI, ISUB));
#endif

    if (   (matched_variant=OPV_IMM2ACC,    TEST_OP(INSTR_HI, ISUB_IMM_FROM_ACC))
        || (matched_variant=OPV_BASE,       TEST_OP(INSTR_HI, ISUB))
        ) {
#ifdef DEBUG
        printf("[SUB] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_ip = decode_params(buf, ip, matched_variant, params);
        sprintf(out, "sub %s", params);
        return new_ip;
    }

#ifdef DEBUG
    printf("TEST_OP(INSTR_HI, ICMP_IMM_WITH_ACC):     %d\n", TEST_OP(INSTR_HI, ICMP_IMM_WITH_ACC));
    printf("TEST_OP(INSTR_HI, ICMP_REGMEM_REG):       %d\n", TEST_OP(INSTR_HI, ICMP_REGMEM_REG));
    printf("TEST_OP(INSTR_HI, ICMP_IMM_WITH_REGMEM):  %d\n", TEST_OP(INSTR_HI, ICMP_IMM_WITH_REGMEM));
#endif

    const u8 bits_432 = (buf[ip+1] >> 3) & 0b111;

    if (   (matched_variant=OPV_IMM2REGMEM, TEST_OP(INSTR_HI, ICMP_IMM_WITH_ACC))
        || (matched_variant=OPV_BASE,       TEST_OP(INSTR_HI, ICMP_REGMEM_REG))
        ) {
#ifdef DEBUG
        printf("[CMP] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        new_ip = decode_params(buf, ip, matched_variant, params);
        sprintf(out, "cmp %s", params);
        return new_ip;
    }

    u8 matched_jmp_code;
    if (   (matched_jmp_code=IJMP_DIRECT_SEG,           TEST_OP(INSTR_HI, IJMP_DIRECT_SEG))
        || (matched_jmp_code=IJMP_DIRECT_SEG_SHORT,     TEST_OP(INSTR_HI, IJMP_DIRECT_SEG_SHORT))
        || (matched_jmp_code=IJMP_INDIRECT_SEG,         TEST_OP(INSTR_HI, IJMP_INDIRECT_SEG))
        || (matched_jmp_code=IJMP_DIRECT_INTER_SEG,     TEST_OP(INSTR_HI, IJMP_DIRECT_INTER_SEG))
        || (matched_jmp_code=IJE,                       TEST_OP(INSTR_HI, IJE))
        || (matched_jmp_code=IJL,                       TEST_OP(INSTR_HI, IJL))
        || (matched_jmp_code=IJLE,                      TEST_OP(INSTR_HI, IJLE))
        || (matched_jmp_code=IJB,                       TEST_OP(INSTR_HI, IJB))
        || (matched_jmp_code=IJBE,                      TEST_OP(INSTR_HI, IJBE))
        || (matched_jmp_code=IJP,                       TEST_OP(INSTR_HI, IJP))
        || (matched_jmp_code=IJO,                       TEST_OP(INSTR_HI, IJO))
        || (matched_jmp_code=IJS,                       TEST_OP(INSTR_HI, IJS))
        || (matched_jmp_code=IJNE,                      TEST_OP(INSTR_HI, IJNE))
        || (matched_jmp_code=IJNL,                      TEST_OP(INSTR_HI, IJNL))
        || (matched_jmp_code=IJNLE,                     TEST_OP(INSTR_HI, IJNLE))
        || (matched_jmp_code=IJNB,                      TEST_OP(INSTR_HI, IJNB))
        || (matched_jmp_code=IJNBE,                     TEST_OP(INSTR_HI, IJNBE))
        || (matched_jmp_code=IJNP,                      TEST_OP(INSTR_HI, IJNP))
        || (matched_jmp_code=IJNO,                      TEST_OP(INSTR_HI, IJNO))
        || (matched_jmp_code=IJNS,                      TEST_OP(INSTR_HI, IJNS))
        || (matched_jmp_code=IJCXZ,                     TEST_OP(INSTR_HI, IJCXZ))) {
        // decode jumps
#ifdef DEBUG
        printf("[JUMPS] MATCHED_VARIANT: %s\n", opv_str(matched_variant));
#endif
        char params[32];
        const char* instr_str = instr2str(INSTR_HI, NONE);
        assert((instr_str[0] == 'j' || instr_str[0] == 'n')
                && "instruction name must start with either 'j' or 'n'");
        new_ip = decode_jmps(buf, ip, matched_jmp_code, params);
        sprintf(out, "%s %s", instr2str(matched_jmp_code, 0), params);

        return new_ip;
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
        new_ip = decode_loops(buf, ip, matched_variant, params);

        return new_ip;
    }

    // Check for opcodes with the same value (other flags must differ)
    if (   TEST_OP(INSTR_HI, IADD_IMM2REGMEM)
        || TEST_OP(INSTR_HI, ISUB_IMM_FROM_REGMEM)
        || TEST_OP(INSTR_HI, ICMP_IMM_WITH_REGMEM)) {
        new_ip = decode_params(buf, ip, OPV_IMM2REGMEM_SOURCEBIT, params);
        const u8 bits_432 = (buf[ip+1] >> 3) & 0b111;

#ifdef DEBUG
        printf("[CONFLICT_CASE]: "); __print_bits(bits_432);
#endif

        switch (bits_432) {
        case 0b000: // ADD
#ifdef DEBUG
        printf("[ADD] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            sprintf(out, "add %s", params);
            break;
        case 0b101: // SUB
#ifdef DEBUG
        printf("[SUB] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            sprintf(out, "sub %s", params);
            break;
        case 0b111: // CMP 
#ifdef DEBUG
        printf("[CMP] (CONFLICT CASE)\n"); __print_bits(bits_432);
#endif
            sprintf(out, "cmp %s", params);
            break;
        }

        return new_ip;
    }

    assert(0 && "No decode matched");
    return -1;
}

int main(int argc, const char **argv) {
    if (argc < 2)  {
        goto no_arg_error;
    }

    const char* filename = argv[1];
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        goto bad_path_error;
    }

    fseek(file, 0, SEEK_END);
    u32 file_size = ftell(file);
    rewind(file);

    u8 *buf = (u8*)malloc(file_size);
    u32 nread = 0;
    u32 bytes_read = 0;
    while ((nread = fread(buf, sizeof(u8), file_size, file)) > 0) {
        bytes_read += nread;
    }
    init_jmp(bytes_read);
    if (ferror(file)) {
        goto read_error;
    }
    fclose(file);

    char* out[OUT_BUFSIZE];
    for (u32 i=0; i<OUT_BUFSIZE; i++) {
        out[i] = malloc(sizeof(char) * 64);
        memset(out[i], 0, sizeof(char) * 64);
    }

    u32 out_cursor = 0;
    strcat(out[out_cursor], "bits 16\n\n");
    out_cursor += 1;

    u32 *ip_to_cursor = malloc(sizeof(u32) * file_size);
    memset(ip_to_cursor, 0, sizeof(u32) * file_size);

    for (u32 ip=0; ip<file_size; ip+=2) {
        char line[64];

        ip = decode(buf, ip, line);

        // Keep tracks of ip -> line
        ip_to_cursor[ip] = out_cursor;

        assert(strlen(line) != 0);
        strcat(line, "\n");
        strcpy(out[out_cursor++], line);
#ifdef DEBUG
        printf("\n==================\nLINE: %s==================\n", line);
#endif
    }

    for (u32 i=0; i<OUT_BUFSIZE; i++) {
        fprintf(stdout, "%s", out[i]);
        for (u32 label_location=0;
             label_location<jmp_locations.len; 
             label_location++) {
            if (ip_to_cursor[jmp_locations.buf[label_location]] == i) {
                fprintf(stdout, "%s\n", jmp_locations.labels[label_location]);
            }
        }
    }

    return 0;

no_arg_error:
    fprintf(stderr, "[NO_ARG_ERR]: no file arg provided\n");
    return -1;
bad_path_error: 
    fprintf(stderr, "[BAD_PATH_ERR]: path %s might not exist\n", filename);
    return -1;
read_error:
    fprintf(stderr, "[READ_FILE_ERR]: error reading file!\n");
    fclose(file);
    return -1;
}
