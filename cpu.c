#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

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

void regcode_to_str(const u8 code, const u8 w_bit, char *out) {
    char *__out;
    if (w_bit) switch (code) {
        case REG_AL: __out = "al"; break;
        case REG_CL: __out = "cl"; break;
        case REG_DL: __out = "dl"; break;
        case REG_BL: __out = "bl"; break;
        case REG_AH: __out = "ah"; break;
        case REG_CH: __out = "ch"; break;
        case REG_DH: __out = "dh"; break;
        case REG_BH: __out = "bh"; break;
    }
    if (!w_bit) switch (code) {
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

void instrcode_to_str(const u8 code, char *out) {
}

void decode(const u16 instr, char *out) {
    const u8 OP  = (instr & 0b1111110000000000) >> 0x10;
    const u8 D   = (instr & 0b0000001000000000) >> 0x9;
    const u8 W   = (instr & 0b0000000100000000) >> 0x7;
    const u8 MOD = (instr & 0b0000000011000000) >> 0x6;
    const u8 REG = (instr & 0b0000000000111000) >> 0x3;
    const u8 RM  = (instr & 0b0000000000000111);

    char reg[2];
    regcode_to_str(REG, W, reg);
    char rm[2];
    regcode_to_str(RM, W, reg);
    char op[3];
    instrcode_to_str(OP, op);
    sprintf(out, "%s %s,%s", op, reg, rm);
}

int main(int argc, const char **argv) {
}
