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

#define OUT_BUFSIZE 2048

#define TEST_OP(OPCODE, AGAINST) ((OPCODE&AGAINST)==AGAINST)

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

u32 decode_mov(const u8 *buf, const u32 ip, char *out) {
    u16 hi = (u16)(buf[ip]) << 8;
    u16 lo = (u16)(buf[ip+1]);
    u16 instr = hi | lo;
    const u8 INSTR_LO = (instr >> 8);

    u32 new_ip = ip;
    char reg[32] = { 0 }, rm[32] = { 0 };

    // Case immediate to register mov
    if (TEST_OP(INSTR_LO, IMOV_IMM2REG)) {
        const u8 W = (instr & 0b0000100000000000) >> 11;
        const u8 REG = (instr & 0b0000011100000000) >> 8;
        regcode_to_str(REG, W, reg);

#ifdef DEBUG
        printf("\n");
        printf("INSTR_LO: "); __print_bits(INSTR_LO);
        printf("W:        "); __print_bits(W);
        printf("REG:      "); __print_bits(REG);
        printf("\n");
#endif

        u8 data8   = instr & 0b0000000011111111;
        u16 data16 = instr & 0b0000000011111111;
        if (W) {
            data16 = ((u16)(buf[ip + 2] << 8)) | data16;
            new_ip += 1;
        }

#ifdef DEBUG
       printf("DATA-8: "); __print_bits(data8);
#endif

        sprintf(out, "mov %s, %d", reg, W ? data16 : data8);
    } else if (TEST_OP(INSTR_LO, IMOV_MEM2ACC)) {
        const u8 W        = (instr & 0b0000000100000000) >> 8;
        const u16 addr_lo = (instr & 0b0000000011111111);
        const u16 addr_hi = (u16)(buf[ip + 2] << 8);
        u16 addr = addr_lo;
        if (W) {
            addr = addr_hi | addr_lo;
            new_ip += 1;
        }
        sprintf(out, "mov ax, [%d]", addr);
    } else if (TEST_OP(INSTR_LO, IMOV_ACC2MEM)) {
        const u8 W        = (instr & 0b0000000100000000) >> 8;
        const u16 addr_lo = (instr & 0b0000000011111111);
        u16 addr = addr_lo;
        if (W) {
            const u16 addr_hi = (u16)(buf[ip + 2] << 8);
            addr = addr_hi | addr_lo;
            new_ip += 1;
        }
        sprintf(out, "mov [%d], ax", addr);
    } else if (TEST_OP(INSTR_LO, IMOV_IMM2REGMEM)) {
        const u8 D   = (instr & 0b0000001000000000) >> 9; assert(D == 1);
        const u8 REG = (instr & 0b0000000000111000) >> 3; assert(REG == 0);
        const u8 W   = (instr & 0b0000000100000000) >> 8;
        const u8 MOD = (instr & 0b0000000011000000) >> 6;
        const u8 RM  = (instr & 0b0000000000000111);

        const u16 OPT_1 = (u16)(buf[ip + 2]);
        const u16 OPT_2 = (u16)(buf[ip + 3]);
        const u16 OPT_3 = (u16)(buf[ip + 4]);
        const u16 OPT_4 = (u16)(buf[ip + 5]);

#ifdef DEBUG
        printf("\n");
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

        u16 data = 0;
        switch (MOD) {
        case MOD_RM: {
            data = W ? OPT_2 << 8 | OPT_1 : OPT_1;
            sprintf(rm, "%s", ops[RM]);
            break;
        }
        case MOD_RM_OFF8: {
            i8 addr = OPT_1;
            data = W ? OPT_3 << 8 | OPT_2 : OPT_2;
            char addr_sign = addr < 0 ? '-' : '+';
            sprintf(rm, "%s %c %d", ops[RM], addr_sign, abs(addr));
            new_ip += 1; break;
        }
        case MOD_RM_OFF16: {
            i16 addr = OPT_2 << 8 | OPT_1;
            data = W ? OPT_4 << 8 | OPT_3 : OPT_3;
            char addr_sign = addr < 0 ? '-' : '+';
            sprintf(rm, "%s %c %d", ops[RM], addr_sign, abs(addr));
            new_ip += 2; break;
        }
        }

        if (W) {
            // One more byte of data
            new_ip += 1;
        }
        __print_bits(data);

        sprintf(out, "mov [%s], %s %d", rm, W ? "word" : "byte", data);

        // There's always at least one additinal byte for 8-bit [data]
        new_ip += 1;
    } else if (TEST_OP(INSTR_LO, IMOV)) {
        const u8 D   = (instr & 0b0000001000000000) >> 9;
        const u8 W   = (instr & 0b0000000100000000) >> 8;
        const u8 MOD = (instr & 0b0000000011000000) >> 6;
        const u8 REG = (instr & 0b0000000000111000) >> 3;
        const u8 RM  = (instr & 0b0000000000000111);

#ifdef DEBUG
        printf("\n");
        printf("INSTR_LO: "); __print_bits(INSTR_LO);
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
            sprintf(out, "mov %s, %s", destination, source);
            break;
        }
        
        case MOD_RM: {
            if (RM == RM_DIRECT) {
                u16 hi = (u16)(buf[ip + 2]) << 8;
                u16 lo = (u16)(buf[ip + 3]);
                u16 wide = hi | lo;
                sprintf(rm, "[%d]", wide);
                new_ip += 2;
            } else {
                sprintf(rm, "[%s]", ops[RM]);
            }

            regcode_to_str(REG, W, reg);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            sprintf(out, "mov %s, %s", destination, source);
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
            sprintf(out, "mov %s, %s", destination, source);
            break;
        }

        case MOD_RM_OFF16: {
            u16 hi = (u16)(buf[ip + 2]) << 8;
            u16 lo = (u16)(buf[ip + 3]);
            u16 data = hi | lo;
            const i16 wide = (data >> 8) | (data << 8);
            char wide_sign = wide < 0 ? '-' : '+';
            sprintf(rm, "[%s %c %d]", ops[RM], wide_sign, abs(wide));
            new_ip += 2;

            regcode_to_str(REG, W, reg);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            sprintf(out, "mov %s, %s", destination, source);
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
    const u8 INSTR_LO = (instr >> 8);

#ifdef DEBUG
    printf("[MOV_MATCH] INSTR_LO: "); __print_bits(INSTR_LO);
#endif

    if (TEST_OP(INSTR_LO, IMOV_IMM2REG)
        || TEST_OP(INSTR_LO, IMOV)
        || TEST_OP(INSTR_LO, IMOV_ACC2MEM)
        || TEST_OP(INSTR_LO, IMOV_MEM2ACC)
        || TEST_OP(INSTR_LO, IMOV_IMM2REGMEM)) {
        return decode_mov(buf, ip, out);
    }

    assert(0 && "No mov decode matched");
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
    if (ferror(file)) {
        goto read_error;
    }
    fclose(file);

    char out[OUT_BUFSIZE];
    memset(out, 0, OUT_BUFSIZE);
    strcat(out, "bits 16\n\n");

    for (u32 ip=0; ip<file_size; ip+=2) {
        char line[32];

        ip = decode(buf, ip, line);

        assert(strlen(line) != 0);
        strcat(line, "\n");
        strcat(out, line);
    }

    fprintf(stdout, "%s", out);
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
