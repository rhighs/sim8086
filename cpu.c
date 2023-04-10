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

#define IMOV            0b00100010
#define IMOV_IMM2REGMEM 0b00110000
#define IMOV_IMM2REG    0b00101100

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

u8 decode_mov(const u16 instr, const u16 opts, char *out) {
    const u8 OP  = (instr & 0b1111110000000000) >> 10;
    const u8 D   = (instr & 0b0000001000000000) >> 9;
    const u8 W   = (instr & 0b0000000100000000) >> 8;
    const u8 MOD = (instr & 0b0000000011000000) >> 6;
    const u8 REG = (instr & 0b0000000000111000) >> 3;
    const u8 RM  = (instr & 0b0000000000000111);

    #ifdef DEBUG
        printf("\n");
        printf("OP:  "); __print_bits(OP);
        printf("D:   "); __print_bits(D);
        printf("W:   "); __print_bits(W);
        printf("MOD: "); __print_bits(MOD);
        printf("REG: "); __print_bits(REG);
        printf("RM:  "); __print_bits(RM);
        printf("\n");
    #endif

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

    u8 bytes_read = 0;
    char reg[32] = { 0 }, rm[32] = { 0 };

    // Case immediate to register mov
    if (TEST_OP(OP, IMOV_IMM2REG)) {
        const u8 W = (instr & 0b0000100000000000) >> 11;
        const u8 REG = (instr & 0b000001110000000) >> 7;
        regcode_to_str(REG, W, reg);

        u16 data = 0;
        if (W) {
            data = (opts << 8) | (opts >> 8);
            bytes_read = 1;
        } else {
            data = opts >> 8;
        }

        sprintf(out, "mov %s, %d", reg, data);
    } else if (TEST_OP(OP, IMOV)) {
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
                u16 wide = opts;
                sprintf(rm, "[+%d]", wide);
                bytes_read = 2;
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
            const u8 byte = opts >> 8;
            if (byte == 0) {
                sprintf(rm, "[%s]", ops[RM], byte);
            } else {
                sprintf(rm, "[%s+%d]", ops[RM], byte);
            }
            bytes_read = 1;

            regcode_to_str(REG, W, reg);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            sprintf(out, "mov %s, %s", destination, source);
            break;
        }

        case MOD_RM_OFF16: {
            const u16 wide = opts;
            sprintf(rm, "[%s+%d]", ops[RM], wide);
            bytes_read = 2;

            regcode_to_str(REG, W, reg);

            const char* source = D ? rm : reg;
            const char* destination = D ? reg : rm;
            sprintf(out, "mov %s, %s", destination, source);
            break;
        }
        }
    }

    return bytes_read;
}

u8 decode(const u16 instr, const u16 opts, char *out) {
    const u8 OP  = (instr & 0b1111110000000000) >> 10;
    if (TEST_OP(OP, IMOV_IMM2REG)
        || TEST_OP(OP, IMOV)) {
        return decode_mov(instr, opts, out);
    }

    return 0;
}

#define OUT_BUFSIZE 2048

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

    for (u32 i=0; i<file_size; i+=2) {
        char line[32];
        u16 hi = (u16)(buf[i]) << 8;
        u16 lo = (u16)(buf[i+1]);
        u16 instr_line = hi | lo;

        if (i < file_size - 2) {
            u16 hi = (u16)(buf[i + 2]) << 8;
            u16 lo = (u16)(buf[i + 3]);
            u16 opts = hi | lo;
            u8 nbytes_read = decode(instr_line, opts, line);
            i += nbytes_read;
        } else if (i < file_size - 1) {
            u16 opts = buf[i + 2];
            u8 nbytes_read = decode(instr_line, opts, line);
        } else {
            u8 _ = decode(instr_line, 0, line);
        }

        assert(strlen(line) != 0);
        strcat(line, "\n");
        strcat(out, line);
    }

    fprintf(stdout, out);
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
