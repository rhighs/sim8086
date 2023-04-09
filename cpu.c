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

#define IMOV 0b00100010

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

void instrcode_to_str(const u8 code, char *out) {
    char *__out;
    switch (code) {
        case IMOV:
            __out = "mov";
            break;
    }
    strcpy(out, __out);
}

void decode(const u16 instr, char *out) {
    const u8 OP  = (instr & 0b1111110000000000) >> 10;
    const u8 D   = (instr & 0b0000001000000000) >> 9;
    const u8 W   = (instr & 0b0000000100000000) >> 8;
    const u8 MOD = (instr & 0b0000000011000000) >> 6;
    const u8 REG = (instr & 0b0000000000111000) >> 3;
    const u8 RM  = (instr & 0b0000000000000111);

    char op[10], reg[10], rm[10];


    instrcode_to_str(OP, op);
    regcode_to_str(REG, W, reg);
    regcode_to_str(RM, W, rm);

#ifdef DEBUG
    printf("\n");
    printf("MOD:"); __print_bits(MOD);
    printf("%s:", op); __print_bits(OP);
    printf("%s:", reg); __print_bits(REG);
    printf("%s:", rm); __print_bits(RM);
    printf("\n");
#endif

    const char* source = D ? rm : reg;
    const char* destination = D ? reg : rm;
    sprintf(out, "%s %s, %s", op, destination, source);
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

        decode(instr_line, line);
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
