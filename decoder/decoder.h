#ifndef DECODER_H
#define DECODER_H

#include <stdint.h>

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

typedef enum {
    MOV,
    MOV_IMM2REG,
    MOV_IMM2REGMEM,
    MOV_MEM2ACC,
    MOV_ACC2MEM,
    ADD,
    ADD_IMM2REGMEM,
    ADD_IMM2ACC,
    SUB,
    SUB_IMM_FROM_REGMEM,
    SUB_IMM_FROM_ACC,
    CMP_REGMEM_REG,
    CMP_IMM_WITH_REGMEM,
    CMP_IMM_WITH_ACC,
    JMP_DIRECT_SEG,
    JMP_DIRECT_SEG_SHORT,
    JMP_INDIRECT_SEG,
    JMP_DIRECT_INTER_SEG,
    JMP_INDIRECT_INTER_SEG,
    JE,
    JZ,
    JL,
    JNGE,
    JLE,
    JNG,
    JB,
    JNAE,
    JBE,
    JNA,
    JP,
    JPE,
    JO,
    JS,
    JNE,
    JNZ,
    JNL,
    JGE,
    JNLE,
    JG,
    JNB,
    JAE,
    JNBE,
    JA,
    JNP,
    JPO,
    JNO,
    JNS,
    JCXZ,
    LOOP,
    LOOPZ,
    LOOPE,
    LOOPNZ,
    LOOPNE,
    NOOP,
} op_code_t;

/**
 * Defines operand types assigned by the decoder
 */
typedef enum {
    OperandRegister,
    OperandImmediate
} operand_register_type_t;

typedef struct {
    operand_register_type_t type;
    union {
        struct { u16 value; } imm;
        struct { u8 index; } reg;
    };
} operand_t;

/**
 * A simple decode unit
 */
typedef struct {
    operand_t **operands;
    u8 is_wide;
    u8 op_code;
} instruction_t;

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
    u8 *buf;
    u32 buflen;

    u32 *cursor2pc;
    u32 pc;
} decoder_context_t;

u32 init_from_file(decoder_context_t *context, const char *filepath);

u32 jmp_loc2label(const decoder_context_t *context, char *dst,
        const u32 location);

u32 decode(decoder_context_t *context, instruction_t *decoded_construct,
        const u32 cursor, char *out);

u32 decode_params(decoder_context_t *context, instruction_t *decoded_construct,
        op_variants_t variant, const u32 cursor, char *out);

u32 decode_jmps(decoder_context_t *context, instruction_t *decoded_construct,
        const u32 cursor, const u8 jmp_code, char *out);

#endif
