#ifndef OPCODE_H
#define OPCODE_H

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
#define IJMP_DIRECT_INTER_SEG    0b11101010 
#define IJMP_INDIRECT_SEG        0b11111111 // Must check bits 2-3-4 from 2nd byte
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
#define SAME_OPCODE_OPS 0b10000000

#define INOT  0b11110110

#define ISAL  0b11010000
#define ISHL  0b11010000
#define ISAR  0b11010000
#define ISHR  0b11010000

#define IROL  0b11010000
#define IROR  0b11010000

#define IAND_REGMEM2REG  0b00100000
#define IAND_IMM2REGMEM  0b10000000
#define IAND_IMM2ACC     0b00100100

#define ITEST_REGMEM2REG  0b00010000
#define ITEST_IMM2REGMEM  0b11110110
#define ITEST_IMM2ACC     0b10101000

#define IOR_REGMEM2REG  0b00100000
#define IOR_IMM2REGMEM  0b10000000
#define IOR_IMM2ACC     0b00100100

#define IXOR_REGMEM2REG  0b00110000
#define IXOR_IMM2REGMEM  0b10000000
#define IXOR_IMM2ACC     0b00110100

#define IMUL  0b11110110
#define IIMUL 0b11110110
#define IDIV  0b11110110
#define IIDIV 0b11110110

#define IPOP            0b01011000
#define IPOP_REGMEM     0b10001111

#define IPUSH_REGMEM    0b11111111
#define IPUSH           0b01011000

typedef enum {
    OP_MOV,
    OP_MOV_IMM2REG,
    OP_MOV_IMM2REGMEM,
    OP_MOV_MEM2ACC,
    OP_MOV_ACC2MEM,
    OP_ADD,
    OP_ADD_IMM2REGMEM,
    OP_ADD_IMM2ACC,
    OP_SUB,
    OP_SUB_IMM_FROM_REGMEM,
    OP_SUB_IMM_FROM_ACC,
    OP_CMP_REGMEM_REG,
    OP_CMP_IMM_WITH_REGMEM,
    OP_CMP_IMM_WITH_ACC,
    OP_JMP_DIRECT_SEG,
    OP_JMP_DIRECT_SEG_SHORT,
    OP_JMP_INDIRECT_SEG,
    OP_JMP_DIRECT_INTER_SEG,
    OP_JMP_INDIRECT_INTER_SEG,
    OP_JE,
    OP_JZ,
    OP_JL,
    OP_JNGE,
    OP_JLE,
    OP_JNG,
    OP_JB,
    OP_JNAE,
    OP_JBE,
    OP_JNA,
    OP_JP,
    OP_JPE,
    OP_JO,
    OP_JS,
    OP_JNE,
    OP_JNZ,
    OP_JNL,
    OP_JGE,
    OP_JNLE,
    OP_JG,
    OP_JNB,
    OP_JAE,
    OP_JNBE,
    OP_JA,
    OP_JNP,
    OP_JPO,
    OP_JNO,
    OP_JNS,
    OP_JCXZ,
    OP_LOOP,
    OP_LOOPZ,
    OP_LOOPE,
    OP_LOOPNZ,
    OP_LOOPNE,
    OP_NOOP,
    OP_NOT,
    OP_SAL,
    OP_SHL,
    OP_SAR,
    OP_SHR,
    OP_ROL,
    OP_ROR,
    OP_AND_REGMEM2REG,
    OP_AND_IMM2REGMEM,
    OP_AND_IMM2ACC,
    OP_TEST_REGMEM2REG,
    OP_TEST_IMM2REGMEM,
    OP_TEST_IMM2ACC,
    OP_OR_REGMEM2REG,
    OP_OR_IMM2REGMEM,
    OP_OR_IMM2ACC,
    OP_XOR_REGMEM2REG,
    OP_XOR_IMM2REGMEM,
    OP_XOR_IMM2ACC,
    OP_MUL,
    OP_IMUL,
    OP_DIV,
    OP_IDIV,
    OP_POP,
    OP_POP_REGMEM,
    OP_PUSH,
    OP_PUSH_REGMEM,
    OPS_COUNT,
} op_code_t;

#endif
