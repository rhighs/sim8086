## Intel 8086 emulator

The 8086 is a 16-bit processor chip designed by Intel in the mid 70'. The processor
is equiped with eight 16-bit wide data registers AX, BX, CX, DX, SI, DI, BP, SP primarily
used by arithemetical and operational instructions (Other registers such as segment registers 
and status registers are also present). A stack pointer register (SP) is used in combination of a
stack segment pointer to keep track of the 64 KB long stack available in the 8086.

The emulator features a built-in decoder that allows disassembling of machine code data
into a valid 8086 assembly language file (.asm). Regarding simulation capabilities it
is able to replicate execution of almost any type of x8086 program as long as it fits
the official instruction set as per [8086 reference specs](https://edge.edx.org/c4x/BITSPilani/EEE231/asset/8086_family_Users_Manual_1_.pdf).

### Building and running

```bash
$ make build
$ ./decoder samples/listing_<listing_prefix>
```
or 
```
$ make debug
$ ./decoder samples/listing_<listing_prefix>
```
if you want to see debugging logs

