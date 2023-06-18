## Intel 8086 emulator

The 8086 is a 16-bit processor chip designed by Intel in the mid 70'.
The processor is equiped with eight 16-bit wide data registers AX, BX, CX, DX,
SI, DI, BP, SP primarily used by arithemetical and operational instructions
(Other registers such as segment registers  and status registers are also
present). A stack pointer register (SP) is used in combination of a stack
segment pointer to keep track of the 64 KB long stack available in the 8086.

The emulator features a built-in decoder that allows disassembling of machine 
code data into a valid 8086 assembly language. Regarding simulation
capabilities it is able to replicate execution of **almost** any type of x8086
program as long as it fits the official instruction set as per
[8086 reference specs](https://edge.edx.org\
/c4x/BITSPilani/EEE231/asset/8086_family_Users_Manual_1_.pdf).

Bear in mind that being a recreational project and WIP, some instructions
might still be unimplemented and it probably won't change in the short
period unless strictly needed. This emulator is aimed at covering the most
important feature set of the 8086 and it won't bother too much on getting a 1:1
implementation.

### Building and running

```bash
$ make build
$ ./sim8086 <8086_machine_code>
```
or 
```bash
$ make debug
$ ./sim8086 <8086_machine_code> 
```
if you want to see debugging logs

Using the option `--mem-dump <optional_file_name> (default stdout)` you can dump
the cpu raw memory content into a file:
```
$ ./sim8086 <8086_machine_code> --mem-dump dump.data
```
