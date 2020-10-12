# m6803 Plugin

Motorola 6803 plugin for [Binary Ninja](https://binary.ninja/)

**WARNING about opcodes** I just discovered there are more opcodes in the HD6303 than the m6803. I'm targeting the TR 707's HD6303 so that's what's in here. I'll clean up the naming and documentation at some future date. 

Includes a default Binary View that will detect the [Roland TR 707](https://en.wikipedia.org/wiki/Roland_TR-707) Program rom (based on the first 6 bytes) to make it easier to RE the 707.

**This still doesn't do anything at all useful**

## Todo

- [x] Implement entire 6803 Instruction Set
- [x] Implement LLIL methods
- [ ] Map 707 Ram and Memory Registers
- [ ] Hack a 707 and see if this even worked.
- [ ] Fix documentation/naming wrt HD8303.

