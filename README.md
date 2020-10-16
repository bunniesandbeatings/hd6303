# HD6303 Plugin


Hitachi HD6303 plugin for [Binary Ninja](https://binary.ninja/)

Should also work fine with Motorola 6803/01 and HD6301

Includes a default Binary View that will detect the [Roland TR 707](https://en.wikipedia.org/wiki/Roland_TR-707) 
Program rom (based on the first 6 bytes) to make it easier to RE the 707.

If you're hacking roms in Synths, take a look at: 
  * [Kris Sekula's Eprom Emulator](https://github.com/Kris-Sekula/EPROM-EMU-NG) 

## Todo

- [x] Implement entire 6303 Instruction Set - feels 'Mostly' correct
- [x] Implement LLIL methods - Wouldn't trust it with my life.
- [ ] Map 707 Ram and Memory Registers
    - [x] Enough to be useful
    - [ ] all of it
- [ ] Decipher the 707 code and find out just how much I got wrong
- [ ] Hack a 707 and see if this even worked.
- [X] Fix documentation/naming wrt HD6303.

