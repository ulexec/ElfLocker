# ElfLocked
PoC multi-layer Protector for ELF32 binaries

This protector was an old project standing as a private repository for various years now in my github account, and based that encountering ELF32 ET_EXEC binaries are currently outdated in a sense, I decided to make it public.

This protector contains two layers of abstraction implementing various anti-debugging/anti-analysis techniques ranging from:
* Anti Ptrace
* Breakpoint traps
* Self modifying code
* Anti LD_PRELOAD
* Parent process checks
* Various Control-Flow obfuscation techniques applied on different sections:
  * Exception manipulation
  * Hardware Breakpoint manipulation
  * Control-Flow flattening

The embedded binary is also subject to a base-relocation to make the unpacking process a bit harder. This today is a default for PIE binaries, but at the time it was not trivial to rebase an ET_EXEC ELF binary. 
Leaving this project here for historic purposes and hopefully to bring some light into ELF Packers/Protectors. 
SPOILER: This project is from 2016! coding style is terrible as it was a very old project, you have been warned :D
