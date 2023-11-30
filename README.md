# q800-rom-hacking
Disassembling and annotating the Q800 ROM in Ghidra (Quadra/Centris 610,650,800 checksum F1ACDA13)

## scripts/

Some assorted (and very unfinished) scripts for Ghidra.

### AnnotateRomTables.py

Based on [unirom](https://github.com/rb6502/unirom) by rb6502, read the machine support tables from the ROM and annotate all the machine support tables and their entries.

### FindRomWrites.py

In order to reverse engineer the early boot process, there's a second copy of the ROM mapped at 0x00000000 (as well as the usual 0x40000000). When the machine first switches on, ROM is mapped to the zero address as well to allow the m68k to load SP from 0x0:4 and PC from 0x4:8. This will remap all the reads/writes in this space into RAM, which they are more likely to be.

![Ghidra memory map window](pic/memory_map.png)

### ImportLomemGlobals.py 

A modified version of the low memory globals list from the [Mac Almanac II](http://www.mac.linux-m68k.org/devel/macalmanac.php) is included as `lomem_globals.txt`. This script imports it, setting labels and data types as specified in the file.

### ImportSymbolsShifted.py

A modified version of `ImportSymbolsScript.py` from Ghidra which allows you to import the symbols with a prefix, put them at a memory offset, or in another address space. Used with cy384's [68k-mac-rom-maps](https://github.com/cy384/68k-mac-rom-maps) - converted tables of ROM symbols from MPW 3.5. 

### RemoveUndefinedTypes.py

After running FindRomWrites.py, you may be left with a bunch of `undefined1`, `undefined2` and `undefined4` data declarations with no references to them. This will remove them all.


## Useful other repos

- [https://github.com/cy384/68k-mac-rom-maps](https://github.com/cy384/68k-mac-rom-maps)
    - Converted tables of ROM symbols from MPW 3.5.
    - Partial A-Trap instruction decoding

- [unirom](https://github.com/rb6502/unirom)
    - C++ code to decode machine support tables from ROM

- [https://github.com/elliotnunn/supermario](https://github.com/elliotnunn/supermario)
    - Patched version of the `SuperMario` (codename for System 7.1) leaked source.

## ... the ghidra project?

It'll be posted when it's less of a mess...