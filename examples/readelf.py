#! /usr/bin/env python
import sys, os

if sys.version_info[0] == 2 and sys.version_info[1] < 5:
    sys.stderr.write("python version older than 2.5 is not supported\n")
    exit(1)

sys.path.insert(1, os.path.abspath(sys.path[0]+'/..'))
from elfesteem import elf_init, elf

import subprocess
def popen_read_out_err(cmd):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    p.stdin.close()
    return p.stdout.read() + p.stderr.read()

import re
def get_readelf_version():
    readelf_v = popen_read_out_err(["readelf", "--version"])
    if type(readelf_v) != str: readelf_v = str(readelf_v, encoding='latin1')
    r = re.search(r'GNU readelf .* (\d+\.\d+)', readelf_v)
    if r:
        sys.stderr.write("readelf version %s\n" % float(r.groups()[0]))
        return float(r.groups()[0])
    else:
        sys.stderr.write("Could not detect readelf version\n")
        sys.stderr.write(readelf_v)
        return None

et_strings = {
    elf.ET_REL: 'REL (Relocatable file)',
    elf.ET_EXEC: 'EXEC (Executable file)',
    elf.ET_DYN: 'DYN (Shared object file)',
    elf.ET_CORE: 'CORE (Core file)',
    }
def expand_code(table, val):
    if val in table: return table[val]
    return '<unknown>: %#x' % val

def is_pie(e):
    # binutils 2.37
    # 2021-06-15 https://github.com/bminor/binutils-gdb/commit/93df3340fd5ad32f784214fc125de71811da72ff
    for i, sh in enumerate(e.sh):
        if sh.sh.type != elf.SHT_DYNAMIC:
            continue
        if e.wsize == 32:
            dyntab = sh.dyntab[:-2]
        elif e.wsize == 64:
            dyntab = sh.dyntab[:-1]
        for d in dyntab:
            if d.type == elf.DT_FLAGS_1 and d.name & elf.DF_1_PIE:
                return True
    return False

def display_headers(e):
    print("ELF Header:")
    import struct
    ident = struct.unpack('16B', e.Ehdr.ident)
    print("  Magic:   %s "%' '.join(['%02x'%_ for _ in ident]))
    print("  Class:                             %s"%expand_code({
        elf.ELFCLASS32: 'ELF32',
        elf.ELFCLASS64: 'ELF64',
        }, ident[elf.EI_CLASS]))
    print("  Data:                              %s"%expand_code({
        elf.ELFDATA2LSB: "2's complement, little endian",
        elf.ELFDATA2MSB: "2's complement, big endian",
        }, ident[elf.EI_DATA]))
    print("  Version:                           %s"%expand_code({
        1: '1 (current)',
        }, ident[elf.EI_VERSION]))
    print("  OS/ABI:                            %s"%expand_code({
        0: 'UNIX - System V',
        }, ident[elf.EI_OSABI]))
    print("  ABI Version:                       %d"%ident[elf.EI_ABIVERSION])
    elf_file_type = expand_code(et_strings, e.Ehdr.type)
    if e.Ehdr.type == elf.ET_DYN and elf.is_pie(e):
        elf_file_type = 'DYN (Position-Independent Executable file)'
    print("  Type:                              %s"%elf_file_type)
    machine_code = dict(elf.constants['EM'])
    # Same textual output as readelf, from readelf.c
    machine_code[elf.EM_M32]            = 'ME32100'
    machine_code[elf.EM_SPARC]          = 'Sparc'
    machine_code[elf.EM_386]            = 'Intel 80386'
    machine_code[elf.EM_68K]            = 'MC68000'
    machine_code[elf.EM_88K]            = 'MC88000'
    machine_code[elf.EM_486]            = 'Intel 80486'
    machine_code[elf.EM_860]            = 'Intel 80860'
    machine_code[elf.EM_MIPS]           = 'MIPS R3000'
    machine_code[elf.EM_S370]           = 'IBM System/370'
    machine_code[elf.EM_MIPS_RS3_LE]    = 'MIPS R4000 big-endian'
    machine_code[elf.EM_PARISC]         = 'HPPA'
    machine_code[elf.EM_SPARC32PLUS]    = 'Sparc v8+'
    machine_code[elf.EM_960]            = 'Intel 80960'
    machine_code[elf.EM_PPC]            = 'PowerPC'
    machine_code[elf.EM_PPC64]          = 'PowerPC64'
    machine_code[elf.EM_V800]           = 'NEC V800'
    machine_code[elf.EM_FR20]           = 'Fujitsu FR20'
    machine_code[elf.EM_RH32]           = 'TRW RH32'
    machine_code[elf.EM_ARM]            = 'ARM'
    machine_code[elf.EM_FAKE_ALPHA]     = 'Digital Alpha (old)'
    machine_code[elf.EM_SH]             = 'Renesas / SuperH SH'
    machine_code[elf.EM_SPARCV9]        = 'Sparc v9'
    machine_code[elf.EM_TRICORE]        = 'Siemens Tricore'
    machine_code[elf.EM_ARC]            = 'ARC'
    machine_code[elf.EM_H8_300]         = 'Renesas H8/300'
    machine_code[elf.EM_H8_300H]        = 'Renesas H8/300H'
    machine_code[elf.EM_H8S]            = 'Renesas H8S'
    machine_code[elf.EM_H8_500]         = 'Renesas H8/500'
    machine_code[elf.EM_IA_64]          = 'Intel IA-64'
    machine_code[elf.EM_MIPS_X]         = 'Stanford MIPS-X'
    machine_code[elf.EM_COLDFIRE]       = 'Motorola Coldfire'
    machine_code[elf.EM_X86_64]         = 'Advanced Micro Devices X86-64'
    print("  Machine:                           %s"%expand_code(machine_code, e.Ehdr.machine))
    print("  Version:                           %#x"%e.Ehdr.version)
    print("  Entry point address:               %#x"%e.Ehdr.entry)
    print("  Start of program headers:          %d (bytes into file)"%e.Ehdr.phoff)
    print("  Start of section headers:          %d (bytes into file)"%e.Ehdr.shoff)
    print("  Flags:                             %#x"%e.Ehdr.flags)
    print("  Size of this header:               %d (bytes)"%e.Ehdr.ehsize)
    print("  Size of program headers:           %d (bytes)"%e.Ehdr.phentsize)
    print("  Number of program headers:         %d"%e.Ehdr.phnum)
    print("  Size of section headers:           %d (bytes)"%e.Ehdr.shentsize)
    print("  Number of section headers:         %d"%e.Ehdr.shnum)
    print("  Section header string table index: %d"%e.Ehdr.shstrndx)

def display_program_headers(e):
    # Output format similar to readelf -l
    if len(e.ph.phlist) == 0:
        print("\nThere are no program headers in this file.")
        return
    print("\nElf file type is %s" % expand_code(et_strings, e.Ehdr.type))
    print("Entry point 0x%x" % e.Ehdr.entry)
    print("There are %d program headers, starting at offset %d" % (e.Ehdr.phnum, e.Ehdr.phoff))
    print("\nProgram Headers:")
    if e.wsize == 32:
        header = "  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align"
        format = "  %-14s 0x%06x 0x%08x 0x%08x 0x%05x 0x%05x %-3s 0x%x"
    elif e.wsize == 64:
        header = "  Type           Offset             VirtAddr           PhysAddr\n                FileSiz            MemSiz              Flags  Align"
        format = "  %-14s 0x%016x 0x%016x 0x%016x\n                0x%016x 0x%016x  %-3s    %x"
    print(header)
    for p in e.ph:
        flags = [' ', ' ', ' ']
        if p.ph.flags & 4: flags[0] = 'R'
        if p.ph.flags & 2: flags[1] = 'W'
        if p.ph.flags & 1: flags[2] = 'E'
        print(format%(elf.constants['PT'][p.ph.type],
                         p.ph.offset, p.ph.vaddr, p.ph.paddr,
                         p.ph.filesz, p.ph.memsz, ''.join(flags),
                         p.ph.align))
        if p.ph.type == elf.PT_INTERP:
            s = p.shlist[0]
            print('      [Requesting program interpreter: %s]' % e[s.sh.offset:s.sh.offset+s.sh.size].strip('\0'))
    if len(e.sh.shlist) == 0:
        return
    print("\n Section to Segment mapping:")
    print("  Segment Sections...")
    for i, p in enumerate(e.ph):
        res = "   %02d     " % i
        for s in p.shlist:
            res += s.sh.name + " "
        print(res)

def display_dynamic(e):
    machine = elf.constants['EM'][e.Ehdr.machine]
    for i, sh in enumerate(e.sh):
        if sh.sh.type != elf.SHT_DYNAMIC:
            continue
        if e.wsize == 32:
            header = "  Tag        Type                         Name/Value"
            format = "%#010x %-28s  %s"
            dyntab = sh.dyntab[:-2]
        elif e.wsize == 64:
            header = "  Tag        Type                         Name/Value"
            format = "%#018x %-20s  %s"
            dyntab = sh.dyntab[:-1]
        print("\nDynamic section at offset %#x contains %d entries:" % (sh.sh.offset, len(dyntab)))
        print(header)
        for d in dyntab:
            type = elf.constants['DT'].get(machine, {}).get(d.type, None)
            if type is None: type = elf.constants['DT'].get(d.type, None)
            else: type = machine + '_' + type
            if type in ('NEEDED',):
                name = 'Shared library: [%s]' % d.name
            elif type in ('STRSZ','SYMENT','RELSZ','RELENT','PLTRELSZ','RELASZ'):
                name = '%d (bytes)' % d.name
            elif type in ('PLTGOT','HASH','STRTAB','SYMTAB','INIT','FINI','REL',
                          'JMPREL','DEBUG','RELA',
                          'CHECKSUM','VERNEED',
                          'GNU_HASH',
                          'MIPS_BASE_ADDRESS','MIPS_LIBLIST','MIPS_GOTSYM',
                          'MIPS_HIDDEN_GOTIDX','MIPS_PROTECTED_GOTIDX',
                          'MIPS_LOCAL_GOTIDX','MIPS_LOCALPAGE_GOTIDX',
                          'MIPS_SYMBOL_LIB','MIPS_MSYM','MIPS_CONFLICT',
                          'MIPS_RLD_MAP','MIPS_OPTIONS',
                          'MIPS_INTERFACE','MIPS_INTERFACE_SIZE'):
                name = '%#x' % d.name
            elif type == 'PLTREL':
                name = elf.constants['DT'].get(d.name, d.name)
            elif type == 'MIPS_FLAGS':
                if d.name == 0:
                    name = 'NONE'
                else:
                    flags = ('QUICKSTART', 'NOTPOT', 'NO_LIBRARY_REPLACEMENT',
                             'NO_MOVE', 'SGI_ONLY', 'GUARANTEE_INIT',
                             'DELTA_C_PLUS_PLUS', 'GUARANTEE_START_INIT',
                             'PIXIE', 'DEFAULT_DELAY_LOAD', 'REQUICKSTART',
                             'REQUICKSTARTED', 'CORD', 'NO_UNRES_UNDEF',
                             'RLD_ORDER_SAFE')
                    name = ' '.join([ f for (f,b)
                                        in zip(flags,reversed(bin(d.name)[2:]))
                                        if b == '1' ])
            else:
                name = d.name
            output = format%(d.type, '(%s)'%type, name)
            print(output)


def display_symbols(sections):
    for s in sections:
        print("\n"+s.readelf_display())



if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-H', '--help', action='help', default=argparse.SUPPRESS, help='Display this information')
    parser.add_argument('-h', '--file-header', dest='options', action='append_const', const='headers',  help='Display the ELF file header')
    parser.add_argument('-S', '--section-headers', '--sections', dest='options', action='append_const', const='sections', help="Display the sections' header")
    parser.add_argument('-r', '--relocs', dest='options', action='append_const', const='reltab',   help='Display the relocations (if present)')
    parser.add_argument('-s', '--syms', '--symbols', dest='options', action='append_const', const='symtab',   help='Display the symbol table')
    parser.add_argument('--dyn-syms', dest='options', action='append_const', const='dynsym',   help='Display the dynamic symbol table')
    parser.add_argument('-d', '--dynamic', dest='options', action='append_const', const='dynamic',  help='Display the dynamic section (if present)')
    parser.add_argument('-l', '--program-headers', '--segments', dest='options', action='append_const', const='program',  help='Display the program headers')
    parser.add_argument('-g', '--section-groups', dest='options', action='append_const', const='groups',   help='Display the section groups')
    parser.add_argument('--readelf', dest='readelf_version', action='append', help='Simulate the output of a given version of readelf')
    parser.add_argument('file', nargs='+', help='ELF file(s)')
    args = parser.parse_args()
    if args.options is None:
        args.options = []

    elf.is_pie = lambda _: False
    if args.readelf_version:
        for readelf in args.readelf_version:
            if 'native' in readelf:
                readelf_version = get_readelf_version()
            else:
                readelf_version = float(readelf)
        if True:
            # TODO: readelf has a different output if "do_section_details" or "do_wide"
            elf.Shdr.header64 = ["  [Nr] Name              Type             Address           Offset",
                                 "       Size              EntSize          Flags  Link  Info  Align"]
            elf.Shdr.format64 = ("  [%(idx)2d] %(name17)-17s %(type_txt)-15s  %(addr)016x  %(offset)08x\n"
                                 "       %(size)016x  %(entsize)016x %(flags_txt)3s      %(link)2d    %(info)2d     %(addralign)d")
        if readelf_version >= 2.26:
            # 2016-01-20 https://github.com/bminor/binutils-gdb/commit/9fb71ee49fc37163697e4f34e16097928eb83d66
            elf.Shdr.footer = property(lambda _: [
                "Key to Flags:",
                "  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),",
                "  L (link order), O (extra OS processing required), G (group), T (TLS),",
                "  C (compressed), x (unknown), o (OS specific), E (exclude),",
                "  %sp (processor specific)" % (
                    "l (large), " if e.Ehdr.machine in (elf.EM_X86_64, elf.EM_L10M, elf.EM_K10M) else
                    "y (noread), " if e.Ehdr.machine == elf.EM_ARM else
                    "" ),
                ])
        if readelf_version >= 2.27:
            # 2016-07-05 https://github.com/bminor/binutils-gdb/commit/f0728ee368f217f2473798ad7ccfe9feae4412ce
            elf.Shdr.footer = property(lambda _: [
                "Key to Flags:",
                "  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),",
                "  L (link order), O (extra OS processing required), G (group), T (TLS),",
                "  C (compressed), x (unknown), o (OS specific), E (exclude),",
                "  %sp (processor specific)" % (
                    "l (large), " if e.Ehdr.machine in (elf.EM_X86_64, elf.EM_L10M, elf.EM_K10M) else
                    "y (purecode), " if e.Ehdr.machine == elf.EM_ARM else
                    "" ),
                ])
        if readelf_version >= 2.29: # more precisely 2.29.1
            # 2017-09-05 https://github.com/bminor/binutils-gdb/commit/83eef883581525d04df3a8e53a82c01d0d12b56a
            elf.Shdr.footer = property(lambda _: [
                "Key to Flags:",
                "  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),",
                "  L (link order), O (extra OS processing required), G (group), T (TLS),",
                "  C (compressed), x (unknown), o (OS specific), E (exclude),",
                "  %sp (processor specific)" % (
                    "l (large), " if e.Ehdr.machine in (elf.EM_X86_64, elf.EM_L10M, elf.EM_K10M) else
                    "y (purecode), " if e.Ehdr.machine == elf.EM_ARM else
                    "v (VLE), " if e.Ehdr.machine == elf.EM_PPC else
                    "" ),
                ])
        if readelf_version >= 2.36: # more precisely 2.36.1
            # 2021-02-02 https://github.com/bminor/binutils-gdb/commit/5424d7ed94cf5a7ca24636ab9f4e6d5c353fc0d3
            elf.Shdr.footer = property(lambda _: [
                "Key to Flags:",
                "  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),",
                "  L (link order), O (extra OS processing required), G (group), T (TLS),",
                "  C (compressed), x (unknown), o (OS specific), E (exclude),",
                "  %s%sp (processor specific)" % (
                    "R (retain), D (mbind), " if e.Ehdr.ident[elf.EI_OSABI] in (elf.ELFOSABI_GNU, elf.ELFOSABI_FREEBSD) else
                    "D (mbind), " if e.Ehdr.ident[elf.EI_OSABI] == elf.ELFOSABI_NONE else
                    ""
                    ,
                    "l (large), " if e.Ehdr.machine in (elf.EM_X86_64, elf.EM_L10M, elf.EM_K10M) else
                    "y (noread), " if e.Ehdr.machine == elf.EM_ARM else
                    "" ),
                ])
        if readelf_version >= 2.35:
            # 2020-07-02 https://github.com/bminor/binutils-gdb/commit/0942c7ab94e554657c3e11ab85ae7f15373ee80d
            elf.Shdr.name17 = property(lambda _: _.name[:12]+"[...]" if len(_.name) > 17 else _.name)
        if readelf_version >= 2.37:
            # 2021-06-15 https://github.com/bminor/binutils-gdb/commit/93df3340fd5ad32f784214fc125de71811da72ff
            elf.is_pie = is_pie


    for file in args.file:
        if len(args.file) > 1:
            print("\nFile: %s" % file)
        fd = open(file, 'rb')
        try:
            raw = fd.read()
        finally:
            fd.close()
        e = elf_init.ELF(raw)
        if 'headers' in args.options:
            display_headers(e)
        if 'sections' in args.options:
            print(e.sh.readelf_display())
        if 'reltab' in args.options:
            for sh in e.sh:
                if not 'rel' in dir(sh): continue
                print("\n" + sh.readelf_display())
        if 'symtab' in args.options or 'dynsym' in args.options:
            display_symbols(e.getsectionsbytype(elf.SHT_DYNSYM))
        if 'symtab' in args.options:
            display_symbols(e.getsectionsbytype(elf.SHT_SYMTAB))
        if 'dynamic' in args.options:
            display_dynamic(e)
        if 'program' in args.options:
            display_program_headers(e)
        if 'groups' in args.options:
            for sh in e.sh:
                if not sh.sh.type == elf.SHT_GROUP: continue
                print(sh.readelf_display())
