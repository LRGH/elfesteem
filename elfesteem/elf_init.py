#! /usr/bin/env python

import struct
import logging

from elfesteem import elf
from elfesteem.strpatchwork import StrPatchwork

log = logging.getLogger("elfparse")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)



def align_to(value, alignment):
    trimed = value - (value & (alignment-1))
    extra = 0
    if (value & (alignment-1)):
        extra = alignment

    return trimed + extra

### Sections


def inheritsexwsize(self, parent, kargs):
    for f in ['sex', 'wsize']:
        if f in kargs:
            setattr(self, f, kargs[f])
            del kargs[f]
        elif parent != None:
            setattr(self, f, getattr(parent, f))

class SectionMetaclass(type):
    sectypes = {}
    def __new__(cls, name, bases, dct):
        o = type.__new__(cls, name, bases, dct)
        if name != "SectionBase" and o.sht is not None:
            SectionMetaclass.sectypes[o.sht] = o
        return o

SectionBase = SectionMetaclass('SectionBase', (object,), {})

class Section(SectionBase):
    '''
    sht: (elf.SHT_*) Section header type
    sh: (elf.Shdr) actual header
    parent: (SHList) list of sections
    phparents: (list[ProgramHeader]) all ProgramHeader's that fully contain this section
    phparent: (ProgramHeader) _main_ ProgramHeader in witch this section resides
                first encountered, prefering elf.PT_LOAD sections
    content: (StrPatchwork) actual bytes of the section header
    '''

    sht = None
    def create(cls, parent, shstr=None):
        if shstr is None:
            sh = None
        else:
            sh = elf.Shdr(parent = None, content = shstr, sex = parent.sex, 
wsize = parent.wsize)
            if sh.type in SectionMetaclass.sectypes:
                cls = SectionMetaclass.sectypes[sh.type]
        i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
        if sh is not None:
            sh.parent=i
        i.__init__(parent, sh)
        return i
    create = classmethod(create)

    def append_section_content(self, appended_section):
        # type: (Section) -> None
        old_size = self.size
        self.resize(0, appended_section.size)

        self.content[
            old_size:
            self.size
        ] = appended_section.content.pack()

    def next_section(self):
        # type: () -> Union[Section, list[Section]]:
        stacket = False
        stack = []
        latest = None
        for section in self.parent.shlist:
            if section.sh.offset <= self.sh.offset or section is self:
                continue

            if latest is None or section.sh.offset < latest.sh.offset:
                latest = section
                stacket = False
                stack = [section]
                continue

            if section.sh.offset == latest.sh.offset:
                stacket = True
                stack.append(section)

        if stacket:
            return stack

        return latest

    def fix_allignment_requierments(self):
        # local_logger = logging.getLogger("expand_sections")
        # local_logger.setLevel(logging.DEBUG)

        if self.sh.addralign == 0 or (self.addr % self.sh.addralign) == 0:
            return

        req = self.sh.addralign - (self.addr % self.sh.addralign)
        og_offset = self.sh.offset

        # local_logger.debug(f"offseting ({hex(self.addr)})[{self}]${self.sh.addralign} with {req}")
        
        self.sh.offset += req
        if self.addr:
            self.sh.addr += req

        next_section = self.next_section()
        if type(next_section) is list:
            next_section = next_section[0]

        if next_section is not None:
            # local_logger.debug(f"\tfound next section [{next_section}]")
            old_req = req
            # local_logger.debug(f"{req=: x}, {next_section.sh.offset=: x}, {self.sh.offset=: x}, {self.size=: x}")
            unused = next_section.sh.offset - (self.sh.offset + self.size)
            # local_logger.debug(f"{unused=: x}")

            if unused >= 0:
                reuse = req
                req = 0
            else:
                # unused < 0 aka h
                reuse = abs(unused)
                req += abs(unused)

            # local_logger.debug(f"\trecovered {reuse}: [{old_req} -> {req}]")

        if req == 0:
            # local_logger.debug("\tpremature solve")
            return

        if self.phparent:
            # local_logger.debug(hex(self.phparent.addr), hex(self.phparent.ph.filesz), hex(self.phparent.ph.memsz))
            self.phparent.resize(self, req)
            for ph in self.phparents:
                if ph is self.phparent:
                    continue
                if ph.ph.type == elf.PT_LOAD:
                    continue

                ph.resize(self, req)
        else:
            self.parent.move_after(self, req)

    def resize(self, old, new):
        # type: (int, int) -> None
        # local_logger = logging.getLogger("expand_sections")
        # local_logger.setLevel(logging.DEBUG)

        og_size = self.sh.size
        self.sh.size += new-old

        diff = new - old
        next_section = self.next_section()
        if type(next_section) is list:
            next_section = next_section[0]
        if next_section is not None:
            # take in to account existing space between this and the next section
            # local_logger.debug("\tdiff , (next_section.sh.offset - self.sh.offset - self.size))")
            # local_logger.debug("\t", next_section.sh.offset, self.sh.offset, og_size)
            # local_logger.debug("\t", diff , (next_section.sh.offset - self.sh.offset - og_size))
            diff = max(0, diff - (next_section.sh.offset - self.sh.offset - og_size))

        # local_logger.debug("resize", self)
        # local_logger.debug("next: ", next_section)
        # local_logger.debug("\t", hex(new-old))
        # local_logger.debug("\t", hex(diff))
        if diff == 0:
            for ph in self.phparents:
                if self.sh.offset + self.size == ph.ph.filesz + ph.size:
                    # only extend segments
                    # ignore posible segment overlaps since it is guaranteed that no section will overlap
                    ph.size += new-old
            return

        if self.phparent:
            # local_logger.debug(hex(self.phparent.addr), hex(self.phparent.ph.filesz), hex(self.phparent.ph.memsz))
            self.phparent.resize(self, diff)
            for ph in self.phparents:
                if ph is self.phparent:
                    continue
                if ph.ph.type == elf.PT_LOAD:
                    continue
                ph.resize(self, diff)
        else:
            self.parent.move_after(self, diff)
        
    def move(self, diff):
        self.sh.offset += diff

        if self.addr:
            # don't change for unmaped sections
            self.sh.addr += diff

    def parse_content(self):
        pass
    def pack(self):
        data = self.content
        if type(data) != str: data = data.pack()
        return data
    def get_linksection(self):
        try:
            linksection = self.parent[self.sh.link]
        except IndexError:
            linksection = NoLinkSection
        return linksection
    def set_linksection(self, val):
        if isinstance(val, Section):
            val = self.parent.shlist.find(val)
        if type(val) is int:
            self.sh.link = val
    linksection = property(get_linksection, set_linksection)
    def get_infosection(self):
        #XXX info may not be in sh list ?!?
        if not self.sh.info in self.parent:
            return None
        return self.parent[self.sh.info]
    def set_infosection(self, val):
        if isinstance(val, Section):
            val = self.parent.shlist.find(val)
        if type(val) is int:
            self.sh.info = val
    infosection = property(get_infosection, set_infosection)
    shstrtab = property(lambda _: _.parent._shstrtab)
    def __init__(self, parent, sh=None, **kargs):
        self.parent=parent
        self.phparent=None
        self.phparents=[]
        inheritsexwsize(self, parent, {})
        if sh is None:
            sh = elf.Shdr(parent=self, type=self.sht, name_idx=0, **kargs)
        self.sh=sh
        self.content=StrPatchwork()
    def __repr__(self):
        return "%(name)-15s %(offset)08x %(size)06x %(addr)08x %(flags)x" % self.sh
    def recalc(self):
        pass
    size = property(lambda _: _.sh.size)
    addr = property(lambda _: _.sh.addr)
    name = property(lambda _: _.sh.name)

class NullSection(Section):
    sht = elf.SHT_NULL
    def get_name(self, ofs):
        # XXX check this
        return ""

class ProgBits(Section):
    sht = elf.SHT_PROGBITS

class HashSection(Section):
    sht = elf.SHT_HASH

class NoBitsSection(Section):
    sht = elf.SHT_NOBITS

class ShLibSection(Section):
    sht = elf.SHT_SHLIB

class InitArray(Section):
    sht = elf.SHT_INIT_ARRAY

class FiniArray(Section):
    sht = elf.SHT_FINI_ARRAY

class GroupSection(Section):
    sht = elf.SHT_GROUP
    def get_flags(self):
        flags, = struct.unpack("I", self.content[:4])
        return flags
    def get_sections(self):
        l = len(self.content)//4 - 1
        sections = struct.unpack("I"*l, self.content[4:])
        return sections
    def set_flags(self, value):
        self.content[0] = struct.pack("I", value)
    def set_sections(self, value):
        for idx in self.sections:
            self.parent.shlist[idx].sh.flags &= ~elf.SHF_GROUP
        for idx in value:
            self.parent.shlist[idx].sh.flags |= elf.SHF_GROUP
            self.parent.shlist[idx].sh.addralign = 1
        self.content[4] = struct.pack("I"*len(value), *value)
    flags = property(get_flags, set_flags)
    sections = property(get_sections, set_sections)
    def readelf_display(self):
        if self.flags == elf.GRP_COMDAT: flags = 'COMDAT'
        else:                            flags = ''
        symbol = self.parent.parent.sh[self.sh.link]
        if not symbol.sh.type == elf.SHT_SYMTAB:
            return "readelf: Error: Bad sh_link in group section `%s'"%self.sh.name
        symbol = symbol[self.sh.info].name
        rep = [ "%s group section [%4d] `%s' [%s] contains %d sections:" % (
            flags,
            self.parent.parent.sh.shlist.index(self),
            self.sh.name,
            symbol,
            len(self.sections)) ]
        format = "   [%5s]   %s"
        rep.append(format % ('Index',' Name'))
        for s_idx in self.sections:
            s = self.parent.parent.sh[s_idx].sh
            rep.append(format % (s_idx,s.name))
            if not (s.flags & elf.SHF_GROUP):
                rep.append("No SHF_GROUP in %s" % s.name)
        return "\n".join(rep)


class SymTabSHIndeces(Section):
    sht = elf.SHT_SYMTAB_SHNDX

class GNUVerSym(Section):
    sht = elf.SHT_GNU_versym
    entry_size = 2
    def parse_content(self):
        c = self.content
        unpack_format = "H"
        self.indexes = []
        while len(c) >= self.entry_size:
            self.indexes.append(struct.unpack("H", c[:self.entry_size])[0])
            c = c[self.entry_size:]

    def __getitem__(self, i):
        return self.indexes[i]
    def __setitem__(self, i, val):
        self.indexes[i] = val
        self.content[i * self.entry_size: i * self.entry_size + self.entry_size] = struct.pack("H", val)
    def __len__(self):
        return len(self.indexes)


class GNUVerNeed(Section):
    '''
    elements: list[elf.Verneed64|elf.Vernaux64]
    needs: list[elf.Verneed64]
    auxs: list[elf.Vernaux64]
    '''
    sht = elf.SHT_GNU_verneed
    entry_size = -1
    Verneed = None
    Vernaux = None
    

    def parse_content(self):
        self.Verneed = {64: elf.Verneed64, 32: elf.Verneed32}[self.wsize]
        self.Vernaux = {64: elf.Vernaux64, 32: elf.Vernaux32}[self.wsize]
        self.entry_size = {64: 0x10, 32: 0x10}[self.wsize]

        aux_remaining_count = 0

        unpack_format = "H"
        self.elements = [None] * (len(self.content) // self.entry_size)
        self.needs = []
        self.auxs = []


        c = self.content
        while len(c) >= self.entry_size:
            elem = self.Verneed(parent=self, content=c[:self.entry_size])
            self.needs.append(elem)
            elem.offset = len(self.content) - len(c)
            self.elements[elem.offset // self.entry_size] = elem
            c = c[elem.vn_next:]
            if not elem.vn_next:
                break
        
        # TODO: validate for multiple needs
        for need in self.needs:
            c = self.content[need.offset+need.vn_aux:]
            while len(c) >= self.entry_size:
                elem = self.Vernaux(parent=self, content=c[:self.entry_size])
                self.auxs.append(elem)
                elem.offset = len(self.content) - len(c)
                self.elements[elem.offset // self.entry_size] = elem
                c = c[elem.vna_next:]
                if not elem.vna_next:
                    break

    def __getitem__(self, i):
        return self.elements[i]
    def __setitem__(self, i, val):
        self.elements[i] = val
        self.content[i * self.entry_size: i * self.entry_size + self.entry_size] = val.pack()
        raise Exception("TODO")
        # TODO: update in needs/auxs
    def __len__(self):
        return len(self.elements)

class GNUVerDef(Section):
    sht = elf.SHT_GNU_verdef

class GNULibLIst(Section):
    sht = elf.SHT_GNU_LIBLIST

class CheckSumSection(Section):
    sht = elf.SHT_CHECKSUM

class NoteSection(Section):
    sht = elf.SHT_NOTE
    def parse_content(self):
        c = self.content
        self.notes = []
        # XXX: c may not be aligned?
        while len(c)> 12:
            namesz,descsz,typ = struct.unpack("III",c[:12])
            name = c[12:12+namesz]
            desc = c[12+namesz:12+namesz+descsz]
            c = c[12+namesz+descsz:]
            self.notes.append((typ,name,desc))



class Dynamic(Section):
    sht = elf.SHT_DYNAMIC
    def parse_content(self):
        Dyn = { 32: elf.Dyn32, 64: elf.Dyn64 }[self.wsize]
        c = self.content
        self.dyntab = []
        self.dynamic = {}
        sz = self.sh.entsize
        if sz == 0:
            sz = self.wsize // 4
        idx = 0
        while len(c) > sz*idx:
            s = c[sz*idx:sz*(idx+1)]
            idx += 1
            dyn = Dyn(parent=self, content=s)
            self.dyntab.append(dyn)
            if type(dyn.name) is str:
                self.dynamic[dyn.name] = dyn
    def __getitem__(self,item):
        if type(item) is str:
            return self.dynamic[item]
        return self.dyntab[item]
    def __setitem__(self, item, val):
        if not isinstance(val, elf.Dyn32):
            raise ValueError("Cannot set Dynamic item to %r" % val)
        if item >= len(self.dyntab):
            self.dyntab.extend([None for i in range(item + 1 - len(self.dyntab))])
        # TODO: completly remove old entry
        self.dyntab[item] = val
        if type(val.name) is str:
            self.dynamic[val.name] = val
        
        self.content[item * self.sh.entsize] = val.pack()
        # if val.info>>4 == elf.STB_LOCAL and item >= self.sh.info:
        #     # One greater than the symbol table index of the last local symbol
        #     self.sh.info = item+1
    def get_with_type(self, target_type):
        for dyn_entry in (self.dyntab):
            if dyn_entry.type == target_type:
                return dyn_entry
        
        return None
    def update_wi(self, idx, new_val):
        dyn_entry = self[idx]
        dyn_entry.name_idx = self.parent.parent.getsectionbyname(".fini").addr
        self[idx] = dyn_entry
    def update_wt(self, target_type, new_val):
        for i, dyn_entry in enumerate(self.dyntab):
            if dyn_entry.type != target_type:
                continue
            dyn_entry.name_idx = new_val
            self[i] = dyn_entry
            break
        else:
            raise Exception("not found")
    def recalc(self):
        self.update_wt(elf.DT_FINI, self.parent.parent.getsectionbyname(".fini").addr)
        self.update_wt(elf.DT_FINI_ARRAY, self.parent.parent.getsectionbyname(".fini_array").addr)
        self.update_wt(elf.DT_FINI_ARRAYSZ, self.parent.parent.getsectionbyname(".fini_array").size)
        self.update_wt(elf.DT_INIT_ARRAY, self.parent.parent.getsectionbyname(".init_array").addr)
        self.update_wt(elf.DT_INIT_ARRAYSZ, self.parent.parent.getsectionbyname(".init_array").size)

        # check for full-RELRO
        # !!! this might not be up to spec 
        if self.get_with_type(elf.DT_PLTGOT) is not None:
            if (self.get_with_type(elf.DT_FLAGS) is not None and self.get_with_type(elf.DT_FLAGS).name_idx & elf.DF_BIND_NOW):
                self.update_wt(elf.DT_PLTGOT, self.parent.parent.getsectionbyname(".got").addr)
            else:
                self.update_wt(elf.DT_PLTGOT, self.parent.parent.getsectionbyname(".got.plt").addr)
        
        if self.parent.parent.getsectionbyname(".rela.plt"):
            self.update_wt(elf.DT_JMPREL, self.parent.parent.getsectionbyname(".rela.plt").addr)
        
        self.update_wt(elf.DT_SYMTAB, self.parent.parent.getsectionbyname(".dynsym").addr)
        self.update_wt(elf.DT_STRTAB, self.parent.parent.getsectionbyname(".dynstr").addr)
        self.update_wt(elf.DT_STRSZ, self.parent.parent.getsectionbyname(".dynstr").size)
        self.update_wt(elf.DT_RELA, self.parent.parent.getsectionbyname(".rela.dyn").addr)
        self.update_wt(elf.DT_RELASZ, self.parent.parent.getsectionbyname(".rela.dyn").size)

        if self.parent.parent.getsectionbyname(".plt"):
            self.update_wt(elf.DT_PLTRELSZ, self.parent.parent.getsectionbyname(".plt").size)

        self.update_wt(elf.DT_VERSYM, self.parent.parent.getsectionbyname(".gnu.version").addr)
        self.update_wt(elf.DT_VERNEED, self.parent.parent.getsectionbyname(".gnu.version_r").addr)
        
        for ph in self.parent.parent.ph:
            if ph.ph.type == elf.PT_DYNAMIC:
                ph.ph.offset = self.sh.offset
                ph.ph.paddr = ph.ph.vaddr = self.sh.addr

from elfesteem.cstruct import data_null, bytes_to_name, name_to_bytes

class StrTable(Section):
    sht = elf.SHT_STRTAB

    def get_name(self, idx):
        n = self.content[idx:self.content.find(data_null, idx)]
        return bytes_to_name(n)

    def find_name(self, name):
        name = name_to_bytes(name)
        if name + data_null in self.content:
            return self.content.find(name+data_null)
        
        return None

    def add_name(self, name):
        name = name_to_bytes(name)
        if name + data_null in self.content:
            return self.content.find(name)
        
        # TODO: check for unused space and reuse, aka 2 or more NULL bytes
        idx = len(self.content)

        self.resize(0, len(name))
        self.content[idx] = name+data_null

        return idx

    def mod_name(self, idx, name):
        name = name_to_bytes(name)
        n = self.content[idx:self.content.find(data_null, idx)]
        dif = len(name) - len(n)
        if dif != 0:
            raise ValueError("Didn't fit in str section")
        return idx
    
    def last_char(self):
        pos = 0
        for i, c in enumerate(self.content):
            if c != data_null:
                pos = i

        return pos
    last_char = property(last_char)

class SymTable(Section):
    sht = elf.SHT_SYMTAB
    def __init__(self, *args, **kargs):
        Section.__init__(self, *args, **kargs)
        self.symtab=[]
        self.symbols={}
    def parse_content(self):
        Sym = { 32: elf.Sym32, 64: elf.Sym64 }[self.wsize]
        c = self.content
        sz = Sym(self).bytelen
        if sz != self.sh.entsize:
            log.error("SymTable has invalid entsize %d instead of %d",
                self.sh.entsize, sz)
        idx = 0
        while len(c) > sz*idx:
            s = c[sz*idx:sz*(idx+1)]
            idx += 1
            sym = Sym(parent=self, content=s)
            self.symtab.append(sym)
            self.symbols[sym.name] = sym
    def __len__(self):
        return len(self.symtab)
    def __getitem__(self,item):
        if type(item) is str:
            return self.symbols[item]
        return self.symtab[item]
    def __setitem__(self,item,val):
        if not isinstance(val, elf.Sym32):
            raise ValueError("Cannot set SymTable item to %r"%val)
        if item >= len(self.symtab):
            self.symtab.extend([None for i in range(item+1-len(self.symtab))])
        self.symtab[item] = val
        self.symbols[val.name] = val
        self.content[item*self.sh.entsize] = val.pack()
        if val.info>>4 == elf.STB_LOCAL and item >= self.sh.info:
            # One greater than the symbol table index of the last local symbol
            self.sh.info = item+1
    def readelf_display(self):
        rep = [ "Symbol table '%s' contains %d entries:"
                % (self.sh.name, len(self.symtab)) ]
        if self.wsize == 32:
            rep.append("   Num:    Value  Size Type    Bind   Vis      Ndx Name")
        elif self.wsize == 64:
            rep.append("   Num:    Value          Size Type    Bind   Vis      Ndx Name")
        rep.extend([ _.readelf_display() for _ in self.symtab ])
        return "\n".join(rep)


class DynSymTable(SymTable):
    sht = elf.SHT_DYNSYM


class RelTable(Section):
    sht = elf.SHT_REL
    def rel_type(self):
        if self.__class__.sht == elf.SHT_REL:
            return { 32: elf.Rel32,  64: elf.Rel64 }[self.wsize]
        elif self.__class__.sht == elf.SHT_RELA:
            return { 32: elf.Rela32, 64: elf.Rela64 }[self.wsize]
        elif self.parent.parent.Ehdr.machine == elf.EM_MIPS and self.wsize == 64:
            return elf.Rel64MIPS
        else:
            raise Exception("unknown Rel")

    def parse_content(self):
        Rel = self.rel_type()
        c = self.content
        self.reltab=[]
        self.rel = {}
        sz = self.sh.entsize
        idx = 0
        while len(c) > sz*idx:
            s = c[sz*idx:sz*(idx+1)]
            idx += 1
            rel = Rel(parent=self, content=s)
            self.reltab.append(rel)
            self.rel[rel.sym] = rel

    def __setitem__(self,item,val):
        if not isinstance(val, elf.RelBase):
            raise ValueError("Cannot set RelTable item to %r"%val)
        if item >= len(self.reltab):
            self.reltab.extend([None for i in range(item+1-len(self.reltab))])
        self.reltab[item] = val
        self.rel[val.name] = val
        self.content[item * self.sh.entsize] = val.pack()

    def readelf_display(self):
        ret = "Relocation section %r at offset 0x%x contains %d entries:" % (
            self.sh.name,
            self.sh.offset,
            len(self.reltab))
        if self.wsize == 32:
            ret += "\n Offset     Info    Type            Sym.Value  Sym. Name"
        elif self.wsize == 64:
            ret += "\n  Offset          Info           Type           Sym. Value    Sym. Name"
        if self.sht == elf.SHT_RELA:
            ret += " + Addend"
        for r in self.reltab:
            ret += "\n" + r.readelf_display()
        return ret

class RelATable(RelTable):
    sht = elf.SHT_RELA


### Section List

class SHList(object):
    def __init__(self, parent, **kargs):
        self.parent = parent
        inheritsexwsize(self, parent, kargs)
        self.shlist = []
        ehdr = self.parent.Ehdr
        of1 = ehdr.shoff
        if not of1: # No SH table
            return
        filesize = len(parent.content)
        if of1 > filesize:
            log.error("Offset to section headers after end of file")
            return
        if of1+ehdr.shnum*ehdr.shentsize > filesize:
            log.error("Offset to end of section headers after end of file")
            return
        for i in range(ehdr.shnum):
            of2 = of1+ehdr.shentsize
            shstr = parent[of1:of2]
            self.shlist.append( Section.create(self, shstr=shstr) )
            of1=of2
        assert len(self.shlist) == ehdr.shnum
        # The shstrtab section is not always valid :-(
        if 0 <= ehdr.shstrndx < ehdr.shnum:
            self._shstrtab = self.shlist[ehdr.shstrndx]
        else:
            self._shstrtab = None
        if not isinstance(self._shstrtab, StrTable):
            class NoStrTab(object):
                def get_name(self, idx):
                    return "<no-name>"
            self._shstrtab = NoStrTab()

        if ehdr.shnum == 0: return

        for s in self.shlist:
            if not isinstance(s, NoBitsSection):
                if s.sh.offset > filesize:
                    log.error("Offset to section %d after end of file",
                              self.shlist.index(s))
                    continue
                if s.sh.offset+s.sh.size > filesize:
                    log.error("Offset to end of section %d after end of file",
                              self.shlist.index(s))
                    continue
                s.content = StrPatchwork(parent[s.sh.offset: s.sh.offset+s.sh.size])
        # Follow dependencies when initializing sections
        zero = self.shlist[0]
        todo = self.shlist[1:]
        done = []
        while todo:
            s = todo.pop(0)
            if ( (s.linksection in done + [zero, NoLinkSection]) and
                 (s.infosection in done + [zero, None]) ):
                done.append(s)
                s.parse_content()
            else:
                todo.append(s)
    def append(self, item):
        self.shlist.append(item)
    def __len__(self):
        return len(self.shlist)
    def __getitem__(self, item):
        return self.shlist[item]
    def __repr__(self):
        rep = ["#  section         offset   size   addr     flags"]
        for i,s in enumerate(self.shlist):
            rep.append("%2i %r %s" % (i, s, s.__class__.__name__))
        return "\n".join(rep)
    def readelf_display(self):
        rep = [ "There are %d section headers, starting at offset %#x:"
                % (len(self.shlist), self.parent.Ehdr.shoff),
                "",
                "Section Headers:" ]
        if self.wsize == 32:
            rep.append( "  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al" )
        elif self.wsize == 64:
            rep.extend(["  [Nr] Name              Type             Address           Offset    Size              EntSize          Flags  Link  Info  Align"])
        rep.extend([ _.sh.readelf_display() for _ in self ])
        rep.extend([ # Footer
"Key to Flags:",
"  W (write), A (alloc), X (execute), M (merge), S (strings)",
"  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)",
"  O (extra OS processing required) o (OS specific), p (processor specific)",
            ])
        return "\n".join(rep)
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        c = struct.pack("")
        for s in self.shlist:
            c += s.sh.pack()
        return c

    def move_after(self, sec, diff):
        '''Only used when a resized section doesn't bellong to a segment

        !!! Untested ?
        '''

        old_section_file_end = sec.sh.offset + sec.sh.size - diff
        old_section_memory_end = sec.sh.addr + sec.sh.size - diff

        reason_is_mapped = sec.sh.addr != 0
        
        for section in self.shlist:
            # check if a section needs to be moved relative to only one addres?
            checks = [
                section.sh.offset > old_section_file_end,
                section.addr > old_section_memory_end,
            ]
            if reason_is_mapped:
                assert all(checks) or not any(checks)

            # skip previous sections
            if section.sh.offset < old_section_file_end:
                continue

            if section is sec:
                continue

            section.move(diff)


        if old_section_file_end < self.parent.Ehdr.shoff:
            self.parent.Ehdr.shoff += diff


        symbol_table = self.parent.getsectionbyname(".symtab")
        if symbol_table and sec.addr:
            for i, symbol in enumerate(symbol_table.symtab):
                if symbol.value >= old_section_memory_end:
                    symbol.value += diff
                    symbol_table[i] = symbol

class NoLinkSection(object):
    get_name = lambda s,i:None
    add_name = lambda s,n:None
    mod_name = lambda s,i,n:None
NoLinkSection = NoLinkSection()

### Program Header List


class ProgramHeader(object):
    def __init__(self, parent, PHtype, phstr, **kargs):
        self.parent = parent
        inheritsexwsize(self, parent, kargs)
        self.ph = PHtype(parent=self, content=phstr)
        self.shlist = [] # based on readelf's "Section to Segment mapping"
        self.shlist_partial = [] # These are other sections of interest
        ph_file_end = self.ph.offset+self.ph.filesz
        ph_mem_end  = self.ph.vaddr+self.ph.memsz
        for s in self.parent.parent.sh:
            if isinstance(s, NullSection):
                continue
            if self.ph.type != elf.PT_TLS and (
               (s.sh.flags & elf.SHF_TLS) and s.sh.type == elf.SHT_NOBITS):
                # .tbss is special.  It doesn't contribute memory space
                # to normal segments.
                continue
            if s.sh.flags & elf.SHF_ALLOC:
                if   (self.ph.vaddr <= s.sh.addr) and \
                     (s.sh.addr+s.sh.size <= ph_mem_end):
                    if not s.phparent:
                        s.phparent = self
                    elif s.phparent.ph.type != elf.PT_LOAD and self.ph.type == elf.PT_LOAD:
                        s.phparent = self
                    s.phparents.append(self)
                    self.shlist.append(s)
            else:
                if   (self.ph.offset <= s.sh.offset) and \
                     (s.sh.offset+s.sh.size <= ph_file_end):
                    if not s.phparent:
                        s.phparent = self
                    elif s.phparent.ph.type != elf.PT_LOAD and self.ph.type == elf.PT_LOAD:
                        s.phparent = self
                    s.phparents.append(self)
                    self.shlist.append(s)
            if s in self.shlist:
                continue
            if   self.ph.offset <= s.sh.offset           < ph_file_end:
                # Section start in Segment
                self.shlist_partial.append(s)
            elif self.ph.offset < s.sh.offset+s.sh.size <= ph_file_end:
                # Section end in Segment
                self.shlist_partial.append(s)
    def resize(self, sec, diff):
        # local_logger = logging.getLogger("expand_sections")
        # local_logger.setLevel(logging.DEBUG)
        # the ELF standard demand that p_vaddr % p_align == p_offset % p_align, 
        # This requirements is designed such that it is possible to map the segments
        # from the file into memory while still keeping the file size minimal
        # (there is no need to insert padding into the file).
        
        old_size = max(self.ph.filesz, self.ph.memsz)
        new_size = old_size + diff

        self.ph.filesz += diff
        self.ph.memsz += diff

        # update trailing sections address to avoid overlap
        # local_logger.debug("LOCAL:")
        for section in self.shlist:
            # local_logger.debug(section)

            if section.sh.addr and section.addr > sec.addr:
                # local_logger.debug(f"Offseting section {section}")
                section.sh.addr += diff

            if section.sh.offset > sec.sh.offset:
                # local_logger.debug(f"\tadd {section.sh.offset:x} {diff}")
                section.sh.offset += diff
                # local_logger.debug(f"\t{section.sh.offset:x}")

        performed_segment_expansion = False

        # TODO: remove hacky fix: self.ph.align > 0x30
        if align_to(old_size, self.ph.align) != align_to(new_size, self.ph.align) and self.ph.align > 0x30:
            # local_logger.debug(f"{old_size=:x}|{align_to(old_size, self.ph.align):x}")
            # local_logger.debug(f"{new_size=:x}|{align_to(new_size, self.ph.align):x}")
            # local_logger.debug("Offseting subsequent segments after {self.shlist}")
            segment_diff = align_to(new_size, self.ph.align) - align_to(old_size, self.ph.align)
            self.parent.move_after(sec, segment_diff, sec.sh.size - diff)
            performed_segment_expansion = True
        
        # handled in move_after??
        # yes but not properly, as a result of segment alignment
        for section in self.shlist:
            assert not sec.addr < section.addr < sec.addr + sec.size - diff
            assert not sec.sh.offset < section.sh.offset < sec.sh.offset + sec.size - diff

        if performed_segment_expansion:
            return

        self.parent.parent.Ehdr.shoff += diff
        

        # local_logger.debug("GLOBAL:")
        for section in self.parent.parent.sh:
            # local_logger.debug(section)
            if section.phparent:
                # local_logger.debug("\tskiping")
                continue

            if self.ph.offset < section.sh.offset:
                # local_logger.debug(f"\toffseting {diff:x}")
                section.move(diff)

    # get_rvaitem needs addr and size (same names as in the Shdr class)
    # Note that we should always have memsz >= filesz unless memsz == 0
    # Note that paddr is irrelevant for most OS
    def get_size(self):
        return self.ph.memsz
    size = property(get_size)
    def get_addr(self):
        return self.ph.vaddr
    addr = property(get_addr)

class PHList(object):
    def __init__(self, parent, **kargs):
        self.parent = parent
        inheritsexwsize(self, parent, kargs)
        self.phlist = []
        ehdr = self.parent.Ehdr
        of1 = ehdr.phoff
        for i in range(ehdr.phnum):
            of2 = of1+ehdr.phentsize
            phstr = parent[of1:of2]
            self.phlist.append(ProgramHeader(self,
                { 32: elf.Phdr32, 64: elf.Phdr64 }[self.wsize],
                phstr))
            of1 = of2

    def __getitem__(self, item):
        return self.phlist[item]

    def __repr__(self):
        r = ["   offset filesz vaddr    memsz"]
        for i,p in enumerate(self.phlist):
            l = "%(offset)07x %(filesz)06x %(vaddr)08x %(memsz)07x %(type)02x %(flags)01x"%p.ph
            l = ("%2i " % i)+l
            r.append(l)
            r.append("   "+" ".join([s.sh.name for s in p.shlist]))
        return "\n".join(r)
    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        c = struct.pack("")
        for p in self.phlist:
            c += p.ph.pack()
        return c
    def move_after(self, sec, diff, old_section_size):
        # local_logger = logging.getLogger("expand_sections")
        # local_logger.setLevel(logging.DEBUG)

        # this is called by a ProgramHeader after a Section has beed resized
        # old_section_size = sec.sh.size - diff
        # local_logger.debug(f"{hex(old_section_size)} = {hex(sec.sh.size)} - {hex(diff)}")

        old_section_file_end = sec.sh.offset + old_section_size
        old_section_memory_end = sec.sh.addr + old_section_size
        # local_logger.debug("old_section_memory_end = sec.sh.addr + old_section_size")
        # local_logger.debug(f"{hex(old_section_memory_end)} = {hex(sec.sh.addr)} + {hex(old_section_size)}")

        for p in self.phlist:
            # address changes are requiered ONLY if the previous segment overflows in to it
            # is there an instant when a segment needs to be moved relative to only one addres?
            checks = [
                p.ph.offset > old_section_file_end,
                p.ph.vaddr > old_section_memory_end,
                p.ph.vaddr > old_section_memory_end
            ]
            assert all(checks) or not any(checks)

            if p.ph.offset < old_section_file_end:
                continue

            p.ph.offset += diff
            p.ph.vaddr += diff
            p.ph.paddr += diff


        for section in self.parent.sh:
            if section.phparent is sec.phparent:
                # skip sections in segment
                continue

            # check if a section needs to be moved relative to only one addres?
            checks = [
                p.ph.offset > old_section_file_end,
                p.ph.vaddr > old_section_memory_end,
                p.ph.vaddr > old_section_memory_end
            ]
            assert all(checks) or not any(checks)
            # skip previous sections
            if section.sh.offset < old_section_file_end:
                continue

            section.move(diff)

        # the section header is at the end; so it's offset needs to be updated 
        self.parent.Ehdr.shoff += diff


class virt(object):
    def __init__(self, x):
        self.parent = x

    def get_rvaitem(self, item, section = None):
        if item.stop is None:
            s = self.parent.getsectionbyvad(item.start, section)
            return [(s, item.start-s.addr)]

        total_len = item.stop - item.start
        start = item.start
        virt_item = []
        while total_len > 0:
            s = self.parent.getsectionbyvad(start, section)
            if not s:
                raise ValueError('unknown rva address! %x'%start)
            s_start = start - s.addr
            s_stop = item.stop - s.addr
            if s_stop > s.size:
                s_stop =  s.size
            s_len = s_stop - s_start
            if s_len == 0:
                raise ValueError('empty section! %x'%start)
            total_len -= s_len
            start += s_len
            n_item = slice(s_start, s_stop)
            virt_item.append((s, n_item))
        return virt_item


    def __call__(self, ad_start, ad_stop = None, section = None):
        rva_items = self.get_rvaitem(slice(ad_start, ad_stop), section)
        return self.rvaitems2binary(rva_items)

    def __getitem__(self, item):
        rva_items = self.get_rvaitem(item)
        return self.rvaitems2binary(rva_items)
    def get(self, start, end):
        # Deprecated API
        return self[start:end]

    def rvaitems2binary(self, rva_items):
        data_out = struct.pack("")
        for s, n_item in rva_items:
            if not isinstance(s, ProgramHeader):
                data_out += s.content[n_item]
                continue
            if not type(n_item) is slice:
                n_item = slice(n_item, n_item+1)
            start = n_item.start + s.ph.offset
            stop  = n_item.stop + s.ph.offset
            n_item = slice(start, stop)
            data_out += self.parent.content[n_item]
        return data_out

    def __setitem__(self, item, data):
        if not type(item) is slice:
            item = slice(item, item+len(data))
        rva_items = self.get_rvaitem(item)
        if not rva_items:
             return
        off = 0
        for s, n_item in rva_items:
            if isinstance(s, ProgBits):
                i = slice(off, n_item.stop+off-n_item.start)

                data_slice = data.__getitem__(i)
                s.content.__setitem__(n_item, data_slice)
                off = i.stop
            else:
                raise ValueError('TODO XXX')

        return

    def __len__(self):
        # __len__ should not be used: Python returns an int object, which
        # will cap values to 0x7FFFFFFF on 32 bit systems. A binary can have
        # a base address higher than this, resulting in the impossibility to
        # handle such programs.
        log.warning("__len__ deprecated")
        return self.max_addr()
    def max_addr(self):
        # the maximum virtual address is found by retrieving the maximum
        # possible virtual address, either from the program entries, and
        # section entries. if there is no such object, raise an error.
        l = 0
        if  self.parent.ph.phlist:
            for phdr in self.parent.ph.phlist:
                l = max(l, phdr.ph.vaddr + phdr.ph.memsz)
        if  self.parent.sh.shlist:
            for shdr in self.parent.sh.shlist:
                l = max(l, shdr.sh.addr  + shdr.sh.size)
        return l

    def is_addr_in(self, ad):
        return self.parent.is_in_virt_address(ad)

    def find(self, pattern, offset = 0):
        sections = []
        for s in self.parent.ph:
            s_max = s.ph.memsz#max(s.ph.filesz, s.ph.memsz)
            if offset < s.ph.vaddr + s_max:
                sections.append(s)

        if not sections:
            return -1
        offset -= sections[0].ph.vaddr
        if offset < 0:
            offset = 0
        for s in sections:
            data = self.parent.content[s.ph.offset:s.ph.offset+s.ph.filesz]
            ret = data.find(pattern, offset)
            if ret != -1:
                return ret  + s.ph.vaddr
            offset = 0
        return -1

def elf_default_content(self, **kargs):
    if self.Ehdr.type == elf.ET_REL:
        elf_default_content_reloc(self, **kargs)

def elf_default_content_reloc(self, **kargs):
    # Create the Section header string table, which contains the names
    # of the sections
    self.sh._shstrtab = StrTable(self.sh, addralign = 1)
    self.sh._shstrtab.content[0] = '\0'
    symtab = SymTable(self.sh, addralign = 4, entsize = 16)
    strtab = StrTable(self.sh, addralign = 1)
    symtab.sh.name = ".symtab"
    strtab.sh.name = ".strtab"
    self.sh._shstrtab.sh.name = ".shstrtab"
    # Create the Section Header List
    sections = kargs.get('sections',[".text"])
    relocs = kargs.get('relocs',[])
    self.sh.shlist.append(NullSection(self.sh))
    for name in sections:
        flags = {}
        if name.startswith(".text"):
            SectionType = ProgBits
            flags['addralign'] = 4
            flags['flags'] = elf.SHF_ALLOC|elf.SHF_EXECINSTR
            if name.startswith(".text.startup"):
                flags['addralign'] = 16
        if name.startswith(".data"):
            SectionType = ProgBits
            flags['addralign'] = 4
            flags['flags'] = elf.SHF_ALLOC|elf.SHF_WRITE
        if name.startswith(".bss"):
            SectionType = NoBitsSection
            flags['addralign'] = 4
            flags['flags'] = elf.SHF_ALLOC|elf.SHF_WRITE
        if name.startswith(".rodata"):
            SectionType = ProgBits
            flags['addralign'] = 1
            flags['flags'] = elf.SHF_ALLOC
            if name.startswith(".rodata."):
                flags['flags'] |= elf.SHF_MERGE
            if name.startswith(".rodata.str"):
                flags['flags'] |= elf.SHF_STRINGS
                flags['entsize'] = 1
            if name.startswith(".rodata.str1.4"):
                flags['addralign'] = 4
            if name.startswith(".rodata.cst4"):
                flags['entsize'] = 4
                flags['addralign'] = 4
        if name == ".eh_frame":
            SectionType = ProgBits
            flags['addralign'] = 4
            flags['flags'] = elf.SHF_ALLOC
        if name == ".comment":
            SectionType = ProgBits
            flags['addralign'] = 1
            flags['entsize'] = 1
            flags['flags'] = elf.SHF_MERGE|elf.SHF_STRINGS
        if name == ".note.GNU-stack":
            SectionType = ProgBits
            flags['addralign'] = 1
        if name == ".group":
            SectionType = GroupSection
            flags['addralign'] = 4
            flags['entsize'] = 4
        if not name in relocs:
            flags['name'] = name
        self.sh.shlist.append(SectionType(self.sh, **flags))
        if name in relocs:
            flags = { 'name': ".rel"+name, 'addralign': 4, 'entsize': 8 }
            flags['info'] = len(self.sh.shlist)-1
            self.sh.shlist.append(RelTable(self.sh, **flags))
            self.sh.shlist[-2].sh.name_idx = self.sh.shlist[-1].sh.name_idx+4
    self.sh.shlist.append(self.sh._shstrtab)
    self.sh.shlist.append(symtab)
    self.sh.shlist.append(strtab)
    # Automatically generate some values
    self.Ehdr.shstrndx = self.sh.shlist.index(self.sh._shstrtab)
    self.Ehdr.shnum = len(self.sh.shlist)
    symtab.sh.link = self.sh.shlist.index(strtab)
    for s in self.sh.shlist:
        if isinstance(s, RelTable) or isinstance(s, GroupSection):
            s.sh.link = self.sh.shlist.index(symtab)
    # Note that all sections are empty, and therefore the section offsets
    # and sizes are invalid
    # elf_set_offsets() should take care of that

def elf_set_offsets(self):
    if self.Ehdr.type != elf.ET_REL:
        # TODO
        return
    # Set offsets; the standard section layout is not the order of the shlist
    s = self.getsectionbyname("")
    s.sh.offset = 0
    pos = self.Ehdr.ehsize
    section_layout = [".group", ".text", ".data", ".bss"]
    section_layout += [ s.sh.name for s in self.sh.shlist if s.sh.name.startswith(".rodata") ]
    section_layout += [ s.sh.name for s in self.sh.shlist if s.sh.name.startswith(".data.") ]
    section_layout += [ s.sh.name for s in self.sh.shlist if s.sh.name.startswith(".text.") ]
    section_layout += [ ".comment", ".note.GNU-stack", ".eh_frame" ]
    section_layout = section_layout \
        + [ ".shstrtab", None, ".symtab", ".strtab"] \
        + [ ".rel"+name for name in section_layout ]
    for name in section_layout:
        if name is None:
            pos = ((pos + 3)//4)*4
            self.Ehdr.shoff = pos
            self.Ehdr.shentsize = self.sh._shstrtab.sh.bytelen
            pos += self.Ehdr.shnum * self.Ehdr.shentsize
            continue
        for s in self.getsectionsbyname(name):
            align = s.sh.addralign
            s.sh.offset = ((pos + align-1)//align)*align
            s.sh.size = len(s.content)
            pos = s.sh.offset
            if name != ".bss": pos += s.sh.size
    for s in self.sh.shlist[1:]:
        if s.sh.offset == 0:
            align = s.sh.addralign
            s.sh.offset = ((pos + align-1)//align)*align
            s.sh.size = len(s.content)
            pos = s.sh.offset
        

# ELF object
class ELF(object):
    # API shared by all/most binary containers
    architecture = property(lambda _:elf.constants['EM'].get(_.Ehdr.machine,'UNKNOWN(%d)'%_.Ehdr.machine))
    entrypoint = property(lambda _:_.Ehdr.entry)
    sections = property(lambda _:_.sh)
    symbols = property(lambda _:_.getsectionbytype(elf.SHT_SYMTAB))
    dynsyms = property(lambda _:_.getsectionbytype(elf.SHT_DYNSYM))

    def __init__(self, elfstr = None, **kargs):
        self._virt = virt(self)
        if elfstr is None:
            # Create an ELF file, with default header values
            # kargs can supersede these default values
            self.wsize = kargs.get('wsize', 32)
            self.sex = kargs.get('sex', '<')
            self.Ehdr = elf.Ehdr(parent=self)
            self.Ehdr.ident = struct.pack("16B",
                0x7f,0x45,0x4c,0x46, # magic number, \x7fELF
                {32:1, 64:2}[self.wsize], # EI_CLASS
                {'<':1,'>':2}[self.sex],  # EI_DATA
                1, # EI_VERSION
                0, # EI_OSABI
                0, # EI_ABIVERSION
                0,0,0,0,0,0,0)
            self.Ehdr.version = 1
            self.Ehdr.type = kargs.get('e_type', elf.ET_REL)
            self.Ehdr.machine = kargs.get('e_machine', elf.EM_386)
            self.Ehdr.ehsize = self.Ehdr.bytelen
            self.sh = SHList(self)
            self.ph = PHList(self)
            elf_default_content(self, **kargs)
            return
        self.content = StrPatchwork(elfstr)
        self.parse_content()
        try:
            self.check_coherency()
        except ValueError:
            # Report the exception message in a way compatible with most
            # versions of python.
            import sys
            log.error(str(sys.exc_info()[1]))

    def get_virt(self):
        return self._virt
    virt = property(get_virt)

    def parse_content(self):
        h = struct.unpack("B"*8, self.content[:8])
        if h[:4] != ( 0x7f,0x45,0x4c,0x46 ): # magic number, \x7fELF
            raise ValueError("Not an ELF")
        self.wsize = h[4]*32
        self.sex   = {1:'<', 2:'>'} .get(h[5], '')
        if self.sex == '':
            log.error("Invalid ELF, endianess defined to %d", h[5])
        if not self.wsize in (32, 64):
            log.error("Invalid ELF, wordsize defined to %d", self.wsize)
            self.wsize = 32
        self.Ehdr = elf.Ehdr(parent=self, content=self.content)
        self.sh = SHList(self)
        self.ph = PHList(self)
    def resize(self, old, new):
        pass
    def __getitem__(self, item):
        return self.content[item]

    def build_content(self):
        if self.Ehdr.shoff == 0:
            elf_set_offsets(self)
        c = StrPatchwork()
        c[0] = self.Ehdr.pack()
        c[self.Ehdr.phoff] = self.ph.pack()
        for s in self.sh:
            c[s.sh.offset] = s.pack()
        sh = self.sh.pack()
        if len(sh):
            # When 'shoff' is invalid, 'sh' is empty, but the line below
            # is very slow because strpatchwork extends the file.
            c[self.Ehdr.shoff] = sh
        return c.pack()

    def check_coherency(self):
        if self.Ehdr.version != 1:
            raise ValueError("Ehdr version is %d instead of 1"%self.Ehdr.version)
        symtab_count, dynsym_count, hash_count = 0, 0, 0
        for sh in self.sh:
            if sh.sh.type == elf.SHT_SYMTAB:
                symtab_count += 1
            if sh.sh.type == elf.SHT_DYNSYM:
                dynsym_count += 1
            if sh.sh.type == elf.SHT_HASH:
                hash_count += 1
        if symtab_count > 1:
            raise ValueError("Has more than one (%d) sections SYMTAB"% symtab_count)
        if dynsym_count > 1:
            raise ValueError("Has more than one (%d) sections DYNSYM"% dynsym_count)
        if hash_count > 1:
            raise ValueError("Has more than one (%d) sections HASH"% hash_count)
        if self.Ehdr.shstrndx == elf.SHN_UNDEF:
            log.warning("No section (e.g. core file)")
        else:
            if self.Ehdr.shstrndx >= len(self.sh):
                raise ValueError("No section of index shstrndx=%d"%self.Ehdr.shstrndx)
            elif self.sh[self.Ehdr.shstrndx].sh.type != elf.SHT_STRTAB:
                raise ValueError("Section of index shstrndx is of type %d instead of %d"%(self.sh[self.Ehdr.shstrndx].sh.type, elf.SHT_STRTAB))
            elif self.sh[self.Ehdr.shstrndx].sh.name != '.shstrtab':
                raise ValueError("Section of index shstrndx[%d] is of name '%s' instead of '%s'"%(self.Ehdr.shstrndx, self.sh[self.Ehdr.shstrndx].sh.name, '.shstrtab'))

        skipable_section_types = [
        ]

        for sh1 in self.sh:
            # the section after BSS can overlap

            for sh2 in self.sh:
                if sh2.sh.type in skipable_section_types:
                    continue

                if sh1.sh.type != elf.SHT_NOBITS and sh2.sh.type != elf.SHT_NOBITS and \
                        (sh1.sh.offset < sh2.sh.offset < sh1.sh.offset + sh1.size or \
                         sh2.sh.offset < sh1.sh.offset < sh2.sh.offset + sh2.size):
                    raise ValueError("Section offset overlap for [%r] [%r]" % (sh1, sh2))

                if not sh1.addr or not sh2.addr:
                    continue

                if sh1.sh.flags & sh2.sh.flags & elf.SHF_ALLOC and \
                        (sh1.addr < sh2.addr < sh1.addr + sh1.size or \
                         sh2.addr < sh1.addr < sh2.addr + sh2.size):
                    raise ValueError("Section address overlap for [%r] [%r]" % (sh1, sh2))

    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        return self.build_content()

    def getsectionsbytype(self, sectiontype):
        return [s for s in self.sh if s.sh.type == sectiontype]
    def getsectionbytype(self, sectiontype):
        s = self.getsectionsbytype(sectiontype)
        if len(s) == 0: return ()
        return s[0]
    def getsectionsbyname(self, name):
        if ',' in name: name = name[:name.index(',')]
        return [s for s in self.sh if s.sh.name.strip('\x00') == name]
    def getsectionbyname(self, name):
        s = self.getsectionsbyname(name)
        if len(s) == 0: return None
        return s[0]

    def getsectionbyvad(self, ad, section = None):
        if section:
            s = self.getsectionbyname(section)
            if s.sh.addr <= ad < s.sh.addr + s.sh.size:
                return s
        sh = [ s for s in self.sh if s.addr <= ad < s.addr+s.size ]
        ph = [ s for s in self.ph if s.addr <= ad < s.addr+s.size ]

        if len(sh) == 1 and len(ph) == 1:
            # Executable returns a section and a PH
            if not sh[0] in ph[0].shlist:
                raise ValueError("Mismatch: section not in segment")
            return sh[0]
        if len(sh) == 1 and len(ph) > 1:
            # Executable may also return a section and many PH
            # e.g. the start of the .got section
            return sh[0]
        if len(sh) == 0 and len(ph) == 1:
            # Core returns a PH
            return ph[0]
        if len(ph) == 0 and len(sh) > 1:
            # Relocatable returns many sections, all at address 0
            # The priority given to .text is heuristic
            for s in sh:
                if s.sh.name == '.text':
                    return s
            for s in sh:
                if s.sh.name.startswith('.text'):
                    return s
            return sh[0]
        return None

    def has_relocatable_sections(self):
        return self.Ehdr.type == elf.ET_REL

    def is_in_virt_address(self, ad):
        for s in self.sh:
            if s.sh.addr <= ad < s.sh.addr + s.sh.size:
                return True
        return False

if __name__ == "__main__":
    import readline
    readline.parse_and_bind("tab: complete")

    fd = open("/bin/ls")
    try:
        raw = fd.read()
    finally:
        fd.close()
    e = ELF(raw)
    print (repr(e))
    #o = ELF(open("/tmp/svg-main.o").read())
