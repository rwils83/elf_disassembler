# disas1.py

from elftools.elf.elffile import ELFFile
from capstone import *


with open('./chall.elf', 'rb') as f:
    elf = ELFFile(f)
    code = elf.get_section_by_name('.text')
    ops = code.data()
    addr = code['sh_addr']
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(ops, addr):
        print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}')
