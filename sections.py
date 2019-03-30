# sections.py
from elftools.elf.elffile import ELFFile


with open('./chall.elf', 'rb') as f:
    e = ELFFile(f)
    for section in e.iter_sections():
        print(hex(section['sh_addr']), section.name)
