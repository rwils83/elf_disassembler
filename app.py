#!/usr/bin/env python3

# sections.py
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import *
import argparse
import sys

description="An elf based disassembler"


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit()
        

def sections(file):
    with open(file, 'rb') as f:
        e = ELFFile(f)
        for section in e.iter_sections():
            print(hex(section['sh_addr']), section.name)


def disassemble(file):
    with open(file, 'rb') as f:
        elf = ELFFile(f)
        code = elf.get_section_by_name('.text')
        ops = code.data()
        addr = code['sh_addr']
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(ops, addr):
            print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}')


def relocations(file):
    with open(file, 'rb') as f:
        e = ELFFile(f)
        for section in e.iter_sections():
            if isinstance(section, RelocationSection):
                print(f'{section.name}:')
                symbol_table = e.get_section(section['sh_link'])
                for relocation in section.iter_relocations():
                    symbol = symbol_table.get_symbol(relocation['r_info_sym'])
                    addr = hex(relocation['r_offset'])
                    print(f'{symbol.name} {addr}')


def parse_args():
    description = "A python based ELF disassembler."    
    parser =MyParser()
    parser.add_argument("-s", "--sections",action="store",help="Show sections of selected file. Usage: /.app.py -s/--sections [FILENAME]")
    parser.add_argument("-d", "--disassemble",action="store", help="Disassemble selected file. Due to large volume of output, pipe to less! Usage: /.app.py -d [FILENAME]|less")
    parser.add_argument("-r", "--relocations",action="store", help="Show relocations of selected file. Usage: /.app.py -r/--relocations [FILENAME]")
    args= parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()

    if args.sections:
        sections(args.sections)

    if args.disassemble:
        disassemble(args.disassemble)

    if args.relocations:
        relocations(args.relocations)



