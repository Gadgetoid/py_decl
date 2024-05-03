# Basic usage of py_decl.py *on* an RP2-based MicroPython board

from py_decl import PyDecl, MemoryReader

parser = PyDecl(MemoryReader(machine.mem8))

print(parser.parse())
