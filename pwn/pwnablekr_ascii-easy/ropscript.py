#!/usr/bin/env python3
from ropper import RopperService

def are_bytes_printable(num):
    for x in range(0, 4):
        byte = (num >> x * 8) & 0xFF
        if byte < 0x20 or byte > 0x7f:
            return False
    return True


options = {'color': False, 'all': True, type: 'all'}

rs = RopperService(options) 
rs.addFile('libc-2.15.so')
rs.loadGadgetsFor()

gadgets = rs.getFileFor(name='libc-2.15.so').gadgets
printable = [gadget for gadget in gadgets if are_bytes_printable(gadget.address + 0x5555e000)]

for gadget in printable:
    print(gadget)
