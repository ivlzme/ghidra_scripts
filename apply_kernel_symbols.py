#!/usr/bin/env python3
# Apply kernel symbols by parsing the `__ksymtab`, `__ksymtab_gpl`, and 
# `__ksymtab_strings` sections
# TODO: API-style comments
# TODO: Only works for x86_64

from ghidra.program.model.data import PointerDataType

def apply_function_symbol(addr, symbol):
    print('Applying symbol for {} at 0x{}'.format(symbol, addr))
    # TODO: why are addresses so messed up on my test kernel?
    # TODO: implement

def find_symbol_sections(currentProgram):
    ksymtab = None
    ksymtab_gpl = None
    ksymtab_strings = None
    blocks = currentProgram.getMemory().getBlocks()
    for block in blocks:
        if block.getName() == '__ksymtab':
            ksymtab = block
        elif block.getName() == '__ksymtab_gpl':
            ksymtab_gpl = block
        elif block.getName() == '__ksymtab_strings':
            ksymtab_strings = block
    return ksymtab, ksymtab_gpl, ksymtab_strings

def read_pointer(addr):
    ptr = getDataAt(addr)
    # TODO: handle if data type is defined but not pointer (see Data.isPointer())
    if not ptr:
        ptr = createData(addr, PointerDataType.dataType)
    return ptr.getValue()

def read_string(addr):
    symbol = getDataAt(addr)
    # TODO: handle if data type is defined but not string
    if not symbol:
        symbol = createAsciiString(addr)
    return symbol.getValue()

def main():
    # Find ksymtab* sections
    state = getState()
    currentProgram = state.getCurrentProgram()
    ksymtab, ksymtab_gpl, ksymtab_strings = find_symbol_sections(currentProgram)

    # Initialize monitor for progress
    total_addrs = (ksymtab.getSize() + ksymtab_gpl.getSize()) / 8 # sizeof(pointer)
    monitor.initialize(total_addrs)

    # Iterate through the sections and apply strings
    # TODO: assumes __ksymtab always comes before __ksymtab_gpl
    addr_i = ksymtab.getStart()
    str_i = ksymtab_strings.getStart()
    count = 0
    while addr_i < ksymtab_gpl.getEnd() and str_i < ksymtab_strings.getEnd():
        address = read_pointer(addr_i)
        symbol = read_string(str_i)
        apply_function_symbol(address, symbol)

        # Advance
        addr_i = addr_i.addNoWrap(8) # sizeof(pointer)
        str_i = str_i.addNoWrap(len(symbol)+1)
        monitor.incrementProgress(1)
        count += 1

        # Allow script to be cancelled 
        monitor.checkCanceled()
    
    print('Applied {} symbols'.format(count))

if __name__ == "__main__":
    main()