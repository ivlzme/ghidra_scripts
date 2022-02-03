# Extract a partial Module.symvers from a decompressed Linux kernel (vmlinux.bin)
#
# @author ivlzme
# @category symbol

def read_data_at(addr, data_type):
    """
    Read the datatype at a given addr. If the addr is undefined data, define it. If the data is defined, clear it and
    redefine it

    @param :addr: Program address to read data (ghidra.program.model.address.Address)
    @param :data_type: Type of data to read at addr (ghidra.program.model.data.DataType)
    @return the value of the read data
    """
    dt = getDataAt(addr)
    if dt is None:
        # Undefined data; define it!
        dt = createData(addr, data_type)
    elif str(dt.toString()) != str(dt.toString()):
        # Defined it; redefine it!
        removeData(addr)
        dt = createData(addr, data_type)
    return dt.getValue()

def find_byte_str(bstr, start_addr=None):
    """
    Search program for first occurrence of a byte string

    @param :bstr: Python byte string to search for
    @param :start_addr: Address to start searching at (defaults to program start address)
    @return Address of found byte string (ghidra.program.model.address.GenericAddress)
    """
    if not start_addr:
        start_addr = currentProgram,getMinAddress()
    return findBytes(start_addr, bstr)

def find_str(str, start_addr=None):
    """
    Search program for first occurrence of a null-terminated ASCII string. Use findBytes under-the-hood since
    FlatProgramAPI.findStrings only finds defined strings :/

    @param :str: Python string to search for
    @param :start_addr: Address to start search at (defaults to program start address)
    """
    bstr = str.encode(str) + b'\x00'
    return find_byte_str(bstr, start_addr)

def find_addr(addr, start_addr=None):
    """
    Search program for first occurrence of a addresa value.

    @param :addr: Address value to search for (ghidra.program.model.address.Address)
    @param :start_addr: Address to start search at (defaults to program start address)
    """
    # TODO: 32-bit LE only
    bstr = struct.pack('<I', addr.getUnsignedOffset())
    return find_byte_str(bstr, start_addr)

def get_section(name):
    """
    Iterate through program sections and retrieve a memory block by name

    @param :name: Name of the section to find
    @return Memory block (ghidra.program.model.mem.MemoryBlock) of corresponding section
    """
    for block in currentProgram.getMemoryBlocks():
        if block.getName() == name:
            return block
    return None

def main():
    """
    Main driver function
    """
    currentProgram.setImageBase(toAddr(IMAGE_BASE), True)


if __name__ == "__main__":
    main()
