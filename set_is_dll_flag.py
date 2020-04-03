#!/usr/bin/env python3

"""
Simple program to set the IMAGE_FILE_DLL* flag on Windows PE files (.exes, .dlls, etc...),
which will trick Windows into thinking the file is a .dll. 
This allows using LoadLibrary() on the file and calling the file's functions from a
separate program.

*https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
"""

import struct

def set_dll_flag(pe_path):
    # naive and simple implementation w/minimal checks. returns True on success; otherwise False

    # read the file's header
    f = open(pe_path, "rb+")
    first_chunk = f.read(0x1000)
    if not first_chunk.startswith(b"MZ"):
        print("[-] Not a PE file. Try using on a .exe file for example.")
        return False

    # parse the file's header

    offset_pe_header = 0x3c
    size_pe_header = 4
    offset_file_chars = 0x16
    size_file_chars = 2

    # find the PE header and calculate the file characteristics field address
    addr_file_characteristics = struct.unpack("<I", 
        first_chunk[offset_pe_header:offset_pe_header+size_pe_header])[0] + offset_file_chars

    # read the file characteristics field
    file_characteristics = struct.unpack("<H", 
        first_chunk[addr_file_characteristics:addr_file_characteristics+size_file_chars])[0]

    # turn on the IMAGE_FILE_DLL(0x2000) flag
    is_dll_file_flag_on = 0x2000
    file_characteristics |= is_dll_file_flag_on

    f.seek(addr_file_characteristics)
    f.write(struct.pack("<H", file_characteristics))
    f.close()
    return True

def main():
    import sys
    if (len(sys.argv) != 2):
        print(f"[-] Usage: {sys.argv[0]} <path to target PE>")
        return

    set_dll_flag(sys.argv[1])
    print("[+] Done")
    return

if __name__ == '__main__':
    main()