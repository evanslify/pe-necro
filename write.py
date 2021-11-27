import math
import pefile
import mmap
import os
import reloc_build
import sys


def cal_size_of_raw_data(file_alignment, size):
    # return (((size + file_alignment - 1) / file_alignment) * file_alignment)
    return file_alignment * math.ceil(size / file_alignment)


def cal_virtual_size(size):
    return size


def align(size, file_alignment):
    return file_alignment * math.ceil(size / file_alignment)
    # return (((val_to_align + alignment - 1) / alignment) * alignment) + 1


def run(exe_path, reloc_path):
    pe = pefile.PE(exe_path)
    reloc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    if reloc.VirtualAddress:
        print("Reloc found in file! Skipping {}".format(exe_path))
        return

    payload = reloc_build.run(reloc_path, pe.OPTIONAL_HEADER.ImageBase)

    # print("[*] 0: Resize the Executable")
    original_size = os.path.getsize(exe_path)
    # print("\t[+] Original Size = %d, Payload Size = %d" % (original_size, len(payload)))
    fd = open(exe_path, 'a+b')
    _map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    _map.resize(original_size + 0x28 + len(payload))
    _map.flush()
    _map.close()
    fd.close()

    pe = pefile.PE(exe_path)
    # print("\t[+] New Size = %d bytes\n" % os.path.getsize(exe_path))

    # print("[*] 1: Add the New Section Header")

    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)

    # Look for valid values for the new section header
    raw_size = cal_size_of_raw_data(file_alignment, len(payload))
    virtual_size = cal_virtual_size(len(payload))

    raw_offset = int(align((pe.sections[last_section].PointerToRawData +
                        pe.sections[last_section].SizeOfRawData),
                    file_alignment))

    virtual_offset = int(align((pe.sections[last_section].VirtualAddress +
                            pe.sections[last_section].Misc_VirtualSize),
                        section_alignment))

    characteristics = 0x42000040
    # Section name must be equal to 8 bytes
    name = ".reloc" + (2 * '\x00')

    # Create the section
    # Set the name
    pe.set_bytes_at_offset(new_section_offset, name.encode('ascii'))
    # print("\t[+] Section Name = %s" % name)
    # Set the virtual size
    pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
    # print("\t[+] Virtual Size = %s" % hex(virtual_size))
    # Set the virtual offset
    pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
    # print("\t[+] Virtual Offset = %s" % hex(virtual_offset))
    # Set the raw size
    pe.set_dword_at_offset(new_section_offset + 16, raw_size)
    # print("\t[+] Raw Size = %s" % hex(raw_size))
    # Set the raw offset
    pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
    # print("\t[+] Raw Offset = %s" % hex(raw_offset))
    # Set the following fields to zero
    pe.set_bytes_at_offset(new_section_offset + 24, (b"\x00" * 12))
    # Set the characteristics
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)
    # print("\t[+] Characteristics = %s\n" % hex(characteristics))

    # STEP 0x03 - Modify the Main Headers
    # print("[*] 2: Modify the Main Headers")
    pe.FILE_HEADER.NumberOfSections += 1
    # print("\t[+] Number of Sections = %s" % pe.FILE_HEADER.NumberOfSections)
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
    # print("\t[+] Size of Image = %d bytes" % pe.OPTIONAL_HEADER.SizeOfImage)

    pe.write(exe_path)

    pe = pefile.PE(exe_path)
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1

    reloc_rva = pe.sections[last_section].VirtualAddress
    # print("\t[+] Relocation Directory RVA  = %s" % hex(reloc_rva))
    # print("\t[+] Relocation Directory Size = %s" % hex(len(payload)))

    pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size = len(payload)
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress = reloc_rva

    # print("[*] STEP 3: Inject the payload in the New Section")
    raw_offset = pe.sections[last_section].PointerToRawData
    if raw_size > len(payload):
        payload.extend(bytearray(raw_size - len(payload)))
    pe.set_bytes_at_offset(raw_offset, bytes(payload))
    print("\t[+] payload wrote in the new section {}".format(exe_path))
    pe.write(exe_path)


if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2])
