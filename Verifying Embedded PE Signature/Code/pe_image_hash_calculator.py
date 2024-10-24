import pefile
import hashlib
import sys

pe = pefile.PE(sys.argv[1], fast_load=True) 

# Extract Security directory
security_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]    

# CheckSum file offset
checksum_offset = pe.OPTIONAL_HEADER.dump_dict()['CheckSum']['FileOffset']  

# IMAGE_DIRECTORY_ENTRY_SECURITY file offset
certificate_table_offset = security_directory.dump_dict()['VirtualAddress']['FileOffset'] 

# Certificate section virtual address and size
certificate_virtual_addr = security_directory.VirtualAddress
certificate_size = security_directory.Size

# Read PE image file
raw_data = pe.__data__

# Skip OptionalHeader.CheckSum field and continue until IMAGE_DIRECTORY_ENTRY_SECURITY
buffer = raw_data[:checksum_offset] + raw_data[checksum_offset+0x04:certificate_table_offset]   

# Skip IMAGE_DIRECTORY_ENTRY_SECURITY and certificate if exist
if certificate_virtual_addr == 0 or certificate_size == 0:
    buffer += raw_data[certificate_table_offset+0x08:]
else:
    buffer += raw_data[certificate_table_offset+0x08:certificate_virtual_addr] + raw_data[certificate_virtual_addr+certificate_size:]   

# Digest of PE image file
print(f"MD5:\t {hashlib.md5(buffer).hexdigest()}")
print(f"SHA1:\t {hashlib.sha1(buffer).hexdigest()}")
print(f"SHA256:\t {hashlib.sha256(buffer).hexdigest()}")

