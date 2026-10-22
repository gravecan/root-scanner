import struct
import re
import os

target = r'C:\Users\ginob\Downloads\Root.exe'
with open(target, 'rb') as f:
    buf = f.read()

print(f"Total file size: {len(buf)} bytes")

# Check for known packer / runtime signatures
signatures = {
    b'UPX!': 'UPX',
    b'Themida': 'Themida',
    b'WinLicense': 'WinLicense',
    b'VMProtect': 'VMProtect',
    b'Enigma': 'Enigma',
    b'PyInstaller': 'PyInstaller',
    b'MEI\x0c\x0b\x0a\x0b': 'PyInstaller archive',
    b'_MEI': 'PyInstaller extraction dir',
    b'PK\x03\x04': 'ZIP archive embedded',
    b'7z\xbc\xaf\x27\x1c': '7z archive embedded',
    b'electron.asar': 'Electron asar',
    b'corlib': '.NET corlib',
    b'mscorlib': '.NET mscorlib',
    b'System.Runtime': '.NET Core / 5+',
    b'go.buildid': 'Go binary',
    b'rustc': 'Rust binary',
    b'C:\\Users\\': 'Source path PDB / build user',
}

for sig, name in signatures.items():
    idx = 0
    count = 0
    while True:
        pos = buf.find(sig, idx)
        if pos == -1:
            break
        count += 1
        idx = pos + len(sig)
        if count == 1:
            print(f"Found signature '{name}' at offset 0x{pos:X}")
    if count > 1:
        print(f"  (Total occurrences of '{name}': {count})")

# Check imports
# Parse PE data directories
e_lfanew = struct.unpack_from('<I', buf, 0x3C)[0]
opt_magic = struct.unpack_from('<H', buf, e_lfanew + 24)[0]
if opt_magic == 0x20B: # PE32+
    import_rva, import_size = struct.unpack_from('<II', buf, e_lfanew + 24 + 112 + 8)
else:
    import_rva, import_size = struct.unpack_from('<II', buf, e_lfanew + 24 + 96 + 8)

print(f"Import Directory RVA: 0x{import_rva:X}, size: 0x{import_size:X}")

# Map RVA to file offset
num_sections = struct.unpack_from('<H', buf, e_lfanew + 6)[0]
opt_size = struct.unpack_from('<H', buf, e_lfanew + 20)[0]
sec_table_offset = e_lfanew + 24 + opt_size

sections = []
for i in range(num_sections):
    sec = buf[sec_table_offset + i*40 : sec_table_offset + (i+1)*40]
    name = sec[:8].rstrip(b'\x00').decode('latin1', errors='ignore')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', sec, 8)
    sections.append({'name': name, 'vsize': vsize, 'vaddr': vaddr, 'rawsize': rawsize, 'rawptr': rawptr})

def rva_to_offset(rva):
    for s in sections:
        if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
            return s['rawptr'] + (rva - s['vaddr'])
    return None

if import_rva:
    imp_off = rva_to_offset(import_rva)
    print(f"Import table file offset: 0x{imp_off:X}")
    dll_idx = 0
    while True:
        entry = buf[imp_off + dll_idx*20 : imp_off + (dll_idx+1)*20]
        orig_first_thunk, timedate, forwarder, name_rva, first_thunk = struct.unpack_from('<IIIII', entry, 0)
        if name_rva == 0:
            break
        name_off = rva_to_offset(name_rva)
        dll_name = buf[name_off:buf.find(b'\x00', name_off)].decode('latin1', errors='ignore')
        print(f"DLL: {dll_name}")
        dll_idx += 1
