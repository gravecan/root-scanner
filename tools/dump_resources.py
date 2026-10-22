import struct
import os

target = r'C:\Users\ginob\Downloads\Root.exe'
with open(target, 'rb') as f:
    buf = f.read()

# Resource directory parser
e_lfanew = struct.unpack_from('<I', buf, 0x3C)[0]
opt_magic = struct.unpack_from('<H', buf, e_lfanew + 24)[0]
rsrc_rva, rsrc_size = struct.unpack_from('<II', buf, e_lfanew + 24 + (112 if opt_magic == 0x20b else 96) + 16)

# Find .rsrc section
num_sections = struct.unpack_from('<H', buf, e_lfanew + 6)[0]
opt_size = struct.unpack_from('<H', buf, e_lfanew + 20)[0]
sec_offset = e_lfanew + 24 + opt_size

rsrc_raw_ptr = None
for i in range(num_sections):
    sec = buf[sec_offset + i*40 : sec_offset + (i+1)*40]
    name = sec[:8].rstrip(b'\x00').decode('latin1', errors='ignore')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', sec, 8)
    if name == '.rsrc':
        rsrc_raw_ptr = rawptr
        rsrc_vaddr = vaddr
        break

print(f".rsrc RVA: 0x{rsrc_rva:X}, RawPtr: 0x{rsrc_raw_ptr:X}")

def rva_to_file_offset(rva):
    return rsrc_raw_ptr + (rva - rsrc_vaddr)

# Dump resources tree
# Type -> ID -> Language -> DataEntry
def parse_resource_dir(dir_offset, level=0):
    entries = []
    num_named = struct.unpack_from('<H', buf, dir_offset + 12)[0]
    num_id = struct.unpack_from('<H', buf, dir_offset + 14)[0]
    total = num_named + num_id
    for i in range(total):
        entry_off = dir_offset + 16 + i*8
        name_or_id, data_or_sub = struct.unpack_from('<II', buf, entry_off)
        is_sub = bool(data_or_sub & 0x80000000)
        sub_off = rsrc_raw_ptr + (data_or_sub & 0x7FFFFFFF)
        if name_or_id & 0x80000000:
            name_str_off = rsrc_raw_ptr + (name_or_id & 0x7FFFFFFF)
            length = struct.unpack_from('<H', buf, name_str_off)[0]
            name = buf[name_str_off+2 : name_str_off+2+length*2].decode('utf-16le', errors='ignore')
        else:
            name = name_or_id
        
        if is_sub:
            sub_res = parse_resource_dir(sub_off, level + 1)
            entries.append((name, sub_res))
        else:
            # Data entry: RVA, Size, CodePage, Reserved
            data_rva, data_sz = struct.unpack_from('<II', buf, sub_off)
            entries.append((name, (data_rva, data_sz, rva_to_file_offset(data_rva))))
    return entries

res_tree = parse_resource_dir(rsrc_raw_ptr)

# Flatten
flat_resources = []
def flatten_tree(node, path=[]):
    if isinstance(node, list):
        for k, v in node:
            flatten_tree(v, path + [str(k)])
    elif isinstance(node, tuple):
        flat_resources.append((path, node))

flatten_tree(res_tree)
print(f"Total resource entries: {len(flat_resources)}")
os.makedirs(r'C:\Users\ginob\Downloads\ee\dumped_resources', exist_ok=True)

for path, (rva, sz, foff) in flat_resources:
    res_bytes = buf[foff : foff + sz]
    preview = res_bytes[:32]
    path_str = "/".join(path)
    print(f"Res: {path_str:30s} | Size: {sz:8d} (0x{sz:X}) | Offset: 0x{foff:X} | Preview: {preview[:16]}")
    # Save large or interesting resources
    if sz > 1000 or any(p in path_str.lower() for p in ['html', 'js', 'json', 'data', '10', 'rcdata']):
        filename = "_".join(path).replace('/', '_')
        with open(os.path.join(r'C:\Users\ginob\Downloads\ee\dumped_resources', filename + '.bin'), 'wb') as rf:
            rf.write(res_bytes)
