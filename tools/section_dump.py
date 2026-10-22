import struct
import math

target = r'C:\Users\ginob\Downloads\Root.exe'
with open(target, 'rb') as f:
    buf = f.read()

def entropy(data):
    if not data:
        return 0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    ent = 0
    l = len(data)
    for c in freq:
        if c > 0:
            p = c / l
            ent -= p * math.log2(p)
    return ent

e_lfanew = struct.unpack_from('<I', buf, 0x3C)[0]
time_stamp = struct.unpack_from('<I', buf, e_lfanew + 8)[0]
num_sections = struct.unpack_from('<H', buf, e_lfanew + 6)[0]
opt_size = struct.unpack_from('<H', buf, e_lfanew + 20)[0]
entry_point = struct.unpack_from('<I', buf, e_lfanew + 40)[0]
image_base = struct.unpack_from('<Q', buf, e_lfanew + 48)[0]
sec_table_offset = e_lfanew + 24 + opt_size

print(f"Timestamp: {hex(time_stamp)}")
print(f"Entry Point RVA: 0x{entry_point:X}")
print(f"Image Base: 0x{image_base:X}")

sections = []
for i in range(num_sections):
    sec = buf[sec_table_offset + i*40 : sec_table_offset + (i+1)*40]
    name = sec[:8].rstrip(b'\x00').decode('latin1', errors='ignore')
    vsize, vaddr, rawsize, rawptr, _, _, _, _, chars = struct.unpack_from('<IIIIIIII', sec, 8) + (struct.unpack_from('<I', sec, 36)[0],)
    sec_data = buf[rawptr : rawptr + rawsize]
    ent = entropy(sec_data)
    print(f"Section {name:8s} | VAddr: 0x{vaddr:08X} | VSize: 0x{vsize:08X} | RawPtr: 0x{rawptr:08X} | RawSize: 0x{rawsize:08X} | Chars: 0x{chars:08X} | Entropy: {ent:.3f}")
