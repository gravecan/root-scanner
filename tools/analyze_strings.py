import struct
import re

target = r'C:\Users\ginob\Downloads\Root.exe'
with open(target, 'rb') as f:
    buf = f.read()

def extract_strings(data, min_len=5):
    # ASCII
    ascii_re = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    for m in ascii_re.finditer(data):
        yield m.start(), m.group().decode('ascii', errors='ignore')
    # UTF-16LE
    utf16_re = re.compile(rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}')
    for m in utf16_re.finditer(data):
        yield m.start(), m.group().decode('utf-16le', errors='ignore')

# Scan .text and .rdata
print("Scanning .text and .rdata...")
text_rdata = buf[0x400 : 0x191A00 + 0x71800]

interesting = []
for off, s in extract_strings(text_rdata, min_len=6):
    # filter out generic noise
    s_lower = s.lower()
    if any(k in s_lower for k in ['root', 'scan', 'cheat', 'minecraft', 'clicker', 'autoclick', 'reach', 'killaura', 'vape', 'drip', 'inject', 'process', 'pid', 'window', 'journal', 'usn', 'prefetch', 'bam', 'shimcache', 'amcache', 'pcasvc', 'userassist', 'muicache', 'eventlog', 'github', 'discord', 'webhook', 'http', 'api', 'token', 'auth']):
        interesting.append((off, s))

print(f"Total interesting strings found in text+rdata: {len(interesting)}")
for off, s in interesting[:80]:
    print(f"0x{off:X}: {s}")

# Check .rsrc content types
rsrc_raw = buf[0x00B53800 : 0x00B53800 + 0x00707E00]
print(f"\n.rsrc size: {len(rsrc_raw)} bytes")
# Check for embedded PE, ZIP, PNG, etc.
magic_headers = {
    b'MZ': 'Embedded PE (EXE/DLL)',
    b'PK\x03\x04': 'ZIP archive',
    b'\x89PNG': 'PNG image',
    b'GIF89a': 'GIF image',
    b'\xff\xd8\xff': 'JPEG image',
    b'BM': 'BMP image',
    b'{\\rtf': 'RTF document',
    b'<?xml': 'XML document',
    b'{\n': 'JSON object',
    b'{"': 'JSON object',
}

for magic, desc in magic_headers.items():
    pos = 0
    while True:
        pos = rsrc_raw.find(magic, pos)
        if pos == -1:
            break
        print(f"Found {desc} in .rsrc at relative offset 0x{pos:X} (absolute: 0x{0x00B53800 + pos:X})")
        pos += len(magic)
        if desc == 'Embedded PE (EXE/DLL)':
            # let's only report first 5
            pass
        if pos > 0x100000 and desc in ['PNG image', 'JPEG image', 'BMP image']:
            print(f"  ... skipping further image hits")
            break
