import re

target = r'C:\Users\ginob\Downloads\Root.exe'
with open(target, 'rb') as f:
    buf = f.read()

# Search across all strings in the binary
def get_all_strings(data, min_len=4):
    for m in re.finditer(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', data):
        yield m.start(), m.group().decode('ascii', errors='ignore')
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}', data):
        yield m.start(), m.group().decode('utf-16le', errors='ignore')

# Dump all unique strings from the binary into categories
strings = list(get_all_strings(buf, min_len=4))
print(f"Total strings extracted: {len(strings)}")

categories = {
    'modules': [],
    'cheats_detected': [],
    'jvm_class_analysis': [],
    'memory_injection_rules': [],
    'usn_fs_rules': [],
    'event_log_rules': [],
    'registry_rules': [],
    'network_web_api': [],
    'ui_callbacks': [],
}

cheat_keywords = [
    'vape', 'drip', 'doomsday', 'koid', 'slinky', 'breeze', 'antic', 'haru',
    'reach', 'autoclicker', 'clicker', 'killaura', 'aimassist', 'velocity',
    'fastplace', 'wtap', 'esp', 'nametags', 'fly', 'speed', 'timer',
    'injector', 'pemapper', 'jni', 'jvm', 'agent', 'attach', 'javassist',
    'bytebuddy', 'asm', 'mixin', 'spongepowered', 'minecraft'
]

for off, s in strings:
    sl = s.lower()
    if any(k in sl for k in ['root', 'scanner', 'window.root', 'webview', 'setstatus', 'updateprogress']):
        categories['ui_callbacks'].append((off, s))
    if any(k in sl for k in ['usn', 'mft', 'journal', '$j', '$max', 'fsctl_']):
        categories['usn_fs_rules'].append((off, s))
    if any(k in sl for k in ['eventlog', 'wevt', 'evtx', 'pcasvc', 'service', '7045', 'system.evtx', 'security.evtx']):
        categories['event_log_rules'].append((off, s))
    if any(k in sl for k in ['bam', 'shimcache', 'appcompat', 'userassist', 'muicache', 'currentversion', 'run']):
        categories['registry_rules'].append((off, s))
    if any(k in sl for k in ['http', 'api/', 'discord', 'webhook', 'token', 'auth', 'license', 'github']):
        categories['network_web_api'].append((off, s))
    if any(k in sl for k in ['classloader', 'defineclass', 'findclass', 'bytecode', 'javassist', 'agent', 'mixin', 'transform', 'constantpool']):
        categories['jvm_class_analysis'].append((off, s))
    if any(k in sl for k in ['virtualalloc', 'createremotethread', 'writeprocessmemory', 'readprocessmemory', 'ntquery', 'peb', 'vad', 'executable memory', 'allocated']):
        categories['memory_injection_rules'].append((off, s))
    if any(k in sl for k in cheat_keywords):
        categories['cheats_detected'].append((off, s))

with open(r'C:\Users\ginob\Downloads\ee\categorized_strings.txt', 'w', encoding='utf-8') as out:
    for cat, items in categories.items():
        out.write(f"\n=================== {cat.upper()} ({len(items)}) ===================\n")
        # Deduplicate while preserving order
        seen = set()
        for off, s in items:
            s_clean = s.strip()
            if s_clean not in seen and len(s_clean) > 3:
                seen.add(s_clean)
                out.write(f"0x{off:08X}: {s_clean}\n")

print("Categorization complete! Saved to categorized_strings.txt")
