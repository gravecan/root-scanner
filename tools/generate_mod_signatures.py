with open('categorized_strings.txt', 'r', encoding='utf-8', errors='ignore') as f:
    text = f.read()

keywords = [
    'vape', 'drip', 'slinky', 'doomsday', 'rise', 'antic', 'reach', 'aim',
    'click', 'velocity', 'fastplace', 'wtap', 'killaura', 'fly', 'timer',
    'mixin', 'vora', 'jnic', 'bloom', 'elyp', 'javainjector', 'pemapper',
    'nativeinjector', 'desirable', 'whoami', 'hitbox', 'agent'
]

signatures = []
for line in text.splitlines():
    if ': ' in line:
        addr, val = line.split(': ', 1)
        val = val.strip()
        low = val.lower()
        if any(p in low for p in keywords) and 3 <= len(val) <= 60:
            if not any(val.startswith(x) for x in ['http', '<', 'const ', '//', 'function', 'var ', 'let ', 'return', 'selectLanguage']):
                if not any(c in val for c in ['{', '}', ';', '?', '(', ')', '=']):
                    signatures.append(val)

unique = sorted(list(set(signatures)))
print(f"Total signatures: {len(unique)}")
with open('tools/mod_signatures.inc', 'w', encoding='utf-8') as out:
    for s in unique:
        # Escape quotes and backslashes
        esc = s.replace('\\', '\\\\').replace('"', '\\"')
        out.write(f'    "{esc}",\n')
print("Saved to tools/mod_signatures.inc successfully!")
