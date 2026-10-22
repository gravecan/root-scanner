import os
import subprocess
import sys

toolchain_bin = os.path.abspath(r'toolchain\w64devkit\bin')
os.environ['PATH'] = toolchain_bin + os.pathsep + os.environ['PATH']
objcopy = os.path.join(toolchain_bin, 'objcopy.exe')
gxx = os.path.join(toolchain_bin, 'g++.exe')

# Step 1: Ensure inlined window HTML is generated
if not os.path.exists('ui/index.html'):
    print("Generating ui/index.html...")
    with open('dumped_resources/10_401_1033.bin', 'r', encoding='utf-8') as f:
        html = f.read()
    with open('dumped_resources/10_402_1033.bin', 'r', encoding='utf-8') as f:
        styles = f.read()
    with open('dumped_resources/10_403_1033.bin', 'r', encoding='utf-8') as f:
        native = f.read()
    with open('dumped_resources/10_404_1033.bin', 'r', encoding='utf-8') as f:
        app = f.read()
    html = html.replace('<link rel="stylesheet" href="./styles.css" />', f'<style>\n{styles}\n</style>')
    html = html.replace('<link rel="stylesheet" href="./native.css" />', f'<style>\n{native}\n</style>')
    html = html.replace('<script src="./app.js"></script>', f'<script>\n{app}\n</script>')
    os.makedirs('ui', exist_ok=True)
    with open('ui/index.html', 'w', encoding='utf-8') as f:
        f.write(html)

# Step 2: Ensure prebaked report template is generated
if not os.path.exists('ui/prebaked_report.html'):
    print("Generating ui/prebaked_report.html...")
    import base64
    with open('dumped_resources/3_9_1033.bin', 'rb') as f:
        icon_b64 = base64.b64encode(f.read()).decode()
    with open('dumped_resources/10_406_1033.bin', 'rb') as f:
        tree_b64 = base64.b64encode(f.read()).decode()
    with open('dumped_resources/10_301_1033.bin', 'r', encoding='utf-8') as f:
        template = f.read()
    prebaked = template.replace('@@ICON@@', icon_b64).replace('@@TREE_FRAMES@@', tree_b64)
    with open('ui/prebaked_report.html', 'w', encoding='utf-8') as f:
        f.write(prebaked)

# Step 3: Convert binary assets into COFF object files
assets = [
    ('ui/index.html', 'ui_index_html.o'),
    ('ui/prebaked_report.html', 'ui_report_template.o'),
    ('dumped_resources/10_302_1033.bin', 'backdrop_blob.o'),
    ('dumped_resources/10_201_1033.bin', 'font_regular.o'),
    ('dumped_resources/10_202_1033.bin', 'font_bold.o'),
    ('dumped_resources/10_203_1033.bin', 'font_semibold.o'),
    ('WebView2Loader.dll', 'wv2_loader_blob.o')
]

for src, dst in assets:
    if not os.path.exists(dst) or os.path.getmtime(src) > os.path.getmtime(dst):
        print(f"Embedding asset: {src} -> {dst}")
        cmd = [objcopy, '-I', 'binary', '-O', 'pe-x86-64', '-B', 'i386:x86-64', src, dst]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"Error on {src}:", res.stderr)
            sys.exit(1)

# Step 4: Compile native C++ sources and link with embedded assets
sources = [
    'src/main.cpp',
    'src/process_inspector.cpp',
    'src/memory_scanner.cpp',
    'src/bytecode_analyzer.cpp',
    'src/journal_forensics.cpp',
    'src/registry_forensics.cpp',
    'src/accounts_extractor.cpp',
    'src/report_generator.cpp'
]

asset_objects = [dst for _, dst in assets]
output_exe = 'Root.exe'

link_cmd = [
    gxx,
    '-std=c++17',
    '-O2',
    '-Iinclude',
    '-Iwebview2_sdk/build/native/include',
] + sources + asset_objects + [
    '-ldwmapi',
    '-lshell32',
    '-lshlwapi',
    '-ladvapi32',
    '-lole32',
    '-loleaut32',
    '-luuid',
    '-mwindows',
    '-o', output_exe
]

print("Compiling and linking native Root.exe...")
res = subprocess.run(link_cmd, capture_output=True, text=True)

if res.returncode == 0:
    size = os.path.getsize(output_exe)
    print(f"SUCCESS: {output_exe} compiled successfully! Size: {size} bytes ({size / (1024*1024):.2f} MB)")
else:
    print("BUILD FAILED!")
    if res.stderr:
        print("Stderr:", res.stderr)
    sys.exit(1)
