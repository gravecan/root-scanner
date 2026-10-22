import subprocess
import os

toolchain_bin = os.path.abspath(r'toolchain\w64devkit\bin')
objcopy = os.path.join(toolchain_bin, 'objcopy.exe')

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
    cmd = [
        objcopy,
        '-I', 'binary',
        '-O', 'pe-x86-64',
        '-B', 'i386:x86-64',
        src, dst
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Error on {src}:", res.stderr)
    else:
        print(f"Compiled {src} -> {dst} ({os.path.getsize(dst)} bytes)")

print("All asset object files compiled successfully!")
