import os
import subprocess
import sys

toolchain_bin = os.path.abspath(r'toolchain\w64devkit\bin')
os.environ['PATH'] = toolchain_bin + os.pathsep + os.environ['PATH']

sources = [
    'root_reconstructed/src/main.cpp',
    'root_reconstructed/src/process_inspector.cpp',
    'root_reconstructed/src/memory_scanner.cpp',
    'root_reconstructed/src/bytecode_analyzer.cpp',
    'root_reconstructed/src/journal_forensics.cpp',
    'root_reconstructed/src/registry_forensics.cpp',
    'root_reconstructed/src/accounts_extractor.cpp',
    'root_reconstructed/src/report_generator.cpp'
]

output_exe = 'Root.exe'

cmd = [
    os.path.join(toolchain_bin, 'g++.exe'),
    '-std=c++17',
    '-O2',
    '-Iroot_reconstructed/include',
    '-Iwebview2_sdk/build/native/include',
] + sources + [
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

print("Compiling native C++ Root.exe...")
print("Command:", " ".join(cmd))
res = subprocess.run(cmd, capture_output=True, text=True)

print("Return code:", res.returncode)
if res.stdout:
    print("Stdout:", res.stdout)
if res.stderr:
    print("Stderr:", res.stderr)

if res.returncode == 0:
    print(f"SUCCESS: {output_exe} compiled successfully!")
    stat = os.stat(output_exe)
    print(f"File size: {stat.st_size} bytes")
else:
    print("COMPILATION FAILED!")
