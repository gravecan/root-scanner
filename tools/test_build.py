import os
import subprocess
import sys

toolchain_bin = os.path.abspath(r'toolchain\w64devkit\bin')
os.environ['PATH'] = toolchain_bin + os.pathsep + os.environ['PATH']

cmd = [
    os.path.join(toolchain_bin, 'g++.exe'),
    '-std=c++17',
    '-Iwebview2_sdk/build/native/include',
    'test_wv2.cpp',
    '-o', 'test_wv2.exe'
]

print("Running:", " ".join(cmd))
res = subprocess.run(cmd, capture_output=True, text=True)
print("Return code:", res.returncode)
print("Stdout:", res.stdout)
print("Stderr:", res.stderr)

if res.returncode == 0:
    run_res = subprocess.run(['test_wv2.exe'], capture_output=True, text=True)
    print("Execution output:", run_res.stdout)
