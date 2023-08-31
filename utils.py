import struct
from capstone import *
from keystone import *

NOP = b"\x90"
PREFIX = "let sc = ["
POSTFIX = "];\n"

def tod(data):
    data = data.ljust(8, b"\x90")
    assert len(data) == 8
    return struct.unpack('<d', data)[0]

def tol(data):
    assert len(data) == 8
    return str(struct.unpack('<Q', data)[0]) + "n"

def tof(data):
    assert len(data) == 4
    return struct.unpack('<f', data)[0]

def PrintShellCode(buf, arch, mode):  
    buf = buf.ljust(len(buf) + 8 - (len(buf)%8), NOP)
    op = tod
    step = 8

    if mode == "wasm":
        op = tol
    if mode == "jit" and arch == 32:
        op = tof
        step = 4

    print(PREFIX)
    for i in range(0, len(buf), step):
        print(f'''  {op(buf[i:i+step])},''')
    print(POSTFIX)

buf1 =  b"\x90\x90\x90\x90\x90\x90"

# test
PrintShellCode(buf1, 64, "jit")
PrintShellCode(buf1, 32, "jit")
PrintShellCode(buf1, 64, "wasm")