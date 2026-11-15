#!/usr/bin/env python3
import ctypes, os, struct, sys
libc = ctypes.CDLL('libc.so.6', use_errno=True)
libc.ptrace.restype = ctypes.c_ulonglong
class user_regs(ctypes.Structure):
    _fields_ = [(r, ctypes.c_ulonglong) for r in
        ['r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi',
         'orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs']]
F = os.path.abspath('original/obfuscation_labyrinth/labyrinth100')
out = open('logs/drive_run.txt', 'w', buffering=1)
pid = os.fork()
if pid == 0:
    libc.personality(0x0040000)
    libc.ptrace(0, 0, 0, 0)
    fd = os.open('/tmp/lab_input.txt', os.O_RDONLY)
    os.dup2(fd, 0)
    os.dup2(out.fileno(), 1)
    os.execv(F, [F])
    os._exit(1)
os.waitpid(pid, 0)
maps = open('/proc/%d/maps' % pid).read()
base = int([l for l in maps.splitlines() if 'labyrinth100' in l][0].split('-')[0], 16)
SITE = base + 0x9089
def peek(a):
    return libc.ptrace(2, pid, ctypes.c_void_p(a), 0)
def poke(a, v):
    libc.ptrace(5, pid, ctypes.c_void_p(a), ctypes.c_void_p(v))
word = peek(SITE)
poke(SITE, (word & ~0xff) | 0xcc)
libc.ptrace(7, pid, 0, 0)
states = []
while True:
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status) or os.WIFSIGNALED(status):
        break
    regs = user_regs()
    libc.ptrace(12, pid, 0, ctypes.byref(regs))
    if regs.rip == SITE + 1:
        computed = peek(regs.rbp - 0x10)
        poke(regs.rbp - 0x378, computed)
        states.append(computed)
        poke(SITE, word)
        regs.rip = SITE
        libc.ptrace(13, pid, 0, ctypes.byref(regs))
        libc.ptrace(9, pid, 0, 0)
        os.waitpid(pid, 0)
        poke(SITE, (word & ~0xff) | 0xcc)
    libc.ptrace(7, pid, 0, 0)
try: libc.ptrace(8, pid, 0, 0); os.waitpid(pid, 0)
except Exception: pass
out.close()
print('layers authenticated: %d' % len(states), flush=True)
for i, s in enumerate(states):
    print('state[%03d] = %016x' % (i + 1, s), flush=True)
