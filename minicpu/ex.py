from pwn import *

s = process('./minicpu')

bytecode  = ''
bytecode += '7d800002' # a2 + 0x10 => 2
bytecode += '7d300004' # a2 + 0x6 => 4
bytecode += 'f0abcdef' # read(0, buffer, 4); -> user input 'flag'
bytecode += '7d207ffc' # a2 + 0x6 => 7ffc
bytecode += 'f0abcdef' # read(0, buffer, 4); -> user input 'AAAA'
bytecode += '31800000' # a2 + 0x10 => 1
bytecode += 'f0abcdef' # open(flag) with fd 3
bytecode += '7d100003' # a2 + 0x2 => 3
bytecode += '7d300064' # a2 + 0x6 => 100
bytecode += '29800000' # a2 + 0x10 => 2
bytecode += 'f0abcdef' # read(3, flag_buffer, 100)
bytecode += '7d100001' # a2 + 0x2 => 1
bytecode += '29800000' # a2 + 0x10 => 3
bytecode += 'f0abcdef' # write(3, flag_buffer, 100)

s.recvuntil('Run\n')
s.sendline(bytecode)
s.send('flag')
s.send('AAAA')
flag = s.recv().replace('\x00','').replace('\x0a', '')
print flag

