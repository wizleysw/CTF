import angr

proj = angr.Project('./very_success')

state = proj.factory.blank_state(addr=0x401084)

state.mem[state.regs.esp+8:].dword = 0x402159
state.mem[state.regs.esp+4:].dword = 0x4010e4
state.mem[state.regs.esp:].dword = 0x401064

state.memory.store(0x402159, state.solver.BVS("pwnwiz", 8*40))

simgr = proj.factory.simgr(state)
simgr.explore(find=0x40106b, avoid=0x401072)

s = simgr.found[0]
flag = s.solver.eval(s.memory.load(0x402159,40), cast_to=str).strip('\0')
print 'flag : ' + flag

