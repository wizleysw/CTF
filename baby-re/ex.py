import angr
import claripy

class scanf_hook(angr.SimProcedure):
	def run(self, fmt, ptr):
		self.state.mem[ptr].dword = vars[self.state.globals['scanf_count']]
		self.state.globals['scanf_count']+=1

proj = angr.Project('./baby-re')

vars = [claripy.BVS('%d' %i, 32) for i in range(13)]

proj.hook_symbol('__isoc99_scanf', scanf_hook(), replace=True)

simul_manager = proj.factory.simulation_manager()
simul_manager.one_active.options.add(angr.options.LAZY_SOLVES)
simul_manager.one_active.globals['scanf_count']=0

simul_manager.explore(find=0x402936, avoid=0x402946)

flag = 'flag : '

for x in vars:
	flag += chr(simul_manager.one_found.solver.eval(x))
print(flag)
