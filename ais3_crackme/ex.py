import angr
import claripy

proj = angr.Project('./ais3_crackme')

argv1 = claripy.BVS("argv1", 8*30)

state = proj.factory.entry_state(args=['./ais3_crackme', argv1])
simgr = proj.factory.simgr(state)

simgr.explore(find=lambda path: "Correct!" in path.state.posix.dumps(1))

s = simgr.found[0]
flag = s.solver.eval(argv1, cast_to = str)
print 'flag : ' + flag
