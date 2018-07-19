import angr

project = angr.Project('./r100')
state = project.factory.entry_state()
simgr = project.factory.simgr(state)

simgr.explore(find=0x400849)
s = simgr.found[0]
exploit = s.posix.dumps(0)[0:12]
print 'Found : ' + exploit

