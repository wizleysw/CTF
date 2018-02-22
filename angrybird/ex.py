import angr
 
FIND_ADDR = 0x404FAB
MAIN_START = 0x4007B8
 
p = angr.Project('./angrybird4')
start = p.factory.blank_state(addr=MAIN_START)
pg = p.factory.path_group(start)
pg.explore(find=FIND_ADDR)
found = pg.found[0]
print found.state.posix.dumps(0)
