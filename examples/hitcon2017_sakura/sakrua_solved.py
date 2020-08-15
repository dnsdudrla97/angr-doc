import angr
import os
import sys
from pwn import *

data = open("./sakura", "rb").read()

finds = []
avoids = []
index = 0
count = 0
while True:
    res = data.find(b"\xC6\x85\xB7\xE1\xFF\xFF\x00", index)
    # print(hex(res))
    if res == -1:
        break
    
    avoids.append(0x400000 + res)
    
    if count % 3 == 2:
        finds.append(0x400000 + res + 7)
        
    count += 1
    index = res + 1

p = angr.Project('./sakura')
state = p.factory.entry_state()

for find in finds:
    #print(hex(find))
    sm=p.factory.simgr(state)
    simgr.explore(find=find, avoid=avoids)
    state=simgr.found[0]
    # print(repr(state.posix.dumps(0)))

open("flag_input", 'wb').write(state.posix.dumps(0))



