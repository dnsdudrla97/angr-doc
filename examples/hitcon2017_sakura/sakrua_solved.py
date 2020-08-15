import angr
from pwn import *
PATH='./sakura'

def main():
    global PATH
    data = open("./sakura", "rb").read()

    find_list = []
    avoid_list = []
    idx = 0
    cnt = 0

    while True:
        res = data.find(b"\xC6\x85\xB7\xE1\xFF\xFF\x00", idx)
        # print(hex(res))
        if res == -1:
            break
        
        avoid_list.append(0x400000 + res)
        
        if cnt % 3 == 2:
            find_list.append(0x400000 + res + 7)
            
        cnt += 1
        idx = res + 1

    p = angr.Project('./sakura')
    state = p.factory.entry_state()

    for find in find_list:
        #print(hex(find))
        sm=p.factory.simgr(state)
        sm.explore(find=find, avoid=avoid_list)
        state=sm.found[0]
        # print(repr(state.posix.dumps(0)))
        
    p=process(PATH)
    p.send(state.posix.dumps(0))
    flag = p.recvline()
    log.info(repr(flag))

if __name__ == "__main__":
    main()