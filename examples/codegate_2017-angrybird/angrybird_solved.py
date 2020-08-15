import angr

def solved():
    p=angr.Project('./angrybird_3', auto_load_libs=False)
    state = p.factory.blank_state(addr=0x4007C2)

    sm = p.factory.simgr(state)
    sm.explore(find=0x404fab)

    flag = sm.found[0].posix.dumps(0)
    print(flag[:20])
  
# def NoPatch():


def main():
    solved()



if __name__ == "__main__":
    main()

