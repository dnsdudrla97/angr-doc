import angr, sys
def solve():
    p = angr.Project('./engine', auto_load_libs=False)
    state = p.factory.entry_state()

    sm = p.factory.simgr(state)

    sm.explore(find=0x401A0C, avoid=0x40137C)
    print(sm.found[0].posix.dumps(0))
    print(sm.found[1].posix.dumps(0))

    # sm.run(until = lambda sm_ : len(sm_.active) > 1)

    # act = sm.active
    # input_0 = sm.active[0].posix.dumps(0)
    # input_1 = sm.active[1].posix.dumps(0)

    # r = None

    # print(act)
    # print(input_0)
    # print(input_1)

def main():
    solve()


if __name__ == "__main__":
    main()

    # 0000000000001A0C
    # avoid -> 000000000000137C