import angr
import sys

def solve1():
    p = angr.Project('./fauxware', auto_load_libs=False)
    state = p.factory.entry_state()
    sm = p.factory.simgr(state)
    print(sm)
    sm.run(until = lambda sm_: len(sm_.active) > 1)
    input_0 = sm.active[0].posix.dumps(0)
    input_1 = sm.active[1].posix.dumps(0)
    r = None
    print(input_0)
    print(input_1)

def solve2():
    p = angr.Project('./fauxware', auto_load_libs=False)
    state=p.factory.entry_state()
    sm=p.factory.simgr(state)
    sm.explore(find=0x4006F6, avoid=(0x4007CE, 0x4006E6))

    print(sm.found[0].posix.dumps(0))


def main():
    solve1()

if __name__ == "__main__":
    main()

