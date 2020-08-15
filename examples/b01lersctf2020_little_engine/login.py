# coding: utf-8
import angr
import claripy
import time


def get_id():

    p=angr.Project('./login', auto_load_libs=False)
    state = p.factory.entry_state()
    sm = p.factory.simgr(state)
    sm.explore(find=0x4021D4, avoid=(0x4021A2))

    sm.found


def main():
    get_id()

if __name__ == "__main__":
    main()
    