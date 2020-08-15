#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri
# Runtime: ~3 minutes

import angr

START_ADDR = 0x4007c2
FIND_ADDR = 0x404fab  # This is right before the printf

def main():
    proj = angr.Project('./angrybird')

    # 해당 바이너리에서 함수 부분을 우회 한다.
    state = proj.factory.entry_state(addr=START_ADDR)
    # 함수 프롤로그 변경
    state.regs.rbp = state.regs.rsp
    # 0x40의 길이 값
    state.mem[state.regs.rbp - 0x74].int = 0x40

    state.mem[state.regs.rbp - 0x70].long = 0x1000 # strncmp@got
    state.mem[state.regs.rbp - 0x68].long = 0x1008 # puts@got
    state.mem[state.regs.rbp - 0x60].long = 0x1010 # _stack_chk_fail@got
    state.mem[state.regs.rbp - 0x58].long = 0x1018 # _lib_start_main

    sm = proj.factory.simulation_manager(state)  # 시뮬레이션 생성
    sm.explore(find=FIND_ADDR)

    found = sm.found[-1]
    flag = found.posix.dumps(0)

    print(flag[:20])    

if __name__ == '__main__':
    main()
