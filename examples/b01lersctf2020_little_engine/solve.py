#!/usr/bin/env python
# coding: utf-8
import angr
import claripy
import time

#compiled on ubuntu 18.04 system:
#https://github.com/b01lers/b01lers-ctf-2020/tree/master/rev/100_little_engine

def main():
    #프로그램에서 사용되는 주소 설정
    #기본 주소를 가정한다.
    base_addr = 0x400000

    #원하는 입력의 길이는 ghidra 에서 이진수를 반대로 하여 75이다.
    #실제 배열은 크기의 4배이므로 해당 크기에 4배를 추가해야 한다.
    #첫 번째 입력에 1바이트 추가
    input_len = 1+75*4

    #angr 프로젝트 설정
    p = angr.Project('./engine', main_opts={'base_addr': base_addr})

    # 코드/바이너리를 보면 입력 문자열이 22 바이트를 채울 것으로 예상된다는 것을 알 수 있다.
    # 따라서 8바이트 기호 크기이며 이진법의 제약 조건을 찾을 수 있기를 바란다.
    # 실행 중 예상
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]

    # 첫 번째 입력을 위해 추가 \n 다음 플래그를 찾는다.
    # Claripy.Concat -> 여러 비트 표현식을 함께 새로운 비트 표현식으로 연결한다.
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

    # 좀더 빠르고 효율적인 해결을 위해 유니콘 엔진 활성화
    st = p.factory.full_init_state(
            args=['./engine'],
            add_options=angr.options.unicorn,
            stdin=flag
           )

    # 줄 바꿈이 아닌 바이트로 제한 (0x20)
    # ASCII 전용 문자로 제한 (0x7F)
    for k in flag_chars:
        st.solver.add(k < 0x7f)
        st.solver.add(k > 0x20)

    # SMGR 실행
    # step
    sm = p.factory.simulation_manager(st)
    sm.run()

    # stdout에 win 함수 출력이 있는 모든 완료된 상태를 가져온다.
    y = []
    for x in sm.deadended:
        if b"Chugga" in x.posix.dumps(1):
            y.append(x)

    # 첫 번째 출력 가져오기
    valid = y[0].posix.dumps(0)

    # 구문 분석하고 최종 플래그 건환
    bt = [ chr(valid[i]) for i in range(0,len(valid),2)]
    flag = ''.join(bt)[1:76]
    return flag

def test():
    assert main() == "pctf{th3_m0d3rn_st34m_3ng1n3_w45_1nv3nt3d_1n_1698_buT_th3_b3st_0n3_in_1940}"

if __name__ == "__main__":
    before = time.time()
    print(main())
    after = time.time()
    print("Time elapsed: {}".format(after - before))
