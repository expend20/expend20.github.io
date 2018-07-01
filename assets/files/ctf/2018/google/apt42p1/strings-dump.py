#!/usr/bin/env python

from pwn import *
from struct import *
import sys
import re


# v5 = -2880579060539979662LL;
#   v3 = (_BYTE *)sub_40AC41();

#   for ( i = 5; i >= 0; i -= 4 )
#   {
#     v5 = 6364136223846793005LL * v5 + 1;
#     *(_DWORD *)&v3[4 * ((i >> 2)] = dword_40B257[i >> 2] ^ HIDWORD(v5);
#   }


def decryptNtp(initVal, multVal, initData, loopLen):

	outIdx2 = []

	mult = initVal

	for i in range(loopLen, -1, -4):

		mult = multVal * mult + 1
		mult &= 0xffffffffffffffff  

		idx2 = i >> 2

		r1 = unpack("<I", initData[idx2*4:idx2*4+4])[0]
		r2 = ((mult & 0xfffffffff00000000) >> 32)

		outIdx2.insert(0, r1 ^ r2)


	out = ''
	for i in outIdx2:
		out += pack("<I", i)

	return out


if __name__ == "__main__":


	e = ELF("./ntpdate")


	listData = open('list.txt', 'r').read() # 

	idx = 0

	for m0 in re.finditer("sub_(.*?)      proc near(.*?)sub_.*?      endp", listData, re.M + re.S): #

		for m in re.finditer("lea     rax, [a-z]+_([0-9A-Fa-f]+)\r\n.*?mov     rax, ([0-9A-Fa-f]+)h?.*?mov     \[rbp.*?\], ([0-9A-Fa-f]+)h?\r.*?mov     rax, ([0-9A-Fa-f]+)h?", m0.group(0), re.M + re.S):

			log.info(m.group(2))

			initVal = int(m.group(2).strip().strip('h'), 16)
			multVal = int(m.group(4).strip().strip('h'), 16)
			initDataAddr = int(m.group(1).strip().strip('h'), 16)
			initDataLen = int(m.group(3).strip().strip('h'), 16)

			initData = e.read(initDataAddr, initDataLen+4)

			log.info("initVal = 0x%x", initVal)
			log.info("multVal = 0x%x", multVal)
			log.info("initDataAddr = 0x%x", initDataAddr)
			log.info("initDataLen = 0x%x", initDataLen)

			d = decryptNtp(initVal, multVal, initData, initDataLen-1)
			d = d.split("\x00")[0]

			log.info("extracted: %s", d)

