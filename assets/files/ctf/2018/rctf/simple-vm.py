import subprocess, re


def checkIdx(s):

	p1 = subprocess.Popen(["ConsoleApplication2.exe"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

	p1.stdin.write(s)
	p1.stdin.close()


	res = p1.stdout.read()
	print(res)

	r = re.search('\[(\d+)\]', res)

	return int(r.group(1))


tail = ''
head = '0000000000000000000000000000000'


idx = 1
while idx < 33:

	for i in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789':


		s = head + i + tail

		print('try %s...' % s)

		r = checkIdx(s)

		if idx != r:

		 	print("found: %s (idx = %d, r = %d)" % (s, idx, r))
		 	idx += 1
		 	
		 	head = head[:-1]
		 	tail = i + tail
		 	break




# Input Flag:09a71bf084a93df7ce3def3ab1bd61f6
# Right
