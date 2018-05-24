import subprocess, re

#output = subprocess.Popen(['ConsoleApplication2.exe < 1.txt'], stdout=subprocess.PIPE).communicate()[0]

out = [
"B80C91FE", "70573EFE",
"BEED92AE", "7F7A8193",
"7390C17B", "90347C6C",
"AA7A15DF", "AA7A15DF",
"526BA076", "153F1A32",
"545C15AD", "7D8AA463",
"526BA076", "FBCB7AA0",
"7D8AA463", "9C513266",
"526BA076", "6D7DF3E1",
"AA7A15DF", "9C513266",
"1EDC3864", "9323BC07",
"7D8AA463", "FBCB7AA0",
"153F1A32", "526BA076",
"F5650025", "AA7A15DF",
"1EDC3864", "B13AD888"]

class baby():

	def __init__(self):
		p1 = subprocess.Popen(["./babyre"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

		p1.stdin.write("111\n")
		p1.stdin.write("12\n")
		#p1.stdin.close()


		self.p1 = p1

	def check(self, s, idx):

		self.p1.stdin.write(s+"\n")
		self.p1.stdin.close()

		res = self.p1.stdout.read()

		res = re.search("your input:try again(.*?)your input:try again", res, re.M + re.DOTALL)

		res = res.group(1).splitlines()

		return res[idx]

		#print(res)
		#print(len(res))




flag = ""

for i in range(0, 30):

	for j in range(0, 0xff):

		#print("trying %s" % (flag + chr(j)))

		h = baby().check(flag + chr(j), i);

		#print("%s ? %s" %  (h, out[i].lower()))
		if h == out[i].lower():

			flag += chr(j)
			print("found %s, len = %d" % (flag, len(flag)))
			break

	#print("j done")

print(flag)