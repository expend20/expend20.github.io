---
layout: post
title: "[InCTF:Kernel Reversing Part 2] NetBSD kernel module."
comments: true
---

![](/assets/files/ctf/2018/inctf/kernel2/logo.png)
* https://s3.us-east-2.amazonaws.com/inctfi/chall_final.tar.gz
* [orig link](https://ctf.inctf.in/challenges)
* [ctftime](https://ctftime.org/event/662/)

The function `check_flag()` is really interesting. First of all, it checks two values. That values should be set by `mmap()` and `write()` call to the driver device. Later that values will be `xor`ed with one another and the result would be actually checked in `check_flag()`. 

![](/assets/files/ctf/2018/inctf/kernel2/check_flag.png)

There are two magic values that we can bruteforce:

```
    if ( len_1 == 7
                * ((unsigned __int64)(((unsigned __int64)(len_1 - (0x2492492492492493LL * (unsigned __int128)len_1 >> 64)) >> 1)
                                    + (0x2492492492492493LL * (unsigned __int128)len_1 >> 64)) >> 2) )

...
    if ( (unsigned int)(need16 - 1) > 0x1F
      || (v28 + 2) * (v28 + 1) + ((v28 + 2) * (v28 + 1) - 1) * ((v28 + 2) * (v28 + 1) - 1) != 0x16C93 )

```

The python scripts.
```
#!/usr/bin/python

for v13 in xrange(1023):
    if v13 == 7 * ((((v13 - (0x2492492492492493 * v13 >> 64)) >> 1) + (0x2492492492492493 * v13 >> 64)) >> 2):
        print v13 
```
and
```
#!/usr/bin/python

for v33 in xrange(1023):
    if (v33 + 2) * (v33 + 1) + ((v33 + 2) * (v33 + 1) - 1) * ((v33 + 2) * (v33 + 1) - 1) == 93331:
        print v33 
```

Will give results `7*x` for the first, and `16` for the second. So the password length should be a power of 7.

Now we should reverse engineer whole function and write a solver. We can actually debug it with GDB, orgs are provided us with a very useful intro to debugging.

```
#!/usr/bin/env python

rev = "#v(2fx]PJZF[wY48E=,5hyAkL>s3?m|~;pS_WNgIjOuU0Q.$G7+eCl^d1rq9XKDa)':BcHn&zTob}<Mi*!R{6t-V"

out = ''


for chrToFind, carry in zip('bios{1}', [-1, 0, 0, -1, 0, -1, 0]):

	idx = rev.find(chr(ord(chrToFind) - 16)) + carry

	strbin = bin(idx)

	toPrint = strbin.replace("b", "").replace("0", "`").replace("1", "c")
	toPrint = toPrint.rjust(8, '`')[1:]

	print("[%s:%s:%d/%x] %s" % (chrToFind, chr(ord(chrToFind) - 16), idx, idx, toPrint))

	out += toPrint

print("out: %s" % out)

```

The final code will look like this.

```
#include <sys/cdefs.h>
#include <err.h> 
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/mman.h>

#define _PATH_DEV_MAPPER "/dev/chall2"

int main(int argc, char **argv)
{
        int devfd;
        char *buf;
        char *p;
        int i;


        buf = malloc(50);

        if ((devfd = open(_PATH_DEV_MAPPER, O_RDWR)) == -1)
                err(EXIT_FAILURE, "Cannot open %s", _PATH_DEV_MAPPER);

        for (i = 0; i < 16; i++){
                ioctl(devfd, 0x20004B01);
        }

        p = mmap(0, 50, PROT_READ + PROT_WRITE, 0, devfd, 0);
        strcpy(p, "c`c```c```cc`c`c```ccc````cc``c`cccc`c``````ccc`c"); 
        write(devfd, "\x01", 1);
        
        ioctl(devfd, 0x20004B02, "1234567", 7);

        read(devfd, buf, 100);
        printf("%s", buf);
        if (close(devfd) == -1)
                err(EXIT_FAILURE, "Cannot close %s", _PATH_DEV_MAPPER);

        return EXIT_SUCCESS;
}

```
