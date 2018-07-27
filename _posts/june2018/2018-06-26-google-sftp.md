---
layout: post
title:  "[Google CTF:sftp] Randomized heap :D"
comments: true
---


# [Google CTF:sftp] Randomized heap :D

## The challenge. 

This is the [chall](https://ctftime.org/task/6237) from [google ctf](https://capturetheflag.withgoogle.com) named `sftp`. The task was relatively easy (60 solves), but I managed to fail it for the first time, and only with some hints from [@kaanezder](https://twitter.com/kaanezder) I got a clear understanding. Thanks, man!

>This file server has a sophisticated malloc implementation designed to thwart traditional heap exploitation techniques...

>sftp.ctfcompetition.com 1337

[Attachment](/assets/files/ctf/2018/google/sftp/sftp-1cae4cc41720386239e5c1e2c5ba0f24196637b25db6d3074c377b47f554a89d.zip)

## Let's try it.

Actually, the description is already given us a very straight hint, but let's just play with the file. The first thing is to guess password. In IDA we can see, that password is checked by hash:
```
  __printf_chk(1LL, "%s@%s's password: ", off_208B88);
  if ( !(unsigned int)__isoc99_scanf("%15s", &v5) )
    return 0LL;
  v3 = _IO_getc(stdin);
  LOWORD(v3) = v5;
  if ( !v5 )
    return 0LL;
  v4 = 0x5417;
  do
  {
    v3 ^= v4;
    ++v0;
    v4 = 2 * v3;
    LOWORD(v3) = *v0;
  }
  while ( (_BYTE)v3 );
  result = 1LL;
  if ( (_WORD)v4 != 0x8DFAu )
    return 0LL;
  return result; 
```

But the hash is only 2 bytes, so we can start brute force (if you do not find the origin password, there are huge chances to get collision):

```
#!/usr/bin/env python

from pwn import *
from struct import *


def hash(word):

	v4 = 0x5417
	v3 = 0

	for c in word:
		v3 = ord(c) ^ v4
		v4 = (v3 * 2) & 0xffff

		if v4 == 0x8DFA:
			log.info("got it! %s [%s]", word, c)
			exit(1)

	log.info("%s %x", word, v4)

for ps in open("../../../rockyou.txt", 'r').readlines():

	#log.info("%s" % ps)
	hash(ps) 
```

I've used `rockyou` dictionary, with only one exception: I check password after every character, not only after word. Ok, we found it, password = `Steve` (Corresponding entry in `rockyou` is `Steven`).

Also, you can notice, that you can input any symbols (0..255) not only printable ones. 

Ok, now we got in, and we can explore bugs in binary. There are plenty of them. First I tried to create a lot of directories. Binary was crashing randomly after 100..10000 tries. Then I create a directory and make `cd` to it, in a loop, the crash happened much earlier. Then you can simply type `cd /` and got crash right after it. It was all different bugs, but briefly analyzing them, you can see, that all of them is not really useful. There are no leaks, there are no possibilities of RIP control (well, at least I couldn't find any :D).

There is also sources file available as sftp:
```
Connected to sftp.google.ctf.
sftp> ls
flag
src
sftp> ls src
sftp.c
sftp> get src/sftp.c
14910
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
....
```
[sftp.c](/assets/files/ctf/2018/google/sftp/sftp.c)

Wow, we can analyze at sources level now. Sources are obviously no full, but they do match our binary file.

## Actual bug

Let's remember task description, there was something about `alloc()`, right? Hm... binary is exporting some memory relative functions:

![](/assets/files/ctf/2018/google/sftp/export.png)

* malloc():
```
signed __int64 malloc()
{
  return rand() & 0x1FFFFFFF | 0x40000000LL;
}
```

* realloc():
```
__int64 __fastcall realloc(__int64 a1)
{
  return a1;
}
```

* free():
```
void free()
{
  ;
}
```

Beautiful! If you would break in gdb at `rand()` you can confirm that all memory allocation is just a fiction, pointers are randomly picked up from mapped memory region, never free, and not changed at reallocation. 
```
Start              End                Perm	Name
0x40000000         0x60100000         rw-p	mapped
```

Now, the idea is to allocate memory, we will try to get overlapped chunks and make leaks from it. The size of mapped memory is not so small (>512MB). Btw, the binary is almost fully protected:
```
$ checksec sftp
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

## Exploiting.

Obviously, we need to allocate one (or small number) big chunk of memory and lots of small ones. The most suitable candidate for the big one is `put file` command, with maximum possible size:
```
#define file_max 65535
```

For the small chunks, I'll use `put file` also, but only with 8 bytes (to match pointer size on x64 platform). 

The idea is working, we can get a typical leak of binary structures:

![](/assets/files/ctf/2018/google/sftp/leak0.png)

This must be the structure `entry` and `file_entry` right after it. 

```
struct entry {
	struct directory_entry* parent_directory;
	enum entry_type type;
	char name[name_max];
};

struct file_entry {
	struct entry entry;

	size_t size;
	char* data;
};

```

Now we can overwrite data with `put` command on the big chunk, then read or write small chunk to get or set any memory of process that we want. Let's analyze the first pointer of the leaked structure. Actually, it points somewhere in `.bss` section. Since we put our files in root directory it must be the global variable `root`:

```
directory_entry* root = NULL;
```

Actually substructing 0x208be0 from this address we will get base of `sftp` image in memory. Now we can craft pointer to `.got.plt` section and read address to `libc`. Then we can overwrite pointer in `.got.plt` got get code execution. Briefly search of function candidates to overwrite, I saw that `strrchr()` is the perfect one, because it is called with the argument that we control. So we can simply write `mkdir sh` and `strrchr()` will be called with `sh` argument. We just need to change that pointer to get shell.

Here is [my sploit](/assets/files/ctf/2018/google/sftp/sftp-dbg.py) ;-)  






