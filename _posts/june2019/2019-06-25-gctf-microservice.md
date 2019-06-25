---
layout: post
title: "[gCTF: MicroServiceDaemonOS] Reversing and exploiting ELF file."
comments: true
---


![](https://i.imgur.com/u72ANH6.png)

* [orig file](https://storage.googleapis.com/gctf-2019-attachments/20b9f783720a27550432c6bbb2bd89b34ccfd47c35767ec2a6be1957d4f6da14), [backup](/assets/files/ctf/2019/google/MicroServiceDaemonOS)
* [orig link](https://capturetheflag.withgoogle.com/)
* [ctftime](https://ctftime.org/event/809)

Hey folks, it's been a while since my last write-up. Let's fix this :) In last weekend I was playing google ctf, this task actually took me a day and a half. Let me walk you through my journey.

44 teams managed to solve it. Is that number big or small? Well, this means the challenge is quite easy for the event with maximum score weight. Also it's been 2 days since the end of the ctf and no one published the write-up yet. I know how frustrating it could be, when you spend day or more to solve the task, fail in the end, and no one publish the write-up, so you can't improve your skills.

I backup the binary in the header of this post, you could try yours skills before further reading.

# first glance

Before popping a disassembler I usually check `strace`/`ltrace` log and briefly check the functionality of an app. In this case `ltrace` reveals a lot of `mprotect` calls and reading from `/dev/urandom`. The application is not quite talkative, you can't even check it's features without reversing it.

![](https://i.imgur.com/Ljt60OP.png)

Btw, usually `checksec` output is quite representative, but it is kind of misleading in this case, because it shows `no canary`, and that's why I focused on searching stack overflow vulnerability. But (you will see) that the challenge is not about stack overflow.

![](https://i.imgur.com/QFWfyf5.png)

# digging into...

So, let's reverse it. I'll skip the boring part, and just summarize what it does. This part heavily depends on your toolset and practical skills. I guess it can take up to several hours in average to fully understand what the program does.

* You have two options from main menu. The first option is `l` another is `c`. `l` is creating the "microservice", and `c` is running it. You can create up to 10 microservices. You can't modify them (without exploiting), once they have created.
* When you create "microservice" you set up it's type. It can be `0` or `1`. Each "microservice" has two "features". The "microservice" with type `0` has xoring and kind of rc4 functionality, and the `1` type has code for Murmur hashing and the code for just filling memory with `1` byte values.
* Each "microservice" has dedicated memory. Each "microservice" has memory on the stack and on the globally allocated memory. The globally allocated memory has chunks of size 0x8000000 for each "microservice" (0x8000000 * 10 = 0x50000000 in total). The first 0x4000 bytes of each chunk containing executable code for first "feature", the second 0x4000 bytes contains the code for the second "feature", the other data is reserved for using by "features" code.

# the first and the last vulnerability

All user's input is carefully filtered except only one place. This place is "offset" input for rc4 related "feature". Let's pop a crash.

```
'Welcome to MicroServiceDaemonOS\n'
'Provide command: '
[DEBUG] Sent 0x2 bytes:
'l\n'
[DEBUG] Received 0x1a bytes:
'Provide type of trustlet: '
[DEBUG] Sent 0x2 bytes:
'1\n'
[DEBUG] Received 0x11 bytes:
'Provide command: '
[DEBUG] Sent 0x2 bytes:
'l\n'
[DEBUG] Received 0x1a bytes:
'Provide type of trustlet: '
[DEBUG] Sent 0x2 bytes:
'1\n'
[*] Paused (press any to continue)
[DEBUG] Received 0x11 bytes:
'Provide command: '
[DEBUG] Sent 0x2 bytes:
'c\n'
[DEBUG] Received 0x15 bytes:
'Provide index of ms: '
[DEBUG] Sent 0x2 bytes:
'0\n'
[DEBUG] Received 0xb bytes:
'Call type: '
[DEBUG] Sent 0x2 bytes:
's\n'
[DEBUG] Received 0x13 bytes:
'Provide data size: '
[DEBUG] Sent 0x3 bytes:
'64\n'
[DEBUG] Received 0x15 bytes:
'Provide data offset: '
[DEBUG] Sent 0xc bytes:
'-2147483647\n'
[DEBUG] Sent 0x40 bytes:
'A' * 0x40
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$
[DEBUG] Sent 0x1 bytes:
'\n' * 0x1
[*] Process './MicroServiceDaemonOS' stopped with exit code -11 (SIGSEGV) (pid 2801)
[*] Got EOF while sending in interactive
```

It will write some random data to "microservice's" dedicated memory, with invalid offset. The only useful thing you can leverage from this is out-of-bound write (OOBW). If you specify size = 1, you will get next primitive: "write random byte to lower memory". Fortunately, the application prints that resulting value to user. So you can use byte-by-byte bruteforcing. Unfortunately, the address of write is randomized by "page" address with mask 0x7ff8 << 12 at the startup.    

# making OOBW predictable

This is where Murmur hashing "feature" might be useful. You can overflow one byte in previous chunk, and then bruteforce all "pages" of lower "microservice" to find the random page offset. This would take time, but if you succeed, you can point OOBW vulnerability to the executable code, and modify it!

# bruteforcing the shellcode

I've used usual pwntool's shellcode `shellcraft.sh()` which is 48 bytes long. It takes seconds on local machine, but it might take up to hour or even more on remote server, depending on your's network latency. So, let me repeat, you need to use bruteforce two times. First for find the proper page offset, which is up to 0x7ff8 variants, then you should bruteforce 48 bytes of shellcode with 1/256 probability of each byte.

The application has 20 minutes alarm. If your bruteforce not succeed in this time window you need to start it from the beginning. I wrote the code which tries 0x800 pages, and then reconnects if failed to save time. Then I ran it with 16 threads:

![](https://i.imgur.com/aQik8H3.png)

And finally I got the flag:

![](https://i.imgur.com/svXeoc2.png)

# conclusion

Despite a lot of solvers it wasn't quite easy to me. You need to spot the vulnerability first, then reverse all the binary to find the way how to apply it, after that you need to leverage bruteforce, and in the end you could screw up just because of your network latency.

[final exploit](/assets/files/ctf/2019/google/xpwn.py)

cheers)
