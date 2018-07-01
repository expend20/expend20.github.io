---
layout: default
title:  "[Google CTF:APT42 - Part 1] Unfinished RE"

---

# [Google CTF:APT42 - Part 1] Unfinished RE.

Hello all, this is my unfinished write-up for the [challange](https://ctftime.org/task/6241) from [google ctf](https://capturetheflag.withgoogle.com). I know that this is a little bit dumb to post unfinished work, but I made some progress, and want to share it with someone ;)

## The task.

![](/assets/files/ctf/2018/google/apt42p1/chall.png)

[attach](/assets/files/ctf/2018/google/apt42p1/ntpdate-9754f5add12f4a19bf772f248f96c142ccc1ec011a59e76e192e8c0e2afb5291.zip)


So, we are given by some file, that is supposed to be infected, but originally it is used as NTP client. Let's analyze it with IDA. The `main()` function is:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{

...

  v31 = isatty(1);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "NTP client v0.1 (");
  if ( v31 )
    v4 = "single";
  else
    v4 = "daemon";
  v5 = std::operator<<<std::char_traits<char>>(v3, v4);
  v6 = std::operator<<<std::char_traits<char>>(v5, " mode)");
  v7 = std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
  std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
  while ( 1 )
  {
    if ( v31 )
    {
      v8 = std::operator<<<std::char_traits<char>>(&std::cout, "---");
      std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
    }
    if ( !GetLocalTime() )
    {
      v9 = std::operator<<<std::char_traits<char>>(&std::cout, "Error reading local time.");
      std::ostream::operator<<(v9, &std::endl<char,std::char_traits<char>>);
    }
    else if ( (unsigned __int8)GetNTPTime() ^ 1 )
    {
      v10 = std::operator<<<std::char_traits<char>>(&std::cout, "Error fetching reference time.");
      std::ostream::operator<<(v10, &std::endl<char,std::char_traits<char>>);
    }
    else if ( current_time == ntp_time )
    {
      if ( v31 )
      {
        v27 = std::operator<<<std::char_traits<char>>(&std::cout, "System time is in perfect sync!");
        std::ostream::operator<<(v27, &std::endl<char,std::char_traits<char>>);
      }
    }
    else
    {
      v30 = *(_QWORD *)std::max<long>(&current_time, &ntp_time);
      v11 = v30 - *(_QWORD *)std::min<long>(&current_time, &ntp_time);
      v12 = std::operator<<<std::char_traits<char>>(&std::cout, "Local time is ");
      v13 = std::ostream::operator<<(v12, v11);
      v14 = std::operator<<<std::char_traits<char>>(v13, " second");
      v15 = v11 == 1 ? &unk_40B306 : "s";
      v16 = std::operator<<<std::char_traits<char>>(v14, v15);
      v17 = v30 == current_time ? " ahead" : " behind";
      v18 = std::operator<<<std::char_traits<char>>(v16, v17);
      std::ostream::operator<<(v18, &std::endl<char,std::char_traits<char>>);
      v19 = std::operator<<<std::char_traits<char>>(&std::cout, " - local time: ");
      v20 = localtime(&current_time);
      v21 = asctime(v20);
      std::operator<<<std::char_traits<char>>(v19, v21);
      v22 = std::operator<<<std::char_traits<char>>(&std::cout, " - reference time: ");
      v23 = localtime(&ntp_time);
      v24 = asctime(v23);
      std::operator<<<std::char_traits<char>>(v22, v24);
      std::operator<<<std::char_traits<char>>(&std::cout, "Adjusting... ");
      v25 = stime(&ntp_time) == -1 ? "failed (are you root?)" : "OK.";
      v26 = std::operator<<<std::char_traits<char>>(&std::cout, v25);
      std::ostream::operator<<(v26, &std::endl<char,std::char_traits<char>>);
    }
    if ( v31 )
      break;
    sub_400A40(60LL);
  }
  v28 = std::operator<<<std::char_traits<char>>(&std::cout, "---");
  std::ostream::operator<<(v28, &std::endl<char,std::char_traits<char>>);
  return 0;
}
``` 

What we can see here, is some C++ code. The binary can be executed in `single` mode or in `daemon` mode, the call to `isatty()` is responsible for choosing the mode. There is some unnamed function that is called almost at the end, and only in `daemon` mode. Let's look at it:

![](/assets/files/ctf/2018/google/apt42p1/sneaky.png) 

Wow, we had found some shellcode-style code. You can simply press `u` to undefine that code, and `c` to make code again in proper place, to analyze file futher.

![](/assets/files/ctf/2018/google/apt42p1/sneaky2.png)

## Reversing and patching.

There is a bunch of such shellcode-style functions in binary. If we will analyze binary dynamically with gdb, we can stop what the code is doing. The code is deobfuscating from itself some constants, search libc in memory, and execute functions bypassing `.got.plt` trampolines. The major check are:
 
 * check time
 * check `/etc/krb5.conf` for `domain.google.com string`
 * check domain `mlwr-part1.ctfcompetition.com`

Then I spot some weird behavior. The code is sending all possible signals using `bsd_signal()`and `sighandler_t = 1`. Here is `strace` log:

```
rt_sigaction(SIGHUP, {SIG_IGN, [HUP], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGINT, {SIG_IGN, [INT], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGQUIT, {SIG_IGN, [QUIT], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGILL, {SIG_IGN, [ILL], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGTRAP, {SIG_IGN, [TRAP], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGABRT, {SIG_IGN, [ABRT], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGBUS, {SIG_IGN, [BUS], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGFPE, {SIG_IGN, [FPE], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGKILL, {SIG_IGN, [KILL], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, 0x7fff195daea8, 8) = -1 EINVAL (Invalid argument)
rt_sigaction(SIGUSR1, {SIG_IGN, [USR1], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGSEGV, {SIG_IGN, [SEGV], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGUSR2, {SIG_IGN, [USR2], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGPIPE, {SIG_IGN, [PIPE], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGALRM, {SIG_IGN, [ALRM], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGTERM, {SIG_IGN, [TERM], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGSTKFLT, {SIG_IGN, [STKFLT], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGCHLD, {SIG_IGN, [CHLD], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGCONT, {SIG_IGN, [CONT], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGSTOP, {SIG_IGN, [STOP], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, 0x7fff195daea8, 8) = -1 EINVAL (Invalid argument)
rt_sigaction(SIGTSTP, {SIG_IGN, [TSTP], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGTTIN, {SIG_IGN, [TTIN], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGTTOU, {SIG_IGN, [TTOU], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGURG, {SIG_IGN, [URG], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGXCPU, {SIG_IGN, [XCPU], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGXFSZ, {SIG_IGN, [XFSZ], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGVTALRM, {SIG_IGN, [VTALRM], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGPROF, {SIG_IGN, [PROF], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGWINCH, {SIG_IGN, [WINCH], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGIO, {SIG_IGN, [IO], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGPWR, {SIG_IGN, [PWR], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGSYS, {SIG_IGN, [SYS], SA_RESTORER|SA_RESTART, 0x7fd5be4114b0}, {SIG_DFL, [], 0}, 8) = 0
```

I do not understand why it needed, but anyways after it, the code creates some IPC objects (memory map and mutex) and run `clone()` function with new entry `0x40a740`.

Btw, python [pwn tools](https://docs.pwntools.com) and [peda](https://github.com/longld/peda) provided us great opportunity to patch binary on disk, or in memory with gdb. Let me give you some examples:

```
#!/usr/bin/env python
from pwn import *
...

log.info("patch only")

e = ELF("./ntpdate")

e.asm(0x409400, "xor rax, rax; nop; nop") # isatty() check

# time check, krb5.conf check, domain check...

e.write(0x408E7E, "\x90\x90") 
e.write(0x408E65, "\x90\x90")
e.write(0x408E6E, "\x90\x90")

e.save("./ntpatch")
```

This simple script will patch all the checks in the file, and force it to communicate with the server (but please crate krb5.conf anyways).

This simple script will do all the patches is a memory and set breakpoints, for debugging:
```
#!/usr/bin/env python
from pwn import *

def patchMem(addr, data):

	o = ""
	idx = 0

	for d in data:

		o += 'set *(char *)(%s+%d)=0x%x\n' % (addr, idx, ord(d))

		idx += 1

	return o
...

c = gdb.debug("./ntpdate", """
b main
c
""" + patchMem("isatty", asm("mov rax, 0; ret")) + patchMem("0x408E7E", "\x90\x90")  + patchMem("0x408E65", "\x90\x90")  + patchMem("0x408E6E", "\x90\x90")  + """
b *0x40ab0f
c
set $rdx=0x090900
set follow-fork-mode child
b * 0x40a740
b * 0x40A106
""")

c.interactive()
```

To debug the code after `clone()` call, we need to clear flag `CLONE_UNTRACED` and `set follow-fork-mode child` in gdb. But I prefer to just patch binary and analyze further at runtime.

After `clone()` execution we face the most fun part -- communication with the server.

## The protocol.

The code is communicating with the server every one minute. It receives some commands, executes it and send a result to the server. Let's look at some examples from wireshark:

![](/assets/files/ctf/2018/google/apt42p1/wireshark1.png)
![](/assets/files/ctf/2018/google/apt42p1/wireshark2.png)
![](/assets/files/ctf/2018/google/apt42p1/wireshark3.png)

The actual sequence of commands given by server is:

```
exec echo $USER
exec hostname
exec uname -a
exec ip a
rm
```

After receiving `rm` the code stops and removes itself on disk.

The protocol is simple, we can reverse it. And talk to the server by ourselves. Let's try. 

The typical sequence is: `hello` --> `<recv command>` --> `<send result>` --> `la revedere`. `la revedere` is just goodbye in Romanian. This sequence is true for all, except last message. There is no `la revedere` is the last message, but just `ok` instead.

Let's analyze the packet format:
![](/assets/files/ctf/2018/google/apt42p1/wireshark1.png)

 * `0f 00 00 00` is packet size, excluding this field 
 * `c6 01 28 6c 2b 5d 8e a2` this seems random data, unique for every instance, zero in server packets
 * `68 65 6c 6c 6f 00` this is `hello`
 * `f9` is just xor checksum

There is also `stream` command that is folowed by any string ending '\x0a'.

Now we can write the script, to force the server to send as all the commands.
```
#!/usr/bin/env python

from pwn import *
from struct import *
import sys


rn = randoms(8)


def sendData(cmd):

	data = rn
	data += cmd + '\x00'

	a = 0
	for c in data:
		a = 0xff & (a ^ ord(c))

	data += p8(a)

	r.send(p32(len(data)) + data)

context.log_level = "debug"


if __name__ == "__main__":

	cmds = ""

	while 1:

		r = remote("mlwr-part1.ctfcompetition.com", 4242)

		sendData("hello")

		sleep(0.5)
		size = unpack("<I", r.recvn(4))[0]
		log.info("recn: %d", size)
		data = r.recvn(size)
		cmd = data[8:-2]
		cmd = cmd.replace("\x00", ' ')

		cmds += cmd + "\n"

		log.info("command = %s", cmd)

		sendData("stream")
		r.send("1\x0a")

		sendData("la revedere")

		if cmd == 'rm':
			break

	log.info("commands: %s", cmds)

	#r.interactive()
	
```

Ok, it works. But still there is no any kind of flag :( I had tried to send different commands instead of `hello`, for example, `flag` or `ls` or `cat flag`, with no luck. Then I've tried not to send `la revedere` or send it where it is not needed. Still with no luck, the server is just ignored my commands. Then I gave up.

# UPD:

After [p4 team shared their solution](https://github.com/p4-team/ctf/blob/master/2018-06-23-google-ctf/apt42-part1/README.md), I realized that I needed to send `part1 flag` instead of `hello`. And this is not stupid guessing since this string was hardcoded and obfuscated in the binary itself, but never executed. So I would need to do more static analisys, to get the flag, that was my mistake.


# UPD2:

Here is [the script](/assets/files/ctf/2018/google/apt42p1/strings-dump.py) that dumps obfuscated strings from [asm listing](/assets/files/ctf/2018/google/apt42p1/list.txt). As you can see `part1 flag` is among of them:
```
[*] extracted: waitpid
[*] extracted: /etc/krb5.conf
[*] extracted: open
[*] extracted: read
[*] extracted: close
[*] extracted: domain.google.com
[*] extracted: strcasestr
[*] extracted: __stack_chk_fail
[*] extracted: 4242
[*] extracted: mlwr-part1.ctfcompetition.com
[*] extracted: getaddrinfo
[*] extracted: signal
[*] extracted: socket
[*] extracted: connect
[*] extracted: close
[*] extracted: socket
[*] extracted: setsockopt
[*] extracted: htons
[*] extracted: bind
[*] extracted: close
[*] extracted: listen
[*] extracted: send
[*] extracted: send
[*] extracted: send
[*] extracted: send
[*] extracted: strlen
[*] extracted: recv
[*] extracted: recv
[*] extracted: recv
[*] extracted: recv
[*] extracted: hello
[*] extracted: part1 flag
[*] extracted: stream
[*] extracted: recv
[*] extracted: send
[*] extracted: __stack_chk_fail
[*] extracted: close
[*] extracted: close
[*] extracted: close
[*] extracted: close
[*] extracted: accept
[*] extracted: waitpid
[*] extracted: __errno_location
[*] extracted: close
[*] extracted: syscall
[*] extracted: close
[*] extracted: waitpid
[*] extracted: __errno_location
[*] extracted: hello
[*] extracted: exec
[*] extracted: exec
[*] extracted: strlen
[*] extracted: strlen
[*] extracted: syscall
[*] extracted: error
[*] extracted: sh
[*] extracted: -c
[*] extracted: stream
[*] extracted: dup2
[*] extracted: dup2
[*] extracted: dup2
[*] extracted: -c
[*] extracted: sh
[*] extracted: /bin/sh
[*] extracted: execl
[*] extracted: syscall
[*] extracted: waitpid
[*] extracted: __errno_location
[*] extracted: la revedere
[*] extracted: bg
[*] extracted: bg
[*] extracted: strlen
[*] extracted: strlen
[*] extracted: system
[*] extracted: ok
[*] extracted: rm
[*] extracted: /proc/self/exe
[*] extracted: readlink
[*] extracted: unlink
[*] extracted: ok
[*] extracted: kill
[*] extracted: syscall
[*] extracted: error
[*] extracted: upgrade
[*] extracted: error
[*] extracted: ok
[*] extracted: close
[*] extracted: nop
[*] extracted: ok
[*] extracted: error
[*] extracted: __stack_chk_fail
[*] extracted: close
[*] extracted: sleep
[*] extracted: gettimeofday
[*] extracted: getpid
[*] extracted: getppid
[*] extracted: ELF
[*] extracted: send
[*] extracted: syscall
[*] extracted: syscall
[*] extracted: mmap
[*] extracted: syscall
[*] extracted: syscall
[*] extracted: clone
[*] extracted: munmap

``` 



