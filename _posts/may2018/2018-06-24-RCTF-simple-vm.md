---
layout: default
title:  "[RCTF:simple-vm] Solving simple VM."
date:   2018-05-24 
---

# [RCTF:simple-vm] Solving simple VM.

In case you are not familiar with VM-stuff, here is short description:
> In code obfuscation, a virtual machine is a mechanism used to execute a different instruction set than the one used by the machine that runs the program.

This phrase is taken from [here](https://resources.infosecinstitute.com/reverse-engineering-virtual-machine-protected-binaries/), you can check this article for more information. We will focus on the task from [RCTF 2018](https://ctftime.org/event/624) called [simple-vm](https://ctftime.org/task/6136). In case you want to practice yourself before reading this write-up, you can find sources of this task [here](/assets/files/ctf/2018/rctf/simple_vm.zip). 

# Input data

First of all, we had two files:

```
$ file p.bin 
p.bin: data

00000000   01 30 00 00  00 10 18 43  14 15 47 40  17 10 1D 4B  .0.....C..G@...K
00000010   12 1F 49 48  18 53 54 01  57 51 53 05  56 5A 08 58  ..IH.ST.WQS.VZ.X
00000020   5F 0A 0C 58  09 00 01 02  03 04 05 06  00 00 00 00  _..X............
00000030   15 00 01 00  00 0E 12 0B  0C 00 01 00  00 35 00 00  .............5..
00000040   00 66 15 10  01 00 00 0E  0A 66 16 0C  10 01 00 00  .f.......f......
00000050   47 00 00 00  66 03 40 01  00 00 10 11  F1 00 00 00  G...f.@.........
00000060   13 04 43 01  00 00 08 04  41 01 00 00  10 03 40 01  ..C.....A.....@.
00000070   00 00 08 04  42 01 00 00  03 41 01 00  00 03 43 01  ....B....A....C.
00000080   00 00 08 10  03 42 01 00  00 08 04 44  01 00 00 66  .....B.....D...f
00000090   03 40 01 00  00 11 F1 00  00 00 10 03  44 01 00 00  .@..........D...
000000A0   16 05 40 01  00 00 0E 06  40 01 00 00  0C 45 01 00  ..@.....@....E..
000000B0   00 55 00 00  00 66 03 46  01 00 00 11  05 00 00 00  .U...f.F........
000000C0   13 10 03 46  01 00 00 11  11 01 00 00  13 17 18 60  ...F...........`
000000D0   01 00 00 0C  46 01 00 00  B6 00 00 00  01 76 01 00  ....F........v..
000000E0   00 66 00 00  00 00 00 00  00 00 00 00  00 00 00 00  .f..............
000000F0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................
00000100   0A 49 6E 70  75 74 20 46  6C 61 67 3A  00 00 00 0F  .Input Flag:....
00000110   1F 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................
00000120   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................
00000130   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................
00000140   20 00 00 00  00 1F 1F 00  00 00 00 00  00 00 00 00   ...............
00000150   05 57 72 6F  6E 67 0A 52  69 67 68 74  0A 00 00 00  .Wrong.Right....
00000160   15 50 01 00  00 0E 12 0B  0C 50 01 00  00 65 01 00  .P.......P...e..
00000170   00 00 00 00  00 00 15 56  01 00 00 0E  12 0B 0C 50  .......V.......P
00000180   01 00 00 7B  01 00 00 00  00 00 00 00               ...{........

$ file vm_rel 
vm_rel: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b3589d5417c06a14acbbcc8d600f4a3d946898b0, stripped
```

One is simple hex data, other is ELF64 executable. We can see strings "Input Flag" as well as "Wrong" and "Right" in hex data. Probably this strings are used by VM. 

# Approach

Let's play with ELF64 file. 

```
$ ./vm_rel 
Input Flag:11111
111111
11111111111111111111
Wrong
```

We need to guess and input flag.

If we open `vm_rel` file in IDA and analyze it with Hex-Rays Decompiler, there is a couple of things that we can notice:

 * Strings "Input Flag", "Wrong", "Right" a really taken from `p.bin` file. We can't find this strings in ELF64.
 * The first thing the program will do, is reading `p.bin` file
```
signed __int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
...
  v3 = fopen("p.bin", "rb");
  v4 = "err 0";
  if ( !v3 )
    goto LABEL_4;
...
```
 * There is only one sub-function, that is called from `main()` -> `sub_400896()` and this is our main VM function:
```
      case 0:
        return *(unsigned int *)&base[nextInst];
      case 1:
        goto LABEL_35;
      case 2:
        v4 = nextInst;
        nextInst = currentInst + 9;
        base[*(signed int *)&base[v4]] = *(_DWORD *)&base[(signed int)currentInst + 5];
        break;
      case 3:
        v5 = nextInst;
        nextInst += 4;
        v6 = *(signed int *)&base[v5];
        goto LABEL_27;
      case 4:
        v7 = nextInst;
        nextInst += 4;
        v8 = *(signed int *)&base[v7];
        goto LABEL_31;
```
 * We can confirm, that the content of binary is corresponding to the task name, it's really VM :)

## Code rebuild

Generally, to understand what is going on under the hood of VM, you need to reverse every single opcode of native VM instruction. This can take a while...

I used a little bit different and easy approach. There is not much code overall. And the code can be easily taken from Hex-Rays and recompiled under the C compiler, that you are comfortable with. After that, the debugging and tracing will be far easier. 

## Analyze

So I [recompile code](/assets/files/ctf/2018/rctf/simple-vm.cpp), put `printf()` into every native VM opcode, and got the full [trace](/assets/files/ctf/2018/rctf/simple-vm-trace.txt) of code-flow. I didn't afraid to make a mistake in opcode description in logs, because I'm not interfering with code execution. I just need to understand in general, what the program is doing. 

After reading data with `getchar()` program performs some calculations on input data in a loop. One interation of a loop is like this:

```
        #4:0x55 C (0x7d) =  DB [0x140] (0x20)
        #0x10:0x5a G (0x130) = C (0x20)
        #0x11:0x5b C (0x20) += DD (0xf1)
        #0x13:0x60 C = [C] (0x111)
        #4:0x61 [0x143] = C (0x52)
        #8:0x66 C = ~(storedG 0x20  & C 0x52) RES = 0xffffffff
        #4:0x67 [0x141] = C (0xffffffff)
        #0x10:0x6c G (0x20) = C (0xffffffff)
        #4:0x6d C (0xffffffff) =  DB [0x140] (0x20)
        #8:0x72 C = ~(storedG 0xffffffff  & C 0x20) RES = 0xffffffdf
        #4:0x73 [0x142] = C (0xffffffdf)
        #4:0x78 C (0xffffffdf) =  DB [0x141] (0xff)
        #4:0x7d C (0xffffffff) =  DB [0x143] (0x52)
        #8:0x82 C = ~(storedG 0xffffffff  & C 0x52) RES = 0xffffffad
        #0x10:0x83 G (0xffffffff) = C (0xffffffad)
        #4:0x84 C (0xffffffad) =  DB [0x142] (0xdf)
        #8:0x89 C = ~(storedG 0xffffffad  & C 0xffffffdf) RES = 0x72
        #4:0x8a [0x144] = C (0x72)
        #4:0x90 C (0x72) =  DB [0x140] (0x20)
        #0x11:0x95 C (0x20) += DD (0xf1)
        #0x10:0x9a G (0xffffffad) = C (0x111)
        #4:0x9b C (0x111) =  DB [0x144] (0x72)
        #0x16:0xa0 [G(0x111)] = C (0x72)
        #5:0xa1 G (0x111) = [0x140] (0x20)
        #0xE:0xa6 G++ (0x20)
        #6:0xa7 [0x140] (0x20) = G (0x21)
        #0xC:0xac IF [0xad]-- (0x1f) GOTO 0x55 -----------
```

Then, execution comes to VM opcode #18, that performs comparing of VM register with some stored data in `p.bin`, if there is no match we output "Wrong" string via `putchar()` 
```
        #18:0xce if 39 goto 0x0160
        #0x15:0x160 G (0x9) = DD [0x161] (0x150)
        #0xE:0x165 G++ (0x150)
        #0x12:0x166 C = G (0x151)
        #0xB: PUTCHAR(C)
W       #0xC:0x168 IF [0x169]-- (0x5) GOTO 0x165 -----------
        #0xE:0x165 G++ (0x151)
        #0x12:0x166 C = G (0x152)
        #0xB: PUTCHAR(C)
r       #0xC:0x168 IF [0x169]-- (0x4) GOTO 0x165 -----------
        #0xE:0x165 G++ (0x152)
        #0x12:0x166 C = G (0x153)
        #0xB: PUTCHAR(C)
o       #0xC:0x168 IF [0x169]-- (0x3) GOTO 0x165 -----------
        #0xE:0x165 G++ (0x153)
        #0x12:0x166 C = G (0x154)
        #0xB: PUTCHAR(C)
n       #0xC:0x168 IF [0x169]-- (0x2) GOTO 0x165 -----------
        #0xE:0x165 G++ (0x154)
        #0x12:0x166 C = G (0x155)
        #0xB: PUTCHAR(C)
g       #0xC:0x168 IF [0x169]-- (0x1) GOTO 0x165 -----------
```

Original 0x18 code:
```
      case 0x18:
        if ( c )
LABEL_35:
          nextInst = *(_DWORD *)&base[nextInst];
        else
          nextInst = currentInst + 5;
        break;
```



Actually, only now I realized, that 0x18 VM opcode **is the only conditional opcode** except the loop opcodes. This is the only place in VM   that can check our flag. 

If we patch source code, with:
```
      case 0x18:
        if ( 0 ) # it was 'c' variable here
LABEL_35:
```
then any input flag will print "Right" string. 

But our goal is to find that input flag. So we need to understand how 'c' variable depends on input flag. 

After a couple of tests, I noticed, that when opcode 0x18 executes first time, 'c' variable depends only on the last character of the flag. By the way, in code trace, we can easily find the length of the flag, by simply counting `getchar()` call, it's called 0x20 times.

So now, we can bruteforce flag, one by one character from the end, and check when 'c' variable becomes zero. 

To do that, I put some new logs to our C sources, that will print count of successful 0x18 opcode execution. Then I wrote a simple [python](/assets/files/ctf/2018/rctf/simple-vm.py) script that will execute recompiled binary, analyze logs and actually brute new character.

Viola, we got flag:
```
....
Input Flag:[31] rigth char = 5 (0x35) 7 (0x37)
try 07a71bf084a93df7ce3def3ab1bd61f6...
Input Flag:[31] rigth char = 5 (0x35) 9 (0x39)
try 08a71bf084a93df7ce3def3ab1bd61f6...
Input Flag:[31] rigth char = 9 (0x39) 7 (0x37)
try 09a71bf084a93df7ce3def3ab1bd61f6...
Input Flag:Right
```


# Conclusion

My approach was not the easiest one, but also not the hardest one. The more fast approach was to figure out from sources, that 0x18 opcode is the key, and how this conditional opcode is correlated with input. The hardest one was to analyze VM more deeply and run bruteforcer directly on the reversed pseudocode.

Time spent **6-8 hours**. 
