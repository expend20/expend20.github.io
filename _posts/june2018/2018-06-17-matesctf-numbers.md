---
layout: default
title:  "[MatesCTF:numers] Using Z3 to solve math equations. "
---

# [MatesCTF:numers] Using Z3 to solve math equations.


## Intro.

Hello! This is wire-up from [Mates CTF](https://ctftime.org/event/629/tasks/) for `numbers` task.

We are given by [numbers.exe](/assets/files/ctf/2018/matesctf/numbers.exe) binary, that wanted from us to give some numbers:
```
>numbers.exe
----- The Numbers -----
Designed by Quang Nguyen(quangnh89), a member of PiggyBird. My blog: https://develbranch.com
Enter the first part (8 numbers):
```

## Welcome to floating point data.

If we open exe file in IDA, we will see a lot of [SSE](https://en.wikipedia.org/wiki/Streaming_SIMD_Extensions) instructions:

```
.text:0000000000401517                 lea     rcx, [rbp-11h]  ; Format
.text:000000000040151B                 call    scanf
.text:0000000000401520                 movd    xmm0, cs:dword_403098
.text:0000000000401528                 movq    xmm1, qword ptr [rbp-64h]
.text:000000000040152D                 ucomiss xmm1, xmm0
.text:0000000000401530                 jp      loc_402163
.text:0000000000401536                 jbe     loc_402163
.text:000000000040153C                 movd    xmm0, cs:dword_40309C
.text:0000000000401544                 ucomiss xmm0, dword ptr [rbp-64h]
.text:0000000000401548                 jp      loc_402163
.text:000000000040154E                 jbe     loc_402163
.text:0000000000401554                 movd    xmm0, cs:dword_4030A0
.text:000000000040155C                 movq    xmm1, qword ptr [rbp-68h]
.text:0000000000401561                 ucomiss xmm1, xmm0
.text:0000000000401564                 jp      loc_402163
.text:000000000040156A                 jbe     loc_402163
.text:0000000000401570                 movd    xmm0, cs:dword_4030A4
.text:0000000000401578                 ucomiss xmm0, dword ptr [rbp-68h]
```

To understand what is going on, you need to know how floating point values are saved in memory. It is very simple to view data in windbg:
```
0:000> dd 403098
00000000`00403098  00000000 437f0000 00000000 437f0000
00000000`004030a8  00000000 437f0000 00000000 437f0000
00000000`004030b8  00000000 437f0000 00000000 437f0000
00000000`004030c8  00000000 437f0000 00000000 437f0000
0:000> df 403098
00000000`00403098                 0              255                0              255
00000000`004030a8                 0              255                0              255
00000000`004030b8                 0              255                0              255
00000000`004030c8                 0              255                0              255
``` 

As you can see, DWORD data `0x437f0000` is corresponding to 255 integer. So, the next code basically checks that value on stack is `< 255`:
```
.text:000000000040153C                 movd    xmm0, cs:dword_40309C 	  # 0x437f0000 = 255
.text:0000000000401544                 ucomiss xmm0, dword ptr [rbp-64h]
.text:0000000000401548                 jp      loc_402163
.text:000000000040154E                 jbe     loc_402163
```

Next, there is some mathematical equations is checked against the input data. For example the next code is checked `(x5 + x6)*(x5 + x6) + x4*x4 == 153844`

```
.text:00000000004016C0                 movd    xmm0, dword ptr [rbp-74h]
.text:00000000004016C5                 addss   xmm0, dword ptr [rbp-78h]
.text:00000000004016CA                 movd    dword ptr [rbp-84h], xmm0
.text:00000000004016D2                 movd    xmm0, dword ptr [rbp-74h]
.text:00000000004016D7                 addss   xmm0, dword ptr [rbp-78h]
.text:00000000004016DC                 movq    xmm1, xmm0
.text:00000000004016E0                 movd    xmm0, dword ptr [rbp-84h]
.text:00000000004016E8                 mulss   xmm0, xmm1
.text:00000000004016EC                 movd    dword ptr [rbp-88h], xmm0
.text:00000000004016F4                 movd    xmm0, dword ptr [rbp-70h]
.text:00000000004016F9                 mulss   xmm0, dword ptr [rbp-70h]
.text:00000000004016FE                 movq    xmm1, xmm0
.text:0000000000401702                 movd    xmm0, dword ptr [rbp-88h]
.text:000000000040170A                 addss   xmm0, xmm1
.text:000000000040170E                 movd    dword ptr [rbp-8Ch], xmm0
.text:0000000000401716                 movd    xmm0, cs:dword_4030D8
.text:000000000040171E                 ucomiss xmm0, dword ptr [rbp-8Ch]
.text:0000000000401725                 jp      loc_402163
.text:000000000040172B                 jnz     loc_402163

0:000> df 4030D8
00000000`004030d8            153844

``` 

# Using Z3 solver.

There is a lot of this kind of checks, you need to reverse all of it. Finally, you will get a list like this, for the first 8 input values:

```
x1 < 256, x2 < 256, x3 < 256, x4 < 256, x5 < 256, x6 < 256, x7 < 256, x8 < 256, 
	(x5 + x6)*(x5 + x6) + x4*x4 == 153844, 
	(x5 + x6)*(x5 + x6) + x3*x3 == 131400, 
	x5*x5 - x1*x1 == 181,
	x6*x6 - x2*x2 == 46717,
	x1 * x4 == 19080,
	x2 * x3 == 15300,
	x1 * x5 + x1 * x6 - 119 * x5 ==	18871,
	x2 * x6 + x2 * x5 - 70 * x6 == 16930,
	x4 * x5 - x3 * x6 == -16558,
	x1 * x2 - x7 == 9043,
	x7 * x8 == 4247
```

The main question is how to solve this? The first my idea was to bruteforce all of data of 0..255 for each value. Luckily enough there is a much more intelligent way. The way is to use awesome [Z3 solver](https://www.cs.tau.ac.il/~msagiv/courses/asv/z3py/guide-examples.htm).

Indeed, all you need is to run [this](/assets/files/ctf/2018/matesctf/num.py) script:
```
#!/usr/bin/env python

from z3 import *

x1 = Int('x1')
x2 = Int('x2')
x3 = Int('x3')
x4 = Int('x4')
x5 = Int('x5')
x6 = Int('x6')
x7 = Int('x7')
x8 = Int('x8')


solve(x1 < 256, x2 < 256, x3 < 256, x4 < 256, x5 < 256, x6 < 256, x7 < 256, x8 < 256, 
	(x5 + x6)*(x5 + x6) + x4*x4 == 153844, 
	(x5 + x6)*(x5 + x6) + x3*x3 == 131400, 
	x5*x5 - x1*x1 == 181,
	x6*x6 - x2*x2 == 46717,
	x1 * x4 == 19080,
	x2 * x3 == 15300,
	x1 * x5 + x1 * x6 - 119 * x5 ==	18871,
	x2 * x6 + x2 * x5 - 70 * x6 == 16930,
	x4 * x5 - x3 * x6 == -16558,
	x1 * x2 - x7 == 9043,
	x7 * x8 == 4247)

# res : 90 102 150 212 91 239 137 31

solve(x1 < 256, x2 < 256, x3 < 256, x4 < 256, x5 < 256, x6 < 256, x7 < 256, x8 < 256, 
	(x4 + x6) * (x5 + x7) + (x5 * x4) == 43907,
	x1 * x2 + x5 == 12563,
	(x1 + x6) * (x2 + x6) + x3 * x3 == 130348,
	x5 * x1 - x1 * x2 == -10682,
	x4 * x6 - x2 * x3 == -9474,
	x1 * x4 == 15484,
	x2 * x3 == 32384,
	x1 * x6 - 27 * x5 + x2 * x6 == 32257,
	x2 * x7 - 74 * x3 + x1 * x2 == 8670,
	x3 * x4 - x8 * x7 == 28838,
	x1 * x3 + x7 == 24910,
	x7 * x8 == 11136)

# res: 98 128 253 158 19 145 116 96
```

We can check this values, and get the flag!

```
Designed by Quang Nguyen(quangnh89), a member of PiggyBird. My blog: https://develbranch.com
Enter the first part (8 numbers):
90 102 150 212 91 239 137 31
Enter the second part (8 numbers):
98 128 253 158 19 145 116 96
The flag is matesctf{All you need is SMT!!}
```



