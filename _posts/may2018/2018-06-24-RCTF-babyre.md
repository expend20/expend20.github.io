---
layout: default
title:  "[RCTF:babyre] RE without IDA."
date:   2018-05-24 
---

# [RCTF2018:babyre] RE without IDA.

This is the task from [RCTF 2018](https://ctftime.org/event/624), babyre ([sources](/assets/files/ctf/2018/rctf/babyre.zip)).

# Input files and data

Let's see what we got. We had two files, one of which is ELF64, other `out` is simple text:
```
B80C91FE70573EFE
BEED92AE7F7A8193
7390C17B90347C6C
AA7A15DFAA7A15DF
526BA076153F1A32
545C15AD7D8AA463
526BA076FBCB7AA0
7D8AA4639C513266
526BA0766D7DF3E1
AA7A15DF9C513266
1EDC38649323BC07
7D8AA463FBCB7AA0
153F1A32526BA076
F5650025AA7A15DF
1EDC3864B13AD888
```

# Simple approach

Let's try to play with ELF file. 
```
$ ./babyre 
111
111
stringsaretoolong
```
Or...
```
$ ./babyre 
111
11
your input:try again11
526ba076
526ba076
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
your input:try again
```

The output of the program is a little bit disorienting us. It inputs two lines, the second one should be not so small and not so large (`11` will fit perfectly), then it outputs text: `your input:try again` and still waiting for input. So we give it another string `11` and only then, we got actual output.

The output seems to match `out` file, that we given at the start of the task, but with a little bit different formatting.

It seems we need to input some data to the program, and the output should match with `out` file.

Let's focus on the output of the program. It seems, that every new line of the output is corresponding to out third input character. We can verify this, by trying such values, as third input `1`, `11`, `111`. The first two input lines let's leave the same as in the previous example, it seems it really does not matter so far.

```
$ ./babyre 
111
11
your input:try again1
526ba076 <<< first character
b8c4f788
b8c4f788
b8c4f788
...
```

```
$ ./babyre 
111
11
your input:try again11
526ba076 <<< first character
526ba076 <<< second character
b8c4f788
b8c4f788
b8c4f788
b8c4f788
b8c4f788
...
```

```
$ ./babyre 
111
11
your input:try again111
526ba076 <<< ...
526ba076 <<< ...
526ba076 <<< third character
b8c4f788
b8c4f788
b8c4f788
b8c4f788
...
```

Now we know input string length, and we can start to bruteforce. Bruteforce script will try every character, one by one until we got output value `B80C91FE` for the first character, then we switch to next character, until the end of the string.

Here is the [script](/assets/files/ctf/2018/rctf/babyre.py). Execution of this will give us the flag:

```
$ python babyre.py
found R, len = 1
found RC, len = 2
found RCT, len = 3
found RCTF, len = 4
found RCTF{, len = 5
found RCTF{K, len = 6
found RCTF{Ke, len = 7
found RCTF{Kee, len = 8
found RCTF{Kee1, len = 9
found RCTF{Kee1o, len = 10
found RCTF{Kee1o9, len = 11
found RCTF{Kee1o9_, len = 12
found RCTF{Kee1o9_1, len = 13
found RCTF{Kee1o9_1s, len = 14
found RCTF{Kee1o9_1s_, len = 15
found RCTF{Kee1o9_1s_a, len = 16
found RCTF{Kee1o9_1s_a1, len = 17
found RCTF{Kee1o9_1s_a1r, len = 18
found RCTF{Kee1o9_1s_a1re, len = 19
found RCTF{Kee1o9_1s_a1rea, len = 20
found RCTF{Kee1o9_1s_a1read, len = 21
found RCTF{Kee1o9_1s_a1ready, len = 22
found RCTF{Kee1o9_1s_a1ready_, len = 23
found RCTF{Kee1o9_1s_a1ready_s, len = 24
found RCTF{Kee1o9_1s_a1ready_so, len = 25
found RCTF{Kee1o9_1s_a1ready_so1, len = 26
found RCTF{Kee1o9_1s_a1ready_so1v, len = 27
found RCTF{Kee1o9_1s_a1ready_so1ve, len = 28
found RCTF{Kee1o9_1s_a1ready_so1ved, len = 29
found RCTF{Kee1o9_1s_a1ready_so1ved}, len = 30
RCTF{Kee1o9_1s_a1ready_so1ved}
```

# Conclusion

Usually, the first things we do is running IDA, to analyze the code. Wich can be time-consuming. In this task, we can just observe the behavior of the program, analyze input/output of the program, and do the job, without really opening IDA :)



