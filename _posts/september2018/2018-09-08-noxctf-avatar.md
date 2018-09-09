---
layout: post
title: "[noxCTF:Avatar] Just reversing, bruteforcing and guessing."
comments: true
---

![](/assets/files/ctf/2018/noxCTF/avatar/logo.png)

* [orig link](https://ctf18.noxale.com/challenges)
* [ctftime](https://ctftime.org/event/671)
* [file](/assets/files/ctf/2018/noxCTF/avatar/Avatar.zip)


Initial analysis reveals some C++ code, and 4 parts of the flag, which is read from user sequentially. 

![](/assets/files/ctf/2018/noxCTF/avatar/cinitial.png)

# AES128.

The first check is aes related. You could find `aes_key_schedule_128()` and `aes_encrypt_128()` functions. The sources probably are taken from [here](https://github.com/openluopworld/aes_128). At the first glance, it is not feasible to break that cipher, but lets analyze in detail what the program is doing.

 1. `aes_key_schedule_128()` is called with **hardcoded** key which is located at `0x7BF340`
 1. `aes_encrypt_128()` encrypts user data
 1. encrypted data is compared with another hardcoded value

So, it is a misuse of aes, we can just call decryption routine with hardcoded encrypted data and key, this will restore the original data.

```
#include <stdio.h>

#include "aes.h"

int main(int argc, char *argv[]) {

	uint8_t i, r;

	/* 128 bit key */
	uint8_t key[] = {

		0x2f, 0xdf, 0x09, 0x58, 0x4e, 0xac, 0x6b, 0x77, 
		0xf4, 0xdb, 0x7f, 0x7b, 0xf7, 0x99, 0x9c, 0x20
	};

 
	uint8_t ciphertext[AES_BLOCK_SIZE] = { 0xff, 0x80, 0xcf, 0x0c, 0x7c, 0x2a, 0x29, 0xcc, 0xd6, 0xc7, 0x0c, 0xbd, 0x13, 0xd1, 0x40, 0xb0 };

	
	uint8_t roundkeys[AES_ROUND_KEY_SIZE];

	aes_key_schedule_128(key, roundkeys);

	// decryption
	aes_decrypt_128(roundkeys, ciphertext, ciphertext);
	printf("Plain text:\n");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%2x ", ciphertext[i]);
	}

	printf("%s", ciphertext);

	return 0;

}
```
And we get first part of the flag.

```
Plain text:
46 75 31 31 5f 4d 30 30 6e  0  0  0  0  0  0  0 Fu11_M00n
```

# Mapping and permutating.

The second checking function is located at `0x4022DA`, which is doing next.

 1. Maps user input into other values (mapping data at `0x564880`).
 1. Rotates and permutates mapped data couple of times
 1. Checks that data with hardcoded one at `0x7BF440`. 

From that data, we can conclude the length of the password. We can also do all this in reverse:

```
	def mkmap():
		r = {}
		s = [0x42, 0xf8, 0x64, 0xd0, 0x68, 0xe3, 0x6c, 0xb6, 0x6e, 0x85, 0x31, 0xf5, 0x30, 0xb7, 0x33, 0xc8, 0x54, 0x88, 0x5f, 0xe8]
		for i in range(0, len(s) / 2):

			r[s[i*2 + 1]] = s[i*2]

		return r

	r1 = bytearray([0xe8, 0xb6, 0xf5, 0xc8, 0x85, 0xe3, 0xc8, 0xf8, 
					0xe8, 0x85, 0x88, 0xb7, 0xd0])
	
	r1 = xchg(r1, 4, 10)
	r1 = r1[-3:] + r1[:-3]
	r1 = xchg(r1, 11, 10)
	r1 = xchg(r1, 0, 5)
	r1 = xchg(r1, 4, 1)
	r1 = r1[7:] + r1[:7]
	r1 = xchg(r1, 5, 7)
	r1 = xchg(r1, 2, 0xc)

	mp = mkmap()
	for i in range(0, len(r1)):
		if r1[i]:
			r1[i] = mp[r1[i]]

	r.sendlineafter("Earth Kingdom:", str(r1)) # Th3_Bl1nd_0n3
```

This will produce `Th3_Bl1nd_0n3` which is accepted by the program.

# The math. 

The next check is about solving next math equation:

```
((14 * (((x | 0x40) - 0x5336654 + 0x1E240) | 0x10000) >> 1) - 0x3B93AE7C) & 0xFFFFFFFFFFFF7FFFLL ^ 0x6E988) == 0x1CDEDC990D1LL;
```

Were `x` is user input. I found the value `0x420B1B2E57` which was accepted by the program and moved to the last stage.


# Bruteforcing.

Let's reverse the last checking function at `0x402508` named `OO00OO0O`.

 1. It calculates MD5 from user input.
 1. Then it splits that MD5 hash into 6 parts. The 5 parts are 6-byte each, and the last one is a 2-byte length.
 1. Calculates sha256 from each of that part.
 1. Comparing that sha256 values against hardcoded ones at `0x7BF380`

We could dump hashes from the binary:

```
3c9314956b8ecf32f6745a3d7b98338f6b48b584c5e1250feb3e79bfb2a6d5c7
f288534efaf4c06262adea0158526b3bd2985b7a2112a30dadaf9eaa90ad9701
7e0f334f9a5012575aeceec44686b102cf8849ab32cd797f157f09961041231a
f84a58f150a0d9cb21c67ec27970f9cad863c76be773c8417650d63c13352e66
27fe87f345ea08a26e8f732f5120e2ef419b9a03a6ef14e8f18a3b83bd41a81c
8bd574fdb05c2dc5017188a2f4c32d5b81963e0a33eccba92404e968c665006d
```

Since we know the length of that values and we know the values [a-f0-9], we can bruteforce it with the hashcat easily.

```
hashcat64.exe -a3 -m 1400 hashes.txt ?h?h?h?h?h?h
```

This buteforce will be running only a couple of seconds, and give the result:

```
3c9314956b8ecf32f6745a3d7b98338f6b48b584c5e1250feb3e79bfb2a6d5c7 a76857 
f288534efaf4c06262adea0158526b3bd2985b7a2112a30dadaf9eaa90ad9701 f5cbff
7e0f334f9a5012575aeceec44686b102cf8849ab32cd797f157f09961041231a 7d4a83
f84a58f150a0d9cb21c67ec27970f9cad863c76be773c8417650d63c13352e66 60602b
27fe87f345ea08a26e8f732f5120e2ef419b9a03a6ef14e8f18a3b83bd41a81c da247a
8bd574fdb05c2dc5017188a2f4c32d5b81963e0a33eccba92404e968c665006d fd
```

*NOTE: For the last 2-byte we must use `?h?h` argument.*

Now we can combine that values into MD5 and use [hashkiller](https://hashkiller.co.uk/md5-decrypter.aspx) to restore the original value.

```
a76857f5cbff7d4a8360602bda247afd MD5 : B41dy
```

Lets put all the puzzles together.

```
./Avatar
Water Tribes:
Fu11_M00n
Earth Kingdom:
Th3_Bl1nd_0n3
Fire Nation:
420B1B2E57
Air Nomads:
B41dy
You have mastered the four elements and now worthy to earn the flag:
noxCTF{Fu11_M00n-Th3_Bl1nd_0n3-420B1B2E57-B41dy}
```

Wooohooo! Now we got the flag! 

# The ooops.

But the flag will not be accepted by CTFd. Wtf? We could find some hints in strings of binary

>Have you seen the irreversible operations in fire nation?

>The lit speak fluent LEET

Yes indeed, there are multiple values possible in the round 2. To be honest, I had written some bruteforcer, instead of diving in that math, which reveals 4 possible values. 


```
#include <stdio.h>

void main() {

	unsigned long long x, y;
	
	x = ((((((0x1CDEDC990D1L & 0xFFFFFFFFFFFF7FFF ^ 0x6E988) + 0x3B93AE7C) / 14) << 1) | 0x10000) - 0x1E240 + 0x5336654) | 0x40;

	printf("0x%p | %lld\n", x, x);


	for (x = 0x420B1B2E56 + 0x1000000; x > 0x420B1B2E56 - 0x1000000; x--) {

		y = (((14 * (((x | 0x40) - 0x5336654 + 0x1E240) | 0x10000) >> 1) - 0x3B93AE7C) & 0xFFFFFFFFFFFF7FFFL ^ 0x6E988) - 0x1CDEDC990D1L;
		if (!y) {
			printf("correct! 0x%p | .%lld\n", x, x);
			//break;
		}

	}

	printf("done!");
		
}

```

The values are:
```
0x000000420B1B2E56 | 283654172246
correct! 0x000000420B1B2E57 | .283654172247
correct! 0x000000420B1B2E17 | .283654172183
correct! 0x000000420B1A2E57 | .283654106711
correct! 0x000000420B1A2E17 | .283654106647
done!
```

The last one was finally accepted as flag. 

**noxCTF{Fu11_M00n-Th3_Bl1nd_0n3-420B1A2E17-B41dy}**

