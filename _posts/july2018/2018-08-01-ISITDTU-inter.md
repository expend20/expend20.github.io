---
layout: post
title: "[ISITDTU CTF:inter] Reversing inter.exe"
comments: true
---


![](/assets/files/ctf/2018/ISITDTU/inter/inter_task.png)

* [Original task](https://ctf.isitdtu.com/challenges#Inter)
* [ctftime](https://ctftime.org/event/642)


We are given by [inter.exe](/assets/files/ctf/2018/ISITDTU/inter/inter.exe) file, which is:

```
inter.exe: PE32 executable (console) Intel 80386, for MS Windows
```

Let's analyze the file with a disassembler. The first thing we notice, that it creates the first thread, sleeps 0x64 seconds and create the second thread.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{

  ...

  CreateThread(0, 0, StartAddress, 0, 0, &ThreadId);
  Sleep(0x64u);
  CreateThread(0, 0, (LPTHREAD_START_ROUTINE)thread2, 0, 0, &v6);
  v14 = unk_403240;

  ...

```

The first thread opens named pipe and reads data from it:

```
  hNamedPipe = CreateNamedPipeW(L"\\\\.\\pipe\\LogPipe", 3u, 0, 1u, 0x400u, 0x400u, 120000u, 0);
        
...

	ConnectNamedPipe(v2, 0);
        ReadFile(v2, Buffer, 0x400u, &NumberOfBytesRead, 0);

```

The second thread is anti debugging thread, it checks software breakpoints `int 3` or `0xcc` by xoring code data

```
  while ( (*((_BYTE *)StartAddress + v2) ^ 0x55) != 0x99u )
  {
    if ( ++v2 >= a2 )
      return 0;
  }

```

We can simply patch that sleep and creation of the second thread.

Now the program has only 2 threads. One is the main thread, that reads the user input and writes to the pipe, the second one reads data from the pipe, comparing it to some values and write back the result.

The program expects from user 5 numbers. When you enter the number, it is converted from `ascii` to `int`, and the sum of digits is computed. For the first number, the particular check is

```
        case 1:
          if ( numSum != 0x1E )
            goto FAIL;
          v20 = intNum ^ 0x1E;
          v8 = ((unsigned __int8)(intNum ^ 0x1E) | (((unsigned __int8)(BYTE1(intNum) ^ 0x1E) | (((unsigned __int8)(BYTE2(intNum) ^ 0x1E) | ((unsigned __int8)(HIBYTE(intNum) ^ 0x1E) << 8)) << 8)) << 8)) == 0x672E6B41;
LABEL_11:
          if ( !v8 )
            goto FAIL;
          goto OK;
```

So, the input must be:

```
>>> 0x672E6B41 ^ 0x1e1e1e1e
2033218911
>>> hex(2+0+3+3+2+1+8+9+1+1)
'0x1e'
```

For the second number the check is a little bit more complex:

```
        case 2:
          if ( numSum == 35 )
          {
            v9 = 0;
            v18 = 0x40C211F;
            v19 = 0x1F18;
            if ( intNum > 0 )
            {
              while ( 1 )
              {
                v10 = intNum;
                intNum /= 35;
                v11 = *((unsigned __int8 *)&v18 + v9++);
                if ( (unsigned int)(v10 % 35) != v11 )
                  break;
                if ( intNum <= 0 )
                {
                  if ( v9 != 6 )
                    goto FAIL;
                  v2 = hNamedPipe;
                  WriteFile(hNamedPipe, L"1", 2u, &NumberOfBytesWritten, 0);
                  v1 = 2;
                  goto LABEL_5;
                }
              }
            }
          }
          goto FAIL;
```

Instead of reconstructing logic we can write a simple bruteforcer, that will check all possible values within a couple of seconds:

```
typedef struct  {
	int v18;
	int v19;
} v1819t;

void solve2() {

	int v9, v18, v10, intNum, v11, v2, v19, i;

	v1819t v1819;


	for (i = 0; i < 0xFFFFFFFF; i++) {

		intNum = i;

		v9 = 0;
		v1819.v18 = 0x40C211F;
		v1819.v19 = 0x1F18;
		if (intNum > 0)
		{
			while (1)
			{
				v10 = intNum;
				intNum /= 35;
				v11 = *(char*)((size_t)&v1819.v18 + v9++);
				if ((v10 % 35) != v11)
					break;
				if (intNum <= 0)
				{
					if (v9 != 6) {
						printf("NO :(\n");
						
						break;
					}

					printf("YES! %d\n", i);
					return;
				}
			}
		}

	}

	printf("nope");
}
```

The result is `1664380511`. 

The third value is simple check:

```
        case 3:
          if ( numSum != 0x21 )
            goto FAIL;
          v8 = ((intNum + 0x21) ^ 0xCAFEBABE) == 0xA8CAD9EF;
          goto LABEL_11;
```

The result is:

```
>>> (0xA8CAD9EF ^ 0xCAFEBABE) - 0x21
1647600432
```

For the fourth number MD5 hash is computed, then the result is compared with `e861a6e17bd11a7cec8b6c8514728d2b`. We can use [HashKiller](https://hashkiller.co.uk/md5-decrypter.aspx) to find the number:

```
e861a6e17bd11a7cec8b6c8514728d2b MD5 : 1835360107
``` 

And the last one:

```
if ( numSum == 45 && ((intNum + 45) ^ 0xCAFACADA) == 0xFB94F394 )
```

The number is:

```
>>> (0xFB94F394 ^ 0xCAFACADA) - 45
829307169
```

Let's put it all together and get the flag.

```
        >>>>>>Challenge crack<<<<<<
Please give me 5 numbers to get the flag: 2033218911
1664380511
1647600432
1835360107
829307169
You Win. Submit flag: ISITDTU{y0u_c4n_b4c0me_k1n9!}
```

