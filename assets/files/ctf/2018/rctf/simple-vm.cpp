// ConsoleApplication2.cpp : Defines the entry point for the console application.
//

#define  _CRT_SECURE_NO_WARNINGS 1

//#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

long buf = 0;
void* ptr = 0;

#define _DWORD unsigned int
#define _BYTE unsigned char

#define __int64 unsigned int

DWORD globVar;
DWORD c;


__int64 vm()
{
	__int64 currentInst; // rax
	_BYTE *base; // rbp
	int nextInst; // ebx
	__int64 v4; // rdx
	__int64 v5; // rax
	__int64 v6; // rax
	__int64 v7; // rax
	__int64 v8; // rax
	__int64 v9; // rax
	int v10; // eax
	__int64 v11; // rax
	char v12; // dl
	int v13; // eax
	int v14; // eax
	_BYTE *v15; // rax
	__int64 v16; // rax
	__int64 v17; // rax
	__int64 v18; // rax
	unsigned int tmp; // rax

	currentInst = 0LL;
	base = (_BYTE*)ptr;
	while (1)
	{
		nextInst = currentInst + 1;
		switch (base[currentInst])
		{
		case 0:
			//printf("exit");
			return *(unsigned int *)&base[nextInst];
		case 1:
			tmp = *(_DWORD *)&base[nextInst];
			//printf("\t#1:0x%x GOTO 0x%x\n", currentInst, tmp);
			goto LABEL_35;
		case 2:
			
			v4 = nextInst;
			nextInst = currentInst + 9;
			base[*(signed int *)&base[v4]] = *(_DWORD *)&base[(signed int)currentInst + 5];
			//printf("\t#2:0x%000x [0x%x] = 0x%x [0x00x]\n", currentInst, v4, *(_DWORD *)&base[(signed int)currentInst + 5], (signed int)currentInst + 5);
			break;
		case 3:
			
			v5 = nextInst;
			nextInst += 4;
			v6 = *(signed int *)&base[v5];
			//printf("\t#3:0x%000x C (0x%x) =  DB [0x%x] (0x%x) \n", currentInst, c, v6, base[v6]);
			goto LABEL_27;
		case 4:
			
			v7 = nextInst;
			nextInst += 4;
			v8 = *(signed int *)&base[v7];
			//printf("\t#4:0x%000x [0x%x] = C (0x%x) \n", currentInst, v8, c);
			goto LABEL_31;
		case 5:
			v9 = nextInst;
			nextInst += 4;
			v10 = (char)base[*(signed int *)&base[v9]];
			//printf("\t#5:0x%x G (0x%x) = [0x%x] (0x%x)\n", currentInst, globVar, *(signed int *)&base[v9], v10);
			goto LABEL_21;
		case 6:
			v11 = nextInst;
			v12 = globVar;
			nextInst += 4;
			v8 = *(signed int *)&base[v11];
			//printf("\t#6:0x%x [0x%x] (0x%x) = G (0x%x)\n", currentInst, v8, base[v8], globVar);

			/// base[v8] = v12;
			goto LABEL_9;
		case 7:
			//printf("\t#7:0x%x \n", currentInst);
			v13 = globVar;
			goto LABEL_23;
		case 8:
			
			v14 = ~(globVar & c);
			//printf("\t#8:0x%x C = ~(storedG 0x%x  & C 0x%x) RES = 0x%x \n", currentInst, globVar, c, v14);
			goto LABEL_12;
		case 0xA:
			//printf("\t#0xA:0x%x C = GETCHAR() \n", currentInst);
			v14 = getchar();


			goto LABEL_12;
		case 0xB:
			//printf("\t#0xB: PUTCHAR(C) \n");
			putchar(c);
			break;
		case 0xC:
			
			v15 = &base[*(signed int *)&base[nextInst]];
			//printf("\t#0xC:0x%x IF [0x%x]-- (0x%x) GOTO 0x%x ----------- \n", currentInst, nextInst, *v15, *(_DWORD *)&base[nextInst + 4]);
			if (*v15)
			{
				nextInst = *(_DWORD *)&base[nextInst + 4];
				--*v15;
			}
			else
			{
				//printf(")))) endloopp\n");
				nextInst += 8;
			}

			
			break;
		case 0xD:
			//printf("\t#0xD:0x%x C++ (0x%x)\n", currentInst, c);
			++c;
			break;
		case 0xE:
			//printf("\t#0xE:0x%x G++ (0x%x)\n", currentInst, globVar);
			++globVar;
			break;
		case 0xF:
			//printf("\t#0xF:0x%x \n", currentInst);
			v14 = globVar;
			goto LABEL_12;
		case 0x10:
			//printf("\t#0x10:0x%x G (0x%x) = C (0x%x) \n", currentInst, globVar, c);
			v10 = c;
			goto LABEL_21;
		case 0x11:
			
			v16 = nextInst;
			nextInst += 4;
			v13 = *(_DWORD *)&base[v16];
			//printf("\t#0x11:0x%x C (0x%x) += DD (0x%x) \n", currentInst, c, v13);
		LABEL_23:
			c += v13;
			break;
		case 0x12:
			//printf("\t#0x12:0x%x C = G (0x%x)\n", currentInst, globVar);
			v6 = globVar;
			goto LABEL_27;
		case 0x13:
			//printf("\t#0x13:0x%x C = [C] (0x%x)\n", currentInst, c);
			v6 = c;
		LABEL_27:
			v14 = (char)base[v6];
			goto LABEL_12;
		case 0x14:
			//printf("\t#0x14:0x%x \n", currentInst);
			v17 = nextInst;
			nextInst += 4;
			v14 = *(_DWORD *)&base[v17];
			goto LABEL_12;
		case 0x15:
			v18 = nextInst;
			nextInst += 4;
			v10 = *(_DWORD *)&base[v18];
			//printf("\t#0x15:0x%000x G (0x%x) = DD [0x%x] (0x%x) \n", currentInst, globVar, v18, v10);
		LABEL_21:
			globVar = v10;
			break;
		case 0x16:
			//printf("\t#0x16:0x%x [G(0x%x)] = C (0x%x)\n", currentInst, globVar, c);
			v8 = globVar;
		LABEL_31:
			v12 = c;
		LABEL_9:
			base[v8] = v12;
			break;
		case 0x17:
			//printf("\t#0x17:0x%x C (0x%x) -= G (0x%x) \n", currentInst, c, globVar);
			v14 = c - globVar;
		LABEL_12:
			c = v14;
			break;
		case 0x18:
			//printf("\t#18:0x%x if C (%0x %d) goto 0x%04x <<<<<<<<<<<<<<< \n", currentInst, c, c, *(_DWORD *)&base[nextInst]);


			if (c) {
			LABEL_35:
				nextInst = *(_DWORD *)&base[nextInst];
			}
			else
				nextInst = currentInst + 5;
			break;
			
		default:
			break;
		}
		if (nextInst >= buf)
			return 0LL;
		currentInst = nextInst;
	}
}

int main()
{
	FILE *v3; // rax
	const char *v4; // rdi
	FILE *v5; // rbx
	size_t v6; // rbp
	void *v8; // rax

	v3 = fopen("p.bin", "rb");
	v4 = "err 0";
	if (!v3)
		goto LABEL_4;
	v5 = v3;
	fseek(v3, 0LL, 2);
	buf = ftell(v5);
	fseek(v5, 0LL, 0);
	v6 = buf;
	if (buf <= 0)
	{
		v4 = "err 1";
	LABEL_4:
		puts(v4);
		return 0xFFFFFFFFLL;
	}
	v8 = malloc(buf);
	ptr = v8;
	v4 = "err 3";
	if (!v8)
		goto LABEL_4;
	v4 = "err 4";
	if (buf != fread(v8, 1uLL, v6, v5))
		goto LABEL_4;
	fclose(v5);
	v4 = "err 5";
	if ((unsigned int)vm())
		goto LABEL_4;
	free(ptr);


	return 0LL;
}