What does the f say?
Description
Tired from exploring the endless mysteries of space, you need some rest and a welcome distraction. 
From extreme flaming kamikazes to dangleberry sours, Fox space bar has everything. 
Treat yourself like a king, but be careful! Don't drink and teleport!

Challenge Overview

•	Given a 64-bit binary, dynamically linked, and not stripped.
•	Binary protections:
•	RELRO: FULL
•	Canary: ENABLED
•	NX: ENABLED
•	PIE: ENABLED
•	RPATH: NONE
•	RUNPATH: NONE

Vulnerabilities Exploited

1.	Format String Vulnerability (FSB): Found in the drinks_menu() function.
2.	Buffer Overflow (BOF): Possible in the warning() function due to lack of input validation.

Approach

1.	Leaking Canary and PIE:
•	Exploit the FSB to leak Canary and PIE addresses.
2.	Leaking Libc:
•	Leak a libc address to determine the libc version.
3.	Calculating Libc Base:
•	Calculate the libc base address to perform Return-to-Libc (Ret2Libc) attack.
4.	Exploiting the BOF:
•	Craft a payload to perform Ret2Libc attack and gain a shell.

Usage
1.	Run the provided exploit script solve.py to interact with the challenge.
2.	Follow the script to leak addresses, calculate bases, and exploit the vulnerability.

Requirements
•	Python (3.x recommended)
•	pwntools library (pip install pwntools)

This challenge was created for the purpose of enhancing exploit development skills.

