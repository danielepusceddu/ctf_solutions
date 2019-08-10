libc-2.15 is loaded into memory at a fixed address.

There is an unsafe strcpy we can use to ROP. However, we can't use any byte that is not printable.

I made a Ropper script, ropscript.py, to find all gadgets with printable addresses.

Then after going through them to find useful gadgets, I created the payload in ascii.py
