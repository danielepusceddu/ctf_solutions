#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('infinity_gauntlet')

host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 21700)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()
from time import time
from math import floor
import re


from ctypes import CDLL
libc = CDLL('/usr/lib/libc.so.6')
start_time = libc.time(0)
libc.srand(start_time)

def toint_ifpossible(x: str):
    try:
        x = int(x)
    except Exception:
        pass
    return x

def get_round_equation():
    io.recvline() # round num line
    eq = io.recvline().decode().strip()
    eq_type, params, result = re.search('(foo|bar)\((.*)\) = (\d*)', eq).groups()
    params = params.replace(' ', '').split(',')
    params = [toint_ifpossible(x) for x in params]

    log.info(eq)
    return eq_type, params, toint_ifpossible(result)

def parse_foo(par1, par2, result):
    if par1 == '?':
        target = result ^ 0x539 ^ (par2 + 1)
    elif par2 == '?':
        target = (result ^ 0x539 ^ par1) - 1
    else:
        target = par1 ^ 0x539 ^ (par2 + 1)
    return target

def parse_bar(par1, par2, par3, result):
    if par1 == '?':
        target = result - (par2 * (par3 +1))
    elif par2 == '?':
        target = (result - par1) // (par3+1)
    elif par3 == '?':
        target = ((result - par1) // (par2)) - 1
    else:
        target = par1 + par2 * (par3+1)
    return target

io.recvline()
flag_len = 5
flag = list('?' * flag_len)

for roundnum in range(1, 300):
    log.info(f'Round Num: {roundnum}')
    io.recvline()

    v14 = libc.rand()

    if roundnum <= 49:
        answer = libc.rand() % 0x10000
    
    func = libc.rand() # choose between foo and bar
    log.info('Predicting: ' + ('foo' if func & 1 != 0 else 'bar'))

    eq_type, params, result = get_round_equation()

    if eq_type == 'bar':
        v16 = libc.rand()
        v17 = v16 % 4
        if not ((v16 & 3) != 0 and v17 != 1 and v17 != 2):
            libc.rand()

        libc.rand()
        target = parse_bar(*params, result)
    else:
        libc.rand()
        libc.rand()
        target = parse_foo(*params, result)

    if roundnum > 49:
        upper_byte_real = target & 0xFF00
        upper_byte_prediction = (v14 % flag_len + roundnum) << 8 & 0xFF00
        while upper_byte_prediction != upper_byte_real:
            flag_len += 1
            upper_byte_prediction = (v14 % flag_len + roundnum) << 8 & 0xFF00
            flag = list('?' * flag_len)

        log.info(f'Upper byte expected: {upper_byte_prediction}, Real: {upper_byte_real}')
        assert upper_byte_real == upper_byte_prediction

        encrypted_char = target & 0xFF
        char_index = v14 % flag_len
        v9 = 17 * char_index
        char_plain = chr((v9 ^ encrypted_char) % 256)
        flag[char_index] = char_plain
        log.info(''.join(flag))

        if '?' not in flag:
            log.info('Flag complete.')
            break

    else: # roundnum <= 49
        log.info(f'{target}, {answer}')
        assert target == answer, 'test'

    io.sendline(str(target))

# actf{snapped_away_the_end}
io.close()

