# CanaRy - 300pts.
### Reversing
Let's look at the program's source, vuln.c.<br/>
We can see that the program tries to emulate a canary in the vuln() function...<br/>

```
char canary[KEY_LEN];
char buf[BUF_SIZE];
```

The program asks us how many characters we want to write into buf. There is no real limit, we can overflow it.<br/>
However, when we overflow buf, we end up touching canary. The program checks the integrity of canary, if we modified it, the function calls exit().<br/>

**How's the canary obtained?**<br/>
In the function read_canary(), we see that the canary is obtained from a file canary.txt in the challenge's directory.</br>
Let's do an ls.<br/>

```
user@pico-2019-shell1:/problems/canary_4_221260def5087dde9326fb0649b434a7$ ls -al
total 96
drwxr-xr-x   2 root       root        4096 Sep 28 22:06 .
drwxr-x--x 684 root       root       69632 Oct 10 18:02 ..
-r--r-----   1 hacksports canary_4       5 Sep 28 22:06 canary.txt
-r--r-----   1 hacksports canary_4      42 Sep 28 22:06 flag.txt
-rwxr-sr-x   1 hacksports canary_4    7744 Sep 28 22:06 vuln
-rw-rw-r--   1 hacksports hacksports  1469 Sep 28 22:06 vuln.c
```

We can see that canary.txt's "last modified" is the same as all the other files, so... It's a constant canary. Not very useful.

### Exploit
We have a constant canary. We can just **bruteforce the canary** byte by byte.<br/>
After we know the canary, we can skip the exit() call and redirect the program's flow, overwriting the return address with the display_flag() function address.<br/>
However, there is another problem. What is the function address? The executable has PIE enabled. <br/>
Since the program is 32bit, we can easily **bruteforce the PIE base address**.<br/>
Only some of the 32 bits are actually random. We can bruteforce it easily.<br/>

In short, there are 2 steps required:
* Bruteforce the constant canary
* Bruteforce the 32bit PIE address

The full exploit is written in exploit.py<br/>

Flag: **picoCTF{cAnAr135_mU5t_b3_r4nd0m!_bf34cd22}**
