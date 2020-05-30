### Summary
Heap challenge with libc 2.27, which introduces tcache.

This is the first heap challenge I solved, so some things I'm about to say may be wrong.

We need a leak to libc base addr, we can double free but we can't get out of the tcache because we have a limited number of frees available and we can't create chunks bigger than tcache limit.

We can't leak libc address from tcache chunks because they won't ever point to a wilderness, they'll just point to NULL

However, we can set up a fake chunk with size 0x500 and then free it. 0x500 doesn't fit in tcache, so it will give us pointers to wilderness. I bumped into some libc security checks such as `(!prev)` and `corrupted size vs. prev_size`, and basically I had to exploit tcache poisoning with the double free to write more fake chunks to evade these checks.

Techniques used:
https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_dup.c

https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_poisoning.c

Docker for challenge:

https://github.com/hsncsclub/HSCTF-6-Problems/tree/master/pwn/aria-writer
