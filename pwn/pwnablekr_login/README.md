### Summary
Basically, it's a challenge about buffer overflow, but you can only overwrite the EBP.
We can make EBP point to our input, which enables us to set the return address of the caller of the vulnerable function.

### Payload
```
aaaaa  // will get popped by 2nd leave
<system_gadget>
<pointer to aaaa>  // Overflow on EBP
```

1st leave: pops pointer to EBP register

2nd leave: pops aaaa to ebp, return address will be `<system_gadget>`



### Vulnerable code

```C
_BOOL4 __cdecl auth(int a1)
{
  char v2; // [esp+14h] [ebp-14h]
  char *s2; // [esp+1Ch] [ebp-Ch]
  int v4; // [esp+20h] [ebp-8h]

  memcpy(&v4, &input, a1); //a1 can be at most 12, overflow of 4
  s2 = (char *)calc_md5((int)&v2, 12);
  printf("hash : %s\n", s2);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}
```

### Flag
`control EBP, control ESP, control EIP, control the world~`
