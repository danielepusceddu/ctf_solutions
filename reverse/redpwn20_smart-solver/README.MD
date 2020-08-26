This is a Vim challenge in disguise. There is a HUGE main, with many conditionals, and the challenge name hints us to use z3. Get the assembly with `gdb -batch -ex 'file ./SMarT-solver' -ex 'disassemble main' > maindump.txt`

Remove the instructions above and below the conditionals, and start working to turn this into python z3 code.

```
:%g/^cmp/norm dd
:%s/^jae.*/</   # jae: exit if above or equal. so, we want below
:%s/^jbe.*/</
df[$xJldf[$xJldwBPli ^[j0  # run this macro like 5000 times. ^[ is an ESC
:%s/-//g            # the - cannot be used in python variable names.
```

This is what we've got now:
```rbp0x120 < rbp0x11f
rbp0x120 > rbp0x11e 
rbp0x120 < rbp0x11d 
rbp0x120 < rbp0x11c 
......
```

Make a copy of the file as it is now. We'll come back to it later.
Run these 2 commands:
```
:%s/^/s.add(/
:%s/$/)/```

And we got the constraints ready.
```s.add(rbp0x120 < rbp0x11f)
s.add(rbp0x120 > rbp0x11e)
s.add(rbp0x120 < rbp0x11d)
s.add(rbp0x120 < rbp0x11c)
......```


Now, we need to define all these variables. Open the copied file 
```
:%s/ .*//
:sort u     # sort all lines and remove duplicates
```

And use the macro `A = BitVec('^[0yw$pa', 8)^[j0`
Now we got:

```rbp0x100 = BitVec('rbp0x100', 8)
rbp0x101 = BitVec('rbp0x101', 8)
rbp0x102 = BitVec('rbp0x102', 8)
rbp0x103 = BitVec('rbp0x103', 8)
........
``` 


And you get the gist. The challenge description tells us the characters are all lowercase, so add constraints for that, and remember to include `{` and `}`.
