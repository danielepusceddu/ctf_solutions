# Time's Up, One Last Time - 500pts.

**Please take a minute to read the writeup of Time's Up Again before reading this writeup**

### First Look
Let's run the program and see what happens.

> osboxes@osboxes:/pico19/timesUp3$ ./times-up-one-last-time
>
> Challenge: (((((81350923) x (992025469)) * ((-345445693) f (-1965453472))) o (((-1637073355) t (953418846)) x ((-1728968449) ^ (-1556478121)))) o ((((-1265342796) o (-2122365540)) & ((2042378268) x ((-1634343330) / (-1451382175)))) o (((828482903) ^ (945852822)) f ((-1648182454) + (-667561138)))))
>
> Setting alarm...
>
> Alarm clock

This time, we see an important difference... What are those new operators? In the previous challenges we saw only subtraction, sum and division.


### Reversing
#### strace
Let's see strace.

> ualarm(10, 0, 0, 2880)

This time we only have 10 microseconds... Doing all of these operations on PicoCTF's toasters sounds unrealistic. This time we're forced to escape SIGALRM as I've shown you in the writeup for Time's Up Again.

There is another very interesting difference in the strace output. This time, we don't see any call to `signal(SIGALRM, SIG_DFL)`, which opens up a new way to avoid SIGALRM: By using `signal(SIGALRM, SIG_IGN)` before our exec.

This makes me think that using sigprocmask was not an intended solution for Time's Up Again. We will never know.

#### decompile
We need to find out what those new operators do. After looking around a bit with IDA, I've found that we can see it from the function at offset 0xCA2.

```
  switch ( (unsigned int)off_1024 )
  {
    case '%':
      if ( a3 )
        result = a2 % a3;
      else
        result = a2;
      break;
    case '&':
      result = a3 & a2;
      break;
    case '*':
      result = a3 * a2;
      break;
    case '+':
      result = a2 + a3;
      break;
    case '-':
      result = a2 - a3;
      break;
    case '/':
      if ( a3 )
        result = a2 / a3;
      else
        result = a2;
      break;
    case '^':
      result = a3 ^ a2;
      break;
    case 'f':
      result = a2;
      break;
    case 'o':
      result = a3;
      break;
    case 'r':
      result = a3;
      break;
    case 't':
      result = a2;
      break;
    case 'x':
      result = a3;
      break;
    case '|':
      result = a3 | a2;
      break;
    default:
      exit(1);
      return result;
  }
```

Sum, sub, and mul are the same as always.<br/>
Notice that division and modulo return the lvalue if the rvalue equals to 0.<br/>
**&, ^, and |** are the correspondent bitwise operators.<br/>
**f, o, r, t, x** are just some weird operators that return either lvalue or rvalue, nothing difficult.<br/>
 

### Solution: Solving the expression
Knowing this, we can use the power of Libre software to modify the tinyexpr library to suit our needs. We need to add these operators to the library and the expression will be solved properly.<br/>
You can see this solution in the files exploit.c and tinyexpr.c<br/>


### Solution: Bruteforce
While testing my first solution (solving the expression), I realized that thanks to the bitwise operators, the solution of the expression often ends up being 0.<br/>
So, instead of actually solving the expression, we can just send '0' a lot of times until we get the flag.<br/>
Run the program barebones.c until you get the flag.<br/>


### Credits
Thanks to codeplea for a great, easy to use, and easily modifiable arithmetic parser for C.<br/>
https://github.com/codeplea/tinyexpr

