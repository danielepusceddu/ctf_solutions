# Time's Up - 400pts.

### First Look
Let's run the program and see what happens.

>osboxes@osboxes:/pico19/timesUp$ ./times-up 
>
>Challenge: (((((-556682696) + (-1742681648)) + ((455119779) + (-1094692113))) - (((718048668) + (-814245522)) + ((-610588965) + (-514774128)))) - ((((1754003648) + (-999076248)) + ((-422779418) + (-1903498889))) + (((1370463972) + (-1241985648)) + ((-857901974) - (1493859769)))))
>
>Setting alarm...
>
>Solution? Alarm clock

Basically, it asks us to solve an expression and give the result.

After a short delay, the program is killed, so we need to solve the expression fast.


### Reversing
By running the program with `ltrace ./times-up`, we can see every libc function call made by the program.

Here are some useful lines I've found:

> signal(SIGALRM, 0)

This function takes 2 parameters. The first parameter is a constant that indentifies a certain signal. The second parameter tells the course of action for whenever that signal is triggered.


ltrace already tells us that the first parameter is for SIGALRM, the alarm / timer signal.  The second parameter is SIG_DFL (we can verify by looking at the signal.h libc source file). 
Basically, SIG_DFL specifies that the default action for SIGALRM should be taken, which is to kill the program.

It was not added manually by the challenge creators. With gdb, we can see that it is called inside the program start routine.


> time(0) = 1570438963
>
> srand(0x5d9aff33, 0x7ffc54b65288, 0x7ffc54b65298, 0) 

srand gets called with the output of time. 0x5d9aff33 equals to 1570438963.
After this, we can see a lot of calls to rand(). We can assume their purpose is to generate the expression we need to solve.


> ualarm(5000, 0, 0, 2880)
>
> printf("Solution? ") 
>
> __isoc99_scanf(0x55b7f746ee68, 0x55b7f7672770, 0, 0Solution?  <no return ...>
>
> --- SIGALRM (Alarm clock) ---
>
> +++ killed by SIGALRM +++

Finally, we can see that it calls ualarm(5000). That means SIGALRM will be raised after 5000 microseconds, which is 5 milliseconds.

In other words, we need to retrieve the expression, solve it, and give it to the program in less than 5 milliseconds. It's enough time.



### Solution
We can use pwntools and python's eval() to do everything we need.


```
from pwn import *

p = process('./times-up')
p.recvuntil('Challenge: ')
expr = p.recvline()
result = eval(expr)
p.sendline(str(result))
print p.recvall()
```

Flag: **picoCTF{Gotta go fast. Gotta go FAST. #028ca78e}**
