# Time's Up, Again - 450pts.

### First Look
Let's run the program and see what happens.

> osboxes@osboxes:/pico19/timesUp2$ ./times-up-again 
>
> Challenge: (((((-52815999) - (-455631185)) + ((506330670) - (287586908))) + (((-783690141) * (1129961688)) + ((968135910) + (-532253008)))) * ((((-611846001) - (1827816890)) - ((261971858) + (1452576703))) + (((-303988106) + (1002750425)) + ((1908742675) + (2058401240)))))
>
> Setting alarm...
>
> Solution? Alarm clock

There does not seem to be much difference from the first Time's Up. Let's look at the program's internals.


### Reversing
As before, we will run `ltrace ./times-up-again` to see the libc function calls made by the program.

Here are the interesting things to notice.

> ualarm(200, 0, 0, 2880)

This is the first change we will notice... ualarm is now called with 200 microseconds instead of 5000.

In other words, we need to be *a lot* faster this time around. Python with pwntools and eval() will not cut it.



> time(0)  = 1570470799
>
> srand(0x5d9b7b8f, 0x7fff191be438, 0x7fff191be448, 0)
>
> fopen("/dev/urandom", "r")  

Just like in the first challenge, it uses the time as srand seed.

However, it also opens /dev/urandom, and then we can see a lot of fread() calls next to the rand() calls.

If we use a decompiler like Ghidra to analyze the executable, we will find that /dev/urandom is used to obtain the integers of the expression, while rand() is used to obtain the operators and the amount of operations. We see that from the functions gen_expr(), get_random() and get_random_op() in particular.  

While we can easily predict the output of rand(), we cannot do the same for /dev/urandom. Because of this, predicting the expression isn't a viable option.


### Solution: Going Fast
Basically, we need to do the same thing that we did in Time's Up 1, but a lot faster. 

We don't have time for games anymore. We have to drop Python and pwntools, and go back to C.

Here are the steps we need to do.
* Start the challenge program from our C program. We will use fork() and exec(). Before the exec(), we will need to have initialized 2 pipes, one for parent -> child communication, and the other for child -> parent communication.
* Obtain the string for the expression we need to solve, by using our C -> P pipe.
* Solve the expression. We will use a modified version of the "tinyexpr" library to do this.
* Send the solution of the expression using our P -> C pipe.
* Obtain the flag using our C -> P pipe.

##### Why do we need a *modified* version of the tinyexpr library?

Because the challenge program uses long int, and since we are dealing with very large numbers, the operations will overflow. We need all 8 bytes. 

Tinyexpr uses double by default, which uses some space to store information about the floating point.

We can simply change every double in the library to a long, and the library will work for our challenge.

See the source code in exploit.c, tinyexpr.c, tinyexpr.h

Flag: **picoCTF{Hasten. Hurry. Ferrociously Speedy. #3b0e50c7}**


### Solution: Going Slow
There is a way to solve the challenge while still using pwntools and eval().<br/>
We can use signal.h in a program of our own that tells to block any SIGALRM. Then we can execute the challenge program and our block directive will be inherited by the challenge.<br/>
You can see this in blockSignal.c. You can use the same technique of pwntools and eval() on this program.


### Credits
Thanks to codeplea for a great, easy to use, and easily modifiable arithmetic parser for C.
https://github.com/codeplea/tinyexpr

