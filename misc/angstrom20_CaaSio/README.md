# CaaSio
## Misc, 220 pts.

#### Description
Clam's creative calculator causes coders' chronic craziness. Find his calculator-as-a-service over tcp at nc misc.2020.chall.actf.co 20201 and the flag at /ctf/flag.txt. Remember, the "b" in regex stands for "bugless." Source.

Author: aplet123

#### Hint
The calculator is merely a prototype.

### Writeup
This is a calculator service that makes use of javascript's eval.<br>
That is already a big red flag, however our input is filtered heavily by a regex:

`/(?:Math(?:(?:\.\w+)|\b))|[()+\-*/&|^%<>=,?:]|(?:\d+\.?\d*(?:e\d+)?)/g`

This regex is not applied if user.trusted equals true. So our goal is setting that boolean to true, this will enable us to make full use of eval(), which we will use to read the flag file. How do we do it?<br>
We can send at most 3 queries. We would need 2 queries to read the file, so we're limited to one query below 200 characters.<br>


#### Modifying Math
Math is the only object we have access to. It is frozen, meaning we can't modify its attributes. We also can't modify its attributes' attributes: Object.freeze() is shallow, yes, but the regex prevents us from doing it anyway.<br>
`Math.attribute.x' gets filtered to `Math.attribute`.

#### Prototypes
The hint given to us is very important: it mentions prototypes. Prototypes are a feature of Javascript, they are like a static father object which other objects inherit from.<br> 
Now, notice something: `user.trusted` is never set. It is undefined. We could define `user.trusted` in the prototype and there would be no shadowing by user's attributes. Math shares the same prototype as user, so we can do it from there, since Math is the only object we have access to.

#### Anonymous Functions
The regex is very restricting, but we have enough characters to create and *call* an anonymous javascript function. This is the solution.

`((Math,)=>(Math.trusted=1))(Math.__proto__)`

Math is the only name we can use for the parameter. We call it with `Math.__proto__`, so what happens is this: `Math.__proto__.trusted=1`. Since user shares the same prototype and has no trusted attribute, user.trusted will be the same object as `user.__proto__.trusted` and `Math.__proto__.trusted`.<br>
We can now read the flag with the fs module.

```
> ((Math,)=>(Math.trusted=1))(Math.__proto__)
1
> var fs = require('fs');
undefined
> fs.readFileSync('/ctf/flag.txt', 'ascii');
actf{pr0t0typ3s_4re_4_bl3ss1ng_4nd_4_curs3}
```

### Flag
`actf{pr0t0typ3s_4re_4_bl3ss1ng_4nd_4_curs3}`
