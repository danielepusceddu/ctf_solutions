The executable mmaps a zone of memory and then lets us write to it. The zone of memory is then executed.

Seccomp is used to allow only the open, read, write and exit syscalls.

We load the filename to the mmap memory and write a shellcode that opens it and writes it to stdout.

The shellcode was written manually as the purpose of this challenge is to practice writing shellcode. However we could've used pwntool's shellcraft instead.

We could've pushed the filename to the stack instead but that greatly increases the size of the shellcode and it is more complex to do manually. pwntools provides the shellcraft.pushstr() function to do that.


The challenge is solved but I have a doubt.
This script works when connecting to the server. It does not work when I use it locally.

The issue is in the filename. To work on my machine, I have to prepend "./" or "/" to the filename.

That makes sense to me because the executable chroots to the flag's directory. However it doesn't work with the server and I have no idea why. "./" nor "/" work.


