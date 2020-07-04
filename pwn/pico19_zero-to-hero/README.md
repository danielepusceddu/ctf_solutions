## Things to take away from this challenge
* tcache does not use `prev_size`... If you use, for example, 0x108 as size, your input will be placed right next to `size` of the next tcache chunk
* null byte overflow can be used to change the tcache bin of the next chunk, allowing you to double free it even on 2.29. This is because the double free check simply checks if the chunk is already present in its tcache bin. Free it -> Change its bin -> Free it again
* Something kool to do: Changing `free_hook` to `system` -> Freeing a chunk with `/bin/sh` as its content :^)))
