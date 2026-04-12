# elf_loader
This repo just has a tiny generic-ish ELF loader written entirely in Nim.

It doesn't aim to replace glibc's dlfcn entirely, rather just act as a generic loader for various different ELF variants on the same system (e.g loading a Bionic-compiled shared object on desktop GNU/Linux), regardless of compatibility, though this'll probably require a lot more work.

# roadmap
- [X] map segments and stuff
- [X] open glibc
- [X] perform enough relocations to make it happy
- [X] call `.init_array`
- [X] basic calls like `_exit` work (calls that reach into glibc's internal state either don't work, or end up deadlocking, say, if they try messing with a futex)
- [X] some calls like `open` work, but crash and/or cause UB if they try setting errno (probably TLS work is required)
- [ ] Proper TLS initialization (glibc-style)
- [ ] Optional Bionic-style TLS initialization
