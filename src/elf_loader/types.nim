## Types and internal loader state structs
##
## Copyright (C) 2026 Trayambak Rai (xtrayambak@disroot.org)
import pkg/elf_loader/elf

type
  LoaderCallbacks* = object
    resolveSymbol*: proc(name: string): pointer

  LibraryState* = object
    ## Private state used exclusively by the loader.
    ## Not meant for public usage, unless you know what you're doing!
    loadBias*: int64 ## The real address at which the allocated segments are
    dyn*: seq[ELF64Dyn]
    tp*: pointer

    callbacks*: LoaderCallbacks

  Library* = object
    path*: string ## Absolute path to the library
    fd*: int32 ## File descriptor to the library

    elf*: ELF ## Parsed ELF data

    state*: LibraryState
