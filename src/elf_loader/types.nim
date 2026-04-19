## Types and internal loader state structs
##
## Copyright (C) 2026 Trayambak Rai (xtrayambak@disroot.org)
import pkg/elf_loader/elf

type
  LoaderCallbacks* = object
    resolveSymbol*: proc(name: string): pointer

  LibraryCache* = object
    ## Private library state cache.
    ## Not meant for public usage at all.
    hasGnuHash*: bool
    gnuHash*: uint64 # DT_GNU_HASH, cached after the library is loaded.

    hasSymTab*: bool
    symTable*: uint64 # DT_SYMTAB, cached after the library is loaded.

  LibraryState* = object
    ## Private state used exclusively by the loader.
    ## Not meant for public usage, unless you know what you're doing!
    loadBias*: int64 ## The real address at which the allocated segments are
    dyn*: seq[ELF64Dyn]
    tp*: pointer

    callbacks*: LoaderCallbacks
    cache*: LibraryCache

  Library* = object
    path*: string ## Absolute path to the library
    fd*: int32 ## File descriptor to the library

    elf*: ELF ## Parsed ELF data

    state*: LibraryState
