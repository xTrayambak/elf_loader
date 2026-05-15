## Core library loading routines
##
## Copyright (C) 2026 Trayambak Rai (xtrayambak@disroot.org)
import std/[strformat, options, posix]
import pkg/elf_loader/[common, elf, gnu_hash, relocator, types]
#!fmt: off
import pkg/[results, shakar, pretty]
#!fmt: on

proc handleLoadPhdr(
    lib: var Library, phdr: ProgramHeader, pageSize: int64
): Result[void, string] =
  ## Handle a Load program header
  let
    vma = cast[int64](phdr.virtualAddr) + lib.state.loadBias
    offset = cast[int64](phdr.offset)

    pageStart = vma and -pageSize
    offsetDiff = vma - pageStart
    mappedSize = phdr.memSize + cast[uint64](offsetDiff)
    fileOffset = offset - offsetDiff

    fileEnd = vma + cast[int64](phdr.fileSize)
    memEnd = vma + cast[int64](phdr.memSize)

    filePageEnd = (fileENd + pageSize - 1) and -pageSize
    memPageEnd = (memEnd + pageSize - 1) and -pageSize

    fileMappedSize = cast[uint64](filePageEnd - pageStart)

  if mappedSize == 0: #or phdr.virtualAddr == 0:
    return ok()

  var prot: int32
  if phdr.flags.contains(PHFlag.Executable):
    prot = prot or PROT_EXEC

  if defined(elfLoaderWritablePages) or phdr.flags.contains(PHFlag.Writable):
    prot = prot or PROT_WRITE

  if phdr.flags.contains(PHFlag.Readable):
    prot = prot or PROT_READ

  debug(&"handle LOAD program header. vma=0x{vma:X}; offset={offset}")
  if fileMappedSize > 0:
    debug(
      &"mmap(addr=0x{pageStart:X}, size={mappedSize}, prot={prot}, fd={lib.fd}, offset=0x{fileOffset:X})"
    )
    let section = mmap(
      cast[pointer](pageStart),
      cast[int64](mappedSize),
      prot,
      MAP_PRIVATE or MAP_FIXED,
      lib.fd,
      fileOffset,
    )

    if section == MAP_FAILED:
      return err(
        &"Failed to allocate page for LOAD program header: {strerror(errno)} ({errno})"
      )

  if phdr.memSize > phdr.fileSize:
    # bss
    let
      zerStart = fileEnd
      zerEnd = min(memEnd, filePageEnd)
      zerSize = cast[int64](zerEnd - zerStart)

    if zerSize > 0:
      # just zero out the tail of the last page mapped from the file
      zeroMem(cast[pointer](zerStart), zerSize)

    if memPageEnd > filePageEnd:
      # map any remaining BSS pages
      let bssSize = memPageEnd - filePageEnd

      let bss = mmap(
        cast[pointer](filePageEnd),
        bssSize,
        prot,
        MAP_PRIVATE or MAP_FIXED or MAP_ANONYMOUS,
        -1,
        0,
      )

      if bss == MAP_FAILED:
        return err(&"Failed to map BSS section: {strerror(errno)} ({errno})")

  ok()

proc handleLoadPhdrs(lib: var Library, pageSize: int64): Result[void, string] =
  var maxVma: uint64
  var minVma = high(uint64)

  for phdr in lib.elf.prog:
    if phdr.kind != ProgramHeaderKind.Load:
      continue

    if minVma > phdr.virtualAddr:
      minVma = phdr.virtualAddr
    if maxVma < (phdr.virtualAddr + phdr.memSize):
      maxVma = phdr.virtualAddr + phdr.memSize

  assert(maxVma > minVma)

  let totalSize = maxVma - minVma
  debug(&"handleLoadPhdrs; minVma=0x{minVma:X}; maxVma=0x{maxVma:X}")

  lib.state.loadBias = cast[int64](mmap(
    nil, cast[int64](totalSize), PROT_NONE, MAP_PRIVATE or MAP_ANONYMOUS, -1, 0
  ))
  lib.state.maxVma = maxVma

  if lib.state.loadBias == cast[int64](MAP_FAILED):
    return err(
      &"Failed to mmap() {totalSize} bytes for load segments: {$strerror(errno)} ({$errno})"
    )

  debug(&"LOAD map chunk @ 0x{lib.state.loadBias:X}")

  for phdr in lib.elf.prog:
    case phdr.kind
    of ProgramHeaderKind.Load:
      if (let lphdr = handleLoadPhdr(lib, phdr, pageSize); !lphdr):
        return lphdr
    else:
      debug(&"ignore phdr {phdr.kind}")

  ok()

proc callArrays(lib: var Library): Result[void, string] =
  ## Routine to call .init_array's members
  let
    initArrayOpt = lib.state.dyn[DynType.InitArray]
    initArraySizeOpt = lib.state.dyn[DynType.InitArraySize]

  if !initArrayOpt:
    debug("object has no .init_array, ignoring.")
    return ok()

  if !initArraySizeOpt:
    debug("object has an .init_array but doesn't specify its size!")
    return err("Initialization constructor array size not specified")

  type InitArrayFn = proc() {.cdecl.}

  let
    initArrayAddr = (&initArrayOpt).vptr
    arrayCount = (&initArraySizeOpt).vptr div 8

  debug(&"CALL .init_array; count={arrayCount}")
  let initArray =
    cast[ptr UncheckedArray[int64]](lib.state.loadBias + cast[int64](initArrayAddr))

  for i in 0 ..< arrayCount:
    let data = initArray[i]
    if data == 0:
      continue

    var fn: int64
    if data < lib.state.loadBias:
      fn = lib.state.loadBias + cast[int64](data)
    else:
      fn = data

    # debug(&"CALL init_array[{i}] @ 0x{fn:X}")
    cast[InitArrayFn](fn)()

  ok()

proc loadLibraryImpl(lib: var Library): Result[void, string] =
  var libStat: Stat
  if fstat(lib.fd, libStat) != 0:
    return err(&"Cannot fstat() library: {strerror(errno)} ({errno})")

  let buffer = cast[ptr UncheckedArray[uint8]](mmap(
    nil, libStat.st_size, PROT_READ, MAP_PRIVATE, lib.fd, 0
  ))
  if cast[pointer](buffer) == MAP_FAILED:
    return err(&"Failed to map object: {strerror(errno)} ({errno})")

  lib.elf = parseELF(buffer)
  discard munmap(buffer, libStat.st_size)

  let pageSize = sysconf(SC_PAGESIZE)
  if (let load = handleLoadPhdrs(lib, pageSize = pageSize); !load):
    return load

  for shdr in lib.elf.sect:
    case shdr.kind
    of SectionHeaderKind.Dynamic:
      lib.state.dyn = newSeqOfCap[ELF64Dyn](shdr.size div shdr.entrySize)

      debug(
        &"PT_DYNAMIC shdr; vaddr=0x{shdr.virtualAddr:X}; numdyn={shdr.size div shdr.entrySize}"
      )

      let data = cast[ptr UncheckedArray[uint8]](cast[int64](shdr.virtualAddr) +
        lib.state.loadBias)
      var offset = 0'u64

      while offset < shdr.size:
        let dyn = cast[ptr ELF64Dyn](data[offset].addr)[]
        if dyn.tag == DynType.Null:
          break

        debug(&"DYNA tag={dyn.tag} ({cast[uint64](dyn.tag)}); v=0x{dyn.vptr:X}")
        lib.state.dyn &= dyn

        offset += shdr.entrySize # probs 16
    else:
      discard

  if (let reloc = processRelocations(lib); !reloc):
    return reloc

  if (let initArray = callArrays(lib); !initArray):
    return initArray

  ok()

proc prepareCache(lib: var Library) =
  ## Prepare some internal caching logic.
  zeroMem(lib.state.cache.addr, sizeof(LibraryCache))

  let
    gnuHash = lib.state.dyn[DynType.GNUHash]
    symTab = lib.state.dyn[DynType.SymbolTable]

  if *gnuHash:
    lib.state.cache.hasGnuHash = true
    lib.state.cache.gnuHash = (&gnuHash).vptr

  if *symTab:
    lib.state.cache.hasSymTab = true
    lib.state.cache.symTable = (&symTab).vptr

proc loadLibraryAbs*(
    path: string, callbacks: LoaderCallbacks
): Result[Library, string] =
  var lib: Library
  lib.state.callbacks = callbacks
  lib.path = path
  lib.fd = open(cstring(path), O_RDONLY)

  if lib.fd < 0:
    return err(&"Cannot load library '{path}': {strerror(errno)} ({errno})")

  let res = loadLibraryImpl(lib)
  if isErr(res):
    return err(res.error())

  prepareCache(lib)
  ok(ensureMove(lib))

iterator items*(lib: var Library): string =
  assert(lib.state.cache.hasSymTab)

  let
    gnuHash = lib.state.cache.gnuHash
    base = cast[ptr UncheckedArray[uint32]](lib.state.loadBias + cast[int64](gnuHash))

    nBuckets = base[0]
    symOffset = base[1]
    bloomSize = base[2]
    bloomShift = base[3]

  debug &"gnuHash={gnuHash}; nbuckets={nbuckets}; symoffset={symoffset}; bloomsize={bloomsize}; bloomshift={bloomshift}"
  let
    bloomFilter = cast[ptr UncheckedArray[uint64]](base[4].addr)
    buckets = cast[ptr UncheckedArray[uint32]](bloomFilter[bloomSize].addr)
    chains = cast[ptr UncheckedArray[uint32]](buckets[nbuckets].addr)

  var symIdx = 0'u64 # buckets[h mod nBuckets]

  let symTabBase = lib.state.loadBias + cast[int64](lib.state.cache.symTable)

  while true:
    let
      symIdxChain = symIdx - symOffset
      chainHash = chains[symIdxChain]
      sym = cast[ptr ELF64Sym](symTabBase + (cast[int64](symIdx) * sizeof(ELF64Sym)))[]

    yield $getSymbolName(lib, sym)

    if (chainHash and 1) != 0:
      break
    inc symIdx

proc symAddr*(lib: var Library, symbol: string): pointer =
  if not lib.state.cache.hasSymTab:
    # If the symbol table just... doesn't exist somehow, we can't resolve stuff.
    return nil

  if not lib.state.cache.hasGnuHash:
    return nil # TODO: Regular hash search implementation.

  let
    gnuHash = lib.state.cache.gnuHash
    base = cast[ptr UncheckedArray[uint32]](lib.state.loadBias + cast[int64](gnuHash))

    nBuckets = base[0]
    symOffset = base[1]
    bloomSize = base[2]
    bloomShift = base[3]

  debug &"gnuHash={gnuHash}; nbuckets={nbuckets}; symoffset={symoffset}; bloomsize={bloomsize}; bloomshift={bloomshift}"
  let
    bloomFilter = cast[ptr UncheckedArray[uint64]](base[4].addr)
    buckets = cast[ptr UncheckedArray[uint32]](bloomFilter[bloomSize].addr)
    chains = cast[ptr UncheckedArray[uint32]](buckets[nbuckets].addr)

    h = gnuHash(symbol)
    bitmaskWord = bloomFilter[(h div 64) and (bloomSize - 1)]

    hashBit1 = h mod 64
    hashBit2 = (h shr bloomShift) mod 64

  if ((bitmaskWord shr hashBit1) and 1) == 0 or ((bitmaskWord shr hashBit2) and 1) == 0:
    return nil

  var symIdx = buckets[h mod nBuckets]
  if symIdx < symOffset:
    return nil

  let symTabBase = lib.state.loadBias + cast[int64](lib.state.cache.symTable)

  while true:
    let
      symIdxChain = symIdx - symOffset
      chainHash = chains[symIdxChain]
      sym = cast[ptr ELF64Sym](symTabBase + (cast[int64](symIdx) * sizeof(ELF64Sym)))[]

    if (h or 1) == (chainHash or 1):
      let symName = getSymbolName(lib, sym)
      if symName == symbol:
        return cast[pointer](lib.state.loadBias + cast[int64](sym.value))

    if (chainHash and 1) != 0:
      break
    inc symIdx

  nil
