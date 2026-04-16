## Core library loading routines
##
## Copyright (C) 2026 Trayambak Rai (xtrayambak@disroot.org)
import std/[strformat, options]
from std/posix import PROT_READ, PROT_WRITE, PROT_EXEC # TODO: Add these to nuzzle
import pkg/elf_loader/[common, elf, gnu_hash, relocator, types]
#!fmt: off
import pkg/[results, shakar],
       pkg/nuzzle/x64/bindings/prelude
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
    mappedSize = cast[int64](phdr.memSize) + offsetDiff
    fileOffset = offset - offsetDiff

  if mappedSize == 0: #or phdr.virtualAddr == 0:
    return ok()

  var prot: int32
  if phdr.flags.contains(PHFlag.Executable):
    prot = prot or posix.PROT_EXEC

  if phdr.flags.contains(PHFlag.Writable):
    prot = prot or posix.PROT_WRITE

  if phdr.flags.contains(PHFlag.Readable):
    prot = prot or posix.PROT_READ

  debug(&"handle LOAD program header. vma=0x{vma:X}; offset={offset}")
  debug(
    &"mmap(addr=0x{pageStart:X}, size={mappedSize}, prot={prot}, fd={lib.fd}, offset=0x{fileOffset:X})"
  )
  let section = posix.mmap(
    cast[pointer](pageStart),
    mappedSize,
    prot,
    posix.MAP_PRIVATE or posix.MAP_FIXED,
    lib.fd,
    fileOffset,
  )

  if section == posix.MAP_FAILED:
    return err(
      "Failed to allocate page for LOAD program header: " & $posix.strerror(errno) & " (" &
        $errno & ')'
    )

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

  lib.state.loadBias = cast[int64](posix.mmap(
    nil,
    cast[int64](totalSize),
    posix.PROT_NONE,
    posix.MAP_PRIVATE or posix.MAP_ANONYMOUS,
    -1,
    0,
  ))

  if lib.state.loadBias == cast[int64](posix.MAP_FAILED):
    return err(
      "Failed to mmap() {totalSize} bytes for load segments: {$strerror(errno)} ({$errno})"
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

proc handleTLSPhdr(lib: var Library): Result[void, string] =
  for phdr in lib.elf.prog:
    if phdr.kind != ProgramHeaderKind.TLS:
      continue

    let
      tlsBlockSize = 4096 #8 + phdr.memSize
      tls = posix.mmap(
        nil,
        tlsBlockSize,
        PROT_READ or PROT_WRITE,
        posix.MAP_PRIVATE or posix.MAP_ANONYMOUS,
        -1,
        0,
      )

    if tls == posix.MAP_FAILED:
      return err("mmap() failed for TLS block: " & $strerror(errno))

    let
      tp = cast[uint64](tls) + phdr.memSize
      initializedContent =
        cast[pointer](cast[uint64](lib.state.loadBias) + phdr.virtualAddr)

    copyMem(tls, initializedContent, phdr.fileSize)

    let bssStart = cast[pointer](cast[uint64](tls) + phdr.fileSize)
    zeroMem(bssStart, phdr.memSize - phdr.fileSize) # zero out the remaining stuff

    cast[ptr uint64](tp)[] = tp
    lib.state.tp = cast[pointer](tp)
    break

  ok()

proc callArrays(lib: var Library): Result[void, string] =
  ## Routine to call .init_array's members
  let
    initArrayOpt = lib.state.dyn[DynType.InitArray]
    initArraySizeOpt = lib.state.dyn[DynType.InitArraySize]

  if !initArrayOpt or !initArraySizeOpt:
    debug("object has no .init_array or doesn't specify its size, ignoring.")
    return

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

    debug(&"CALL init_array[{i}] @ 0x{fn:X}")

    var fs: uint64
    discard arch_prctl(ARCH_GET_FS, cast[pointer](fs.addr))
    debug(&"fs: 0x{fs:X} => 0x{cast[uint64](lib.state.tp):X}")

    cast[InitArrayFn](fn)()

  ok()

proc loadLibraryImpl(lib: var Library): Result[void, string] =
  var libStat: posix.Stat
  if posix.fstat(lib.fd, libStat) != 0:
    return err(
      "Cannot fstat() library: " & $posix.strerror(posix.errno) & " (" & $posix.errno &
        ')'
    )

  var buffer = newString(libStat.st_size)
  if posix.read(lib.fd, buffer[0].addr, libStat.st_size) != libStat.st_size:
    return err(
      "Cannot read library's contents into buffer: " & $posix.strerror(posix.errno) &
        " (" & $posix.errno & ')'
    )

  lib.elf = parseELF(buffer)

  let pageSize = posix.sysconf(posix.SC_PAGESIZE)

  if (let load = handleLoadPhdrs(lib, pageSize = pageSize); !load):
    return load

  if (let tls = handleTLSPhdr(lib); !tls):
    return tls

  for shdr in lib.elf.sect:
    case shdr.kind
    of SectionHeaderKind.Dynamic:
      lib.state.dyn = newSeqOfCap[ELF64Dyn](shdr.size div shdr.entrySize)

      debug(
        &"PT_DYNAMIC shdr; vaddr=0x{shdr.virtualAddr:X}; numdyn={lib.state.dyn.len}"
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

proc loadLibraryAbs*(path: string): Result[Library, string] =
  var lib: Library
  lib.path = path
  lib.fd = open(cstring(path), posix.O_RDONLY)

  let res = loadLibraryImpl(lib)
  if isErr(res):
    return err(res.error())

  ok(ensureMove(lib))

proc symAddr*(lib: Library, symbol: string): pointer =
  let gnuHashOpt = lib.state.dyn[DynType.GNUHash]
  if !gnuHashOpt:
    return nil # TODO: Regular hash search implementation

  let
    gnuHash = (&gnuHashOpt).vptr
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

  let symTabBase =
    lib.state.loadBias + cast[int64]((&lib.state.dyn[DynType.SymbolTable]).vptr)

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
