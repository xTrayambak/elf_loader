## Relocation routines
##
## Copyright (C) 2026 Trayambak Rai (xtrayambak@disroot.org)
import std/[strformat]
import pkg/elf_loader/[common, elf, types]
import pkg/[results, shakar]

proc processAddendReloc(lib: var Library): Result[void, string] =
  let
    relaDyn = &lib.state.dyn[DynType.RelocAddend]
    relaDynSize = &lib.state.dyn[DynType.RelocAddendSize]
    relaElemSize = (&lib.state.dyn[DynType.RelocAddendElementSize]).vptr
    rela =
      cast[ptr UncheckedArray[uint8]](lib.state.loadBias + cast[int64](relaDyn.vptr))

  let symTable = cast[int64]((&lib.state.dyn[DynType.SymbolTable]).vptr)

  var pos = 0'u64
  while pos < cast[uint64](relaDynSize.vptr):
    let addendElem = cast[ptr ELF64Rela](cast[int64](rela) + cast[int64](pos))[]
    debug(
      &"RELA pos={pos}; offset={addendElem.offset}; info={addendElem.info}; addend={addendElem.addend}"
    )

    let rType = addendElem.info and 0xFFFFFFFF'u64
    case rType
    of 1, 6, 7:
      let
        patchAddr =
          cast[ptr uint64](lib.state.loadBias + cast[int64](addendElem.offset))
        symIdx = cast[int64](addendElem.info shr 32)
        sym = cast[ptr ELF64Sym](lib.state.loadBias + symTable +
          (symIdx * int64 sizeof(ELF64Sym)))[]
        isStrong = (sym.info shr 4) != 2 # FIXME: define these as constants
        symbolName = getSymbolName(lib, sym)

      debug(&"RELA {symbolName}")

      var fptr: uint64
      if sym.sectionIndex != 0:
        fptr = cast[uint64](lib.state.loadBias + cast[int64](sym.value))
      else:
        let resolved = lib.state.callbacks.resolveSymbol($symbolName)
        if resolved == nil and not isStrong:
          return err(&"Failed to resolve symbol '{symbolName}', required by {lib.path}")

        fptr = cast[uint64](resolved)

      let finalVal = fptr + cast[uint64](addendElem.addend)
      debug &"REL write 0x{finalVal:X} @ 0x{cast[uint64](patchAddr):X}"
      patchAddr[] = finalVal
    of 8:
      let
        patchAddr =
          cast[ptr uint64](lib.state.loadBias + cast[int64](addendElem.offset))
        finalVal = cast[uint64](lib.state.loadBias + cast[int64](addendElem.addend))

      debug(
        &"RELA R_X86_64_RELATIVE; write 0x{finalVal:X} @ 0x{cast[uint64](patchAddr):X}"
      )
      patchAddr[] = finalVal
    of 18:
      let
        gotEntry = cast[ptr UncheckedArray[uint64]](lib.state.loadBias +
          cast[int64](addendElem.offset))

        symIdx = cast[int64](addendElem.info shr 32)
        sym = cast[ptr ELF64Sym](lib.state.loadBias + symTable +
          (symIdx * int64 sizeof(ELF64Sym)))[]
      gotEntry[0] = 1
      gotEntry[1] = sym.value
    of 37:
      let
        gotEntry = cast[ptr UncheckedArray[uint64]](lib.state.loadBias +
          cast[int64](addendElem.offset))

        symIdx = cast[int64](addendElem.info shr 32)
        sym = cast[ptr ELF64Sym](lib.state.loadBias + symTable +
          (symIdx * int64 sizeof(ELF64Sym)))[]
      gotEntry[0] = cast[uint64](0x1337)
      gotEntry[1] = sym.value
    else:
      debug(&"RELA unknown ({rType})")
      return err(&"Relocation failed. Cannot handle addend variant {rType}!")

    pos += relaElemSize

  ok()

proc processRelativeReloc(lib: var Library): Result[void, string] =
  let
    reloRel = (&lib.state.dyn[DynType.RelocRelative]).vptr
    reloRelSize = (&lib.state.dyn[DynType.RelocRelativeSize]).vptr
    reloRelElemSize = (&lib.state.dyn[DynType.RelocRelativeElementSize]).vptr
    reloRelCount = reloRelSize div reloRelElemSize

  debug(
    &"RELR vma=0x{reloRel:X}; size={reloRelSize}; elemSize={reloRelElemSize}; count={reloRelCount}"
  )

  var
    pos: uint64
    numRelo: uint64
    caddr: int64 # current mem address we're working on

  while numRelo < reloRelCount:
    let relr = cast[ptr ELF64Relr](cast[int64](lib.state.loadBias) +
      cast[int64](reloRel + pos))[]

    if (relr and 1) == 0:
      # new address entry.
      # we need to set caddr to load bias + the relr's value, then add the load bias to the value at which caddr's u64 now points to, then increment caddr's u64 by 8 to go ahead
      caddr = lib.state.loadBias + cast[int64](relr)
      cast[ptr int64](caddr)[] += lib.state.loadBias
      debug(&"RELR addr entry; set caddr -> 0x{caddr:X}")
      caddr += 8
    else:
      var bitmap = relr shr 1
      var offset = caddr
      while bitmap != 0:
        if (bitmap and 1) != 0:
          # if the current LSB is a set bit,
          # we need to apply the reloc here, just add the load bias
          # debug(&"*0x{offset:X} += 0x{lib.state.loadBias:X}")
          cast[ptr int64](offset)[] += lib.state.loadBias

        bitmap = bitmap shr 1
        offset += 8

      caddr += 504 # move 63*8 bytes ahead

    pos += reloRelElemSize
    inc numRelo

  ok()

proc processRelocations*(lib: var Library): Result[void, string] =
  if *lib.state.dyn[DynType.RelocAddend]:
    if (let rela = processAddendReloc(lib); !rela):
      return rela

  if *lib.state.dyn[DynType.RelocRelative]:
    if (let relr = processRelativeReloc(lib); !relr):
      return relr

  ok()
