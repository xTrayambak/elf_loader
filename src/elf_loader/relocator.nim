## Relocation routines
##
## Copyright (C) 2026 Trayambak Rai (xtrayambak@disroot.org)
import std/[strformat]
import pkg/elf_loader/[common, elf, types]
import pkg/[results, shakar]

const
  RelocationGroupedByInfoFlag = 1
  RelocationGroupedByOffsetDeltaFlag = 2
  RelocationGroupedByAddendFlag = 4
  RelocationGroupHasAddendFlag = 8

proc applyRelocation(
    lib: var Library, kind: RelocationKind, addendElem: ELF64Rela, symTable: int64
): Result[void, string] =
  case kind
  of RelocationKind.X64Direct, RelocationKind.X64Global, RelocationKind.X64JumpSlot:
    let
      patchAddr = cast[ptr uint64](lib.state.loadBias + cast[int64](addendElem.offset))
      symIdx = cast[int64](addendElem.info shr 32)
      sym = cast[ptr ELF64Sym](lib.state.loadBias + symTable +
        (symIdx * int64 sizeof(ELF64Sym)))[]
      isStrong = (sym.info shr 4) != 2 # FIXME: define these as constants
      symbolName = getSymbolName(lib, sym)

    debugRel(&"RELA {symbolName}")

    var fptr: uint64
    if sym.sectionIndex != 0:
      fptr = cast[uint64](lib.state.loadBias + cast[int64](sym.value))
    else:
      let resolved = lib.state.callbacks.resolveSymbol($symbolName)
      if resolved == nil and not isStrong:
        return err(&"Failed to resolve symbol '{symbolName}', required by {lib.path}")

      fptr = cast[uint64](resolved)

    let finalVal = fptr + cast[uint64](addendElem.addend)
    debugRel &"REL write 0x{finalVal:X} @ 0x{cast[uint64](patchAddr):X}"
    patchAddr[] = finalVal
  of RelocationKind.X86Relative, RelocationKind.X64Relative:
    let
      patchAddr = cast[ptr uint64](lib.state.loadBias + cast[int64](addendElem.offset))
      finalVal = cast[uint64](lib.state.loadBias + cast[int64](addendElem.addend))

    debugRel(&"RELO RELATIVE; write 0x{finalVal:X} @ 0x{cast[uint64](patchAddr):X}")
    patchAddr[] = finalVal
  of RelocationKind.X64DynamicThreadPointerModule:
    let
      gotEntry = cast[ptr UncheckedArray[uint64]](lib.state.loadBias +
        cast[int64](addendElem.offset))

      symIdx = cast[int64](addendElem.info shr 32)
      sym = cast[ptr ELF64Sym](lib.state.loadBias + symTable +
        (symIdx * int64 sizeof(ELF64Sym)))[]
    gotEntry[0] = 1
    gotEntry[1] = sym.value
  of RelocationKind.X64TerminationPhaseOffset:
    let
      gotEntry = cast[ptr UncheckedArray[uint64]](lib.state.loadBias +
        cast[int64](addendElem.offset))

      symIdx = cast[int64](addendElem.info shr 32)
      sym = cast[ptr ELF64Sym](lib.state.loadBias + symTable +
        (symIdx * int64 sizeof(ELF64Sym)))[]
    gotEntry[0] = cast[uint64](0x1337)
    gotEntry[1] = sym.value
    assert(off, "bad relocation, bad bad relocation >:(")
  of RelocationKind.X6432:
    let
      patchAddr = cast[ptr uint32](lib.state.loadBias + cast[int64](addendElem.offset))
      symIdx = cast[int64](addendElem.info shr 32)
      sym = cast[ptr ELF64Sym](lib.state.loadBias + symTable +
        (symIdx * int64 sizeof(ELF64Sym)))[]
      isStrong = (sym.info shr 4) != 2 # FIXME: define these as constants
      symbolName = getSymbolName(lib, sym)

    debugRel(&"RELA {symbolName}")

    var fptr: uint64
    if sym.sectionIndex != 0:
      fptr = cast[uint64](lib.state.loadBias + cast[int64](sym.value))
    else:
      let resolved = lib.state.callbacks.resolveSymbol($symbolName)
      if resolved == nil and not isStrong:
        return err(&"Failed to resolve symbol '{symbolName}', required by {lib.path}")

      fptr = cast[uint64](resolved)

    let finalVal = fptr + cast[uint64](addendElem.addend)
    if finalVal > cast[uint64](uint32.high):
      return err(
        &"Failed to perform 32-bit direct relocation, result exceeds limit ({finalVal})"
      )

    debugRel &"REL32 write 0x{finalVal:X} @ 0x{cast[uint64](patchAddr):X}"
    patchAddr[] = cast[uint32](finalVal)
  of RelocationKind.X64Copy:
    let
      dest = cast[int64](lib.state.loadBias + cast[int64](addendElem.offset))
      symIdx = cast[int64](addendElem.info shr 32)
      sym = cast[ptr ELF64Sym](lib.state.loadBias + symTable +
        (symIdx * int64 sizeof(ELF64Sym)))[]

      symbolName = getSymbolName(lib, sym)

    debugRel(&"REL x64 copy '{symbolName}'")
  else:
    debugRel(&"RELA unknown ({cast[uint32](kind)})")
    when not defined(elfLoaderIgnoreUnknownRelocations):
      return
        err(&"Relocation failed. Cannot handle relocation type {cast[uint32](kind)}!")

  ok()

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
    debugRel(
      &"RELA pos={pos}; offset={addendElem.offset}; info={addendElem.info}; addend={addendElem.addend}"
    )

    let rType = RelocationKind(cast[uint32](addendElem.info and 0xFFFFFFFF'u64))
    if (let relo = applyRelocation(lib, rType, addendElem, symTable); !relo):
      return relo

    pos += relaElemSize

  ok()

func readULEB128*(
    buffer: ptr UncheckedArray[uint8], pos: int64
): tuple[data: uint64, size: int64] =
  # stolen from uaemu, fly high
  const ContByte = 0x80

  var final: uint64
  let originalPos = pos
  var pos = pos
  var shift: int64

  while true:
    let byt = cast[uint8](buffer[pos])
    inc pos

    final = final or (cast[uint64](byt and 0x7F) shl shift)

    if (byt and ContByte) == 0:
      break

    shift += 7

  (data: ensureMove(final), size: pos - originalPos)

func readSLEB128*(
    buffer: ptr UncheckedArray[uint8], pos: int64
): tuple[data: uint64, size: int64] =
  const
    ContByte = 0x80
    SignBit = 0x40

  var final: uint64
  let originalPos = pos
  var pos = pos
  var shift: int
  var byt: uint8

  while true:
    byt = buffer[pos]
    inc pos

    final = final or (cast[uint64](byt and 0x7F) shl shift)
    shift += 7

    if (byt and ContByte) == 0:
      break

  if shift < 64 and (byt and SignBit) != 0:
    final = final or cast[uint64](-cast[int64](1'i64 shl shift))

  (data: final, size: pos - originalPos)

proc processRelativeReloc(lib: var Library): Result[void, string] =
  let
    reloRel = (&lib.state.dyn[DynType.RelocRelative]).vptr
    reloRelSize = (&lib.state.dyn[DynType.RelocRelativeSize]).vptr
    reloRelElemSize = (&lib.state.dyn[DynType.RelocRelativeElementSize]).vptr
    reloRelCount = reloRelSize div reloRelElemSize

  debugRel(
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
      debugRel(&"RELR addr entry; set caddr -> 0x{caddr:X}")
      caddr += 8
    else:
      var bitmap = relr shr 1
      var offset = caddr
      while bitmap != 0:
        if (bitmap and 1) != 0:
          # if the current LSB is a set bit,
          # we need to apply the reloc here, just add the load bias
          # debugRel(&"*0x{offset:X} += 0x{lib.state.loadBias:X}")
          cast[ptr int64](offset)[] += lib.state.loadBias

        bitmap = bitmap shr 1
        offset += 8

      caddr += 504 # move 63*8 bytes ahead

    pos += reloRelElemSize
    inc numRelo

  ok()

proc processAndroidRela(lib: var Library): Result[void, string] =
  # Largely based on https://github.com/minecraft-linux/android_bionic/blob/main/linker/linker_reloc_iterators.h#L48

  let
    relaAddr =
      cast[int64]((&lib.state.dyn[DynType.AndroidRela]).vptr) + lib.state.loadBias
    relaBuffer = cast[ptr UncheckedArray[uint8]](relaAddr)

  if relaBuffer[0] != cast[uint8]('A') or relaBuffer[1] != cast[uint8]('P') or
      relaBuffer[2] != cast[uint8]('S') or relaBuffer[3] != cast[uint8]('2'):
    return err(
      &"Cannot perform APS2 relocations (at 0x{relaAddr:X}): buffer doesn't start with expected signature"
    )

  let symTable = cast[int64]((&lib.state.dyn[DynType.SymbolTable]).vptr)

  var
    pos = 4'i64
    relOffset = 0'u64
    relAddend = 0'i64
    relInfo = 0'u64

  let numRelocs = readSLEB128(relaBuffer, pos)
  pos += numRelocs.size

  let offset = readSLEB128(relaBuffer, pos)
  pos += offset.size

  var idx = 0'u64

  while idx < numRelocs.data:
    let groupSizeVal = readSLEB128(relaBuffer, pos)
    pos += groupSizeVal.size

    let groupFlagsVal = readSLEB128(relaBuffer, pos)
    pos += groupFlagsVal.size

    let
      groupSize = groupSizeVal.data
      groupFlags = groupFlagsVal.data

    var groupROffsetDelta = 0'u64

    if (groupFlags and RelocationGroupedByOffsetDeltaFlag) != 0:
      let val = readSLEB128(relaBuffer, pos)
      groupROffsetDelta = val.data
      pos += val.size

    if (groupFlags and RelocationGroupedByInfoFlag) != 0:
      let val = readSLEB128(relaBuffer, pos)
      relInfo = val.data
      pos += val.size

    let groupFlagsReloc =
      groupFlags and (RelocationGroupHasAddendFlag or RelocationGroupedByAddendFlag)

    if groupFlagsReloc == RelocationGroupHasAddendFlag:
      # Each relocation has an addend. This is the default situation with lld's current encoder.
      discard
    elif groupFlagsReloc ==
        (RelocationGroupHasAddendFlag or RelocationGroupedByAddendFlag):
      let val = readSLEB128(relaBuffer, pos)
      relAddend += cast[int64](val.data)
      pos += val.size
    else:
      relAddend = 0

    for i in 0 ..< groupSize:
      if (groupFlags and RelocationGroupedByOffsetDeltaFlag) != 0:
        relOffset += groupROffsetDelta
      else:
        let val = readSLEB128(relaBuffer, pos)
        relOffset += val.data
        pos += val.size

      if (groupFlags and RelocationGroupedByInfoFlag) == 0:
        let val = readSLEB128(relaBuffer, pos)
        relInfo = val.data
        pos += val.size

      if groupFlagsReloc == RelocationGroupHasAddendFlag:
        let val = readSLEB128(relaBuffer, pos)
        relAddend += cast[int64](val.data)
        pos += val.size

      debugRel &"APS2 REL {i}/{groupSize} | pos: {pos}; info: {relInfo}; offset: {relOffset}; addend: {relAddend}"
      if (
        let rel = applyRelocation(
          lib,
          cast[RelocationKind](relInfo),
          ELF64Rela(
            offset: cast[uint64](relOffset),
            info: cast[uint64](relInfo),
            addend: relAddend,
          ),
          symTable,
        )
        !rel
      ):
        return rel

    idx += groupSize

  ok()

proc processPLT(lib: var Library): Result[void, string] =
  let
    jmpRelAddr =
      lib.state.loadBias + cast[int64]((&lib.state.dyn[DynType.JumpRel]).vptr)
    jmpRelSize = cast[int64]((&lib.state.dyn[DynType.PLTRelSize]).vptr)
    numPltRelocs = jmpRelSize div sizeof(ELF64Rela)

    pltRelocs = cast[ptr UncheckedArray[ELF64Rela]](jmpRelAddr)
    symTable = cast[int64]((&lib.state.dyn[DynType.SymbolTable]).vptr)

  debugRel &"handle PLT relocations; addr=0x{jmpRelAddr:X}; size={jmpRelSize}; numRelocs={numPltRelocs}"

  for i in 0 ..< numPltRelocs:
    let
      reloc = pltRelocs[i]
      kind = cast[RelocationKind](reloc.info and 0xFFFFFFFF'u64)

    debugRel &"PLT rel {i} [{kind}]"
    if (let relo = applyRelocation(lib, kind, reloc, symTable); !relo):
      return relo

  ok()

proc processRelocations*(lib: var Library): Result[void, string] =
  if *lib.state.dyn[DynType.RelocAddend]:
    if (let rela = processAddendReloc(lib); !rela):
      return rela

  if *lib.state.dyn[DynType.RelocRelative]:
    if (let relr = processRelativeReloc(lib); !relr):
      return relr

  if *lib.state.dyn[DynType.AndroidRela]:
    if (let arelr = processAndroidRela(lib); !arelr):
      return arelr

  if *lib.state.dyn[DynType.JumpRel]:
    if (let pltrel = processPLT(lib); !pltrel):
      return pltrel

  ok()
