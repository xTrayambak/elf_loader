## Relocation routines
##
## Copyright (C) 2026 Trayambak Rai (xtrayambak@disroot.org)
import std/[strformat]
import pkg/elf_loader/[common, elf, types]
import pkg/[results, shakar]

proc tlsdescStub() {.cdecl.} =
  echo "stub()"
  assert off

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

      debug(&"RELA {getSymbolName(lib, sym)}")

      var fptr: uint64
      if sym.sectionIndex != 0:
        fptr = cast[uint64](lib.state.loadBias + cast[int64](sym.value))
      else:
        assert off, getSymbolName(lib, sym)
        fptr = cast[uint64](tlsdescStub)

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
      gotEntry[0] = cast[uint64](tlsdescStub)
      gotEntry[1] = sym.value
    else:
      debug(&"RELA unknown ({rType})")

    pos += relaElemSize

  ok()

proc processRelocations*(lib: var Library): Result[void, string] =
  if (let rela = processAddendReloc(lib); !rela):
    return rela

  ok()
