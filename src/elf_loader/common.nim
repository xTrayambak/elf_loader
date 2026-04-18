## Common routines
##
## Copyright (C) 2026 Trayambak Rai (xtrayambak@disroot.org)
import std/options
import pkg/shakar
import pkg/elf_loader/[elf, types]

template debug*(msg: string) =
  when defined(elfLoaderVerbose): #or not defined(release):
    stdout.write("[loader | debug]: " & msg & '\n')

func `[]`*(dyns: seq[ELF64Dyn], dt: DynType): Option[ELF64Dyn] {.inline.} =
  for dyn in dyns:
    if dyn.tag == dt:
      return some(dyn)

  none(ELF64Dyn)

func getSymbolName*(lib: Library, sym: ELF64Sym): string =
  let strTab = cast[ptr UncheckedArray[char]](lib.state.loadBias +
    cast[int64]((&lib.state.dyn[DynType.StringTable]).vptr))

  $cast[cstring](strTab[sym.name].addr)
