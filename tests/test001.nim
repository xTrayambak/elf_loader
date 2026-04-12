import pkg/elf_loader
import pkg/[pretty, results]
import common, posix, strformat

let lib = loadLibraryAbs(getLibcPath())
if isErr(lib):
  echo "failed"
  echo lib.error()
else:
  echo "done"
  print get(lib)

let libc = get lib
let sym = cast[proc(path: cstring, flags: int32, mode: uint16): int32 {.cdecl.}](symAddr(
  libc, "open"
))
assert sym != nil
let x = sym("/dev/stdout".cstring, O_RDONLY, 0)
