import pkg/elf_loader
import pkg/[pretty, results]
import common

let lib = loadLibraryAbs(getLibcPath())
if isErr(lib):
  echo "failed"
  echo lib.error()
else:
  echo "done"
  print get(lib)

let libc = get lib
let sym = cast[proc(status: int32) {.cdecl.}](symAddr(libc, "_exit"))
sym(5)
