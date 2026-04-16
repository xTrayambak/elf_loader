import std/[strformat, posix]
import pkg/elf_loader, pkg/elf_loader/gnu_hash
import pkg/[pretty, results]
import common

let lib = loadLibraryAbs(
  getLibcPath(),
  LoaderCallbacks(
    resolveSymbol: proc(name: string): pointer =
      echo &"Resolve symbol '{name}'"
      # a very stupid shim to just use the pre-existing glibc versions of these symbols
      dlsym(nil, cstring(name))
  ),
)
if isErr(lib):
  echo lib.error()
else:
  echo "done"
  print get(lib)

let libc = get lib
let sym = cast[proc(path: cstring, flags: int32, mode: uint16): int32 {.cdecl.}](symAddr(
  libc, "open"
))
let sym2 = cast[proc(fd: int32, buf: cstring, cnt: uint64): int64 {.cdecl.}](symAddr(
  libc, "write"
))
assert sym != nil
let x = sym("/dev/stdout".cstring, O_RDWR, 0)
discard sym2(x, cstring("hello elf_loader! :P\n"), 21)
