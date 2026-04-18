## really stupid benchmark for `dlopen` vs `loadLibraryAbs` on glibc
## this is mostly for fun. glibc's loader is a whole another beast compared to
## this toy loader.
import std/posix
import pkg/[results, benchy], pkg/elf_loader
import ../common

let path = getLibcPath()
echo "glibc: " & path

let x = dlopen(path.cstring, posix.RTLD_LAZY)
let y = loadLibraryAbs(
    path,
    LoaderCallbacks(
      resolveSymbol: proc(name: string): pointer =
        # a very stupid shim to just use the pre-existing glibc versions of these symbols
        # technically speaking, elf_loader can't load glibc without glibc already being
        # loaded into it, yet. :P
        dlsym(nil, cstring(name))
    ),
  )
  .get()

const syms = [
  "open", "read", "write", "jumbogram", "blabla", "ioctl", "thisdoesntexist", "execve",
  "socket", "msgctl", "mq_open", "nice", "kill", "swapon", "swapoff", "poll", "epoll",
  "fakepoll", "pread", "horse", "pread64", "_exit", "exit", "totallyreal", "access",
]

timeIt "glibc dlfcn":
  for symbol in syms:
    let sym {.used.} = dlsym(x, cstring(symbol))

timeIt "elf_loader":
  for symbol in syms:
    let sym {.used.} = symAddr(y, symbol)
