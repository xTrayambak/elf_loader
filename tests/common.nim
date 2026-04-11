import std/[osproc, os, strutils]

proc getLibcPath*(): string =
  # super dirty hack
  let (output, _) = execCmdEx("ldd " & getAppFilename())

  output[output.find("libc.so.6 => ") ..< output.len].splitLines()[0].split(
    "libc.so.6 => "
  )[1].split(' ')[0]
