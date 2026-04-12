## GNU's hash implementation for the bloom filter
##
## Copyright (C) 2026 Trayambak Rai (xtrayambak@disroot.org)

func gnuHash*(name: string): uint32 {.inline.} =
  var hash = 5381'u32
  for c in name:
    hash = (hash shl 5) + hash + cast[uint32](ord(c))

  ensureMove(hash)
