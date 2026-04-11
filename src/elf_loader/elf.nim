## ELF parser
##
## Copyright (C) 2025-2026 Trayambak Rai (xtrayambak@disroot.org)
import std/[strutils]
import pkg/flatty/binny

const cpu64 = defined(amd64) or defined(arm64)

type
  ELF64Dyn* {.packed.} = object
    tag*: DynType
    vptr*: uint64

  ELF64Rela* {.packed.} = object
    offset*: uint64
    info*: uint64
    addend*: int64

  DynType* {.pure, size: sizeof(uint64).} = enum
    Null = 0
    Needed = 1
    PLTRelSize = 2
    PLTGOT = 3
    Hash = 4
    StringTable = 5
    SymbolTable = 6
    RelocAddend = 7
    RelocAddendSize = 8
    RelocAddendElementSize = 9
    StringTableSize = 10
    SymbolTableSize = 11
    Init = 12
    Fini = 13
    SOName = 14
    RPath = 15
    Symbolic = 16
    Reloc = 17
    RelocSize = 18
    RelocElementSize = 19
    PLTRelType = 20
    Debug = 21
    TextRel = 22
    JumpRel = 23
    BindNow = 24
    InitArray = 25
    FiniArray = 26
    InitArraySize = 27
    FiniArraySize = 28
    RunPath = 29
    Flags = 30
    RelocRelativeSize = 35
    RelocRelative = 36
    RelocRelativeElementSize = 37

    # gnu-isms
    GNUHash = 0x6ffffef5
    TLSDescriptorsPLT = 0x6ffffef6
    TLSDescriptorsGOT = 0x6ffffef7
    SymbolVersionTable = 0x6ffffff0
    RelocAddendCount = 1879048193
    VersionNeeded = 0x6ffffffe
    VersionNeededCount = 0x6fffffff
    VersionDefinition = 0x6fffffe0
    VersionDefinitionCount = 0x6fffffe1
    Checksum = 0x6fffffd4
    SymbolVersion = 1879048192
    VersionDef = 1879048188
    VersionDefCount = 1879048189
    Flags1 = 1879048195
    VersionNeed = 1879048187

  ELF64Sym* {.packed.} = object
    name*: uint32
    info*: uint8
    other*: uint8
    sectionIndex*: uint16
    value*: uint64
    size*: uint64

  ELFParsingError* = object of ValueError
    ## The base error from which all errors related
    ## to ELF parsing derive.

  InvalidELFMagic* = object of ELFParsingError
    ## This error is raised when an ELF file's magic section
    ## of 4 bytes is malformed.

  InvalidELFClass* = object of ELFParsingError
  InvalidELFEndianness* = object of ELFParsingError
  InvalidELFABI* = object of ELFParsingError
  InvalidELFObjectType* = object of ELFParsingError
  InvalidELFArchitecture* = object of ELFParsingError

  ProgramHeaderParseError* = object of ELFParsingError
  InvalidProgramHeaderType* = object of ProgramHeaderParseError

  SectionHeaderParseError* = object of ELFParsingError
  InvalidSectionHeaderType* = object of SectionHeaderParseError

  ABI* {.pure.} = enum
    ## All the ABIs that the ELF standard recognizes.
    ## 0x00 - SystemV
    SystemV

    ## 0x01 - HP-UX
    HPUX

    ## 0x02 - NetBSD
    NetBSD

    ## 0x03 - Linux
    Linux

    ## 0x04 - GNU Hurd
    GNUHurd

    ## 0x06 - Solaris
    Solaris

    ## 0x07 - AIX (Monterey)
    AIX

    ## 0x08 - IRIX
    IRIX

    ## 0x09 - FreeBSD
    FreeBSD

    ## 0x0A - Tru64
    Tru64

    ## 0x0B - Novell Modesto
    NovellModesto

    ## 0x0C - OpenBSD
    OpenBSD

    ## 0x0D - OpenVMS
    OpenVMS

    ## 0x0E - NonStop Kernel
    NonStopKernel

    ## 0x0F - AROS
    AROS

    ## 0x10 - FenixOS
    FenixOS

    ## 0x11 - Nuxi CloudABI
    NuxiCloudABI

    ## 0x12 - Stratus Technologies OpenVOS
    OpenVOS

  ObjectType* {.pure.} = enum
    None
    Relocatable
    Executable
    SharedObject
    Core
    LowOS
    HighOS
    LowCPU
    HighCPU

  Architecture* {.pure.} = enum
    ## A list of all architectures the ELF standard recognizes.
    None
    Bellmac32
    SPARC
    x86
    M68k
    M88k
    IntelMCU
    Intel80860
    MIPS
    System370
    RS3000
    Reserved
    PARISC
    Intel80960
    PPC32
    PPC64
    S390
    IBMSPU
    NECV800
    FR20
    TRWRH32
    RCE
    ARM
    DigitalAlpha
    SuperH
    SPARCV9
    TriCore
    Argonaut
    H8300
    H8300H
    H8S
    H8500
    IA64
    MIPSX
    ColdFire
    M68HC12
    FujitsuMMA
    SiemensPCP
    SonyNCPU
    DensoNDR1
    StarCore
    ToyotaME16
    ST100
    TinyJ
    AMD64
    SonyDSP
    PDP10
    PDP11
    FX66
    ST9
    ST7
    MC68HC16
    MC68HC11
    MC68HC08
    MC68HC05
    SVx
    ST19
    VAX
    Axis32
    Infineon32
    Element14
    LSI16
    TMS320C6000
    Elbrus
    ARM64
    Z80
    RISCV
    BPF
    WDC65C816
    LoongArch

  ProgramHeaderKind* {.pure, size: sizeof(uint32).} = enum
    Null
    Load
    Dynamic
    Interp
    Note
    Shlib
    Phdr
    TLS
    OSReserved
    CPUReserved

  SectionHeaderKind* {.pure, size: sizeof(uint32).} = enum
    Null
    ProgramData
    SymbolTable
    StringTable
    RelocAddend
    SymbolHash
    Dynamic
    Note
    NoBits
    Reloc
    Reserved
    DynSymTable
    InitArray
    FiniArray
    PreinitArray
    Group
    ExSectionIndices
    NumDefinedTypes
    OSReserved

  PHFlag* {.pure, size: sizeof(uint8).} = enum
    Executable = 0x1
    Writable = 0x2
    Readable = 0x4

  SHFlag* {.pure, size: sizeof(uint8).} = enum
    Writable
    Allocates
    Executable
    Mergeable
    Strings
    InfoLink
    LinkOrder
    Nonconforming
    Group
    TLS
    OSReserved
    CPUReserved
    Ordered
    Excluded

  ProgramHeader* = object
    kind*: ProgramHeaderKind
    flags*: set[PHFlag]

    when cpu64:
      offset*: uint64
      virtualAddr*: uint64
      physicalAddr*: uint64
      fileSize*: uint64
      memSize*: uint64
      alignment*: uint64
    else:
      offset*: uint32
      virtualAddr*: uint32
      physicalAddr*: uint32
      fileSize*: uint32
      memSize*: uint32
      alignment*: uint32

  SectionHeader* = object
    name*: uint32
    kind*: SectionHeaderKind
    flags*: set[SHFlag]

    when cpu64:
      virtualAddr*: uint64
      offset*: uint64
      size*: uint64
      alignment*: uint64
      entrySize*: uint64
    else:
      virtualAddr*: uint32
      offset*: uint32
      size*: uint32
      alignment*: uint32
      entrySize*: uint32

    link*: uint32
    info*: uint32

  Header* = object ## The full ELF header, as expected by the ELF spec.
    bits: uint8
    elfVersion*: uint8

    endianness*: Endianness

    abi*: ABI
    abiVersion*: uint8

    objectType*: ObjectType
    arch*: Architecture
    version*: uint32

    when cpu64:
      entryPoint*: uint64
      programHeaderOffset*: uint64
      sectionHeaderOffset*: uint64
    else:
      entryPoint*: uint32
      programHeaderOffset*: uint32
      sectionHeaderOffset*: uint32

    flags*: uint32
    size*: uint16

    programHeaderTableSize*: uint16
    programHeaderNum*: uint16

    sectionHeaderTableSize*: uint16
    sectionHeaderNum*: uint16
    sectionHeaderTableNameOffset*: uint16

    programHeaders*: seq[ProgramHeader]
    sectionHeaders*: seq[SectionHeader]

  ELFStream* = string | openArray[byte] | openArray[uint8] | seq[uint8] | seq[byte]

  ELF* = object
    header*: Header
    prog*: seq[ProgramHeader]
    sect*: seq[SectionHeader]

template throw(error: untyped, message: string) =
  raise newException(error, message)

func asHex(b: SomeUnsignedInt): string =
  "0x" & toHex(b)

func toSHFlags(value: uint32 | uint64): set[SHFlag] {.raises: [].} =
  var flags: set[SHFlag]

  if (value and 0x1) != 0:
    flags.incl(SHFlag.Writable)
  if (value and 0x2) != 0:
    flags.incl(SHFlag.Allocates)
  if (value and 0x4) != 0:
    flags.incl(SHFlag.Executable)
  if (value and 0x10) != 0:
    flags.incl(SHFlag.Mergeable)
  if (value and 0x20) != 0:
    flags.incl(SHFlag.Strings)
  if (value and 0x40) != 0:
    flags.incl(SHFlag.InfoLink)
  if (value and 0x80) != 0:
    flags.incl(SHFlag.LinkOrder)
  if (value and 0x100) != 0:
    flags.incl(SHFlag.Nonconforming)
  if (value and 0x200) != 0:
    flags.incl(SHFlag.Group)
  if (value and 0x400) != 0:
    flags.incl(SHFlag.TLS)
  if (value and 0x0FF00000) != 0:
    flags.incl(SHFlag.OSReserved)
  if (value and 0xF0000000'u64) != 0:
    flags.incl(SHFlag.CPUReserved)
  if (value and 0x4000000'u64) != 0:
    flags.incl(SHFlag.Ordered)
  if (value and 0x8000000'u64) != 0:
    flags.incl(SHFlag.Excluded)

  move(flags)

func validateElfHeader*(content: ELFStream) {.raises: [InvalidELFMagic].} =
  ## This function accepts a sequence of bytes and validates the first four
  ## against the standard ELF magic bytes to ensure that they are part of an ELF file.
  ##
  ## If any of these validations fail, it raises an `InvalidELFMagic` exception.

  if content.len < 4:
    # If the buffer is smaller than 4 bytes, it's invalid by default because
    # we don't have the full magic sequence.
    throw(
      InvalidELFMagic,
      "Only " & $content.len &
        " ELF magic byte(s) were provided. This function expects 4 bytes at the very least.",
    )

  if content.readUint8(0x00) != 0x7F:
    throw(InvalidELFMagic, "ELF does not start with expected magic byte of 0x7F.")

  if content.readUint8(0x01) != 0x45: # E
    throw(InvalidELFMagic, "ELF's second magic byte is invalid. Expected 0x45.")

  if content.readUint8(0x02) != 0x4c: # L
    throw(InvalidELFMagic, "ELF's third magic byte is invalid. Expected 0x4c.")

  if content.readUint8(0x03) != 0x46: # F
    throw(InvalidELFMagic, "ELF's fourth magic byte is invalid. Expected 0x46.")

func parseElfHeader*(content: string): Header =
  ## Given a valid ELF file, parse its header and return back a `Header` structure
  ## which contains all of the data contained within the ELF's header section.
  ##
  ## This function also performs validation upon the given contents to ensure that
  ## it is part of a valid ELF file.
  ##
  ## **See also**:
  ## * `proc validateElfHeader(content: ELFStream)`_
  validateElfHeader(content)

  var header: Header

  let mode = content.readUint8(0x04)
  case mode
  of 1:
    # 32-bit ELF
    header.bits = 32
  of 2:
    # 64-bit ELF
    header.bits = 64
  else:
    throw(
      InvalidELFClass,
      "ELF's class byte must be either 1 (32-bit) or 2 (64-bit), got " & $mode &
        " instead.",
    )

  # Endianness
  case content.readUint8(0x05)
  of 1:
    header.endianness = littleEndian
  of 2:
    header.endianness = bigEndian
  else:
    throw(
      InvalidELFEndianness,
      "ELF's endianness must be 1 (little endian) or 2 (big endian)",
    )

  # ELF version (generally 1)
  header.elfVersion = content.readUint8(0x06)

  # ABI
  header.abi =
    case content.readUint8(0x07)
    of 0x00:
      ABI.SystemV
    of 0x01:
      ABI.HPUX
    of 0x02:
      ABI.NetBSD
    of 0x03:
      ABI.Linux
    of 0x04:
      ABI.GNUHurd
    of 0x06:
      ABI.Solaris
    of 0x07:
      ABI.AIX
    of 0x08:
      ABI.IRIX
    of 0x09:
      ABI.FreeBSD
    of 0x0A:
      ABI.Tru64
    of 0x0B:
      ABI.NovellModesto
    of 0x0C:
      ABI.OpenBSD
    of 0x0D:
      ABI.OpenVMS
    of 0x0E:
      ABI.NonStopKernel
    of 0x0F:
      ABI.AROS
    of 0x10:
      ABI.FenixOS
    of 0x11:
      ABI.NuxiCloudABI
    of 0x12:
      ABI.OpenVOS
    else:
      throw(InvalidELFABI, "Got unexpected ELF ABI byte: " & content.readUint8(6).asHex)

  # ABI Version
  header.abiVersion = content.readUint8(0x08)

  # The next 7 bytes are reserved. They must be ignored.

  # Object type
  header.objectType =
    case content.readUint16(0x10)
    of 0x00:
      ObjectType.None
    of 0x01:
      ObjectType.Relocatable
    of 0x02:
      ObjectType.Executable
    of 0x03:
      ObjectType.SharedObject
    of 0x04:
      ObjectType.Core
    of 0xFE00:
      ObjectType.LowOS
    of 0xFEFF:
      ObjectType.HighOS
    of 0xFF00:
      ObjectType.LowCPU
    of 0xFFFF:
      ObjectType.HighCPU
    else:
      throw(InvalidELFObjectType, "Got invalid ELF object type.")

  header.arch =
    case content.readUint16(0x12)
    of 0x00:
      Architecture.None
    of 0x01:
      Architecture.Bellmac32
    of 0x02:
      Architecture.SPARC
    of 0x03:
      Architecture.x86
    of 0x04:
      Architecture.M68k
    of 0x05:
      Architecture.M88k
    of 0x06:
      Architecture.IntelMCU
    of 0x07:
      Architecture.Intel80860
    of 0x08:
      Architecture.MIPS
    of 0x09:
      Architecture.System370
    of 0x0A:
      Architecture.RS3000
    of {0x0B'u16 .. 0x0E'u16}:
      Architecture.Reserved
    of 0x0F:
      Architecture.PARISC
    of 0x13:
      Architecture.Intel80960
    of 0x14:
      Architecture.PPC32
    of 0x15:
      Architecture.PPC64
    of 0x16:
      Architecture.S390
    of 0x17:
      Architecture.IBMSPU
    of {0x18'u16 .. 0x23'u16}:
      Architecture.Reserved
    of 0x24:
      Architecture.NECV800
    of 0x25:
      Architecture.FR20
    of 0x26:
      Architecture.TRWRH32
    of 0x27:
      Architecture.RCE
    of 0x28:
      Architecture.ARM
    of 0x29:
      Architecture.DigitalAlpha
    of 0x2A:
      Architecture.SuperH
    of 0x2B:
      Architecture.SPARCV9
    of 0x2C:
      Architecture.TriCore
    of 0x2D:
      Architecture.Argonaut
    of 0x2E:
      Architecture.H8300
    of 0x2F:
      Architecture.H8300H
    of 0x30:
      Architecture.H8S
    of 0x31:
      Architecture.H8500
    of 0x32:
      Architecture.IA64
    of 0x33:
      Architecture.MIPSX
    of 0x34:
      Architecture.ColdFire
    of 0x35:
      Architecture.M68HC12
    of 0x36:
      Architecture.FujitsuMMA
    of 0x37:
      Architecture.SiemensPCP
    of 0x38:
      Architecture.SonyNCPU
    of 0x39:
      Architecture.DensoNDR1
    of 0x3A:
      Architecture.StarCore
    of 0x3B:
      Architecture.ToyotaME16
    of 0x3C:
      Architecture.ST100
    of 0x3D:
      Architecture.TinyJ
    of 0x3E:
      Architecture.AMD64
    of 0x3F:
      Architecture.SonyDSP
    of 0x40:
      Architecture.PDP10
    of 0x41:
      Architecture.PDP11
    of 0x42:
      Architecture.FX66
    of 0x43:
      Architecture.ST9
    of 0x44:
      Architecture.ST7
    of 0x45:
      Architecture.MC68HC16
    of 0x46:
      Architecture.MC68HC11
    of 0x47:
      Architecture.MC68HC08
    of 0x48:
      Architecture.MC68HC05
    of 0x49:
      Architecture.SVx
    of 0x4A:
      Architecture.ST19
    of 0x4B:
      Architecture.VAX
    of 0x4C:
      Architecture.Axis32
    of 0x4D:
      Architecture.Infineon32
    of 0x4E:
      Architecture.Element14
    of 0x4F:
      Architecture.LSI16
    of 0x8C:
      Architecture.TMS320C6000
    of 0xAF:
      Architecture.Elbrus
    of 0xB7:
      Architecture.ARM64
    of 0xDC:
      Architecture.Z80
    of 0xF3:
      Architecture.RISCV
    of 0xF7:
      Architecture.BPF
    of 0x101:
      Architecture.WDC65C816
    of 0x102:
      Architecture.LoongArch
    else:
      throw(InvalidELFArchitecture, "Got malformed architecture payload")

  header.version = content.readUint32(0x14)

  when cpu64:
    header.entryPoint = content.readUint64(0x18)
    header.programHeaderOffset = content.readUint64(0x20)
    header.sectionHeaderOffset = content.readUint64(0x28)
    header.flags = content.readUint32(0x30)
    header.size = content.readUint16(0x34)
    header.programHeaderTableSize = content.readUint16(0x36)
    header.programHeaderNum = content.readUint16(0x38)
    header.sectionHeaderTableSize = content.readUint16(0x3A)
    header.sectionHeaderNum = content.readUint16(0x3C)
    header.sectionHeaderTableNameOffset = content.readUint16(0x3E)
  else:
    header.entryPoint = content.readUint32(0x18)
    header.programHeaderOffset = content.readUint32(0x1C)
    header.sectionHeaderOffset = content.readUint32(0x20)
    header.flags = content.readUint32(0x24)
    header.size = content.readUint16(0x28)
    header.programHeaderTableSize = content.readUint16(0x2A)
    header.programHeaderNum = content.readUint16(0x2C)
    header.sectionHeaderTableSize = content.readUint16(0x2E)
    header.sectionHeaderNum = content.readUint16(0x30)
    header.sectionHeaderTableNameOffset = content.readUint16(0x32)

  move(header)

func parseProgramHeaders*(content: string, count: uint): seq[ProgramHeader] =
  var headers = newSeqOfCap[ProgramHeader](count)

  var offset = when cpu64: 0x40 else: 0x34

  for i in 0 ..< count:
    var header: ProgramHeader
    let typ = content.readUint32(offset)
    offset += 4

    case typ
    of 0x0'u32:
      header.kind = ProgramHeaderKind.Null
    of 0x1'u32:
      header.kind = ProgramHeaderKind.Load
    of 0x2'u32:
      header.kind = ProgramHeaderKind.Dynamic
    of 0x3'u32:
      header.kind = ProgramHeaderKind.Interp
    of 0x4'u32:
      header.kind = ProgramHeaderKind.Note
    of 0x5'u32:
      header.kind = ProgramHeaderKind.Shlib
    of 0x6'u32:
      header.kind = ProgramHeaderKind.Phdr
    of 0x7'u32:
      header.kind = ProgramHeaderKind.TLS
    else:
      # FIXME: This is stupid.
      if typ >= 0x60000000'u32 or typ <= 0x6FFFFFFF'u32:
        header.kind = ProgramHeaderKind.OSReserved
      elif typ >= 0x70000000'u32 or typ <= 0x7FFFFFFF'u32:
        header.kind = ProgramHeaderKind.CPUReserved
      else:
        throw ProgramHeaderParseError,
          "Invalid program header type (p_type): " & asHex(typ)

    let flags = content.readUint32(offset)

    if (flags and 0x1) != 0:
      header.flags.incl(PHFlag.Executable)

    if (flags and 0x2) != 0:
      header.flags.incl(PHFlag.Writable)

    if (flags and 0x4) != 0:
      header.flags.incl(PHFlag.Readable)

    offset += 4

    when cpu64:
      header.offset = content.readUint64(offset)
      offset += 8

      header.virtualAddr = content.readUint64(offset)
      offset += 8

      header.physicalAddr = content.readUint64(offset)
      offset += 8

      header.fileSize = content.readUint64(offset)
      offset += 8

      header.memSize = content.readUint64(offset)
      offset += 8

      header.alignment = content.readUint64(offset)
      offset += 8
    else:
      header.offset = content.readUint32(offset)
      offset += 4

      header.virtualAddr = content.readUint32(offset)
      offset += 4

      header.physicalAddr = content.readUint32(offset)
      offset += 4

      header.fileSize = content.readUint32(offset)
      offset += 4

      header.memSize = content.readUint32(offset)
      offset += 4

      header.alignment = content.readUint32(offset)
      offset += 6

    headers &= move(header)

  move(headers)

func parseSectionHeaders*(content: string, header: Header): seq[SectionHeader] =
  var headers = newSeqOfCap[SectionHeader](header.sectionHeaderNum)
  var offset = int(header.sectionHeaderOffset)

  let boundary =
    header.sectionHeaderOffset +
    (header.sectionHeaderTableSize * header.sectionHeaderNum)

  let entrySize = header.sectionHeaderTableSize.int
  for i in 0'u16 ..< header.sectionHeaderNum:
    let seg = content[offset ..< offset + entrySize]
    var header: SectionHeader
    var cursor: int

    header.name = seg.readUint32(cursor)
    cursor += 4

    let kind = seg.readUint32(cursor)
    case kind
    of 0x0:
      header.kind = SectionHeaderKind.Null
    of 0x1:
      header.kind = SectionHeaderKind.ProgramData
    of 0x2:
      header.kind = SectionHeaderKind.SymbolTable
    of 0x3:
      header.kind = SectionHeaderKind.StringTable
    of 0x4:
      header.kind = SectionHeaderKind.RelocAddend
    of 0x5:
      header.kind = SectionHeaderKind.SymbolHash
    of 0x6:
      header.kind = SectionHeaderKind.Dynamic
    of 0x7:
      header.kind = SectionHeaderKind.Note
    of 0x8:
      header.kind = SectionHeaderKind.NoBits
    of 0x9:
      header.kind = SectionHeaderKind.Reloc
    of 0x0A:
      header.kind = SectionHeaderKind.Reserved
    of 0x0B:
      header.kind = SectionHeaderKind.DynSymTable
    of 0x0E:
      header.kind = SectionHeaderKind.InitArray
    of 0x0F:
      header.kind = SectionHeaderKind.FiniArray
    of 0x10:
      header.kind = SectionHeaderKind.PreinitArray
    of 0x11:
      header.kind = SectionHeaderKind.Group
    of 0x12:
      header.kind = SectionHeaderKind.ExSectionIndices
    of 0x13:
      header.kind = SectionHeaderKind.NumDefinedTypes
    else:
      if kind > 0x60000000:
        header.kind = SectionHeaderKind.OSReserved
      else:
        throw InvalidSectionHeaderType, "Invalid section type (sh_type): " & asHex(kind)

    cursor += 4

    when cpu64:
      header.flags = toSHFlags(seg.readUint64(cursor))
      cursor += 8

      header.virtualAddr = seg.readUint64(cursor)
      cursor += 8

      header.offset = seg.readUint64(cursor)
      cursor += 8

      header.size = seg.readUint64(cursor)
      cursor += 8

      header.link = seg.readUint32(cursor)
      cursor += 4

      header.info = seg.readUint32(cursor)
      cursor += 4

      header.alignment = seg.readUint64(cursor)
      cursor += 8

      header.entrySize = seg.readUint64(cursor)
      cursor += 8
    else:
      header.flags = toSHFlags(seg.readUint32(cursor))
      cursor += 4

      header.virtualAddr = seg.regUint32(cursor)
      cursor += 4

      header.offset = seg.readUint32(cursor)
      cursor += 4

      header.size = seg.readUint32(cursor)
      cursor += 4

      header.link = seg.readUint32(cursor)
      cursor += 4

      header.info = seg.readUint32(cursor)
      cursor += 4

      header.alignment = seg.readUint32(cursor)
      cursor += 4

      header.entrySize = seg.readUint32(cursor)
      cursor += 4

    headers &= move(header)

    offset += entrySize

  move(headers)

func parseELF*(content: string): ELF =
  var elf = ELF(header: parseElfHeader(content))
  elf.prog = parseProgramHeaders(content, elf.header.programHeaderNum)
  elf.sect = parseSectionHeaders(content, elf.header)

  ensureMove(elf)
