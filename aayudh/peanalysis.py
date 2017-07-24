# -*- coding: utf-8 -*-

import pylibemu
import peutils
import pydasm
import pefile
import yara

import pyasn1.codec.der.decoder
import pyasn1.codec.der.encoder
import pyasn1_modules.rfc2315

from fileutils import file_entropy_compression_stats, file_strings_ascii, file_strings_unicode, file_xor_search, file_hashes, is_file, file_basename, file_dirname, file_mimetype, file_json_open, file_exiftool
from utils import objdict, info, debug, warn, error, run_command, timestamp_to_utc_string, dict_normalize, data_hashes, data_magic, data_mimetype
from adobemalwareclassifier import run_J48, run_J48Graft, run_PART, run_Ridor
from onlinelookup import OnlineLookup
from bloomfilter import BloomFilter

from itertools import izip
import bitstring
import traceback
import binascii
import tempfile
import hashlib
import struct
import string
import json
import time
import bz2
import os
import re

from datetime import datetime
from dateutil import parser
from dateutil import tz


class PEAnalysis:
  def __init__(self, filename, config=None):
    if not is_file(filename) and file_mimetype(filename) != "application/x-dosexec":
      return None

    # initialize default config opts
    # these will be overridden via config file
    self.config = objdict({})
    self.config.verbose = False

    # override default config opts
    if config:
      for key, value in config.iteritems():
        self.config[key] = value

    # initialize config opts that cannot be overridden
    self.config.filename = filename
    self.config.signatures = objdict({})

    self.config.signatures.api = self.config.sigapi
    self.config.signatures.mutexes = self.config.sigmutexes
    self.config.signatures.pdbpaths = self.config.sigpdbpaths
    self.config.signatures.regexantivm = self.config.sigregexantivm
    self.config.signatures.regex = self.config.sigregex
    self.config.signatures.knownsections = self.config.sigknownsections
    self.config.signatures.packersections = self.config.sigpackersections
    self.config.signatures.userdb = self.config.siguserdb
    self.config.signatures.yara = self.config.sigyara
    self.config.signatures.mandiant = objdict({})
    self.config.signatures.mandiant.hashfile = self.config.sigmandiant_hashfile
    self.config.signatures.mandiant.bloomfilterfile = self.config.sigmandiant_bloomfilterfile
    self.config.signatures.nsrl = objdict({})
    self.config.signatures.nsrl.hashfile = self.config.signsrl_hashfile
    self.config.signatures.nsrl.bloomfilterfile = self.config.signsrl_bloomfilterfile
    self.config.signatures.langid = self.config.langid

    self.report = objdict({})
    self.report.static = objdict({})

    self.report.static.authenticode = objdict({})
    self.report.static.authenticode.certs = None
    self.report.static.authenticode.hashes = objdict({})
    self.report.static.authenticode.hashes.md5 = None
    self.report.static.authenticode.hashes.sha256 = None
    self.report.static.authenticode.hashes.ssdeep = None
    self.report.static.authenticode.offset = None
    self.report.static.authenticode.openssl = None
    self.report.static.authenticode.size = None
    self.report.static.debug = None
    self.report.static.dosheader = objdict({})
    self.report.static.dosheader.dosstub = objdict({})
    self.report.static.dosheader.dosstub.md5 = None
    self.report.static.dosheader.dosstub.raw = None
    self.report.static.dosheader.dosstub.sha256 = None
    self.report.static.dosheader.dosstub.ssdeep = None
    self.report.static.entropycategory = None
    self.report.static.exports = None
    self.report.static.hashes = objdict({})
    self.report.static.hashes.authentihash = None
    self.report.static.hashes.imphash = None
    self.report.static.hashes.pehash = None
    self.report.static.imports = None
    self.report.static.manifest = None
    self.report.static.NETversion = None
    self.report.static.ntheaders = objdict({})
    self.report.static.ntheaders.datadirectory = None
    self.report.static.ntheaders.fileheader = objdict({})
    self.report.static.ntheaders.fileheader.Characteristics = objdict({})
    self.report.static.ntheaders.fileheader.Characteristics.flags = None
    self.report.static.ntheaders.fileheader.Characteristics.Value = None
    self.report.static.ntheaders.fileheader.NumberOfSections = None
    self.report.static.ntheaders.fileheader.Machine = None
    self.report.static.ntheaders.fileheader.Machine_verbose = None
    self.report.static.ntheaders.fileheader.TimeDateStamp = None
    self.report.static.ntheaders.fileheader.TimeDateStamp_verbose = None
    self.report.static.ntheaders.optionalheader = objdict({})
    self.report.static.ntheaders.optionalheader.DllCharacteristics = objdict({})
    self.report.static.ntheaders.optionalheader.DllCharacteristics.flags = None
    self.report.static.ntheaders.optionalheader.DllCharacteristics.Value = None
    self.report.static.ntheaders.optionalheader.ImageBase = None
    self.report.static.ntheaders.optionalheader.CheckSum = None
    self.report.static.ntheaders.optionalheader.SizeOfStackCommit = None
    self.report.static.ntheaders.optionalheader.SizeOfStackReserve = None
    self.report.static.ntheaders.optionalheader.SizeOfHeapCommit = None
    self.report.static.ntheaders.optionalheader.SizeOfHeapReserve = None
    self.report.static.ntheaders.optionalheader.Magic = None
    self.report.static.ntheaders.optionalheader.Magic_verbose = None
    self.report.static.ntheaders.optionalheader.Subsystem = None
    self.report.static.ntheaders.optionalheader.Subsystem_verbose = None
    self.report.static.ntheaders.optionalheader.AddressOfEntryPoint = None
    self.report.static.ntheaders.sections = None
    self.report.static.ntheaders.signature = None
    self.report.static.overlay = objdict({})
    self.report.static.overlay.hashes = objdict({})
    self.report.static.overlay.hashes.md5 = None
    self.report.static.overlay.hashes.sha256 = None
    self.report.static.overlay.hashes.ssdeep = None
    self.report.static.overlay.magic = None
    self.report.static.overlay.mimetype = None
    self.report.static.overlay.offset = None
    self.report.static.overlay.size = None
    self.report.static.relocations = None
    self.report.static.resources = None
    self.report.static.strings = objdict({})
    self.report.static.strings.ascii = None
    self.report.static.strings.unicode = None
    self.report.static.tls = None
    self.report.static.versioninfo = objdict({})
    self.report.static.versioninfo.Codepage = None
    self.report.static.versioninfo.Codepage_verbose = None
    self.report.static.versioninfo.fileinfo = objdict({})
    self.report.static.versioninfo.fileinfo.FileOS = None
    self.report.static.versioninfo.fileinfo.FileOS_verbose = None
    self.report.static.versioninfo.fileinfo.FileSubtype = None
    self.report.static.versioninfo.fileinfo.FileSubtype_verbose = None
    self.report.static.versioninfo.fileinfo.FileType = None
    self.report.static.versioninfo.fileinfo.FileType_verbose = None
    self.report.static.versioninfo.FileVersion = None
    self.report.static.versioninfo.FileVersion_verbose = None
    self.report.static.versioninfo.FileDescription = None
    self.report.static.versioninfo.FileDescription_verbose = None
    self.report.static.versioninfo.OriginalFilename = None
    self.report.static.versioninfo.OriginalFilename_verbose = None
    self.report.static.versioninfo.CompanyName = None
    self.report.static.versioninfo.CompanyName_verbose = None
    self.report.static.versioninfo.LegalCopyright = None
    self.report.static.versioninfo.LegalCopyright_verbose = None
    self.report.static.versioninfo.Language = None
    self.report.static.versioninfo.Language_verbose = None
    self.report.static.versioninfo.Translation = None

    self.report.dynamic = objdict({})
    self.report.dynamic.dns = None
    self.report.dynamic.network = None
    self.report.dynamic.loaddlls = None
    self.report.dynamic.process = None

    self.report.dynamic.registry = objdict({})
    self.report.dynamic.registry.read = None
    self.report.dynamic.registry.write = None

    self.report.dynamic.filesystem = objdict({})
    self.report.dynamic.filesystem.read = None
    self.report.dynamic.filesystem.write = None
    self.report.dynamic.filesystem.move = None
    self.report.dynamic.filesystem.dropped = None

    self.report.scan = objdict({})
    self.report.scan.adobemalwareclassifier = None
    self.report.scan.antivm = None
    self.report.scan.mutex = None
    self.report.scan.regex = None
    self.report.scan.shellcode = None
    self.report.scan.whitelist = None
    self.report.scan.yara = None
    self.report.scan.online = None
    self.report.indicators = objdict({})
    self.report.indicators.checks = objdict({})
    self.report.indicators.flags = objdict({})
    self.report.indicators.warnings = []

    try:
      self.pe = pefile.PE(filename)
    except Exception as ex:
      self.report.indicators.warnings.append("%s" % ex)

  def get_dosheader(self): # ms, rich, dosstub
    self.report.static.dosheader = objdict({})
    self.report.static.dosheader.mzheader = objdict({})

    dosheader = self.pe.DOS_HEADER.dump_dict()
    for i in range(len(self.pe.DOS_HEADER.__keys__)):
      self.report.static.dosheader.mzheader[self.pe.DOS_HEADER.__keys__[i][0]] = dosheader[self.pe.DOS_HEADER.__keys__[i][0]]['Value']

    # http://www.ntcore.com/files/richsign.htm
    # http://www.stoned-vienna.com/microsofts-rich-header.html
    rich_start_offset = 128 # 0x80
    if "e_lfanew" in self.report.static.dosheader.mzheader and self.report.static.dosheader.mzheader.e_lfanew:
      richdata = self.pe.__data__[128:self.report.static.dosheader.mzheader.e_lfanew]
      richdatasize = len(richdata)
      richdwordcount = richdatasize / 4

      richdwordlist = list(struct.unpack("<%dI" % richdwordcount, richdata))
      richstring = re.search("Rich", richdata)
      if richstring:
        richstringoffset = re.search("Rich", richdata).start()
        richxorkey = struct.unpack("<I", richdata[richstringoffset+4:richstringoffset+8])[0]
        richmagicstring = str("%x" % (struct.unpack("<I", richdata[:4])[0] ^ richxorkey)).decode("hex")

        if richmagicstring == "SnaD":
          if richdwordlist[1] == richxorkey and richdwordlist[2] == richxorkey and richdwordlist[3] == richxorkey:
            self.report.static.dosheader.richheader = []
            for i in range(0, richdwordcount, 2):
              # ignore first 4 DWORDs (has SnaD string and 3 times repeated xorkey/checksum)
              if i < 4:
                continue
              # extract current and next dword
              compid = struct.unpack("<I", richdata[i*4:(i*4)+4])[0]
              # stop processing if we reach the Rich string
              # this means compid parsing is complete
              if str("%08x" % (compid)).decode("hex") == "hciR":
                break
              libid, version = struct.unpack(">HH", ("%08x" % (compid ^ richxorkey)).decode("hex"))
              revision = struct.unpack("<I", richdata[(i+1)*4:((i+1)*4)+4])[0] ^ richxorkey
              self.report.static.dosheader.richheader.append({
                "libid": libid,
                "version": version,
                "revision": revision
              })

      # dos stub @ offset 64, size 64
      if len(self.pe.__data__) >= 127:
        self.report.static.dosheader.dosstub = objdict({})
        self.report.static.dosheader.dosstub.raw = self.pe.__data__[64:128]
        self.report.static.dosheader.dosstub.md5 = data_hashes(self.report.static.dosheader.dosstub.raw, "md5")
        self.report.static.dosheader.dosstub.sha256 = data_hashes(self.report.static.dosheader.dosstub.raw, "sha256")
        self.report.static.dosheader.dosstub.ssdeep = data_hashes(self.report.static.dosheader.dosstub.raw, "ssdeep")

  def get_ntheader(self):
    self.report.static.ntheaders = objdict({})
    self.report.static.ntheaders.fileheader = objdict({})
    self.report.static.ntheaders.optionalheader = objdict({})

    # get ntheader signature string: "PE"
    self.report.static.ntheaders.signature = self.pe.NT_HEADERS.Signature

    # if signature is valid, get file/optional headers, sections and datadirs
    if struct.pack("<h", self.report.static.ntheaders.signature) == "PE":
      fileheader = self.pe.NT_HEADERS.FILE_HEADER.dump_dict()
      for i in range(len(self.pe.NT_HEADERS.FILE_HEADER.__keys__)):
        if self.pe.NT_HEADERS.FILE_HEADER.__keys__[i][0] == 'Characteristics':
          self.report.static.ntheaders.fileheader.Characteristics = objdict({})
          self.report.static.ntheaders.fileheader.Characteristics.Value = fileheader[self.pe.NT_HEADERS.FILE_HEADER.__keys__[i][0]]['Value']
          self.report.static.ntheaders.fileheader.Characteristics.flags = objdict({})
          for c in pefile.image_characteristics:
            self.report.static.ntheaders.fileheader.Characteristics.flags[c[0]] = True if self.report.static.ntheaders.fileheader.Characteristics.Value & c[1] else False
        else:
          self.report.static.ntheaders.fileheader[self.pe.NT_HEADERS.FILE_HEADER.__keys__[i][0]] = fileheader[self.pe.NT_HEADERS.FILE_HEADER.__keys__[i][0]]['Value']

      # https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#COFF_Header
      machinetypes = {
        0x14c: "Intel 386",
        0x14d: "Intel i860",
        0x162: "MIPS R3000",
        0x166: "MIPS little endian (R4000)",
        0x168: "MIPS R10000",
        0x169: "MIPS little endian WCI v2",
        0x183: "old Alpha AXP",
        0x184: "Alpha AXP",
        0x1a2: "Hitachi SH3",
        0x1a3: "Hitachi SH3 DSP",
        0x1a6: "Hitachi SH4",
        0x1a8: "Hitachi SH5",
        0x1c0: "ARM little endian",
        0x1c2: "Thumb",
        0x1d3: "Matsushita AM33",
        0x1f0: "PowerPC little endian",
        0x1f1: "PowerPC with floating point support",
        0x200: "Intel IA64",
        0x266: "MIPS16",
        0x268: "Motorola 68000 series",
        0x284: "Alpha AXP 64-bit",
        0x366: "MIPS with FPU",
        0x466: "MIPS16 with FPU",
        0xebc: "EFI Byte Code",
        0x8664: "AMD AMD64",
        0x9041: "Mitsubishi M32R little endian",
        0xc0ee: "clr pure MSIL"
      }
      self.report.static.ntheaders.fileheader.Machine_verbose = machinetypes[self.report.static.ntheaders.fileheader.Machine] if self.report.static.ntheaders.fileheader.Machine in machinetypes else None

      # TimeDateStamp is a string with a combination of hex and printable datestring
      # lets split it into raw and verbose components
      r = int(self.report.static.ntheaders.fileheader.TimeDateStamp.split(" [")[0], 0)
      v = self.report.static.ntheaders.fileheader.TimeDateStamp.split(" [")[1].split("]")[0]
      self.report.static.ntheaders.fileheader.TimeDateStamp = r
      self.report.static.ntheaders.fileheader.TimeDateStamp_verbose = v

      optionalheader = self.pe.NT_HEADERS.OPTIONAL_HEADER.dump_dict()
      for i in range(len(self.pe.NT_HEADERS.OPTIONAL_HEADER.__keys__)):
        if self.pe.NT_HEADERS.OPTIONAL_HEADER.__keys__[i][0] == 'DllCharacteristics':
          self.report.static.ntheaders.optionalheader.DllCharacteristics = objdict({})
          self.report.static.ntheaders.optionalheader.DllCharacteristics.Value = optionalheader[self.pe.NT_HEADERS.OPTIONAL_HEADER.__keys__[i][0]]['Value']
          self.report.static.ntheaders.optionalheader.DllCharacteristics.flags = objdict({})
          for c in pefile.dll_characteristics:
            self.report.static.ntheaders.optionalheader.DllCharacteristics.flags[c[0]] = True if self.report.static.ntheaders.optionalheader.DllCharacteristics.Value & c[1] else False
        else:
          self.report.static.ntheaders.optionalheader[self.pe.NT_HEADERS.OPTIONAL_HEADER.__keys__[i][0]] = optionalheader[self.pe.NT_HEADERS.OPTIONAL_HEADER.__keys__[i][0]]['Value']

      # https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339%28v=vs.85%29.aspx
      magictypes = {
        0x10b: "32_BIT",
        0x20b: "64_BIT",
        0x107: "ROM_IMAGE"
      }
      self.report.static.ntheaders.optionalheader.Magic_verbose = magictypes[self.report.static.ntheaders.optionalheader.Magic] if self.report.static.ntheaders.optionalheader.Magic in magictypes else None

      subsystemtypes = {
        0: "UNKNOWN",
        1: "NATIVE",
        2: "WINDOWS_GUI",
        3: "WINDOWS_CUI",
        5: "OS2_CUI",
        7: "POSIX_CUI",
        9: "WINDOWS_CE_GUI",
        10: "EFI_APPLICATION",
        11: "EFI_BOOT_SERVICE_DRIVER",
        12: "EFI_RUNTIME_DRIVER",
        13: "EFI_ROM",
        14: "XBOX",
        16: "BOOT_APPLICATION"
      }
      self.report.static.ntheaders.optionalheader.Subsystem_verbose = subsystemtypes[self.report.static.ntheaders.optionalheader.Subsystem] if self.report.static.ntheaders.optionalheader.Subsystem in subsystemtypes else None

      self.report.static.ntheaders.datadirectory = []
      for d in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if d.VirtualAddress != 0 or d.Size != 0:
          try:
            secname = ''.join([c for c in self.pe.get_section_by_rva(d.VirtualAddress).Name if c in string.printable])
          except:
            secname = None
          self.report.static.ntheaders.datadirectory.append({
            "Name": d.name,
            "Size": d.Size,
            "Section": secname,
            "VirtualAddress": d.VirtualAddress
          })

      self.report.static.ntheaders.sections = []
      for section in self.pe.sections:
        secname = ''.join([c for c in section.Name if c in string.printable])
        currsection = objdict({})
        currsection[secname] = objdict({})
        currsection[secname].hashes = objdict({})
        currsection[secname].hashes.md5 = section.get_hash_md5()
        currsection[secname].hashes.sha256 = section.get_hash_sha256()
        currsection[secname].hashes.ssdeep = data_hashes(section.get_data(), "ssdeep")
        currsection[secname].entropy = section.get_entropy()
        currsection[secname].VirtualAddress = section.VirtualAddress
        currsection[secname].Misc_VirtualSize = section.Misc_VirtualSize
        currsection[secname].SizeOfRawData = section.SizeOfRawData

        currsection[secname].Characteristics = objdict({})
        currsection[secname].Characteristics.Value = section.dump_dict()['Characteristics']['Value']
        flag = currsection[secname].Characteristics.Value

        currsection[secname].Characteristics.flags = objdict({})
        currsection[secname].Characteristics.flags.IMAGE_SCN_TYPE_NO_PAD = True if flag & 0x00000008 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_CNT_CODE = True if flag & 0x00000020 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_CNT_INITIALIZED_DATA = True if flag & 0x00000040 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_CNT_UNINITIALIZED_DATA = True if flag & 0x00000080 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_LNK_OTHER = True if flag & 0x00000100 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_LNK_INFO = True if flag & 0x00000200 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_LNK_REMOVE = True if flag & 0x00000800 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_LNK_COMDAT = True if flag & 0x00001000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_NO_DEFER_SPEC_EXC = True if flag & 0x00004000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_GPREL = True if flag & 0x00008000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_FARDATA = True if flag & 0x00008000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_PURGEABLE = True if flag & 0x00020000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_16BIT = True if flag & 0x00020000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_LOCKED = True if flag & 0x00040000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_PRELOAD = True if flag & 0x00080000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_1BYTES = True if flag & 0x00100000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_2BYTES = True if flag & 0x00200000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_4BYTES = True if flag & 0x00300000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_8BYTES = True if flag & 0x00400000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_16BYTES = True if flag & 0x00500000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_32BYTES = True if flag & 0x00600000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_64BYTES = True if flag & 0x00700000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_128BYTES = True if flag & 0x00800000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_256BYTES = True if flag & 0x00900000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_512BYTES = True if flag & 0x00A00000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_1024BYTES = True if flag & 0x00B00000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_2048BYTES = True if flag & 0x00C00000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_4096BYTES = True if flag & 0x00D00000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_8192BYTES = True if flag & 0x00E00000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_ALIGN_MASK = True if flag & 0x00F00000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_LNK_NRELOC_OVFL = True if flag & 0x01000000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_DISCARDABLE = True if flag & 0x02000000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_NOT_CACHED = True if flag & 0x04000000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_NOT_PAGED = True if flag & 0x08000000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_SHARED = True if flag & 0x10000000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_EXECUTE = True if flag & 0x20000000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_READ = True if flag & 0x40000000 else False
        currsection[secname].Characteristics.flags.IMAGE_SCN_MEM_WRITE = True if flag & 0x80000000 else False

        flag = currsection[secname].Characteristics.Value
        perms = []
        perms += "R" if flag & 0x40000000 else "-"
        perms += "W" if flag & 0x80000000 else "-"
        perms += "X" if flag & 0x20000000 else "-"
        currsection[secname].permissions = "".join(perms)

        currsection[secname].checks = objdict({})
        currsection[secname].checks.entrypoint = True if section.contains_rva(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint) else False
        currsection[secname].checks.executablecode = True if flag & 0x00000020 else False
        currsection[secname].checks.initializeddata = True if flag & 0x00000040 else False
        currsection[secname].checks.uninitializeddata = True if flag & 0x00000080 else False

        currsection[secname].codecaves = []

        # http://www.brokenthorn.com/Resources/OSDevPE.html
        # http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/
        knownsections = file_json_open(self.config.signatures.knownsections)

        suspicioussections = [
          "Tut4you", "PE_ADS"
        ]

        # http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/
        packersections = file_json_open(self.config.signatures.packersections)

        currsection[secname].classification = "CLEAN"
        currsection[secname].classificationreasons = []

        if section.SizeOfRawData == 0:
          currsection[secname].classification = "SUSPICIOUS"
          currsection[secname].classificationreasons.append("SizeOfRawData should be nonzero")
        if currsection[secname].entropy > 0.0 and currsection[secname].entropy < 1.0:
          currsection[secname].classification = "SUSPICIOUS"
          currsection[secname].classificationreasons.append("Entropy: 0.0 > %s < 1.0" % currsection[secname].entropy)
        if currsection[secname].entropy > 7.0:
          currsection[secname].classification = "SUSPICIOUS"
          currsection[secname].classificationreasons.append("Entropy: %s > 7.0" % currsection[secname].entropy)
        if 'W' in currsection[secname].permissions and 'X' in currsection[secname].permissions:
          currsection[secname].classification = "SUSPICIOUS"
          currsection[secname].classificationreasons.append("Permissions: %s should be W^X" % currsection[secname].permissions)
        if secname in packersections.keys():
          currsection[secname].classification = "SUSPICIOUS"
          currsection[secname].classificationreasons.append("Section name \"%s\" is used by packers (%s)" % (secname, packersections[secname]["description"]))
        if secname in suspicioussections:
          currsection[secname].classification = "SUSPICIOUS"
          currsection[secname].classificationreasons.append("Section name \"%s\" is suspicious" % secname)
        if secname not in knownsections:
          currsection[secname].classification = "SUSPICIOUS"
          currsection[secname].classificationreasons.append("Section name \"%s\" is not commonly used" % secname)

        self.report.static.ntheaders.sections.append(currsection)

  def get_relocations(self):
    if hasattr(self.pe, "DIRECTORY_ENTRY_BASERELOC"):
      self.report.static.relocations = []
      for entry in self.pe.DIRECTORY_ENTRY_BASERELOC:
        for subentry in entry.entries:
          self.report.static.relocations.append({
            "baserva": subentry.base_rva,
            "rva": subentry.rva,
            "type": subentry.type
          })

  def get_manifest(self):
    if hasattr(self.report.static, "resources"):
      for rsrcentry in self.report.static.resources:
        if rsrcentry["name"] == "RT_MANIFEST":
          self.report.static.manifest = self.pe.write()[self.pe.get_offset_from_rva(rsrcentry["OffsetToData"]):self.pe.get_offset_from_rva(rsrcentry["OffsetToData"])+rsrcentry["Size"]]

  def get_versioninfo(self):
    if hasattr(self.pe, "VS_VERSIONINFO"):
      if hasattr(self.pe, "FileInfo"):
        for entry in self.pe.FileInfo:
          if hasattr(entry, "StringTable"):
            for tabentry in entry.StringTable:
              for strentry in tabentry.entries.items():
                self.report.static.versioninfo[strentry[0].replace(" ", "")] = strentry[1]
          elif hasattr(entry, "Var"):
            for varentry in entry.Var:
              if hasattr(varentry, "entry"):
                self.report.static.versioninfo[varentry.entry.keys()[0].replace(" ", "")] = varentry.entry.values()[0]

    if self.report.static.versioninfo and hasattr(self.report.static.versioninfo, "Translation") and self.report.static.versioninfo.Translation:
      self.report.static.versioninfo.Language, self.report.static.versioninfo.Codepage = self.report.static.versioninfo.Translation.split(" ", 2)
      del self.report.static.versioninfo.Translation
      siglangid = objdict(file_json_open(self.config.signatures.langid))

      if self.report.static.versioninfo.Language in siglangid.langids:
        self.report.static.versioninfo.Language_verbose = siglangid.langids[self.report.static.versioninfo.Language]
      self.report.static.versioninfo.Language = int(self.report.static.versioninfo.Language, 0)

      if self.report.static.versioninfo.Codepage in siglangid.codepages:
        self.report.static.versioninfo.Codepage_verbose = siglangid.codepages[self.report.static.versioninfo.Codepage]
      self.report.static.versioninfo.Codepage = int(self.report.static.versioninfo.Codepage, 0)

      if hasattr(self.pe, "VS_FIXEDFILEINFO"):
        self.report.static.versioninfo.fileinfo = objdict({})
        # https://msdn.microsoft.com/en-us/library/windows/desktop/ms646997%28v=vs.85%29.aspx
        self.report.static.versioninfo.fileinfo.FileOS = self.pe.VS_FIXEDFILEINFO.FileOS
        self.report.static.versioninfo.fileinfo.FileOS_verbose = []
        if self.report.static.versioninfo.fileinfo.FileOS & 0x00010000L != 0:
          self.report.static.versioninfo.fileinfo.FileOS_verbose.append("VOS_DOS")
        if self.report.static.versioninfo.fileinfo.FileOS & 0x00040000L != 0:
          self.report.static.versioninfo.fileinfo.FileOS_verbose.append("VOS_NT")
        if self.report.static.versioninfo.fileinfo.FileOS & 0x00000001L != 0:
          self.report.static.versioninfo.fileinfo.FileOS_verbose.append("VOS__WINDOWS16")
        if self.report.static.versioninfo.fileinfo.FileOS & 0x00000004L != 0:
          self.report.static.versioninfo.fileinfo.FileOS_verbose.append("VOS__WINDOWS32")

        self.report.static.versioninfo.fileinfo.FileType = self.pe.VS_FIXEDFILEINFO.FileType
        self.report.static.versioninfo.fileinfo.FileType_verbose = None
        if self.report.static.versioninfo.fileinfo.FileType == 0x00000001L:
          self.report.static.versioninfo.fileinfo.FileType_verbose = "VFT_APP"
        elif self.report.static.versioninfo.fileinfo.FileType == 0x00000002L:
          self.report.static.versioninfo.fileinfo.FileType_verbose = "VFT_DLL"
        elif self.report.static.versioninfo.fileinfo.FileType == 0x00000003L:
          self.report.static.versioninfo.fileinfo.FileType_verbose = "VFT_DRV"
        elif self.report.static.versioninfo.fileinfo.FileType == 0x00000004L:
          self.report.static.versioninfo.fileinfo.FileType_verbose = "VFT_FONT"
        elif self.report.static.versioninfo.fileinfo.FileType == 0x00000005L:
          self.report.static.versioninfo.fileinfo.FileType_verbose = "VFT_VXD"
        elif self.report.static.versioninfo.fileinfo.FileType == 0x00000007L:
          self.report.static.versioninfo.fileinfo.FileType_verbose = "VFT_STATIC_LIB"

        self.report.static.versioninfo.fileinfo.FileSubtype = self.pe.VS_FIXEDFILEINFO.FileSubtype
        self.report.static.versioninfo.fileinfo.FileSubtype_verbose = None
        if self.report.static.versioninfo.fileinfo.FileType == 0x00000003L:
          if self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000001L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_PRINTER"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000002L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_KEYBOARD"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000003L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_LANGUAGE"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000004L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_DISPLAY"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000005L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_MOUSE"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000006L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_NETWORK"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000007L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_SYSTEM"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000008L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_INSTALLABLE"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000009L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_SOUND"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x0000000AL:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_COMM"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x0000000CL:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_DRV_VERSIONED_PRINTER"

        elif self.report.static.versioninfo.fileinfo.FileType == 0x00000004L:
          if self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000001L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_FONT_RASTER"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000002L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_FONT_VECTOR"
          elif self.report.static.versioninfo.fileinfo.FileSubtype == 0x00000003L:
            self.report.static.versioninfo.fileinfo.FileSubtype_verbose = "VFT2_FONT_TRUETYPE"

  # https://github.com/Rurik/FileInfo/blob/master/FileInfo.py
  def get_NETversion(self):
    if not (len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 and \
      self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].name == 'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR' and \
      self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0):
      self.report.static.NETversion = None
      return
    """
    Code to extract .NET compiled version.
    typedef struct t_MetaData_Header {
      DWORD Signature;    // BSJB
      WORD MajorVersion;
      WORD MinorVersion;
      DWORD Unknown1;
      DWORD VersionSize;
      PBYTE VersionString;
      WORD Flags;
      WORD NumStreams;
      PBYTE Streams;
    } METADATA_HEADER, *PMETADATA_HEADER;
    """
    data = open(self.config.filename, 'rb').read()
    offset = data.find('BSJB')
    if offset > 0:
      hdr = data[offset:offset+32]
      magic = hdr[0:4]
      major = struct.unpack('i', hdr[4:8])[0]
      minor = struct.unpack('i', hdr[8:12])[0]
      size = struct.unpack('i', hdr[12:16])[0]
      self.report.static.NETversion = hdr[16:16+size].strip('\x00')
    else:
      self.report.static.NETversion = None

  def get_authenticode(self):
    if hasattr(self.pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
      for s in self.pe.__structures__:
        if s.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
          address = s.VirtualAddress
          size = s.Size
          authenticoderaw = self.pe.write()[address+8:]
          if address != 0 and size != 0 and len(authenticoderaw) != 0:
            self.report.static.authenticode = objdict({})

            # authentiocde/digicert in ASN.1 structure with DER encoding (alternative: PEM encoding - convert using openssl)
            #  DWORD       dwLength - this is the length of bCertificate
            #  WORD        wRevision
            #  WORD        wCertificateType
            #  BYTE        bCertificate[dwLength] - this contains the PKCS7 signature
            self.report.static.authenticode.offset = address+8
            self.report.static.authenticode.size = (len(self.pe.write()) - self.report.static.authenticode.offset)

            self.report.static.authenticode.hashes = objdict({})
            self.report.static.authenticode.hashes.md5 = data_hashes(authenticoderaw, "md5")
            self.report.static.authenticode.hashes.sha256 = data_hashes(authenticoderaw, "sha256")
            self.report.static.authenticode.hashes.ssdeep = data_hashes(authenticoderaw, "ssdeep")

            # https://github.com/vivisect/vivisect/blob/master/PE/__init__.py
            # http://l33t.codes/pkcs-7-with-pefile-and-pyasn1/
            if authenticoderaw:
              try:
                substrate = authenticoderaw
                contentInfo, rest = pyasn1.codec.der.decoder.decode(substrate, asn1Spec=pyasn1_modules.rfc2315.ContentInfo())
                if rest:
                  substrate = substrate[:-len(rest)]
                contentType = contentInfo.getComponentByName('contentType')
                contentInfoMap = {
                    (1, 2, 840, 113549, 1, 7, 1): pyasn1_modules.rfc2315.Data(),
                    (1, 2, 840, 113549, 1, 7, 2): pyasn1_modules.rfc2315.SignedData(),
                    (1, 2, 840, 113549, 1, 7, 3): pyasn1_modules.rfc2315.EnvelopedData(),
                    (1, 2, 840, 113549, 1, 7, 4): pyasn1_modules.rfc2315.SignedAndEnvelopedData(),
                    (1, 2, 840, 113549, 1, 7, 5): pyasn1_modules.rfc2315.DigestedData(),
                    (1, 2, 840, 113549, 1, 7, 6): pyasn1_modules.rfc2315.EncryptedData()
                    }
                seqTypeMap = {
                    (2,5,4,3):                      'CN',
                    (2,5,4,7):                      'L',
                    (2,5,4,10):                     'O',
                    (2,5,4,11):                     'OU',
                    (1,2,840,113549,1,9,1):         'E',
                    (2,5,4,6):                      'C',
                    (2,5,4,8):                      'ST',
                    (2,5,4,9):                      'STREET',
                    (2,5,4,12):                     'TITLE',
                    (2,5,4,42):                     'G',
                    (2,5,4,43):                     'I',
                    (2,5,4,4):                      'SN',
                    (0,9,2342,19200300,100,1,25):   'DC',
                }
                content, _ = pyasn1.codec.der.decoder.decode(contentInfo.getComponentByName('content'), asn1Spec=contentInfoMap[contentType])
                certs = content.getComponentByName('certificates')
                self.report.static.authenticode.certs = []
                for i in certs:
                  iparts = []
                  for rdnsequence in i["certificate"]["tbsCertificate"]["issuer"]:
                    for rdn in rdnsequence:
                      rtype = rdn[0]["type"]
                      rvalue = rdn[0]["value"][2:]
                      iparts.append('%s=%s' % (seqTypeMap.get( rtype, 'UNK'), rvalue))
                  issuer = ','.join(iparts)
                  sparts = []
                  for rdnsequence in i["certificate"]["tbsCertificate"]["subject"]:
                    for rdn in rdnsequence:
                      rtype = rdn[0]["type"]
                      rvalue = rdn[0]["value"][2:]
                      sparts.append('%s=%s' % (seqTypeMap.get( rtype, 'UNK'), rvalue))
                  subject = ','.join(sparts)
                  serial = int(i["certificate"]["tbsCertificate"]["serialNumber"])
                  # Time(componentType=NamedTypes(NamedType('utcTime', UTCTime()), NamedType('generalTime', GeneralizedTime()))).setComponents(UTCTime('100516235959Z'))
                  notbefore = i["certificate"]["tbsCertificate"]["validity"]["notBefore"][0]
                  notafter = i["certificate"]["tbsCertificate"]["validity"]["notAfter"][0]
                  cert = {
                    "subject": subject,
                    "issuer": issuer,
                    "serial": serial,
                    "version": None,
                    "algorithm": None,
                    "notbefore": "%s UTC" % datetime.strptime("20%s" % notbefore[:-1], "%Y%m%d%H%M%S").replace(tzinfo=tz.tzutc()).strftime("%b %d %H:%M:%S %Y"),
                    "notbefore_raw": int(time.mktime((parser.parse("%s UTC" % datetime.strptime("20%s" % notbefore[:-1], "%Y%m%d%H%M%S").replace(tzinfo=tz.tzutc()).strftime("%b %d %H:%M:%S %Y"))).timetuple())),
                    "notafter": "%s UTC" % datetime.strptime("20%s" % notafter[:-1], "%Y%m%d%H%M%S").replace(tzinfo=tz.tzutc()).strftime("%b %d %H:%M:%S %Y"),
                    "notafter_raw": int(time.mktime((parser.parse("%s UTC" % datetime.strptime("20%s" % notafter[:-1], "%Y%m%d%H%M%S").replace(tzinfo=tz.tzutc()).strftime("%b %d %H:%M:%S %Y"))).timetuple())),
                    #"bytes": pyasn1.codec.der.encoder.encode(i['certificate'])
                  }
                  self.report.static.authenticode.certs.append(cert)
                try:
                  tmp = tempfile.NamedTemporaryFile()
                  tmp.write(authenticoderaw)
                  tmp.seek(0)
                  # openssl pkcs7 -inform DER -print_certs -text -in authenticode.der
                  cmd = "%s %s" % ("openssl pkcs7 -inform DER -print_certs -text -in", tmp.name)
                  stdout, stderr = run_command(cmd)
                  if stdout:
                    self.report.static.authenticode.openssl = stdout
                finally:
                  tmp.close()
              except Exception as ex:
                warn("Exception while parsing authenticode: %s" % ex)
                self.report.static.authenticode = None

    if 'authenticode' not in self.report.static:
      self.report.static.authenticode = None

  def get_debug(self):
    # http://www.godevtool.com/Other/pdb.htm
    # http://0xdabbad00.com/2014/01/01/a-failed-attempt-at-identifying-a-developer-using-data-in-the-pe-file-format/
    # https://en.wikipedia.org/wiki/Universally_unique_identifier
    # https://en.wikipedia.org/wiki/Globally_unique_identifier
    # https://github.com/MITRECND/multiscanner/blob/master/modules/PEFile.py
    if hasattr(self.pe, "DIRECTORY_ENTRY_DEBUG"):
      self.report.static.debug = objdict({})
      try:
        for dbg in self.pe.DIRECTORY_ENTRY_DEBUG:
          if hasattr(dbg.struct, "Type"):
            #if len(pefile.debug_types) >= dbg.struct.Type and pefile.debug_types[dbg.struct.Type][0] == 'IMAGE_DEBUG_TYPE_CODEVIEW':
            if dbg.struct.Type == 0x2 and pefile.debug_types[dbg.struct.Type][0] == 'IMAGE_DEBUG_TYPE_CODEVIEW':
              debug_offset, debug_size = dbg.struct.PointerToRawData, dbg.struct.SizeOfData
              if debug_size > 0 and debug_size < 0x200:
                debug_data = self.pe.__data__[debug_offset:debug_offset + debug_size]
                if debug_data[:4] == "RSDS":
                  guid_raw = debug_data[4:20]
                  self.report.static.debug = {
                    'Sig': debug_data[0x00:0x04],
                    'Size': debug_size,
                    'TimeDateStamp': '0x%08X [%s]' % (dbg.struct.TimeDateStamp, timestamp_to_utc_string(dbg.struct.TimeDateStamp)),
                    'GUID': "-".join(["%X" % struct.unpack("<I", guid_raw[0:4])[0], "%X" % struct.unpack("<H", guid_raw[4:6])[0], "%X" % struct.unpack("<H", guid_raw[6:8])[0], guid_raw[8:10].encode("hex").upper(), guid_raw[10:16].encode("hex").upper()]),
                    'Age': struct.unpack('I', debug_data[0x14:0x18])[0],
                    'PDBPath': debug_data[0x18:dbg.struct.SizeOfData - 1].decode('UTF-8', errors='replace') if dbg.struct.SizeOfData > 0x18 else None
                  }

                elif debug_data[:4] == "NB10":
                  self.report.static.debug.update({
                    'Sig': debug_data[0x00:0x04],
                    'Size': debug_size,
                    'Time': struct.unpack('I', debug_data[0x08:0x0c])[0],
                    'Age': struct.unpack('I', debug_data[0x0c:0x10])[0],
                    'PDBPath': debug_data[0x10:dbg.struct.SizeOfData - 1].decode('UTF-8', errors='replace') if dbg.struct.SizeOfData > 0x10 else None
                  })

      except Exception as ex:
        warn("Could not parse debug information: %s" % ex)
        traceback.print_exc()

  def get_exports(self):
    if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
      self.report.static.exports = []
      for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
        self.report.static.exports.append({
          "name": exp.name,
          "address": self.pe.OPTIONAL_HEADER.ImageBase + exp.address,
          "ordinal": exp.ordinal
        })
    if 'exports' not in self.report.static:
      self.report.static.exports = None

  def get_imports(self):
    if self.config.signatures.api and is_file(self.config.signatures.api):
      sigapis = file_json_open(self.config.signatures.api)
    else:
      sigapis = None
    if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
      self.report.static.imports = []
      for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
        entrylist = []
        for api in entry.imports:
          if (api.name != None) and (api.name != ""):
            name = api.name
            address = api.address
            ordinal = api.ordinal
            description = None
            apitype = None
            if sigapis:
              for sigapi in sigapis.keys():
                if api.name.startswith(sigapi):
                  description = sigapis[sigapi]["description"]
                  apitype = sigapis[sigapi]["type"]
                  break
            entrylist.append({
              "name": name,
              "address": address,
              "ordinal": ordinal,
              "description": description,
              "type": apitype
            })
        self.report.static.imports.append({
          entry.dll: entrylist
        })
    if 'imports' not in self.report.static:
      self.report.static.imports = None

  def get_overlay(self):
    # http://reverseengineering.stackexchange.com/questions/2014/how-can-one-extract-the-appended-data-of-a-portable-executable
    offset = self.pe.get_overlay_data_start_offset()
    if offset:
      self.report.static.overlay = objdict({})
      self.report.static.overlay.offset = self.pe.get_overlay_data_start_offset()
      self.report.static.overlay.size = len(self.pe.write()[self.report.static.overlay.offset:])
      self.report.static.overlay.magic = data_magic(self.pe.write()[self.report.static.overlay.offset:])
      self.report.static.overlay.mimetype = data_mimetype(self.pe.write()[self.report.static.overlay.offset:])
      self.report.static.overlay.hashes = objdict({})
      self.report.static.overlay.hashes.md5 = data_hashes(self.pe.write()[self.report.static.overlay.offset:], "md5")
      self.report.static.overlay.hashes.sha256 = data_hashes(self.pe.write()[self.report.static.overlay.offset:], "sha256")
      self.report.static.overlay.hashes.ssdeep = data_hashes(self.pe.write()[self.report.static.overlay.offset:], "ssdeep")
    else:
      self.report.static.overlay = None

  # http://malware-crawler.googlecode.com/svn-history/r13/MalwareCrawler/src/processing/all_info.py
  def get_pehash(self):
    try:
      #image characteristics
      img_chars = bitstring.BitArray(hex(self.pe.FILE_HEADER.Characteristics))
      #pad to 16 bits

      # fix for PE32+ binaries: https://gist.github.com/wxsBSD/3a940333aede72b3c4d3
      if len(img_chars) == 8:
        img_chars = bitstring.BitArray('0b00000000') + img_chars

      img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
      img_chars_xor = img_chars[0:8] ^ img_chars[8:16]

      #start to build pehash
      pehash_bin = bitstring.BitArray(img_chars_xor)

      #subsystem
      sub_chars = bitstring.BitArray(hex(self.pe.FILE_HEADER.Machine))
      #pad to 16 bits
      sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
      sub_chars_xor = sub_chars[0:8] ^ sub_chars[8:16]
      pehash_bin.append(sub_chars_xor)

      #Stack Commit Size
      stk_size = bitstring.BitArray(hex(self.pe.OPTIONAL_HEADER.SizeOfStackCommit))
      stk_size_bits = string.zfill(stk_size.bin, 32)
      #now xor the bits
      stk_size = bitstring.BitArray(bin=stk_size_bits)
      stk_size_xor = stk_size[8:16] ^ stk_size[16:24] ^ stk_size[24:32]
      #pad to 8 bits
      stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
      pehash_bin.append(stk_size_xor)

      #Heap Commit Size
      hp_size = bitstring.BitArray(hex(self.pe.OPTIONAL_HEADER.SizeOfHeapCommit))
      hp_size_bits = string.zfill(hp_size.bin, 32)
      #now xor the bits
      hp_size = bitstring.BitArray(bin=hp_size_bits)
      hp_size_xor = hp_size[8:16] ^ hp_size[16:24] ^ hp_size[24:32]
      #pad to 8 bits
      hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
      pehash_bin.append(hp_size_xor)

      #Section chars
      for section in self.pe.sections:
        #virutal address
        sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
        sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
        sect_va_bits = sect_va[8:32]
        pehash_bin.append(sect_va_bits)

        #rawsize
        sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
        sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
        sect_rs_bits = string.zfill(sect_rs.bin, 32)
        sect_rs = bitstring.BitArray(bin=sect_rs_bits)
        sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
        sect_rs_bits = sect_rs[8:32]
        pehash_bin.append(sect_rs_bits)

        #section chars
        sect_chars =  bitstring.BitArray(hex(section.Characteristics))
        sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
        sect_chars_xor = sect_chars[16:24] ^ sect_chars[24:32]
        pehash_bin.append(sect_chars_xor)

        #entropy calulation
        address = section.VirtualAddress
        size = section.SizeOfRawData
        raw = self.pe.write()[address+size:]
        if size == 0:
          kolmog = bitstring.BitArray(float=1, length=32)
          pehash_bin.append(kolmog[0:8])
          continue
        bz2_raw = bz2.compress(raw)
        bz2_size = len(bz2_raw)
        #k = round(bz2_size / size, 5)
        k = bz2_size / size
        kolmog = bitstring.BitArray(float=k, length=32)
        pehash_bin.append(kolmog[0:8])

      m = hashlib.sha1()
      m.update(pehash_bin.tobytes())

      return m.hexdigest()

    except Exception as ex:
      self.report.hashes.pehash = None
      warn("Could not calculate PEHash: %s" % ex)


  # mastiff: EXE-sig.py plugin
  def get_resources(self):
    self.report.static.resources = []
    if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
      for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource_type.name is not None:
          name = "%s" % resource_type.name
        else:
          name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
        if name == None:
          name = "%d" % resource_type.struct.Id
        if hasattr(resource_type, 'directory'):
          for resource_id in resource_type.directory.entries:
            if hasattr(resource_id, 'directory'):
              for resource_lang in resource_id.directory.entries:
                if len(self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)) > 0:
                  self.report.static.resources.append({
                    "name": name,
                    "filetype": data_mimetype(self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)),
                    "lang": pefile.LANG.get(resource_lang.data.lang, '*unknown*'),
                    "sublang": pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang),
                    "OffsetToData": resource_lang.data.struct.OffsetToData,
                    "Size": resource_lang.data.struct.Size,
                    "hashes": objdict({
                      "md5": data_hashes(self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size), "md5"),
                      "sha256": data_hashes(self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size), "sha256"),
                      "ssdeep": data_hashes(self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size), "ssdeep")
                    })
                  })

  # http://stackoverflow.com/questions/17195924/python-equivalent-of-unix-strings-utility
  def get_strings(self, N=4):
    with open(self.config.filename, "rb") as f:
      self.report.static.strings.ascii = []
      filedata = f.read()
      for match in re.finditer(r"([\x20-\x7e]{%d,})" % N, filedata):
        start = match.start()
        end = match.end()
        size = end - start
        data = filedata[start:end]
        secname = ''.join([c for c in self.pe.get_section_by_offset(start).Name if c in string.printable]) if self.pe.get_section_by_offset(start) else None
        self.report.static.strings.ascii.append({
          "string": data,
          "offset": start,
          "size": size,
          "section": secname
        })
    with open(self.config.filename, "rb") as f:
      self.report.static.strings.unicode = []
      filedata = f.read()
      for match in re.finditer(ur'(?:[\x20-\x7E][\x00]){%d,}' % N, filedata):
        start = match.start()
        end = match.end()
        size = end - start
        data = filedata[start:end]
        secname = self.pe.get_section_by_offset(start).Name.replace('\x00', '') if self.pe.get_section_by_offset(start) else None
        self.report.static.strings.unicode.append({
          "string": data.decode('utf-16le'),
          "offset": start,
          "size": len(data.decode('utf-16le')),
          "section": secname
        })

  def get_tls(self):
    if (hasattr(self.pe, 'DIRECTORY_ENTRY_TLS') and \
    self.pe.DIRECTORY_ENTRY_TLS and \
    self.pe.DIRECTORY_ENTRY_TLS.struct and \
    self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
      self.report.static.tls = []
      callback_array_rva = self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - self.pe.OPTIONAL_HEADER.ImageBase
      idx = 0
      while True:
        func = self.pe.get_dword_from_data(self.pe.get_data(callback_array_rva + 4 * idx, 4), 0)
        if func == 0:
          break
        self.report.static.tls.append(func)
        idx += 1
    else:
      self.report.static.tls = None

  def scan_adobemalwareclassifier(self):
    self.report.scan.adobemalwareclassifier = objdict({})
    DebugSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 6 else None
    ImageVersion = ((self.pe.OPTIONAL_HEADER.MajorImageVersion*100)+self.pe.OPTIONAL_HEADER.MinorImageVersion)*1000
    IatRVA = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 1 else None
    ExportSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 0 else None
    ResourceSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 2 else None
    VirtualSize = self.pe.sections[1].Misc_VirtualSize if len(self.pe.sections) > 1 else None
    NumberOfSections = self.pe.FILE_HEADER.NumberOfSections
    self.report.scan.adobemalwareclassifier.J48 = "SUSPICIOUS" if run_J48(DebugSize, ImageVersion, IatRVA, ExportSize, ResourceSize, VirtualSize, NumberOfSections) else "CLEAN"
    self.report.scan.adobemalwareclassifier.J48Graft = "SUSPICIOUS" if run_J48Graft(DebugSize, ImageVersion, IatRVA, ExportSize, ResourceSize, VirtualSize, NumberOfSections) else "CLEAN"
    self.report.scan.adobemalwareclassifier.PART = "SUSPICIOUS" if run_PART(DebugSize, ImageVersion, IatRVA, ExportSize, ResourceSize, VirtualSize, NumberOfSections) else "CLEAN"
    self.report.scan.adobemalwareclassifier.Ridor = "SUSPICIOUS" if run_Ridor(DebugSize, ImageVersion, IatRVA, ExportSize, ResourceSize, VirtualSize, NumberOfSections) else "CLEAN"

  def scan_antivm(self):
    if not self.config.signatures.regexantivm or not is_file(self.config.signatures.regexantivm):
      return
    try:
      antivm = file_json_open(self.config.signatures.regexantivm)
      with open(self.config.filename, 'rb') as f:
        data = f.read()
    except:
      self.report.scan.antivm = None
      return
    self.report.scan.antivm = []
    if antivm and data:
      for entry in antivm.keys():
        # json doesn't allow raw hex escaped sequences
        # ugly hack to replace \\ with a \ as an alternative
        match = re.match(antivm[entry]["pattern"].replace('\\\\', '\\'), data)
        if match:
          if self.report.indicators.flags:
            self.report.indicators.flags.antivm = True
          else:
            self.report.indicators.flags = objdict({})
            self.report.indicators.flags.antivm = True
          self.report.scan.antivm.append({
            "name": entry,
            "description": antivm[entry]["description"],
            "score": antivm[entry]["score"],
            "start": match.start(),
            "end": match.end()
          })
    else:
      self.report.scan.antivm = None

  def scan_entrypoint(self):
    self.report.scan.entrypoint = objdict({})
    self.report.scan.entrypoint.rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    self.report.scan.entrypoint.va = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint + self.pe.OPTIONAL_HEADER.ImageBase
    self.report.scan.entrypoint.disassembly = ("")
    N = 100
    offset = 0
    memimage = self.pe.get_memory_mapped_image()[self.report.scan.entrypoint.rva:self.report.scan.entrypoint.rva+N]
    while offset < len(memimage):
      i = pydasm.get_instruction(memimage[offset:], pydasm.MODE_32)
      if i:
        self.report.scan.entrypoint.disassembly += "\n%d    %s" % (offset, pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, self.report.scan.entrypoint.va+offset))
        offset += i.length
      else:
        #self.report.scan.entrypoint.disassembly += "\n[COULD_NOT_DISASSEMBLE_FURTHER]"
        break

  def scan_exiftool(self):
    try:
      exifresult = exiftool(self.config.filename)
      if exifresult:
        self.report.scan.exiftool = exifresult
      else:
        self.report.scan.exiftool = None
    except IOError as io:
      self.report.scan.exiftool = None
    except Exception as ex:
      self.report.scan.exiftool = None

  def scan_mutex(self):
    if not self.config.signatures.mutexes or not is_file(self.config.signatures.mutexes):
      return
    with open(self.config.signatures.mutexes, 'r') as f:
      mutex_data = f.read()
    # regex to read mutexes from "santas bag of mutants" file
    mutexes = re.compile(r'^([A-Z][^\s]+)\s*([^\r]+)\r$', re.MULTILINE|re.IGNORECASE).findall(mutex_data)
    self.report.scan.mutex = []
    imports = []
    if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
      for lib in self.pe.DIRECTORY_ENTRY_IMPORT:
        for imp in lib.imports:
          if (imp.name != None) and (imp.name != ""):
            imports.append(imp.name)
    strings = []
    if hasattr(self.report.static, "strings") and self.report.static.strings.ascii:
      for s in self.report.static.strings.ascii:
        strings.append(s["string"])
    for mutex in mutexes:
      # if mutex name is not one of the imported apis and
      # if mutex name is present in the ascii strings output then
      # we have a hit!
      if mutex[1] not in imports and mutex[1] in strings:
        self.report.scan.mutex.append({
          "value": mutex[1],
          "threat": mutex[0]
        })

  def scan_online(self):
    if not self.config.enableonlinelookup:
      return
    online = OnlineLookup(self.config.filename)
    # if online not inititalized, skip lookup
    if online.config and online.lookuplist:
      self.report.scan.online = objdict({})
      for lookup in online.lookuplist:
        self.report.scan.online[lookup] = None
      if not self.config.enableonlinelookup:
        info("Initiating online lookup (this might take time)")
        self.report.scan.online = online.lookup()
    else:
      self.report.scan.online = None

  def scan_regex(self):
    if not self.config.signatures.regex or not is_file(self.config.signatures.regex):
      return
    try:
      regexes = file_json_open(self.config.signatures.regex)
      with open(self.config.filename, 'rb') as f:
        data = f.read()
    except:
      self.report.scan.regex = None
      return
    self.report.scan.regex = []
    if regexes and data:
      for entry in regexes.keys():
        match = re.match(r"%s" % (regexes[entry]["pattern"]), data, re.DOTALL|re.MULTILINE|re.UNICODE)
        if match:
          self.report.scan.regex.append({
            "name": entry,
            "description": regexes[entry]["description"],
            "score": regexes[entry]["score"],
            "start": match.start(),
            "end": match.end()
          })
    else:
      self.report.scan.regex = None

  def scan_shellcode(self):
    with open(self.config.filename, 'rb') as f:
      data = f.read()
    e = pylibemu.Emulator()
    offset = e.shellcode_getpc_test(data)
    e.test()
    profile = e.emu_profile_output
    if profile: # shellcode found!
      self.report.scan.shellcode = objdict({})
      self.report.scan.shellcode.offset = offset
      self.report.scan.shellcode.profile = profile
    else:
      self.report.scan.shellcode = None

  # http://handlers.sans.org/jclausing/packerid.py
  def scan_userdb(self):
    if not self.config.signatures.userdb or not is_file(self.config.signatures.userdb):
      return
    matches = peutils.SignatureDatabase(self.config.signatures.userdb).match_all(pefile.PE(self.config.filename), ep_only=True)
    if matches:
      self.report.scan.userdb = matches
    else:
      self.report.scan.userdb = None

  def scan_whitelist(self):
    self.report.scan.whitelist = objdict({})
    self.report.scan.whitelist.mandiant = None
    self.report.scan.whitelist.nsrl = None
    if not hasattr(self.report, "hashes") or not self.report.hashes.md5:
      return
    for source in self.report.scan.whitelist.keys():
      if self.config.signatures[source] and is_file(self.config.signatures[source].hashfile):
        filterobj = BloomFilter(datafile=self.config.signatures[source].hashfile, filterfile=self.config.signatures[source].bloomfilterfile)
        if is_file(self.config.signatures[source].bloomfilterfile):
          filterobj.load_from_file()
        else:
          filterobj.add_to_filter()
          filterobj.save_to_file()
        self.report.scan.whitelist[source] = True if filterobj.search_filter(self.report.hashes.md5) else False
        # don't wait for GC to free this object
        del filterobj

  def scan_xor(self):
    self.report.scan.xor = objdict({})
    self.report.scan.xor.xored, self.report.scan.xor.scan = file_xor_search(self.config.filename)

  def scan_yara(self):
    if not self.config.signatures.yara or not is_file(self.config.signatures.yara):
      return

    self.report.scan.yara = objdict({})
    try:
      matches = yara.compile(self.config.signatures.yara).match(self.config.filename)
      for match in matches:
        self.report.scan.yara[match.rule] = objdict({})
        self.report.scan.yara[match.rule].meta = match.meta
        self.report.scan.yara[match.rule].namespace = match.namespace
        self.report.scan.yara[match.rule].tags = match.tags
    except yara.SyntaxError as ex:
      warn("Could not scan with yara: %s" % ex)

  def pe_meta(self):
    # calculate generic hashes: md5, sha256
    info("Invoking metadata collection")
    self.report.hashes = objdict({})
    self.report.hashes.md5 = file_hashes(self.config.filename, 'md5')
    self.report.hashes.sha256 = file_hashes(self.config.filename, 'sha256')

  def pe_parse(self):
    # calculate pe format specific hashes and parse the file
    info("Invoking PE parser")
    self.report.static.hashes.imphash = self.pe.get_imphash()
    self.report.static.hashes.pehash = self.get_pehash()
    if self.config.enableentropycompressionstats:
      stats = objdict(file_entropy_compression_stats(self.config.filename))
      entropy = float(stats.entropy)
      # Entropy:        Range
      # Text:           4.401-5.030
      # Native:         6.084-6.369
      # Packed:         7.199-7.267
      # Compressed:     7.295-7.312
      # Encrypted:      7.6-8.0
      if entropy >= 7.6 and entropy <= 8.0:
        self.report.static.entropycategory = 'ENCRYPTED'
      elif entropy >= 7.295 and entropy <= 7.312:
        self.report.static.entropycategory = 'COMPRESSED'
      elif entropy >= 7.199 and entropy <= 7.267:
        self.report.static.entropycategory = 'PACKED'
      elif entropy >= 6.084 and entropy <= 6.369:
        self.report.static.entropycategory = 'NATIVEXECUTABLE'
      elif entropy >= 4.401 and entropy <= 5.030:
        self.report.static.entropycategory = 'TEXT'
      elif entropy > 0.0 and entropy < 1.0:
        self.report.static.entropycategory = 'SUSPICIOUS'
      else:
        self.report.static.entropycategory = 'UNKNOWN'
    else:
      self.report.static.entropycategory = 'UNKNOWN'

    self.get_dosheader()
    self.get_ntheader()
    self.get_NETversion()
    self.get_authenticode()
    self.get_exports()
    self.get_imports()
    self.get_debug()
    self.get_overlay()
    self.get_resources()
    self.get_strings()
    self.get_tls()
    self.get_manifest()
    self.get_versioninfo()
    self.get_relocations()

  def pe_dynamic(self):
    if self.config.cuckooreport and is_file(self.config.cuckooreport):
      try:
        cuckooreport = file_json_open(self.config.cuckooreport)
        if cuckooreport and "behavior" in cuckooreport:
          if "dns" in cuckooreport["behavior"]:
            if not self.report.dynamic.dns:
              self.report.dynamic.dns = list()
            for entry in cuckooreport["behavior"]["dns"]:
              self.report.dynamic.dns.append(objdict({
                "dst": entry
              }))
            for entry in self.report.dynamic.dns:
              for key in ["dst", "dport", "timestamp", "process", "pid", "operation", "result", "details"]:
                if key not in entry:
                  entry[key] = None
          if "network" in cuckooreport["behavior"]:
            if not self.report.dynamic.network:
              self.report.dynamic.network = list()
            for entry in cuckooreport["behavior"]["network"]:
              self.report.dynamic.network.append(objdict({
                "dst": entry
              }))
            for entry in self.report.dynamic.network:
              for key in ["dst", "dport", "timestamp", "process", "pid", "operation", "result", "details"]:
                if key not in entry:
                  entry[key] = None
          if "library" in cuckooreport["behavior"] and "load" in cuckooreport["behavior"]["library"]:
            if len(cuckooreport["behavior"]["library"]["load"]):
              if self.report.dynamic.loaddlls:
                self.report.dynamic.loaddlls += cuckooreport["behavior"]["library"]["load"]
              else:
                self.report.dynamic.loaddlls = cuckooreport["behavior"]["library"]["load"]
          if "process" in cuckooreport["behavior"]:
            if len(cuckooreport["behavior"]["process"]):
              if self.report.dynamic.process:
                self.report.dynamic.process += cuckooreport["behavior"]["process"]
              else:
                self.report.dynamic.process = cuckooreport["behavior"]["process"]
              for entry in self.report.dynamic.process:
                for key in ["name", "timestamp", "process", "pid", "operation", "result", "details"]:
                  if key not in entry:
                    entry[key] = None
          if "registry" in cuckooreport["behavior"]:
            if len(cuckooreport["behavior"]["registry"]["read"]):
              if self.report.dynamic.registry.read:
                self.report.dynamic.registry.read += cuckooreport["behavior"]["registry"]["read"]
              else:
                self.report.dynamic.registry.read = cuckooreport["behavior"]["registry"]["read"]
              for entry in self.report.dynamic.registry.read:
                for key in ["name", "timestamp", "process", "pid", "operation", "result", "details"]:
                  if key not in entry:
                    entry[key] = None
            if len(cuckooreport["behavior"]["registry"]["write"]):
              if self.report.dynamic.registry.write:
                self.report.dynamic.registry.write += cuckooreport["behavior"]["registry"]["write"]
              else:
                self.report.dynamic.registry.write = cuckooreport["behavior"]["registry"]["write"]
              for entry in self.report.dynamic.registry.write:
                for key in ["name", "timestamp", "process", "pid", "operation", "result", "details"]:
                  if key not in entry:
                    entry[key] = None
          if "filesystem" in cuckooreport["behavior"]:
            if len(cuckooreport["behavior"]["filesystem"]["read"]):
              if self.report.dynamic.filesystem.read:
                self.report.dynamic.filesystem.read += cuckooreport["behavior"]["filesystem"]["read"]
              else:
                self.report.dynamic.filesystem.read = cuckooreport["behavior"]["filesystem"]["read"]
              for entry in self.report.dynamic.filesystem.read:
                for key in ["name", "timestamp", "process", "pid", "operation", "result", "details"]:
                  if key not in entry:
                    entry[key] = None
            if len(cuckooreport["behavior"]["filesystem"]["write"]):
              if self.report.dynamic.filesystem.write:
                self.report.dynamic.filesystem.write += cuckooreport["behavior"]["filesystem"]["write"]
              else:
                self.report.dynamic.filesystem.write = cuckooreport["behavior"]["filesystem"]["write"]
              for entry in self.report.dynamic.filesystem.write:
                for key in ["name", "timestamp", "process", "pid", "operation", "result", "details"]:
                  if key not in entry:
                    entry[key] = None
            if len(cuckooreport["behavior"]["filesystem"]["move"]):
              if self.report.dynamic.filesystem.move:
                self.report.dynamic.filesystem.move += cuckooreport["behavior"]["filesystem"]["move"]
              else:
                self.report.dynamic.filesystem.move = cuckooreport["behavior"]["filesystem"]["move"]
              for entry in self.report.dynamic.filesystem.move:
                for key in ["name", "timestamp", "process", "pid", "operation", "result", "details"]:
                  if key not in entry:
                    entry[key] = None
            if len(cuckooreport["attachment"]):
              if self.report.dynamic.filesystem.dropped:
                self.report.dynamic.filesystem.dropped += cuckooreport["attachment"]
              else:
                self.report.dynamic.filesystem.dropped = cuckooreport["attachment"]
              for entry in self.report.dynamic.filesystem.dropped:
                if "attachid" in entry:
                  del entry["attachid"]
      except Exception as ex:
        pass

    if self.config.noribenreport and is_file(self.config.noribenreport):
      try:
        if not is_file(self.config.noribenreport):
          return
        with open(self.config.noribenreport, 'r') as fo:
          noribenreport = fo.readlines()

        for line in noribenreport[1:]:
          if len(line.strip().replace("\",\"", "\"|").replace("\"", "").split("|")) == 7:
            csv = line.strip().replace("\",\"", "\"|\"").replace("\"", "").split("|")
            timestamp = csv[0]
            procname = csv[1]
            pid = int(csv[2])
            operation = csv[3]
            path = csv[4]
            result = csv[5]
            details = csv[6]
            if operation in ["WriteFile"]:
              if self.report.dynamic.filesystem.write:
                self.report.dynamic.filesystem.write.append(objdict({
                  "name": path,
                  "timestamp": timestamp,
                  "process": procname,
                  "pid": pid,
                  "operation": operation,
                  "result": result,
                  "details": details
                }))
              else:
                self.report.dynamic.filesystem.write = [objdict({
                  "name": path,
                  "timestamp": timestamp,
                  "process": procname,
                  "pid": pid,
                  "operation": operation,
                  "result": result,
                  "details": details
                })]
            if operation in ["RegSetValue"]:
              if self.report.dynamic.registry.write:
                self.report.dynamic.registry.write.append(objdict({
                  "name": path,
                  "timestamp": timestamp,
                  "value": None,
                  "process": procname,
                  "pid": pid,
                  "operation": operation,
                  "result": result,
                  "details": details
                }))
              else:
                self.report.dynamic.registry.write = [objdict({
                  "name": path,
                  "timestamp": timestamp,
                  "value": None,
                  "process": procname,
                  "pid": pid,
                  "operation": operation,
                  "result": result,
                  "details": details
                })]
            if operation in ["TCP Receive", "TCP Disconnect", "TCP Reconnect", "TCP Send"]:
              # extract dst and dport from noriben csv path entry (#4)
              dst, dport = path.split(" ")[2].split(":")
              # replace protonames with respective port
              # inspired from https://github.com/Rurik/Noriben/blob/master/Noriben.py#L586-L600
              portmappings = [("443", "https"), ("80", "http")]
              for port, proto in portmappings:
                dport = dport.replace(proto, port)
              # ignore dst with localhost/127.*
              match = re.search(r"(localhost|127\.*)", dst, re.IGNORECASE)
              if match:
                continue
              if self.report.dynamic.network:
                self.report.dynamic.network.append(objdict({
                  "dst": dst,
                  "dport": int(dport),
                  "timestamp": timestamp,
                  "value": None,
                  "process": procname,
                  "pid": pid,
                  "operation": operation,
                  "result": result,
                  "details": details
                }))
              else:
                self.report.dynamic.network = [objdict({
                  "dst": dst,
                  "dport": int(dport),
                  "timestamp": timestamp,
                  "value": None,
                  "process": procname,
                  "pid": pid,
                  "operation": operation,
                  "result": result,
                  "details": details
                })]
            if operation in ["UDP Send", "UDP Receive"]:
              # extract dst and dport from noriben csv path entry (#4)
              dst, dport = path.split(" ")[2].split(":")
              # replace protonames with respective port
              # inspired from https://github.com/Rurik/Noriben/blob/master/Noriben.py#L586-L600
              portmappings = [("53", "domain")]
              for port, proto in portmappings:
                dport = dport.replace(proto, port)
              # ignore dst with localhost/127.*
              match = re.search(r"(localhost|127\.*)", dst, re.IGNORECASE)
              if match:
                continue
              if self.report.dynamic.network:
                self.report.dynamic.network.append(objdict({
                  "dst": dst,
                  "dport": int(dport),
                  "timestamp": timestamp,
                  "value": None,
                  "process": procname,
                  "pid": pid,
                  "operation": operation,
                  "result": result,
                  "details": details
                }))
              else:
                self.report.dynamic.network = [objdict({
                  "dst": dst,
                  "dport": int(dport),
                  "timestamp": timestamp,
                  "value": None,
                  "process": procname,
                  "pid": pid,
                  "operation": operation,
                  "result": result,
                  "details": details
                })]
            if operation in ["Process Start", "Process Exit", "Process Create"]:
              if self.report.dynamic.process:
                self.report.dynamic.process.append(objdict({
                  "name": path,
                  "timestamp": timestamp,
                  "value": None,
                  "process": procname,
                  "pid": pid,
                  "operation": operation,
                  "result": result,
                  "details": details
                }))
              else:
                self.report.dynamic.process = [objdict({
                  "name": path,
                  "timestamp": timestamp,
                  "value": None,
                  "process": procname,
                  "pid": pid,
                  "operation": operation,
                  "result": result,
                  "details": details
                })]
      except Exception as ex:
        print ex
        pass

  # wrapper over get_* and scan_* functions
  def pe_scan(self):
    info("Initiating scanning on raw and parsed PE fields")
    self.scan_adobemalwareclassifier()
    self.scan_antivm()
    self.scan_entrypoint()
    self.scan_mutex()
    self.scan_regex()
    self.scan_shellcode()
    self.scan_userdb()
    self.scan_whitelist()
    self.scan_xor()
    self.scan_yara()
    self.scan_online()

  # populate indicators
  def pe_indicators(self):
    info("Identifying suspicious indicators")
    self.report.indicators.flags = objdict({})
    self.report.indicators.flags.Bit32 = self.pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE
    self.report.indicators.flags.DLL = True if self.pe.FILE_HEADER.IMAGE_FILE_DLL else False
    self.report.indicators.flags.Executable = True if self.pe.FILE_HEADER.IMAGE_FILE_EXECUTABLE_IMAGE else False
    self.report.indicators.flags.Driver = True if self.pe.is_driver() else False
    self.report.indicators.flags.System = True if self.pe.FILE_HEADER.IMAGE_FILE_SYSTEM else False
    self.report.indicators.flags.DebugStripped = True if self.pe.FILE_HEADER.IMAGE_FILE_DEBUG_STRIPPED else False
    self.report.indicators.flags.RelocStripped = True if self.pe.FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED else False

    # http://reverseengineering.stackexchange.com/questions/9293/how-use-pefile-to-check-for-nx-aslr-safeseh-and-cfg-control-flow-guard-flag
    self.report.indicators.flags.NXCompatible = True if self.pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT else False
    self.report.indicators.flags.ASLR = True if self.pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE else False
    self.report.indicators.flags.ControlFlowGuard = True if self.pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF else False
    self.report.indicators.flags.ForceIntegrity = True if self.pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY else False
    self.report.indicators.flags.SafeSEH = True if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 10 and self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[10].name == 'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG' and self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[10].VirtualAddress != 0 and self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[10].Size != 0 else False
    self.report.indicators.flags.SEH = False if self.pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH else True
    self.report.indicators.flags.Signed = True if 'authenticode' in self.report.static.keys() and self.report.static.authenticode else False

    # http://www.codeguru.com/cpp/w-p/dll/openfaq/article.php/c14001/Determining-Whether-a-DLL-or-EXE-Is-a-Managed-Component.htm
    # http://stackoverflow.com/questions/1366503/best-way-to-check-if-a-dll-file-is-a-clr-assembly-in-c-sharp
    self.report.indicators.flags.Managed = True if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 and self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].name == 'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR' and self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0 else False
    self.report.indicators.flags.Native = not self.report.indicators.flags.Managed

    self.report.indicators.flags.Suspicious = True if peutils.is_suspicious(self.pe) else False
    self.report.indicators.flags.Packed = peutils.is_probably_packed(self.pe)

    warnings = self.pe.get_warnings()
    if len(warnings):
      self.report.indicators.warnings = warnings

    self.report.indicators.checks = objdict({})

    # sizeofrawdata pointers should form an non-breaking list
    self.report.indicators.checks.SectionPointers = objdict({})
    self.report.indicators.checks.SectionPointers.classification = "CLEAN"
    self.report.indicators.checks.SectionPointers.reason = 'Section pointers form a non-breaking list'
    sectioncount = self.pe.FILE_HEADER.NumberOfSections
    # a file could claim to have more than available sections, so beware
    if self.pe.FILE_HEADER.NumberOfSections > 1 and (self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections)):
      for i in range(0, sectioncount-1):
        nextp = self.pe.sections[i].SizeOfRawData + self.pe.sections[i].PointerToRawData
        currp = self.pe.sections[i+1].PointerToRawData
        if nextp != currp:
          currsecname = ''.join([c for c in self.pe.sections[i].Name if c in string.printable])
          nextsecname = ''.join([c for c in self.pe.sections[i+1].Name if c in string.printable])
          self.report.indicators.checks.SectionPointers.classification = "SUSPICIOUS"
          self.report.indicators.checks.SectionPointers.reason = 'Section pointers list is broken (section[%d].nextp:0x%08x [%s] != section[%d].currp:0x%08x [%s])' % (i, nextp, currsecname, i+1, currp, nextsecname)
          break

    # section name has nonascii characters or is empty
    self.report.indicators.checks.SectionNames = objdict({})
    self.report.indicators.checks.SectionNames.classification = "CLEAN"
    self.report.indicators.checks.SectionNames.reason = "Section names are non-empty and contain ascii-only characters"
    for idx, sec in enumerate(self.pe.sections):
      if not re.match("^[.A-Za-z][a-zA-Z]+", sec.Name):
        self.report.indicators.checks.SectionNames.classification = "SUSPICIOUS"
        self.report.indicators.checks.SectionNames.reason = "Section %d has a suspicious name: \"%s\" (Failed non-empty && ascii-only check)" % (idx, sec.Name)

    # sptional header size should be 224B
    self.report.indicators.checks.SizeOfOptionalHeader = objdict({})
    self.report.indicators.checks.SizeOfOptionalHeader.classification = "CLEAN"
    self.report.indicators.checks.SizeOfOptionalHeader.reason = "SizeOfOptionalHeader is correct (%dB)" % (self.pe.FILE_HEADER.SizeOfOptionalHeader)
    if self.pe.FILE_HEADER.SizeOfOptionalHeader != 224:
      self.report.indicators.checks.SizeOfOptionalHeader.classification = "SUSPICIOUS"
      self.report.indicators.checks.SizeOfOptionalHeader.reason = "SizeOfOptionalHeader seems suspicious (actual size %dB != expected size 224B)" % (self.pe.FILE_HEADER.SizeOfOptionalHeader)

    # checksum should be non-zero
    self.report.indicators.checks.ChecksumNonZero = objdict({})
    self.report.indicators.checks.ChecksumNonZero.classification = "CLEAN"
    self.report.indicators.checks.ChecksumNonZero.reason = "Image checksum is non-zero (%d)" % (self.pe.OPTIONAL_HEADER.CheckSum)
    if self.pe.OPTIONAL_HEADER.CheckSum == 0:
      self.report.indicators.checks.ChecksumNonZero.classification = "SUSPICIOUS"
      self.report.indicators.checks.ChecksumNonZero.reason = "Image checksum should be non-zero"

    # actual checksum should be equal to claimed
    self.report.indicators.checks.ChecksumInvalid = objdict({})
    self.report.indicators.checks.ChecksumInvalid.classification = "CLEAN"
    self.report.indicators.checks.ChecksumInvalid.reason = "Actual image checksum: %d == claimed image checksum: %d" % (self.pe.generate_checksum(), self.pe.OPTIONAL_HEADER.CheckSum)
    if self.pe.OPTIONAL_HEADER.CheckSum != self.pe.generate_checksum() and not self.pe.verify_checksum():
      self.report.indicators.checks.ChecksumInvalid.classification = "SUSPICIOUS"
      self.report.indicators.checks.ChecksumInvalid.reason = "Actual image checksum: %d != claimed image checksum: %d" % (self.pe.generate_checksum(), self.pe.OPTIONAL_HEADER.CheckSum)

    # count of data directories should be 16
    self.report.indicators.checks.NumberOfRVAAndSizes = objdict({})
    self.report.indicators.checks.NumberOfRVAAndSizes.classification = "CLEAN"
    self.report.indicators.checks.NumberOfRVAAndSizes.reason = "NumberOfRvaAndSizes, i.e count of data directories, is correct (%d)" % (self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
    if self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes != 16:
      self.report.indicators.checks.NumberOfRVAAndSizes.classification = "SUSPICIOUS"
      self.report.indicators.checks.NumberOfRVAAndSizes.reason = "NumberOfRvaAndSizes, i.e count of data directories, seems suspicious (actual count %d != expected count 16)" % (self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)

    # loaderflags should be 0
    self.report.indicators.checks.LoaderFlags = objdict({})
    self.report.indicators.checks.LoaderFlags.classification = "CLEAN"
    self.report.indicators.checks.LoaderFlags.reason = "LoaderFlags is zero"
    if self.pe.OPTIONAL_HEADER.LoaderFlags != 0:
      self.report.indicators.checks.LoaderFlags.classification = "SUSPICIOUS"
      self.report.indicators.checks.LoaderFlags.reason = "LoaderFlags seems suspicious (%d != 0)" % (self.pe.OPTIONAL_HEADER.LoaderFlags)

    # tls callback function(s) found
    self.report.indicators.checks.TLSCallback = objdict({})
    self.report.indicators.checks.TLSCallback.classification = "CLEAN"
    self.report.indicators.checks.TLSCallback.reason = "TLS callbacks not found"
    if hasattr(self.pe, "DIRECTORY_ENTRY_TLS"):
      self.report.indicators.checks.TLSCallback.classification = "SUSPICIOUS"
      self.report.indicators.checks.TLSCallback.reason = "TLS callbacks array found @ VA:0x%08x (RVA:0x%08x)" % (self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks, self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - self.pe.OPTIONAL_HEADER.ImageBase)

    # timestamp should be >= 1999 and <= currentyear
    try:
      first_year = 1999
      compile_year = time.gmtime(self.pe.FILE_HEADER.TimeDateStamp)[0]
      current_year = time.gmtime(time.time())[0]
      self.report.indicators.checks.Timestamp = objdict({})
      self.report.indicators.checks.Timestamp.classification = "CLEAN"
      if compile_year < first_year or compile_year > current_year:
        self.report.indicators.checks.Timestamp.classification = "SUSPICIOUS"
      self.report.indicators.checks.Timestamp.reason = "first_year:%d <= compile_year:%d <= current_year:%d" % (first_year, compile_year, current_year)
    except Exception as ex:
      self.report.indicators.checks.Timestamp = None

    # entrypoint should be in the first section
    self.report.indicators.checks.EntryPointNotInFirstSection = objdict({})
    self.report.indicators.checks.EntryPointNotInFirstSection.classification = "CLEAN"
    self.report.indicators.checks.EntryPointNotInFirstSection.reason = "Entrypoint is in the first section"
    #if len(self.pe.sections) > 0 and self.pe.OPTIONAL_HEADER.AddressOfEntryPoint > (self.pe.sections[0].VirtualAddress + self.pe.sections[0].Misc_VirtualSize):
    if len(self.pe.sections) > 0 and not self.pe.sections[0].contains_rva(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint):
      self.report.indicators.checks.EntryPointNotInFirstSection.classification = "SUSPICIOUS"
      self.report.indicators.checks.EntryPointNotInFirstSection.reason = "Entrypoint (0x%08x) is outside of the first section (size: 0x%08x)" % (self.pe.OPTIONAL_HEADER.AddressOfEntryPoint, self.pe.sections[0].VirtualAddress + self.pe.sections[0].Misc_VirtualSize)

    # entrypoint should be in a commonly used section
    # Malware Analyst's Cookbook - suspicious entrypoint sections if not one of the below
    # .text, .code for usermode programs
    # .INIT, .PAGE for kernel drivers
    epsections = ['.text', '.code', 'CODE', 'INIT', 'PAGE']
    self.report.indicators.checks.EntryPointInUncommonSection = objdict({})
    self.report.indicators.checks.EntryPointInUncommonSection.classification = "CLEAN"
    self.report.indicators.checks.EntryPointInUncommonSection.reason = "Entrypoint is in a common section"
    if self.pe.sections:
      for idx, sec in enumerate(self.pe.sections):
        if sec.contains_rva(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint):
          secname = ''.join([c for c in sec.Name if c in string.printable])
          if secname not in epsections:
            self.report.indicators.checks.EntryPointInUncommonSection.classification = "SUSPICIOUS"
            self.report.indicators.checks.EntryPointInUncommonSection.reason = "Entrypoint is in an uncommon section: %s" % secname
            break
          else:
            self.report.indicators.checks.EntryPointInUncommonSection.classification = "CLEAN"
            self.report.indicators.checks.EntryPointInUncommonSection.reason = "Entrypoint is in a common section: %s" % secname

    self.report.indicators.checks.combined = objdict({})

    # http://cobweb.cs.uga.edu/~liao/PE_Presentation.pdf
    #1 sizeof initialized data should be non-zero
    SizeOfInitializedDataIsZero = True if not self.pe.OPTIONAL_HEADER.SizeOfInitializedData else False

    #2 section names is not amongst those commonly used
    knownsections = file_json_open(self.config.signatures.knownsections)
    UnknownSectionNames = []
    for idx, section in enumerate(self.pe.sections):
      secname = ''.join([c for c in section.Name if c in string.printable])
      if secname not in knownsections.keys():
        UnknownSectionNames.append(self.report.static.ntheaders.sections[idx])

    #3 dll characteristics should be non-zero
    DLLCharacteristicsIsZero = True if not self.pe.OPTIONAL_HEADER.DllCharacteristics else False

    #4 majorimageversion should be non-zero
    MajorImageVersionIsZero = True if not self.pe.OPTIONAL_HEADER.MajorImageVersion else False

    #5 checksum should be non-zero
    ChecksumIsZero = True if not self.pe.generate_checksum() else False

    # 1,2,3 => TP:97.0%, FP:0.8%
    if SizeOfInitializedDataIsZero and len(UnknownSectionNames) and DLLCharacteristicsIsZero:
      self.report.indicators.checks.combined.classification = "SUSPICIOUS"
      self.report.indicators.checks.combined.reason = "SizeOfInitializedDataIsZero AND UnknownSectionNames AND DLLCharacteristicsIsZero"

    # 1,2,4,5 => TP:97.9%, FP:0.16%
    elif SizeOfInitializedDataIsZero and len(UnknownSectionNames) and MajorImageVersionIsZero and ChecksumIsZero:
      self.report.indicators.checks.combined.classification = "SUSPICIOUS"
      self.report.indicators.checks.combined.reason = "SizeOfInitializedDataIsZero AND UnknownSectionNames AND MajorImageVersionIsZero AND ChecksumIsZero"

    # 1,2,3,4 => TP:98.4%, FP:0.4%
    elif SizeOfInitializedDataIsZero and len(UnknownSectionNames) and DLLCharacteristicsIsZero and MajorImageVersionIsZero:
      self.report.indicators.checks.combined.classification = "SUSPICIOUS"
      self.report.indicators.checks.combined.reason = "SizeOfInitializedDataIsZero AND UnknownSectionNames AND DLLCharacteristicsIsZero AND MajorImageVersionIsZero"

    # 1,2,3,5 => TP:98.9%, FP:0.2%
    elif SizeOfInitializedDataIsZero and len(UnknownSectionNames) and DLLCharacteristicsIsZero and ChecksumIsZero:
      self.report.indicators.checks.combined.classification = "SUSPICIOUS"
      self.report.indicators.checks.combined.reason = "SizeOfInitializedDataIsZero AND UnknownSectionNames AND DLLCharacteristicsIsZero AND ChecksumIsZero"

    # 1,2,3,4,5 => TP:99.5%, FP:0.16%
    elif SizeOfInitializedDataIsZero and len(UnknownSectionNames) and DLLCharacteristicsIsZero and MajorImageVersionIsZero and ChecksumIsZero:
      self.report.indicators.checks.combined.classification = "SUSPICIOUS"
      self.report.indicators.checks.combined.reason = "SizeOfInitializedDataIsZero AND UnknownSectionNames AND DLLCharacteristicsIsZero AND MajorImageVersionIsZero AND ChecksumIsZero"

    # probably clean, decide via other scan results
    else:
      del self.report.indicators.checks.combined

  def analyze(self):
    self.pe_meta()
    if len(self.report.indicators.warnings) == 0:
      self.pe_parse()
      if self.config.cuckooreport or self.config.noribenreport:
        self.pe_dynamic()
      self.pe_scan()
      self.pe_indicators()

    # delete md5/sha256 from report as we will have them in filemeta section of report
    if hasattr(self.report, "hashes") and hasattr(self.report.hashes, "md5"):
      del self.report.hashes.md5
    if hasattr(self.report, "hashes") and hasattr(self.report.hashes, "sha256"):
      del self.report.hashes.sha256

    if hasattr(self.report, "hashes") and not (hasattr(self.report.hashes, "pehash") and hasattr(self.report.hashes, "imphash")):
      del self.report.hashes

    # done with analysis, normalize report and return
    self.report = dict_normalize(self.report)

