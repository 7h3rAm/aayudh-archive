# -*- coding: utf-8 -*-

import exiftool as ExifTool
from hachoir_metadata import metadata
from hachoir_parser import createParser
from hachoir_core.tools import humanFilesize
from hachoir_core.memory import limitedMemory
from hachoir_core.stream import FileInputStream
from hachoir_subfile.search import SearchSubfile
from hachoir_core.cmd_line import unicodeFilename

from cigma.cigma import Cigma
from utils import byte_freq, data_entropy_compression_stats, data_to_bmpimage, data_to_pngimage, unicode_to_string, data_hashes, warn

import os
import json
import math
import glob
import zlib
import array
import errno
import codecs
import pydeep
import signal
import fnmatch
import hashlib
import binascii
import collections
from functools import wraps

try:
  from cStringIO import StringIO
except:
  from StringIO import StringIO


# calculate entropy of a file
# http://www.kennethghartman.com/calculate-file-entropy/
def file_entropy_compression_stats(filename, precision=2):
  if filename and filename != "":
    file_handle = open(filename, "rb")
    # read the whole file into a byte array
    bytearr = map(ord, file_handle.read())
    file_handle.close()
    freqlist, filesizeinbytes = byte_freq(bytearr)
    # shannon entropy
    ent = 0.0
    for freq in freqlist:
      if freq > 0:
        ent = ent + freq * math.log(freq, 2)
    ent = -ent
    # minimum possible filesize after compression
    minfilesize = (ent * filesizeinbytes) / 8
    # compression efficiency
    sizediff = filesizeinbytes - minfilesize
    if sizediff > 0:
      compressionratio = (sizediff / filesizeinbytes) * 100
    else:
      compressionratio = 0
    entropy = float("{0:.2f}".format(ent))
    if entropy >= 7.6 and entropy <= 8.0:
      entropycategory = "ENCRYPTED"
    elif entropy >= 7.295 and entropy <= 7.267:
      entropycategory = "COMPRESSED"
    elif entropy >= 4.401 and entropy <= 5.030:
      entropycategory = "TEXT"
    elif entropy > 0.0 and entropy < 1.0:
      entropycategory = "SUSPICIOUS"
    else:
      entropycategory = "UNKNOWN"
    return dict({
      "bytefreqlist": freqlist,
      "filesizeinbytes": filesizeinbytes,
      "entropy": entropy,
      "entropycategory": entropycategory,
      "minfilesize": float("{0:.2f}".format(minfilesize)),
      "compressionratio": float("{0:.2f}".format(compressionratio))
    })


def file_to_bmpimage(filename, maxsize=180000):
  if filename and filename != "":
    bytes = ""
    with open(filename, "rb") as fd:
      while True:
        byteblock = fd.read(1024)
        if byteblock:
          bytes += byteblock
          if len(bytes) < maxsize:
            continue
        break
    return data_to_bmpimage(data=bytes)


# http://cmattoon.com/visual-binary-analysis-python/
# slightly modified to fit need
def file_to_pngimage(filename, width=256, maxsize=180000, enable_colors=True):
  if filename and filename != "":
    bytes = ""
    with open(filename, "rb") as fd:
      while True:
        byteblock = fd.read(1024)
        if byteblock:
          bytes += byteblock
          if len(bytes) < maxsize:
            continue
        break
    return data_to_pngimage(data=bytes, width=width, maxsize=maxsize, enable_colors=enable_colors)


def file_to_pdf(filename):
  if filename and filename != "":
    pdffile = "%s.pdf" % (os.path.basename(filename))
    pdffile = StringIO()
    pdfkit.from_file(filename, pdffile)
    print pdffile.getvalue()
    return None


def file_magic(filename):
  if filename and filename != "":
    return Cigma().identify(filename=filename)


def file_mimetype(filename):
  if filename and filename != "":
    result = Cigma().identify(filename=filename)
    return result["match"]["mimetype"] if result["match"] else None
    parser = createParser(unicodeFilename(filename), filename)
    return {"mimetype": str(parser.mime_type)} if parser else {"mimetype": "text/plain"}


def file_metadata(filename):
  if filename and filename != "":
    parser = createParser(unicodeFilename(filename), filename)
    meta = metadata.extractMetadata(parser) if parser else None
    metalist = meta.exportPlaintext() if meta else []
    meta = collections.defaultdict(collections.defaultdict)
    for item in metalist:
      if item.endswith(":"):
        k = item[:-1]
      else:
        tag, value = item.split(": ", 1)
        tag = tag[2:]
        meta[k][tag] = value
    return unicode_to_string(default_to_regular(meta))["Metadata"] if meta else {}


def file_subfiles(filename):
  if filename and filename != "":
    offset, size, memorylimit, filemaxsize = 0, 999999, 50*1024*1024, 100 * 1024 * 1024
    stream = FileInputStream(unicodeFilename(filename), real_filename=filename)
    subfile = SearchSubfile(stream, offset, size)
    try:
      subfile.loadParsers()
      subfile.stats = {}
      subfile.verbose = False
      subfile.next_offset = None
      subfiles = []
      while subfile.current_offset < subfile.size:
        _ = subfile.datarate.update(subfile.current_offset)
        for offset, parser in subfile.findMagic(subfile.current_offset):
          try:
            size = parser.content_size//8 if parser.content_size else None
          except Exception as ex:
            size = None
          try:
            description = parser.description if not(parser.content_size) or parser.content_size//8 < filemaxsize else parser.__class__.__name__
          except Exception as ex:
            description = None
          offset = offset//8
          # skip the first subfile
          # as its the original file itself
          if offset == 0:
            continue
          with open(filename, "rb") as fo:
            filedata = fo.read()
          mimetype = data_mimetype(filedata[offset:offset+size]) if offset > 0 and size and size > 0 else None
          md5 = data_hashes(filedata[offset:offset+size], "md5") if offset >= 0 and size > 0 else None
          sha256 = data_hashes(filedata[offset:offset+size], "sha256") if (offset or offset == 0) and size else None
          ssdeep = data_hashes(filedata[offset:offset+size], "ssdeep") if (offset or offset == 0) and size else None
          subfiles.append({
            "offset": offset,
            "size": size,
            "mimetype": mimetype,
            "description": description,
            "hashes": {
              "md5": md5,
              "sha256": sha256,
              "ssdeep": ssdeep
            }
          })
        subfile.current_offset += subfile.slice_size
        if subfile.next_offset:
          subfile.current_offset = max(subfile.current_offset, subfile.next_offset)
        subfile.current_offset = min(subfile.current_offset, subfile.size)
    except MemoryError:
      error("[!] Memory error!")
    return subfiles if subfiles and len(subfiles) else None


# http://stackoverflow.com/questions/2186525/use-a-glob-to-find-files-recursively-in-python
def file_search(search_dir="./", regex="*"):
  matches = []
  for root, dirnames, filenames in os.walk(search_dir):
    for filename in fnmatch.filter(filenames, regex):
      if os.path.exists(os.path.join(root, filename)):
        matches.append(os.path.join(root, filename))
  return matches


# http://stackoverflow.com/questions/2186525/use-a-glob-to-find-files-recursively-in-python
def file_list(directory, pattern="*.*", whitelist=None):
  if directory and directory != "":
    matches = []
    for root, dirnames, filenames in os.walk(directory):
      for filename in fnmatch.filter(filenames, pattern):
        if os.path.exists(os.path.join(root, filename)):
          # if file"s mimetype is in whitelist, append
          mimetype = file_mimetype(os.path.join(root, filename))
          if whitelist:
            if mimetype in whitelist:
              if os.path.join(root, filename) not in matches:
                matches.append(os.path.join(root, filename))
          # if whitelist is None, then append all files
          else:
            if os.path.join(root, filename) not in matches:
              matches.append(os.path.join(root, filename))
    return matches


def file_basename(filename):
  if filename and filename != "":
    return os.path.basename(filename) if is_file(filename) else None


def file_dirname(filename):
  if filename and filename != "":
    return os.path.dirname(filename) if is_file(filename) else None


def file_size(filename):
  if filename and filename != "":
    return os.stat(filename).st_size


def file_size_string(filename):
  if filename and filename != "":
    return size_string(os.stat(filename).st_size)


def file_remove(filename):
  if filename and filename != "" and is_file(filename):
    os.remove(filename)


def file_hashes(filename, algo="sha256", blocksize=65536):
  if filename and filename != "":
    file_handle = open(filename, "rb")
    data = file_handle.read(blocksize)
    if algo == "crc32":
      return int("%d" % (zlib.crc32(open(filename,"rb").read()) & 0xffffffff))
    elif algo == "adler32":
      return "%d" % (zlib.adler32(open(filename,"rb").read()) & 0xffffffff)
    elif algo == "md5":
      hasher = hashlib.md5()
    elif algo == "sha1":
      hasher = hashlib.sha1()
    elif algo == "sha224":
      hasher = hashlib.sha224()
    elif algo == "sha256":
      hasher = hashlib.sha256()
    elif algo == "sha384":
      hasher = hashlib.sha384()
    elif algo == "sha512":
      hasher = hashlib.sha512()
    elif algo == "ssdeep":
      return pydeep.hash_file(filename)
    else:
      return None
    while len(data) > 0:
      hasher.update(data)
      data = file_handle.read(blocksize)
    return hasher.hexdigest()


def file_open(filename):
  if filename and filename != "":
    with codecs.open(filename, mode="r", encoding="utf-8") as fo:
      return fo.read()


def file_save(filename, data, mode="w"):
  if filename and filename != "":
    mkdirp(os.path.dirname(filename))
    try:
      with codecs.open(filename, mode, encoding="utf-8") as fo:
        fo.write(data)
    except Exception as ex:
      with open(filename, mode) as fo:
        fo.write(data)


def file_json_open(filename):
  if filename and filename != "":
    return dict(json.loads(file_open(filename)))


def file_json_save(filename, data):
  if filename and filename != "":
    # save json data to file
    with open(filename, "w") as jsonfile:
      return json.dump(data, jsonfile)


def file_strings_ascii(filename, N=4):
  if filename and filename != "":
    with open(filename, "rb") as f:
      return re.findall(r"([\x20-\x7e]{%d,})" % N, f.read())


# search for printable ASCII characters encoded as UTF-16LE
# http://stackoverflow.com/questions/10637055/how-do-i-extract-unicode-character-sequences-from-an-mz-executable-file
def file_strings_unicode(filename, N=4):
  if filename and filename != "":
    data = open(filename,"rb").read()
    pat = re.compile(ur"(?:[\x20-\x7E][\x00]){%d,}" % N)
    return [w.decode("utf-16le") for w in pat.findall(data)]


# http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdirp(path):
  if path and path != "":
    try:
      os.makedirs(path)
    except OSError as exc: # Python >2.5
      if exc.errno == errno.EEXIST and os.path.isdir(path):
        pass
      else: raise


def is_dir(path):
  if path and path != "":
    return os.path.isdir(path)


def is_file(filename):
  if filename and filename != "":
    return os.path.isfile(filename)


# http://www.cloudshield.com/blog/advanced-malware/how-to-efficiently-detect-xor-encoded-content-part-1-of-2/
def file_xor_search(filename, keylengths=[1,2,4,8], searchstring="This program", searchoffset=78):
  def xordelta(s, keylen=1):
    delta = array.array("B", s)
    for x in xrange(keylen, len(s)):
      delta[x - keylen] ^= delta[x]
    return delta.tostring()[:-keylen]
  # https://github.com/guelfoweb/peframe/blob/master/peframe/modules/xor.py
  check = []
  for l in keylengths:
    keydelta = xordelta(searchstring, l)
    docdelta = xordelta(filename, l)
    offset = -1
    while(True):
      offset += 1
      offset = docdelta.find(keydelta, offset)
      if(offset > 0):
        print ("Key length: %d offset: %08X" % (l, offset))
        check.append((l, offset))
      else:
        break
  detect = [item for item in check if item[1] == searchoffset]
  if detect:
    return (True, check)
  else:
    return (False, [])

# http://stackoverflow.com/questions/2281850/timeout-function-if-it-takes-too-long-to-finish
class TimeoutError(Exception):
  pass
def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
  def decorator(func):
    def _handle_timeout(signum, frame):
      raise TimeoutError(error_message)
    def wrapper(*args, **kwargs):
      signal.signal(signal.SIGALRM, _handle_timeout)
      signal.alarm(seconds)
      try:
        result = func(*args, **kwargs)
      finally:
        signal.alarm(0)
      return result
    return wraps(func)(wrapper)
  return decorator
@timeout(5)
def file_exiftool(filename):
  ex = ExifTool.ExifTool()
  ex.start()
  if ex.running:
    exifdata = unicode_to_string(ex.get_metadata(filename))
    ex.terminate()
    return exifdata
  else:
    return None


# write some packet data to a pcap file
def file_pcapwriter(filename, pktlist):
  pcap_endian = "="
  pcap_magic = 0xA1B2C3D4
  pcap_version_major = 2
  pcap_version_minor = 4
  pcap_thiszone = 0
  pcap_sigfigs = 0
  pcap_snaplen = 65535
  pcap_network = 1
  pcap_header = struct.pack(
    pcap_endian + "IHHIIII",
    pcap_magic,
    pcap_version_major,
    pcap_version_minor,
    pcap_thiszone,
    pcap_sigfigs,
    pcap_snaplen,
    pcap_network)
  pcap_ts_sec = 0x50F551DD
  pcap_ts_usec = 0x0008BD2E
  pcap_incl_len = 0
  pcap_orig_len = 0
  ethernet = ("00 0b 00 0b 00 0b"
    "00 0a 00 0a 00 0a"
    "08 00")
  eth_header = binascii.a2b_hex("".join(ethernet.split()))
  fo = open(filename, "wb")
  fo.write(pcap_header)
  for pkt in pktlist:
    pcap_ts_usec += random.randint(1000, 3000)
    pcap_incl_len = len(pkt) + 14
    pcap_orig_len = len(pkt) + 14
    pkt_header = struct.pack(pcap_endian + "IIII",
      pcap_ts_sec,
      pcap_ts_usec,
      pcap_incl_len,
      pcap_orig_len)
    fo.write(pkt_header)
    fo.write(eth_header)
    fo.write(pkt)

