# -*- coding: utf-8 -*-

from __future__ import division

from nltk.chat import eliza
elizabot = eliza.Chat(eliza.pairs)
from nltk.chat import iesha
ieshabot = iesha.Chat(iesha.pairs)
from nltk.chat import rude
rudebot = rude.Chat(rude.pairs)
from nltk.chat import suntsu as suntsubot
from nltk.chat import zen as zenbot

import scanless.cli.main as scanless

from ttp import ttp

import cleverbot

from PIL import Image, ImageDraw
import colorsys
import base64

from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium import webdriver

from HTMLParser import HTMLParser

from cigma.cigma import Cigma

from pprint import pprint
import ConfigParser
import subprocess
import contextlib
import collections
import rlcompleter
import datetime
import platform
import readline
import requests
import binascii
import textwrap
import hashlib
import getpass
import pydeep
import random
import string
import struct
import socket
import urllib
import exrex
import shlex
import math
import code
import json
import time
import zlib
import sys
import os
import re

try:
  from cStringIO import StringIO
except:
  from StringIO import StringIO


requests.packages.urllib3.disable_warnings()

keys = ConfigParser.ConfigParser()
keys.read("%s/data/keys.conf" % (os.path.dirname(__file__)))


# http://goodcode.io/articles/python-dict-object/
class objdict(dict):
  def __getattr__(self, name):
    if name in self:
      return self[name]
    else:
      raise AttributeError("No such attribute: " + name)
  def __setattr__(self, name, value):
    self[name] = value
  def __delattr__(self, name):
    if name in self:
      del self[name]
    else:
      raise AttributeError("No such attribute: " + name)


class sortdict(dict):
  def __str__(self):
    return "{" + ", ".join("%r: %r" % (key, self[key]) for key in sorted(self)) + "}"


# sfo: 2828953: silence stdout of a function
class DummyFile(object):
  def write(self, x):
    pass
@contextlib.contextmanager
def nostdout():
  save_stdout = sys.stdout
  sys.stdout = DummyFile()
  try:
    yield
  except Exception as ex:
    print ex
    pass
  sys.stdout = save_stdout


def interact(conobj, banner):
  class completer(rlcompleter.Completer):
    def attr_matches(self, text):
      m = re.match(r"(\w+(\.\w+)*)\.(\w*)", text)
      if not m:
        return
      expr, attr = m.group(1, 3)
      try:
        object = eval(expr)
      except:
        object = eval(expr, session)
      words = dir(object)
      if hasattr(conobj, "__class__" ):
        words = words + rlcompleter.get_class_members(conobj.__class__)
      matches = []
      n = len(attr)
      for word in words:
        if word[:n] == attr:
          matches.append("%s.%s" % (expr, word))
      return matches
  readline.set_completer(completer().complete)
  readline.parse_and_bind("C-o: operate-and-get-next")
  readline.parse_and_bind("tab: complete")
  code.interact(banner=banner, local = locals())


def exit(retcode=0):
  sys.exit(retcode)


# print message with debug level and function/module name
def doprint(msg, level="INFO", back=0):
  frame = sys._getframe(back + 1)
  filename = os.path.basename(frame.f_code.co_filename).replace(".py", "")
  funcname = frame.f_code.co_name
  lineno = frame.f_lineno
  print "%s [%s.%s.%d] %s: %s" % (current_datetime_string(), filename, funcname, lineno, level, msg)


# print info messages
def info(msg):
  pretext = "INFO"
  doprint(msg, pretext, back=1)


# print debug messages
def debug(msg):
  pretext = "DEBUG"
  doprint(msg, pretext, back=1)


# print warning messages
def warn(msg):
  pretext = "WARN"
  doprint(msg, pretext, back=1)


# print error messages
def error(msg):
  pretext = "ERROR"
  doprint(msg, pretext, back=1)
  exit(1)


def set_prompt(ps1="(prompt) ", ps2="... "):
  sys.ps1 = ps1
  sys.ps2 = ps2


### method definitions


def bin2ascii(binstr):
  return binascii.unhexlify('%x' % int(binstr, 2))


def black_to_color(val):
  val = (val / 255.0)
  rgb = colorsys.hsv_to_rgb(val, 0.99, val)
  return (int(rgb[0]*255), int(rgb[1]*255), int(rgb[2]*255))


# calculate the frequency of each byte value in the file
# http://www.kennethghartman.com/calculate-file-entropy/
def byte_freq_ken(bytearr):
  sizeinbytes = len(bytearr)
  freqlist = []
  for b in range(256):
    ctr = 0
    for byte in bytearr:
      if byte == b:
        ctr += 1
    freqlist.append(float("%.6f" % (float(ctr) / sizeinbytes)))
  return freqlist, sizeinbytes


# calculate the frequency of each byte value in the file
def byte_freq(bytearr):
  c = collections.Counter(bytearr)
  intfreqlist = c.values()
  sizeinbytes = sum(intfreqlist)
  freqlist = []
  for f in intfreqlist:
    freqlist.append(float("%.6f" % (float(f) / sizeinbytes)))
  return freqlist, sizeinbytes


def caesarcipher(data, shift):
  trans = dict(zip(string.lowercase, string.lowercase[shift:] + string.lowercase[:shift]))
  trans.update(zip(string.uppercase, string.uppercase[shift:] + string.uppercase[:shift]))
  return "".join(trans.get(ch, ch) for ch in data).strip()


def caesarcipher_bruteforce(data, searchstring=None):
  maxiterations = 50
  results = objdict()
  for i in range(maxiterations):
    results[i] = caesarcipher(data, i)
    if searchstring and searchstring.lower() in p: return i, p
  return results


def caesarcipher_bruteforce_search(bruteresult, searchstring):
  for key in bruteresult.keys():
    if searchstring in bruteresult[key]:
      print key, bruteresult[key]


def celcius_to_fahrenheit(ctemp):
  return ((ctemp * 9 / 5) + 32)


# pescanner.py
def convert_char(char):
  if char in string.ascii_letters or \
    char in string.digits or \
    char in string.punctuation or \
    char in string.whitespace:
    return char
  else:
    return r"\x%02x" % ord(char)


# pescanner.py
def convert_to_printable(s):
  return "".join([convert_char(c) for c in s])


def current_datetime():
  return datetime.datetime.utcnow()


def current_datetime_string():
  return "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S %d/%b/%Y"), time.tzname[0])


def current_time_string():
  return time.strftime("%c")


def current_weekday():
  return datetime.datetime.today().weekday()


def data_entropy_compression_stats(data):
  # map the data into a byte array
  bytearr = map(ord, data)
  freqlist, datasizeinbytes = byte_freq(bytearr)
  # shannon entropy
  ent = 0.0
  for freq in freqlist:
    if freq > 0:
      ent = ent + freq * math.log(freq, 2)
  ent = -ent
  # minimum possible filesize after compression
  mindatasize = (ent * datasizeinbytes) / 8
  # compression efficiency
  sizediff = datasizeinbytes - mindatasize
  compressionratio = (sizediff / datasizeinbytes) * 100 if sizediff > 0 else 0
  # https://vxheaven.org/lib/pdf/Using%20Entropy%20Analysis%20to%20Find%20Encrypted%20and%20Packed%20Malware.pdf
  # Entropy:                  Range
  # Text:                     4.401-5.030
  # Native:                   6.084-6.369
  # Packed:                   7.199-7.267
  # Compressed:               7.295-7.312
  # Encrypted:                7.6-8.0
  rangedefs = dict({
    0: dict({
      "min": 0.1,
      "max": 0.9,
      "category": "Suspicious"
    }),
    1: dict({
      "min": 0.91,
      "max": 4.400,
      "category": "Suspicious-Text"
    }),
    2: dict({
      "min": 4.401,
      "max": 5.030,
      "category": "Text"
    }),
    3: dict({
      "min": 5.031,
      "max": 6.083,
      "category": "Text-Native"
    }),
    4: dict({
      "min": 6.084,
      "max": 6.369,
      "category": "Native"
    }),
    5: dict({
      "min": 6.370,
      "max": 7.198,
      "category": "Native-Packed"
    }),
    6: dict({
      "min": 7.199,
      "max": 7.267,
      "category": "Packed"
    }),
    7: dict({
      "min": 7.268,
      "max": 7.294,
      "category": "Packed-Compressed"
    }),
    8: dict({
      "min": 7.295,
      "max": 7.312,
      "category": "Compressed"
    }),
    9: dict({
      "min": 7.313,
      "max": 7.59,
      "category": "Compressed-Encrypted"
    }),
    10: dict({
      "min": 7.6,
      "max": 8.0,
      "category": "Encrypted"
    })
  })
  entropy = float("{0:.2f}".format(ent))
  entropycategory = "Unknown"
  for idx in sorted(rangedefs.keys(), reverse=True):
    if entropy >= rangedefs[idx]["min"] and entropy <= rangedefs[idx]["max"]:
      entropycategory = rangedefs[idx]["category"].upper()
  return dict({
    "bytefreqlist": freqlist,
    "datasizeinbytes": datasizeinbytes,
    "entropy": entropy,
    "entropycategory": entropycategory.upper(),
    "mindatasize": float("{0:.2f}".format(mindatasize)),
    "compressionratio": float("{0:.2f}".format(compressionratio))
  })


def data_hashes(data, algo="sha256"):
  if not data:
    return None
  algo = algo.lower()
  if algo == "crc32":
    return int("%d" % (zlib.crc32(data) & 0xffffffff))
  elif algo == "adler32":
    return "%d" % (zlib.adler32(data) & 0xffffffff)
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
    if hasattr(pydeep, "hash_data"):
      return pydeep.hash_data(data)
    elif hasattr(pydeep, "hash_buf"):
      return pydeep.hash_buf(data)
    else:
      return None
  else:
    return None
  hasher.update(data)
  return hasher.hexdigest()


def data_magic(data):
  return Cigma().identify(data=data)


def data_mimetype(data):
  result = Cigma().identify(data=data)
  return result["match"]["mimetype"] if result["match"] else None


def data_size(data):
  return len(data)


def data_size_string(data):
  return size_string(data_size(data))


# https://github.com/Xen0ph0n/XRayGlasses
# todo: add support for other image types
# todo: use PIL or something else to get rid of manually crafting images
def data_to_bmpimage(data):
  outdata = None
  b = bytearray(data)
  # pad the end of the byte array so the length is a multiple of 256
  if len(b) % 256 > 0:
    remainder = len(b) % 256
    padding = 256 - remainder
    for i in range(padding):
      b.append(0x00)
  # start writing the static BMP header
  outdata = "\x42\x4d\x36\x2c\x01\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x00\x01\x00\x00"
  # build and write the height value in the header
  height = int(len(b) / 256)
  heightbigendian = struct.pack("i", height)
  outdata += heightbigendian
  # finish writing the static BMP header
  outdata += "\x01\x00\x18\x00\x00\x00\x00\x00\x00\x2c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  # re-order the byte array so the top-left pixel will correspond with the first byte value
  # this allows the image to be constructed left-to-right, top-to-bottom
  output = bytearray()
  for i in range(height, 0, -1):
    startval = ( i - 1 ) * 256
    stopval = startval + 256
    output.extend(b[startval:stopval])
  # write each byte value 3 times to populate the BGR values for each pixel, producing a 256-shade grayscale output
  # optionally, one or two BGR levels can be muted conditionally based on byte values (i.e. ASCII colorization)
  for i in range(len(output)):
    a = chr(output[i])
    outdata += a + a + a
  return outdata


def data_to_pngimage(data, width=256, maxsize=180000, enable_colors=True):
  size = (width, 1)
  pixels = (size[0] * size[1])
  bytes = data
  bytes = [ord(byte) for byte in bytes]
  bytes = bytes if maxsize is None else bytes[:maxsize]
  if enable_colors:
    img = [black_to_color(b) for b in bytes]
  else:
    img = [(b,b,b) for b in bytes]
  lines = int(len(bytes) / size[0])+1
  size = (size[0], lines)
  im = Image.new("RGB", size)
  im.putdata(img)
  pngimage = StringIO()
  im.save(pngimage, format="PNG")
  return pngimage.getvalue()


# http://stackoverflow.com/questions/26496831/how-to-convert-defaultdict-of-defaultdicts-of-defaultdicts-to-dict-of-dicts-o
def dict_default_to_regular(d):
  if isinstance(d, collections.defaultdict):
    d = {k: dict_default_to_regular(v) for k, v in d.iteritems()}
  return d


def dict_normalize(indict):
  # replace all empty or "NA" values in dicts with None
  # needs testing
  """
    indict = {
      "a": "",
      "b": "",
      "c": "NA",
      "d": "NA",
      "e": 1,
      "f": {
        "fa": "",
        "fb": "",
        "fc": "NA",
        "fd": "NA",
        "fe": 1,
        "ff": ["11", 22, "ab", "", {1: ""}]
      },
      "g": [1, "r", 66, "", 99]
    }
  """
  if not isinstance(indict, dict):
    return indict
  for k, v in indict.iteritems():
    if isinstance(v, dict):
      dict_normalize(v)
    elif isinstance(v, list):
      for idx, item in enumerate(v):
        if isinstance(item, dict):
          dict_normalize(item)
        if isinstance(item, list):
          dict_normalize(item)
        elif isinstance(item, str):
          if not item or item == "NA":
            indict[k][idx] = None
    elif isinstance(v, str):
      if not v or v == "NA":
        indict[k] = None
  return indict


def dict_print(dictdata):
  sd = collections.OrderedDict(sorted(dictdata.items()))
  print json.dumps(sd, indent=4)


def download(queryurl):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
  }
  res = requests.get(queryurl, headers=customheaders, verify=False)
  if res.status_code == 200:
    return res.content
  else:
    return None


def upload_file(queryurl, filepath, queryheaders):
  try:
    res = requests.post(queryurl, headers=queryheaders, files=dict({"file": open(filepath)}), verify=False)
    if res.status_code == 200: return res.content
    else: return None
  except:
    return None


def upload_json(queryurl, querydata, queryheaders):
  res = requests.post(queryurl, headers=queryheaders, json=querydata, verify=False)
  if res.status_code == 200: return res.content
  else: return None


# dump assembled instrs
def dump_asm(data, opcodesize=28, fillchar="."):
  offset = 0
  while offset < len(data):
    i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
    if not i:
      break
    else:
      j = 1
      opcodes = ""
      data = data[offset:(offset + i.length)]
      for c in data:
        opcodes = opcodes + str("%02x " % (ord(c)))
      print "[0x%08x] (%02dB) %s %s" % (offset,
          i.length,
          opcodes.ljust(opcodesize, fillchar),
          pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0))
    offset += i.length


# https://arcpy.wordpress.com/2012/04/20/146/
# start = time.time(); time.sleep(10); end = time.time(); sec_elapsed = end - start
def elapsed_time_string(sec_elapsed):
  h = int(sec_elapsed / (60 * 60))
  m = int((sec_elapsed % (60 * 60)) / 60)
  s = sec_elapsed % 60.
  return "{}:{:>02}:{:>05.2f}".format(h, m, s)


def eliza(query):
  return objdict({
    "success": True,
    "query": query,
    "response": elizabot.respond(query)
  })


def iesha(query):
  return objdict({
    "success": True,
    "query": query,
    "response": ieshabot.respond(query)
  })


morseencodetab = {"A": ".-", "B": "-...","C": "-.-.", "D": "-..", "E": ".","F": "..-.", "G": "--.",
    "H": "....","I": "..", "J": ".---","K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
    "P": ".--.","Q": "--.-","R": ".-.", "S": "...", "T": "-","U": "..-", "V": "...-","W": ".--",
    "X": "-..-", "Y": "-.--","Z": "--..", " ": "/", "0": "-----", "1": ".----", "2": "..---", "3": "...--",
    "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----."}
morsedecodetab = dict((v, k) for (k, v) in morseencodetab.items())

def morse_decode(message, offset=0):
  message = message + " " if offset == 0 else message
  if offset < len(message):
    morsechar = ""
    for key, char in enumerate(message[offset:]):
      if char == " ":
        offset = key + offset + 1
        letter = morsedecodetab[morsechar] if morsechar in morsedecodetab else morsechar
        return letter + "%s" % morse_decode(message, offset)
      else:
        morsechar += char
  else:
    return ""


def morse_encode(message):
  return " ".join([morseencodetab[c.upper()] if c.upper() in morseencodetab else c for c in message])


def rude(query):
  return objdict({
    "success": True,
    "query": query,
    "response": rudebot.respond(query)
  })


def suntsu(query):
  return objdict({
    "success": True,
    "query": query,
    "response": suntsubot.suntsu_chatbot.respond(query)
  })


def zen(query):
  return objdict({
    "success": True,
    "query": query,
    "response": zenbot.zen_chatbot.respond(query)
  })


# Inspired from jsunpack, slightly modified
def expand_chunked(chunk_data):
  try:
    data = chunk_data
    decoded = ""
    chunk_pos = data.find("\n")+1
    chunk_length = int("0x"+data[:chunk_pos], 0)
    while(chunk_length > 0):
      decoded += data[chunk_pos:chunk_length+chunk_pos]
      data = data[chunk_pos+chunk_length+2:] # +2 skips \r\n
      chunk_pos = data.find("\n")+1
      if chunk_pos <= 0:
        break
      chunk_length = int("0x"+data[:chunk_pos], 0)
    return decoded
  except:
    warn("Exception while dechunking. Returning %dB data as-is." % (len(chunk_data)))
    return chunk_data


def expand_deflate(deflate_data):
  try:
    # http://love-python.blogspot.in/2008/07/accept-encoding-gzip-to-make-your.html
    return zlib.decompress(deflate_data)
  except:
    warn("Exception while expanding defalte data. Returning %dB data as-is." % (len(deflate_data)))
    return deflate_data


# http://stackoverflow.com/questions/2695152/in-python-how-do-i-decode-gzip-encoding
def expand_gzip(gzip_data):
  try:
    return zlib.decompress(gzip_data, 16+zlib.MAX_WBITS)
  except Exception as ex:
    warn("Exception while expanding gzip data. Returning %dB data as-is." % (len(gzip_data)))
    return gzip_data


def fahrenheit_to_celcius(ftemp):
  return ((ftemp - 32) * 5 / 9)


def from_base64(data):
    return base64.b64decode(data) if data else data


def get_args(arguments):
  return shlex.split(arguments)


def hexdump(data, dataoffset=0, length=16, sep="."):
  lines = []
  FILTER = "".join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
  for c in xrange(0, len(data), length):
    chars = data[c:c+length]
    hex = " ".join(["%02x" % ord(x) for x in chars])
    printablechars = "".join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
    lines.append("%08x:  %-*s  |%s|\n" % (c+dataoffset, length*3, hex, printablechars))
  return "".join(lines)


def inch_to_millibar(inch):
  return (inch / 0.0295299830714)


# https://stackoverflow.com/questions/3764291/checking-network-connection/33117579#33117579
def internet(host="8.8.8.8", port=53, timeout=3):
  """
  Host: 8.8.8.8 (google-public-dns-a.google.com)
  OpenPort: 53/tcp
  Service: domain (DNS/TCP)
  """
  try:
    socket.setdefaulttimeout(timeout)
    socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
    return True
  except Exception as ex:
    print ex
    return False


# utilitybelt: https://github.com/yolothreat/utilitybelt
regexcve = re.compile("((CVE-)?(19|20)\\d{2}-\\d{4,7})", re.I | re.S | re.M)
regexipv4 = re.compile("((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", re.I | re.S | re.M)
regexemail = re.compile("\\b[A-Za-z0-9_.]+@[0-9a-z.-]+\\b", re.I | re.S | re.M)
regexdomain = re.compile("([a-z0-9-_]+\\.){1,4}(io|in|us|cn|ru|com|aero|am|asia|au|az|biz|br|ca|cat|cc|ch|co|coop|cx|de|edu|fr|gov|hk|info|int|ir|jobs|jp|kr|kz|lu|me|mil|mobi|museum|name|net|nl|nr|org|post|pre|ru|tel|tk|travel|tw|ua|uk|uz|ws|xxx)", re.I | re.S | re.M)
regexmd5 = re.compile("\\b[a-f0-9]{32}\\b", re.I | re.S | re.M)
regexsha1 = re.compile("\\b[a-f0-9]{40}\\b", re.I | re.S | re.M)
regexsha256 = re.compile("\\b[a-f0-9]{64}\\b", re.I | re.S | re.M)
regexsha512 = re.compile("\\b[a-f0-9]{128}\\b", re.I | re.S | re.M)
regexssdeep = re.compile("\\b\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\\b", re.I | re.S | re.M)
regexurl = re.compile("(((http|ftp)[s]?|file)://)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", re.I | re.S | re.M)


def is_cve(query):
  return bool(re.match(regexcve, query))


def is_domain(query):
  return bool(re.match(regexdomain, url_to_domain(query)))


def is_email(query):
  return bool(re.match(regexemail, query))


def is_ipv4(query):
  return bool(re.match(regexipv4, url_to_domain(query)))


def is_md5(query):
  return bool(re.match(regexmd5, query))


def is_sha1(query):
  return bool(re.match(regexsha1, query))


def is_sha256(query):
  return bool(re.match(regexsha256, query))


def is_sha512(query):
  return bool(re.match(regexsha512, query))


def is_ssdeep(query):
  return bool(re.match(regexssdeep, query))


def is_hash(query):
  return True if is_md5(query) or is_sha1(query) or is_sha256(query) or is_sha512(query) or is_ssdeep(query) else False


def is_url(query):
  return bool(re.match(regexurl, query))


def jokes(maxcount=10):
  with open("%s/data/jokes.json" % (os.path.dirname(__file__))) as jsonfile:
    contentdict = json.load(jsonfile)
    jokes = list()
    for _ in range(maxcount):
      jokes.append(random.choice(contentdict[random.choice(contentdict.keys())]))
    return objdict({
      "success": True,
      "jokes": jokes
    })


def kilometer_to_mile(kms):
  return (kms / 1.609)


def mile_to_kilometer(miles):
  return (miles * 1.609)


def millibar_to_inch(mlb):
  return (mlb * 0.0295299830714)


def pause(delay=None):
  delay = 1 if not delay else delay
  time.sleep(delay)


def portscan(target):
  return scanless.scanless(target, "all")

# ascii printable filter for raw bytes
def printable(data):
  return "".join([ch for ch in data if ord(ch) > 31 and ord(ch) < 126
    or ord(ch) == 9
    or ord(ch) == 10
    or ord(ch) == 13
    or ord(ch) == 32])


def regex_exrex(pattern, count):
  count = int(count) if int(count) > 0 and int(count) < 10 else 10
  return objdict({
    "pattern": pattern,
    "data": sorted(set([exrex.getone(pattern) for _ in range(count)])),
    "count": exrex.count(pattern)
  })


def regex_match(pattern, data, flags=re.I):
  match = re.search(pattern, data, flags)
  if match:
    return objdict({
      "pattern": pattern,
      "data": data,
      "flags": flags,
      "datasize": len(data),
      "start": match.start(),
      "end": match.end(),
      "matchsize": match.end()-match.start()+1
    })
  return None


# get regex pattern from compiled object
def regex_pattern(regexobj):
  return regexobj.pattern
  # or
  dumps = pickle.dumps(regexobj)
  pattern = re.search("\n\(S['\"](.*)['\"]\n", dumps).group(1)
  if re.findall(r"\\x[0-9a-f]{2}", pattern):
    pattern = re.sub(r"(\\x)([0-9a-f]{2})", r"x\2", pattern)
  return pattern


def remove_markup(text):
  t = list()
  for entry in text.split(" "):
    if entry and entry[0] == "<" and entry[-1] == ">":
      if "|" in entry:
        try:
          entry = entry.split("|")[1].split(">")[0]
        except:
          pass
      else:
        try:
          entry = "".join("".join(entry[1:])[:-1])
        except:
          pass
    t.append(entry)
  if len(t):
    return " ".join(t).strip()

def run_command(cmd):
  p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
  (stdout, stderr) = p.communicate()
  return (stdout, stderr)


def seconds_to_human(seconds):
  # http://stackoverflow.com/a/26277340/1079836
  days = seconds // 86400
  hours = seconds // 3600 % 24
  minutes = seconds // 60 % 60
  return (days, hours, minutes)


def size_string(bytes, precision=1):
  # http://code.activestate.com/recipes/577081-humanized-representation-of-a-number-of-bytes/
  abbrevs = (
    (1<<50L, "PB"),
    (1<<40L, "TB"),
    (1<<30L, "GB"),
    (1<<20L, "MB"),
    (1<<10L, "KB"),
    (1, "B")
  )
  if bytes == 1:
    return "1B"
  for factor, suffix in abbrevs:
    if bytes >= factor:
      break
  return ("%.*f%s" % (precision, bytes / factor, suffix)).replace(".0", "")


# python version of TallTweets' js implementation
def split_twitter_text(text, maxchars=140):
  def is_url(text):
    return len(ttp.Parser().parse(text).urls) > 0
  if (len(text) <= maxchars):
    return list(text)
  else:
    # declare locals
    chunks, words, cid = list(), text.split(' '), 0
    # loop over all words
    while (len(words)):
      cid += 1
      # add id to each chunk's start
      chunk = "%d/" % (cid)
      chunklen = len(chunk)
      # t.co url's will be truncated to 23 chars and 2 for chunk id
      maxurllen = 23 + 2
      # calc length of next word, use twitter-text utils to check if next word is a url
      nextchunklen = maxurllen if is_url(words[0]) else len(words[0]) + 1
      # we can add more words to current chunk
      while (len(words) > 0 and (chunklen + nextchunklen) <= maxchars):
        # concatenate current word to current chunk
        chunk = " ".join([chunk, words[0]])
        chunklen += nextchunklen
        # remove current word from list
        words = words[1:]
        # prepare for next iteration of loop
        if (len(words) > 0):
          nextchunklen = maxurllen if is_url(words[0]) else len(words[0]) + 1
      # got upto 140 chars in the current chunk, add to chunks list and move on
      chunks.append(chunk)
  # done with all words, got all chunks, return
  return chunks


def truncate_message(content, length=177, sep=" "):
  # https://stackoverflow.com/a/250373/1079836
  if len(content) <= length:
    return content
  else:
    return sep.join(content[:length+1].split(sep)[0:-1])


def ellipsis_message(content, length=177, sep=" ", suffix="..."):
  if len(content) <= length:
    return content
  else:
    return "%s%s" % (truncate_message(content, length, sep), suffix)


def split_message(message, splitchar="\n", maxchars=3000):
  m = maxchars
  l = message.split("\n")
  f, a = list(), list()
  for i in l:
    if len("\n".join(a))+len(i) <= m:
      a.append(i)
    else:
      f.append("\n".join(a))
      a = list()
      a.append(i)
  f.append("\n".join(a))
  return f


def sysinfo():
  return objdict({
    "platform": platform.platform(),
    "machine": platform.machine(),
    "system": platform.system(),
    "node": platform.node(),
    "user": getpass.getuser(),
    "release": platform.release(),
    "version": platform.version(),
    "processor": platform.processor(),
    "architecture": " ".join(platform.architecture()),
    "pythonversion": platform.python_version(),
    "pythoncompiler": platform.python_compiler(),
  })


# http://stackoverflow.com/questions/753052/strip-html-from-strings-in-python
class MLStripper(HTMLParser):
  def __init__(self):
    self.reset()
    self.fed = []
  def handle_data(self, d):
    self.fed.append(d)
  def get_data(self):
    return "".join(self.fed)
def strip_tags(html):
  s = MLStripper()
  s.feed(html)
  return s.get_data().strip()


def time_to_local_string(timeval, timeformat="%d/%b/%Y %H:%M:%S %Z"):
  return time.strftime(timeformat, time.localtime(timeval))


def timestamp_to_utc_string(timeval):
  return "%s UTC" % time.asctime(time.gmtime(timeval))


def to_base64(data):
  return base64.b64encode(data) if data else data


# http://farmdev.com/talks/unicode/
def to_unicode(obj, encoding="utf-8"):
  if isinstance(obj, basestring):
    if not isinstance(obj, unicode):
      obj = unicode(obj, encoding)
  return obj


# http://stackoverflow.com/questions/1254454/fastest-way-to-convert-a-dicts-keys-values-from-unicode-to-str
def unicode_to_string(data):
  if isinstance(data, basestring):
    return data.encode("utf-8")
  elif isinstance(data, collections.Mapping):
    return dict(map(unicode_to_string, data.iteritems()))
  elif isinstance(data, collections.Iterable):
    return type(data)(map(unicode_to_string, data))
  else:
    return data


def url_encode(url):
  return urllib.quote_plus(url)


def url_decode(url):
  return urllib.urldecode(url)


def url_to_domain(domain):
  return re.sub("(ht|f|sm)tps?://", "", domain).split("/")[0] if domain else domain


def webscreenshot(url, imagefile="/tmp/screenshot.png", width=1400, height=800):
  dcap = dict(DesiredCapabilities.PHANTOMJS)
  dcap["phantomjs.page.settings.resourceTimeout"] = 10000
  dcap["phantomjs.page.settings.userAgent"] = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/53 "
    "(KHTML, like Gecko) Chrome/15.0.87"
  )
  br = webdriver.PhantomJS(desired_capabilities=dcap)
  br.set_window_size(width, height)
  br.get(url)
  return objdict({
    "success": True,
    "query": url,
    "imagedata": br.get_screenshot_as_png()
  })


def xor(data, key):
  data = bytearray([ord(b) for b in data]) if isinstance(data, str) else data
  if isinstance(key, str):
    key = bytearray([ord(b) for b in key])
    l = len(key)
    return "".join([chr(data[i] ^ key[i % l]) for i in range(0, len(data))])
  return "".join([chr(data[i] ^ key) for i in range(0, len(data))])


def xor_bruteforce(data, searchstring=None):
  maxiterations = 256
  results = objdict()
  for i in range(maxiterations):
    results[i] = xor(data, i)
    if searchstring and searchstring.lower() in p: return i, p
  return results


def xor_bruteforce_search(bruteresult, searchstring):
  for key in bruteresult.keys():
    if searchstring in bruteresult[key]:
      print key, bruteresult[key]

