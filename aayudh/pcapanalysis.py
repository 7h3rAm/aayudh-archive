# -*- coding: utf-8 -*-

from external.utilitybelt import utilitybelt
from ipwhois import IPWhois
import pylibemu
import pydasm
import yara
import dpkt

from pprint import pprint
import traceback
import datetime
import struct
import socket
import nids
import sys
import re

from utils import objdict, size_string, dict_normalize, data_entropy_compression_stats, info, debug, warn, error, exit, expand_gzip, expand_deflate, expand_chunked
from fileutils import is_file, file_mimetype, file_json_open
from protoid import ProtoID
import apis


class PCAPAnalysis:
  def __init__(self, filename, config=None):
    if not is_file(filename) and file_mimetype(filename) != "application/vnd.tcpdump.pcap":
      return None

    self.config = objdict({})
    self.config.filename = filename
    self.config.verbose = False

    if config:
      for key, value in config.iteritems():
        self.config[key] = value

    self.config.ipproto = objdict({})
    self.config.ipproto.icmp = 1
    self.config.ipproto.igmp = 2
    self.config.ipproto.tcp = 6
    self.config.ipproto.igrp = 9
    self.config.ipproto.udp = 17
    self.config.ipproto.esp = 50
    self.config.ipproto.ah = 51

    # referenced from https://code.google.com/p/dpkt/source/browse/trunk/dpkt/pcap.py
    self.datalink_types = {
      0: 'DLT_NULL',
      1: 'DLT_EN10MB',
      2: 'DLT_EN3MB',
      3: 'DLT_AX25',
      4: 'DLT_PRONET',
      5: 'DLT_CHAOS',
      6: 'DLT_IEEE802',
      7: 'DLT_ARCNET',
      8: 'DLT_SLIP',
      9: 'DLT_PPP',
      10: 'DLT_FDDI',
      18: 'DLT_PFSYNC',
      105: 'DLT_IEEE802_11',
      113: 'DLT_LINUX_SLL',
      117: 'DLT_PFLOG',
      127: 'DLT_IEEE802_11_RADIO'
    }

    self.config.signatures = objdict({})
    self.config.signatures.regex = self.config.sigregex
    self.config.signatures.yara = self.config.sigyara

    self.report = objdict({})
    self.report.indicators = objdict({})
    self.report.indicators.checks = objdict({})
    self.report.indicators.flags = objdict({})
    self.report.indicators.warnings = []

    self.report.parsed = objdict({})
    self.report.parsed.flows = objdict({})
    self.report.parsed.hosts = objdict({})

    self.report.parsed.counts = objdict({})
    self.report.parsed.counts.ctsbytes = 0
    self.report.parsed.counts.ctsbytesperpacket = 0
    self.report.parsed.counts.ctspackets = 0
    self.report.parsed.counts.stcbytes = 0
    self.report.parsed.counts.stcbytesperpacket = 0
    self.report.parsed.counts.stcpackets = 0
    self.report.parsed.counts.tcpbytes = 0
    self.report.parsed.counts.tcpbytesperpacket = 0
    self.report.parsed.counts.tcppackets = 0
    self.report.parsed.counts.tcpsessions = 0
    self.report.parsed.counts.udpbytes = 0
    self.report.parsed.counts.udpbytesperpacket = 0
    self.report.parsed.counts.udppackets = 0
    self.report.parsed.counts.ippackets = 0

    try:
      nids.param('pcap_filter', self.config['bpf']) # bpf
      nids.param('scan_num_hosts', 0) # disable portscan detection
      nids.param('pcap_timeout', 64) # ?
      nids.param('multiproc', True) # ?
      nids.param('tcp_workarounds', True) # ?
      nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksum verification
      nids.param('filename', self.config.filename)
      nids.init()

      nids.register_ip(self.handleIPStream)
      nids.register_udp(self.handleUDPStream)
      nids.register_tcp(self.handleTCPStream)
    except Exception as ex:
      self.report.indicators.warnings.append("%s" % ex)
      warn('Exception: %s' % (ex))

  def capinfos(self, filename):
    # generates wireshark's capinfos like stats
    # needs additional testing
    if is_file(filename):
      file_handle = open(filename, 'rb')
      data = file_handle.read()
      pcapstats = dict()
      endianness = None

      # extract pcap magic using host's native endianess
      (pcap_magic, ) = struct.unpack('=I', data[:4])

      # if the pcap is LE
      if pcap_magic == 0xa1b2c3d4:
        (pcap_magic, pcap_version_major, pcap_version_minor, pcap_thiszone, pcap_sigfigs, pcap_snaplen, pcap_network) = struct.unpack('<IHHIIII', data[:24])
        endianness = 'LITTLE'

      # if the pcap is BE
      elif pcap_magic == 0xd4c3b2a1:
        (pcap_magic, pcap_version_major, pcap_version_minor, pcap_thiszone, pcap_sigfigs, pcap_snaplen, pcap_network) = struct.unpack('>IHHIIII', data[:24])
        endianness = 'BIG'

      # for pcaps which are something else (0x4d3c2b1a)?
      else:
        return pcapstats

      starttime = None
      endtime = None
      s = 24
      e = s + 16
      packetscount = 0
      bytescount = 0
      while True:
        if endianness is 'LITTLE':
          (ts_sec, ts_usec, incl_len, orig_len) = struct.unpack('<IIII', data[s:e])
        elif endianness is 'BIG':
          (ts_sec, ts_usec, incl_len, orig_len) = struct.unpack('>IIII', data[s:e])

        packetscount += 1
        bytescount += incl_len

        if not starttime:
          starttime = datetime.datetime.fromtimestamp(ts_sec)
          bytescount += incl_len

        endtime = datetime.datetime.fromtimestamp(ts_sec)

        s = e + incl_len
        e = s + 16

        if e > len(data):
          break

      totsecs = int((endtime - starttime).total_seconds())
      if totsecs < 1:
        totsecs = 1
      pcapstats['totsecs'] = totsecs

      pcapstats['pcapmagic'] = '0x%08X' % pcap_magic
      pcapstats['version_major'] = pcap_version_major
      pcapstats['version_minor'] = pcap_version_minor
      pcapstats['snaplen'] = pcap_snaplen
      pcapstats['pcapencapsulation'] = self.datalink_types[pcap_network]

      pcapstats['packetscount'] = packetscount
      pcapstats['bytescount'] = bytescount

      pcapstats['capturestarttime'] = starttime.strftime('%c').strip()
      pcapstats['captureendtime'] = endtime.strftime('%c').strip()
      pcapstats['captureduration'] = (endtime - starttime).total_seconds()

      byterate = (bytescount / totsecs) if totsecs > 0 else bytescount
      bitrate = ((bytescount * 8) / totsecs) if totsecs > 0 else (bytescount * 8)
      pcapstats['byterate'] = byterate
      pcapstats['bitrate'] = bitrate

      avgpacketsize = (bytescount / packetscount) if packetscount > 0 else bytescount
      avgpacketrate = (packetscount / totsecs) if totsecs > 0 else packetscount
      pcapstats['avgpacketsize'] = avgpacketsize
      pcapstats['avgpacketrate'] = avgpacketrate

      return dict(pcapstats)

  def analyze(self):
    info('Invoking capinfos like pcap stats collection module')

    pcapstats = self.capinfos(self.config.filename)
    self.report.parsed.stats = objdict({})
    for k, v in pcapstats.iteritems():
      self.report.parsed.stats[k] = v

    try:
      debug('Invoking NIDS run() method for flow handling')
      nids.run()
    except Exception as ex:
      self.report.indicators.warnings.append("%s" % ex)
      warn('Exception: %s' % (ex))

    if (self.report.parsed.counts.ctspackets or self.report.parsed.counts.stcpackets or self.report.parsed.counts.tcppackets or self.report.parsed.counts.udppackets)== 0:
      error('NIDS failed to parse %s' % self.config.filename)
      return None

    else:
      if self.report.parsed.counts.ctsbytes > 0 and self.report.parsed.counts.ctspackets > 0:
        self.report.parsed.counts.ctsbytesperpacket = self.report.parsed.counts.ctsbytes / self.report.parsed.counts.ctspackets
        self.report.parsed.counts.ctsbytes = self.report.parsed.counts.ctsbytes
      else:
        self.report.parsed.counts.ctsbytesperpacket = 0
        self.report.parsed.counts.ctsbytes = 0

      if self.report.parsed.counts.stcbytes > 0 and self.report.parsed.counts.stcpackets > 0:
        self.report.parsed.counts.stcbytesperpacket = self.report.parsed.counts.stcbytes / self.report.parsed.counts.stcpackets
        self.report.parsed.counts.stcbytes = self.report.parsed.counts.stcbytes
      else:
        self.report.parsed.counts.stcbytesperpacket = 0
        self.report.parsed.counts.stcbytes = 0

      if self.report.parsed.counts.tcpbytes > 0 and self.report.parsed.counts.tcppackets > 0:
        self.report.parsed.counts.tcpbytesperpacket = self.report.parsed.counts.tcpbytes / self.report.parsed.counts.tcppackets
        self.report.parsed.counts.tcpbytes = self.report.parsed.counts.tcpbytes
      else:
        self.report.parsed.counts.tcpbytesperpacket = 0
        self.report.parsed.counts.tcpbytes = 0

      if self.report.parsed.counts.udpbytes > 0 and self.report.parsed.counts.udppackets > 0:
        self.report.parsed.counts.udpbytesperpacket = self.report.parsed.counts.udpbytes / self.report.parsed.counts.udppackets
        self.report.parsed.counts.udpbytes = self.report.parsed.counts.udpbytes
      else:
        self.report.parsed.counts.udpbytesperpacket = 0
        self.report.parsed.counts.udpbytes = 0

    # gather entropy compression stats
    for flow in self.report.parsed.flows:
      if self.config.enableentropycompressionstats:
        self.report.parsed.flows[flow].stats = objdict({})
        if hasattr(self.report.parsed.flows[flow], "ctsbuf") and self.report.parsed.flows[flow].ctsbuf:
          self.report.parsed.flows[flow].stats.cts = data_entropy_compression_stats(self.report.parsed.flows[flow].ctsbuf)
          del self.report.parsed.flows[flow].stats.cts["bytefreqlist"]
        else:
          self.report.parsed.flows[flow].stats.cts = None

        if hasattr(self.report.parsed.flows[flow], "stcbuf") and self.report.parsed.flows[flow].stcbuf:
          self.report.parsed.flows[flow].stats.stc = data_entropy_compression_stats(self.report.parsed.flows[flow].stcbuf)
          del self.report.parsed.flows[flow].stats.stc["bytefreqlist"]
        else:
          self.report.parsed.flows[flow].stats.cts = None

      else:
        self.report.parsed.flows[flow].stats = objdict({
          "cts": None,
          "stc": None
        })

    # decode layer7 protocol
    if self.config.enableprotodecode:
      dnstype = {
        0: "QUERY",
        1: "RESPONSE"
      }
      opcodes = {
        0: "QUERY",
        1: "IQUERY",
        2: "STATUS",
        4: "NOTIFY",
        5: "UPDATE"
      }
      rcodes = {
        0: "NOERR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
        6: "YXDOMAIN",
        7: "YXRRSET",
        8: "NXRRSET",
        9: "NOTAUTH",
        10: "NOTZONE"
      }
      antypes = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        13: "HINFO",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        41: "OPT"
      }
      ancls = {
        1: "IN",
        3: "CHAOS",
        4: "HESIOD",
        255: "ANY"
      }

      for flow in self.report.parsed.flows:
        if self.report.parsed.flows[flow]["proto"] == "DNS":
          try:
            # check to ensure we parse DNS/UDP only for now
            if "buf" in self.report.parsed.flows[flow]:
              dns = dpkt.dns.DNS(self.report.parsed.flows[flow].buf)
              anlist = []
              for entry in dns.an:
                anlist.append(objdict({
                  "cls": entry["cls"],
                  "cls_verbose": ancls[entry["cls"]] if entry["cls"] in ancls else None,
                  "name": entry["name"],
                  "rdata": socket.inet_ntoa(entry["rdata"]) if entry["type"] == 1 else entry["rdata"],
                  "ttl": entry["ttl"],
                  "type": entry["type"],
                  "type_verbose": antypes[entry["type"]] if entry["type"] in antypes else None
                }))
              qdlist = []
              for entry in dns.qd:
                qdlist.append(objdict({
                  "cls": entry["cls"],
                  "name": entry["name"],
                  "data": entry["data"],
                  "type": entry["type"],
                }))
              arlist = []
              for entry in dns.ar:
                arlist.append(objdict({
                  "cls": entry["cls"],
                  "name": entry["name"],
                  "rdata": entry["rdata"],
                  "ttl": entry["ttl"],
                  "type": entry["type"],
                }))
              nslist = []
              for entry in dns.ns:
                nslist.append(objdict({
                  "cls": entry["cls"],
                  "cls_verbose": ancls[entry["cls"]] if entry["cls"] in ancls else None,
                  "name": entry["name"],
                  "rdata": entry["rdata"],
                  "ttl": entry["ttl"],
                  "type": entry["type"],
                  "type_verbose": antypes[entry["type"]] if entry["type"] in antypes else None
                }))
              flags = []
              if dns.op & dpkt.dns.DNS_CD == dpkt.dns.DNS_CD:      # checking disabled
                flags.append("CHECKING_DISABLED")
              if dns.op & dpkt.dns.DNS_AD == dpkt.dns.DNS_AD:      # authenticated data
                flags.append("AUTHENTICATED_DATA")
              if dns.op & dpkt.dns.DNS_Z == dpkt.dns.DNS_Z:       # unused
                flags.append("ZERO_UNUSED")
              if dns.op & dpkt.dns.DNS_RA == dpkt.dns.DNS_RA:      # recursion available
                flags.append("RECURSION_AVAILABLE")
              if dns.op & dpkt.dns.DNS_RD == dpkt.dns.DNS_RD:      # recursion desired
                flags.append("RECURSION_DESIRED")
              if dns.op & dpkt.dns.DNS_TC == dpkt.dns.DNS_TC:      # truncated
                flags.append("TRUNCATED")
              if dns.op & dpkt.dns.DNS_AA == dpkt.dns.DNS_AA:      # authoritative answer
                flags.append("AUTHORITATIVE_ANSWER")
              self.report.parsed.flows[flow]["l7protocoldecode"] = objdict({
                "an": anlist,
                "ar": arlist,
                "data": dns.data,
                "id": dns.id,
                "ns": nslist,
                "flags": dns.op,
                "flags_verbose": flags,
                "opcode": dns.opcode,
                "opcode_verbose": opcodes[dns.opcode] if dns.opcode in opcodes else None,
                "qd": qdlist,
                "qr": dns.qr,
                "qr_verbose": dnstype[dns.qr] if dns.qr in dnstype else None,
                "rcode": dns.rcode,
                "rcode_verbose": rcodes[dns.rcode] if dns.rcode in rcodes else None,
              })
          except Exception as ex:
            self.report.indicators.warnings.append("%s: %s" % (flow, ex))
            warn('Exception: %s: %s' % (flow, ex))

        elif self.report.parsed.flows[flow]["proto"] == "HTTP":
          try:
            httpreq = dpkt.http.Request(self.report.parsed.flows[flow].ctsbuf) if self.report.parsed.flows[flow].ctsbuf else None
            httpres = dpkt.http.Response(self.report.parsed.flows[flow].stcbuf) if self.report.parsed.flows[flow].stcbuf else None
            self.report.parsed.flows[flow]["l7protocoldecode"] = objdict({
              "request": None,
              "response": None
            })
            if httpreq:
              self.report.parsed.flows[flow].l7protocoldecode.request = objdict({
                  "method": httpreq.method,
                  "uri": httpreq.uri,
                  "version": httpreq.version,
                  "headers": httpreq.headers,
                  "data": httpreq.data,
                  "body": httpreq.body
                })
            if httpres:
              self.report.parsed.flows[flow].l7protocoldecode.response = objdict({
                  "status": httpres.status,
                  "reason": httpres.reason,
                  "version": httpres.version,
                  "headers": httpres.headers,
                  "data": httpres.data,
                  "body": httpres.body
                })
            # decode chunked encoding
            if self.report.parsed.flows[flow]["l7protocoldecode"]["request"] and "transfer-encoding" in self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"]:
              for header in self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"].keys():
                if type(self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"][header]) is str and re.search(r"chunked", self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"][header], re.IGNORECASE):
                  if len(self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["body"]) > 0:
                    self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["decodedbody"] = expand_chunked(self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["body"])
            if self.report.parsed.flows[flow]["l7protocoldecode"]["response"] and "transfer-encoding" in self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"]:
              for header in self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"].keys():
                if type(self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"][header]) is str and re.search(r"chunked", self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"][header], re.IGNORECASE):
                  if len(self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["body"]) > 0:
                    self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["decodedbody"] = expand_chunked(self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["body"])
            # decode gzip content
            if self.report.parsed.flows[flow]["l7protocoldecode"]["request"] and "content-encoding" in self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"]:
              for header in self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"].keys():
                if type(self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"][header]) is str and re.search(r"gzip", self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"][header], re.IGNORECASE):
                  if "decodedbody" in self.report.parsed.flows[flow]["l7protocoldecode"]["request"]:
                    self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["decodedbody"] = expand_gzip(self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["decodedbody"])
                  else:
                    self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["decodedbody"] = expand_gzip(self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["body"])
            if self.report.parsed.flows[flow]["l7protocoldecode"]["response"] and "content-encoding" in self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"]:
              for header in self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"].keys():
                try:
                  if type(self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"][header]) is str and re.search(r"gzip", self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"][header], re.IGNORECASE):
                    if "decodedbody" in self.report.parsed.flows[flow]["l7protocoldecode"]["response"]:
                      self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["decodedbody"] = expand_gzip(self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["decodedbody"])
                    else:
                      self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["decodedbody"] = expand_gzip(self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["body"])
                except TypeError as ex:
                  self.report.indicators.warnings.append("%s: %s" % (flow, ex))
                  warn('Exception: %s: %s' % (flow, ex))

            # decode deflate content
            if self.report.parsed.flows[flow]["l7protocoldecode"]["request"] and "content-encoding" in self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"]:
              for header in self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"].keys():
                if type(self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"][header]) is str and re.search(r"deflate", self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["headers"][header], re.IGNORECASE):
                  if "decodedbody" in self.report.parsed.flows[flow]["l7protocoldecode"]["request"]:
                    self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["decodedbody"] = expand_deflate(self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["decodedbody"])
                  else:
                    self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["decodedbody"] = expand_deflate(self.report.parsed.flows[flow]["l7protocoldecode"]["request"]["body"])
            if self.report.parsed.flows[flow]["l7protocoldecode"]["response"] and "content-encoding" in self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"]:
              for header in self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"].keys():
                try:
                  if type(self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"][header]) is str and re.search(r"deflate", self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["headers"][header], re.IGNORECASE):
                    if "decodedbody" in self.report.parsed.flows[flow]["l7protocoldecode"]["response"]:
                      self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["decodedbody"] = expand_deflate(self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["decodedbody"])
                    else:
                      self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["decodedbody"] = expand_deflate(self.report.parsed.flows[flow]["l7protocoldecode"]["response"]["body"])
                except TypeError as ex:
                  self.report.indicators.warnings.append("%s: %s" % (flow, ex))
                  warn('Exception: %s: %s' % (flow, ex))
          except dpkt.dpkt.NeedData as ex:
            self.report.indicators.warnings.append("%s: %s" % (flow, ex))
            warn('Exception: %s: %s' % (flow, ex))
          except Exception as ex:
            self.report.indicators.warnings.append("%s: %s" % (flow, ex))
            warn('Exception: %s: %s' % (flow, ex))

    # scan with regexes
    if self.config.sigregex and is_file(self.config.sigregex):
      regexes = file_json_open(self.config.sigregex)
      for flow in self.report.parsed.flows:
        self.report.parsed.flows[flow].regex = objdict({})
        self.report.parsed.flows[flow].regex.cts = None
        self.report.parsed.flows[flow].regex.stc = None
        if hasattr(self.report.parsed.flows[flow], "ctsbuf") and self.report.parsed.flows[flow].ctsbuf:
          for entry in regexes.keys():
            match = re.match(r"%s" % (regexes[entry]["pattern"]), self.report.parsed.flows[flow].ctsbuf, re.DOTALL|re.MULTILINE|re.UNICODE)
            if match:
              if not self.report.parsed.flows[flow].shellcode.cts:
                self.report.parsed.flows[flow].shellcode.cts = [objdict({
                  "name": entry,
                  "description": regexes[entry]["description"],
                  "score": regexes[entry]["score"],
                  "start": match.start(),
                  "end": match.end()
                })]
              else:
                self.report.parsed.flows[flow].shellcode.cts.append({
                  "name": entry,
                  "description": regexes[entry]["description"],
                  "score": regexes[entry]["score"],
                  "start": match.start(),
                  "end": match.end()
                })
        if hasattr(self.report.parsed.flows[flow], "stcbuf") and self.report.parsed.flows[flow].stcbuf:
          for entry in regexes.keys():
            match = re.match(r"%s" % (regexes[entry]["pattern"]), self.report.parsed.flows[flow].stcbuf, re.DOTALL|re.MULTILINE|re.UNICODE)
            if match:
              if not self.report.parsed.flows[flow].shellcode.stc:
                self.report.parsed.flows[flow].shellcode.stc = [objdict({
                  "name": entry,
                  "description": regexes[entry]["description"],
                  "score": regexes[entry]["score"],
                  "start": match.start(),
                  "end": match.end()
                })]
              else:
                self.report.parsed.flows[flow].shellcode.stc.append({
                  "name": entry,
                  "description": regexes[entry]["description"],
                  "score": regexes[entry]["score"],
                  "start": match.start(),
                  "end": match.end()
                })

    # scan with libemu
    if self.config.enableshellcode:
      for flow in self.report.parsed.flows:
        self.report.parsed.flows[flow].shellcode = objdict({})
        self.report.parsed.flows[flow].shellcode.cts = None
        self.report.parsed.flows[flow].shellcode.stc = None
        if hasattr(self.report.parsed.flows[flow], "ctsbuf") and self.report.parsed.flows[flow].ctsbuf:
          try:
            e = pylibemu.Emulator()
            offset = e.shellcode_getpc_test(self.report.parsed.flows[flow].ctsbuf)
            e.test()
            profile = e.emu_profile_output
            if profile:
              self.report.parsed.flows[flow].shellcode.cts = {
                "offset": offset,
                "profile": profile
              }
          except Exception as ex:
            self.report.indicators.warnings.append("%s" % ex)
            warn("Could not scan with libemu: %s: %s" % (flow, ex))
        if hasattr(self.report.parsed.flows[flow], "stcbuf") and self.report.parsed.flows[flow].stcbuf:
          try:
            e = pylibemu.Emulator()
            offset = e.shellcode_getpc_test(self.report.parsed.flows[flow].stcbuf)
            e.test()
            profile = e.emu_profile_output
            if profile:
              self.report.parsed.flows[flow].shellcode.stc = {
                "offset": offset,
                "profile": profile
              }
          except Exception as ex:
            self.report.indicators.warnings.append("%s" % ex)
            warn("Could not scan with libemu: %s: %s" % (flow, ex))

    # scan with yara
    if self.config.enableyara:
      if self.config.signatures.yara and is_file(self.config.signatures.yara):
        for flow in self.report.parsed.flows:
          self.report.parsed.flows[flow].yara = objdict({})
          self.report.parsed.flows[flow].yara.cts = None
          self.report.parsed.flows[flow].yara.stc = None
          if hasattr(self.report.parsed.flows[flow], "ctsbuf") and self.report.parsed.flows[flow].ctsbuf:
            try:
              matches = []#yara.compile(self.config.signatures.yara).match(data=self.report.parsed.flows[flow].ctsbuf)
              if matches:
                self.report.parsed.flows[flow].yara.cts = []
                for match in matches:
                  self.report.parsed.flows[flow].yara.cts.append({
                    "rule": match.rule,
                    "meta": match.meta,
                    "namespace": match.namespace,
                    "tags": match.tags
                  })
            except yara.SyntaxError as ex:
              self.report.indicators.warnings.append("%s" % ex)
              warn("Could not scan with yara: %s: %s" % (flow, ex))
          if hasattr(self.report.parsed.flows[flow], "stcbuf") and self.report.parsed.flows[flow].stcbuf:
            try:
              matches = yara.compile(self.config.signatures.yara).match(data=self.report.parsed.flows[flow].stcbuf)
              if matches:
                self.report.parsed.flows[flow].yara.stc = []
                for match in matches:
                  self.report.parsed.flows[flow].yara.stc.append({
                    "rule": match.rule,
                    "meta": match.meta,
                    "namespace": match.namespace,
                    "tags": match.tags
                  })
            except yara.SyntaxError as ex:
              self.report.indicators.warnings.append("%s" % ex)
              warn("Could not scan with yara: %s: %s" % (flow, ex))

    # change the structure of flows key in report dict
    flows = []
    for flow in self.report.parsed.flows:
      if "tcpsport" in self.report.parsed.flows[flow].keys():
        proto = "TCP"
        sport = self.report.parsed.flows[flow].tcpsport
        dport = self.report.parsed.flows[flow].tcpdport
        protobuf = {
          "ctsbuf": self.report.parsed.flows[flow].ctsbuf if "ctsbuf" in self.report.parsed.flows[flow] and self.report.parsed.flows[flow]["ctsbuf"] else None,
          "stcbuf": self.report.parsed.flows[flow].stcbuf if "stcbuf" in self.report.parsed.flows[flow] and self.report.parsed.flows[flow]["stcbuf"] else None
        }

      if "udpsport" in self.report.parsed.flows[flow].keys():
        proto = "UDP"
        sport = self.report.parsed.flows[flow].udpsport
        dport = self.report.parsed.flows[flow].udpdport
        protobuf = {
          "udpbuf": self.report.parsed.flows[flow].buf if "buf" in self.report.parsed.flows[flow] and self.report.parsed.flows[flow].buf else None,
        }

      flows.append({
        "flowid": self.report.parsed.flows[flow].id,
        "srcip": self.report.parsed.flows[flow].ipsrc,
        "dstip": self.report.parsed.flows[flow].ipdst,
        "srcport": sport,
        "dstport": dport,
        "l4protocol": proto,
        "l7protocol": self.report.parsed.flows[flow].proto,
        "l7protocoldecode": self.report.parsed.flows[flow].l7protocoldecode if "l7protocoldecode" in self.report.parsed.flows[flow] else None,
        "protobuf": protobuf,
        "scan": {
          "regex": self.report.parsed.flows[flow].regex,
          "shellcode": self.report.parsed.flows[flow].shellcode if "shellcode" in self.report.parsed.flows[flow] else None,
          "yara": self.report.parsed.flows[flow].yara if "yara" in self.report.parsed.flows[flow] else None
        },
        "stats": self.report.parsed.flows[flow].stats
      })

    # update report with newly structured flows
    self.report.parsed.flows = flows

    # normalize dict to have a consistent representation of empty/uninitialized values
    self.report = dict_normalize(self.report)

  def handleIPStream(self, pkt):
    self.report.parsed.counts.ippackets += 1

    totalflows = 0
    for i in self.report.parsed.flows:
      totalflows += 1

    iphdr = struct.unpack('!BBHHHBBH4s4s', pkt[:20])
    ipversion = iphdr[0] >> 4
    ipihl = iphdr[0] & 0xF
    ipihl *= 4
    iptos = iphdr[1]
    iptotallen = iphdr[2]
    ipid = iphdr[3]
    ipttl = iphdr[5]
    ipproto = iphdr[6]
    ipsrc = socket.inet_ntoa(iphdr[8])
    ipdst = socket.inet_ntoa(iphdr[9])

    if ipproto == self.config.ipproto.tcp:
      tcphdr = struct.unpack('!HHLLBBHHH', pkt[ipihl:ipihl+20])
      tcpsport = tcphdr[0]
      tcpdport = tcphdr[1]
      tcpseq = tcphdr[2]
      tcpack = tcphdr[3]
      tcpoffset = tcphdr[4] >> 4
      tcphl = tcpoffset * 4
      tcpflags = tcphdr[5]
      tcpwindow = tcphdr[6]
      tcpchksum = tcphdr[7]
      tcpurgptr = tcphdr[8]

      data = pkt[ipihl+tcphl:]

      tcpflagsstr = []
      if tcpflags & 1 == 1: tcpflagsstr.append('F')
      if tcpflags & 2 == 2: tcpflagsstr.append('S')
      if tcpflags & 4 == 4: tcpflagsstr.append('R')
      if tcpflags & 8 == 8: tcpflagsstr.append('P')
      if tcpflags & 16 == 16: tcpflagsstr.append('A')
      if tcpflags & 32 == 32: tcpflagsstr.append('U')
      tcpflagsstr = "".join(tcpflagsstr)

      fivetuple = '%s:%s - %s:%s - TCP' % (ipsrc, tcpsport, ipdst, tcpdport)
      revfivetuple = '%s:%s - %s:%s - TCP' % (ipdst, tcpdport, ipsrc, tcpsport)

      if fivetuple not in self.report.parsed.flows and revfivetuple not in self.report.parsed.flows:
        self.report.parsed.flows[fivetuple] = objdict({})
        self.report.parsed.flows[fivetuple].id = totalflows+1
        self.report.parsed.flows[fivetuple].ipsrc = ipsrc
        self.report.parsed.flows[fivetuple].ipdst = ipdst
        self.report.parsed.flows[fivetuple].tcpsport = tcpsport
        self.report.parsed.flows[fivetuple].tcpdport = tcpdport
        self.report.parsed.flows[fivetuple].proto = None
        self.report.parsed.flows[fivetuple].ctsbuflen = None
        self.report.parsed.flows[fivetuple].stcbuflen = None
        debug('[IP#%d.TCP#%d] %s:%s - %s:%s (Flags:%s, Length:%dB)' % (self.report.parsed.counts.ippackets, self.report.parsed.flows[fivetuple]['id'], ipsrc, tcpsport, ipdst, tcpdport, tcpflagsstr, len(data)))

      else:
        if fivetuple in self.report.parsed.flows:
          debug('[IP#%d.TCP#%d] %s:%s - %s:%s (Flags:%s, Length:%dB)' % (self.report.parsed.counts.ippackets, self.report.parsed.flows[fivetuple]['id'], ipsrc, tcpsport, ipdst, tcpdport, tcpflagsstr, len(data)))

        elif revfivetuple in self.report.parsed.flows:
          debug('[IP#%d.TCP#%d] %s:%s - %s:%s (Flags:%s, Length:%dB)' % (self.report.parsed.counts.ippackets, self.report.parsed.flows[revfivetuple]['id'], ipsrc, tcpsport, ipdst, tcpdport, tcpflagsstr, len(data)))

    elif ipproto == self.config.ipproto.udp:
      udphdr = struct.unpack('!HHHH', pkt[ipihl:ipihl+8])
      udpsport = udphdr[0]
      udpdport = udphdr[1]
      udplen = udphdr[2]

      data = pkt[ipihl+8:]

      fivetuple = '%s:%s - %s:%s - UDP' % (ipsrc, udpsport, ipdst, udpdport)
      revfivetuple = '%s:%s - %s:%s - UDP' % (ipdst, udpdport, ipsrc, udpsport)

      if fivetuple not in self.report.parsed.flows and revfivetuple not in self.report.parsed.flows:
        self.report.parsed.flows[fivetuple] = objdict({})
        self.report.parsed.flows[fivetuple].id = totalflows+1
        self.report.parsed.flows[fivetuple].ipsrc = ipsrc
        self.report.parsed.flows[fivetuple].ipdst = ipdst
        self.report.parsed.flows[fivetuple].udpsport = udpsport
        self.report.parsed.flows[fivetuple].udpdport = udpdport
        self.report.parsed.flows[fivetuple].proto = None
        self.report.parsed.flows[fivetuple].buflen = None
        debug('[IP#%d.UDP#%d] %s:%s - %s:%s (Length:%dB)' % (self.report.parsed.counts.ippackets, self.report.parsed.flows[fivetuple]['id'], ipsrc, udpsport, ipdst, udpdport, len(data)))

      else:
        if fivetuple in self.report.parsed.flows:
          debug('[IP#%d.UDP#%d] %s:%s - %s:%s (Length:%dB)' % (self.report.parsed.counts.ippackets, self.report.parsed.flows[fivetuple]['id'], ipsrc, udpsport, ipdst, udpdport, len(data)))

        elif revfivetuple in self.report.parsed.flows:
          debug('[IP#%d.UDP#%d] %s:%s - %s:%s (Length:%dB)' % (self.report.parsed.counts.ippackets, self.report.parsed.flows[revfivetuple]['id'], ipsrc, udpsport, ipdst, udpdport, len(data)))

    if ipsrc not in self.report.parsed.hosts.keys():
      self.report.parsed.hosts[ipsrc] = objdict({})
      self.report.parsed.hosts[ipsrc].whois = None
      self.report.parsed.hosts[ipsrc].whois_text = None
      self.report.parsed.hosts[ipsrc].geo = None
      self.report.parsed.hosts[ipsrc].rdns = None

      if not utilitybelt.is_rfc1918(ipsrc) and not utilitybelt.is_reserved(ipsrc):
        if self.config.enablewhoislookup:
          debug('Invoking whois module for ipsrc %s' % ipsrc)
          ipwhois = IPWhois(ipsrc)

          try:
            self.report.parsed.hosts[ipsrc].whois = ipwhois.lookup_whois()
            #self.report.parsed.hosts[ipsrc].whois_text = ipwhois.get_whois()
          except Exception as ex:
            self.report.indicators.warnings.append("%s: %s" % (ipsrc, ex))
            warn('Exception: %s' % (ex))
            self.report.parsed.hosts[ipsrc].whois = None
            self.report.parsed.hosts[ipsrc].whois_text = None
        else:
          self.report.parsed.hosts[ipsrc].whois = None
          self.report.parsed.hosts[ipsrc].whois_text = None

        if self.config.enablegeoloc:
          debug('Invoking geoloc module for ipsrc %s' % ipsrc)
          try:
            self.report.parsed.hosts[ipsrc].geo = utilitybelt.ip_to_geo(ipsrc)
          except Exception as ex:
            self.report.indicators.warnings.append("%s: %s" % (ipsrc, ex))
            warn('Exception: %s' % (ex))
            self.report.parsed.hosts[ipsrc].geo = None
        else:
          self.report.parsed.hosts[ipsrc].geo = None

        if self.config.enablereversedns:
          try:
            debug('Invoking reversedns lookup for ipdst %s' % ipsrc)
            rdns = apis.dnslg_dnslookup(ipsrc)
            if rdns["success"]:
              self.report.parsed.hosts[ipsrc].rdns = rdns["answers"]
            else:
              self.report.parsed.hosts[ipsrc].rdns = None
          except Exception as ex:
            self.report.indicators.warnings.append("%s: %s" % (ipsrc, ex))
            warn('Exception: %s' % (ex))
            self.report.parsed.hosts[ipsrc].rdns = None
        else:
          self.report.parsed.hosts[ipsrc].rdns = None

    if ipdst not in self.report.parsed.hosts.keys():
      self.report.parsed.hosts[ipdst] = objdict({})
      self.report.parsed.hosts[ipdst].whois = None
      self.report.parsed.hosts[ipdst].whois_text = None
      self.report.parsed.hosts[ipdst].geo = None
      self.report.parsed.hosts[ipdst].rdns = None

      if not utilitybelt.is_rfc1918(ipdst) and not utilitybelt.is_reserved(ipdst):
        if self.config.enablewhoislookup:
          debug('Invoking whois module for ipdst %s' % ipdst)
          ipwhois = IPWhois(ipdst)
          try:
            self.report.parsed.hosts[ipdst].whois = ipwhois.lookup_whois()
            #self.report.parsed.hosts[ipdst].whois_text = ipwhois.get_whois()
          except Exception as ex:
            self.report.indicators.warnings.append("%s: %s" % (ipdst, ex))
            warn('Exception: %s' % (ex))
            self.report.parsed.hosts[ipdst].whois = None
            self.report.parsed.hosts[ipdst].whois_text = None
        else:
          self.report.parsed.hosts[ipdst].whois = None
          self.report.parsed.hosts[ipdst].whois_text = None

        if self.config.enablegeoloc:
          debug('Invoking geoloc module for ipdst %s' % ipdst)
          try:
            self.report.parsed.hosts[ipdst].geo = utilitybelt.ip_to_geo(ipdst)
          except Exception as ex:
            self.report.indicators.warnings.append("%s: %s" % (ipdst, ex))
            warn('Exception: %s' % (ex))
            self.report.parsed.hosts[ipdst].geo = None
        else:
          self.report.parsed.hosts[ipdst].geo = None

      if self.config.enablereversedns:
        try:
          debug('Invoking reversedns lookup for ipdst %s' % ipdst)
          rdns = apis.dnslg_dnslookup(ipdst)
          if rdns["success"]:
            self.report.parsed.hosts[ipdst].rdns = rdns["answers"]
          else:
            self.report.parsed.hosts[ipdst].rdns = None
        except Exception as ex:
          self.report.indicators.warnings.append("%s: %s" % (ipdst, ex))
          warn('Exception: %s' % (ex))
          self.report.parsed.hosts[ipdst].rdns = None
      else:
        self.report.parsed.hosts[ipdst].rdns = None

  def handleUDPStream(self, addr, payload, pkt):
    ((ipsrc, udpsport), (ipdst, udpdport)) = addr
    fivetuple = '%s:%s - %s:%s - UDP' % (ipsrc, udpsport, ipdst, udpdport)
    revfivetuple = '%s:%s - %s:%s - UDP' % (ipdst, udpdport, ipsrc, udpsport)

    if fivetuple in self.report.parsed.flows:
      tuplekey = fivetuple
    else:
      tuplekey = revfivetuple

    self.report.parsed.counts.udppackets += 1
    self.report.parsed.counts.udpbytes += len(payload)
    self.report.parsed.flows[tuplekey].buf = payload
    self.report.parsed.flows[tuplekey].buflen = len(payload)

    if not self.report.parsed.flows[tuplekey].proto and self.report.parsed.flows[tuplekey].buflen:
      debug('[IP#%d.UDP#%d] Invoking protocol identification upon data (%s)' % (
        self.report.parsed.counts.ippackets,
        self.report.parsed.flows[tuplekey].id,
        size_string(self.report.parsed.flows[tuplekey].buflen)))

      self.report.parsed.flows[tuplekey].proto = ProtoID().identify(udpbuf=self.report.parsed.flows[tuplekey].buf, udpport=udpdport)

  def handleTCPStream(self, tcp):
    ((ipsrc, tcpsport), (ipdst, tcpdport)) = tcp.addr
    fivetuple = '%s:%s - %s:%s - TCP' % (ipsrc, tcpsport, ipdst, tcpdport)
    revfivetuple = '%s:%s - %s:%s - TCP' % (ipdst, tcpdport, ipsrc, tcpsport)

    if fivetuple in self.report.parsed.flows:
      tuplekey = fivetuple
    else:
      tuplekey = revfivetuple

    if tcp.nids_state == nids.NIDS_JUST_EST:
      tcp.server.collect = 1
      tcp.client.collect = 1
      self.report.parsed.counts.tcpsessions += 1
      self.report.parsed.flows[tuplekey].ctsbuf = None
      self.report.parsed.flows[tuplekey].ctsbuflen = 0
      self.report.parsed.flows[tuplekey].stcbuf = None
      self.report.parsed.flows[tuplekey].stcbuflen = 0

    elif tcp.nids_state == nids.NIDS_DATA:
      tcp.discard(0)

      # process CTS request
      if tcp.server.count_new > 0:
        self.report.parsed.flows[tuplekey].ctsbuf = tcp.server.data[0:tcp.server.count]
        self.report.parsed.flows[tuplekey].ctsbuflen = len(self.report.parsed.flows[tuplekey].ctsbuf)
        self.report.parsed.counts.ctspackets += 1
        self.report.parsed.counts.ctsbytes += tcp.server.count_new
        self.report.parsed.counts.ctsbytesperpacket = self.report.parsed.counts.ctsbytes / self.report.parsed.counts.ctspackets
        self.report.parsed.counts.tcppackets += 1
        self.report.parsed.counts.tcpbytes += tcp.server.count_new

        if self.report.parsed.flows[tuplekey].ctsbuflen > 0:
          # if proto for this session is unknown and we have data
          if not self.report.parsed.flows[tuplekey].proto:
            debug('[IP#%d.TCP#%d] Invoking protocol identification upon CTS data (%s)' % (
              self.report.parsed.counts.ippackets,
              self.report.parsed.flows[tuplekey].id,
              size_string(self.report.parsed.flows[tuplekey].ctsbuflen)))
            self.report.parsed.flows[tuplekey].proto = ProtoID().identify(ctsbuf=self.report.parsed.flows[tuplekey].ctsbuf, tcpport=tcpdport)
          # else skip protoid and continue
          else:
            debug('[IP#%d.TCP#%d] Received %s of %s CTS data (Total: %s)' % (
              self.report.parsed.counts.ippackets,
              self.report.parsed.flows[tuplekey].id,
              size_string(tcp.server.count_new),
              self.report.parsed.flows[tuplekey].proto,
              size_string(self.report.parsed.flows[tuplekey].ctsbuflen)))

      # process STC request
      if tcp.client.count_new > 0:
        self.report.parsed.flows[tuplekey].stcbuf = tcp.client.data[0:tcp.client.count]
        self.report.parsed.flows[tuplekey].stcbuflen = len(self.report.parsed.flows[tuplekey].stcbuf)
        self.report.parsed.counts.stcpackets += 1
        self.report.parsed.counts.stcbytes += tcp.client.count_new
        self.report.parsed.counts.stcbytesperpacket = self.report.parsed.counts.stcbytes / self.report.parsed.counts.stcpackets
        self.report.parsed.counts.tcppackets += 1
        self.report.parsed.counts.tcpbytes += tcp.client.count_new

        if self.report.parsed.flows[tuplekey].stcbuflen > 0:
          # if proto for this session is unknown and we have data
          if not self.report.parsed.flows[tuplekey].proto:
            debug('[IP#%d.TCP#%d] Invoking protocol identification upon STC data (%s)' % (
              self.report.parsed.counts.ippackets,
              self.report.parsed.flows[tuplekey].id,
              size_string(self.report.parsed.flows[tuplekey].stcbuflen)))
            self.report.parsed.flows[tuplekey].proto = ProtoID().identify(stcbuf=self.report.parsed.flows[tuplekey].stcbuf, tcpport=tcpdport)
          # else skip protoid and continue
          else:
            debug('[IP#%d.TCP#%d] Received %s of %s STC data (Total: %s)' % (
              self.report.parsed.counts.ippackets,
              self.report.parsed.flows[tuplekey].id,
              size_string(tcp.client.count_new),
              self.report.parsed.flows[tuplekey].proto,
              size_string(self.report.parsed.flows[tuplekey].stcbuflen)))

      self.report.parsed.counts.tcpbytesperpacket = self.report.parsed.counts.tcpbytes / self.report.parsed.counts.tcppackets

    elif tcp.nids_state in (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET):
      debug('Found TCP closing sequence for session %s' % tuplekey)
      tcp.server.collect = 0
      tcp.client.collect = 0

