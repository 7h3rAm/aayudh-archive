# -*- coding: utf-8 -*-

import re
import logging.config

import pygal
from pygal import Config
from pygal.style import LightColorizedStyle, RedBlueStyle, CleanStyle

import yara
import pylibemu

from external import utilitybelt
import utils


class Scanner:
  def __init__(self, config={}):
    self.logger = logging.getLogger(__name__)

    self.config = config
    self.online_reports = {
      "AlienVault": "http://www.alienvault.com/apps/rep_monitor/ip/{{host}}",
      "Fortiguard": "http://www.fortiguard.com/ip_rep/index.php?data={{host}}&lookup=Lookup",
      "FreeGeoIP": "http://freegeoip.net/json/{{host}}",
      "IP-API": "http://ip-api.com/#{{host}}",
      "IPVoid": "http://www.ipvoid.com/scan/{{host}}",
      "MalwareDomainList": "http://www.malwaredomainlist.com/mdl.php?search={{host}}&colsearch=All&quantity=50",
      "Robtex": "https://robtex.com/{{host}}",
      "VirusTotal": "https://www.virustotal.com/en/ip-address/{{host}}/information/",
      "Google Safe Browsing": "http://safebrowsing.clients.google.com/safebrowsing/diagnostic?site={{host}}",
      "Arin Whois": "http://whois.arin.net/rest/nets;q={{host}}?showDetails=true",
      "Yandex": "https://yandex.com/infected?l10n=en&url={{host}}",
      "URLVoid": "http://www.urlvoid.com/ip/{{host}}",
      "Mnemonic PDNS": "http://passivedns.mnemonic.no/search/?query={{host}}&method=exact",
      "BGP HE": "http://bgp.he.net/ip/{{host}}"
    }

    self.regexes = {
      "info": {
        #0: {
        #  "regex": re.compile(r"\w{10}", re.I | re.S | re.M),
        #  "description": "TEST/IGNORE"
        #},
        100: {
          "regex": re.compile(r"((https?|ftps?|gopher|telnet|file|notes|ms-help):((//)|(\\\\))+[\w\d:#@%/;$()~_?\+-=\\\.&]*)", re.I | re.S | re.M),
          "description": "Detects a URL over HTTP, HTTPS, FTP, Gopher, Telnet, File, Notes, MS-Help"
        },
        #101: {
        #  "regex": re.compile(r"(https?:\/\/)?(www.)?(youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/watch\?feature=player_embedded&v=)([A-Za-z0-9_-]*)(\&\S+)?(\?\S+)?", re.I | re.S | re.M),
        #  "description": "Detects YouTube links"
        #},
        #102: {
        #  "regex": re.compile(r"https?:\/\/(www.)?vimeo\.com\/([A-Za-z0-9._%-]*)((\?|#)\S+)?", re.I | re.S | re.M),
        #  "description": "Detects Vimeo links"
        #},
        105: {
          "regex": re.compile(r"\W([\w-]+\.)(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt)", re.I | re.S | re.M),
          "description": "Detects MS Office filenames via extension"
        },
        106: {
          "regex": re.compile(r"\W([\w-]+\.)(html|php|js)", re.I | re.S | re.M),
          "description": "Detects HTML, PHP or JS filenames via extension"
        },
        #107: {
        #  "regex": re.compile(r"\W([\w-]+\.)(exe|dll|jar)", re.I | re.S | re.M),
        #  "description": "Detects EXE, DLL or JAR filenames via extension"
        #},
        108: {
          "regex": re.compile(r"\W([\w-]+\.)(zip|zipx|7z|rar|tar|gz)", re.I | re.S | re.M),
          "description": "Detects ZIP, ZIPX, 7Z, RAR, TAR or GZ archive filenames via extension"
        },
        109: {
          "regex": re.compile(r"\W([\w-]+\.)(jpeg|jpg|gif|png|tiff|bmp)", re.I | re.S | re.M),
          "description": "Detects JPEG, JPG, GIF, PNG, TIFF or BMP image filenames via extension"
        },
        110: {
          "regex": re.compile(r"\W([\w-]+\.)(flv|swf)", re.I | re.S | re.M),
          "description": "Detects FLV or SWF filenames via extension"
        },
        111: {
          "regex": re.compile(r"\\b[a-f0-9]{32}\\b", re.I | re.S | re.M),
          "description": "Detects MD5 hash strings"
        },
        112: {
          "regex": re.compile(r"\\b[a-f0-9]{40}\\b", re.I | re.S | re.M),
          "description": "Detects SHA1 hash strings"
        },
        113: {
          "regex": re.compile(r"\\b[a-f0-9]{64}\\b", re.I | re.S | re.M),
          "description": "Detects SHA256 hash strings"
        },
        114: {
          "regex": re.compile(r"\\b[a-f0-9]{128}\\b", re.I | re.S | re.M),
          "description": "Detects SHA512 hash strings"
        },
        115: {
          "regex": re.compile(r"\\b\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\\b", re.I | re.S | re.M),
          "description": "Detects SSDEEP fuzzy hash strings"
        },
        116: {
          "regex": re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', re.I | re.S | re.M),
          "description": "Detects an IPv4 address"
        },
        118: {
          "regex": re.compile('(?=^.{4,255}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', re.I | re.S | re.M),
          "description": "Detects a FQDN string"
        },
        119: {
          "regex": re.compile(r"(CVE-(19|20)\\d{2}-\\d{4,7})", re.I | re.S | re.M),
          "description": "Detects a CVE string identifier"
        },
        120: {
          "regex": re.compile(r"(((([01]? d?\\d)|(2[0-5]{2}))\\.){3}(([01]?\\d?\\d)|(2[0-5]{2})))|(([A-F0-9]){4}(:|::)){1,7}(([A-F0-9]){4})", re.I | re.S | re.M),
          "description": "Detects an IPv6 addrss"
        },
        121: {
          "regex": re.compile(r"([a-zA-Z0-9\.-_]+@)([a-zA-Z0-9-]+\.)(com|net|biz|cat|aero|asia|coop|info|int|jobs|mobi|museum|name|org|post|pre|tel|travel|xxx|edu|gov|mil|br|cc|ca|uk|ch|co|cx|de|fr|hk|jp|kr|nl|nr|ru|tk|ws|tw)\W", re.I | re.S | re.M),
          "description": "Detects an email address - 1"
        },
        122: {
          "regex": re.compile(r"(?<=^|(?<=[^a-zA-Z0-9-_\.]))(@)([A-Za-z]+[A-Za-z0-9]+){4}", re.I | re.S | re.M),
          "description": "Detects a Twitter handle"
        }
      },
      "low": {
        200: {
          "regex": re.compile(r"(\d{3}\-\d{2}\-\d{3})|(\d{3}\s\d{2}\s\d{3})", re.I | re.S | re.M),
          "description": "Detects a Social Security Number"
        },
        201: { # http://stackoverflow.com/questions/7165056/regex-to-match-email-addresses-and-common-obfuscations
          "regex": re.compile(r"^[A-Z0-9\._%+-]+(@|\s*\[\s*at\s*\]\s*)[A-Z0-9\.-]+(\.|\s*\[\s*dot\s*\]\s*)[a-z]{2,6}$", re.I | re.S | re.M),
          "description": "Detects an obfuscated email address"
        },
        202: { # https://www.sans.org/security-resources/idfaq/snort-detect-credit-card-numbers.php
          "regex": re.compile(r"4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}", re.I | re.S | re.M),
          "description": "Detects a VISA Credit Card number"
        },
        203: { # https://www.sans.org/security-resources/idfaq/snort-detect-credit-card-numbers.php
          "regex": re.compile(r"5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}", re.I | re.S | re.M),
          "description": "Detects a Master Card number"
        },
        204: { # https://www.sans.org/security-resources/idfaq/snort-detect-credit-card-numbers.php
          "regex": re.compile(r"6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}", re.I | re.S | re.M),
          "description": "Detects a Discover Credit Card number"
        },
        205: { # https://www.sans.org/security-resources/idfaq/snort-detect-credit-card-numbers.php
          "regex": re.compile(r"3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}", re.I | re.S | re.M),
          "description": "Detects an American Express Credit Card number"
        }
      },
      "medium": {
        #300: {
        #  "regex": re.compile(r"e.{0,2}v.{0,2}a.{0,2}l", re.I | re.S | re.M),
        #  "description": "Detects obfuscated calls to JavaScript eval method"
        #},
        301: {
          "regex": re.compile(r"u.{0,2}n.{0,2}e.{0,2}s.{0,2}c.{0,2}a.{0,2}p.{0,1}e", re.I | re.S | re.M),
          "description": "Detects obfuscated calls to JavaScript unescape method"
        },
        302: {
          "regex": re.compile(r"s.{0,4}u.{0,4}b.{0,4}s.{0,4}t.{0,4}r.{0,4}", re.I | re.S | re.M),
          "description": "Detects obfuscated calls to JavaScript substr method"
        },
        303: {
          "regex": re.compile(r"[zrtypqsdfghjklmwxcvbnZRTYPQSDFGHJKLMWXCVBN]{6,}", re.I | re.S | re.M),
          "description": "Detects 6 or more consecutive occurences of consonants"
        },
        304: { # https://community.emc.com/community/connect/rsaxchange/netwitness/blog/2013/03/19/detecting-malicious-and-suspicious-user-agent-strings
          "regex": re.compile(r"funwebproducts", re.I | re.S),
          "description": "Probable Funwebproduct Adware BHO generated traffic"
        },
        305: { # https://community.emc.com/community/connect/rsaxchange/netwitness/blog/2013/03/19/detecting-malicious-and-suspicious-user-agent-strings
          "regex": re.compile(r"(maar|btrs|searchtoolbar|fctb|cpntdf|talwinhttpclient|bsalsa)", re.I | re.S),
          "description": "Probable Adware generated traffic"
        }
      },
      "high": {
        400: {
          "regex": re.compile(r"\xeb.*\x31.*\x20\x8b.*\x74\x07\xeb.*\xe8.*\xff\xff\xff", re.I | re.S | re.M),
          "description": "This regex detects presence of CLET encoded byte sequences"
        },
        401: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"((\w+)|(\W+))((<\|>)|(\\))((\w+)|(\W+))((<\|>)|(\\))((\w+)|(\W+))((<\|>)|(\\))[^<|\\]+((<\|>)|(\\))((\w+)|(\W+))[^<|\\]+((<\|>)|(\\))[^<|\\]+((\w+)|(\W+))((\w+)|(\W+))+", re.I | re.S),
          "description": "Probable Houdini/Iniduoh/njRAT malware generated traffic"
        },
        402: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"nsis_inetc\s\(mozilla\)", re.I | re.S),
          "description": "Probable Zero Access malware generated traffic"
        },
        403: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"Mozilla\/5\.0\sWinInet", re.I | re.S),
          "description": "Probable Generic Trojan generated traffic"
        },
        404: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"Wget\/1\.9\+cvs-stable\s\(Red\sHat\smodified\)", re.I | re.S),
          "description": "Probable Dyre/Upatre malware generated traffic"
        },
        405: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"RookIE\/1\.0", re.I | re.S),
          "description": "Probable generic password stealing trojan generated traffic"
        },
        406: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"Mozilla\/4\.0\s\(compatible;\sMSIE\s8\.0;\sWindows\sNT\s5\.1;\sTrident\/4\.0\)", re.I | re.S),
          "description": "Probable Egamipload malware generated traffic"
        },
        407: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"Mozilla\/4\.0\s\(compatible;\sMSIE\s6\.0;\sWindows\sNT\s5\.1;\sSV1\)", re.I | re.S),
          "description": "Probable Botnet/Adware generated traffic"
        },
        408: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"Mozilla\/4\.0\s\(compatible;MSIE\s7\.0;Windows\sNT\s6\.0\)", re.I | re.S),
          "description": "Probable Yakes malware generated traffic"
        },
        409: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"^AutoIt$", re.I | re.S),
          "description": "Probable Tupym malware generated traffic"
        },
        410: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"^M$", re.I | re.S),
          "description": "Probable HkMain malware generated traffic"
        },
        411: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"^InetAll$", re.I | re.S),
          "description": "Probable Pennonec malware generated traffic"
        },
        412: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"Opera\/9\.80", re.I | re.S),
          "description": "Probable Andromeda malware generated traffic"
        },
        413: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"Mozilla/4\.0\s\(compatible;\sMSIE;\sWin32\)", re.I | re.S),
          "description": "Probable Bandoo adware generated traffic"
        },
        414: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"Mozilla/4\.0\s\(compatible;\sMSIE\s8\.0;\sWindows\sNT\s6\.0\)", re.I | re.S),
          "description": "Probable IRCbot malware generated traffic"
        },
        415: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"(Mozilla/5\.0\s\(compatible;\sMSIE\s9\.0;\sWindows\sNT\s7\.1;\sTrident/5\.0\)|Mozilla/5\.0\s\(Windows;\sU;\sMSIE\s7\.0;\sWindows\sNT\s6\.0;\sen-US\))", re.I | re.S),
          "description": "Probable Geodo/Feodo malware generated traffic"
        },
        416: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"Mozilla/5\.0\s\(windows\snt\s6\.1;\swow64;\srv:25\.0\)\sGecko/20100101\sfirefox/25\.0", re.I | re.S),
          "description": "Probable Kuluoz malware generated traffic"
        },
        417: { # http://networkraptor.blogspot.in/2015/01/user-agent-strings.html, http://networkraptor.blogspot.in/p/user-agent-strings.html
          "regex": re.compile(r"Mozilla/4\.0\s\(compatible;\sMSIE\s6\.0;\sWindows\sNT\s5\.1;\sSV1;\s\.NET\sCLR\s1\.0\.1(288|975)\)", re.I | re.S),
          "description": "Probable Symml malware generated traffic"
        }
      }
    }
    self.matchdict = {}


  def inspect(self, report, filetype):
    if self.config['enable_yara']:
      report = self.inspect_yara(report, filetype)

    if self.config['enable_shellcode']:
      report = self.inspect_shellcode(report, filetype)

    if self.config['enable_regex']:
      report = self.inspect_regex(report, filetype)

    if self.config['enable_heuristics']:
      report = self.inspect_heuristics(report, filetype)

    self.logger.info('Running post-inspection cleanup tasks upon report dict')
    for k in sorted(report['flows'].keys()):
      proto = k.split(' - ')[2]

      if 'currtid' in report['flows'][k].keys():
        del report['flows'][k]['currtid']

      if 'transactions' in report['flows'][k].keys() and report['flows'][k]['transactions']:
        for tid in sorted(report['flows'][k]['transactions'].keys()):
          if proto == 'UDP':
            if 'yara' not in report['flows'][k]['transactions'][tid].keys():
              report['flows'][k]['transactions'][tid]['yara'] = {
                'buf': None
              }

            if 'shellcode' not in report['flows'][k]['transactions'][tid].keys():
              report['flows'][k]['transactions'][tid]['shellcode'] = {
                'buf': None
              }

            if 'regex' not in report['flows'][k]['transactions'][tid].keys():
              report['flows'][k]['transactions'][tid]['regex'] = {
                'buf': None
              }

            if 'heuristics' not in report['flows'][k]['transactions'][tid].keys():
              report['flows'][k]['transactions'][tid]['heuristics'] = {
                'buf': None
              }

          if proto == 'TCP':
            if 'yara' not in report['flows'][k]['transactions'][tid].keys():
              report['flows'][k]['transactions'][tid]['yara'] = {
                'cts': None,
                'stc': None
              }

            if 'shellcode' not in report['flows'][k]['transactions'][tid].keys():
              report['flows'][k]['transactions'][tid]['shellcode'] = {
                'cts': None,
                'stc': None
              }

            if 'regex' not in report['flows'][k]['transactions'][tid].keys():
              report['flows'][k]['transactions'][tid]['regex'] = {
                'cts': None,
                'stc': None
              }

            if 'heuristics' not in report['flows'][k]['transactions'][tid].keys():
              report['flows'][k]['transactions'][tid]['heuristics'] = {
                'cts': None,
                'stc': None
              }


          stats = None
          if proto == 'UDP' and report['flows'][k]['transactions'][tid]['buf']:
            stats = utils.entropy_compression_stats_buf(report['flows'][k]['transactions'][tid]['buf'])
            report['flows'][k]['transactions'][tid]['bufcompressionratio'] = float(stats['compressionratio'])
            report['flows'][k]['transactions'][tid]['bufentropy'] = float(stats['shannonentropy'])

            # if entropy falls within the 0 - 1 or 7 - 8 range, categorize as suspicious
            if (report['flows'][k]['transactions'][tid]['bufentropy'] > 0 and report['flows'][k]['transactions'][tid]['bufentropy'] < 1) or report['flows'][k]['transactions'][tid]['bufentropy'] > 7:
              report['flows'][k]['transactions'][tid]['bufentropy_category'] = 'SUSPICIOUS'
            else:
              report['flows'][k]['transactions'][tid]['bufentropy_category'] = 'NORMAL'

            report['flows'][k]['transactions'][tid]['bufmindatasize'] = stats['mindatasize']

          stats = None
          if proto == 'TCP' and report['flows'][k]['transactions'][tid]['ctsbuf']:
            stats = utils.entropy_compression_stats_buf(report['flows'][k]['transactions'][tid]['ctsbuf'])
            report['flows'][k]['transactions'][tid]['ctsbufcompressionratio'] = float(stats['compressionratio'])
            report['flows'][k]['transactions'][tid]['ctsbufentropy'] = float(stats['shannonentropy'])

            # if entropy falls within the 0 - 1 or 7 - 8 range, categorize as suspicious
            if (report['flows'][k]['transactions'][tid]['ctsbufentropy'] > 0 and report['flows'][k]['transactions'][tid]['ctsbufentropy'] < 1) or report['flows'][k]['transactions'][tid]['ctsbufentropy'] > 7:
              report['flows'][k]['transactions'][tid]['ctsbufentropy_category'] = 'SUSPICIOUS'
            else:
              report['flows'][k]['transactions'][tid]['ctsbufentropy_category'] = 'NORMAL'

            report['flows'][k]['transactions'][tid]['ctsbufmindatasize'] = stats['mindatasize']

          stats = None
          if proto == 'TCP' and report['flows'][k]['transactions'][tid]['stcbuf']:
            stats = utils.entropy_compression_stats_buf(report['flows'][k]['transactions'][tid]['stcbuf'])
            report['flows'][k]['transactions'][tid]['stcbufcompressionratio'] = float(stats['compressionratio'])
            report['flows'][k]['transactions'][tid]['stcbufentropy'] = float(stats['shannonentropy'])

            # if entropy falls within the 0 - 1 or 7 - 8 range, categorize as suspicious
            if (report['flows'][k]['transactions'][tid]['stcbufentropy'] > 0 and report['flows'][k]['transactions'][tid]['stcbufentropy'] < 1) or report['flows'][k]['transactions'][tid]['stcbufentropy'] > 7:
              report['flows'][k]['transactions'][tid]['stcbufentropy_category'] = 'SUSPICIOUS'
            else:
              report['flows'][k]['transactions'][tid]['stcbufentropy_category'] = 'NORMAL'

            report['flows'][k]['transactions'][tid]['stcbufmindatasize'] = stats['mindatasize']

      for host in report['hosts'].keys():
        if utilitybelt.is_rfc1918(host) or utilitybelt.is_reserved(host):
          report['hosts'][host]['is_private'] = True
          report['hosts'][host]['online_reports'] = None
        else:
          report['hosts'][host]['is_private'] = False
          report['hosts'][host]['online_reports'] = self.online_reports
          for key, value in report['hosts'][host]['online_reports'].iteritems():
            report['hosts'][host]['online_reports'][key] = re.sub(r"{{host}}", host, value)

    return dict(report)


  def inspect_yara(self, report, filetype):
    if filetype == 'PCAP':
      self.logger.info('Loading yara rules from %s' % self.config['yara_rules_dir'])

      rulefiles = []
      rulefiles = utils.find_files(search_dir=self.config['yara_rules_dir'], regex=r"*.yar") + utils.find_files(search_dir=self.config['yara_rules_dir'], regex=r"*.yara")

      rulefiles = sorted(rulefiles)
      self.logger.debug('Found %d yara rule files in %s' % (len(rulefiles), self.config['yara_rules_dir']))

      self.logger.info('Testing all rules found in %d files over %d sessions' % (len(rulefiles), len(report['flows'].keys())))
      for k in sorted(report['flows'].keys()):
        proto = k.split(' - ')[2]

        for f in rulefiles:
          match = None
          y = yara.compile(f)

          if 'transactions' in report['flows'][k].keys() and report['flows'][k]['transactions']:
            for tid in sorted(report['flows'][k]['transactions']):
              if 'yara' not in report['flows'][k]['transactions'][tid].keys():
                if proto == 'TCP':
                  report['flows'][k]['transactions'][tid]['yara'] = {
                    'cts': None,
                    'stc': None
                  }
                elif proto == 'UDP':
                  report['flows'][k]['transactions'][tid]['yara'] = {
                    'buf': None
                  }

              if proto == 'UDP' and report['flows'][k]['transactions'][tid]['buf']:
                if self.config['inspect_udp_depth'] > 0:
                  scanbuf = report['flows'][k]['transactions'][tid]['buf'][:self.config['inspect_udp_depth']]
                else:
                  scanbuf = report['flows'][k]['transactions'][tid]['buf']

                matches = None
                try:
                  matches = y.match(
                    data=scanbuf,
                    timeout=self.config['yara_match_timeout'])
                except Exception, e:
                  pass

                if matches:
                  rulefile = f.rpartition('/')[2]
                  self.logger.debug('%s (UDP, Trans: #%d) matches %d rules from %s' % (k, tid, len(matches), rulefile))

                  for m in matches:
                    rulename = m.rule.encode('utf-8').strip()

                    if not report['flows'][k]['transactions'][tid]['yara']['buf']:
                      report['flows'][k]['transactions'][tid]['yara']['buf'] = {
                        rulefile: {
                          rulename: {
                            'tags': None,
                            'description': None,
                            'strings': None,
                            'namespace': None
                          }
                        }
                      }

                    elif rulefile not in report['flows'][k]['transactions'][tid]['yara']['buf'].keys():
                      report['flows'][k]['transactions'][tid]['yara']['buf'][rulefile] = {
                        rulename: {
                          'tags': None,
                          'description': None,
                          'strings': None,
                          'namespace': None
                        }
                      }

                    elif rulename not in report['flows'][k]['transactions'][tid]['yara']['buf'][rulefile]:
                      report['flows'][k]['transactions'][tid]['yara']['buf'][rulefile][rulename] = {
                        'tags': None,
                        'description': None,
                        'strings': None,
                        'namespace': None
                      }

                    if len(m.tags) is not 0:
                      report['flows'][k]['transactions'][tid]['yara']['buf'][rulefile][rulename]['tags'] = []
                      for tag in m.tags:
                        report['flows'][k]['transactions'][tid]['yara']['buf'][rulefile][rulename]['tags'].append(tag.upper())

                    if 'description' in m.meta.keys():
                      report['flows'][k]['transactions'][tid]['yara']['buf'][rulefile][rulename]['description'] = m.meta['description']

                    if len(m.strings) is not 0:
                      report['flows'][k]['transactions'][tid]['yara']['buf'][rulefile][rulename]['strings'] = []
                      for offset, var, val in m.strings:
                        report['flows'][k]['transactions'][tid]['yara']['buf'][rulefile][rulename]['strings'].append("Found %s @ offset 0x%x" % (var, int(offset)))

                    report['flows'][k]['transactions'][tid]['yara']['buf'][rulefile][rulename]['namespace'] = m.namespace


              if proto == 'TCP' and report['flows'][k]['transactions'][tid]['ctsbuf']:
                if self.config['inspect_cts_depth'] > 0:
                  scanbuf = report['flows'][k]['transactions'][tid]['ctsbuf'][:self.config['inspect_cts_depth']]
                else:
                  scanbuf = report['flows'][k]['transactions'][tid]['ctsbuf']

                matches = None
                try:
                  matches = y.match(
                    data=scanbuf,
                    timeout=self.config['yara_match_timeout'])
                except Exception, e:
                  pass

                if matches:
                  rulefile = f.rpartition('/')[2]
                  self.logger.debug('%s (CTS, Trans: #%d) matches %d rules from %s' % (k, tid, len(matches), rulefile))

                  for m in matches:
                    rulename = m.rule.encode('utf-8').strip()

                    if not report['flows'][k]['transactions'][tid]['yara']['cts']:
                      report['flows'][k]['transactions'][tid]['yara']['cts'] = {
                        rulefile: {
                          rulename: {
                            'tags': None,
                            'description': None,
                            'strings': None,
                            'namespace': None
                          }
                        }
                      }

                    elif rulefile not in report['flows'][k]['transactions'][tid]['yara']['cts'].keys():
                      report['flows'][k]['transactions'][tid]['yara']['cts'][rulefile] = {
                        rulename: {
                          'tags': None,
                          'description': None,
                          'strings': None,
                          'namespace': None
                        }
                      }

                    elif rulename not in report['flows'][k]['transactions'][tid]['yara']['cts'][rulefile]:
                      report['flows'][k]['transactions'][tid]['yara']['cts'][rulefile][rulename] = {
                        'tags': None,
                        'description': None,
                        'strings': None,
                        'namespace': None
                      }

                    if len(m.tags) is not 0:
                      report['flows'][k]['transactions'][tid]['yara']['cts'][rulefile][rulename]['tags'] = []
                      for tag in m.tags:
                        report['flows'][k]['transactions'][tid]['yara']['cts'][rulefile][rulename]['tags'].append(tag.upper())

                    if 'description' in m.meta.keys():
                      report['flows'][k]['transactions'][tid]['yara']['cts'][rulefile][rulename]['description'] = m.meta['description']

                    if len(m.strings) is not 0:
                      report['flows'][k]['transactions'][tid]['yara']['cts'][rulefile][rulename]['strings'] = []
                      for offset, var, val in m.strings:
                        report['flows'][k]['transactions'][tid]['yara']['cts'][rulefile][rulename]['strings'].append("Found %s @ offset 0x%x" % (var, int(offset)))

                    report['flows'][k]['transactions'][tid]['yara']['cts'][rulefile][rulename]['namespace'] = m.namespace

              if proto == 'TCP' and report['flows'][k]['transactions'][tid]['stcbuf']:
                if self.config['inspect_stc_depth'] > 0:
                  scanbuf = report['flows'][k]['transactions'][tid]['stcbuf'][:self.config['inspect_stc_depth']]
                else:
                  scanbuf = report['flows'][k]['transactions'][tid]['stcbuf']

                try:
                  matches = y.match(
                    data=scanbuf,
                    timeout=self.config['yara_match_timeout'])
                except Exception, e:
                  pass

                if matches:
                  rulefile = f.rpartition('/')[2]
                  self.logger.debug('%s (STC, Trans: #%d) matches %d rules from %s' % (k, tid, len(matches), rulefile))

                  for m in matches:
                    rulename = m.rule.encode('utf-8').strip()

                    if not report['flows'][k]['transactions'][tid]['yara']['stc']:
                      report['flows'][k]['transactions'][tid]['yara']['stc'] = {
                        rulefile: {
                          rulename: {
                            'tags': None,
                            'description': None,
                            'strings': None,
                            'namespace': None
                          }
                        }
                      }

                    elif rulefile not in report['flows'][k]['transactions'][tid]['yara']['stc'].keys():
                      report['flows'][k]['transactions'][tid]['yara']['stc'][rulefile] = {
                        rulename: {
                          'tags': None,
                          'description': None,
                          'strings': None,
                          'namespace': None
                        }
                      }

                    elif rulename not in report['flows'][k]['transactions'][tid]['yara']['stc'][rulefile]:
                      report['flows'][k]['transactions'][tid]['yara']['stc'][rulefile][rulename] = {
                        'tags': None,
                        'description': None,
                        'strings': None,
                        'namespace': None
                      }

                    if len(m.tags) is not 0:
                      report['flows'][k]['transactions'][tid]['yara']['stc'][rulefile][rulename]['tags'] = []
                      for tag in m.tags:
                        report['flows'][k]['transactions'][tid]['yara']['stc'][rulefile][rulename]['tags'].append(tag.upper())

                    if 'description' in m.meta.keys():
                      report['flows'][k]['transactions'][tid]['yara']['stc'][rulefile][rulename]['description'] = m.meta['description']

                    if len(m.strings) is not 0:
                      report['flows'][k]['transactions'][tid]['yara']['stc'][rulefile][rulename]['strings'] = []
                      for offset, var, val in m.strings:
                        report['flows'][k]['transactions'][tid]['yara']['stc'][rulefile][rulename]['strings'].append("Found %s @ offset 0x%x" % (var, int(offset)))

                    report['flows'][k]['transactions'][tid]['yara']['stc'][rulefile][rulename]['namespace'] = m.namespace

    return dict(report)


  def inspect_shellcode(self, report, filetype):
    if filetype == 'PCAP':
      self.logger.info('Invoking shellcode detection on input buffers')

      for k in sorted(report['flows'].keys()):
        proto = k.split(' - ')[2]

        if 'transactions' in report['flows'][k].keys() and report['flows'][k]['transactions']:
          for tid in sorted(report['flows'][k]['transactions']):
            if 'shellcode' not in report['flows'][k]['transactions'][tid].keys():
              if proto == 'TCP':
                report['flows'][k]['transactions'][tid]['shellcode'] = {
                  'cts': None,
                  'stc': None
                }
              elif proto == 'UDP':
                report['flows'][k]['transactions'][tid]['shellcode'] = {
                  'buf': None
                }

            if proto == 'UDP' and report['flows'][k]['transactions'][tid]['buf']:
              if self.config['inspect_udp_depth'] > 0:
                scanbuf = report['flows'][k]['transactions'][tid]['buf'][:self.config['inspect_udp_depth']]
              else:
                scanbuf = report['flows'][k]['transactions'][tid]['buf']

              e = pylibemu.Emulator()
              offset = e.shellcode_getpc_test(scanbuf)
              e.test()
              profile = e.emu_profile_output

              if profile: # shellcode found!
                self.logger.debug('%s (UDP, Trans: #%d) has shellcode @ offset %d' % (k, tid, offset))
                report['flows'][k]['transactions'][tid]['shellcode']['buf'] = {
                  'offset': offset,
                  'buf': scanbuf[offset:len(report['flows'][k]['transactions'][tid]['buf'])],
                  'profile': profile
                }

            if proto == 'TCP' and report['flows'][k]['transactions'][tid]['ctsbuf']:
              if self.config['inspect_cts_depth'] > 0:
                scanbuf = report['flows'][k]['transactions'][tid]['ctsbuf'][:self.config['inspect_cts_depth']]
              else:
                scanbuf = report['flows'][k]['transactions'][tid]['ctsbuf']

              e = pylibemu.Emulator()
              offset = e.shellcode_getpc_test(scanbuf)
              e.test()
              profile = e.emu_profile_output

              if profile: # shellcode found!
                self.logger.debug('%s (CTS, Trans: #%d) has shellcode @ offset %d' % (k, tid, offset))
                report['flows'][k]['transactions'][tid]['shellcode']['cts'] = {
                  'offset': offset,
                  'buf': scanbuf[offset:len(scanbuf)],
                  'profile': profile
                }

            if proto == 'TCP' and report['flows'][k]['transactions'][tid]['stcbuf']:
              if self.config['inspect_stc_depth'] > 0:
                scanbuf = report['flows'][k]['transactions'][tid]['stcbuf'][:self.config['inspect_stc_depth']]
              else:
                scanbuf = report['flows'][k]['transactions'][tid]['stcbuf']

              e = pylibemu.Emulator()
              offset = e.shellcode_getpc_test(scanbuf)
              e.test()
              profile = e.emu_profile_output

              if profile: # shellcode found!
                self.logger.debug('%s (STC, Trans: #%d) has shellcode @ offset %d' % (k, tid, offset))
                report['flows'][k]['transactions'][tid]['shellcode']['stc'] = {
                  'offset': offset,
                  'buf': scanbuf[offset:len(scanbuf)],
                  'profile': profile
                }

    return dict(report)


  def inspect_regex(self, report, filetype):
    if filetype == 'PCAP':
      self.logger.info('Invoking regex detection on input buffers')

      for k in sorted(report['flows'].keys()):
        proto = k.split(' - ')[2]

        if 'transactions' in report['flows'][k].keys() and report['flows'][k]['transactions']:
          for tid in sorted(report['flows'][k]['transactions']):
            if 'regex' not in report['flows'][k]['transactions'][tid].keys():
              if proto == 'TCP':
                report['flows'][k]['transactions'][tid]['regex'] = {
                  'cts': None,
                  'stc': None
                }
              elif proto == 'UDP':
                report['flows'][k]['transactions'][tid]['regex'] = {
                  'buf': None
                }

            for severity in ['info', 'low', 'medium', 'high']:
              for rid in self.regexes[severity]:

                if proto == 'UDP' and report['flows'][k]['transactions'][tid]['buf']:
                  if self.config['inspect_udp_depth'] > 0:
                    scanbuf = report['flows'][k]['transactions'][tid]['buf'][:self.config['inspect_udp_depth']]
                  else:
                    scanbuf = report['flows'][k]['transactions'][tid]['buf']

                  match = self.regexes[severity][rid]['regex'].search(scanbuf)
                  if match:
                    self.logger.info("%s (Trans: #%d) %08x: Found %s match" % (k, tid, match.start(), utils.size_string(match.end() - match.start())))

                    if 'buf' not in report['flows'][k]['transactions'][tid]['regex'].keys() or not report['flows'][k]['transactions'][tid]['regex']['buf']:
                      report['flows'][k]['transactions'][tid]['regex']['buf'] = {}

                    report['flows'][k]['transactions'][tid]['regex']['buf'][rid] = {
                      'offset': match.start(),
                      'size': match.end() - match.start(),
                      'severity': severity,
                      'description': self.regexes[severity][rid]['description'],
                      'match': scanbuf[match.start():match.end()]
                    }

                if proto == 'TCP' and report['flows'][k]['transactions'][tid]['ctsbuf']:
                  if self.config['inspect_cts_depth'] > 0:
                    scanbuf = report['flows'][k]['transactions'][tid]['ctsbuf'][:self.config['inspect_cts_depth']]
                  else:
                    scanbuf = report['flows'][k]['transactions'][tid]['ctsbuf']

                  match = self.regexes[severity][rid]['regex'].search(scanbuf)
                  if match:
                    self.logger.info("%s (CTS, Trans: #%d) %08x: Found %s match" % (k, tid, match.start(), utils.size_string(match.end() - match.start())))

                    if not report['flows'][k]['transactions'][tid]['regex']['cts']:
                      report['flows'][k]['transactions'][tid]['regex']['cts'] = {}

                    report['flows'][k]['transactions'][tid]['regex']['cts'][rid] = {
                      'offset': match.start(),
                      'size': match.end() - match.start(),
                      'severity': severity,
                      'description': self.regexes[severity][rid]['description'],
                      'match': scanbuf[match.start():match.end()]
                    }

                if proto == 'TCP' and report['flows'][k]['transactions'][tid]['stcbuf']:
                  if self.config['inspect_stc_depth'] > 0:
                    scanbuf = report['flows'][k]['transactions'][tid]['stcbuf'][:self.config['inspect_stc_depth']]
                  else:
                    scanbuf = report['flows'][k]['transactions'][tid]['stcbuf']

                  match = self.regexes[severity][rid]['regex'].search(scanbuf)
                  if match:
                    self.logger.info("%s (STC, Trans: #%d) %08x: Found %s match" % (k, tid, match.start(), utils.size_string(match.end() - match.start())))

                    if not report['flows'][k]['transactions'][tid]['regex']['stc']:
                      report['flows'][k]['transactions'][tid]['regex']['stc'] = {}

                    report['flows'][k]['transactions'][tid]['regex']['stc'][rid] = {
                      'offset': match.start(),
                      'size': match.end() - match.start(),
                      'severity': severity,
                      'description': self.regexes[severity][rid]['description'],
                      'match': scanbuf[match.start():match.end()]
                    }

    return dict(report)


  def inspect_heuristics(self, report, filetype):
    if filetype == 'PCAP':
      self.logger.info('Invoking heuristics detection on input buffers')

      for k in sorted(report['flows'].keys()):
        proto = k.split(' - ')[2]

        if 'transactions' in report['flows'][k].keys() and report['flows'][k]['transactions']:
          for tid in sorted(report['flows'][k]['transactions']):

            if 'heuristics' not in report['flows'][k]['transactions'][tid].keys():
              if proto == 'TCP':
                report['flows'][k]['transactions'][tid]['heuristics'] = {
                  'cts': None,
                  'stc': None
                }
              elif proto == 'UDP':
                report['flows'][k]['transactions'][tid]['heuristics'] = {
                  'buf': None
                }

    return dict(report)

