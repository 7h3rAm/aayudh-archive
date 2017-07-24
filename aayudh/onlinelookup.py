# -*- coding: utf-8 -*-

from shadow_server_api import ShadowServerApi
from team_cymru_api import TeamCymruApi

from fileutils import is_file, file_hashes
from utils import objdict, internet

import urllib2
import json

try:
  import urllib
except:
  import urllib2 as urllib



class ShadowServerAPI:
  def __init__(self, filename):
    if is_file(filename):
      self.config = objdict({})
      self.config.filename = filename
      self.config.md5 = file_hashes(self.config.filename, 'md5')
      self.config.ssdeep = file_hashes(self.config.filename, 'ssdeep')
      self.api = ShadowServerApi()
      self.report = objdict({})

    else:
      return None

  def apiconfig(self):
    self.report.avengines = self.api.list_av_engines["av"]
    self.report.avurl = self.api.shadowserver_av
    self.report.bintesturl = self.api.shadowserver_bintest

  def bintest(self):
    try:
      self.report.bintest = self.api.get_bintest(self.config.md5)
    except Exception as ex:
      self.report.bintest = None

  def lookup_getav(self):
    try:
      self.report.getav = self.api.get_av(self.config.md5)
      if "error" in self.report.getav:
        self.report.getav = None
    except Exception as ex:
      self.report.getav = None

  def lookup_fuzzy(self):
    try:
      self.report.fuzzy = self.api.get_ssdeep_matches(self.config.ssdeep)
    except Exception as ex:
      self.report.fuzzy = None

  # wrapper over internal functions
  # prefer calling this instead of other class funcs
  # as it will ensure all details are captured in returned report dict
  def lookup(self):
    #self.apiconfig()
    self.bintest()
    self.lookup_getav()
    return self.report


class TeamCymruAPI:
  def __init__(self, filename):
    if is_file(filename):
      self.config = objdict({})
      self.config.filename = filename
      self.config.md5 = file_hashes(self.config.filename, 'md5')
      self.config.sha1 = file_hashes(self.config.filename, 'sha1')
      self.api = TeamCymruApi()
      self.report = objdict({})

    else:
      return None

  def lookup_md5(self):
    self.report = self.api.get_cymru(self.config.md5)

  def lookup_sha1(self):
    self.report = self.api.get_cymru(self.config.sha1)

  # wrapper over internal functions
  # prefer calling this instead of other class funcs
  # as it will ensure all details are captured in returned report dict
  def lookup(self):
    self.lookup_sha1()
    return self.report


class Metascan:
  def __init__(self, filename):
    if is_file(filename):
      self.config = objdict({})
      self.config.filename = filename
      self.config.apikey = None
      self.config.url = objdict({})
      self.config.url.hashreport = "https://hashlookup.metascan-online.com/v2/hash/%s" % (file_hashes(self.config.filename, "sha256"))
      self.config.params = { "apikey": self.config.apikey, "file_metadata": 1 }
      self.config.data = urllib.urlencode(self.config.params)
      self.report = None

    else:
      return None

  def lookup_hash(self):
    req = urllib2.Request(self.config.url.hashreport, self.config.data)
    response = urllib2.urlopen(req)
    if response:
      self.report = objdict({})
      self.report.filereport = json.loads(response.read())

  # wrapper over internal functions
  # prefer calling this instead of other class funcs
  # as it will ensure all details are captured in returned report dict
  def lookup(self):
    if not self.config.apikey:
      return None

    self.lookup_hash()
    return self.report


class VirusTotal:
  def __init__(self, filename):
    if is_file(filename):
      self.config = objdict({})
      self.config.filename = filename
      # Privileges: public key, Request rate: 4 requests/minute, Daily quota: 5760 requests/day, Monthly quota: 178560 requests/month
      self.config.apikey = "2cfed5c8ea3e69b1f68a00a083de7f3cdf4de1ea14a317bc5cd3a332493469da"
      self.config.apikey = "9ca790fe3dde490e8fbb5190aa2b2b2ab2406f31e174eb51c37f74a8f88ef1a6"
      self.config.url = objdict({})
      self.config.url.filereport = "https://www.virustotal.com/vtapi/v2/file/report"
      self.config.params = { "resource": file_hashes(self.config.filename, "sha256"), "apikey": self.config.apikey }
      self.config.data = urllib.urlencode(self.config.params)
      self.report = None

    else:
      return None

  def lookup_file(self):
    req = urllib2.Request(self.config.url.filereport, self.config.data)
    response = urllib2.urlopen(req)
    if response:
      self.report = objdict({})
      self.report.filereport = json.loads(response.read())

  # wrapper over internal functions
  # prefer calling this instead of other class funcs
  # as it will ensure all details are captured in returned report dict
  def lookup(self):
    if not self.config.apikey:
      return None

    self.lookup_file()
    return self.report


class OnlineLookup:
  def __init__(self, filename):
    self.config = None
    self.report = None
    self.lookuplist = None
    if internet() and is_file(filename):
      self.config = objdict({})
      self.config.filename = filename
      self.report = objdict({})
      self.lookuplist = ["shadowserver", "teamcymru", "metascan", "virustotal"]

  def lookup_shadowserver(self):
    ss = ShadowServerAPI(self.config.filename)
    ss.lookup()
    return ss.report

  def lookup_teamcymru(self):
    tc = TeamCymruAPI(self.config.filename)
    tc.lookup()
    return tc.report

  def lookup_metascan(self):
    ms = Metascan(self.config.filename)
    ms.lookup()
    return ms.report

  def lookup_virustotal(self):
    vt = VirusTotal(self.config.filename)
    vt.lookup()
    return vt.report

  # wrapper over internal functions
  # prefer calling this instead of other class funcs
  # as it will ensure all details are captured in returned report dict
  def lookup(self):
    # if no internet connectivity, attribute "report" won't be available
    if hasattr(self, "report"):
      try:
        ss = self.lookup_shadowserver()
      except Exception as ex:
        ss = None
      try:
        tc = self.lookup_teamcymru()
      except Exception as ex:
        tc = None
      try:
        ms = self.lookup_metascan()
      except Exception as ex:
        ms = None
      try:
        vt = self.lookup_virustotal()
      except Exception as ex:
        vt = None

      self.report.all = {
        "shadowserver": ss,
        "teamcymru": tc,
        "metascan": ms,
        "virustotal": vt
      }

      return self.report.all

    else:
      return None

