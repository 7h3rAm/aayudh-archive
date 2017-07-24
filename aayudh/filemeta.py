# -*- coding: utf-8 -*-

from pygal.style import LightColorizedStyle, RedBlueStyle, CleanStyle
from pygal import Config
import pygal

from fileutils import file_entropy_compression_stats, file_to_pngimage, file_subfiles, is_file, file_basename, file_dirname, file_mimetype, file_magic, file_hashes
from utils import objdict, info, debug, warn, error, exit, nostdout, dict_normalize
from apis import identicon

import os
import re


class FileMeta:
  def __init__(self, filename, config=None):
    if not is_file(filename):
      return None

    self.config = objdict({})

    # initialize default config opts
    # these could be overridden by user config
    self.config.verbose = False
    self.config.enablefilevisualization = False
    self.config.enablebytefreqhistogram = False
    self.config.enableentropycompressionstats = False

    # override default config opts
    if config:
      for key, value in config.iteritems():
        self.config[key] = value

    # initialize config opts that cannot be overridden
    self.config.filename = filename
    self.report = objdict({})
    self.report.filename = filename
    self.report.filebasename = None
    self.report.filedirname = None
    self.report.filemimetype = None
    self.report.filemagic = None
    self.report.filesize = None
    self.report.fileminsize = None
    self.report.filecompressionratio = None
    self.report.fileentropy = None
    self.report.fileentropycategory = None
    self.report.subfiles = None
    self.report.hashes = objdict({})
    self.report.visual = objdict({})

  def analyze(self):
    self.report.filebasename = file_basename(self.config.filename)
    self.report.filedirname = file_dirname(self.config.filename)
    self.report.filemimetype = file_mimetype(self.config.filename)
    magicresult = file_magic(self.config.filename)
    self.report.filemagic = "%s (%s)" % (magicresult["magic"]["longname"], magicresult["magic"]["shortname"]) if magicresult["magic"] else None
    self.report.hashes.crc32 = file_hashes(self.config.filename, 'crc32')
    self.report.hashes.md5 = file_hashes(self.config.filename, 'md5')
    self.report.hashes.sha1 = file_hashes(self.config.filename, 'sha1')
    self.report.hashes.sha256 = file_hashes(self.config.filename, 'sha256')
    self.report.hashes.sha512 = file_hashes(self.config.filename, 'sha512')
    self.report.hashes.ssdeep = file_hashes(self.config.filename, 'ssdeep')

    with nostdout():
      self.report.subfiles = file_subfiles(self.config.filename)

    # this might take some time to finish
    # based on the filesize, runtime might increase
    # will be autodisabled based on statsfilesizelimit config option
    if self.config.enableentropycompressionstats:
      stats = objdict(file_entropy_compression_stats(self.config.filename))
      self.report.filesize = stats.filesizeinbytes
      self.report.fileminsize = float(stats.minfilesize)
      self.report.filecompressionratio = float(stats.compressionratio)
      self.report.fileentropy = float(stats.entropy)
      self.report.fileentropycategory = stats.entropycategory

    # this might take some time to finish
    # based on the filesize, runtime might increase
    # should be autodisabled based on (statsfilesizelimit) config option
    if self.config.enablefilevisualization:
      self.report.visual.pngrgb = file_to_pngimage(self.config.filename)
      self.report.visual.pnggray = file_to_pngimage(self.config.filename, enable_colors=False)
      rh = identicon(self.report.hashes.sha256)
      self.report.visual.identicon = rh.identicon if rh.success else None

      config = Config()
      config.x_title = 'Bytes'
      config.y_title = 'Frequency'
      config.x_scale = .25
      config.y_scale = .25
      config.width = 900
      config.height = 300
      config.title_font_size = 9
      config.tooltip_font_size = 0
      config.tooltip_border_radius = 0
      config.no_data_text = ""
      config.show_legend = False
      config.show_only_major_dots = True
      config.human_readable = False
      config.show_y_labels = False
      config.fill = True
      config.style = CleanStyle
      bar_chart = pygal.Bar(config)

      # if enableentropycompressionstats config option is disabled, stats won't be generated above
      # as such we need to explicitly generate, on-demand
      if not stats:
        stats = objdict(file_entropy_compression_stats(self.config.filename))

      bar_chart.add('', stats.bytefreqlist)
      self.report.visual.bytefreqhistogram = bar_chart.render(is_unicode=False)
      # pygal inserts a copyright symbol in rendered chart output
      # need to explicitly clean it before returning
      pygalregex = re.compile(r"\xc2\xa9")
      self.report.visual.bytefreqhistogram = pygalregex.sub("", self.report.visual.bytefreqhistogram)

    else:
      self.report.visual.pngrgb = None
      self.report.visual.pnggray = None
      self.report.visual.identicon = None
      self.report.visual.bytefreqhistogram = None

    # done with analysis, normalize report and return
    self.report = dict_normalize(self.report)

