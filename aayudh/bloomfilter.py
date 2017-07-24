# -*- coding: utf-8 -*-

from pybloom import ScalableBloomFilter

class BloomFilter:
  def __init__(self, datafile, filterfile):
    # https://github.com/jaybaird/python-bloomfilter/blob/master/pybloom/pybloom.py
    self.filter = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)
    self.datafile = datafile
    self.filterfile = filterfile
    self.datafilesize = None
    self.filterfilesize = None
    self.change = None

  def add_to_filter(self, update=False):
    # https://github.com/bigsnarfdude/Malware-Probabilistic-Data-Structres/blob/master/Mandiant_MD5_BloomFilter.py
    def stream_lines(filename):
      file = open(filename)
      while True:
        line = file.readline()
        if not line:
          file.close()
          break
        yield line.strip()

    def load_file(filename):
      lines = stream_lines(filename)
      templist = []
      for line in lines:
        templist.append(line)

      return templist

    itemlist = load_file(self.datafile)
    self.itemcount = len(itemlist)

    if not update:
      # reinitialize filter before adding a new set of items
      self.filter = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)

    for item in itemlist:
      _ = self.filter.add(item)

  def update_filter(self):
    # simulate updation via add
    self.add(update=True)

  def save_to_file(self):
    if self.filter:
      f = open(self.filterfile, 'wb')
      self.filter.tofile(f)
      f.close()

  def load_from_file(self):
    del self.filter
    f = open(self.filterfile, 'rb')
    self.filter = ScalableBloomFilter.fromfile(f)
    f.close()

  def search_filter(self, item):
    return True if item in self.filter else False

  def get_stats(self):
    if filter:
      self.datafilesize = file_size(self.datafile)
      self.filterfilesize = file_size(self.filterfile)
      self.change = 100 * (self.filterfilesize - self.datafilesize) / self.datafilesize

      return {
        "initial_capacity": self.filter.initial_capacity,
        "capacity": self.filter.capacity,
        "count": self.filter.count,
        "ratio": self.filter.ratio,
        "scale": self.filter.scale,
        "datafile": self.datafile,
        "filterfile": self.filterfile,
        "datafilesize": self.datafilesize,
        "filterfilesize": self.filterfilesize,
        "change": self.change
      }
    else:
      return None

