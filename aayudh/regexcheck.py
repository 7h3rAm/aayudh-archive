# -*- coding: utf-8 -*-
# http://scorreiait.bufpress.com/2009/03/13/how-to-detect-random-text-in-a-free-text-field/

import re

regex_jsobfus_eval = r"e.{0,2}v.{0,2}a.{0,2}l.{0,1}"
regex_jsobfus_unescape = r"u.{0,2}n.{0,2}e.{0,2}s.{0,2}c.{0,2}a.{0,2}p.{0,1}e"
regex_jsobfus_substr = r"s.{0,4}u.{0,4}b.{0,4}s.{0,4}t.{0,4}r.{0,4}"

regex_novowel = r"[zrtypqsdfghjklmwxcvbnZRTYPQSDFGHJKLMWXCVBN]{4,}"
regex_homerow = r"[qsdfghjklmQSDFGHJKLM]{3,}"

jsobfus_regex = [ regex_jsobfus_eval, regex_jsobfus_unescape, regex_jsobfus_substr ]

homerow_fallback_minmatchsize = 4

def detect_jsobfus(buf):
  try:
    scriptbuf = re.search('<script(>|[^>]+)(.+?)</script>', buf).group(2)
  except AttributeError:
    scriptbuf = None

  if scriptbuf:
    for regex in jsobfus_regex:
      match = re.search(regex, scriptbuf)

      if match:
        start = match.start()
        end = match.end()
        return (len(scriptbuf), start, end, scriptbuf[start:end])

  return (0, 0, 0, '')

def detect_random(buf):
  # search with the default novowel regex
  match = re.search(regex_novowel, buf)

  if match:
    start = match.start()
    end = match.end()

    # if matched, find the size of matching string
    match_size = end - start

    # if matchsize is above threshold, found random
    if match_size > homerow_fallback_minmatchsize:
      return (start, end, buf[start:end])
    else:
      # if matchsize is equal or below threshold, use the fallback homerow regex
      match = re.search(regex_homerow, buf)
      if match:
        # if fallback homerow regex matches as well, found random
        return (start, end, buf[start:end])

  return (0, 0, '')

