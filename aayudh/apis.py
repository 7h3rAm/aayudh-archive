# -*- coding: utf-8 -*-
# methods that interact with public/remote apis

import bs4
import facebook
import feedparser

import os
import re
import sys
import json
import arrow
import random
import shodan
import struct
import urllib
import urllib2
import datetime
import requests
import ConfigParser
from lxml import html
from pprint import pprint
from pytz import timezone
import xml.etree.ElementTree
from howdoi import howdoi as hdi
from coinbase.wallet.client import Client

import bottlenose
from bs4 import BeautifulSoup

import shadow_server_api
import team_cymru_api
import virus_total_apis

import utils, fileutils


reload(sys)
sys.setdefaultencoding('utf8')
requests.packages.urllib3.disable_warnings()

keys = ConfigParser.ConfigParser()
keys.read("%s/data/keys.conf" % (os.path.dirname(__file__)))


def amazon(query=None, limit=5):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  amazon = bottlenose.Amazon(keys.get("apikeys", "amazon_access"), keys.get("apikeys", "amazon_secret"), keys.get("apikeys", "amazon_associate"), Parser=BeautifulSoup)
  #search = amazon.ItemSearch(Keywords="Kindle 3G", SearchIndex="All")
  #lookup = amazon.ItemLookup(ItemId="0596520999", ResponseGroup="Images", SearchIndex="Books", IdType="ISBN")
  try:
    xml = amazon.ItemSearch(Keywords=query, SearchIndex="All")
    products = xml.find_all("item")[:limit]
    reply = list()
    for product in products:
      item = amazon.ItemLookup(ItemId=product.asin.string, ResponseGroup="Offers", MerchantId="All")
      try:
        price = item.find("formattedprice").string
        url = product.detailpageurl.string
        title = product.itemattributes.title.string
        manufacturer = product.itemattributes.manufacturer.string
        reply.append(utils.objdict({
          "name": title,
          "price": price,
          "url": url,
          "vendor": manufacturer
        }))
      except:
        continue
    if len(reply):
      return utils.objdict({
        "success": True,
        "searchlink": xml.items.moresearchresultsurl.string,
        "products": reply
      })
    else:
      return utils.objdict({
        "success": False,
        "reason": "No results found for query \"%s\"" % (query)
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def cdnperf(query=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    cdns = ["jsdelivr", "cdnjs", "google", "yandex", "microsoft", "jquery", "bootstrapcdn"]
    if not query or query == "" or query not in cdns:
      stats = utils.objdict()
      for cdn in cdns:
        res = requests.get("https://www.cdnperf.com/api/v1/cdns/%s" % (cdn.lower()), headers=customheaders, verify=False)
        if res.status_code == 200:
          reply = res.json()
          if len(reply):
            stats[cdn.lower()] = reply
    return utils.objdict({
      "success": True,
      "stats": stats
    })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def circllu_cveinfo(cve="cve-2015-1234"):
  if not cve or cve == "" or not utils.is_cve(cve):
    return utils.objdict({
      "success": False,
      "usage": "<cve-year-idid>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    if "cve-" not in cve.lower():
      cve = "cve-%s" % (cve)
    res = requests.get("http://cve.circl.lu/api/cve/%s" % (cve.upper()), headers=customheaders, verify=False)
    if res.status_code == 200:
      if "null" not in res.content:
        reply = res.json()
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "cve": cve.upper(),
          "cvss": reply["cvss"] if "cvss" in reply and reply["cvss"] else None,
          "cvss_verbose": utils.objdict({
            "ac": reply["access"]["complexity"] if "access" in reply and "complexity" in reply["access"] else None,
            "au": reply["access"]["authentication"] if "access" in reply and "authentication" in reply["access"] else None,
            "av": reply["access"]["vector"] if "access" in reply and "vector" in reply["access"] else None,
            "c": reply["impact"]["confidentiality"] if "impact" in reply and "confidentiality" in reply["impact"] else None,
            "i": reply["impact"]["integrity"] if "impact" in reply and "integrity" in reply["impact"] else None,
            "a": reply["impact"]["availability"] if "impact" in reply and "availability" in reply["impact"] else None
          }),
          "summary": reply["summary"],
          "cveurl": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s" % (cve.upper()),
          "references": reply["references"]
        })
      else:
        return utils.objdict({
          "success": False,
          "reason": "Could not find information for %s." % (cve.upper())
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def circllu_cverecent(maxcves=0):
  maxcves = int(maxcves) if maxcves else 0
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("http://cve.circl.lu/api/last", headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      cves = list()
      for node in reply:
        if "REJECT" not in node["summary"]:
          cves.append(utils.objdict({
            "cve": node["id"],
            "summary": node["summary"]
          }))
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "cvebaseurl": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=<CVEID>",
        "cves": cves if maxcves == 0 else cves[:maxcves]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def circllu_cvesearch(vendorproduct="Adobe Reader", maxcves=0):
  if not vendorproduct or vendorproduct == "":
    return utils.objdict({
      "success": False,
      "usage": "<vendor> <product>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("http://cve.circl.lu/api/search/%s" % ("/".join(vendorproduct.lower().split(" "))), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if isinstance(reply, dict): reply = reply["data"]
      cves = list()
      for node in reply:
        if "REJECT" not in node["summary"]:
          cves.append(node["id"])
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "cvebaseurl": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=<CVEID>",
        "vendorproduct": "/".join(vendorproduct.lower().split(" ")).title(),
        "cves": sorted(cves, reverse=True) if maxcves == 0 else sorted(cves, reverse=True)[:maxcves]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def coinbase_account():
  try:
    client = Client(keys.get("apikeys", "coinbasekey"), keys.get("apikeys", "coinbasesecret"))
    reply = client.get_accounts()
    accounts, totalnativebalance, nativecurrency = list(), 0, None
    for account in reply.data:
      totalnativebalance += float(account.native_balance.amount)
      nativecurrency = account.native_balance.currency if account.native_balance.currency else "USD"
      accounts.append(utils.objdict({
        "name": account.name,
        "accountid": account.id,
        "createdat": utils.datestring_to_dateobject(account.created_at),
        "createdathuman": arrow.get(account.created_at).humanize(),
        "currency": account.currency,
        "balance": account.balance.amount,
        "balancehuman": "%s %s" % (account.balance.amount, account.balance.currency),
        "nativebalance": account.native_balance.amount,
        "nativebalancehuman": "%s %s" % (account.native_balance.amount, account.native_balance.currency),
        "accounttype": account.type,
      }))
    if len(accounts):
      return utils.objdict({
        "success": True,
        "accounts": accounts,
        "currentbalance": totalnativebalance,
        "currentbalancehuman": "%.2f %s" % (totalnativebalance, nativecurrency)
      })
    return utils.objdict({
      "success": False,
      "reason": "Found 0 accounts on Coinbase"
    })
  except Exception as ex:
    import traceback
    traceback.print_exc()
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def coinbase_forex():
  try:
    client = Client(keys.get("apikeys", "coinbasekey"), keys.get("apikeys", "coinbasesecret"))
    reply = client.get_exchange_rates()
    btcrate = (1.0-float(reply.rates.BTC))/float(reply.rates.BTC)
    ethrate = (1.0-float(reply.rates.ETH))/float(reply.rates.ETH)
    ltcrate = (1.0-float(reply.rates.LTC))/float(reply.rates.LTC)
    return utils.objdict({
      "success": True,
      "usdrates": utils.objdict({
        "btc": btcrate,
        "btchuman": "1 BTC ≈ %.2f USD" % (btcrate),
        "eth": ethrate,
        "ethhuman": "1 ETH ≈ %.2f USD" % (ethrate),
        "ltc": ltcrate,
        "ltchuman": "1 LTC ≈ %.2f USD" % (ltcrate)
      })
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def coinbase_portfolio():
  try:
    client = Client(keys.get("apikeys", "coinbasekey"), keys.get("apikeys", "coinbasesecret"))
    reply = client.get_accounts()
    stats = utils.objdict({
      "currentbalance": 0,
      "currentbalancehuman": None,
      "buys": utils.objdict({
        "btcamount": 0.0,
        "btcamounthuman": None,
        "ethamount": 0.0,
        "ethamounthuman": None,
        "ltcamount": 0.0,
        "ltcamounthuman": None,
        "fee": 0.0,
        "feehuman": None,
        "total": 0.0,
        "totalhuman": None,
        "subtotal": 0.0,
        "subtotalhuman": None
      }),
      "sells": utils.objdict({
        "btcamount": 0.0,
        "btcamounthuman": None,
        "ethamount": 0.0,
        "ethamounthuman": None,
        "ltcamount": 0.0,
        "ltcamounthuman": None,
        "fee": 0.0,
        "feehuman": None,
        "total": 0.0,
        "totalhuman": None,
        "subtotal": 0.0,
        "subtotalhuman": None
      }),
      "deposits": utils.objdict({
        "amount": 0.0,
        "amounthuman": None,
        "fee": 0.0,
        "feehuman": None,
        "subtotal": 0.0,
        "subtotalhuman": None
      }),
      "withdrawals": utils.objdict({
        "amount": 0.0,
        "amounthuman": None,
        "fee": 0.0,
        "feehuman": None,
        "subtotal": 0.0,
        "subtotalhuman": None
      }),
    })
    totalnativebalance, nativecurrency = 0, None
    for account in reply.data:
      totalnativebalance += float(account.native_balance.amount)
      nativecurrency = account.native_balance.currency if account.native_balance.currency else "USD"
      if "vault" in account.name.lower():
        continue
      buys = account.get_buys()
      for buy in buys.data:
        if buy.amount.currency == "BTC":
          stats.buys.btcamount += float(buy.amount.amount)
        elif buy.amount.currency == "ETH":
          stats.buys.ethamount += float(buy.amount.amount)
        elif buy.amount.currency == "LTC":
          stats.buys.ltcamount += float(buy.amount.amount)
        stats.buys.total += float(buy.total.amount)
        stats.buys.subtotal += float(buy.subtotal.amount)
      sells = account.get_sells()
      for sell in sells.data:
        if sell.amount.currency == "BTC":
          stats.sell.btcamount += float(sell.amount.amount)
        elif sell.amount.currency == "ETH":
          stats.sell.ethamount += float(sell.amount.amount)
        elif sell.amount.currency == "LTC":
          stats.sell.ltcamount += float(sell.amount.amount)
        stats.sell.total += float(sell.total.amount)
        stats.sell.subtotal += float(sell.subtotal.amount)
      deposits = account.get_deposits()
      for deposit in deposits.data:
        stats.deposit.amount += float(deposit.amount.amount)
        stats.deposit.subtotal += float(deposit.subtotal.amount)
      withdrawals = account.get_withdrawals()
      for withdrawal in withdrawals.data:
        stats.withdrawal.amount += float(withdrawal.amount.amount)
        stats.withdrawal.subtotal += float(withdrawal.subtotal.amount)
    stats.buys.btcamounthuman = "%s BTC" % (stats.buys.btcamount)
    stats.buys.ethamounthuman = "%s ETH" % (stats.buys.ethamount)
    stats.buys.ltcamounthuman = "%s LTC" % (stats.buys.ltcamount)
    stats.buys.fee = stats.buys.total - stats.buys.subtotal
    stats.buys.feehuman = "%s USD" % (stats.buys.fee)
    stats.buys.totalhuman = "%s USD" % (stats.buys.total)
    stats.buys.subtotalhuman = "%s USD" % (stats.buys.subtotal)
    stats.sells.btcamounthuman = "%s BTC" % (stats.sells.btcamount)
    stats.sells.ethamounthuman = "%s ETH" % (stats.sells.ethamount)
    stats.sells.ltcamounthuman = "%s LTC" % (stats.sells.ltcamount)
    stats.sells.fee = stats.sells.total - stats.sells.subtotal
    stats.sells.feehuman = "%s USD" % (stats.sells.fee)
    stats.sells.totalhuman = "%s USD" % (stats.sells.total)
    stats.sells.subtotalhuman = "%s USD" % (stats.sells.subtotal)
    stats.deposits.amounthuman = "%s BTC" % (stats.deposits.amount)
    stats.deposits.feehuman = "%s USD" % (stats.deposits.fee)
    stats.deposits.subtotalhuman = "%s USD" % (stats.deposits.subtotal)
    stats.withdrawals.amounthuman = "%s BTC" % (stats.withdrawals.amount)
    stats.withdrawals.feehuman = "%s USD" % (stats.withdrawals.fee)
    stats.withdrawals.subtotalhuman = "%s USD" % (stats.withdrawals.subtotal)
    stats.currentbalance = totalnativebalance
    stats.currentbalancehuman = "%s %s" % (totalnativebalance, nativecurrency)
    stats.portfolio = utils.objdict({
      "amount": stats.buys.total,
      "amounthuman": "%.2f USD" % (stats.buys.total),
      "fee": stats.buys.fee,
      "feehuman": "%.2f USD" % (stats.buys.fee),
      "feeper": ((stats.buys.fee/stats.buys.total)*100),
      "feeperhuman": "%.2f%%" % (((stats.buys.fee/stats.buys.total)*100)),
      "investment": stats.buys.subtotal,
      "investmenthuman": "%.2f USD" % (stats.buys.subtotal),
      "valuation": stats.currentbalance,
      "valuationhuman": "%.2f USD" % (stats.currentbalance),
      "delta": ((stats.currentbalance - stats.buys.subtotal)/stats.buys.subtotal)*100,
      "deltahuman": "%.2f%%" % (((stats.currentbalance - stats.buys.subtotal)/stats.buys.subtotal)*100)
    })
    if len(reply.data):
      return utils.objdict({
        "success": True,
        "stats": stats,
      })
    return utils.objdict({
      "success": False,
      "reason": "Found 0 accounts on Coinbase"
    })
  except Exception as ex:
    import traceback
    traceback.print_exc()
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def coinbase_price():
  try:
    client = Client(keys.get("apikeys", "coinbasekey"), keys.get("apikeys", "coinbasesecret"))
    buyprice = client.get_buy_price()
    sellprice = client.get_sell_price()
    spotprice = client.get_spot_price()
    return utils.objdict({
      "success": True,
      "price": utils.objdict({
        "buy": utils.objdict({
          "basecurrency": buyprice.base,
          "amountcurrency": buyprice.currency,
          "amount": buyprice.amount,
          "amounthuman": "1 %s ≈ %s %s" % (buyprice.base, buyprice.amount, buyprice.currency)
        }),
        "sell": utils.objdict({
          "basecurrency": sellprice.base,
          "amountcurrency": sellprice.currency,
          "amount": sellprice.amount,
          "amounthuman": "1 %s ≈ %s %s" % (sellprice.base, sellprice.amount, sellprice.currency)
        }),
        "spot": utils.objdict({
          "basecurrency": spotprice.base,
          "amountcurrency": spotprice.currency,
          "amount": spotprice.amount,
          "amounthuman": "1 %s ≈ %s %s" % (spotprice.base, spotprice.amount, spotprice.currency)
        })
      })
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def coinbase_user():
  try:
    client = Client(keys.get("apikeys", "coinbasekey"), keys.get("apikeys", "coinbasesecret"))
    reply = client.get_current_user()
    return utils.objdict({
      "success": True,
      "bitcoinunit": reply.bitcoin_unit,
      "country": reply.country.code,
      "state": reply.state,
      "name": reply.name,
      "userid": reply.id,
      "createdat": utils.datestring_to_dateobject(reply.created_at),
      "createdathuman": arrow.get(reply.created_at).humanize(),
      "currency": reply.native_currency,
      "timezone": reply.time_zone
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def ctftime_events(eventid=None):
  # https://ctftime.org/api/
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    params = {
      "limit": 10000,
      "start": 0000000000,
      "finish": 9999999999,
    }
    res = requests.get("https://ctftime.org/api/v1/events/%d/" % int(eventid), headers=customheaders, verify=False) if eventid and eventid != "" else requests.get("https://ctftime.org/api/v1/events/", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if type(reply) == list:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "count": len(reply),
          "events": list(reversed(reply)),
        })
      elif type(reply) == dict:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "events": list([reply]),
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def ctftime_topteams(year=None):
  # https://ctftime.org/api/
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("https://ctftime.org/api/v1/top/%d/" % int(year), headers=customheaders, verify=False) if year and year != "" else requests.get("https://ctftime.org/api/v1/top/", headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if len(reply.keys()):

        teams = list()
        for year in reply:
          reply[year]

        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "teambaseurl": "https://ctftime.org/team/<TEAMID>",
          "topteams": reply,
        })
      else:
        return utils.objdict({
          "success": False,
          "reason": "Failed to find top teams."
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def ctftime_teams(teamid=None):
  # https://ctftime.org/api/
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("https://ctftime.org/api/v1/teams/%d/" % (int(teamid)), headers=customheaders, verify=False) if teamid and teamid != "" else requests.get("https://ctftime.org/api/v1/teams/", headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if type(reply) == list:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "teambaseurl": "https://ctftime.org/team/<TEAMID>",
          "count": len(reply),
          "teams": reply,
        })
      elif type(reply) == dict:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "teambaseurl": "https://ctftime.org/team/<TEAMID>",
          "teams": list([reply]),
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def dilbert(query=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    if query:
      if query.lower() == "current":
        res = requests.get("http://dilbert.com/", headers=customheaders, verify=False)
        caption = "<http://dilbert.com/|Homepage | Dilbert by Scott Adams>"
      else:
        res = requests.get("http://dilbert.com/strip/%s" % (query), headers=customheaders, verify=False)
        caption = "<http://dilbert.com/strip/%s|Dilbert Comic Strip on %s | Dilbert by Scott Adams>" % (query, query)
    else:
      # first dilbert comic: http://dilbert.com/strip/1989-04-16
      ystart, ystop = 1989, 2015
      datestring = random.randint(ystart, ystop), random.randint(1, 12), random.randint(1, 28)
      res = requests.get("http://dilbert.com/strip/%s-%s-%s" % (datestring), headers=customheaders, verify=False)
      caption = "<%s|Dilbert Comic Strip on %s | Dilbert by Scott Adams>" % ("http://dilbert.com/strip/%s-%s-%s" % (datestring), "%s-%s-%s" % (datestring))
    if res.status_code == 200:
      tree = html.fromstring(res.content)
      stripurl = tree.xpath('//img[@class="img-responsive img-comic"]/@src')[0]
      alttext = tree.xpath('//img[@class="img-responsive img-comic"]/@alt')[0]
      if stripurl:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "comic": utils.objdict({
            "alttext": alttext,
            "imgurl": stripurl,
            "img": utils.download(stripurl),
            "stripurl": res.url,
            "caption": caption,
          })
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to get comic strip for url: %s" % (url)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def dnslg_dnslookup(query=None):
  # http://www.dns-lg.com/
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    lurl = longurl(query)
    if lurl.success:
      query = utils.url_to_domain(lurl.longurl)
    if utils.is_ipv4(query):
      res = requests.get("http://www.dns-lg.com/nl01/x/%s" % (utils.url_to_domain(query)), headers=customheaders, verify=False)
    elif utils.is_domain(query):
      res = requests.get("http://www.dns-lg.com/nl01/%s/a" % (utils.url_to_domain(query)), headers=customheaders, verify=False)
    else:
      res = None
    if res:
      answers = list()
      if res.status_code == 200:
        reply = json.loads(res.content)
        if "answer" in reply.keys():
          for answer in reply["answer"]:
            if answer["type"] in ["A", "PTR"]:
              answers.append(answer)
      if answers and len(answers):
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "domain": query,
          "answers": answers
        })
      else:
        return utils.objdict({
          "success": False,
          "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
        })
    if res.status_code >= 500:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": False,
        "reason": reply["message"] if "message" in reply else "failed to lookup query: %s (got HTTP %s)" % (query, res.status_code)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def dpaste(pastedata):
  if not pastedata or pastedata == "":
    return utils.objdict({
      "success": False,
      "usage": "<pastedata>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  data = {
    "content": pastedata,
    "expiry_days": "1"
  }
  try:
    res = requests.post("http://dpaste.com/api/v2/", headers=customheaders, data=data, verify=False)
    if res.status_code == 201:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "pasteurl": res.headers["location"]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP 201 status code but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def dshield_infocon():
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("https://www.dshield.org/api/infocon?json", headers=customheaders, verify=False)
    if res.status_code == 200:
      imgres = requests.get("https://isc.sans.edu/images/status.gif", headers=customheaders, verify=False)
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "status": res.json()["status"].title(),
        "infoconurl": "https://www.dshield.org/infocon.html",
        "infoconimage": imgres.content if imgres.status_code == 200 else None
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def dshield_topips(limit=5):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("https://isc.sans.edu/api/sources/attacks/%s?json" % limit, headers=customheaders, verify=False)
    if res.status_code == 200:

      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "topports": topports if topports and len(topports) else None
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def dshield_topports(limit=5):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("https://isc.sans.edu/api/topports/records/%s?json" % limit, headers=customheaders, verify=False)
    if res.status_code == 200:
      portservice = utils.objdict()
      with open("%s/data/portservice.csv" % (os.path.dirname(__file__)), "r") as fo:
        for line in fo.readlines():
          port, service = line.split(",", 1)
          portservice[int(port)] = service if service[-1] != "\n" else service[:-1]
      topports = utils.objdict()
      for key, value in res.json().iteritems():
        if key not in ["date", "limit"]:
          topports[value["rank"]] = utils.objdict({
            "port": value["targetport"],
            "attacks": value["records"],
            "service": portservice[value["targetport"]] if value["targetport"] in portservice else None
          })
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "topports": topports if topports and len(topports) else None
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def duckduckgo_search(query, maxentries=5):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  restypes = {"A": "answer", "D": "disambiguation", "C": "category", "N": "name", "E": "exclusive", "": "nothing"}
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "q": query,
    "format": "json",
    "no_html": "1"
  }
  try:
    res = requests.get("http://api.duckduckgo.com/", headers=customheaders, params=params, verify=False)
    reply = json.loads(res.content)
    if res.status_code == 200:
      if reply["Infobox"] and reply["Infobox"] != "":
        infobox = list()
        for entry in reply["Infobox"]["content"]:
          infobox.append(utils.objdict({
            "label": entry["label"],
            "value": entry["value"]
          }))
      else:
        infobox = None
      if reply["RelatedTopics"] and reply["RelatedTopics"] != "":
        related = list()
        for entry in reply["RelatedTopics"][:maxentries]:
          if "FirstURL" in entry and "Text" in entry:
            related.append(utils.objdict({
              "link": entry["FirstURL"],
              "text": re.sub(r"([a-z])([A-Z])", r"\1: \2", entry["Text"]),
              "image": utils.download(entry["Icon"]["URL"]) if "Icon" in entry and entry["Icon"] and entry["Icon"]["URL"] and entry["Icon"]["URL"] != "" else None,
              "imageurl": entry["Icon"]["URL"] if "Icon" in entry and entry["Icon"] and entry["Icon"]["URL"] and entry["Icon"]["URL"] != "" else None,
            }))
      else:
        related = None
      if reply["Results"] and reply["Results"] != "":
        results = list()
        for entry in reply["Results"][:maxentries]:
          if "FirstURL" in entry and "Text" in entry:
            results.append(utils.objdict({
              "link": entry["FirstURL"],
              "text": re.sub(r"([a-z])([A-Z])", r"\1: \2", entry["Text"]),
              "image": utils.download(entry["Icon"]["URL"]) if "Icon" in entry and entry["Icon"] and entry["Icon"]["URL"] and entry["Icon"]["URL"] != "" else None,
              "imageurl": entry["Icon"]["URL"] if "Icon" in entry and entry["Icon"] and entry["Icon"]["URL"] and entry["Icon"]["URL"] != "" else None,
            }))
      else:
        results = None
      return utils.objdict({
        "success": True,
        "query": query,
        "requesturl": res.url,
        "ddg": utils.objdict({
          "answer": reply["Answer"] if reply["Answer"] and reply["Answer"] != "" else None,
          "answertype": reply["AnswerType"] if reply["AnswerType"] and reply["AnswerType"] != "" else None,
          "abstracttext": reply["AbstractText"] if reply["AbstractText"] and reply["AbstractText"] != "" else None,
          "abstractsource": reply["AbstractSource"] if reply["AbstractSource"] and reply["AbstractSource"] != "" else None,
          "abstracturl": reply["AbstractURL"] if reply["AbstractURL"] and reply["AbstractURL"] != "" else None,
          "heading": reply["Heading"] if reply["Heading"] and reply["Heading"] != "" else None,
          "imageurl": reply["Image"] if reply["Image"] and reply["Image"] != "" else None,
          "image": utils.download(reply["Image"]) if reply["Image"] and reply["Image"] != "" else None,
          "restype": restypes[reply["Type"]] if reply["Type"] in restypes else None,
          "infobox": infobox,
          "related": related,
          "result": results
        })
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP 201 status code but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def forecastio(location=None):
  if not location or location == "":
    localgeo = localgeoinfo()
    if localgeo["success"]:
      location = localgeo["geoinfo"]["city"]
      lat = localgeo["geoinfo"]["lat"]
      lon = localgeo["geoinfo"]["lon"]
    else:
      location, lat, lon = "Vancouver, BC, Canada", 49.246292, -123.116226
  else:
    geodata = google_geocode(location)
    if geodata.success:
      lat = geodata.latitude
      lon = geodata.longitude
    else:
      lat, lon = None, None
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    if location and lat and lon:
      # https://developer.forecast.io/docs/v2
      res = requests.get("https://api.forecast.io/forecast/%s/%s,%s" % (keys.get("apikeys", "forecastio"), lat, lon), headers=customheaders, verify=False)
      if res.status_code == 200:
        reply = utils.unicode_to_string(res.json())
        dailyweather = list()
        for day in reply["daily"]["data"]:
          item = utils.objdict({
            "condition": None,
            "precipintensity": None,
            "precipprobability": None,
            "humidity": None,
            "windbearing": None,
            "visibility": None,
            "cloudcover": None,
            "ozone": None,
            "temperaturemincelcius": None,
            "temperaturemaxcelcius": None,
            "temperatureminfahrenheit": None,
            "temperaturemaxfahrenheit": None,
            "dewpointcelcius": None,
            "dewpointfahrenheit": None,
            "windspeedkmph": None,
            "windspeedmph": None,
            "pressuremillibars": None,
            "pressureinches": None
          })
          for key in day:
            item["condition"] = utils.unicode_to_string(day["summary"])
            item["precipintensity"] = utils.unicode_to_string(day["precipIntensity"]) if "precipIntensity" in day.keys() else None
            item["precipprobability"] = utils.unicode_to_string(day["precipProbability"]) if "precipProbability" in day.keys() else None
            item["humidity"] = utils.unicode_to_string(day["humidity"]) if "humidity" in day.keys() else None
            item["windbearing"] = utils.unicode_to_string(day["windBearing"]) if "windBearing" in day.keys() else None
            item["visibility"] = utils.unicode_to_string(day["visibility"]) if "visibility" in day.keys() else None
            item["cloudcover"] = utils.unicode_to_string(day["cloudCover"]) if "cloudCover" in day.keys() else None
            item["ozone"] = utils.unicode_to_string(day["ozone"]) if "ozone" in day.keys() else None
            if key == "temperatureMin":
              item["temperaturemincelcius"] = utils.fahrenheit_to_celcius(float(utils.unicode_to_string(day["temperatureMin"])))
              item["temperatureminfahrenheit"] = float(utils.unicode_to_string(day["temperatureMin"]))
            if key == "temperatureMax":
              item["temperaturemaxcelcius"] = utils.fahrenheit_to_celcius(float(utils.unicode_to_string(day["temperatureMax"])))
              item["temperaturemaxfahrenheit"] = float(utils.unicode_to_string(day["temperatureMax"]))
            elif key == "dewPoint":
              item["dewpointcelcius"] = utils.fahrenheit_to_celcius(float(utils.unicode_to_string(day["dewPoint"]))) if "dewPoint" in day.keys() else None
              item["dewpointfahrenheit"] = float(utils.unicode_to_string(day["dewPoint"])) if "dewPoint" in day.keys() else None
            elif key == "windSpeed":
              item["windspeedkmph"] = utils.mile_to_kilometer(utils.unicode_to_string(day["windSpeed"])) if "windSpeed" in day.keys() else None
              item["windspeedmph"] = utils.unicode_to_string(day["windSpeed"]) if "windSpeed" in day.keys() else None
            elif key == "pressure":
              item["pressuremillibars"] = utils.unicode_to_string(day["pressure"]) if "pressure" in day.keys() else None
              item["pressureinches"] = utils.millibar_to_inch(float(utils.unicode_to_string(day["pressure"]))) if "pressure" in day.keys() else None
          dailyweather.append(item)
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "location": location,
          "publicurl": "http://forecast.io/embed/#lat=%s&lon=%s&name=%s" % (lat, lon, location),
          "ca12url": "https://darksky.net/forecast/%s,%s/ca12/en" % (lat, lon),
          "us12url": "https://darksky.net/forecast/%s,%s/us12/en" % (lat, lon),
          "currentweather": utils.objdict({
            "condition": utils.unicode_to_string(reply["currently"]["summary"]),
            "precipintensity": utils.unicode_to_string(reply["currently"]["precipIntensity"]) if "precipIntensity" in reply["currently"].keys() else None,
            "precipprobability": utils.unicode_to_string(reply["currently"]["precipProbability"]) if "precipProbability" in reply["currently"].keys() else None,
            "humidity": utils.unicode_to_string(reply["currently"]["humidity"]) if "humidity" in reply["currently"].keys() else None,
            "windbearing": utils.unicode_to_string(reply["currently"]["windBearing"]) if "windBearing" in reply["currently"].keys() else None,
            "visibility": utils.unicode_to_string(reply["currently"]["visibility"]) if "visibility" in reply["currently"].keys() else None,
            "cloudcover": utils.unicode_to_string(reply["currently"]["cloudCover"]) if "cloudCover" in reply["currently"].keys() else None,
            "ozone": utils.unicode_to_string(reply["currently"]["ozone"]) if "ozone" in reply["currently"].keys() else None,
            "temperaturecelcius": utils.fahrenheit_to_celcius(float(utils.unicode_to_string(reply["currently"]["temperature"]))),
            "temperaturefahrenheit": float(utils.unicode_to_string(reply["currently"]["temperature"])),
            "dewpointcelcius": utils.fahrenheit_to_celcius(float(utils.unicode_to_string(reply["currently"]["dewPoint"]))) if "dewPoint" in reply["currently"].keys() else None,
            "dewpointfahrenheit": float(utils.unicode_to_string(reply["currently"]["dewPoint"])) if "dewPoint" in reply["currently"].keys() else None,
            "windspeedkmph": utils.mile_to_kilometer(utils.unicode_to_string(reply["currently"]["windSpeed"])) if "windSpeed" in reply["currently"].keys() else None,
            "windspeedmph": utils.unicode_to_string(reply["currently"]["windSpeed"]) if "windSpeed" in reply["currently"].keys() else None,
            "pressuremillibars": utils.unicode_to_string(reply["currently"]["pressure"]) if "pressure" in reply["currently"].keys() else None,
            "pressureinches": utils.millibar_to_inch(float(utils.unicode_to_string(reply["currently"]["pressure"]))) if "pressure" in reply["currently"].keys() else None
          }),
          "dailyweather": dailyweather
        })
      return utils.objdict({
        "success": False,
        "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
      })
    else:
      return utils.objdict({
        "success": False,
        "reason": "Could not geolocate: %s" % (location)
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def forismatic():
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "method": "getQuote",
    "format": "json",
    "lang": "en"
  }
  try:
    res = requests.get("http://api.forismatic.com/api/1.0/", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "quotetext": reply["quoteText"].encode("utf-8").strip(),
        "quoteauthor": reply["quoteAuthor"].encode("utf-8").strip() if reply["quoteAuthor"] else "Unknown"
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_chef(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/chef.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_ferblatin(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/ferblatin.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_fudd(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/fudd.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_gungan(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/gungan.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_huttese(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/huttese.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_jive(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/jive.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_minion(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/minion.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_piglatin(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/piglatin.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_pirate(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/pirate.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_sith(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/sith.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_valspeak(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/valspeak.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def funtranslations_yoda(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.funtranslations.com/translate/yoda.json?text=%s" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "success" in reply and "contents" in reply and "translated" in reply["contents"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["contents"]["text"],
          "answer": reply["contents"]["translated"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to translate \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def geoname_datetime(lat=None, lon=None, location=None):
  if not lat and not lon and not location:
    localgeo = localgeoinfo()
    if localgeo["success"]:
      location = localgeo["geoinfo"]["city"]
      lat = localgeo["geoinfo"]["lat"]
      lon = localgeo["geoinfo"]["lon"]
  elif not lat or not lon:
    localgeo = localgeoinfo()
    if localgeo["success"]:
      location = localgeo["geoinfo"]["city"]
      lat = localgeo["geoinfo"]["lat"]
      lon = localgeo["geoinfo"]["lon"]
  elif location and not lat and not lon:
    geocodedata = google_geocode(location)
    lat = geocodedata["latitude"]
    lon = geocodedata["longitude"]

  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://api.geonames.org/timezoneJSON?lat=%s&lng=%s&username=%s" % (lat, lon, keys.get("apikeys", "geonames")), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "location": location,
        "date": reply["time"].split(" ")[0],
        "time": reply["time"].split(" ")[1]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def giphy_search(query=None, limit=5, rating="g"):
  # https://github.com/Giphy/GiphyAPI
  # ratings: y, g:general_audience, pg:parental_guidance, pg-13:pg_and_above_13, r:restricted
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "q": query,
    "limit": limit,
    "rating": rating,
    "api_key": keys.get("apikeys", "giphy")
  }
  try:
    res = requests.get("http://api.giphy.com/v1/gifs/search", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      gifs = list()
      for entry in reply["data"]:
        gifs.append(utils.objdict({
          "giphyurl": entry["url"],
          "imgurl": entry["images"]["original"]["url"]
        }))
      if len(gifs):
        return utils.objdict({
          "success": True,
          "gifs": gifs,
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to find gifs for \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def giphy_sticker(query=None, limit=5, rating="g"):
  # https://github.com/Giphy/GiphyAPI
  # ratings: y, g:general_audience, pg:parental_guidance, pg-13:pg_and_above_13, r:restricted
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "q": query,
    "limit": limit,
    "rating": rating,
    "api_key": keys.get("apikeys", "giphy")
  }
  try:
    res = requests.get("http://api.giphy.com/v1/stickers/search", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      gifs = list()
      for entry in reply["data"]:
        gifs.append(utils.objdict({
          "giphyurl": entry["url"],
          "imgurl": entry["images"]["original"]["url"]
        }))
      if len(gifs):
        return utils.objdict({
          "success": True,
          "gifs": gifs,
        })
      return utils.objdict({
        "success": False,
        "reason": "Failed to find gifs for \"%s\"" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_directionslink(locfrom="", locto=""):
  return utils.objdict({
    "success": True,
    "directionslink": "https://www.google.com/maps/dir/%s/%s/" % (locfrom, locto)
  })


def google_finance(query=None):
  if not query or query == "":
    query = random.choice(["QLYS", "JNPR", "CSCO", "GOOGL", "GOOG", "AAPL", "MSFT", "XOM", "BRK.B", "WMT", "JNJ", "GE", "CVX", "WFC", "FB", "TWTR", "TSLA"])
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "q": query
  }
  try:
    res = requests.get("http://finance.google.com/finance/info", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content[6:-2])
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "gfinanceurl": "https://www.google.com/finance?q=%s" % (query),
        "market": reply["e"],
        "company": reply["t"],
        "value": reply["el_cur"] if "el_cur" in reply.keys() else reply["l_cur"],
        "datetime": reply["elt"] if "elt" in reply.keys() else reply["lt"]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_finance_currency(a, f, t):
  if not f or not t or not a or f == "" or t == "" or a == "":
    return utils.objdict({
      "success": False,
      "usage": "<amount> <from> <to>"
    })
  t, f = t.upper(), f.upper()
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "from": f,
    "to": t,
    "a": a
  }
  try:
    res = requests.get("https://finance.google.com/finance/converter", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      result = re.search(r"<span class=bld>([^ ]+)", res.content)
      if result:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "f": f,
          "t": t,
          "a": a,
          "financeurl": "https://www.google.com/finance?q=%s%s" % (f, t),
          "result": float(result.groups()[0])
        })
      else:
        return utils.objdict({
          "success": False,
          "reason": "Failed to convert %s %s to %s" % (a, t.upper(), f.upper())
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_geocode(location=None):
  if not location or location == "":
    return utils.objdict({
      "success": False,
      "usage": "<location>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "address": location,
    "key": keys.get("apikeys", "google"),
  }
  try:
    res = requests.get("https://maps.googleapis.com/maps/api/geocode/json", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "error_message" not in reply:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "address": reply["results"][0]["formatted_address"],
          "latitude": reply["results"][0]["geometry"]["location"]["lat"],
          "longitude": reply["results"][0]["geometry"]["location"]["lng"]
        })
      return utils.objdict({
        "success": False,
        "reason": "%s: %s" % (reply["status"], reply["error_message"])
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_geocode_reverse(latitude=None, longitude=None):
  if not latitude or latitude == "" or not longitude or longitude == "":
    return utils.objdict({
      "success": False,
      "usage": "<latitude> <longitude>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "latlng": "%s,%s" % (latitude, longitude),
    "key": keys.get("apikeys", "google"),
  }
  try:
    res = requests.get("https://maps.googleapis.com/maps/api/geocode/json", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply["status"] != "ZERO_RESULTS" and len(reply["results"]):
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "address": reply["results"][0]["formatted_address"],
          "latitude": reply["results"][0]["geometry"]["location"]["lat"],
          "longitude": reply["results"][0]["geometry"]["location"]["lng"]
        })
      else:
        return utils.objdict({
          "success": False,
          "reason": "Could not reverse geocode %s,%s" % (latitude, longitude)
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_longurl(url):
  # https://www.googleapis.com/urlshortener/v1/url?shortUrl=http://goo.gl/fbsS&key=<key>
  if not url or url == "":
    return utils.objdict({
      "success": False,
      "usage": "<shorturl>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "key": keys.get("apikeys", "google"),
    "shortUrl": url
  }
  try:
    res = requests.get("https://www.googleapis.com/urlshortener/v1/url", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "longurl": reply["longUrl"],
        "shorturl": reply["id"]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_malsearchlink():
  return utils.objdict({
    "success": True,
    "malurl": "https://cse.google.com/cse/home?cx=011750002002865445766:pc60zx1rliu"
  })


def google_maps(location=None, center=None, maptype="roadmap"):
  if not location or location == "":
    return utils.objdict({
      "success": False,
      "usage": "<location>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "key": keys.get("apikeys", "google"),
    "markers": "size:mid|color:red|%s" % (location),
    "center": center if center else location,
    "maptype": maptype.lower() if maptype and maptype.lower() in ["roadmap", "satellite", "hybrid", "terrain"] else "roadmap",
    "size": "800x400",
    "visual_refresh": "true",
    "format": "png",
    "style": "feature:road.highway|element:geometry|visibility:simplified|color:0xc280e9",
    "style": "feature:transit.line|visibility:simplified|color:0xbababa",
    "style": "feature:road.highway|element:labels.text.stroke|visibility:on|color:0xb06eba",
    "style": "feature:road.highway|element:labels.text.fill|visibility:on|color:0xffffff"
  }
  try:
    res = requests.get("http://maps.googleapis.com/maps/api/staticmap", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      geocodedata = google_geocode(location)
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "mapimage": res.content,
        "latitude": geocodedata["latitude"] if geocodedata and "latitude" in geocodedata and geocodedata["latitude"] else None,
        "longitude": geocodedata["longitude"] if geocodedata and "longitude" in geocodedata and geocodedata["longitude"] else None,
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_nearby(location=None, keyword=None, radius=10, limit=5):
  # https://developers.google.com/places/web-service/search
  if not location or location == "":
    return utils.objdict({
      "success": False,
      "usage": "<location>"
    })
  geocodedata = google_geocode(location)
  latitude = geocodedata["latitude"] if geocodedata and "latitude" in geocodedata and geocodedata["latitude"] else None
  longitude = geocodedata["longitude"] if geocodedata and "longitude" in geocodedata and geocodedata["longitude"] else None
  if latitude and longitude:
    customheaders = {
      "User-Agent": "Some script trying to be nice :)"
    }
    validplacetypes = list([
      "accounting", "airport", "amusement_park", "aquarium", "art_gallery", "atm", "bakery", "bank", "bar", "beauty_salon", "bicycle_store",
      "book_store", "bowling_alley", "bus_station", "cafe", "campground", "car_dealer", "car_rental", "car_repair", "car_wash", "casino",
      "cemetery", "church", "city_hall", "clothing_store", "convenience_store", "courthouse", "dentist", "department_store", "doctor",
      "electrician", "electronics_store", "embassy", "fire_station", "florist", "funeral_home", "furniture_store", "gas_station", "gym",
      "hair_care", "hardware_store", "hindu_temple", "home_goods_store", "hospital", "insurance_agency", "jewelry_store", "laundry", "lawyer",
      "library", "liquor_store", "local_government_office", "locksmith", "lodging", "meal_delivery", "meal_takeaway", "mosque", "movie_rental",
      "movie_theater", "moving_company", "museum", "night_club", "painter", "park", "parking", "pet_store", "pharmacy", "physiotherapist",
      "plumber", "police", "post_office", "real_estate_agency", "restaurant", "roofing_contractor", "rv_park", "school", "shoe_store",
      "shopping_mall", "spa", "stadium", "storage", "store", "subway_station", "synagogue", "taxi_stand", "train_station", "transit_station",
      "travel_agency", "university", "veterinary_care", "zoo"
    ])
    kwpt = keyword.lower().replace(" ", "_") if keyword else None
    if kwpt and kwpt in validplacetypes:
      searchtype = kwpt
      nparams = {
        "key": keys.get("apikeys", "google"),
        "location": "%s,%s" % (latitude, longitude),
        "rankby": "prominence",
        "radius": radius * 1000,
        "type": searchtype,
      }
    else:
      searchtype = keyword if keyword else random.choice(validplacetypes)
      nparams = {
        "key": keys.get("apikeys", "google"),
        "location": "%s,%s" % (latitude, longitude),
        "rankby": "prominence",
        "radius": radius * 1000,
        "keyword": searchtype,
      }
    dparams = {
      "key": keys.get("apikeys", "google"),
      "placeid": None,
    }
    pparams = {
      "key": keys.get("apikeys", "google"),
      "photoreference": None,
      "maxwidth": 800,
      "maxheight": 200,
    }
    try:
      nres = requests.get("https://maps.googleapis.com/maps/api/place/nearbysearch/json", headers=customheaders, params=nparams, verify=False)
      if nres.status_code == 200:
        nreply = json.loads(nres.content)
        if nreply["status"] == "OK":
          nearbyresults = list()
          for entry in nreply["results"][:limit]:
            lat, lon, name, vicinity, types, address, placeurl, website, intphone, phone, openinghours, opennow, rating, reviews, photos = None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
            lat, lon = entry["geometry"]["location"]["lat"], entry["geometry"]["location"]["lng"]
            name = entry["name"]
            vicinity = entry["vicinity"]
            types = entry["types"]
            dparams["placeid"] = entry["place_id"]
            dres = requests.get("https://maps.googleapis.com/maps/api/place/details/json", headers=customheaders, params=dparams, verify=False)
            if dres.status_code == 200:
              dreply = json.loads(dres.content)
              if dreply["status"] == "OK":
                address = dreply["result"]["formatted_address"] if dreply["result"]["formatted_address"] and dreply["result"]["formatted_address"] != "" else None
                placeurl = dreply["result"]["url"] if dreply["result"]["url"] and dreply["result"]["url"] != "" else None
                website = dreply["result"]["website"] if "website" in dreply["result"] and dreply["result"]["website"] and dreply["result"]["website"] != "" else None
                intphone = dreply["result"]["international_phone_number"] if "international_phone_number" in dreply["result"] and dreply["result"]["international_phone_number"] and dreply["result"]["international_phone_number"] != "" else None
                phone = dreply["result"]["formatted_phone_number"] if "formatted_phone_number" in dreply["result"] and dreply["result"]["formatted_phone_number"] and dreply["result"]["formatted_phone_number"] != "" else None
                openinghours = dreply["result"]["opening_hours"]["weekday_text"] if "opening_hours" in dreply["result"] and dreply["result"]["opening_hours"] and dreply["result"]["opening_hours"] != "" else None
                opennow = dreply["result"]["opening_hours"]["open_now"] if "opening_hours" in dreply["result"] and dreply["result"]["opening_hours"]["open_now"] and dreply["result"]["opening_hours"]["open_now"] != "" else None
                rating = int(dreply["result"]["rating"]) if "rating" in dreply["result"] and dreply["result"]["rating"] and dreply["result"]["rating"] != "" else None
                ratingmax = 5
                ratingstars = ("%s%s" % ("★" * rating, "☆" * (ratingmax - rating))) if rating and ratingmax else None
                if "reviews" in dreply["result"]:
                  reviews = list()
                  for review in dreply["result"]["reviews"][:limit]:
                    author = review["author_name"] if "author_name" in review and review["author_name"] and review["author_name"] != "" else None
                    authorurl = review["author_url"] if "author_url" in review and review["author_url"] and review["author_url"] != "" else None
                    when = review["relative_time_description"] if "relative_time_description" in review and review["relative_time_description"] and review["relative_time_description"] != "" else None
                    reviewrating = int(review["rating"]) if "rating" in review and review["rating"] and review["rating"] != "" else None
                    reviewratingstars = ("%s%s" % ("★" * reviewrating, "☆" * (ratingmax - reviewrating))) if reviewrating and ratingmax else None
                    reviewtext = review["text"] if "text" in review and review["text"] and review["text"] != "" else None
                    reviews.append(utils.objdict({
                      "author": author,
                      "authorurl": authorurl,
                      "rating": reviewrating,
                      "ratingstars": reviewratingstars,
                      "when": when,
                      "reviewtext": reviewtext,
                    }))
                if "photos" in dreply["result"]:
                  photos = list()
                  for photo in dreply["result"]["photos"][:limit]:
                    pparams["photoreference"] = photo["photo_reference"]
                    pres = requests.get("https://maps.googleapis.com/maps/api/place/photo", headers=customheaders, params=pparams, verify=False)
                    if pres.status_code == 200:
                      photos.append(pres.url)
            nearbyresults.append(utils.objdict({
              "lat": lat,
              "lon": lon,
              "name": name,
              "vicinity": vicinity,
              "types": types,
              "address": address,
              "placeurl": placeurl,
              "website": website,
              "intphone": intphone,
              "phone": phone,
              "openinghours": openinghours,
              "opennow": opennow,
              "rating": rating,
              "ratingstars": ratingstars,
              "ratingmax": ratingmax,
              "reviews": reviews,
              "photos": photos,
            }))
          return utils.objdict({
             "success": True,
             "location": location,
             "radius": radius,
             "searchtype": searchtype,
             "nearbyresults": nearbyresults,
          })
        else:
          return utils.objdict({
            "success": False,
            "reason": "Failed to find relevant results: %s - %s" % (location, searchtype)
          })
      return utils.objdict({
        "success": False,
        "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
      })
    except Exception as ex:
      import traceback
      traceback.print_exc()
      return utils.objdict({
        "success": False,
        "exception": ex
      })
  return utils.objdict({
    "success": False,
    "reason": "Failed to geolocate: %s" % (location)
  })


def google_news_business(limit=5, cc=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    if cc:
      res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=b&output=rss" % cc.lower())
    else:
      localgeo = localgeoinfo()
      if localgeo["success"]:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=b&output=rss" % localgeo["geoinfo"]["countryCode"].lower())
      else:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&topic=b&output=rss")
    feed = list()
    for post in res.entries:
      m = re.search(r"https://t\d.gstatic.com/images\?q=tbn:[^\"]+", post.summary)
      imgurl = post.summary[m.start():m.end()] if m else None
      feed.append(utils.objdict({
        "title": post.title,
        "url": post.link.split("&url=")[1],
        "imageurl": imgurl
      }))
    return utils.objdict({
      "success": True,
      "requesturl": res.url,
      "topic": "Business",
      "feed": feed[:limit]
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_news_entertainment(limit=5, cc=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    if cc:
      res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=e&output=rss" % cc.lower())
    else:
      localgeo = localgeoinfo()
      if localgeo["success"]:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=e&output=rss" % localgeo["geoinfo"]["countryCode"].lower())
      else:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&topic=e&output=rss")
    feed = list()
    for post in res.entries:
      m = re.search(r"https://t\d.gstatic.com/images\?q=tbn:[^\"]+", post.summary)
      imgurl = post.summary[m.start():m.end()] if m else None
      feed.append(utils.objdict({
        "title": post.title,
        "url": post.link.split("&url=")[1],
        "imageurl": imgurl
      }))
    return utils.objdict({
      "success": True,
      "requesturl": res.url,
      "topic": "Entertainment",
      "feed": feed[:limit]
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_news_health(limit=5, cc=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    if cc:
      res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=m&output=rss" % cc.lower())
    else:
      localgeo = localgeoinfo()
      if localgeo["success"]:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=m&output=rss" % localgeo["geoinfo"]["countryCode"].lower())
      else:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&topic=m&output=rss")
    feed = list()
    for post in res.entries:
      m = re.search(r"https://t\d.gstatic.com/images\?q=tbn:[^\"]+", post.summary)
      imgurl = post.summary[m.start():m.end()] if m else None
      feed.append(utils.objdict({
        "title": post.title,
        "url": post.link.split("&url=")[1],
        "imageurl": imgurl
      }))
    return utils.objdict({
      "success": True,
      "requesturl": res.url,
      "topic": "Health",
      "feed": feed[:limit]
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_news_science(limit=5, cc=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    if cc:
      res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=snc&output=rss" % cc.lower())
    else:
      localgeo = localgeoinfo()
      if localgeo["success"]:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=snc&output=rss" % localgeo["geoinfo"]["countryCode"].lower())
      else:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&topic=snc&output=rss")
    feed = list()
    for post in res.entries:
      m = re.search(r"https://t\d.gstatic.com/images\?q=tbn:[^\"]+", post.summary)
      imgurl = post.summary[m.start():m.end()] if m else None
      feed.append(utils.objdict({
        "title": post.title,
        "url": post.link.split("&url=")[1],
        "imageurl": imgurl
      }))
    return utils.objdict({
      "success": True,
      "requesturl": res.url,
      "topic": "Science",
      "feed": feed[:limit]
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_news_scitech(limit=5, cc=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    if cc:
      res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=t&output=rss" % cc.lower())
    else:
      localgeo = localgeoinfo()
      if localgeo["success"]:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=t&output=rss" % localgeo["geoinfo"]["countryCode"].lower())
      else:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&topic=t&output=rss")
    feed = list()
    for post in res.entries:
      m = re.search(r"https://t\d.gstatic.com/images\?q=tbn:[^\"]+", post.summary)
      imgurl = post.summary[m.start():m.end()] if m else None
      feed.append(utils.objdict({
        "title": post.title,
        "url": post.link.split("&url=")[1],
        "imageurl": imgurl
      }))
    return utils.objdict({
      "success": True,
      "requesturl": res.url,
      "topic": "Sci/Tech",
      "feed": feed[:limit]
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_news_sports(limit=5, cc=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    if cc:
      res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=s&output=rss" % cc.lower())
    else:
      localgeo = localgeoinfo()
      if localgeo["success"]:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&topic=s&output=rss" % localgeo["geoinfo"]["countryCode"].lower())
      else:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&topic=s&output=rss")
    feed = list()
    for post in res.entries:
      m = re.search(r"https://t\d.gstatic.com/images\?q=tbn:[^\"]+", post.summary)
      imgurl = post.summary[m.start():m.end()] if m else None
      feed.append(utils.objdict({
        "title": post.title,
        "url": post.link.split("&url=")[1],
        "imageurl": imgurl
      }))
    return utils.objdict({
      "success": True,
      "requesturl": res.url,
      "topic": "Sports",
      "feed": feed[:limit]
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_news_topstories(limit=5, cc=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    if cc:
      res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&output=rss" % cc.lower())
    else:
      localgeo = localgeoinfo()
      if localgeo["success"]:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&ned=%s&output=rss" % localgeo["geoinfo"]["countryCode"].lower())
      else:
        res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&output=rss")
    feed = list()
    for post in res.entries:
      m = re.search(r"https://t\d.gstatic.com/images\?q=tbn:[^\"]+", post.summary)
      imgurl = post.summary[m.start():m.end()] if m else None
      feed.append(utils.objdict({
        "title": post.title,
        "url": post.link.split("&url=")[1],
        "imageurl": imgurl
      }))
    return utils.objdict({
      "success": True,
      "requesturl": res.url,
      "topic": "Top Stories",
      "feed": feed[:limit]
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_news_world(limit=5):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = feedparser.parse("https://news.google.com/news?cf=all&pz=1&topic=w&output=rss")
    feed = list()
    for post in res.entries:
      m = re.search(r"https://t\d.gstatic.com/images\?q=tbn:[^\"]+", post.summary)
      imgurl = post.summary[m.start():m.end()] if m else None
      feed.append(utils.objdict({
        "title": post.title,
        "url": post.link.split("&url=")[1],
        "imageurl": imgurl
      }))
    return utils.objdict({
      "success": True,
      "requesturl": res.url,
      "topic": "World",
      "feed": feed[:limit]
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_placelink(location=None):
  if not location or location == "":
    return utils.objdict({
      "success": False,
      "usage": "<location>"
    })
  return utils.objdict({
    "success": True,
    "placelink": "https://www.google.com/maps/place/%s/" % (location)
  })


def google_safebrowsing(url=None):
  if not url or url == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      url = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  lurl = longurl(url)
  if lurl.success:
    url = lurl.longurl
  # https://developers.google.com/safe-browsing/
  # https://developers.google.com/safe-browsing/lookup_guide
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "key": keys.get("apikeys", "google"),
    "client": "api",
    "appver": "1.5.2",
    "pver": "3.0",
    "url": url
  }
  try:
    res = requests.get("https://sb-ssl.google.com/safebrowsing/api/lookup", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "query": url,
        "reputation": res.content.title(),
        "gsburl": "https://www.google.com/transparencyreport/safebrowsing/?hl=en",
        "trurl": "https://www.google.com/transparencyreport/safebrowsing/diagnostic/index.html#url=%s" % (url)
      })
    elif res.status_code == 204:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "query": url,
        "reputation": "Unknown",
        "gsburl": "https://www.google.com/transparencyreport/safebrowsing/?hl=en",
        "trurl": "https://www.google.com/transparencyreport/safebrowsing/diagnostic/index.html#url=%s" % (url)
      })
    else:
      return utils.objdict({
        "success": False,
        "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_search(query):
  # https://developers.google.com/custom-search/json-api/v1/reference/cse/list
  # https://www.googleapis.com/customsearch/v1?q=query&alt=json&cx=005983647730461686104:qfayqkczxfg&key=<key>
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "key": keys.get("apikeys", "google"),
    "alt": "json",
    "safe": "high",
    "cx": "005983647730461686104:qfayqkczxfg",
    "q": query,
  }
  try:
    res = requests.get("https://www.googleapis.com/customsearch/v1", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)

      response = list()
      for item in reply["items"]:
        response.append(utils.objdict({
          "title": item["title"],
          "description": item["snippet"],
          "link": item["link"]
        }))

      return utils.objdict({
        "success": True,
        "searchtime": reply["searchInformation"]["searchTime"],
        "totalresults": int(reply["searchInformation"]["totalResults"]),
        "response": response
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_shorturl(url):
  # https://www.googleapis.com/urlshortener/v1/url?longUrl=http://www.google.com/&key=<key>
  if not url or url == "":
    return utils.objdict({
      "success": False,
      "usage": "<longurl>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "key": keys.get("apikeys", "google"),
    "fields": "id,longUrl"
  }
  payload = {
    "longUrl": url
  }
  try:
    res = requests.post("https://www.googleapis.com/urlshortener/v1/url", headers=customheaders, params=params, json=payload, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "longurl": url,
        "shorturl": reply["id"]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_streetview(location="India"):
  # https://developers.google.com/maps/documentation/streetview/intro
  if not location or location == "":
    return utils.objdict({
      "success": False,
      "usage": "<location>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "key": keys.get("apikeys", "google"),
    "size": "800x400",
    "location": location,
  }
  try:
    res = requests.get("https://maps.googleapis.com/maps/api/streetview", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      # http://stackoverflow.com/questions/7839746/detecting-we-have-no-imagery-of-google-maps-street-view-static-images
      if utils.data_hashes(data=res.content, algo="md5") not in ["04c856f384f17077bf021aa6803bd623", "b623cbb0fc10c207d254e0c26432a79c"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "streetview": res.content
        })
      return utils.objdict({
        "success": False,
        "reason": "Expected an image from streetview but got none for query: %s" % (location)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def google_youtube(query, limit=5):
  # https://www.googleapis.com/youtube/v3/search?part=id&type=video&maxResults=10&q=query&key=<key>
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "key": keys.get("apikeys", "google"),
    "part": "snippet",
    "type": "video",
    "limit": limit if limit and limit > 0 and limit < 50 else 50,
    "q": query
  }
  try:
    res = requests.get("https://www.googleapis.com/youtube/v3/search", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      videos = list()
      for entry in reply["items"]:
        videos.append(utils.objdict({
          "videotitle": entry["snippet"]["title"],
          "description": entry["snippet"]["description"],
          "published": entry["snippet"]["publishedAt"],
          "videourl": "https://www.youtube.com/watch?v=%s" % (entry["id"]["videoId"]),
          "thumbnail": entry["snippet"]["thumbnails"]["high"]["url"],
          "channeltitle": entry["snippet"]["channelTitle"]
        }))
      if len(videos):
        return utils.objdict({
          "success": True,
          "query": query,
          "requesturl": "https://www.youtube.com/results?search_query=%s" % (query),
          "videos": videos
        })
      else:
        return utils.objdict({
          "success": False,
          "reason": "No results found for search query: %s" % (query)
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def hackernews_askstories(limit=5):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  try:
    res = requests.get("https://hacker-news.firebaseio.com/v0/askstories.json", headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "askstories": reply[:limit]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def hackernews_item(itemid):
  if not itemid or itemid == "":
    return utils.objdict({
      "success": False,
      "usage": "<itemid>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  try:
    res = requests.get("https://hacker-news.firebaseio.com/v0/item/%d.json" % itemid, headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "created": reply["time"],
        "author": reply["by"],
        "authorurl": "https://news.ycombinator.com/user?id=%s" % (reply["by"]),
        "type": reply["type"],
        "itemid": reply["id"],
        "itemparentid": reply["parent"] if "parent" in reply else None,
        "commentscount": reply["descendants"] if "descendants" in reply else 0,
        "score": reply["score"] if "score" in reply else None,
        "title": reply["title"] if "title" in reply else None,
        "url": reply["url"] if "url" in reply else None,
        "hnurl": "https://news.ycombinator.com/item?id=%d" % (reply["id"]),
        "text": reply["text"] if "text" in reply else None
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def hackernews_jobstories(limit=5):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  try:
    res = requests.get("https://hacker-news.firebaseio.com/v0/jobstories.json", headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "jobstories": reply[:limit]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def hackernews_newstories(limit=5):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  try:
    res = requests.get("https://hacker-news.firebaseio.com/v0/newstories.json", headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "newstories": reply[:limit]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def hackernews_showstories(limit=5):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  try:
    res = requests.get("https://hacker-news.firebaseio.com/v0/showstories.json", headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "showstories": reply[:limit]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def hackernews_topstories(limit=5):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  try:
    res = requests.get("https://hacker-news.firebaseio.com/v0/topstories.json", headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "topstories": reply[:limit]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def hackernews_user(user):
  if not user or user == "":
    return utils.objdict({
      "success": False,
      "usage": "<username>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  try:
    res = requests.get("https://hacker-news.firebaseio.com/v0/user/%s.json" % user, headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "created": reply["created"],
        "userid": reply["id"],
        "karma": reply["karma"],
        "submittedids": reply["submitted"]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def haveibeenpwned(email="test@google.com"):
  if not email or email == "":
    return utils.objdict({
      "success": False,
      "usage": "<emailaddr>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "truncateResponse": False
  }
  try:
    res = requests.get("https://haveibeenpwned.com/api/v2/breachedaccount/%s" % (email), headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "email": email,
        "pwned": True,
        "breachdata": res.json()
      })
    elif res.status_code == 404:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "email": email,
        "pwned": False,
        "breachdata": None
      })
    else:
      return utils.objdict({
        "success": False,
        "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def hackertarget_dnslookup(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  lurl = longurl(query)
  if lurl.success:
    query = utils.url_to_domain(lurl.longurl)
  if utils.is_ipv4(query) or utils.is_domain(query):
    return utils.objdict({
      "success": True,
      "headerurl": "http://api.hackertarget.com/dnslookup/?q=%s" % (query)
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
    })


def hackertarget_geoip(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  lurl = longurl(query)
  if lurl.success:
    query = utils.url_to_domain(lurl.longurl)
  if utils.is_ipv4(query) or utils.is_domain(query):
    return utils.objdict({
      "success": True,
      "headerurl": "http://api.hackertarget.com/geoip/?q=%s" % (query)
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
    })


def hackertarget_httpheaders(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  lurl = longurl(query)
  if lurl.success:
    query = utils.url_to_domain(lurl.longurl)
  if utils.is_ipv4(query) or utils.is_domain(query):
    return utils.objdict({
      "success": True,
      "headerurl": "http://api.hackertarget.com/httpheaders/?q=%s" % (query)
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address or domain but got %s instead" % (query)
    })


def hackertarget_nmap(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  lurl = longurl(query)
  if lurl.success:
    query = utils.url_to_domain(lurl.longurl)
  if utils.is_ipv4(query) or utils.is_domain(query):
    return utils.objdict({
      "success": True,
      "headerurl": "http://api.hackertarget.com/nmap/?q=%s" % (query)
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
    })


def hackertarget_pagelinks(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  lurl = longurl(query)
  if lurl.success:
    query = utils.url_to_domain(lurl.longurl)
  if utils.is_ipv4(query) or utils.is_domain(query):
    return utils.objdict({
      "success": True,
      "headerurl": "http://api.hackertarget.com/pagelinks/?q=%s" % (query)
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
    })


def hackertarget_ping(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  lurl = longurl(query)
  if lurl.success:
    query = utils.url_to_domain(lurl.longurl)
  if utils.is_ipv4(query) or utils.is_domain(query):
    return utils.objdict({
      "success": True,
      "headerurl": "http://api.hackertarget.com/nping/?q=%s" % (query)
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
    })


def hackertarget_reversednslookup(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[ip]"
      })
  if utils.is_ipv4(query):
    return utils.objdict({
      "success": True,
      "headerurl": "http://api.hackertarget.com/reversedns/?q=%s" % (query)
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address but got %s instead" % (query)
    })


def hackertarget_subnet(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  lurl = longurl(query)
  if lurl.success:
    query = utils.url_to_domain(lurl.longurl)
  if utils.is_ipv4(query):
    return utils.objdict({
      "success": True,
      "headerurl": "http://api.hackertarget.com/subnetcalc/?q=%s" % (query)
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address but got %s instead" % (query)
    })


def hackertarget_traceroute(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  lurl = longurl(query)
  if lurl.success:
    query = utils.url_to_domain(lurl.longurl)
  if utils.is_ipv4(query) or utils.is_domain(query):
    return utils.objdict({
      "success": True,
      "headerurl": "http://api.hackertarget.com/mtr/?q=%s" % (query)
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
    })


def hackertarget_whois(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  lurl = longurl(query)
  if lurl.success:
    query = utils.url_to_domain(lurl.longurl)
  if utils.is_ipv4(query) or utils.is_domain(query):
    return utils.objdict({
      "success": True,
      "headerurl": "http://api.hackertarget.com/whois/?q=%s" % (query)
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
    })


def horoscope(sunsign=None, when=None):
  if not sunsign or sunsign == "":
    sunsign = random.choice(["Aries", "Taurus", "Gemini", "Cancer", "Leo", "Virgo", "Libra", "Scorpio", "Sagittarious", "Capricorn", "Aquaries", "Pisces"])
  if not when or when == "" or when.lower() not in list(["today", "week", "month", "year"]):
    when = "today"
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    if "today" in when.lower():
      res = requests.get("http://horoscope-api.herokuapp.com/horoscope/today/%s" % (sunsign), headers=customheaders, verify=False)
    elif "week" in when.lower():
      res = requests.get("http://horoscope-api.herokuapp.com/horoscope/week/%s" % (sunsign), headers=customheaders, verify=False)
    elif "month" in when.lower():
      res = requests.get("http://horoscope-api.herokuapp.com/horoscope/month/%s" % (sunsign), headers=customheaders, verify=False)
    elif "year" in when.lower():
      res = requests.get("http://horoscope-api.herokuapp.com/horoscope/year/%s" % (sunsign), headers=customheaders, verify=False)
    else:
      res = None
    if res:
      if res.status_code == 200:
        if "today" in when.lower():
          horoscope, whenstr = (res.json()["horoscope"].replace("[u'", "").replace("['", ""), res.json()["date"])
        if "week" in when.lower():
          horoscope, whenstr = (res.json()["horoscope"].replace("[u'", "").replace("['", ""), res.json()["week"])
        if "month" in when.lower():
          horoscope, whenstr = (res.json()["horoscope"].replace("[u'", "").replace("['", ""), res.json()["month"])
        if "year" in when.lower():
          horoscope, whenstr = (res.json()["horoscope"].replace("[u'", "").replace("['", ""), res.json()["year"])
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "sunsign": sunsign,
          "when": when,
          "whenstr": whenstr,
          "horoscope": horoscope,
        })
      else:
        return utils.objdict({
          "success": False,
          "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
        })
    else:
      return utils.objdict({
        "success": False,
        "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def howdoi(query=None):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  parser = hdi.get_parser()
  args = vars(parser.parse_args(query.split(" ")))
  result = hdi.howdoi(args)
  if result:
    return utils.objdict({
      "success": True,
      "howdoi": result
    })
  else:
    return utils.objdict({
      "success": False,
      "reason": "Failed to find answers for query: %s" % (query)
    })


def identicon(data=None):
  # http://stackoverflow.com/questions/405717/how-to-generate-the-random-default-gravatars-like-on-stack-overflow
  # https://www.gravatar.com/avatar/f9879d71855b5ff21e4963273a886bfc?s=200&d=identicon&r=PG
  if not data or data == "":
    return utils.objdict({
      "success": False,
      "usage": "<data>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
  }
  params = {
    "s": 200,
    "r": "PG",
    "d": "identicon",
  }
  try:
    res = requests.get("https://www.gravatar.com/avatar/%s" % (data), headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "identicon": res.content
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def ipdomaingeoinfo(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  geostats = {
    "as": None,
    "asn": None,
    "city": None,
    "continent_code": None,
    "country_code3": None,
    "country_code": None,
    "country_name": None,
    "hostname": None,
    "ip": None,
    "isp": None,
    "latitude": None,
    "longitude": None,
    "metro_code": None,
    "org": None,
    "postal_code": None,
    "region": None,
    "region_code": None,
    "region_name": None,
    "time_zone": None,
    "zip_code": None,
  }
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    query = utils.url_to_domain(query)
    if utils.is_ipv4(query):
      ipaddress = query
    elif utils.is_domain(query):
      dnsdata = shodan_dns(query)
      if dnsdata.success:
        ipaddress = dnsdata.answer
      else:
        return utils.objdict({
          "success": False,
          "reason": "Could not resolve ipv4 address for domain %s" % (query)
        })
    else:
      ipaddress = None
    if ipaddress:
      providers = [
        "https://freegeoip.net/json/%s" % (ipaddress),
        "http://ip-api.com/json/%s" % (ipaddress),
        "http://ipinfo.io/%s/json/" % (ipaddress)
      ]
      for uri in providers:
        res = requests.get(uri)
        if res:
          try:
            result = json.loads(res.content)
          except Exception as ex:
            continue
          for key in geostats.keys():
            if not geostats[key] and key in result.keys():
              geostats[key] = result[key]
      return utils.objdict({
        "success": True,
        "query": query,
        "ipaddress": ipaddress,
        "geoinfo": utils.objdict(geostats)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def isgd(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<url>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "format": "simple",
    "url": query
  }
  try:
    res = requests.get("https://is.gd/create.php", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "query": query,
        "shorturl": res.content.strip()
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def isitup(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<domain|ip>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("https://isitup.org/%s.json" % (query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "domain": reply["domain"],
        "port": reply["port"],
        "status_code": reply["status_code"],
        "response_ip": reply["response_ip"],
        "response_code": reply["response_code"],
        "response_time": reply["response_time"]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def itsthisforthat():
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "json": ""
  }
  try:
    res = requests.get("http://itsthisforthat.com/api.php", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "this": reply["this"],
        "that": reply["that"]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def jwa_whois(ipaddr):
  # https://jsonwhoisapi.com/docs/
  pass


def littlebobby(query=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    if query and query.lower() == "current":
      res = requests.get("http://www.littlebobbycomic.com/", headers=customheaders, verify=False)
      tree = html.fromstring(res.content)
      stripurl = tree.xpath('//div[@class="flexslider"]/ul[@class="slides"]/li/img/@src')[0]
      alttext = tree.xpath('//div[@class="flexslider"]/ul[@class="slides"]/li/img/@alt')[0]
      if stripurl:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "comic": utils.objdict({
            "alttext": alttext,
            "imgurl": stripurl,
            "img": utils.download(stripurl),
            "stripurl": res.url,
            "caption": "Little Bobby | A Sunday Morning Web Comic on Technology and Security"
          })
        })
    else:
      weekid = random.randint(0, 68)
      res = requests.get("http://www.littlebobbycomic.com/projects/week-%d/" % weekid, headers=customheaders, verify=False)
      if res.status_code == 200:
        tree = html.fromstring(res.content)
        stripurl = tree.xpath('//img[@class="attachment-full size-full wp-post-image"]/@src')[0]
        alttext = tree.xpath('//img[@class="attachment-full size-full wp-post-image"]/@alt')[0]
        if stripurl:
          return utils.objdict({
            "success": True,
            "requesturl": res.url,
            "comic": utils.objdict({
              "alttext": alttext,
              "imgurl": stripurl,
              "img": utils.download(stripurl),
              "stripurl": res.url,
              "caption": "Week %d | Little Bobby" % (weekid)
            })
          })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def localgeoinfo():
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = urllib2.urlopen("http://ip-api.com/json/")
    if res:
      result = json.load(res)
      return utils.objdict({
        "success": True,
        "geoinfo": utils.objdict(result)
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def longurl(query):
  return utils.objdict({
    "success": True,
    "longurl": query
  })


def email_mailgun(efrom, eto, subject="Test email", message="Ignore."):
  return requests.post("https://api.mailgun.net/v3/%s/messages" % keys.get("apikeys", "mailgundomain"),
    auth=("api", keys.get("apikeys", "mailgun")),
    data={
      "from": "%s" % (efrom),
      "to": eto if type(eto) == "list" else [eto],
      "subject": subject,
      "text": message
    }
  )


def mathjs(expr):
  # http://api.mathjs.org/v1/?expr=2*(7-3)
  # http://api.mathjs.org/v1/?expr=2%2F3
  # http://api.mathjs.org/v1/?expr=2%2F3&precision=3
  if not expr or expr == "":
    return utils.objdict({
      "success": False,
      "usage": "<expr>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "expr": expr
  }
  try:
    res = requests.get("https://api.mathjs.org/v1/", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "expr": expr,
        "result": res.content
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def nasa_apod():
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("https://api.nasa.gov/planetary/apod?api_key=%s" % keys.get("apikeys", "nasa"), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "apod": utils.objdict({
          "copyright": reply["copyright"] if "copyright" in reply and reply["copyright"] else None,
          "date": reply["date"] if "date" in reply and reply["date"] else None,
          "explanation": reply["explanation"] if "explanation" in reply and reply["explanation"] else None,
          "title": reply["title"] if "title" in reply and reply["title"] else None,
          "imgurl": reply["url"] if "url" in reply and reply["url"] else None,
          "hdimgurl": reply["hdurl"] if "hdurl" in reply and reply["hdurl"] else None,
        })
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def numbersapi(number):
  apiurl = "http://numbersapi.com/random" if not number or number == "" else "http://numbersapi.com/%s" % (number)
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "min": 0 if not number or number == "" else number,
    "max": 999999999999999 if not number or number == "" else number,
    "notfound": "floor",
    "json": ""
  }
  try:
    res = requests.get(apiurl, headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "numberfact": res.json()["text"]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def omdbapi(query="Rocky IV", plot="short"):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<moviename>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "t": query,
    "plot": plot.lower(),
    "r": "json"
  }
  try:
    res = requests.get("http://www.omdbapi.com/", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply["Response"] and reply["Response"] != "False":
        result = list()
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["Title"],
          "year": "-".join(reply["Year"].encode("utf-8").split("–")) if reply["Year"] != "N/A" else None,
          "rated": reply["Rated"] if reply["Rated"] != "N/A" else None,
          "released": reply["Released"] if reply["Released"] != "N/A" else None,
          "director": reply["Director"].split(", ") if reply["Director"] != "N/A" else None,
          "writer": reply["Writer"].split(", ") if reply["Writer"] != "N/A" else None,
          "actor": reply["Actors"].split(", ") if reply["Actors"] != "N/A" else None,
          "plot": reply["Plot"] if reply["Plot"] != "N/A" else None,
          "country": reply["Country"] if reply["Country"] != "N/A" else None,
          "language": reply["Language"].split(", ") if reply["Language"] != "N/A" else None,
          "rating": reply["imdbRating"] if reply["imdbRating"] != "N/A" else None,
          "votes": reply["imdbVotes"] if reply["imdbVotes"] != "N/A" else None,
          "runtime": "%sm" % reply["Runtime"].split(" ")[0] if reply["Runtime"] != "N/A" else None,
          "genre": reply["Genre"].split(", ") if reply["Genre"] != "N/A" else None,
          "awards": reply["Awards"] if reply["Awards"] != "N/A" else None,
          "posterurl": reply["Poster"] if reply["Poster"] and reply["Poster"] != "N/A" else None,
          "imdburl": "http://imdb.com/title/%s" % reply["imdbID"] if reply["imdbID"] and reply["imdbID"] != "N/A" else None
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def opennotify_astrosinspace():
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("http://api.open-notify.org/astros.json", headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply["message"] == "success":
        astros = list()
        for entry in reply["people"]:
          astros.append(utils.objdict({
            "name": entry["name"],
            "spacecraft": entry["craft"]
          }))
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "astros": astros
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP 200 status code but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def opennotify_issnow():
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("http://api.open-notify.org/iss-now.json", headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply["message"] == "success":
        locationdata = geoname_datetime(reply["iss_position"]["latitude"], reply["iss_position"]["longitude"])
        if locationdata.success:
          locationname = locationdata.location
          locationdate = locationdata.date
          locationtime = locationdata.time
        else:
          locationname = None
          locationdate = None
          locationtime = None
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "currenttime": utils.time_to_local_string(reply["timestamp"]),
          "latitude": reply["iss_position"]["latitude"],
          "longitude": reply["iss_position"]["longitude"],
          "location": locationname,
          "locationdate": locationdate,
          "locationtime": locationtime
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP 200 status code but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def opennotify_isspass(location=None, limit=5):
  if not location or location == "":
    localgeo = localgeoinfo()
    if localgeo["success"]:
      location = localgeo["geoinfo"]["city"]
      lat = localgeo["geoinfo"]["lat"]
      lon = localgeo["geoinfo"]["lon"]
  else:
    geodata = google_geocode(location)
    if geodata.success:
      lat = geodata.latitude
      lon = geodata.longitude
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("http://api.open-notify.org/iss-pass.json?lat=%s&lon=%s&n=%d" % (lat, lon, 5 if limit < 1 or limit > 100 else limit), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      passes = list()
      for entry in reply["response"]:
        passes.append(utils.objdict({
          "risetime": entry["risetime"],
          "risetime_formatted": utils.time_to_local_string(entry["risetime"]),
          "duration": entry["duration"]
        }))
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "latitude": lat,
        "longitude": lon,
        "location": location.title(),
        "passes": passes
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP 200 status code but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def pastebin_create(pastedata, isprivate=True):
  if not pastedata or pastedata == "":
    return utils.objdict({
      "success": False,
      "usage": "<pastedata>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  data = {
    "api_dev_key": keys.get("apikeys", "pastebin"),
    "api_option": "paste",
    "api_paste_code": pastedata,
    "api_paste_private": "1" if isprivate else "0",
    "api_paste_expire_date": "1H",
    "api_paste_format": None
  }
  try:
    res = requests.post("http://pastebin.com/api/api_post.php", headers=customheaders, data=data, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "pasteurl": res.content
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP 201 status code but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def pastebin_retrieve(pasteid):
  if not pasteid or pasteid == "":
    return utils.objdict({
      "success": False,
      "usage": "<pasteid>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("http://pastebin.com/raw/%s" % (pasteid), headers=customheaders, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "pastedata": res.content
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def qrserver_create(data=None, size="m", imgformat="png", fgcolor="000000", bgcolor="ffffff"):
  # http://goqr.me/api/
  # http://api.qrserver.com/v1/create-qr-code/?data=HelloWorld!&size=100x100&format=svg
  if not data or data == "":
    return utils.objdict({
      "success": False,
      "usage": "<data>"
    })
  size = size.lower()
  if size in ["s", "m", "l"]:
    if size == "s":
      size = "100x100"
    elif size == "m":
      size = "250x250"
    elif size == "l":
      size = "500x500"
    else:
      size = "250x250"
  imgformat = imgformat.lower()
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "data": data,
    "size": size,
    "format": imgformat if imgformat in ["png", "gif", "jpeg", "jpg", "svg", "eps"] else "png",
    "color": fgcolor,
    "bgcolor": bgcolor,
  }
  try:
    res = requests.get("http://api.qrserver.com/v1/create-qr-code/", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "qrdata": res.content
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def quotesrest(category=None):
  categories = ["inspire", "management", "sports", "life", "funny", "love", "art"]
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "category": category.lower() if category and category.lower() in categories else random.choice(categories)
  }
  try:
    res = requests.get("http://quotes.rest/qod.json", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      quotejson = res.json()
      if "contents" in quotejson.keys() and "quotes" in quotejson["contents"].keys() and quotejson["contents"]["quotes"]:
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "quotetext": quotejson["contents"]["quotes"][0]["quote"],
          "quoteauthor": quotejson["contents"]["quotes"][0]["author"]
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def razorpay_ifsc(ifsc=None):
  # https://razorpay.com/blog/tech/2016/02/05/razorpay-ifsc-toolkit.html
  if not ifsc or ifsc == "":
    return utils.objdict({
      "success": False,
      "usage": "<ifsc>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("https://ifsc.razorpay.com/%s" % (ifsc.upper()), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      return utils.objdict({
        "success": True,
        "query": ifsc,
        "response": utils.objdict({
          "ifsc": reply["IFSC"].strip(),
          "contact": reply["CONTACT"],
          "bank": reply["BANK"].strip().title(),
          "branch": reply["BRANCH"].strip().title(),
          "address": reply["ADDRESS"].strip().title(),
          "city": reply["CITY"].strip().title(),
          "district": reply["DISTRICT"].strip().title(),
          "state": reply["STATE"].strip().title(),
        })
      })
    return utils.objdict({
      "success": False,
      "reason": "Could not find details for %s on RazorPay" % (ifsc)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def reddit_search(query=None, limit=5):
  # https://www.reddit.com/search.json?q=query&limit=5
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "q": query,
    "limit": limit if limit and limit > 0 and limit < 999999 else 999999
  }
  try:
    res = requests.get("https://www.reddit.com/search.json", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if len(reply["data"]["children"]):
        answers = list()
        for entry in reply["data"]["children"]:
          if "data" in entry and entry["data"] and not entry["data"]["over_18"]:
            answers.append(utils.objdict({
              "title": entry["data"]["title"],
              "url": entry["data"]["url"],
              "author": entry["data"]["author"],
              "authorurl": "https://www.reddit.com/user/%s" % (entry["data"]["author"]),
              "score": entry["data"]["score"],
              "commentscount": entry["data"]["num_comments"],
              "redditurl": "https://www.reddit.com%s" % (entry["data"]["permalink"]),
            }))
        if len(answers):
          return utils.objdict({
            "success": True,
            "requesturl": res.url,
            "results": answers
          })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def reddit_subreddit_search(query=None, limit=5):
  # https://www.reddit.com/r/query/.json?limit=5
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "limit": limit
  }
  try:
    res = requests.get("https://www.reddit.com/r/%s/.json" % (query), headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if len(reply["data"]["children"]):
        answers = list()
        for entry in reply["data"]["children"]:
          if "data" in entry and entry["data"] and not entry["data"]["over_18"]:
            answers.append(utils.objdict({
              "title": entry["data"]["title"],
              "url": entry["data"]["url"],
              "author": entry["data"]["author"],
              "authorurl": "https://www.reddit.com/user/%s" % (entry["data"]["author"]),
              "score": entry["data"]["score"],
              "commentscount": entry["data"]["num_comments"],
              "redditurl": "https://www.reddit.com%s" % (entry["data"]["permalink"]),
            }))
        if len(answers):
          return utils.objdict({
            "success": True,
            "requesturl": res.url,
            "results": answers
          })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def robohash(data=None, imgtype="png", randomize=False):
  if not data or data == "":
    return utils.objdict({
      "success": False,
      "usage": "<data>"
    })
  if randomize:
    roboset = ["set1", "set2", "set3"]
    bgset = ["bg1", "bg2", "bg3"]
    if imgtype.lower() == "png":
      queryurl = "http://robohash.org/%s.png?set=%s&bgset=%s&size=300x300" % (data, random.choice(roboset), random.choice(bgset))
    elif imgtype.lower() == "jpeg" or imgtype.lower() == "jpg":
      queryurl = "http://robohash.org/%s.jpg?set=%s&bgset=%s&size=300x300" % (data, random.choice(roboset), random.choice(bgset))
    else:
      queryurl = "http://robohash.org/%s.bmp?set=%s&bgset=%s&size=300x300" % (data, random.choice(roboset), random.choice(bgset))
  else:
    queryurl = "http://robohash.org/%s.png?set=set2&bgset=bg2&size=300x300" % (data)
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get(queryurl, headers=customheaders, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "query": data,
        "robohash": res.content
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def screenshotmachine(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<domain|ip|url>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "key": keys.get("apikeys", "screenshotmachine"),
    "url": query,
    "format": "PNG",
    "size": "F",
    "timeout": "200",
  }
  try:
    res = requests.get("http://api.screenshotmachine.com/", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "query": query,
        "screenshot": res.content
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def simisimi(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.get("http://sandbox.api.simsimi.com/request.p?key=%s&lc=en&ft=1.0&text=%s" % (keys.get("apikeys", "simisimi"), query), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply["result"] != 401:
        return utils.objdict({
          "success": True,
          "query": query,
          "response": reply["response"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Expected HTTP status code 200 but got 401 instead: %s" % (reply["msg"])
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def shadowserver(lookuphash=None):
  # https://github.com/blacktop/shadow-server-api
  # lookuphash should be md5/sha1
  if not lookuphash or lookuphash == "":
    return utils.objdict({
      "success": False,
      "usage": "<lookuphash>"
    })
  try:
    res = shadow_server_api.ShadowServerApi().get_av(lookuphash)
    if "error" not in res:
      return utils.objdict({
          "success": True,
          "lookuphash": lookuphash,
          "response": res,
          "url": "http://bin-test.shadowserver.org/"
        })
    return utils.objdict({
      "success": False,
      "reason": res["error"],
      "url": "http://bin-test.shadowserver.org/"
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def shellstorm_list(scid=883):
  if not scid or scid == "":
    return utils.objdict({
      "success": False,
      "usage": "<scid>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    res = requests.post("http://shell-storm.org/shellcode/files/shellcode-%s.php" % (scid), headers=customheaders, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "scid": scid,
        "url": res.url,
        "content": utils.strip_tags(res.content),
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def shellstorm_search(query="Windows"):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "s": query.lower()
  }
  try:
    res = requests.post("http://shell-storm.org/api/", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "query": query.lower(),
        "url": res.url,
        "content": res.content,
        "shellcodecount": len(res.content.split("\n"))-1 # to account for a newline at the end of page
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def shodan_exploits(query, limit=5):
  # https://developer.shodan.io/api/exploits/rest
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  try:
    customheaders = {
      "User-Agent": "Some script trying to be nice :)"
    }
    facets = ",".join(["author:%d" % (limit), "platform:%d" % (limit), "port:%d" % (limit), "source:%d" % (limit), "type:%d" % (limit)])
    res = requests.get("https://exploits.shodan.io/api/search?query=%s&facets=%s&key=%s" % (query, facets, keys.get("apikeys", "shodan")), headers=customheaders, verify=False)
    print res.url
    if res.status_code == 200:
      results = res.json()
      count = results["total"]
      if count:
        stats = utils.objdict()
        if "facets" in results and results["facets"]:
          for facet in results["facets"]:
            if len(results["facets"][facet]):
              stats[facet] = list()
              for facetentry in results["facets"][facet]:
                stats[facet].append(utils.objdict({
                  "count": facetentry["count"],
                  "value": facetentry["value"]
                }))
            else:
              stats[facet] = None
        exploits = list()
        for exploit in results["matches"][:limit]:
          cve = None
          if "cve" in exploit and exploit["cve"] and len(exploit["cve"]):
            cve = list()
            for entry in exploit["cve"]:
              cve.append(("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s" % entry, entry))
          bid = None
          if "bid" in exploit and exploit["bid"] and len(exploit["bid"]):
            bid = list()
            for entry in exploit["bid"]:
              bid.append(("http://www.securityfocus.com/bid/%s" % entry, entry))
          msb = None
          if "msb" in exploit and exploit["msb"] and len(exploit["msb"]):
            msb = list()
            for entry in exploit["msb"]:
              msb.append(("https://technet.microsoft.com/en-us/library/security/%s" % entry, entry))
          osvdb = None
          if "osvdb" in exploit and exploit["osvdb"] and len(exploit["osvdb"]):
            osvdb = list()
            for entry in exploit["osvdb"]:
              osvdb.append(("http://osvdb.org/%s" % entry, entry))
          source = exploit["source"] if "source" in exploit and exploit["source"] and len(exploit["source"]) else None
          description = exploit["description"] if "description" in exploit and exploit["description"] and len(exploit["description"]) else None
          if bid or cve or msb or osvdb:
            exploits.append(utils.objdict({
              "bid": bid,
              "cve": cve,
              "msb": msb,
              "osvdb": osvdb,
              "source": source,
              "description": description
            }))
        return utils.objdict({
          "success": True,
          "query": query,
          "total": count,
          "stats": stats,
          "exploits": exploits if exploits and len(exploits) else None,
        })
      else:
        return utils.objdict({
          "success": False,
          "reason": "No results found for query: %s" % (query),
        })
    else:
      return utils.objdict({
        "success": False,
        "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def shodan_dns(query, limit=5):
  # https://shodan.readthedocs.io/en/latest/tutorial.html
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<domain|ip>"
    })
  lurl = longurl(query)
  if lurl.success:
    query = utils.url_to_domain(lurl.longurl)
  try:
    customheaders = {
      "User-Agent": "Some script trying to be nice :)"
    }
    if utils.is_domain(query):
      res = requests.get("https://api.shodan.io/dns/resolve?hostnames=%s&key=%s" % (query, keys.get("apikeys", "shodan")), headers=customheaders, verify=False)
      if res.status_code == 200:
        answer = res.json()[query.lower()]
        answer = answer if isinstance(answer, list) else [answer]
        if answer:
          return utils.objdict({
            "success": True,
            "requesturl": res.url,
            "query": query.lower(),
            "answer": answer
          })
        else:
          return utils.objdict({
            "success": False,
            "reason": "Failed to resolve: %s" % (query)
          })
      else:
        return utils.objdict({
          "success": False,
          "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
        })
    if utils.is_ipv4(query):
      res = requests.get("https://api.shodan.io/dns/reverse?ips=%s&key=%s" % (query, keys.get("apikeys", "shodan")), headers=customheaders, verify=False)
      if res.status_code == 200:
        answer = res.json()[query.lower()]
        if answer:
          answer = answer if isinstance(answer, list) else [answer]
          return utils.objdict({
            "success": True,
            "requesturl": res.url,
            "query": query.lower(),
            "answer": answer
          })
        else:
          return utils.objdict({
            "success": False,
            "reason": "No results found for query: %s" % (query)
          })
      else:
        return utils.objdict({
          "success": False,
          "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
        })
    else:
      return utils.objdict({
        "success": False,
        "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def shodan_honeyscore(ipaddr):
  if not ipaddr or ipaddr == "" or not utils.is_ipv4(ipaddr):
    return utils.objdict({
      "success": False,
      "usage": "<ipaddr>"
    })
  try:
    api = shodan.Shodan(keys.get("apikeys", "shodan"))
    score = api.labs.honeyscore(ipaddr)
    return utils.objdict({
      "success": True,
      "ip": ipaddr,
      "honeyscore": score,
      "ishoneypot": True if score == 1.0 else False,
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def shodan_host(ipaddr, limit=5):
  if not ipaddr or ipaddr == "" or not utils.is_ipv4(ipaddr):
    return utils.objdict({
      "success": False,
      "usage": "<ip>"
    })
  try:
    api = shodan.Shodan(keys.get("apikeys", "shodan"))
    host = api.host(ipaddr, history=True)
    banners = list()
    hostdata = list()
    for entry in sorted(host["data"])[:limit]:
      entrydata = utils.objdict({
        "asn": entry["asn"] if entry and "asn" in entry and entry["asn"] else None,
        "cpe": entry["cpe"] if entry and "cpe" in entry and entry["cpe"] else None,
        "data": entry["data"] if entry and "data" in entry and entry["data"] else None,
        "domains": entry["domains"] if entry and "domains" in entry and entry["domains"] else None,
        "hash": entry["hash"] if entry and "hash" in entry and entry["hash"] else None,
        "hostnames": entry["hostnames"] if entry and "hostnames" in entry and entry["hostnames"] else None,
        "html": entry["html"] if entry and "html" in entry and entry["html"] else None,
        "http": entry["http"] if entry and "http" in entry and entry["http"] else None,
        "info": entry["info"] if entry and "info" in entry and entry["info"] else None,
        "ip": entry["ip"] if entry and "ip" in entry and entry["ip"] else None,
        "ip_str": entry["ip_str"] if entry and "ip_str" in entry and entry["ip_str"] else None,
        "isp": entry["isp"] if entry and "isp" in entry and entry["isp"] else None,
        "org": entry["org"] if entry and "org" in entry and entry["org"] else None,
        "os": entry["os"] if entry and "os" in entry and entry["os"] else None,
        "port": entry["port"] if entry and "port" in entry and entry["port"] else None,
        "product": entry["product"] if entry and "product" in entry and entry["product"] else None,
        "timestamp": entry["timestamp"] if entry and "timestamp" in entry and entry["timestamp"] else None,
        "title": entry["title"] if entry and "title" in entry and entry["title"] else None,
        "transport": entry["transport"] if entry and "transport" in entry and entry["transport"] else None,
        "version": entry["version"] if entry and "version" in entry and entry["version"] else None,
        "timestampstr": None,
        "location": None,
        "screenshot": None,
        "ssl": None
      })
      if entry and "timestamp" in entry and entry["timestamp"]:
        entrydata["timestampstr"] = datetime.datetime.strptime(entry["timestamp"], "%Y-%m-%dT%H:%M:%S.%f").strftime("%d/%b/%Y %H:%M:%S")
      if "location" in entry and entry["location"]:
        entrydata["location"] = utils.objdict({
          "area_code": entry["location"]["area_code"],
          "city": entry["location"]["city"],
          "country_code": entry["location"]["country_code"],
          "country_code3": entry["location"]["country_code3"],
          "country_name": entry["location"]["country_name"],
          "dma_code": entry["location"]["dma_code"],
          "latitude": entry["location"]["latitude"],
          "longitude": entry["location"]["longitude"],
          "postal_code": entry["location"]["postal_code"],
          "region_code": entry["location"]["region_code"],
        })
      if "opts" in entry and entry["opts"] and "screenshot" in entry["opts"] and entry["opts"]["screenshot"]:
        entrydata["screenshot"] = utils.objdict({
          "data": entry["opts"]["screenshot"]["data"],
          "mimetype": entry["opts"]["screenshot"]["mime"],
        })
      if "ssl" in entry and entry["ssl"]:
        entrydata["ssl"] = entry["ssl"]
      hostdata.append(entrydata)
    hostinfo = utils.objdict({
      "area_code": host["area_code"] if host and "area_code" in host and host["area_code"] else None,
      "asn": host["asn"] if host and "asn" in host and host["asn"] else None,
      "city": host["city"] if host and "city" in host and host["city"] else None,
      "country_code": host["country_code"] if host and "country_code" in host and host["country_code"] else None,
      "country_code3": host["country_code3"] if host and "country_code3" in host and host["country_code3"] else None,
      "country_name": host["country_name"] if host and "country_name" in host and host["country_name"] else None,
      "dma_code": host["dma_code"] if host and "dma_code" in host and host["dma_code"] else None,
      "hostnames": host["hostnames"] if host and "hostnames" in host and host["hostnames"] else None,
      "ip": host["ip"] if host and "ip" in host and host["ip"] else None,
      "ip_str": host["ip_str"] if host and "ip_str" in host and host["ip_str"] else None,
      "isp": host["isp"] if host and "isp" in host and host["isp"] else None,
      "last_update": host["last_update"] if host and "last_update" in host and host["last_update"] else None,
      "latitude": host["latitude"] if host and "latitude" in host and host["latitude"] else None,
      "longitude": host["longitude"] if host and "longitude" in host and host["longitude"] else None,
      "org": host["org"] if host and "org" in host and host["org"] else None,
      "os": host["os"] if host and "os" in host and host["os"] else None,
      "ports": host["ports"] if host and "ports" in host and host["ports"] else None,
      "postal_code": host["postal_code"] if host and "postal_code" in host and host["postal_code"] else None,
      "region_code": host["region_code"] if host and "region_code" in host and host["region_code"] else None,
      "tags": host["tags"] if host and "tags" in host and host["tags"] else None,
      "vulns": host["vulns"] if host and "vulns" in host and host["vulns"] else None,
      "hostdata": hostdata,
      "lastupdatestr": None,
      "placelink": None,
    })
    if host and "last_update" in host and host["last_update"]:
      hostinfo["lastupdatestr"] = datetime.datetime.strptime(host["last_update"], "%Y-%m-%dT%H:%M:%S.%f").strftime("%d/%b/%Y %H:%M:%S")
    if host and "latitude" in host and host["latitude"] and "longitude" in host and host["longitude"]:
      placelink = google_placelink("%s,%s" % (hostinfo["latitude"], hostinfo["longitude"]))
      hostinfo["placelink"] = placelink.placelink if placelink.success else None
    if hostinfo:
      return utils.objdict({
        "success": True,
        "ip": ipaddr,
        "hostinfo": hostinfo
      })
    else:
      return utils.objdict({
        "success": False,
        "reason": "No results found for: %s" % (ipaddr)
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def shodan_myip():
  try:
    api = shodan.Shodan(keys.get("apikeys", "shodan"))
    ip = api.tools.myip()
    if ip:
      return utils.objdict({
        "success": True,
        "ip": ip,
      })
    else:
      return utils.objdict({
        "success": False,
        "reason": "No results found",
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def shodan_search(query, limit=5):
  # https://shodan.readthedocs.io/en/latest/tutorial.html
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  try:
    api = shodan.Shodan(keys.get("apikeys", "shodan"))
    results = api.count(query)
    count = results.get("total", 0)
    if count:
      results = api.search(query)
      queryres = list()
      for result in results["matches"][:limit]:
        placelink = google_placelink("%s,%s" % (result["location"]["latitude"], result["location"]["longitude"]))
        placelink = placelink.placelink if placelink.success else None
        queryres.append(utils.objdict({
          "product": result["product"] if "product" in result else None,
          "asn": result["asn"] if "asn" in result else None,
          "ip": result["ip_str"] if "ip_str" in result else None,
          "hostnames": result["hostnames"] if "hostnames" in result and len(result["hostnames"]) else None,
          "domains": result["domains"] if "domains" in result and len(result["domains"]) else None,
          "os": result["os"] if "os" in result else None,
          "isp": result["isp"] if "isp" in result else None,
          "title": result["title"] if "title" in result else None,
          "data": result["data"].strip() if "data" in result else None,
          "location": utils.objdict({
            "city": result["location"]["city"],
            "region_code": result["location"]["region_code"],
            "area_code": result["location"]["area_code"],
            "postal_code": result["location"]["postal_code"],
            "dma_code": result["location"]["dma_code"],
            "country_name": result["location"]["country_name"],
            "country_code": result["location"]["country_code"],
            "country_code3": result["location"]["country_code3"],
            "longitude": result["location"]["longitude"],
            "latitude": result["location"]["latitude"],
          }),
          "placelink": placelink
        }))
      facets = list([
        ("org", limit),
        ("domain", limit),
        ("port", limit),
        ("asn", limit),
        ("country", limit),
      ])
      api = shodan.Shodan(keys.get("apikeys", "shodan"))
      results = api.count(query, facets=facets)
      stats = utils.objdict()
      for facet in results["facets"]:
        if len(results["facets"][facet]):
          stats[facet] = list()
          for entry in results["facets"][facet]:
            stats[facet].append(utils.objdict({
              "count": entry["count"],
              "value": entry["value"]
            }))
      return utils.objdict({
        "success": True,
        "query": query,
        "total": count,
        "hosts": queryres,
        "stats": stats
      })
    else:
      return utils.objdict({
        "success": False,
        "reason": "No results found for query: %s" % (query)
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def ssllabs_scan(domain):
  if not domain or domain == "":
    return utils.objdict({
      "success": False,
      "usage": "<domain|ip>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "host": domain,
    "publish": "on",
    "startNew": "on",
    "all": "done",
    "ignoreMismatch": "on"
  }
  try:
    res = requests.get("https://api.ssllabs.com/api/v2/analyze", headers=customheaders, params=params, verify=False)
    reply = res.json()
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "analysis": reply
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def ssllabs_search(domain):
  if not domain or domain == "":
    return utils.objdict({
      "success": False,
      "usage": "<domain|ip>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  params = {
    "host": domain,
    "publish": "on",
    "startNew": "off",
    "fromCache": "on",
    "all": "done"
  }
  try:
    res = requests.get("https://api.ssllabs.com/api/v2/analyze", headers=customheaders, params=params, verify=False)
    reply = res.json()
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "reporturl": "https://www.ssllabs.com/ssltest/analyze.html?viaform=on&d=%s" % (domain),
        "analysis": reply
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def stackoverflow_search(query, sortcriteria="votes"):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  sortcriteria = sortcriteria.lower() if sortcriteria.lower() in ["activity", "votes", "creation", "hot", "week", "month"] else "votes"
  params = {
    "key": keys.get("apikeys", "stackoverflow"),
    "order": "desc",
    "migrated": False,
    "sort": sortcriteria,
    "accepted": True,
    "closed": False,
    "site": "stackoverflow",
    "body": query
  }
  try:
    res = requests.get("https://api.stackexchange.com/2.2/search/advanced", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = res.json()
      questions = list()
      for q in reply["items"]:
        if q["is_answered"] and q["answer_count"] > 0: questions.append(q)
      if questions and len(questions):
        return utils.objdict({
          "success": True,
          "query": query,
          "requesturl": res.url,
          "questions": questions
        })
      return utils.objdict({
        "success": False,
        "reason": "Could not find an answer for %s" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def teamcymru(lookuphash=None):
  # https://github.com/blacktop/team-cymru-api
  # lookuphash should be md5/sha1
  if not lookuphash or lookuphash == "":
    return utils.objdict({
      "success": False,
      "usage": "<lookuphash>"
    })
  try:
    res = team_cymru_api.TeamCymruApi().get_cymru(lookuphash)
    if "response_code" in res and res["response_code"] == 200:
      return utils.objdict({
          "success": True,
          "lookuphash": lookuphash,
          "lastseen": res["last_seen_utc"],
          "detected": res["detected"],
          "url": "https://hash.cymru.com/"
        })
    else:
      return utils.objdict({
          "success": False,
          "lookuphash": lookuphash,
          "reason": "No data found for %s" % (lookuphash),
          "url": "https://hash.cymru.com/"
      })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def theurbandictionary(query):
  # http://api.urbandictionary.com/v0/define?term=earth
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "term": query
  }
  try:
    res = requests.get("http://api.urbandictionary.com/v0/define", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      definitions = list()
      for defn in reply["list"]:
        definitions.append(utils.objdict({
          "author": defn["author"] if "author" in defn and defn["author"] and defn["author"] != "" else None,
          "definition": defn["definition"] if "definition" in defn and defn["definition"] and defn["definition"] != "" else None,
          "example": defn["example"] if "example" in defn and defn["example"] and defn["example"] != "" else None,
          "up": defn["thumbs_up"] if "thumbs_up" in defn and defn["thumbs_up"] and defn["thumbs_up"] != "" else None,
          "down": defn["thumbs_down"] if "thumbs_down" in defn and defn["thumbs_down"] and defn["thumbs_down"] != "" else None,
          "tudlink": defn["permalink"] if "permalink" in defn and defn["permalink"] and defn["permalink"] != "" else None,
        }))
      if len(definitions):
        return utils.objdict({
          "success": True,
          "query": query,
          "definitions": definitions
        })
      else:
        return utils.objdict({
          "success": False,
          "reason": "Could not find definitions for %s" % (query)
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def transfersh(filepath):
  # https://transfer.sh/
  if not filepath or filepath == "":
    return utils.objdict({
      "success": False,
      "usage": "<filepath>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Max-Days": "5"
  }
  try:
    res = utils.upload_file(queryurl="https://transfer.sh/", filepath=filepath, queryheaders=customheaders)
    if res:
      return utils.objdict({
        "success": True,
        "transfershurl": res
      })
    return utils.objdict({
      "success": False,
      "reason": "Failed to upload file to transfer.sh"
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def uber_rides(start=None, end=None, seats=2):
  if (not start and not end) or (start == "" or end == ""):
    return utils.objdict({
      "success": False,
      "usage": "start=<location> end=<location>"
    })
  else:
    geodata = google_geocode(start) ; start_latitude, start_longitude = (geodata.latitude, geodata.longitude) if geodata.success else (None, None)
    geodata = google_geocode(end) ; end_latitude, end_longitude = (geodata.latitude, geodata.longitude) if geodata.success else (None, None)
    if start_latitude and start_longitude and end_latitude and end_longitude:
      customheaders = {
        "User-Agent": "Some script trying to be nice :)",
        "Accept-Language": "en_US",
        "Content-Type": "application/json",
        "Authorization": "Token %s" % (keys.get("apikeys", "uber_servertoken"))
      }
      params = {
        "start_latitude": start_latitude,
        "start_longitude": start_longitude,
        "end_latitude": end_latitude,
        "end_longitude": end_longitude,
        "seat_count": seats
      }
      try:
        details = utils.objdict()
        if start_latitude and start_longitude:
          tres = requests.get("https://api.uber.com/v1.2/estimates/time", headers=customheaders, params=params, verify=False)
          if tres.status_code == 200:
            time = json.loads(tres.content)
            if time:
              for time in time["times"]:
                _, eta_hours, eta_minutes = utils.seconds_to_human(time["estimate"])
                details[time["display_name"]] = utils.objdict({
                  "eta_seconds": time["estimate"],
                  "eta_minutes": eta_minutes,
                  "eta_hours": eta_hours
                })
              pres = requests.get("https://api.uber.com/v1.2/estimates/price", headers=customheaders, params=params, verify=False)
              if pres.status_code == 200:
                rides = json.loads(pres.content)
                if rides:
                  for ride in rides["prices"]:
                    try: _ = details[ride["display_name"]]
                    except KeyError: details[ride["display_name"]] = utils.objdict({"eta_seconds": 0, "eta_minutes": 0, "eta_hours": 0})
                    details[ride["display_name"]]["price_string"] = ride["estimate"]
                    details[ride["display_name"]]["price_low"] = ride["low_estimate"]
                    details[ride["display_name"]]["price_high"] = ride["high_estimate"]
                  distance_miles = ride["distance"]
                  _, duration_hours, duration_minutes = utils.seconds_to_human(ride["duration"])
                  return utils.objdict({
                    "success": True,
                    "start": start,
                    "end": end,
                    "distance_miles": distance_miles,
                    "distance_kms": utils.mile_to_kilometer(distance_miles),
                    "duration_hours": duration_hours,
                    "duration_minutes": duration_minutes,
                    "rides": details,
                  })
                return utils.objdict({
                  "success": False,
                  "reason": "Could not find ride details for start=%s end=%s" % (start, end)
                })
            return utils.objdict({
              "success": False,
              "reason": "Could not find time details for start=%s" % (start)
            })
        return utils.objdict({
          "success": False,
          "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
        })
      except Exception as ex:
        return utils.objdict({
          "success": False,
          "exception": ex
        })
    return utils.objdict({
      "success": False,
      "reason": "Could not find details for start=%s end=%s" % (start, end)
    })


def virustotal_domain(domain=None):
  # https://github.com/blacktop/virustotal-api
  if not domain or domain == "":
    return utils.objdict({
      "success": False,
      "usage": "<domain>"
    })
  try:
    if utils.is_domain(domain):
      res = virus_total_apis.PublicApi(keys.get("apikeys", "virustotal")).get_domain_report(domain)
      if "results" in res and res["results"] and "response_code" in res and res["results"]["response_code"] == 1:
        return utils.objdict({
          "success": True,
          "query": domain,
          "response": res["results"],
          "url": "https://www.virustotal.com/"
        })
      return utils.objdict({
        "success": False,
        "reason": "Could not find report for %s on VirusTotal" % (domain)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expecting a domain for VirusTotal lookup but got %s instead" % (domain)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def virustotal_hash(lookuphash=None):
  # https://github.com/blacktop/virustotal-api
  if not lookuphash or lookuphash == "":
    return utils.objdict({
      "success": False,
      "usage": "<hash>"
    })
  try:
    res = virus_total_apis.PublicApi(keys.get("apikeys", "virustotal")).get_file_report(lookuphash)
    if "results" in res and res["results"] and "response_code" in res and res["results"]["response_code"] == 1:
      return utils.objdict({
        "success": True,
        "query": lookuphash,
        "response": res["results"],
        "url": "https://www.virustotal.com/"
      })
    return utils.objdict({
      "success": False,
      "reason": "Could not find report for %s on VirusTotal" % (lookuphash)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def virustotal_ip(ipaddr=None):
  # https://github.com/blacktop/virustotal-api
  if not ipaddr:
    localgeo = localgeoinfo()
    if localgeo.success:
      ipaddr = localgeo.geoinfo.query
  try:
    if utils.is_ipv4(ipaddr):
      res = virus_total_apis.PublicApi(keys.get("apikeys", "virustotal")).get_ip_report(ipaddr)
      if "results" in res and res["results"] and "response_code" in res and res["results"]["response_code"] == 1:
        return utils.objdict({
          "success": True,
          "query": ipaddr,
          "response": res["results"],
          "url": "https://www.virustotal.com/"
        })
      return utils.objdict({
        "success": False,
        "reason": "Could not find report for %s on VirusTotal" % (ipaddr)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expecting an IP address for VirusTotal lookup but got %s instead" % (ipaddr)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def virustotal_url(url=None):
  # https://github.com/blacktop/virustotal-api
  if not url or url == "":
    return utils.objdict({
      "success": False,
      "usage": "<url>"
    })
  try:
    res = virus_total_apis.PublicApi(keys.get("apikeys", "virustotal")).get_url_report(url)
    if "results" in res and res["results"] and "response_code" in res and res["results"]["response_code"] == 1:
      return utils.objdict({
        "success": True,
        "query": url,
        "response": res["results"],
        "url": "https://www.virustotal.com/"
      })
    return utils.objdict({
      "success": True,
      "reason": "Could not find report for %s on VirusTotal" % (url)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def voicerss_tts(text=None):
  # http://www.voicerss.org/api/documentation.aspx
  if not text or text == "":
    return utils.objdict({
      "success": False,
      "usage": "<text>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "audio/*",
  }
  params = {
    "src": text,
    "key": keys.get("apikeys", "voicerss"),
    "hl": "en-us",
    "c": "mp3",
    "rnd": "0.7763637386740221",
  }
  try:
    res = requests.get("https://api.voicerss.org/", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "text": text,
        "speech": res.content
      })
    return utils.objdict({
      "success": False,
      "reason": "Could not convert text \"%s\" to speech via VoiceRSS API" % (text)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def vulners_cveinfo(cve="cve-2015-1234"):
  if not cve or cve == "" or not utils.is_cve(cve):
    return utils.objdict({
      "success": False,
      "usage": "<cve-year-idid>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)"
  }
  try:
    if "cve-" not in cve.lower():
      cve = "cve-%s" % (cve)
    res = requests.get("https://vulners.com/api/v3/search/id/?id=%s&references=True" % (cve.upper()), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = res.json()
      if "result" in reply and reply["result"].upper() == "OK" and "data" in reply and reply["data"] and "documents" in reply["data"] and reply["data"]["documents"]:
        reply = reply["data"]["documents"][cve.upper()]
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "cve": cve.upper(),
          "cveurl": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s" % (cve.upper()),
          "cvss": reply["cvss"]["score"] if "cvss" in reply and reply["cvss"] and "score" in reply["cvss"] and reply["cvss"]["score"] else None,
          "cvss_verbose": reply["cvss"]["vector"],
          "description": reply["description"] if "description" in reply and reply["description"] else None,
          "references": reply["references"] if "references" in reply and reply["references"] else None,
        })
      else:
        return utils.objdict({
          "success": False,
          "reason": "Could not find information for %s." % (cve.upper())
        })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def whatthecommit():
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  try:
    res = requests.get("http://whatthecommit.com/index.txt", headers=customheaders, verify=False)
    if res.status_code == 200:
      return utils.objdict({
        "success": True,
        "commitmsg": res.content.strip()
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wikipedia(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "action": "query",
    "prop": "extracts",
    "format": "json",
    "exsectionformat": "plain",
    "exintro": "",
    "explaintext": "",
    "redirects": "",
    "titles": query
  }
  try:
    res = requests.get("https://en.wikipedia.org/w/api.php", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if "query" in reply.keys() and "pages" in reply["query"].keys():
        if "-1" in reply["query"]["pages"].keys() and "missing" in reply["query"]["pages"]["-1"].keys():
          return utils.objdict({
            "success": False,
            "reason": "Expected atleast one response page but got none for query: %s" % (query)
          })
        else:
          return utils.objdict({
            "success": True,
            "requesturl": res.url,
            "query": query,
            "url": "https://en.wikipedia.org/w/index.php?search=%s" % (query),
            "response": utils.unicode_to_string(reply["query"]["pages"][reply["query"]["pages"].keys()[0]]["extract"])
          })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wolframalpha(query):
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
  }
  params = {
    "appid": keys.get("apikeys", "wolfram"),
    "format": "plaintext",
    "output": "JSON",
    "input": query
  }
  try:
    res = requests.get("http://api.wolframalpha.com/v2/query", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = res.json()
      if reply["queryresult"]["success"]:
        output = utils.objdict()
        for pod in reply["queryresult"]["pods"]:
          for subpod in pod["subpods"]:
            if subpod["plaintext"] and subpod["plaintext"] != "":
              # do normalization as per: https://github.com/bscan/pokebot/blob/master/wolfram.py#L97
              if pod["title"] not in output:
                output[pod["title"].replace(u"\uf7d9", "=")] = list()
              output[pod["title"].replace(u"\uf7d9", "=")].append(subpod["plaintext"].replace(u"\uf7d9", "="))
      return utils.objdict({
        "success": True,
        "query": query,
        "requesturl": res.url,
        "resulturl": "http://www.wolframalpha.com/input/?i=%s" % (utils.url_encode(query)),
        "response": output,
      })
      return utils.objdict({
        "success": False,
        "reason": "Expected a response but got none for query: %s" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wordnik_audio(query):
  # http://developer.wordnik.com/docs.html#!/word
  # http://api.wordnik.com:80/v4/word.json/enigma/audio?useCanonical=false&limit=5&api_key=<key>
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "useCanonical": "false",
    "api_key": keys.get("apikeys", "wordnik")
  }
  try:
    res = requests.get("http://api.wordnik.com:80/v4/word.json/%s/audio" % (query), headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply and len(reply):
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply[0]["word"],
          "audiourl": reply[0]["fileUrl"] if reply[0]["fileUrl"] else None,
          "attribution": reply[0]["attributionText"] if reply[0]["attributionText"] else None,
          "duration": reply[0]["duration"] if reply[0]["duration"] else None
        })
      return utils.objdict({
        "success": False,
        "reason": "Expected a response but got none for query: %s" % (query)
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wordnik_definitions(query="enigma", maxdefinitions=1):
  # http://api.wordnik.com/v4/word.json/enigma/definitions?limit=5&includeRelated=true&useCanonical=false&includeTags=false&api_key=<key>
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "limit": maxdefinitions,
    "includeRelated": "true",
    "useCanonical": "false",
    "includeTags": "false",
    "api_key": keys.get("apikeys", "wordnik")
  }
  try:
    res = requests.get("http://api.wordnik.com/v4/word.json/%s/definitions" % (query.lower()), headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply and len(reply):
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply[0]["word"],
          "partofspeech": reply[0]["partOfSpeech"],
          "definition": reply[0]["text"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Expected a response for query %s but got none instead" % (query.lower())
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wordnik_example(query="enigma"):
  # http://api.wordnik.com:80/v4/word.json/enigma/topExample?useCanonical=false&api_key=<key>
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "useCanonical": "false",
    "api_key": keys.get("apikeys", "wordnik")
  }
  try:
    res = requests.get("http://api.wordnik.com/v4/word.json/%s/topExample" % (query.lower()), headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply and len(reply):
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "query": reply["word"],
          "example": reply["text"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Expected a response but got none for query: %s" % (query.lower())
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wordnik_hypernym(query="enigma"):
  # http://api.wordnik.com:80/v4/word.json/enigma/relatedWords?useCanonical=false&limitPerRelationshipType=5&api_key=<key>
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "useCanonical": "false",
    "limitPerRelationshipType": 5,
    "api_key": keys.get("apikeys", "wordnik")
  }
  try:
    res = requests.get("http://api.wordnik.com/v4/word.json/%s/relatedWords" % (query.lower()), headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply and len(reply):
        for node in reply:
          if node["relationshipType"] == "hypernym":
            return utils.objdict({
              "success": True,
              "requesturl": res.url,
              "query": query.lower(),
              "hypernyms": node["words"]
            })
      return utils.objdict({
        "success": False,
        "reason": "Expected a response but got none for query: %s" % (query.lower())
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wordnik_related(query="enigma"):
  # http://api.wordnik.com:80/v4/word.json/enigma/relatedWords?useCanonical=false&limitPerRelationshipType=5&api_key=<key>
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "useCanonical": "false",
    "limitPerRelationshipType": 5,
    "api_key": keys.get("apikeys", "wordnik")
  }
  try:
    res = requests.get("http://api.wordnik.com/v4/word.json/%s/relatedWords" % (query.lower()), headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply and len(reply):
        for node in reply:
          if node["relationshipType"] == "etymologically-related-term":
            return utils.objdict({
              "success": True,
              "requesturl": res.url,
              "query": query.lower(),
              "related": node["words"]
            })
      return utils.objdict({
        "success": False,
        "reason": "Expected a response but got none for query: %s" % (query.lower())
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wordnik_rhyme(query="enigma"):
  # http://api.wordnik.com:80/v4/word.json/enigma/relatedWords?useCanonical=false&limitPerRelationshipType=5&api_key=<key>
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "useCanonical": "false",
    "limitPerRelationshipType": 5,
    "api_key": keys.get("apikeys", "wordnik")
  }
  try:
    res = requests.get("http://api.wordnik.com/v4/word.json/%s/relatedWords" % (query.lower()), headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply and len(reply):
        for node in reply:
          if node["relationshipType"] == "rhyme":
            return utils.objdict({
              "success": True,
              "requesturl": res.url,
              "query": query.lower(),
              "rhymes": node["words"]
            })
      return utils.objdict({
        "success": False,
        "reason": "Expected a response but got none for query: %s" % (query.lower())
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wordnik_synonym(query="enigma"):
  # http://api.wordnik.com:80/v4/word.json/enigma/relatedWords?useCanonical=false&limitPerRelationshipType=5&api_key=<key>
  if not query or query == "":
    return utils.objdict({
      "success": False,
      "usage": "<query>"
    })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  params = {
    "useCanonical": "false",
    "limitPerRelationshipType": 5,
    "api_key": keys.get("apikeys", "wordnik")
  }
  try:
    res = requests.get("http://api.wordnik.com/v4/word.json/%s/relatedWords" % (query.lower()), headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply and len(reply):
        for node in reply:
          if node["relationshipType"] == "synonym":
            return utils.objdict({
              "success": True,
              "requesturl": res.url,
              "query": query.lower(),
              "synonyms": node["words"]
            })
      return utils.objdict({
        "success": False,
        "reason": "Expected a response but got none for query: %s" % (query.lower())
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wordnik_wod():
  # http://api.wordnik.com:80/v4/words.json/wordOfTheDay?useCanonical=false&limitPerRelationshipType=5&api_key=<key>&date=year-month-day
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  now = datetime.datetime.now()
  params = {
    "date": "%s-%s-%s" % (now.year, now.month, now.day),
    "useCanonical": "false",
    "limitPerRelationshipType": 5,
    "api_key": keys.get("apikeys", "wordnik")
  }
  try:
    res = requests.get("http://api.wordnik.com:80/v4/words.json/wordOfTheDay", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if reply and len(reply):
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "word": reply["word"],
          "note": reply["note"],
          "partofspeech": reply["definitions"][0]["partOfSpeech"],
          "definition": reply["definitions"][0]["text"],
          "example": reply["examples"][0]["text"],
          "examplesource": reply["examples"][0]["title"]
        })
      return utils.objdict({
        "success": False,
        "reason": "Expected a response but got none for query: %s" % (query.lower())
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def weboftrust(query=None):
  if not query or query == "":
    localgeo = localgeoinfo()
    if localgeo.success:
      query = localgeo.geoinfo.query
    else:
      return utils.objdict({
        "success": False,
        "usage": "[domain|ip]"
      })
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  params = {
    "hosts": "%s/" % (query),
    "key": keys.get("apikeys", "wot")
  }
  try:
    lurl = longurl(query)
    if lurl.success:
      query = utils.url_to_domain(lurl.longurl)
    if not utils.is_ipv4(query) and not utils.is_domain(query):
      return utils.objdict({
        "success": False,
        "reason": "Expected an ipv4 address or domain name but got %s instead" % (query)
      })
    res = requests.get("http://api.mywot.com/0.4/public_link_json2", headers=customheaders, params=params, verify=False)
    if res.status_code == 200:
      reply = json.loads(res.content)
      if not len(reply.keys()):
        return utils.objdict({
          "success": False,
          "reason": "Expected a response but got none for query: %s" % (query)
        })
      # https://www.mywot.com/wiki/API
      minconfidencethresold = 50
      reputation_components = utils.objdict({
        "0": utils.objdict({
          "description": "Trustworthiness",
          "example": "How much do you trust this site?"
        }),
        "4": utils.objdict({
          "description": "Child Safety",
          "example": "How suitable is this site for children?"
        })
      })
      reputation_confidence = utils.objdict({
        "Excellent": utils.objdict({
          "min": 80,
          "max": 100
        }),
        "Good": utils.objdict({
          "min": 60,
          "max": 79
        }),
        "Unsatisfactory": utils.objdict({
        "min": 40,
        "max": 59
        }),
        "Poor": utils.objdict({
          "min": 20,
          "max": 39
        }),
        "Very Poor": utils.objdict({
          "min": 0,
          "max": 19
        })
      })
      reputation_categories = utils.objdict({
        101: utils.objdict({
          "group": "Negative",
          "description": "Malware or viruses"
        }),
        102: utils.objdict({
          "group": "Negative",
          "description": "Poor customer experience"
        }),
        103: utils.objdict({
          "group": "Negative",
          "description": "Phishing"
        }),
        104: utils.objdict({
          "group": "Negative",
          "description": "Scam"
        }),
        105: utils.objdict({
          "group": "Negative",
          "description": "Potentially illegal"
        }),
        201: utils.objdict({
          "group": "Questionable",
          "description": "Misleading claims or unethical"
        }),
        202: utils.objdict({
          "group": "Questionable",
          "description": "Privacy risks"
        }),
        203: utils.objdict({
          "group": "Questionable",
          "description": "Suspicious"
        }),
        204: utils.objdict({
          "group": "Questionable",
          "description": "Hate, discrimination"
        }),
        205: utils.objdict({
          "group": "Questionable",
          "description": "Spam"
        }),
        206: utils.objdict({
          "group": "Questionable",
          "description": "Potentially unwanted programs"
        }),
        207: utils.objdict({
          "group": "Questionable",
          "description": "Ads/popups"
        }),
        301: utils.objdict({
          "group": "Neutral",
          "description": "Online tracking"
        }),
        302: utils.objdict({
          "group": "Neutral",
          "description": "Alternative/controversial medicine"
        }),
        303: utils.objdict({
          "group": "Neutral",
          "description": "Opinions, religion, politics"
        }),
        304: utils.objdict({
          "group": "Neutral",
          "description": "Other"
        }),
        401: utils.objdict({
          "group": "Negative",
          "description": "Adult content"
        }),
        402: utils.objdict({
          "group": "Questionable",
          "description": "Incidental nudity"
        }),
        403: utils.objdict({
          "group": "Questionable",
          "description": "Gruesome/shocking"
        }),
        404: utils.objdict({
          "group": "Positive",
          "description": "Site for kids"
        }),
        501: utils.objdict({
          "group": "Positive",
          "description": "Good site"
        }),
      })
      result = utils.objdict({
        "reputation": utils.objdict({
          "Trustworthiness": "NA",
          "Child Safety": "NA"
        }),
        "categories": utils.objdict({
          "group": "NA",
          "description": "NA"
        })
      })
      for k, v in reply[reply.keys()[0]].iteritems():
        if k == "0":
          if v[1] >= 50:
            for rck, rcv in reputation_confidence.iteritems():
              if v[0] >= rcv["min"] and v[0] <= rcv["max"]:
                result["reputation"]["Trustworthiness"] = rck
        elif k == "4":
          if v[1] >= 50:
            for rck, rcv in reputation_confidence.iteritems():
              if v[0] >= rcv["min"] and v[0] <= rcv["max"]:
                result["reputation"]["Child Safety"] = rck
        elif k == "categories":
          for ck, cv in v.iteritems():
            for catk, catv in reputation_categories.iteritems():
              if int(ck) == catk:
                result["categories"] = utils.objdict({
                  "group": catv["group"],
                  "description": catv["description"]
                })
      return utils.objdict({
        "success": True,
        "requesturl": res.url,
        "query": reply.keys()[0],
        "group": result["categories"]["group"],
        "description": result["categories"]["description"],
        "childsafety": result["reputation"]["Child Safety"],
        "trustworthiness": result["reputation"]["Trustworthiness"]
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def wunderground_update():
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Accept": "application/json"
  }
  res = requests.get("https://www.wunderground.com/about/faq/international_cities.asp", headers=customheaders, verify=False)
  if res.status_code == 200:
    html = bs4.BeautifulSoup(res.content)
    table = html.find(id="inner-content").find("pre").string
    s = struct.Struct("25s1s2s1s2s2s4s5s7s1s7s1s5s5s")
    cityname_replace = utils.objdict({
      "Poona": "pune",
      "Bombay": "mumbai",
      "Kolkata (Calcutta)": "kolkata",
      "Chennai (Madras)": "chennai"
    })
    wmocity = utils.objdict()
    for line in table.splitlines()[3:]:
      row = s.unpack_from(line)
      wmocity[row[13].strip()] = utils.objdict({
        "city": row[0].strip(),
        "region": row[2].strip(),
        "country": row[4].strip(),
        "id": row[6].strip(),
        "latitude": float(row[8].strip()),
        "longitude": float(row[10].strip()),
        "elevation": int(row[12].strip())
      })
    file_json_save("/home/shiv/toolbox/aayudh/aayudh/data/wmocity.json", wmocity)


def wunderground_report(location="Surat"):
  if not location or location == "":
    return utils.objdict({
      "success": False,
      "usage": "<location>"
    })
  try:
    wmocity = fileutils.file_json_open("%s/data/wmocity.json" % (os.path.dirname(__file__)))
    for entry in wmocity.keys():
      if location.lower() == wmocity[entry]["city"].lower():
        res = feedparser.parse("http://rss.wunderground.com/auto/rss_full/global/stations/%s.xml" % (entry))
        feed = list()
        if res.entries[0].title.split()[0].lower() == "current":
          temp, humi, pres, cond, wdir, wspe = None, None, None, None, None, None
          for data in res.entries[0].summary.split(" | "):
            key, value = data.split(":", 1)
            key = key.strip().lower().replace(" ", "")
            value = value.split(" / ")[0].strip()
            if key == "temperature":
              temp = float(value.split("&")[0])
            if key == "humidity":
              humi = float(value.split("%")[0])/100
            if key == "pressure":
              pres = float(value.split("in")[0])
            if key == "conditions":
              cond = value
            if key == "winddirection":
              wdir = value.replace("N", "North").replace("S", "South").replace("E", "East").replace("W", "West")
            if key == "windspeed":
              wspe = float(value.split("mph")[0])
          return utils.objdict({
            "success": True,
            "requesturl": "http://rss.wunderground.com/auto/rss_full/global/stations/%s.xml" % (entry),
            "currentweather": utils.objdict({
              "location": location,
              "temperaturecelcius": utils.fahrenheit_to_celcius(temp),
              "temperaturefahrenheit": temp,
              "conditions": cond,
              "humidity": humi,
              "windspeedkmph": utils.mile_to_kilometer(wspe),
              "windspeedmph": wspe,
              "pressuremillibars": utils.inch_to_millibar(pres),
              "pressureinches": pres
            })
          })
        else:
          return utils.objdict({
            "success": False,
            "reason": "could not get current weather report for location: %s" % (location)
          })
    return utils.objdict({
      "success": False,
      "reason": "wunderground database has no listing for location: %s" % (location)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })


def xkcd(query=None):
  customheaders = {
    "User-Agent": "Some script trying to be nice :)",
    "Content-Type": "application/json"
  }
  try:
    if query:
      if query.lower() == "current":
        res = requests.get("http://xkcd.com/info.0.json", headers=customheaders, verify=False)
      else:
        res = requests.get("http://xkcd.com/%s/info.0.json" % query, headers=customheaders, verify=False)
    else:
      minid, maxid = 1, 1600
      res = requests.get("http://xkcd.com/%s/info.0.json" % (random.randint(minid, maxid)), headers=customheaders, verify=False)
    if res.status_code == 200:
      reply = utils.objdict(json.loads(res.content))
      if reply and len(reply):
        return utils.objdict({
          "success": True,
          "requesturl": res.url,
          "comic": utils.objdict({
            "year": reply.year if reply.year else None,
            "month": reply.month if reply.month else None,
            "day": reply.day if reply.day else None,
            "stripid": reply.num if reply.num else None,
            "link": reply.link if reply.link else None,
            "news": reply.news if reply.news else None,
            "title": reply.safe_title if reply.safe_title else None,
            "transcript": reply.transcript if reply.transcript else None,
            "alt": reply.alt if reply.alt else None,
            "img": utils.download(reply.img) if reply.img else None,
            "imgurl": reply.img if reply.img else None,
            "stripurl": res.url
          })
        })
      return utils.objdict({
        "success": False,
        "reason": "Expected a response but got none for query: %s" % (query.lower())
      })
    return utils.objdict({
      "success": False,
      "reason": "Expected HTTP status code 200 but got %d instead" % (res.status_code)
    })
  except Exception as ex:
    return utils.objdict({
      "success": False,
      "exception": ex
    })

