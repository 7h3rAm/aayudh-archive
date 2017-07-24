# -*- coding: utf-8 -*-

import re
import logging.config

import utils


class ProtoID:
  def __init__(self):
    self.logger = logging.getLogger(__name__)

    self.config = {}
    self.config['protoregexes'] = {
      'HTTP': {
        'cts': re.compile(r'(GET|POST|HEAD|DELETE|PROPFIND)\s[^\s]+\sHTTP/\d\.\d', re.MULTILINE|re.DOTALL),
        'stc': re.compile(r'HTTP/\d\.\d', re.MULTILINE|re.DOTALL)
      },
      'IMAP': {
        'cts': None,
        'stc': re.compile(r'IMAP.*Subject:\s', re.MULTILINE|re.DOTALL)
      },
      'SMTP': {
        'cts': re.compile(r'(HELO|EHLO).*MAIL\sFROM.*RCPT\sTO', re.MULTILINE|re.DOTALL),
        'stc': re.compile(r'SMTP.*\sready\sat\s', re.MULTILINE|re.DOTALL)
      },
      'POP3': {
        'cts': None,
        'stc': re.compile(r'\+OK\s(Hello\sthere|Password\srequired)\.', re.MULTILINE|re.DOTALL)
      },
      'SIP': {
        'any': re.compile(r'^(SIP/\d\.\d |INVITE sip:)', re.MULTILINE|re.DOTALL)
      },
      'SSDP': { # inspired from https://ask.wireshark.org/questions/2387/ssdp-traffic
        'any': re.compile(r'HTTP/.*[SN]T:', re.MULTILINE|re.DOTALL)
      }
    }

    # https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
    self.config['protoports'] = {
      20: {
        'tcp': ['FTP - Data Channel'],
        'udp': None
      },
      21: {
        'tcp': ['FTP - Control Channel'],
        'udp': None
      },
      22: {
        'tcp': ['SSH'],
        'udp': None
      },
      25: {
        'tcp': ['SMTP'],
        'udp': None
      },
      53: {
        'tcp': ['DNS'],
        'udp': ['DNS']
      },
      43: {
        'tcp': ['WHOIS'],
        'udp': ['WHOIS']
      },
      67: {
        'tcp': None,
        'udp': ['DHCP']
      },
      68: {
        'tcp': None,
        'udp': ['DHCP']
      },
      69: {
        'tcp': ['TFTP'],
        'udp': ['TFTP']
      },
      80: {
        'tcp': ['HTTP'],
        'udp': None
      },
      88: {
        'tcp': ['KERBEROS'],
        'udp': ['KERBEROS']
      },
      123: {
        'tcp': ['Network Time Server'],
        'udp': ['Network Time Protocol']
      },
      137: {
        'tcp': ['NetBIOS Name Service'],
        'udp': ['NetBIOS Name Service']
      },
      138: {
        'tcp': ['NetBIOS Datagram Service'],
        'udp': ['NetBIOS Datagram Service']
      },
      139: {
        'tcp': ['NetBIOS Session Service'],
        'udp': ['NetBIOS Session Service']
      },
      143: {
        'tcp': ['IMAP'],
        'udp': None
      },
      156: {
        'tcp': ['SQL Services'],
        'udp': ['SQL Services']
      },
      161: {
        'tcp': None,
        'udp': ['SNMP']
      },
      162: {
        'tcp': ['SNMPTRAP'],
        'udp': ['SNMPTRAP']
      },
      194: {
        'tcp': ['IRC'],
        'udp': ['IRC']
      },
      443: {
        'tcp': ['HTTPS'],
        'udp': ['QUIC']
      },
      445: {
        'tcp': ['Microsoft-DS Active Directory', 'Microsoft-DS SMB File Sharing'],
        'udp': None
      },
      465: {
        'tcp': ['SMTPS'],
        'udp': None
      },
      500: {
        'tcp': ['ISAKMP'],
        'udp': ['ISAKMP']
      },
      502: {
        'tcp': ['MODBUS'],
        'udp': ['MODBUS']
      },
      548: {
        'tcp': ['Apple File Protocol over TCP'],
        'udp': None
      },
      944: {
        'tcp': None,
        'udp': ['NFS']
      },
      989: {
        'tcp': ['FTPS - Data Channel'],
        'udp': ['FTPS - Data Channel']
      },
      990: {
        'tcp': ['FTPS - Control Channel'],
        'udp': ['FTPS - Control Channel']
      },
      993: {
        'tcp': ['IMAPS'],
        'udp': None
      },
      994: {
        'tcp': ['IRCS'],
        'udp': ['IRCS']
      },
      995: {
        'tcp': ['POP3S'],
        'udp': None
      },
      3689: {
        'tcp': ['iTunes Library Sharing'],
        'udp': None
      },
      5353: {
        'tcp': None,
        'udp': ['mDNS', 'Bonjour']
      },
      9100: {
        'tcp': ['HP Jet Direct'],
        'udp': None
      },
      17500: {
        'tcp': None,
        'udp': ['Dropbox']
      },
    }


  def identify(self, ctsbuf=None, stcbuf=None, udpbuf=None, tcpport=None, udpport=None):
    # check if protocol is HTTP
    if ctsbuf and len(ctsbuf) > 0 and self.config['protoregexes']['HTTP']['cts']:
      self.logger.debug('Testing if %s of CTS data is HTTP' % (utils.size_string(len(ctsbuf))))
      if re.search(self.config['protoregexes']['HTTP']['cts'], ctsbuf):
        self.logger.debug('HTTP CTS regex: \'%s\' matches' % (self.config['protoregexes']['HTTP']['cts'].pattern))
        return 'HTTP'
    if stcbuf and len(stcbuf) > 0 and self.config['protoregexes']['HTTP']['stc']:
      self.logger.debug('Testing if %s of STC data is HTTP' % (utils.size_string(len(stcbuf))))
      if re.search(self.config['protoregexes']['HTTP']['stc'], stcbuf):
        self.logger.debug('HTTP STC regex: \'%s\' matches' % (self.config['protoregexes']['HTTP']['stc'].pattern))
        return 'HTTP'

    # check if protocol is IMAP
    if stcbuf and len(stcbuf) > 0 and self.config['protoregexes']['IMAP']['stc']:
      self.logger.debug('Testing if %s of STC data is IMAP' % (utils.size_string(len(stcbuf))))
      if re.search(self.config['protoregexes']['IMAP']['stc'], stcbuf):
        self.logger.debug('IMAP STC regex: \'%s\' matches' % (self.config['protoregexes']['IMAP']['stc'].pattern))
        return 'IMAP'

    # check if protocol is SMTP
    if ctsbuf and len(ctsbuf) > 0 and self.config['protoregexes']['SMTP']['cts']:
      self.logger.debug('Testing if %s of CTS data is SMTP' % (utils.size_string(len(ctsbuf))))
      if re.search(self.config['protoregexes']['SMTP']['cts'], ctsbuf):
        self.logger.debug('SMTP CTS regex: \'%s\' matches' % (self.config['protoregexes']['SMTP']['cts'].pattern))
        return 'SMTP'
    if stcbuf and len(stcbuf) > 0 and self.config['protoregexes']['SMTP']['stc']:
      self.logger.debug('Testing if %s of STC data is SMTP' % (utils.size_string(len(stcbuf))))
      if re.search(self.config['protoregexes']['SMTP']['stc'], stcbuf):
        self.logger.debug('SMTP STC regex: \'%s\' matches' % (self.config['protoregexes']['SMTP']['stc'].pattern))
        return 'SMTP'

    # check if protocol is POP3
    if stcbuf and len(stcbuf) > 0 and self.config['protoregexes']['POP3']['stc']:
      self.logger.debug('Testing if %s of STC data is POP3' % (utils.size_string(len(stcbuf))))
      if re.search(self.config['protoregexes']['POP3']['stc'], stcbuf):
        self.logger.debug('POP3 STC regex: \'%s\' matches' % (self.config['protoregexes']['POP3']['stc'].pattern))
        return 'POP3'

    # check if protocol is SIP
    if udpbuf and len(udpbuf) > 0 and self.config['protoregexes']['SIP']['any']:
      self.logger.debug('Testing if %s of UDP data is SIP' % (utils.size_string(len(udpbuf))))
      if re.search(self.config['protoregexes']['SIP']['any'], udpbuf):
        self.logger.debug('SIP regex: \'%s\' matches' % (self.config['protoregexes']['SIP']['any'].pattern))
        return 'SIP'

    # check if protocol is SSDP
    if udpbuf and len(udpbuf) > 0 and self.config['protoregexes']['SSDP']['any']:
      self.logger.debug('Testing if %s of UDP data is SSDP' % (utils.size_string(len(udpbuf))))
      if re.search(self.config['protoregexes']['SSDP']['any'], udpbuf):
        self.logger.debug('SSDP regex: \'%s\' matches' % (self.config['protoregexes']['SSDP']['any'].pattern))
        return 'SSDP'

    # if we're here it means that all of the above regexes checks was unsuccessful
    # we need to fallback on port based checks
    self.logger.debug('No regex matched for protoid. Using port mapping as a fallback for port %s' % (tcpport if tcpport else udpport))
    if tcpport and tcpport in self.config['protoports']:
      self.logger.debug('Identified port %d as %s' % (tcpport, ', '.join(self.config['protoports'][tcpport]['tcp'])))
      return ', '.join(self.config['protoports'][tcpport]['tcp'])
    elif udpport and udpport in self.config['protoports']:
      self.logger.debug('Identified port %d as %s' % (udpport, ', '.join(self.config['protoports'][udpport]['udp'])))
      return ', '.join(self.config['protoports'][udpport]['udp'])

    # if we're here it means even the port mapping based checks were unsuccessful
    # or we might have a FN
    # in any case we need to return empty-handed
    return None
