#!/usr/bin/python 
# -*- coding: utf-8 -*-

# AmplificationTester v0.2
# by Øyvind Ingvaldsen <oyvind.ingvaldsen@gmail.com>
# License: MIT

import errno
import socket
from socket import error as SocketError
import json
import csv
import time
from threading import Thread
from Queue import Queue
from select import select
from pprint import pprint
from binascii import hexlify

TERM_MOD = '\033['
TERM_END = TERM_MOD + '0m'
TERM_BOLD = TERM_MOD + '1m'
TERM_RED = TERM_MOD + '91m'
TERM_GREEN = TERM_MOD + '92m'


def whois_lookup(server, request):
  """
  Helper function to do whois request.
  """
  sock = socket.socket()
  sock.connect((server, 43))
  sock.send(request)
  data = ''
  while True:
    buff = sock.recv(4096)
    if len(buff) == 0:
      break
    data += buff
  return data

def send_and_receive_udp(target_ip, port, timeout=1.0, payload='0', buffer_size=4096):
  """
  Helper function to send and receive UDP packets (receives until timeout).
  """
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.connect((target_ip, port))
    bytes_sent = sock.send(payload)
    data = ''
    while True:
      buff = sock.recv(buffer_size) 
      if len(buff) == 0:
        break
      data += buff
    return (True, { 'bytes_sent': bytes_sent, 'bytes_received': len(data), 'data': data })
  except SocketError as e:
    if len(data):
      return (True, { 'bytes_sent': bytes_sent, 'bytes_received': len(data), 'data': data })
    return (False, { 'bytes_sent': bytes_sent })
  finally:
    sock.close()


def run_test(test_type, target_ip, port, payload, timeout, proto='UDP'):
  """
  Just an abstraction of common stuff done when running tests.
  """
  result = create_new_test_result(test_type, target_ip, port)
  (success, data) = send_and_receive_udp(target_ip, port, timeout, payload)   
  if success:
    result = dict(result.items() + data.items())
    result['amplification_factor'] = round(float(result['bytes_received']) / result['bytes_sent'], 2)
    result['exploitable'] = result['amplification_factor'] > 1.0
  return result

def create_new_test_result(test_type, target_ip, port):
  """
  Use a simple data structure to store all test results.
  """
  return {
      'type': test_type,
      'target_ip': target_ip,
      'port': port,
      'bytes_sent': 0,
      'bytes_received': 0,
      'amplification_factor': 0,
      'exploitable': False,
      'data': None
      }

def test_all(target_ip, timeout=2):
  """
  Run all tests against a target IP with the specified timeout.
  """
  return [ 
      test_dns(target_ip, timeout), 
      test_chargen(target_ip, timeout), 
      test_ntp(target_ip, timeout) 
      ]

def test_ntp(target_ip, timeout):
  """
  Test for NTP amplification by sending a monlist request to the target.   
  """
  port = 123 
  payload = b'\x17\x00\x03\x2a' + (b'\x00' * 4)

  result = run_test('NTP', target_ip, port, payload, timeout)
  result.pop('data', None)
  return result

def test_chargen(target_ip, timeout):
  """
  Test for CHARGEN amplification by, well, sending a CHARGEN request.
  """
  port = 19
  payload = '0'

  result = run_test('CHARGEN', target_ip, port, payload, timeout)
  result.pop('data', None)
  return result

def test_dns(target_ip, timeout):
  """
  Test for DNS amplification by sending a DNS Query for '*.google.com' with recursion desired.
  """
  port = 53
  # id=0x1337, rd = 1, numqueries = 1, query=google.com, type=255 (*.), class=1 (IN)
  payload = b'\x13\x37' + b'\x01\x00' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00' + b'\x00\xff' + b'\x00\x01'

  result = run_test('DNS', target_ip, port, payload, timeout)

  if result['data']:
    truncated = ord(result['data'][2]) & 0x2 == 2
    if truncated:
      pass

  result.pop('data', None)
  return result

def thread_task():
  """
  The 'worker' thread
  """
  while True:
    target = queue.get()
    if args.dns:
      results.append(test_dns(target, args.timeout))
    if args.chargen:
      results.append(test_chargen(target, args.timeout))
    if args.ntp:
      results.append(test_ntp(target, args.timeout))
    queue.task_done()

def print_test_result(result, verbose=False):
    """
    Helper-function for semi-pretty printing test results to terminal. 
    """
    if verbose:
      output = '      {}:\n'.format(result['type'])
      output += '        {} bytes sent\n'.format(result['bytes_sent'])
      output += '        {} bytes received\n'.format(result['bytes_received'])
      output += '        '
      if result['amplification_factor'] > 1:
        output += TERM_BOLD + TERM_GREEN
      else:
        output += TERM_RED
      output += '{:.2f}{} amplification factor'.format(result['amplification_factor'], TERM_END)
      print(output)
    else:
      output = '      {}: '.format(result['type'])
      if result['amplification_factor'] > 1:
        output += TERM_BOLD + TERM_GREEN
      else:
        output += TERM_RED
      output += '{:.2f}'.format(result['amplification_factor']) + TERM_END
      print(output)

if __name__ == '__main__':
  """
  For use as a command line tool.
  """

  import sys
  import argparse

  try:
    import netaddr
    has_netaddr = True
  except ImportError:
    has_netaddr = False

  parser = argparse.ArgumentParser()

  parser.add_argument('-v', '--verbose', help='increase output verbosity', action='store_true')
  parser.add_argument('--timeout', help='timeout in seconds', type=float, default=1.5)
  parser.add_argument('--threads', help='number of (python) threads to use', type=int, default=100)

  output_group = parser.add_mutually_exclusive_group()
  output_group.add_argument('--json', help='output all results as JSON', action='store_true')
  output_group.add_argument('--csv', help='output all results as CSV (with headers)', action='store_true')

  target_group = parser.add_argument_group('target (REQUIRED)')
  target_group.add_argument('--ip', type=str, action='append')
  target_group.add_argument('--cidr', type=str, action='append')
  target_group.add_argument('--asn', type=str, action='append')
  target_group.add_argument('--country-code', type=str, action='append')
  target_group.add_argument('--file', help='read IPs from a file', type=file, metavar='FILENAME')

  test_group = parser.add_argument_group('amplification tests')
  test_group.add_argument('--dns', help='test for DNS amplification', action='store_true')
  test_group.add_argument('--chargen', help='test for CHARGEN amplification', action='store_true')
  test_group.add_argument('--ntp', help='test for NTP amplification', action='store_true')
  test_group.add_argument('--all', help='run all tests', action='store_true')

  args = parser.parse_args()

  # fail if no test specified
  if not (args.all or args.dns or args.chargen or args.ntp):
    parser.print_help()
    exit(1)

  if args.all:
    args.dns = args.chargen = args.ntp = True
     
  # list of targets (IPs)
  targets = []
  
  # parse IP inputs
  if args.ip:
    for ip in args.ip:
      if ip not in targets:
        targets.append(ip)

  # parse CIDR inputs
  if args.cidr:
    if not has_netaddr:
      print("You need the 'netaddr' package to parse CIDR strings (pip install netaddr).") 
      exit(1)

    for cidr in args.cidr:
      net = netaddr.IPNetwork(cidr)
      for ip in net:
        ip = str(ip)
        if ip not in targets:
          targets.append(ip)

  # parse ASN inputs using ...
  if args.asn:
    if not has_netaddr:
      print("You need the 'netaddr' package to parse CIDR strings (pip install netaddr).") 
      exit(1)
    for asn in args.asn:
      asn = asn.strip()
      response = whois_lookup('asn.shadowserver.org', 'prefix {}\n'.format(asn))
      for cidr in response.split('\n'):
        if len(cidr) != 0:
          for ip in netaddr.IPNetwork(cidr):
            ip = str(ip)
            if ip not in targets:
              targets.append(ip)

  # parse country code inputs using ...
  if args.country_code:
    if not has_netaddr:
      print("You need the 'netaddr' package to parse CIDR strings (pip install netaddr).") 
      exit(1)
    raise NotImplementedError('WTB a CC to CIDR db')
    for cc in args.country_code:
      cc = cc.strip()
      response = whois_lookup('atari.honeynor.no', 'ipv4 {}\n'.format(cc))
      for cidr in response.split('\n'):
        cidr = cidr.strip()
        if len(net) != 0:
          for ip in netaddr.IPNetwork(cidr):
            ip = str(ip)
            if ip not in targets:
              targets.append(ip)


  # parse input from file
  if args.file:
    for ip in args.file.read().strip().split('\n'):
      ip = ip.strip()
      if not ip in targets:
        targets.append(ip)

  # parse input from stdin
  if select([sys.stdin], [], [], 0)[0]:
    for ip in sys.stdin.read().strip().split('\n'):
      ip = ip.strip()
      if not ip in targets:
        targets.append(ip)

  # exit if we have zero target IPs
  if len(targets) == 0:
    parser.print_help()
    exit(1)

  # non-terminal output is threaded
  if args.json or args.csv:

    queue = Queue()
    results = []

    for i in range(args.threads):
      t = Thread(target=thread_task)
      t.daemon = True
      t.start()

    for target in targets:
      queue.put(target)

    queue.join()

    if args.json:
      print(json.dumps(results, sort_keys=True, indent=2))
    elif args.csv:
      writer = csv.DictWriter(sys.stdout, ['type','target_ip','port','bytes_sent','bytes_received','amplification_factor','exploitable'], dialect='excel')
      writer.writeheader()
      writer.writerows(results)
  
  # output to terminal (not threaded)
  else:
    print('[*] Starting testing of {} targets'.format(len(targets)))
    print('[!] Warning: this is not threaded. Use --csv or --json for super fast processing!')
    start_time = time.time()
    for target in targets:
      print('[*] Testing IP: {}'.format(target))

      if args.dns:
        result = test_dns(target, args.timeout)
        print_test_result(result, args.verbose)

      if args.chargen:
        result = test_chargen(target, args.timeout)
        print_test_result(result, args.verbose)

      if args.ntp:
        result = test_ntp(target, args.timeout)
        print_test_result(result, args.verbose)
    print('[*] Testing done in {:.2f} seconds'.format(time.time() - start_time))
