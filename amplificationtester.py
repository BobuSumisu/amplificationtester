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
from threading import Thread, Lock
from Queue import Queue
from select import select
from pprint import pprint
from binascii import hexlify

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
  data = ''
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.connect((target_ip, port))
    bytes_sent = sock.send(payload)
    while True:
      buff = sock.recv(buffer_size) 
      if len(buff) == 0:
        break
      data += buff
    return (True, { 'bytes_sent': bytes_sent, 'bytes_received': len(data), 'data': data })
  except SocketError as e:
    if len(data):
      return (True, { 'bytes_sent': bytes_sent, 'bytes_received': len(data), 'data': data })
    return (False, str(e))
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
  The peasant
  """
  while True:
    target = queue.get()
    if args.dns:
      res = test_dns(target, args.timeout)
      results.append(res)
      if args.output_format == 'text':
        color = '\033[92m' if res['amplification_factor'] > 1.0 else '\033[91m'
        with output_lock:
          print('{}[DNS] {}: {}\033[0m'.format(color, target, res['amplification_factor']))
    if args.chargen:
      res = test_chargen(target, args.timeout)
      results.append(res)
      if args.output_format == 'text':
        color = '\033[92m' if res['amplification_factor'] > 1.0 else '\033[91m'
        with output_lock:
          print('{}[CHARGEN] {}: {}\033[0m'.format(color, target, res['amplification_factor']))
    if args.ntp:
      res = test_ntp(target, args.timeout)
      results.append(res)
      if args.output_format == 'text':
        color = '\033[92m' if res['amplification_factor'] > 1.0 else '\033[91m'
        with output_lock:
          print('{}[NTP] {}: {}\033[0m'.format(color, target, res['amplification_factor']))

    queue.task_done()

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

  output_group = parser.add_argument_group('output options')
  output_group.add_argument('-e', '--time-estimate', action='store_true')
  output_group.add_argument('-o', '--output-format', type=str, choices=['text','csv','json'], default='text')

  options_group = parser.add_argument_group('execution options')
  options_group.add_argument('-t', '--timeout', type=float, default=1.5)
  options_group.add_argument('-m', '--max-threads', type=int, default=100)

  target_group = parser.add_argument_group('target options')
  target_group.add_argument('-i', '--ip', type=str, action='append')
  target_group.add_argument('-n', '--net', type=str, action='append')
  target_group.add_argument('-a', '--asn', type=str, action='append')
  target_group.add_argument('-c', '--country-code', type=str, action='append')
  target_group.add_argument('-f', '--file', type=file, metavar='FILENAME')

  test_group = parser.add_argument_group('tests options')
  test_group.add_argument('-D', '--dns', action='store_true')
  test_group.add_argument('-C', '--chargen', action='store_true')
  test_group.add_argument('-N', '--ntp', action='store_true')
  test_group.add_argument('-A', '--all', action='store_true')

  args = parser.parse_args()

  if not (args.all or args.dns or args.chargen or args.ntp):
    parser.print_help()
    exit(1)
  elif args.all:
    num_tests = 3
  else:
    num_tests = 1

  if args.all:
    args.dns = args.chargen = args.ntp = True
     
  # list of target as IP strings
  targets = []
  
  # parse IPs
  if args.ip:
    for ip in args.ip:
      targets.append(ip)

  # parse nets in CIDR notation
  if args.net:
    if not has_netaddr:
      print("You need the 'netaddr' package to parse CIDR strings (pip install netaddr).") 
      exit(1)

    for cidr in args.net:
      net = netaddr.IPNetwork(cidr)
      for ip in net:
        targets.append(str(ip))

  # parse ASNs using shadowserver :)
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
            targets.append(str(ip))

  # parse country codes using .. something soon
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
            targets.append(str(ip))

  # parse input from file (expects a list of IPs)
  if args.file:
    for ip in args.file.read().strip().split('\n'):
      targets.append(ip.strip())

  # parse input from stdin (expects a list of IPs)
  if select([sys.stdin], [], [], 0)[0]:
    for ip in sys.stdin.read().strip().split('\n'):
      targets.append(ip.strip())

  # exit if we haven't got any targets
  if len(targets) == 0:
    parser.print_help()
    exit(1)

 
  # a simple time estimate, based on max threads, timeout and number of tests to run per target
  time_estimate = (int(len(targets) / args.max_threads) + 1) * (args.timeout * 1.1) * num_tests

  if args.time_estimate:
    print('Time estimate: {} seconds'.format(time_estimate))
    exit(0)

  if args.output_format == 'text':
    print('[*] Starting testing of {} IPs'.format(len(targets)))
    print('[*] Time estimate: {:.2f} seconds'.format(time_estimate))

  queue = Queue()
  output_lock = Lock()
  results = []
  start_time = time.time()

  for i in range(args.max_threads):
    t = Thread(target=thread_task)
    t.daemon = True
    t.start()

  for target in targets:
    queue.put(target)

  queue.join()
  
  if args.output_format == 'text':
    print('[*] Finished in {:.2f} seconds'.format(time.time() - start_time))

  if args.output_format == 'json':
    print(json.dumps(results, sort_keys=True, indent=2))
  elif args.output_format == 'csv':
    writer = csv.DictWriter(sys.stdout, ['type','target_ip','port','bytes_sent','bytes_received','amplification_factor','exploitable'], dialect='excel')
    writer.writeheader()
    writer.writerows(results)
