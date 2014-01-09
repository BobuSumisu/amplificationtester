AmplificationTester
===================

A simple script to test if a machine is prone to being used in reflection/amplification DDoS attacks.

Currently it supports tests for DNS, NTP and CHARGEN attacks.

Todo
----
- Remove netaddr dependency (own CIDR parsing function)
- «Real» verification by using two machines (one spoofing packets to the other).
- Country-code to netblocks
- SNMP
- QotD
- Backend for saving larger searches etc. And a nice web-gui for it
- Suggestions?

Changelog
--------
- 2014-01-09: 
  - Output to CSV
  - Input from stdin
  - Added the 'exploitable' field (boolean) to results
  - Simple threading using queues.
  - Abstracted shit.
  - ASN to netblocks
- 2014-01-08:
  - first "working" version
  - Support for DNS, NTP and CHARGEN
  - Command line parsing using argparse
  - Pretty output to terminal, and output to JSON
