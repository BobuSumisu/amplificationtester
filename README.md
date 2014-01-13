AmplificationTester
===================

A simple script to test if a machine is prone to being used in reflection/amplification DDoS attacks.

Currently it supports tests for DNS, NTP and CHARGEN attacks.

Usage
-----

    ./amplificationtester.py -A -i 127.0.0.1                  # run ALL tests against IP 127.0.0.1
    ./amplificationtester.py -N -n 192.168.0.0/24             # run NTP-test against every IP in subnet
    ./amplificationtester.py -C -f list_of_ips.txt            # read IPs from a file and run CHARGEN-test against them
    cat list_of_ips2.txt | ./amplificationtester.py -C        # same as above, just cooler
    ./amplificationtester.py -D -i example.com -o csv         # check if example.com is an open resolver and output result as CSV
    ./amplificationtester.py -A -i example.com -o json        # or maybe JSON?
    ./amplificationtester.py -A -f longlist.txt -e            # get a time estimate 
    ./amplificationtester.py -A -f longlist.txt -m 1000 -e    # get a time estimate using 1000 threads (default: 100)
    ./amplificationtester.py -A -i example.com -t 10.0        # change timeout (default: 1.5)

    # the CSV and JSON format has a field called 'exploitable' which is 'True' or 'False':

    ./amplificationtester.py -A -f ips.txt -m 1000 -t 2.5 -o csv | grep True > confirmed.txt

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
