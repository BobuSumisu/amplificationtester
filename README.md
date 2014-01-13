AmplificationTester
===================

A simple script to test if a machine is prone to being used in reflection/amplification DDoS attacks.

Currently it supports tests for DNS, NTP and CHARGEN attacks.

Usage
-----

Run `ALL` tests against `127.0.0.1`:

    ./amplificationtester.py -A -i 127.0.0.1

Run `NTP` test against every IP in `192.168.0.0/24`:

    ./amplificationtester.py -N -n 192.168.0.0/24

Run `CHARGEN` test against every IP in the file `list_of_ips.txt`:

    ./amplificationtester.py -C -f list_of_ips.txt

Can alse come from `stdin`:

    cat list_of_ips2.txt | ./amplificationtester.py -C

Check if `example.com` is an open resolver and output result as `CSV`:

    ./amplificationtester.py -D -i example.com -o csv

Or maybe `JSON`?

    ./amplificationtester.py -A -i example.com -o json

Get a (rought) time estimate of an operation:

    ./amplificationtester.py -A -f longlist.txt -e

Increase max number of threads to `1000` (default `100`):

    ./amplificationtester.py -A -f longlist.txt -m 1000 -e

Change the socket timeout to `10.0 sec` (default `1.5 sec`):

    ./amplificationtester.py -A -i example.com -t 10.0

The result from tests is a simple data structure:

    {
      "type": "<NTP|CHARGEN|DNS>",    // What type of test
      "target_ip": "127.0.0.1",       // The target
      "port": "<123|19|53>",          // Service port
      "bytes_sent": "1",              // Bytes sent (only counts payload, i.e. not IP/UDP headers)
      "bytes_received": "100",        // Bytes received (same as bytes sent)
      "amplification_factor": "100",  // The factor of amplification observed
      "exploitable": "True"           // Basically: amplification_factor > 1.0
    }

The `exploitable` field makes it a bit easier:

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
