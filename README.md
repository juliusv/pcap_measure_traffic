# pcap Traffic Measurement Tool

# Overview

This is a very spartanic and simple tool for counting the number of bytes in
packets matching a provided `pcap-filter` expression (see `man pcap-filter`)
over a specified amount of time.

I decided to write this in C for minimal dependencies. Simply compile it and
copy the binary to any host - all it needs is libpcap, which is likely to be
installed on most systems.

The code is based on the pcap examples at http://www.tcpdump.org/pcap.html.

# Compiling

```bash
gcc pcap_measure_traffic.c -o pcap_measure_traffic -lpcap
```

# Usage

```bash
pcap_measure_traffic <device name> <capture duration> <filter expression>
```

The filter duration is specified in seconds.

The tool will output the total captured bytes in matching packets in MB.

# Examples

```bash
# Measure UDP packets from/to port 8125 on eth0 for 10 seconds:
pcap_measure_traffic eth0 10 "udp port 8125"

# Measure all traffic on loopback for 1 second:
pcap_measure_traffic lo 1 ""
```

# License
BSD (see LICENSE file).

# Contributing
Pull requests welcome!
