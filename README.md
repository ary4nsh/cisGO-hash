# cisGO-hash

This is a tool written in golang that analyzes Hello packets in some Cisco protocols and prints some important data fields of the packets, like protocol version, source and destination IP and MAC addresses, authentication type and in case of available authentication, authentication data (like plain-text string or md5/sha hashes).

## Usage
you can write `./cisGO-hash -h` command to print help menu:
```
A tool for analyzing some Cisco protocol packets

Usage:
  cisGO-hash [flags]

Flags:
      --capture string   Path to the capture file (pcap/pcapng/cap)
      --eigrp            Analyze EIGRP packets
      --glbp             Analyze GLBP packets
  -h, --help             help for cisGO-hash
      --hsrp             Analyze HSRP packets
      --ospf             Analyze OSPF packets
      --vrrp             Analyze VRRP packets
```
## Example
```
./cisGO-hash --eigrp --capture ./EIGRP\ auth/EIGRP\ Capture\ FINAL.pcapng 

...
=== EIGRP Packet #29 ===
EIGRP (IPv4):
- Source address: 192.168.127.1
- Destination address: 224.0.0.10
- Source MAC address: 00:1a:6c:a1:2b:99
- Destination MAC address: 01:00:5e:00:00:0a
- Protocol version: 2
- Virtual router ID: 0
- Autonomous system: 4711
- Authentication type: MD5
- Authentication length: 16
- Digest: e6542394897469acd97b68d52e34b208

=== EIGRP Packet #30 ===
EIGRP (IPv4):
- Source address: 192.168.127.2
- Destination address: 192.168.127.1
- Source MAC address: 00:14:69:9e:11:40
- Destination MAC address: 00:1a:6c:a1:2b:99
- Protocol version: 2
- Virtual router ID: 0
- Autonomous system: 4711
- Authentication type: Not present

=== EIGRP Packet #31 ===
EIGRP (IPv6):
- Source address: fe80::214:69ff:fe9e:1140
- Destination address: ff02::a
- Source MAC address: 00:14:69:9e:11:40
- Destination MAC address: 33:33:00:00:00:0a
- Protocol version: 2
- Virtual router ID: 0
- Autonomous system: 4711
- Authentication type: MD5
- Authentication length: 16
- Digest: 0cae9735ef75c5ab087c02fbf586a955
- K values: K1=1, K2=0, K3=1, K4=0, K5=0, K6=0
...
```
