# cisGO-hash

This is a tool written in golang that analyzes some Cisco protocols and prints some important data fields of the packets, like protocol version, source and destination IP and MAC addresses, authentication type and in case of available authentication, authentication data (like plain-text string or md5/sha hashes).

## Usage
you can write `./cisGO-hash -h` command to print help menu:
```
A tool for analyzing some Cisco protocol packets

Usage:
  cisGO-hash [flags]

Flags:
      --capture string   Path to the capture file (pcap/pcapng/cap)
      --eigrp            Analyze EIGRP packets
  -h, --help             help for cisGO-hash
      --hsrp             Analyze HSRP packets
      --ospf             Analyze OSPF packets
      --vrrp             Analyze VRRP packets
```
