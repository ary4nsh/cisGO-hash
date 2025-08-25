package protocols

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// VRRPPacket represents a VRRP packet with extracted information
type VRRPPacket struct {
	SrcIP            string
	DstIP            string
	SrcMAC           string
	DstMAC           string
	Version          uint8
	VirtualRouterID  uint8
	Priority         uint8
	AuthType         string
	AuthString       string
	MD5AuthData      string
	VirtualAddresses []string
}

// VRRP authentication type constants
var vrrpAuthTypes = map[uint8]string{
	0: "No authentication",
	1: "Plain-text",
	254: "MD5",
}

// ExtractVRRPFromPcap analyzes VRRP packets from capture files
func ExtractVRRPFromPcap(filename string) {
	var handle *pcap.Handle
	var err error
	
	// Determine file type and open accordingly
	if strings.HasSuffix(strings.ToLower(filename), ".pcapng") {
		file, err := os.Open(filename)
		if err != nil {
			log.Fatal("Error opening file:", err)
		}
		defer file.Close()
		
		reader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			log.Fatal("Error creating pcapng reader:", err)
		}
		
		processVRRPFromNgReader(reader)
		return
	} else {
		// Handle pcap and cap files
		handle, err = pcap.OpenOffline(filename)
		if err != nil {
			log.Fatal("Error opening pcap file:", err)
		}
		defer handle.Close()
	}
	
	processVRRPFromHandle(handle)
}

func processVRRPFromNgReader(reader *pcapgo.NgReader) {
	var vrrpPackets []VRRPPacket
	totalPackets := 0
	packetNum := 1
	
	for {
		data, _, err := reader.ReadPacketData()
		if err != nil {
			break // End of file
		}
		
		totalPackets++
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		
		if vrrpPacket := extractVRRPInfo(packet); vrrpPacket != nil {
			fmt.Printf("=== VRRP Packet #%d ===\n", packetNum)
			printVRRPPacket(*vrrpPacket)
			vrrpPackets = append(vrrpPackets, *vrrpPacket)
			packetNum++
		}
	}
	
	printVRRPSummary(totalPackets, len(vrrpPackets))
}

func processVRRPFromHandle(handle *pcap.Handle) {
	var vrrpPackets []VRRPPacket
	totalPackets := 0
	packetNum := 1
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		totalPackets++
		
		if vrrpPacket := extractVRRPInfo(packet); vrrpPacket != nil {
			fmt.Printf("=== VRRP Packet #%d ===\n", packetNum)
			printVRRPPacket(*vrrpPacket)
			vrrpPackets = append(vrrpPackets, *vrrpPacket)
			packetNum++
		}
	}
	
	printVRRPSummary(totalPackets, len(vrrpPackets))
}

func extractVRRPInfo(packet gopacket.Packet) *VRRPPacket {
	// Check if this is a VRRP packet (IP protocol 112)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if ip.Protocol != 112 { // VRRP protocol number
			return nil
		}
		
		vrrpPacket := &VRRPPacket{
			SrcIP: ip.SrcIP.String(),
			DstIP: ip.DstIP.String(),
		}
		
		// Extract MAC addresses
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			vrrpPacket.SrcMAC = eth.SrcMAC.String()
			vrrpPacket.DstMAC = eth.DstMAC.String()
		}
		
		// Extract VRRP-specific information from payload
		if len(ip.Payload) >= 8 { // Minimum VRRP header size
			parseVRRPPayload(ip.Payload, vrrpPacket)
		}
		
		return vrrpPacket
	}
	
	return nil
}

func parseVRRPPayload(payload []byte, vrrpPacket *VRRPPacket) {
	if len(payload) < 8 {
		return
	}
	
	// VRRP Header Structure:
	// Version (4 bits) + Type (4 bits) - offset 0
	// Virtual Router ID (1 byte) - offset 1
	// Priority (1 byte) - offset 2
	// Count IP Addrs (1 byte) - offset 3
	// Authentication Type (1 byte) - offset 4
	// Advertisement Interval (1 byte) - offset 5
	// Checksum (2 bytes) - offset 6-7
	// IP Address(es) (4 bytes each) - offset 8+
	// Authentication Data (8 bytes) - at the end
	
	// VRRP fixed header
	vrrpPacket.Version = (payload[0] >> 4) & 0x0F
	vrrpPacket.VirtualRouterID = payload[1]
	vrrpPacket.Priority = payload[2]
	authTypeValue := payload[4]

	if name, ok := vrrpAuthTypes[authTypeValue]; ok {
		vrrpPacket.AuthType = name
	} else {
		vrrpPacket.AuthType = fmt.Sprintf("Unknown (%d)", authTypeValue)
	}

	// Virtual IPv4 addresses
	countIPAddrs := payload[3]
	ipOffset := 8
	for i := uint8(0); i < countIPAddrs && ipOffset+4 <= len(payload); i++ {
		vip := net.IPv4(payload[ipOffset], payload[ipOffset+1], payload[ipOffset+2], payload[ipOffset+3])
		vrrpPacket.VirtualAddresses = append(vrrpPacket.VirtualAddresses, vip.String())
		ipOffset += 4
	}

	// Authentication data
	const md5Len = 16
	if authTypeValue == 254 && len(payload) >= md5Len {
		// MD5 digest is the last 16 bytes
		digest := payload[len(payload)-md5Len:]
		vrrpPacket.MD5AuthData = fmt.Sprintf("%x", digest)
	} else if authTypeValue == 1 && len(payload) >= 8 {
		// Plain-text password in last 8 bytes (null-terminated or printable only)
		auth := payload[len(payload)-8:]
		var pass []byte
		for _, b := range auth {
			if b == 0 {
				break
			}
			if b >= 32 && b <= 126 {
				pass = append(pass, b)
			}
		}
		if len(pass) > 0 {
			vrrpPacket.AuthString = string(pass)
		}
	}

	// VRRPv3 note
	if vrrpPacket.Version == 3 && authTypeValue != 0 {
		vrrpPacket.AuthType = "VRRPv3 uses IPsec for authentication"
	}
}

func printVRRPPacket(packet VRRPPacket) {
	fmt.Printf("- Source address: %s\n", packet.SrcIP)
	fmt.Printf("- Destination address: %s\n", packet.DstIP)
	fmt.Printf("- Source MAC address: %s\n", packet.SrcMAC)
	fmt.Printf("- Destination MAC address: %s\n", packet.DstMAC)
	fmt.Printf("- Protocol version: %d\n", packet.Version)
	fmt.Printf("- Virtual router ID: %d\n", packet.VirtualRouterID)
	fmt.Printf("- Router priority: %d\n", packet.Priority)
	fmt.Printf("- Authentication type: %s\n", packet.AuthType)
	
	// Print authentication data based on type
	if packet.AuthString != "" {
		fmt.Printf("- Authentication string: %s\n", packet.AuthString)
	} else if packet.MD5AuthData != "" {
		fmt.Printf("- MD5 authentication data: %s\n", packet.MD5AuthData)
	} else if packet.AuthType != "No authentication" && packet.AuthType != "VRRPv3 uses IPsec for authentication" {
		fmt.Printf("- Authentication data: Not readable\n")
	}
	
	// Print virtual addresses
	if len(packet.VirtualAddresses) > 0 {
		if len(packet.VirtualAddresses) == 1 {
			fmt.Printf("- Virtual address: %s\n", packet.VirtualAddresses[0])
		} else {
			fmt.Printf("- Virtual addresses: %s\n", strings.Join(packet.VirtualAddresses, ", "))
		}
	} else {
		fmt.Printf("- Virtual address: Not found\n")
	}
	
	fmt.Println()
}

func printVRRPSummary(totalPackets, vrrpPackets int) {
	fmt.Println("=== SUMMARY ===")
	fmt.Printf("Total packets processed: %d\n", totalPackets)
	fmt.Printf("VRRP packets found: %d\n", vrrpPackets)
}
