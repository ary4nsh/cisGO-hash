package protocols

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// EIGRPPacket represents an EIGRP packet with extracted information
type EIGRPPacket struct {
	SrcIP            string
	DstIP            string
	SrcMAC           string
	DstMAC           string
	Version          uint8
	VirtualRouterID  uint16
	AutonomousSystem uint16
	AuthType         string
	AuthLength       uint16
	Digest           string
	KValues          []uint8
	HasKValues       bool
	IsIPv6           bool
}

// ExtractEIGRPFromPcap analyzes EIGRP packets from capture files
func ExtractEIGRPFromPcap(filename string) {
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
		
		processEIGRPFromNgReader(reader)
		return
	} else {
		// Handle pcap and cap files
		handle, err = pcap.OpenOffline(filename)
		if err != nil {
			log.Fatal("Error opening pcap file:", err)
		}
		defer handle.Close()
	}
	
	processEIGRPFromHandle(handle)
}

func processEIGRPFromNgReader(reader *pcapgo.NgReader) {
	var eigrpPackets []EIGRPPacket
	totalPackets := 0
	packetNum := 1
	
	for {
		data, _, err := reader.ReadPacketData()
		if err != nil {
			break // End of file
		}
		
		totalPackets++
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		
		if eigrpPacket := extractEIGRPInfo(packet); eigrpPacket != nil {
			fmt.Printf("=== EIGRP Packet #%d ===\n", packetNum)
			printEIGRPPacket(*eigrpPacket)
			eigrpPackets = append(eigrpPackets, *eigrpPacket)
			packetNum++
		}
	}
	
	printEIGRPSummary(totalPackets, len(eigrpPackets))
}

func processEIGRPFromHandle(handle *pcap.Handle) {
	var eigrpPackets []EIGRPPacket
	totalPackets := 0
	packetNum := 1
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		totalPackets++
		
		if eigrpPacket := extractEIGRPInfo(packet); eigrpPacket != nil {
			fmt.Printf("=== EIGRP Packet #%d ===\n", packetNum)
			printEIGRPPacket(*eigrpPacket)
			eigrpPackets = append(eigrpPackets, *eigrpPacket)
			packetNum++
		}
	}
	
	printEIGRPSummary(totalPackets, len(eigrpPackets))
}

func extractEIGRPInfo(packet gopacket.Packet) *EIGRPPacket {
	var eigrpPacket *EIGRPPacket
	var payload []byte
	
	// Check for IPv4 EIGRP packet (IP protocol 88)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if ip.Protocol != 88 { // EIGRP protocol number
			return nil
		}
		
		eigrpPacket = &EIGRPPacket{
			SrcIP:      ip.SrcIP.String(),
			DstIP:      ip.DstIP.String(),
			AuthType:   "Not present",
			IsIPv6:     false,
			HasKValues: false,
		}
		payload = ip.Payload
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		// Check for IPv6 EIGRP packet (Next Header 88)
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		if ipv6.NextHeader != 88 { // EIGRP protocol number
			return nil
		}
		
		eigrpPacket = &EIGRPPacket{
			SrcIP:      ipv6.SrcIP.String(),
			DstIP:      ipv6.DstIP.String(),
			AuthType:   "Not present",
			IsIPv6:     true,
			HasKValues: false,
		}
		payload = ipv6.Payload
	} else {
		return nil
	}
	
	// Extract MAC addresses
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		eigrpPacket.SrcMAC = eth.SrcMAC.String()
		eigrpPacket.DstMAC = eth.DstMAC.String()
	}
	
	// Extract EIGRP-specific information from payload
	if len(payload) >= 20 { // Minimum EIGRP header size
		// EIGRP Header structure:
		// Version (1 byte)
		// Opcode (1 byte) 
		// Checksum (2 bytes)
		// Flags (4 bytes)
		// Sequence (4 bytes)
		// Acknowledgment (4 bytes)
		// Virtual Router ID (2 bytes) - often called Process ID
		// Autonomous System (2 bytes)
		
		eigrpPacket.Version = payload[0]
		
		if len(payload) >= 20 {
			// Extract Virtual Router ID (Process ID) at offset 16
			eigrpPacket.VirtualRouterID = binary.BigEndian.Uint16(payload[16:18])
			// Extract Autonomous System at offset 18
			eigrpPacket.AutonomousSystem = binary.BigEndian.Uint16(payload[18:20])
		}
		
		// Extract K values and authentication info from TLVs
		parseEIGRPTLVs(payload[20:], eigrpPacket)
	}
	
	return eigrpPacket
}

func parseEIGRPTLVs(tlvData []byte, eigrpPacket *EIGRPPacket) {
	offset := 0
	
	for offset+4 <= len(tlvData) {
		tlvType := binary.BigEndian.Uint16(tlvData[offset:offset+2])
		tlvLength := binary.BigEndian.Uint16(tlvData[offset+2:offset+4])
		
		if tlvLength < 4 || offset+int(tlvLength) > len(tlvData) {
			break
		}
		
		tlvValue := tlvData[offset+4:offset+int(tlvLength)]
		
		switch tlvType {
		case 0x0001: // Parameters TLV - contains K values
			if len(tlvValue) >= 6 {
				// Parameters TLV structure:
				// K1 (1 byte)
				// K2 (1 byte) 
				// K3 (1 byte)
				// K4 (1 byte)
				// K5 (1 byte)
				// K6 (1 byte)
				// Hold Time (2 bytes)
				eigrpPacket.KValues = []uint8{
					tlvValue[0], // K1
					tlvValue[1], // K2
					tlvValue[2], // K3
					tlvValue[3], // K4
					tlvValue[4], // K5
					tlvValue[5], // K6
				}
				eigrpPacket.HasKValues = true
			}
		case 0x0002: // Authentication TLV
			parseAuthenticationTLV(tlvValue, eigrpPacket)
		}
		
		offset += int(tlvLength)
	}
}

func parseAuthenticationTLV(authData []byte, eigrpPacket *EIGRPPacket) {
	if len(authData) < 4 {
		return
	}
	
	// Authentication TLV structure:
	// Auth Type (2 bytes) - 2=MD5, 3=SHA256
	// Auth Length (2 bytes) - length of digest
	// Key ID (2 bytes)
	// Key Sequence (4 bytes)  
	// Null pad (8 bytes)
	// Digest (variable length based on auth length)
	
	authType := binary.BigEndian.Uint16(authData[0:2])
	authLength := binary.BigEndian.Uint16(authData[2:4])
	
	eigrpPacket.AuthLength = authLength
	
	switch authType {
	case 2:
		eigrpPacket.AuthType = "MD5"
	case 3:
		eigrpPacket.AuthType = "SHA256"
	default:
		eigrpPacket.AuthType = fmt.Sprintf("Unknown (%d)", authType)
	}
	
	// Extract digest based on the authentication length
	// The digest starts after: Auth Type (2) + Auth Length (2) + Key ID (4) + Key Sequence (4) + Null pad (8) = 20 bytes
	digestOffset := 20
	if len(authData) >= digestOffset+int(authLength) {
		digest := authData[digestOffset : digestOffset+int(authLength)]
		eigrpPacket.Digest = fmt.Sprintf("%x", digest)
	}
}

func printEIGRPPacket(packet EIGRPPacket) {
	if packet.IsIPv6 {
		fmt.Printf("EIGRP (IPv6):\n")
	} else {
		fmt.Printf("EIGRP (IPv4):\n")
	}
	
	fmt.Printf("- Source address: %s\n", packet.SrcIP)
	dstHint := packet.DstIP
	if packet.DstIP == "ff02::a" {
		dstHint = "ff02::a (multicast)"
	}
	fmt.Printf("- Destination address: %s\n", dstHint)
	fmt.Printf("- Source MAC address: %s\n", packet.SrcMAC)
	fmt.Printf("- Destination MAC address: %s\n", packet.DstMAC)
	fmt.Printf("- Protocol version: %d\n", packet.Version)
	fmt.Printf("- Virtual router ID: %d\n", packet.VirtualRouterID)
	fmt.Printf("- Autonomous system: %d\n", packet.AutonomousSystem)
	fmt.Printf("- Authentication type: %s\n", packet.AuthType)
	
	if packet.AuthType != "Not present" {
		fmt.Printf("- Authentication length: %d\n", packet.AuthLength)
		fmt.Printf("- Digest: %s\n", packet.Digest)
	}
	
	if packet.HasKValues {
		fmt.Printf("- K values: K1=%d, K2=%d, K3=%d, K4=%d, K5=%d, K6=%d\n",
			packet.KValues[0], packet.KValues[1], packet.KValues[2],
			packet.KValues[3], packet.KValues[4], packet.KValues[5])
	}
	fmt.Println()
}

func printEIGRPSummary(totalPackets, eigrpPackets int) {
	fmt.Println("=== SUMMARY ===")
	fmt.Printf("Total packets processed: %d\n", totalPackets)
	fmt.Printf("EIGRP packets found: %d\n", eigrpPackets)
}
