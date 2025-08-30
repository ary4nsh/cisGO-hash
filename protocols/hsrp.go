package protocols

import (
	"encoding/binary"
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

// HSRPPacket represents an HSRP packet with extracted information
type HSRPPacket struct {
	SrcIP         string
	DstIP         string
	SrcMAC        string
	DstMAC        string
	Version       uint8
	State         string
	HelloTime     uint32 // Changed to uint32 for HSRPv2
	HoldTime      uint32 // Changed to uint32 for HSRPv2
	Priority      uint8
	Priorityv2    uint32
	Group         uint16
	VirtualIP     string
	SenderIP      string
	MD5KeyID      uint8
	MD5Digest     string
	PlainTextAuth string
}

// HSRP state constants for HSRPv1
var hsrpV1States = map[uint8]string{
	0:  "Initial",
	1:  "Learn", 
	2:  "Listen",
	4:  "Speak",
	8:  "Standby",
	16: "Active",
}

// HSRP state constants for HSRPv0 and HSRPv2
var hsrpV0V2States = map[uint8]string{
	0: "Initial",
	1: "Learn",
	2: "Listen",
	4: "Speak",
	6: "Active", // HSRPv2 Active state
	8: "Standby",
	16: "Active", // HSRPv0 Active state
}

// TLV types for HSRPv0 and HSRPv2
const (
	TLV_GROUP_STATE = 1
	TLV_INTERFACE_STATE = 2
	TLV_TEXT_AUTH = 3
	TLV_MD5_AUTH = 4
	TLV_IPV6 = 5
)

// ExtractHSRPFromPcap analyzes HSRP packets from capture files
func ExtractHSRPFromPcap(filename string) {
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
		
		processHSRPFromNgReader(reader)
		return
	} else {
		// Handle pcap and cap files
		handle, err = pcap.OpenOffline(filename)
		if err != nil {
			log.Fatal("Error opening pcap file:", err)
		}
		defer handle.Close()
	}
	
	processHSRPFromHandle(handle)
}

func processHSRPFromNgReader(reader *pcapgo.NgReader) {
	var hsrpPackets []HSRPPacket
	totalPackets := 0
	packetNum := 1
	
	for {
		data, _, err := reader.ReadPacketData()
		if err != nil {
			break // End of file
		}
		
		totalPackets++
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		
		if hsrpPacket := extractHSRPInfo(packet); hsrpPacket != nil {
			fmt.Printf("=== HSRP Packet #%d ===\n", packetNum)
			printHSRPPacket(*hsrpPacket)
			hsrpPackets = append(hsrpPackets, *hsrpPacket)
			packetNum++
		}
	}
	
	printHSRPSummary(totalPackets, len(hsrpPackets))
}

func processHSRPFromHandle(handle *pcap.Handle) {
	var hsrpPackets []HSRPPacket
	totalPackets := 0
	packetNum := 1
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		totalPackets++
		
		if hsrpPacket := extractHSRPInfo(packet); hsrpPacket != nil {
			fmt.Printf("=== HSRP Packet #%d ===\n", packetNum)
			printHSRPPacket(*hsrpPacket)
			hsrpPackets = append(hsrpPackets, *hsrpPacket)
			packetNum++
		}
	}
	
	printHSRPSummary(totalPackets, len(hsrpPackets))
}

func extractHSRPInfo(packet gopacket.Packet) *HSRPPacket {
	// HSRP packets are UDP packets on port 1985
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp.DstPort != 1985 && udp.SrcPort != 1985 {
			return nil
		}
		
		// Get IP layer for addresses
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			
			hsrpPacket := &HSRPPacket{
				SrcIP: ip.SrcIP.String(),
				DstIP: ip.DstIP.String(),
			}
			
			// Extract MAC addresses
			if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
				eth, _ := ethLayer.(*layers.Ethernet)
				hsrpPacket.SrcMAC = eth.SrcMAC.String()
				hsrpPacket.DstMAC = eth.DstMAC.String()
			}
			
			// Parse HSRP payload
			if len(udp.Payload) > 0 {
				parseHSRPPayload(udp.Payload, hsrpPacket)
			}
			
			return hsrpPacket
		}
	}
	
	return nil
}

func parseHSRPPayload(payload []byte, hsrpPacket *HSRPPacket) {
	if len(payload) < 2 {
		return
	}

	// Determine HSRP version by analyzing packet structure
	// HSRPv0: Starts with 0x00 0x00 but has TLV authentication at the end
	// HSRPv2: Starts with TLV structure (type 1, length >= 24)
	// HSRPv1: Starts with version 1 and doesn't have TLV structure
	
	firstByte := payload[0]
	secondByte := payload[1]
	
	// Check for HSRPv2 first - starts with Group State TLV (type=1, len>=24)
	if firstByte == TLV_GROUP_STATE && secondByte >= 24 && len(payload) >= int(secondByte)+2 {
		hsrpPacket.Version = 2
		parseHSRPv2Payload(payload, hsrpPacket)
		return
	}
	
	// Check for HSRPv0 - starts with 0x00 0x00 and has specific structure
	if firstByte == 0x00 && secondByte == 0x00 && len(payload) >= 20 {
		hsrpPacket.Version = 0
		parseHSRPv0Payload(payload, hsrpPacket)
		return
	}
	
	// Fallback to HSRPv1 parsing
	hsrpPacket.Version = 1
	parseHSRPv1Payload(payload, hsrpPacket)
}

func parseHSRPv0Payload(payload []byte, hsrpPacket *HSRPPacket) {
	basePacketSize := 20
	if len(payload) < basePacketSize {
		return
	}

	// HSRPv0 packet structure (from Wireshark samples):
	// 0-1: Version + Op Code (0x00 0x00)
	// 2: State 
	// 3: Hello Time
	// 4: Hold Time  
	// 5: Priority
	// 6: Group
	// 7: Reserved
	// 8-15: Authentication Data (8 bytes)
	// 16-19: Virtual IP Address (4 bytes)
	// 20+: Optional TLV authentication

	// Check if this is a Hello packet (Op Code = 0)
	opCode := payload[1]
	if opCode != 0 {
		return // Only process Hello packets
	}

	stateValue := payload[2]
	if name, ok := hsrpV0V2States[stateValue]; ok {
		hsrpPacket.State = name
	} else {
		hsrpPacket.State = fmt.Sprintf("Unknown (%d)", stateValue)
	}

	hsrpPacket.HelloTime = uint32(payload[3])
	hsrpPacket.HoldTime = uint32(payload[4])
	hsrpPacket.Priority = payload[5]
	hsrpPacket.Group = uint16(payload[6])

	// Extract Virtual IP from offset 16-19
	if len(payload) >= 20 {
		hsrpPacket.VirtualIP = net.IPv4(payload[16], payload[17], payload[18], payload[19]).String()
	}

	hsrpPacket.SenderIP = hsrpPacket.SrcIP // default

	// Parse authentication
	// First check for plain text in auth data field (offset 8-15)
	authData := payload[8:16]
	parseHSRPv0AuthData(authData, hsrpPacket)
	
	// Check for TLV authentication after base packet
	if len(payload) > basePacketSize {
		parseTLVAuthentication(payload[basePacketSize:], hsrpPacket)
	}
}

func parseHSRPv0AuthData(authData []byte, hsrpPacket *HSRPPacket) {
	// Check if it's all zeros (no authentication in this field)
	allZero := true
	for _, b := range authData {
		if b != 0 {
			allZero = false
			break
		}
	}
	
	if allZero {
		return
	}
	
	// Check if it contains printable text (null-terminated)
	textEnd := -1
	isPrintableText := true
	
	for i, b := range authData {
		if b == 0 {
			textEnd = i
			break
		}
		if b < 32 || b > 126 {
			isPrintableText = false
			break
		}
	}
	
	if isPrintableText {
		if textEnd == -1 {
			textEnd = len(authData)
		}
		if textEnd > 0 {
			hsrpPacket.PlainTextAuth = string(authData[:textEnd])
		}
	}
}

func parseTLVAuthentication(tlvData []byte, hsrpPacket *HSRPPacket) {
	if len(tlvData) < 2 {
		return
	}
	
	tlvType := tlvData[0]
	tlvLength := int(tlvData[1])
	
	if len(tlvData) < tlvLength+2 {
		return
	}
	
	data := tlvData[2 : 2+tlvLength]
	
	switch tlvType {
	case TLV_TEXT_AUTH:
		parseTextAuthTLV(data, hsrpPacket)
	case TLV_MD5_AUTH:
		parseMD5AuthTLV(data, hsrpPacket)
	}
}

func parseHSRPv1Payload(payload []byte, hsrpPacket *HSRPPacket) {
	if len(payload) < 20 {
		return
	}

	// HSRPv1 packet structure:
	// 0: Version (1 byte)
	// 1: Op Code (1 byte)  
	// 2: State (1 byte)
	// 3: Hello Time (1 byte)
	// 4: Hold Time (1 byte)
	// 5: Priority (1 byte)
	// 6: Group (1 byte)
	// 7: Reserved (1 byte)
	// 8-15: Authentication Data (8 bytes)
	// 16-19: Virtual IP Address (4 bytes)

	stateValue := payload[2]
	if name, ok := hsrpV1States[stateValue]; ok {
		hsrpPacket.State = name
	} else {
		hsrpPacket.State = fmt.Sprintf("Unknown (%d)", stateValue)
	}

	hsrpPacket.HelloTime = uint32(payload[3])
	hsrpPacket.HoldTime = uint32(payload[4])
	hsrpPacket.Priority = payload[5]
	hsrpPacket.Group = uint16(payload[6])

	if len(payload) >= 20 {
		hsrpPacket.VirtualIP = net.IPv4(payload[16], payload[17], payload[18], payload[19]).String()
	}

	hsrpPacket.SenderIP = hsrpPacket.SrcIP // default

	// Parse authentication - HSRPv1 auth data is at offset 8-15 (8 bytes)
	parseHSRPv1Authentication(payload, hsrpPacket)
}

func parseHSRPv1Authentication(payload []byte, hsrpPacket *HSRPPacket) {
	if len(payload) < 20 {
		return
	}

	// Authentication data in HSRPv1 is at offset 8-15 (8 bytes)
	authData := payload[8:16]
	
	// Check for MD5 authentication trailer (20 additional bytes after standard packet)
	if len(payload) >= 40 {
		// Look for MD5 signature: 0x01 0x01 at the start of trailer
		trailer := payload[20:]
		if len(trailer) >= 20 && trailer[0] == 0x01 && trailer[1] == 0x01 {
			// MD5 authentication detected
			// Sender IP is at offset 4-7 in trailer
			if len(trailer) >= 8 {
				hsrpPacket.SenderIP = net.IPv4(trailer[4], trailer[5], trailer[6], trailer[7]).String()
			}
			// Key ID is at offset 8 in trailer
			if len(trailer) >= 9 {
				hsrpPacket.MD5KeyID = trailer[8]
			}
			// MD5 digest is at offset 12-27 in trailer (16 bytes)
			if len(trailer) >= 28 {
				hsrpPacket.MD5Digest = fmt.Sprintf("%x", trailer[12:28])
			}
			return
		}
	}
	
	// Check the 8-byte authentication field for plain text auth
	// First check if it's all zeros (no authentication)
	allZero := true
	for _, b := range authData {
		if b != 0 {
			allZero = false
			break
		}
	}
	
	if allZero {
		// No authentication
		return
	}
	
	// Check if it contains printable text
	isPrintableText := true
	textLength := 0
	for i, b := range authData {
		if b == 0 {
			textLength = i
			break
		}
		if b < 32 || b > 126 {
			isPrintableText = false
			break
		}
		textLength = i + 1
	}
	
	if isPrintableText && textLength > 0 {
		// Plain text authentication
		hsrpPacket.PlainTextAuth = string(authData[:textLength])
	} else {
		// Binary authentication data (could be part of MD5 or other)
		hsrpPacket.MD5Digest = "Binary authentication data"
		hsrpPacket.MD5KeyID = authData[0]
	}
}

func parseHSRPv2Payload(payload []byte, hsrpPacket *HSRPPacket) {
	if len(payload) < 4 {
		return
	}
	
	// HSRPv2 uses TLV structure
	offset := 0
	
	for offset < len(payload) {
		// Need at least 2 bytes for TLV header (type + length)
		if offset+2 > len(payload) {
			break
		}
		
		tlvType := payload[offset]
		tlvLength := int(payload[offset+1])
		
		// TLV length refers to just the data portion
		totalTLVLength := tlvLength + 2
		
		// Ensure we have enough data for this entire TLV
		if offset+totalTLVLength > len(payload) {
			break
		}
		
		// Extract TLV data
		tlvDataStart := offset + 2
		tlvDataEnd := offset + totalTLVLength
		
		if tlvDataEnd > len(payload) || tlvDataStart >= tlvDataEnd {
			break
		}
		
		tlvData := payload[tlvDataStart:tlvDataEnd]
		
		switch tlvType {
		case TLV_GROUP_STATE:
			parseGroupStateTLV(tlvData, hsrpPacket)
		case TLV_TEXT_AUTH:
			parseTextAuthTLV(tlvData, hsrpPacket)
		case TLV_MD5_AUTH:
			parseMD5AuthTLV(tlvData, hsrpPacket)
		}
		
		// Move to next TLV
		offset += totalTLVLength
	}
}

func parseGroupStateTLV(data []byte, hsrpPacket *HSRPPacket) {
	// Group State TLV Structure (based on Wireshark samples):
	// 0: Version (1 byte)
	// 1: Op Code (1 byte)
	// 2: State (1 byte)
	// 3: IP Ver (1 byte)
	// 4-5: Group (2 bytes)
	// 6-11: Identifier (6 bytes)
	// 12-15: Priority (4 bytes)
	// 16-19: Hello time (4 bytes)
	// 20-23: Hold time (4 bytes)
	// 24-27: Virtual IP (4 bytes)
	
	minRequiredLength := 28
	if len(data) < minRequiredLength {
		return
	}
	
	// Check if this is a Hello packet (Op Code = 0 at offset 1)
	opCode := data[1]
	if opCode != 0 {
		return // Only process Hello packets
	}
	
	// Extract state (offset 2)
	stateValue := data[2]
	if stateName, exists := hsrpV0V2States[stateValue]; exists {
		hsrpPacket.State = stateName
	} else {
		hsrpPacket.State = fmt.Sprintf("Unknown (%d)", stateValue)
	}
	
	// Extract group (2 bytes at offset 4-5)
	hsrpPacket.Group = binary.BigEndian.Uint16(data[4:6])
	
	// Extract priority (4 bytes at offset 12-15)
	hsrpPacket.Priorityv2 = binary.BigEndian.Uint32(data[12:16])
	
	// Extract hello time (4 bytes at offset 16-19)
	hsrpPacket.HelloTime = binary.BigEndian.Uint32(data[16:20])
	
	// Extract hold time (4 bytes at offset 20-23)
	hsrpPacket.HoldTime = binary.BigEndian.Uint32(data[20:24])
	
	// Extract Virtual IP (4 bytes at offset 24-27)
	virtualIP := net.IPv4(data[24], data[25], data[26], data[27])
	hsrpPacket.VirtualIP = virtualIP.String()
}

func parseTextAuthTLV(data []byte, hsrpPacket *HSRPPacket) {
	if len(data) < 1 {
		return
	}
	
	// Find the end of the string (null-terminated or end of data)
	var textEnd int
	for i, b := range data {
		if b == 0 {
			textEnd = i
			break
		}
		textEnd = i + 1
	}
	
	if textEnd > 0 {
		hsrpPacket.PlainTextAuth = string(data[:textEnd])
	}
}

func parseMD5AuthTLV(data []byte, hsrpPacket *HSRPPacket) {
	// MD5 Auth TLV Structure (based on Wireshark samples):
	// 0: MD5 Algorithm (1 byte)
	// 1: Padding (1 byte)
	// 2-3: MD5 Flags (2 bytes)
	// 4-7: Sender's IP Address (4 bytes)
	// 8-11: MD5 Key ID (4 bytes)
	// 12-27: MD5 Authentication Data (16 bytes)
	
	minRequiredLength := 28
	if len(data) < minRequiredLength {
		return
	}
	
	// Extract Sender's IP Address (offset 4-7)
	senderIP := net.IPv4(data[4], data[5], data[6], data[7])
	hsrpPacket.SenderIP = senderIP.String()
	
	// Extract MD5 Key ID (4 bytes at offset 8-11, but we'll use just the first byte)
	hsrpPacket.MD5KeyID = data[8]
	
	// Extract MD5 digest (16 bytes at offset 12-27)
	digestData := data[12:28]
	hsrpPacket.MD5Digest = fmt.Sprintf("%x", digestData)
}

func printHSRPPacket(packet HSRPPacket) {
	fmt.Printf("- Source address: %s\n", packet.SrcIP)
	fmt.Printf("- Destination address: %s\n", packet.DstIP)
	fmt.Printf("- Source MAC address: %s\n", packet.SrcMAC)
	fmt.Printf("- Destination MAC address: %s\n", packet.DstMAC)
	fmt.Printf("- Protocol version: %d\n", packet.Version)
	fmt.Printf("- State: %s\n", packet.State)
	
	if packet.Version == 2 {
		// HSRPv2 times are in milliseconds, convert to seconds for display
		fmt.Printf("- Hello time: %d seconds\n", packet.HelloTime/1000)
		fmt.Printf("- Hold time: %d seconds\n", packet.HoldTime/1000)
		fmt.Printf("- Router priority: %d\n", packet.Priorityv2)
	} else {
		// HSRPv0 and HSRPv1 times are in seconds
		fmt.Printf("- Hello time: %d seconds\n", packet.HelloTime)
		fmt.Printf("- Hold time: %d seconds\n", packet.HoldTime)
		fmt.Printf("- Router priority: %d\n", packet.Priority)
	}
	
	fmt.Printf("- HSRP group: %d\n", packet.Group)
	fmt.Printf("- Virtual IP address: %s\n", packet.VirtualIP)
	
	// Always print sender's IP for HSRPv0 and HSRPv2
	if packet.Version == 0 || packet.Version == 2 {
		if packet.SenderIP != "" {
			fmt.Printf("- Sender's IP address: %s\n", packet.SenderIP)
		}
	} else {
		// For HSRPv1, only print sender's IP if it's different from source IP
		if packet.SenderIP != "" && packet.SenderIP != packet.SrcIP {
			fmt.Printf("- Sender's IP address: %s\n", packet.SenderIP)
		}
	}
	
	// Handle authentication display
	if packet.PlainTextAuth != "" {
		fmt.Printf("- Authentication: Plain-text\n")
		fmt.Printf("- Plain-text password: %s\n", packet.PlainTextAuth)
	} else if packet.MD5Digest != "" {
		if packet.MD5Digest == "Binary authentication data" {
			fmt.Printf("- Authentication: Binary/Unknown\n")
			fmt.Printf("- Auth Key ID: %d\n", packet.MD5KeyID)
		} else {
			fmt.Printf("- Authentication: MD5\n")
			fmt.Printf("- MD5 key ID: %d\n", packet.MD5KeyID)
			fmt.Printf("- MD5 digest: %s\n", packet.MD5Digest)
		}
	} else {
		fmt.Printf("- Authentication: None\n")
	}
	fmt.Println()
}

func printHSRPSummary(totalPackets, hsrpPackets int) {
	fmt.Println("=== SUMMARY ===")
	fmt.Printf("Total packets processed: %d\n", totalPackets)
	fmt.Printf("HSRP packets found: %d\n", hsrpPackets)
}
