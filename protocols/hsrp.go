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
	HelloTime     uint8
	HoldTime      uint8
	Priority      uint8
	Group         uint16
	VirtualIP     string
	SenderIP      string
	MD5KeyID      uint8
	MD5Digest     string
	PlainTextAuth string
}

// HSRP state constants
var hsrpStates = map[uint8]string{
	0:  "Initial",
	1:  "Learn", 
	2:  "Listen",
	4:  "Speak",
	8:  "Standby",
	16: "Active",
}

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
			if len(udp.Payload) >= 20 { // Minimum HSRP packet size
				parseHSRPPayload(udp.Payload, hsrpPacket)
			}
			
			return hsrpPacket
		}
	}
	
	return nil
}

func parseHSRPPayload(payload []byte, hsrpPacket *HSRPPacket) {
	if len(payload) < 20 {
		return
	}
	
	// HSRP Header Structure:
	// Version (1 byte) - offset 0
	// Op Code (1 byte) - offset 1  
	// State (1 byte) - offset 2
	// Hello Time (1 byte) - offset 3
	// Hold Time (1 byte) - offset 4
	// Priority (1 byte) - offset 5
	// Group (1 byte) - offset 6
	// Reserved (1 byte) - offset 7
	// Authentication Data (8 bytes) - offset 8-15
	// Virtual IP Address (4 bytes) - offset 16-19
	// Additional data may follow for authentication
	
	hsrpPacket.Version = payload[0]
	
	// Extract state
	stateValue := payload[2]
	if stateName, exists := hsrpStates[stateValue]; exists {
		hsrpPacket.State = stateName
	} else {
		hsrpPacket.State = fmt.Sprintf("Unknown (%d)", stateValue)
	}
	
	hsrpPacket.HelloTime = payload[3]
	hsrpPacket.HoldTime = payload[4]
	hsrpPacket.Priority = payload[5]
	hsrpPacket.Group = uint16(payload[6]) // For HSRPv1, group is 1 byte
	
	// Extract Virtual IP Address (4 bytes at offset 16)
	if len(payload) >= 20 {
		virtualIP := net.IPv4(payload[16], payload[17], payload[18], payload[19])
		hsrpPacket.VirtualIP = virtualIP.String()
	}
	
	// For HSRPv1, the sender's IP is often the source IP of the packet
	hsrpPacket.SenderIP = hsrpPacket.SrcIP
	
	// Check for MD5 authentication
	// In HSRPv1, authentication data is at offset 8-15
	// For MD5 authentication, there may be additional data after the basic header
	if len(payload) > 20 {
		// Check if this might be MD5 authentication
		// MD5 auth typically has a longer payload with Key ID + digest at the end
		if len(payload) >= 37 { // 20 bytes header + 1 byte Key ID + 16 bytes MD5 digest
			// Extract MD5 Key ID (1 byte before the digest)
			keyIDOffset := len(payload) - 17 // 1 byte before the 16-byte digest
			hsrpPacket.MD5KeyID = payload[keyIDOffset]
			
			// Extract MD5 digest from the end of the packet
			digestStart := len(payload) - 16
			hsrpPacket.MD5Digest = fmt.Sprintf("%x", payload[digestStart:])
		} else if len(payload) >= 36 { // 20 bytes header + 16 bytes MD5 digest (no separate Key ID)
			// Extract potential MD5 digest from the end of the packet
			digestStart := len(payload) - 16
			hsrpPacket.MD5Digest = fmt.Sprintf("%x", payload[digestStart:])
			// Key ID might be embedded in authentication field at offset 8
			hsrpPacket.MD5KeyID = payload[8]
		} else {
			// Simple text authentication - extract from offset 8-15
			authData := payload[8:16]
			// Check if it's printable text (simple auth) or binary (likely no auth/simple)
			isPrintable := true
			nonZeroFound := false
			for _, b := range authData {
				if b == 0 {
					break
				}
				nonZeroFound = true
				if b < 32 || b > 126 {
					isPrintable = false
					break
				}
			}
			if isPrintable && nonZeroFound {
				// Extract the plain text password (null-terminated)
				var password []byte
				for _, b := range authData {
					if b == 0 {
						break
					}
					password = append(password, b)
				}
				if len(password) > 0 {
					hsrpPacket.PlainTextAuth = string(password)
				}
			}
		}
	} else {
		// Check simple authentication in the 8-byte auth field
		authData := payload[8:16]
		allZero := true
		for _, b := range authData {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			// Check if it's printable text
			isPrintable := true
			for _, b := range authData {
				if b == 0 {
					break
				}
				if b < 32 || b > 126 {
					isPrintable = false
					break
				}
			}
			if isPrintable {
				// Extract the plain text password (null-terminated)
				var password []byte
				for _, b := range authData {
					if b == 0 {
						break
					}
					password = append(password, b)
				}
				if len(password) > 0 {
					hsrpPacket.PlainTextAuth = string(password)
				}
			} else {
				hsrpPacket.MD5Digest = "Non-text authentication present"
				// Try to extract Key ID from first byte of auth data
				hsrpPacket.MD5KeyID = payload[8]
			}
		}
	}
	
	// Handle HSRPv2 if version is 2
	if hsrpPacket.Version == 2 && len(payload) >= 40 {
		// HSRPv2 has a different structure
		// Group number is 2 bytes in HSRPv2
		hsrpPacket.Group = binary.BigEndian.Uint16(payload[6:8])
		
		// Virtual IP might be at a different offset in HSRPv2
		if len(payload) >= 28 {
			virtualIP := net.IPv4(payload[24], payload[25], payload[26], payload[27])
			hsrpPacket.VirtualIP = virtualIP.String()
		}
		
		// For HSRPv2 with MD5 auth, Key ID extraction might differ
		if len(payload) >= 48 { // HSRPv2 with MD5 auth
			keyIDOffset := len(payload) - 17
			hsrpPacket.MD5KeyID = payload[keyIDOffset]
			
			digestStart := len(payload) - 16
			hsrpPacket.MD5Digest = fmt.Sprintf("%x", payload[digestStart:])
		}
	}
}

func printHSRPPacket(packet HSRPPacket) {
	fmt.Printf("- Source address: %s\n", packet.SrcIP)
	fmt.Printf("- Destination address: %s\n", packet.DstIP)
	fmt.Printf("- Source MAC address: %s\n", packet.SrcMAC)
	fmt.Printf("- Destination MAC address: %s\n", packet.DstMAC)
	fmt.Printf("- Protocol version: %d\n", packet.Version)
	fmt.Printf("- State: %s\n", packet.State)
	fmt.Printf("- Hello time: %d seconds\n", packet.HelloTime)
	fmt.Printf("- Hold time: %d seconds\n", packet.HoldTime)
	fmt.Printf("- Router priority: %d\n", packet.Priority)
	fmt.Printf("- HSRP group: %d\n", packet.Group)
	fmt.Printf("- Virtual IP address: %s\n", packet.VirtualIP)
	fmt.Printf("- Sender's IP address: %s\n", packet.SenderIP)
	
	if packet.MD5Digest != "" {
		fmt.Printf("- MD5 key ID: %d\n", packet.MD5KeyID)
		fmt.Printf("- MD5 digest: %s\n", packet.MD5Digest)
	} else if packet.PlainTextAuth != "" {
		fmt.Printf("- Plain-text password: %s\n", packet.PlainTextAuth)
	} else {
		fmt.Printf("- MD5 digest: Not present\n")
	}
	fmt.Println()
}

func printHSRPSummary(totalPackets, hsrpPackets int) {
	fmt.Println("=== SUMMARY ===")
	fmt.Printf("Total packets processed: %d\n", totalPackets)
	fmt.Printf("HSRP packets found: %d\n", hsrpPackets)
}
