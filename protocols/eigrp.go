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
	SrcIP        string
	DstIP        string
	SrcMAC       string
	DstMAC       string
	Version      uint8
	VirtualRouterID uint16
	AutonomousSystem uint16
	MD5Digest    string
	KValues      []uint8
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
	// Check if this is an EIGRP packet (IP protocol 88)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if ip.Protocol != 88 { // EIGRP protocol number
			return nil
		}
		
		eigrpPacket := &EIGRPPacket{
			SrcIP: ip.SrcIP.String(),
			DstIP: ip.DstIP.String(),
		}
		
		// Extract MAC addresses
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			eigrpPacket.SrcMAC = eth.SrcMAC.String()
			eigrpPacket.DstMAC = eth.DstMAC.String()
		}
		
		// Extract EIGRP-specific information from payload
		if len(ip.Payload) >= 20 { // Minimum EIGRP header size
			payload := ip.Payload
			
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
			
			// Extract K values and MD5 digest from TLVs
			parseEIGRPTLVs(payload[20:], eigrpPacket)
		}
		
		return eigrpPacket
	}
	
	return nil
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
			if len(tlvValue) >= 12 {
				eigrpPacket.KValues = []uint8{
					tlvValue[0], // K1
					tlvValue[1], // K2
					tlvValue[2], // K3
					tlvValue[3], // K4
					tlvValue[4], // K5
					tlvValue[5], // K6 (if present)
				}
			}
		case 0x0002: // Authentication TLV
			if len(tlvValue) >= 16 {
				// Extract MD5 digest (last 16 bytes of auth data)
				digestStart := len(tlvValue) - 16
				eigrpPacket.MD5Digest = fmt.Sprintf("%x", tlvValue[digestStart:])
			}
		}
		
		offset += int(tlvLength)
	}
	
	// Set default K values if not found
	if len(eigrpPacket.KValues) == 0 {
		eigrpPacket.KValues = []uint8{1, 0, 1, 0, 0, 0} // Default EIGRP K values
	}
}

func printEIGRPPacket(packet EIGRPPacket) {
	fmt.Printf("- Source address: %s\n", packet.SrcIP)
	fmt.Printf("- Destination address: %s\n", packet.DstIP)
	fmt.Printf("- Source MAC address: %s\n", packet.SrcMAC)
	fmt.Printf("- Destination MAC address: %s\n", packet.DstMAC)
	fmt.Printf("- Protocol version: %d\n", packet.Version)
	fmt.Printf("- Virtual router ID: %d\n", packet.VirtualRouterID)
	fmt.Printf("- Autonomous system: %d\n", packet.AutonomousSystem)
	
	if packet.MD5Digest != "" {
		fmt.Printf("- MD5 digest: %s\n", packet.MD5Digest)
	} else {
		fmt.Printf("- MD5 digest: Not present\n")
	}
	
	fmt.Printf("- K values: K1=%d, K2=%d, K3=%d, K4=%d, K5=%d, K6=%d\n",
		packet.KValues[0], packet.KValues[1], packet.KValues[2],
		packet.KValues[3], packet.KValues[4], packet.KValues[5])
	fmt.Println()
}

func printEIGRPSummary(totalPackets, eigrpPackets int) {
	fmt.Println("=== SUMMARY ===")
	fmt.Printf("Total packets processed: %d\n", totalPackets)
	fmt.Printf("EIGRP packets found: %d\n", eigrpPackets)
}
