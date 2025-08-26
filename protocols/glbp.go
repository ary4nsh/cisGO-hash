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

// GLBPPacket represents a GLBP packet with extracted information
type GLBPPacket struct {
	SrcIP            string
	DstIP            string
	SrcMAC           string
	DstMAC           string
	Version          uint8
	GLBPGroup        uint16
	VGState          string
	HelloPriority    uint8
	VFState          string
	VFPriority       uint8
	Weight           uint8
	VirtualAddress   string
	AuthType         string
	PlainTextAuth    string
	MD5Hash          string
}

// GLBP VG (Virtual Gateway) state constants
var glbpVGStates = map[uint8]string{
	0:  "Initial",
	1:  "Listen",
	2:  "Standby", 
	32: "Active",
}

// GLBP VF (Virtual Forwarder) state constants
var glbpVFStates = map[uint8]string{
	0:  "Initial",
	1:  "Listen", 
	2:  "Standby",
	32: "Active",
	3:  "Disabled",
}

// ExtractGLBPFromPcap analyzes GLBP packets from capture files
func ExtractGLBPFromPcap(filename string) {
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
		
		processGLBPFromNgReader(reader)
		return
	} else {
		// Handle pcap and cap files
		handle, err = pcap.OpenOffline(filename)
		if err != nil {
			log.Fatal("Error opening pcap file:", err)
		}
		defer handle.Close()
	}
	
	processGLBPFromHandle(handle)
}

func processGLBPFromNgReader(reader *pcapgo.NgReader) {
	var glbpPackets []GLBPPacket
	totalPackets := 0
	packetNum := 1
	
	for {
		data, _, err := reader.ReadPacketData()
		if err != nil {
			break // End of file
		}
		
		totalPackets++
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		
		if glbpPacket := extractGLBPInfo(packet); glbpPacket != nil {
			fmt.Printf("=== GLBP Packet #%d ===\n", packetNum)
			printGLBPPacket(*glbpPacket)
			glbpPackets = append(glbpPackets, *glbpPacket)
			packetNum++
		}
	}
	
	printGLBPSummary(totalPackets, len(glbpPackets))
}

func processGLBPFromHandle(handle *pcap.Handle) {
	var glbpPackets []GLBPPacket
	totalPackets := 0
	packetNum := 1
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		totalPackets++
		
		if glbpPacket := extractGLBPInfo(packet); glbpPacket != nil {
			fmt.Printf("=== GLBP Packet #%d ===\n", packetNum)
			printGLBPPacket(*glbpPacket)
			glbpPackets = append(glbpPackets, *glbpPacket)
			packetNum++
		}
	}
	
	printGLBPSummary(totalPackets, len(glbpPackets))
}

func extractGLBPInfo(packet gopacket.Packet) *GLBPPacket {
	// GLBP packets are UDP packets on port 3222
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp.DstPort != 3222 && udp.SrcPort != 3222 {
			return nil
		}
		
		// Get IP layer for addresses
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			
			glbpPacket := &GLBPPacket{
				SrcIP: ip.SrcIP.String(),
				DstIP: ip.DstIP.String(),
			}
			
			// Extract MAC addresses
			if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
				eth, _ := ethLayer.(*layers.Ethernet)
				glbpPacket.SrcMAC = eth.SrcMAC.String()
				glbpPacket.DstMAC = eth.DstMAC.String()
			}
			
			// Parse GLBP payload based on authentication type
			if len(udp.Payload) >= 28 {
				determineAuthTypeAndParse(udp.Payload, glbpPacket)
			}
			
			return glbpPacket
		}
	}
	
	return nil
}

// Determine authentication type and call appropriate parsing function
func determineAuthTypeAndParse(payload []byte, glbpPacket *GLBPPacket) {
	if len(payload) < 12 {
		return
	}

	// Extract basic header information
	glbpPacket.Version = payload[0]
	glbpPacket.GLBPGroup = uint16(payload[2])<<8 | uint16(payload[3])
	glbpPacket.AuthType = "null" // default

	// Check first TLV to determine authentication type
	offset := 12
	if offset+1 < len(payload) {
		firstTLVType := payload[offset]
		
		switch firstTLVType {
		case 1: // Hello TLV first - null authentication
			parseNullAuthGLBP(payload, glbpPacket)
		case 3: // Auth TLV first - check auth type
			// Peek at auth type to determine if it's plain-text or MD5
			if offset+4 < len(payload) {
				authType := payload[offset+2]
				switch authType {
				case 1:
					parsePlainTextAuthGLBP(payload, glbpPacket)
				case 2:
					parseMD5AuthGLBP(payload, glbpPacket)
				default:
					parseNullAuthGLBP(payload, glbpPacket)
				}
			}
		default:
			// Fallback to null auth parsing
			parseNullAuthGLBP(payload, glbpPacket)
		}
	}
}

// Parse GLBP payload with null authentication
// TLV structure: t=Hello, t=Request/Response
func parseNullAuthGLBP(payload []byte, glbpPacket *GLBPPacket) {
    glbpPacket.AuthType = "null"
    offset := 12

    // 1) Hello TLV
    if offset+1 >= len(payload) {
        return
    }

    helloType   := payload[offset]
    helloLength := int(payload[offset+1])

    if helloType != 1 { // sanity: must be Hello
        return
    }
    if offset+2+helloLength > len(payload) { // clamp
        helloLength = len(payload) - offset - 2
        if helloLength < 0 {
            return
        }
    }

    parseHelloTLVAtOffset(payload, offset, helloLength, glbpPacket)

    // move past the Hello TLV
    offset += helloLength

    // 2) Request/Response TLV (immediately follows Hello)
    if offset+1 >= len(payload) {
        return
    }

    rrType   := payload[offset]
    rrLength := int(payload[offset+1])

    if rrType != 2 { // sanity: must be Request/Response
        return
    }
    if offset+2+rrLength > len(payload) { // clamp
        rrLength = len(payload) - offset - 2
        if rrLength < 0 {
            return
        }
    }

    parseRequestResponseTLVAtOffset(payload, offset, rrLength, glbpPacket)
}

// Parse GLBP payload with plain-text authentication
// TLV structure: t=Auth, t=Hello, t=Request/Response
func parsePlainTextAuthGLBP(payload []byte, glbpPacket *GLBPPacket) {
	offset := 12

	// 1) Auth TLV
	if offset+1 >= len(payload) {
		return
	}
	authType   := payload[offset]
	authLength := int(payload[offset+1])
	if authType != 3 { // sanity
		return
	}
	if offset+authLength > len(payload) {
		authLength = len(payload) - offset - 2
		if authLength < 0 {
			return
		}
	}
	parseAuthTLVAtOffset(payload, offset, authLength, glbpPacket)
	offset += authLength

	// 2) Hello TLV
	if offset+1 >= len(payload) {
		return
	}
	helloType   := payload[offset]
	helloLength := int(payload[offset+1])
	if helloType != 1 {
		return
	}
	if offset+helloLength > len(payload) {
		helloLength = len(payload) - offset - 2
		if helloLength < 0 {
			return
		}
	}
	parseHelloTLVAtOffset(payload, offset, helloLength, glbpPacket)
	offset += helloLength

	// 3) Request/Response TLV
	if offset+1 >= len(payload) {
		return
	}
	rrType   := payload[offset]
	rrLength := int(payload[offset+1])
	if rrType != 2 {
		return
	}
	if offset+rrLength > len(payload) {
		rrLength = len(payload) - offset - 2
		if rrLength < 0 {
			return
		}
	}
	parseRequestResponseTLVAtOffset(payload, offset, rrLength, glbpPacket)
}

// Parse GLBP payload with MD5 authentication
// TLV structure: t=Auth, t=4, t=Hello, t=Request/Response
func parseMD5AuthGLBP(payload []byte, glbpPacket *GLBPPacket) {
	offset := 12

	// 1) Auth TLV (type 3)
	if offset+1 >= len(payload) {
		return
	}
	authType   := payload[offset]
	authLength := int(payload[offset+1])
	if authType != 3 {
		return
	}
	if offset+authLength > len(payload) {
		authLength = len(payload) - offset - 2
		if authLength < 0 {
			return
		}
	}
	parseAuthTLVAtOffset(payload, offset, authLength, glbpPacket)
	offset += authLength

	// 2) Type-4 TLV  (skip, but still advance)
	if offset+1 >= len(payload) {
		return
	}
	t4Type   := payload[offset]
	t4Length := int(payload[offset+1])
	if t4Type != 4 {
		return
	}
	if offset+t4Length > len(payload) {
		t4Length = len(payload) - offset - 2
		if t4Length < 0 {
			return
		}
	}
	// Nothing to parse for type 4, just skip
	offset += t4Length

	// 3) Hello TLV (type 1)
	if offset+1 >= len(payload) {
		return
	}
	helloType   := payload[offset]
	helloLength := int(payload[offset+1])
	if helloType != 1 {
		return
	}
	if offset+helloLength > len(payload) {
		helloLength = len(payload) - offset - 2
		if helloLength < 0 {
			return
		}
	}
	parseHelloTLVAtOffset(payload, offset, helloLength, glbpPacket)
	offset += helloLength

	// 4) Request/Response TLV (type 2)
	if offset+1 >= len(payload) {
		return
	}
	rrType   := payload[offset]
	rrLength := int(payload[offset+1])
	if rrType != 2 {
		return
	}
	if offset+rrLength > len(payload) {
		rrLength = len(payload) - offset - 2
		if rrLength < 0 {
			return
		}
	}
	parseRequestResponseTLVAtOffset(payload, offset, rrLength, glbpPacket)
}

// Parse Hello TLV at specific offset
func parseHelloTLVAtOffset(payload []byte, offset, tlvLength int, glbpPacket *GLBPPacket) {
	if tlvLength < 26 {
		return
	}
	
	// Hello TLV structure (starting from offset):
	// offset+0: Type (1 byte)
	// offset+1: Length (1 byte)
	// offset+2: Unknown1-0 (1 byte)
	// offset+3: VG state (1 byte)
	// offset+4: Unknown1-1 (1 byte)
	// offset+5: GLBP hello priority (1 byte)
	// offset+6-7: Unknown1-2 (2 bytes)
	// offset+8-11: Helloint (4 bytes)
	// offset+12-15: Holdint (4 bytes)
	// offset+16-17: Redirect (2 bytes)
	// offset+18-19: Timeout (2 bytes)
	// offset+20-21: Unknown1-3 (2 bytes)
	// offset+22: Address type (1 byte)
	// offset+23: Address length (1 byte)
	// offset+24-27: Virtual IPv4 (4 bytes) - last 4 bytes of TLV
	
	// VG state at offset+3
	if offset+3 < len(payload) {
		vgState := payload[offset+3]
		if vgStateName, exists := glbpVGStates[vgState]; exists {
			glbpPacket.VGState = vgStateName
		}
	}
	
	// GLBP hello priority at offset+5
	if offset+5 < len(payload) {
		glbpPacket.HelloPriority = payload[offset+5]
	}
	
	// Virtual IPv4 address at last 4 bytes of TLV
	if offset+2+tlvLength >= 4 {
		virtualIPOffset := offset + tlvLength - 4
		if virtualIPOffset+3 < len(payload) {
			virtualIP := net.IPv4(payload[virtualIPOffset], payload[virtualIPOffset+1], 
								 payload[virtualIPOffset+2], payload[virtualIPOffset+3])
			glbpPacket.VirtualAddress = virtualIP.String()
		}
	}
}

// Parse Request/Response TLV at specific offset
func parseRequestResponseTLVAtOffset(payload []byte, offset, tlvLength int, glbpPacket *GLBPPacket) {
	if tlvLength < 18 {
		return
	}
	
	// Request/Response TLV structure (starting from offset):
	// offset+0: Type (1 byte)
	// offset+1: Length (1 byte)
	// offset+2: Forwarder (1 byte)
	// offset+3: VF state (1 byte)
	// offset+4: Unknown2-1 (1 byte)
	// offset+5: VF priority (1 byte)
	// offset+6: Weight (1 byte)
	// offset+7-13: Unknown2-2 (7 bytes)
	// offset+14-19: Virtualmac (6 bytes) - last 6 bytes
	
	// VF state at offset+3
	if offset+3 < len(payload) {
		vfState := payload[offset+3]
		if vfStateName, exists := glbpVFStates[vfState]; exists {
			glbpPacket.VFState = vfStateName
		}
	}
	
	// VF priority at offset+5
	if offset+5 < len(payload) {
		glbpPacket.VFPriority = payload[offset+5]
	}
	
	// Weight at offset+6
	if offset+6 < len(payload) {
		glbpPacket.Weight = payload[offset+6]
	}
}

// Parse Auth TLV at specific offset
func parseAuthTLVAtOffset(payload []byte, offset, tlvLength int, glbpPacket *GLBPPacket) {
	if tlvLength < 4 {
		return
	}
	
	// Auth type at offset+2, auth length at offset+3
	authType := payload[offset+2]
	authDataLength := int(payload[offset+3])
	
	switch authType {
	case 0:
		glbpPacket.AuthType = "No authentication"
	case 1:
		glbpPacket.AuthType = "Plain-text"
		if authDataLength > 0 && authDataLength <= 32 && offset+4+authDataLength <= len(payload) {
			var password []byte
			for j := 0; j < authDataLength; j++ {
				b := payload[offset+4+j]
				if b == 0 {
					break
				}
				if b >= 32 && b <= 126 {
					password = append(password, b)
				}
			}
			if len(password) > 0 {
				glbpPacket.PlainTextAuth = string(password)
			}
		}
	case 2:
		glbpPacket.AuthType = "MD5"
		if authDataLength == 16 && offset+4+16 <= len(payload) {
			glbpPacket.MD5Hash = fmt.Sprintf("%x", payload[offset+4:offset+4+16])
		}
	}
}

func printGLBPPacket(packet GLBPPacket) {
	fmt.Printf("- Source address: %s\n", packet.SrcIP)
	fmt.Printf("- Destination address: %s\n", packet.DstIP)
	fmt.Printf("- Source MAC address: %s\n", packet.SrcMAC)
	fmt.Printf("- Destination MAC address: %s\n", packet.DstMAC)
	fmt.Printf("- Protocol version: %d\n", packet.Version)
	fmt.Printf("- GLBP group: %d\n", packet.GLBPGroup)
	fmt.Printf("- VG state: %s\n", packet.VGState)
	fmt.Printf("- GLBP hello priority: %d\n", packet.HelloPriority)
	fmt.Printf("- VF state: %s\n", packet.VFState)
	fmt.Printf("- VF priority: %d\n", packet.VFPriority)
	fmt.Printf("- Weight: %d\n", packet.Weight)
	fmt.Printf("- Virtual address: %s\n", packet.VirtualAddress)
	fmt.Printf("- Authentication type: %s\n", packet.AuthType)
	
	if packet.AuthType != "null" && packet.AuthType != "No authentication" {
		if packet.PlainTextAuth != "" {
			fmt.Printf("- Plain-text password: %s\n", packet.PlainTextAuth)
		} else if packet.MD5Hash != "" {
			fmt.Printf("- MD5 authentication data: %s\n", packet.MD5Hash)
		}
	}
	
	fmt.Println()
}

func printGLBPSummary(totalPackets, glbpPackets int) {
	fmt.Println("=== SUMMARY ===")
	fmt.Printf("Total packets processed: %d\n", totalPackets)
	fmt.Printf("GLBP packets found: %d\n", glbpPackets)
}
