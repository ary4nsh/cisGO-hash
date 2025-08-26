package protocols

import (
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)

func ExtractOSPFFromPcapng(filename string) error {
	// Create or open the hash file for writing
	hashFile, err := os.Create("ospf-hashes.txt")
	if err != nil {
		fmt.Printf("ERROR: Cannot create ospf-hashes.txt: %v\n", err)
		return err
	}
	defer hashFile.Close()
	
	// Open the capture file
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		fmt.Printf("ERROR: Cannot open file: %v\n", err)
		return err
	}
	defer handle.Close()

	
	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	totalPackets := 0
	ospfPackets := 0
	hashesWritten := 0

	// Process each packet
	for packet := range packetSource.Packets() {
		totalPackets++
		
		// Print progress every 100 packets
		if totalPackets%100 == 0 {
			fmt.Printf("Processed %d packets...\n", totalPackets)
		}
		
		// Check for OSPF packets (both IPv4 and IPv6)
		var ospfPayload []byte
		var srcIP, dstIP net.IP
		
		// Check IPv4 first
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip := ipLayer.(*layers.IPv4)
			if ip.Protocol == layers.IPProtocolOSPF {
				ospfPayload = ip.Payload
				srcIP = ip.SrcIP
				dstIP = ip.DstIP
			}
		}
		
		// Check IPv6 if no IPv4 OSPF found
		if ospfPayload == nil {
			if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
				ip := ipLayer.(*layers.IPv6)
				if ip.NextHeader == layers.IPProtocolOSPF {
					ospfPayload = ip.Payload
					srcIP = ip.SrcIP
					dstIP = ip.DstIP
				} else if ip.NextHeader == layers.IPProtocolAH {
					// Handle IPv6 Authentication Header
					ospfPayload, srcIP, dstIP = parseIPv6WithAuthHeader(packet, ip)
				}
			}
		}
		
		// Process OSPF packet if found
		if ospfPayload != nil && len(ospfPayload) > 0 {
			ospfPackets++
			
			// Check OSPF version from packet header
			version := ospfPayload[0]
			
			if version == 2 {
				// Parse as OSPFv2
				if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
					ip := ipv4Layer.(*layers.IPv4)
					hashes := parseOSPFv2Packet(packet, ip, ospfPackets)
					for _, hash := range hashes {
						_, err := hashFile.WriteString(hash + "\n")
						if err != nil {
							fmt.Printf("ERROR: Cannot write to ospf-hashes.txt: %v\n", err)
						} else {
							hashesWritten++
						}
					}
				}
			} else if version == 3 {
				// Parse as OSPFv3
				parseOSPFv3Packet(packet, srcIP, dstIP, ospfPayload, ospfPackets)
			} else {
				// Unknown OSPF version
				fmt.Printf("\n=== OSPF Packet #%d ===\n", ospfPackets)
				fmt.Printf("- Source address: %s\n", srcIP)
				fmt.Printf("- Destination address: %s\n", dstIP)
				fmt.Printf("- Unknown OSPF version: %d\n", version)
				fmt.Println()
			}
		}
	}
	
	fmt.Printf("\n=== SUMMARY ===\n")
	fmt.Printf("Total packets processed: %d\n", totalPackets)
	fmt.Printf("OSPF packets found: %d\n", ospfPackets)
	fmt.Printf("MD5 hashes written to ospf-hashes.txt: %d\n", hashesWritten)
	
	if totalPackets == 0 {
		fmt.Println("ERROR: No packets found in file. File might be corrupted or empty.")
		return fmt.Errorf("no packets found")
	}
	
	if ospfPackets == 0 {
		fmt.Println("No OSPF packets found. This might be normal if the capture doesn't contain OSPF traffic.")
	}
	
	return nil
}

func parseIPv6WithAuthHeader(packet gopacket.Packet, ip *layers.IPv6) ([]byte, net.IP, net.IP) {
	// Parse IPv6 Authentication Header manually
	payload := ip.Payload
	if len(payload) < 8 {
		return nil, nil, nil
	}
	
	// Authentication Header format:
	// 0: Next Header (1 byte)
	// 1: Payload Length (1 byte) - in 4-byte units, minus 2
	// 2-3: Reserved (2 bytes)
	// 4-7: Security Parameters Index (4 bytes)
	// 8-11: Sequence Number (4 bytes)
	// 12+: Integrity Check Value (variable length)
	
	nextHeader := payload[0]
	payloadLength := payload[1]
	
	// Calculate total AH header length in bytes
	// Formula: (Payload Length + 2) * 4
	ahHeaderLength := int(payloadLength+2) * 4
	
	// Check if this is OSPF
	if nextHeader == 89 && len(payload) > ahHeaderLength { // 89 is OSPF protocol number
		ospfPayload := payload[ahHeaderLength:]
		return ospfPayload, ip.SrcIP, ip.DstIP
	}
	
	return nil, nil, nil
}

func parseOSPFv2Packet(packet gopacket.Packet, ip *layers.IPv4, packetNum int) []string {
	var hashes []string
	
	fmt.Printf("\n=== OSPFv2 Packet #%d ===\n", packetNum)
	
	// Get source MAC
	srcMAC := ""
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC.String()
	}
	
	// Get OSPF payload
	payload := ip.Payload
	if len(payload) < 24 {
		fmt.Printf("OSPF payload too short: %d bytes\n", len(payload))
		return hashes
	}
	
	// Parse OSPF header manually
	version := payload[0]
	msgType := payload[1]
	packetLength := uint16(payload[2])<<8 | uint16(payload[3])
	areaID := net.IPv4(payload[8], payload[9], payload[10], payload[11])
	authType := uint16(payload[14])<<8 | uint16(payload[15])
	
	// Print basic info
	fmt.Printf("- Source address: %s\n", ip.SrcIP)
	fmt.Printf("- Destination address: %s\n", ip.DstIP)
	if srcMAC != "" {
		fmt.Printf("- Source MAC address: %s\n", srcMAC)
	}
	fmt.Printf("- Protocol version: %d", version)
	if version == 2 {
		fmt.Printf(" (IPv4)\n")
	} else {
		fmt.Printf(" (Unknown)\n")
	}
	fmt.Printf("- Area ID: %s\n", areaID)
	fmt.Printf("- Authentication type: %d", authType)
	switch authType {
	case 0:
		fmt.Printf(" (null)\n")
	case 1:
		fmt.Printf(" (plain-text)\n")
	case 2:
		fmt.Printf(" (cryptographic)\n")
	default:
		fmt.Printf(" (unknown)\n")
	}
	
	// Parse authentication fields based on auth type
	var authKeyID uint8
	var authDataLength uint8
	var authSequenceNumber uint32
	var authData []byte
	
	if authType == 2 {
		// For cryptographic authentication, the 8-byte auth field contains:
		// Bytes 16-17: Reserved (2 bytes, should be 0)
		// Byte 18: Key ID (1 byte)
		// Byte 19: Auth Data Length (1 byte)  
		// Bytes 20-23: Cryptographic Sequence Number (4 bytes)
		authKeyID = payload[18]
		authDataLength = payload[19]
		authSequenceNumber = uint32(payload[20])<<24 | uint32(payload[21])<<16 | 
							uint32(payload[22])<<8 | uint32(payload[23])
		
		fmt.Printf("- Authentication key ID: %d\n", authKeyID)
		fmt.Printf("- Authentication data length: %d\n", authDataLength)
		fmt.Printf("- Authentication sequence number: %d\n", authSequenceNumber)
		
		// Extract authentication data based on the length
		// The actual authentication data is appended after the OSPF packet
		authStartPos := int(packetLength)
		
		// Extract authentication data of specified length
		if len(payload) >= authStartPos+int(authDataLength) {
			authData = payload[authStartPos:authStartPos+int(authDataLength)]
			fmt.Printf("- Authentication data (%d bytes): %x\n", authDataLength, authData)
		} else {
			fmt.Printf("- Authentication data: (hash not found or insufficient data)\n")
		}
	} else if authType == 1 {
		// For plain-text authentication, use the 8-byte auth field
		authData = payload[16:24]
		authDataLength = 8
		
		// Convert hex to ASCII and remove null bytes
		password := string(authData)
		// Remove null bytes from the end
		for i := len(password) - 1; i >= 0; i-- {
			if password[i] != 0 {
				password = password[:i+1]
				break
			}
		}
		
		fmt.Printf("- Authentication data length: %d\n", authDataLength)
		if password != "" {
			fmt.Printf("- Authentication data: %s\n", password)
		} else {
			fmt.Printf("- Authentication data: %x\n", authData)
		}
	} else if authType == 0 {
		// Null authentication - don't print authentication data fields
	}
	
	// If it's a Hello packet (type 1), parse more info
	if msgType == 1 && len(payload) >= 44 {
		networkMask := net.IPv4(payload[24], payload[25], payload[26], payload[27])
		routerPriority := payload[31]
		designatedRouter := net.IPv4(payload[36], payload[37], payload[38], payload[39])
		backupDesignatedRouter := net.IPv4(payload[40], payload[41], payload[42], payload[43])
		
		fmt.Printf("- Network mask: %s\n", networkMask)
		fmt.Printf("- Router priority: %d\n", routerPriority)
		fmt.Printf("- Designated router: %s\n", designatedRouter)
		fmt.Printf("- Backup designated router: %s\n", backupDesignatedRouter)
	}
	
	fmt.Println()
	
	// Generate netmd5 hash format for MD5 authentication
	if authType == 2 && len(authData) == int(authDataLength) && msgType == 1 && authDataLength > 0 {
		// Extract OSPF header + Hello packet (without the MD5 hash)
		ospfPacketData := payload[:packetLength]
		netmd5Hash := fmt.Sprintf("$netmd5$%x$%x", ospfPacketData, authData)
		fmt.Printf("%s\n", netmd5Hash)
		hashes = append(hashes, netmd5Hash)
	}
	
	return hashes
}

func parseOSPFv3Packet(packet gopacket.Packet, srcIP, dstIP net.IP, payload []byte, packetNum int) {
	fmt.Printf("\n=== OSPFv3 Packet #%d ===\n", packetNum)
	
	// Minimum OSPFv3 header is 16 bytes
	if len(payload) < 16 {
		fmt.Printf("OSPFv3 payload too short: %d bytes\n", len(payload))
		return
	}
	
	// Get source and destination MAC addresses
	srcMAC := ""
	dstMAC := ""
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC.String()
		dstMAC = eth.DstMAC.String()
	}
	
	// Parse OSPFv3 header
	version := payload[0]  // Version (should be 3)
	msgType := payload[1]  // Type
	packetLength := uint16(payload[2])<<8 | uint16(payload[3])  // Packet Length
	routerID := net.IPv4(payload[4], payload[5], payload[6], payload[7])  // Router ID
	areaID := net.IPv4(payload[8], payload[9], payload[10], payload[11])  // Area ID
	checksum := uint16(payload[12])<<8 | uint16(payload[13])  // Checksum
	instanceID := payload[14]  // Instance ID
	reserved := payload[15]  // Reserved
	
	// Print basic info
	fmt.Printf("- Source address: %s\n", srcIP)
	
	// Handle destination address with multicast hint
	destHint := dstIP.String()
	if dstIP.String() == "ff02::5" {
		destHint = "ff02::5 (multicast)"
	}
	fmt.Printf("- Destination address: %s\n", destHint)
	
	if srcMAC != "" {
		fmt.Printf("- Source MAC address: %s\n", srcMAC)
	}
	if dstMAC != "" {
		fmt.Printf("- Destination MAC address: %s\n", dstMAC)
	}
	fmt.Printf("- Protocol version: %d", version)
	if version == 3 {
		fmt.Printf(" (IPv6)\n")
	} else {
		fmt.Printf(" (Unknown)\n")
	}
	fmt.Printf("- Area ID: %s\n", areaID)
	
	// If it's a Hello packet (type 1), parse Hello-specific fields
	if msgType == 1 && len(payload) >= 28 {  // OSPFv3 Hello packet minimum size
		// OSPFv3 Hello packet structure (after 16-byte header):
		// Bytes 16-19: Interface ID (4 bytes)
		// Byte 20: Router Priority (1 byte)
		// Bytes 21-23: Options (3 bytes)
		// Bytes 24-25: Hello Interval (2 bytes)
		// Bytes 26-27: Router Dead Interval (2 bytes)
		// Bytes 28-31: Designated Router (4 bytes)
		// Bytes 32-35: Backup Designated Router (4 bytes)
		// Bytes 36+: List of neighbors
		
		if len(payload) >= 36 {
			interfaceID := uint32(payload[16])<<24 | uint32(payload[17])<<16 | 
						   uint32(payload[18])<<8 | uint32(payload[19])
			routerPriority := payload[20]
			options := uint32(payload[21])<<16 | uint32(payload[22])<<8 | uint32(payload[23])
			helloInterval := uint16(payload[24])<<8 | uint16(payload[25])
			routerDeadInterval := uint16(payload[26])<<8 | uint16(payload[27])
			designatedRouter := net.IPv4(payload[28], payload[29], payload[30], payload[31])
			backupDesignatedRouter := net.IPv4(payload[32], payload[33], payload[34], payload[35])
			
			fmt.Printf("- Router priority: %d\n", routerPriority)
			fmt.Printf("- Designated router: %s\n", designatedRouter)
			fmt.Printf("- Backup designated router: %s\n", backupDesignatedRouter)
			
			// Additional info (not requested but useful for debugging)
			_ = interfaceID
			_ = options
			_ = helloInterval
			_ = routerDeadInterval
		}
	}
	
	// Additional fields not displayed per requirements
	_ = packetLength
	_ = routerID
	_ = checksum
	_ = instanceID
	_ = reserved
	
	fmt.Println()
}
