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
	fmt.Printf("Starting to analyze file: %s\n", filename)
	
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

	fmt.Println("File opened successfully, reading packets...")
	
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
		
		// Look for IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		
		ip := ipLayer.(*layers.IPv4)
		
		// Check if protocol is 89 (OSPF)
		if ip.Protocol == layers.IPProtocolOSPF {
			ospfPackets++
			fmt.Printf("\n=== OSPF Packet #%d ===\n", ospfPackets)
			
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
				continue
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
				// Null authentication
				fmt.Printf("- Authentication data length: 0\n")
				fmt.Printf("- Authentication data: (none)\n")
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
				
				// Write to file
				_, err := hashFile.WriteString(netmd5Hash + "\n")
				if err != nil {
					fmt.Printf("ERROR: Cannot write to ospf-hashes.txt: %v\n", err)
				} else {
					hashesWritten++
				}
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
