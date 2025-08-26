package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"cisGO-hash/protocols"
)

var (
	capture string
	ospf    bool
	eigrp   bool
	hsrp    bool
	vrrp    bool
	glbp    bool
)

func main() {
	root := &cobra.Command{
		Use:   "cisGO-hash",
		Short: "A tool for analyzing some Cisco protocol packets",
	}
	
	root.PersistentFlags().StringVar(&capture, "capture", "", "Path to the capture file (pcap/pcapng/cap)")
	root.PersistentFlags().BoolVar(&ospf, "ospf", false, "Analyze OSPF packets")
	root.PersistentFlags().BoolVar(&eigrp, "eigrp", false, "Analyze EIGRP packets")
	root.PersistentFlags().BoolVar(&hsrp, "hsrp", false, "Analyze HSRP packets")
	root.PersistentFlags().BoolVar(&vrrp, "vrrp", false, "Analyze VRRP packets")
	root.PersistentFlags().BoolVar(&glbp, "glbp", false, "Analyze GLBP packets")
	
	root.Run = func(_ *cobra.Command, _ []string) {
		if capture == "" {
			fmt.Println("Error: --capture flag is required")
			os.Exit(1)
		}
		
		if !ospf && !eigrp && !hsrp && !vrrp && !glbp {
			fmt.Println("Error: Please specify either --ospf, --eigrp, --hsrp, --vrrp or --glbp flag")
			os.Exit(1)
		}
		
		protocolCount := 0
		if ospf { protocolCount++ }
		if eigrp { protocolCount++ }
		if hsrp { protocolCount++ }
		if vrrp { protocolCount++ }
		if glbp { protocolCount++ }
		
		if protocolCount > 1 {
			fmt.Println("Error: Please specify only one protocol flag at a time")
			os.Exit(1)
		}
		
		if ospf {
			protocols.ExtractOSPFFromPcapng(capture)
		}
		
		if eigrp {
			protocols.ExtractEIGRPFromPcap(capture)
		}
		
		if hsrp {
			protocols.ExtractHSRPFromPcap(capture)
		}
		
		if vrrp {
			protocols.ExtractVRRPFromPcap(capture)
		}
		
		if glbp {
			protocols.ExtractGLBPFromPcap(capture)
		}
	}
	
	root.Execute()
}

// isFileExtension checks if filename has the specified extension
func isFileExtension(filename, ext string) bool {
	if len(filename) < len(ext) {
		return false
	}
	return filename[len(filename)-len(ext):] == ext
}
