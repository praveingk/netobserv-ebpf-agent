package exporter

import (

	//	"bytes"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

/*type Packets struct {
	rawcontents *[]byte
}*/

var (
	iface  = "ens3f1"
	buffer = int32(1600)
	filter = "tcp and port 21"
)

func deviceExists(name string) bool {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}
	for _, device := range devices {
		if device.Name == name {
			return true
		}
	}
	return false
}

func StartPCAPRecieve(error) {
	if !deviceExists(iface) {
		log.Fatal("Unable to access interface ", iface)
	}

	handler, err := pcap.OpenLive(iface, buffer, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		app := packet.ApplicationLayer()
		if app != nil {
			payload := app.Payload()
			//dst := packet.NetworkLayer().NetworkFlow().Dst()
			fmt.Printf(filter, "->", payload)
		}
	}
}
