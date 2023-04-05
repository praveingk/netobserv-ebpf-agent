package exporter

import (
	"net"
	//"time"
	"fmt"

	//	"github.com/google/gopacket"
	//	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

const (
	HOST = "localhost"
	PORT = "8080"
	TYPE = "tcp"
)

type Packets struct {
	//rawcontents *[]byte
	//a int
	//b int
}

type PCAPStream struct {
	hostPort             string
	clientConn           net.Conn
	maxPacketsPerMessage int
}

var plog = logrus.WithField("component", "flow/Packets")

//var cc []Packets

// NewAccounter creates a new Accounter.
// The cache has no limit and it's assumed that eviction is done by the caller.
func NewPacketsBuffer() *Packets {
	return &Packets{}
}

// Account runs in a new goroutine. It reads all the records from the input channel
// and accumulate their metrics internally. Once the metrics have reached their max size
// or the eviction times out, it evicts all the accumulated flows by the returned channel.
func (c *Packets) Format(in <-chan *[]byte) {
	/*for packet := range cc{
		fmt.Println(packet.rawcontents)
	}*/

	plog.Infof("New Packet IN : %+v", in)
}

//func StartPCAPSend(in <-chan *[]byte) (*PacketStream , error){
func StartPCAPSend(hostPort string, maxPacketsPerMessage int) (*PCAPStream, error) {

	clientConn, err := net.Dial("tcp", hostPort)
	if err != nil {
		return nil, err
	}
	//go sendPCAPPackets(conn, in)
	return &PCAPStream{
		hostPort:             hostPort,
		clientConn:           clientConn,
		maxPacketsPerMessage: maxPacketsPerMessage,
	}, nil

}

func (p *PCAPStream) ExportFlows(in <-chan []*byte) {

	log := plog.WithField("collector", p.hostPort)

	//Create handler by opening PCAP stream
	for packet := range in {
		fmt.Println(packet)
		//Send each on connection conn
		//_, err := p.clientConn.Write([]byte(packet))
		_, err := p.clientConn.Write([]byte("HELLO WORLD"))
		if err != nil {
			log.Fatal(err)
		}
	}

}
