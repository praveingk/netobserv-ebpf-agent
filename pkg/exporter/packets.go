package exporter

import (
	"github.com/sirupsen/logrus"
)

type Packets struct {
}

var plog = logrus.WithField("component", "flow/Packets")

// NewAccounter creates a new Accounter.
// The cache has no limit and it's assumed that eviction is done by the caller.
func NewPacketsBuffer() *Packets {
	return &Packets{}
}

// Account runs in a new goroutine. It reads all the records from the input channel
// and accumulate their metrics internally. Once the metrics have reached their max size
// or the eviction times out, it evicts all the accumulated flows by the returned channel.
func (c *Packets) Format(in <-chan *[]byte) {
	plog.Infof("New Packet IN : %+v", in)
}
