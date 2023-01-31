package flow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf/perf"
	"github.com/netobserv/gopipes/pkg/node"
	"github.com/sirupsen/logrus"
)

var pblog = logrus.WithField("component", "flow.PerfTracer")

// RingBufTracer receives single-packet flows via ringbuffer (usually, these that couldn't be
// added in the eBPF kernel space due to the map being full or busy) and submits them to the
// userspace Aggregator map
type PerfTracer struct {
	perfArray perfReader
	stats     stats
}

type perfReader interface {
	ReadPerf() (perf.Record, error)
}

func NewPerfTracer(
	reader perfReader, logTimeout time.Duration,
) *PerfTracer {
	return &PerfTracer{
		perfArray: reader,
		stats:     stats{loggingTimeout: logTimeout},
	}
}

func (m *PerfTracer) TraceLoop(ctx context.Context) node.StartFunc[*[]byte] {
	return func(out chan<- *[]byte) {
		debugging := logrus.IsLevelEnabled(logrus.DebugLevel)
		for {
			select {
			case <-ctx.Done():
				pblog.Debug("exiting trace loop due to context cancellation")
				return
			default:
				if err := m.listenAndForwardPerf(debugging, out); err != nil {
					if errors.Is(err, perf.ErrClosed) {
						pblog.Debug("Received signal, exiting..")
						return
					}
					pblog.WithError(err).Warn("ignoring flow event")
					continue
				}
			}
		}
	}
}

func (m *PerfTracer) listenAndForwardPerf(debugging bool, forwardCh chan<- *[]byte) error {
	event, err := m.perfArray.ReadPerf()
	if err != nil {
		return fmt.Errorf("reading from perf event array: %w", err)
	}
	// Parses the ringbuf event entry into an Event structure.
	packet, err := RawReadFrom(bytes.NewBuffer(event.RawSample))
	if err != nil {
		return fmt.Errorf("parsing data received from the perf event array: %w %+v", err, *packet)
	}
	if debugging {
		m.stats.logRingBufferFlows(false)
	}

	pblog.Infof("Read packet from perf array :%+v", *packet)
	// Will need to send it to accounter anyway to account regardless of complete/ongoing flow
	forwardCh <- packet

	return nil
}
