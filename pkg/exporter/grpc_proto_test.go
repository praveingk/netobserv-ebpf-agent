package exporter

import (
	"fmt"
	"net"
	"testing"
	"time"

	test2 "github.com/netobserv/netobserv-ebpf-agent/pkg/test"

	"github.com/mariomac/guara/pkg/test"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/grpc"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const timeout = 2 * time.Second

func TestGRPCProto_ExportFlows_AgentIP(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	coll, err := grpc.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	// Start GRPCProto exporter stage
	exporter, err := StartGRPCProto(fmt.Sprintf("127.0.0.1:%d", port), 1000)
	require.NoError(t, err)

	// Send some flows to the input of the exporter stage
	flows := make(chan []*flow.Record, 10)
	flows <- []*flow.Record{
		{AgentIP: net.ParseIP("10.9.8.7")},
	}
	flows <- []*flow.Record{
		{RawRecord: flow.RawRecord{Id: ebpf.BpfFlowId{EthProtocol: flow.IPv6Type}},
			AgentIP: net.ParseIP("8888::1111")},
	}
	go exporter.ExportFlows(flows)

	rs := test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 1)
	r := rs.Entries[0]
	assert.EqualValues(t, 0x0a090807, r.GetAgentIp().GetIpv4())

	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 1)
	r = rs.Entries[0]
	assert.EqualValues(t, net.ParseIP("8888::1111"), r.GetAgentIp().GetIpv6())

	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		//ok!
	}
}

func TestGRPCProto_SplitLargeMessages(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	coll, err := grpc.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	const msgMaxLen = 10000
	// Start GRPCProto exporter stage
	exporter, err := StartGRPCProto(fmt.Sprintf("127.0.0.1:%d", port), msgMaxLen)
	require.NoError(t, err)

	// Send a message much longer than the limit length
	flows := make(chan []*flow.Record, 10)
	var input []*flow.Record
	for i := 0; i < 25000; i++ {
		input = append(input, &flow.Record{RawRecord: flow.RawRecord{Id: ebpf.BpfFlowId{
			EthProtocol: flow.IPv6Type,
		}}, AgentIP: net.ParseIP("1111::1111"), Interface: "12345678"})
	}
	flows <- input
	go exporter.ExportFlows(flows)

	// expect that the submitted message is split in chunks no longer than msgMaxLen
	rs := test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, msgMaxLen)
	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, msgMaxLen)
	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 5000)

	// after all the operation, no more flows are sent
	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		//ok!
	}
}
