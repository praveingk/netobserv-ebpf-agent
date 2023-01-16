package ebpf

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../bpf/flows.c -- -I../../bpf/headers

const (
	qdiscType = "clsact"
	// constants defined in flows.c as "volatile const"
	constSampling      = "sampling"
	constTraceMessages = "trace_messages"
	aggregatedFlowsMap = "aggregated_flows"
)

var log = logrus.WithField("component", "ebpf.FlowFetcher")

// FlowFetcher reads and forwards the Flows from the Traffic Control hooks in the eBPF kernel space.
// It provides access both to flows that are aggregated in the kernel space (via PerfCPU hashmap)
// and to flows that are forwarded by the kernel via ringbuffer because could not be aggregated
// in the map
type FlowFetcher struct {
	objects        *bpfObjects
	qdiscs         map[ifaces.Interface]*netlink.GenericQdisc
	egressFilters  map[ifaces.Interface]*netlink.BpfFilter
	ingressFilters map[ifaces.Interface]*netlink.BpfFilter
	ingressPano    map[ifaces.Interface]*netlink.BpfFilter
	ringbufReader  *ringbuf.Reader
	perfReader     *perf.Reader
	cacheMaxSize   int
	enableIngress  bool
	enableEgress   bool
}

func NewFlowFetcher(
	traceMessages bool,
	sampling, cacheMaxSize int,
	ingress, egress bool,
) (*FlowFetcher, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).
			Warn("can't remove mem lock. The agent could not be able to start eBPF programs")
	}

	objects := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	// Resize aggregated flows map according to user-provided configuration
	spec.Maps[aggregatedFlowsMap].MaxEntries = uint32(cacheMaxSize)

	traceMsgs := 0
	if traceMessages {
		traceMsgs = 1
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		constSampling:      uint32(sampling),
		constTraceMessages: uint8(traceMsgs),
	}); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants definition: %w", err)
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	// read events from igress+egress ringbuffer
	flows, err := ringbuf.NewReader(objects.DirectFlows)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}

	// read events from igress+egress perf array
	packets, err := perf.NewReader(objects.PacketPayloads, 10000)
	if err != nil {
		return nil, fmt.Errorf("accessing to perf: %w", err)
	}
	return &FlowFetcher{
		objects:        &objects,
		ringbufReader:  flows,
		perfReader:     packets,
		egressFilters:  map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters: map[ifaces.Interface]*netlink.BpfFilter{},
		ingressPano:    map[ifaces.Interface]*netlink.BpfFilter{},
		qdiscs:         map[ifaces.Interface]*netlink.GenericQdisc{},
		cacheMaxSize:   cacheMaxSize,
		enableIngress:  ingress,
		enableEgress:   egress,
	}, nil
}

// Register and links the eBPF fetcher into the system. The program should invoke Unregister
// before exiting.
func (m *FlowFetcher) Register(iface ifaces.Interface) error {
	ilog := log.WithField("iface", iface)
	// Load pre-compiled programs and maps into the kernel, and rewrites the configuration
	ipvlan, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return fmt.Errorf("failed to lookup ipvlan device %d (%s): %w", iface.Index, iface.Name, err)
	}
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  qdiscType,
	}
	if err := netlink.QdiscDel(qdisc); err == nil {
		ilog.Warn("qdisc clsact already existed. Deleted it")
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("qdisc clsact already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create clsact qdisc on %d (%s): %T %w", iface.Index, iface.Name, err, err)
		}
	}
	m.qdiscs[iface] = qdisc

	if err := m.registerEgress(iface, ipvlan); err != nil {
		return err
	}

	if err := m.registerIngress(iface, ipvlan); err != nil {
		return err
	}

	return nil
}

func (m *FlowFetcher) registerEgress(iface ifaces.Interface, ipvlan netlink.Link) error {
	ilog := log.WithField("iface", iface)
	if !m.enableEgress {
		ilog.Debug("ignoring egress traffic, according to user configuration")
		return nil
	}
	// Fetch events on egress
	egressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	egressFilter := &netlink.BpfFilter{
		FilterAttrs:  egressAttrs,
		Fd:           m.objects.EgressFlowParse.FD(),
		Name:         "tc/egress_flow_parse",
		DirectAction: true,
	}
	if err := netlink.FilterDel(egressFilter); err == nil {
		ilog.Warn("egress filter already existed. Deleted it")
	}
	if err := netlink.FilterAdd(egressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("egress filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create egress filter: %w", err)
		}
	}
	m.egressFilters[iface] = egressFilter
	return nil
}

func (m *FlowFetcher) registerIngress(iface ifaces.Interface, ipvlan netlink.Link) error {
	ilog := log.WithField("iface", iface)
	if !m.enableIngress {
		ilog.Debug("ignoring ingress traffic, according to user configuration")
		return nil
	}
	// Fetch events on ingress
	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           m.objects.IngressFlowParse.FD(),
		Name:         "tc/ingress_flow_parse",
		DirectAction: true,
	}
	if err := netlink.FilterDel(ingressFilter); err == nil {
		ilog.Warn("ingress filter already existed. Deleted it")
	}
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("ingress filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create ingress filter: %w", err)
		}
	}
	m.ingressFilters[iface] = ingressFilter

	panoFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           m.objects.IngressPanoParse.FD(),
		Name:         "tc/ingress_pano_parse",
		DirectAction: true,
	}
	if err := netlink.FilterDel(panoFilter); err == nil {
		ilog.Warn("pano filter already existed. Deleted it")
	}
	if err := netlink.FilterAdd(panoFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			ilog.WithError(err).Warn("pano filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create pano filter: %w", err)
		}
	}
	m.ingressPano[iface] = panoFilter
	return nil
}

// Close the eBPF fetcher from the system.
// We don't need an "Close(iface)" method because the filters and qdiscs
// are automatically removed when the interface is down
func (m *FlowFetcher) Close() error {
	log.Debug("unregistering eBPF objects")

	var errs []error
	// m.ringbufReader.Read is a blocking operation, so we need to close the ring buffer
	// from another goroutine to avoid the system not being able to exit if there
	// isn't traffic in a given interface
	if m.ringbufReader != nil {
		if err := m.ringbufReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.objects != nil {
		if err := m.objects.EgressFlowParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.IngressFlowParse.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.AggregatedFlows.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := m.objects.DirectFlows.Close(); err != nil {
			errs = append(errs, err)
		}
		m.objects = nil
	}
	for iface, ef := range m.egressFilters {
		log.WithField("interface", iface).Debug("deleting egress filter")
		if err := netlink.FilterDel(ef); err != nil {
			errs = append(errs, fmt.Errorf("deleting egress filter: %w", err))
		}
	}
	m.egressFilters = map[ifaces.Interface]*netlink.BpfFilter{}
	for iface, igf := range m.ingressFilters {
		log.WithField("interface", iface).Debug("deleting ingress filter")
		if err := netlink.FilterDel(igf); err != nil {
			errs = append(errs, fmt.Errorf("deleting ingress filter: %w", err))
		}
	}
	for iface, igf := range m.ingressPano {
		log.WithField("interface", iface).Debug("deleting ingress pano")
		if err := netlink.FilterDel(igf); err != nil {
			errs = append(errs, fmt.Errorf("deleting ingress pano: %w", err))
		}
	}
	m.ingressFilters = map[ifaces.Interface]*netlink.BpfFilter{}
	for iface, qd := range m.qdiscs {
		log.WithField("interface", iface).Debug("deleting Qdisc")
		if err := netlink.QdiscDel(qd); err != nil {
			errs = append(errs, fmt.Errorf("deleting qdisc: %w", err))
		}
	}
	m.qdiscs = map[ifaces.Interface]*netlink.GenericQdisc{}
	if len(errs) == 0 {
		return nil
	}

	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
}

func (m *FlowFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return m.ringbufReader.Read()
}

func (m *FlowFetcher) ReadPerf() (perf.Record, error) {
	return m.perfReader.Read()
}

// LookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
// It returns a map where the key
// For synchronization purposes, we get/delete a whole snapshot of the flows map.
// This way we avoid missing packets that could be updated on the
// ebpf side while we process/aggregate them here
// Changing this method invocation by BatchLookupAndDelete could improve performance
// TODO: detect whether BatchLookupAndDelete is supported (Kernel>=5.6) and use it selectively
// Supported Lookup/Delete operations by kernel: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
// Race conditions here causes that some flows are lost in high-load scenarios
func (m *FlowFetcher) LookupAndDeleteMap() map[flow.RecordKey][]flow.RecordMetrics {
	flowMap := m.objects.AggregatedFlows

	iterator := flowMap.Iterate()
	flows := make(map[flow.RecordKey][]flow.RecordMetrics, m.cacheMaxSize)

	id := flow.RecordKey{}
	var metrics []flow.RecordMetrics
	// Changing Iterate+Delete by LookupAndDelete would prevent some possible race conditions
	// TODO: detect whether LookupAndDelete is supported (Kernel>=4.20) and use it selectively
	for iterator.Next(&id, &metrics) {
		if err := flowMap.Delete(id); err != nil {
			log.WithError(err).WithField("flowId", id).
				Warnf("couldn't delete flow entry")
		}
		// We observed that eBFP PerCPU map might insert multiple times the same key in the map
		// (probably due to race conditions) so we need to re-join metrics again at userspace
		// TODO: instrument how many times the keys are is repeated in the same eviction
		flows[id] = append(flows[id], metrics...)
	}
	return flows
}
