package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gavv/monotime"
	"github.com/netobserv/gopipes/pkg/node"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/exporter"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
	"github.com/sirupsen/logrus"
)

var alog = logrus.WithField("component", "agent.Flows")

// Status of the agent service. Helps on the health report as well as making some asynchronous
// tests waiting for the agent to accept flows.
type Status int

var pano bool

const (
	StatusNotStarted Status = iota
	StatusStarting
	StatusStarted
	StatusStopping
	StatusStopped
)

func (s Status) String() string {
	switch s {
	case StatusNotStarted:
		return "StatusNotStarted"
	case StatusStarting:
		return "StatusStarting"
	case StatusStarted:
		return "StatusStarted"
	case StatusStopping:
		return "StatusStopping"
	case StatusStopped:
		return "StatusStopped"
	default:
		return "invalid"
	}
}

// Flows reporting agent
type Flows struct {
	cfg *Config

	// input data providers
	interfaces ifaces.Informer
	filter     interfaceFilter
	ebpf       ebpfFlowFetcher

	// processing nodes to be wired in the buildAndStartPipeline method

	mapTracer    *flow.MapTracer
	rbTracer     *flow.RingBufTracer
	perfTracer   *flow.PerfTracer
	accounter    *flow.Accounter
	packetbuffer *flow.Packets
	exporter     node.TerminalFunc[[]*flow.Record]

	// elements used to decorate flows with extra information
	interfaceNamer flow.InterfaceNamer
	agentIP        net.IP

	status Status
}

// ebpfFlowFetcher abstracts the interface of ebpf.FlowFetcher to allow dependency injection in tests
type ebpfFlowFetcher interface {
	io.Closer
	Register(iface ifaces.Interface) error

	LookupAndDeleteMap() map[flow.RecordKey][]flow.RecordMetrics
	ReadRingBuf() (ringbuf.Record, error)
	ReadPerf() (perf.Record, error)
}

// FlowsAgent instantiates a new agent, given a configuration.
func FlowsAgent(cfg *Config) (*Flows, error) {
	alog.Info("initializing Flows agent")

	// configure informer for new interfaces
	var informer ifaces.Informer
	switch cfg.ListenInterfaces {
	case ListenPoll:
		alog.WithField("period", cfg.ListenPollPeriod).
			Debug("listening for new interfaces: use polling")
		informer = ifaces.NewPoller(cfg.ListenPollPeriod, cfg.BuffersLength)
	case ListenWatch:
		alog.Debug("listening for new interfaces: use watching")
		informer = ifaces.NewWatcher(cfg.BuffersLength)
	default:
		alog.WithField("providedValue", cfg.ListenInterfaces).
			Warn("wrong interface listen method. Using file watcher as default")
		informer = ifaces.NewWatcher(cfg.BuffersLength)
	}

	alog.Debug("acquiring Agent IP")
	agentIP, err := fetchAgentIP(cfg)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}
	alog.Debug("agent IP: " + agentIP.String())

	// configure selected exporter
	exportFunc, err := buildFlowExporter(cfg)
	if err != nil {
		return nil, err
	}

	ingress, egress := flowDirections(cfg)

	panofilters := cfg.PanoFilters
	//Log stmts are temporary
	alog.Info("==========PANO===========")
	alog.Info(string(panofilters))

	debug := false
	if cfg.LogLevel == logrus.TraceLevel.String() || cfg.LogLevel == logrus.DebugLevel.String() {
		debug = true
	}

	fetcher, err := ebpf.NewFlowFetcher(debug, cfg.Sampling, cfg.CacheMaxFlows, ingress, egress)
	if err != nil {
		return nil, err
	}

	return flowsAgent(cfg, informer, fetcher, exportFunc, agentIP)
}

// flowsAgent is a private constructor with injectable dependencies, usable for tests
func flowsAgent(cfg *Config,
	informer ifaces.Informer,
	fetcher ebpfFlowFetcher,
	exporter node.TerminalFunc[[]*flow.Record],
	agentIP net.IP,
) (*Flows, error) {
	// configure allow/deny interfaces filter
	filter, err := initInterfaceFilter(cfg.Interfaces, cfg.ExcludeInterfaces)
	if err != nil {
		return nil, fmt.Errorf("configuring interface filters: %w", err)
	}

	registerer := ifaces.NewRegisterer(informer, cfg.BuffersLength)

	interfaceNamer := func(ifIndex int) string {
		iface, ok := registerer.IfaceNameForIndex(ifIndex)
		if !ok {
			return "unknown"
		}
		return iface
	}

	mapTracer := flow.NewMapTracer(fetcher, cfg.CacheActiveTimeout)
	rbTracer := flow.NewRingBufTracer(fetcher, mapTracer, cfg.CacheActiveTimeout)
	perfTracer := flow.NewPerfTracer(fetcher, cfg.CacheActiveTimeout)

	accounter := flow.NewAccounter(
		cfg.CacheMaxFlows, cfg.CacheActiveTimeout, time.Now, monotime.Now)
	packetbuffer := flow.NewPacketsBuffer()
	return &Flows{

		ebpf:           fetcher,
		exporter:       exporter,
		interfaces:     registerer,
		filter:         filter,
		cfg:            cfg,
		mapTracer:      mapTracer,
		rbTracer:       rbTracer,
		perfTracer:     perfTracer,
		accounter:      accounter,
		packetbuffer:   packetbuffer,
		agentIP:        agentIP,
		interfaceNamer: interfaceNamer,
	}, nil
}

func flowDirections(cfg *Config) (ingress, egress bool) {
	switch cfg.Direction {
	case DirectionIngress:
		return true, false
	case DirectionEgress:
		return false, true
	case DirectionBoth:
		return true, true
	default:
		alog.Warnf("unknown DIRECTION %q. Tracing both ingress and egress traffic", cfg.Direction)
		return true, true
	}
}

func buildFlowExporter(cfg *Config) (node.TerminalFunc[[]*flow.Record], error) {
	switch cfg.Export {
	case "grpc":
		if cfg.TargetHost == "" || cfg.TargetPort == 0 {
			return nil, fmt.Errorf("missing target host or port: %s:%d",
				cfg.TargetHost, cfg.TargetPort)
		}
		target := fmt.Sprintf("%s:%d", cfg.TargetHost, cfg.TargetPort)
		grpcExporter, err := exporter.StartGRPCProto(target, cfg.GRPCMessageMaxFlows)
		if err != nil {
			return nil, err
		}
		return grpcExporter.ExportFlows, nil
	case "kafka":
		if len(cfg.KafkaBrokers) == 0 {
			return nil, errors.New("at least one Kafka broker is needed")
		}
		var compression compress.Compression
		if err := compression.UnmarshalText([]byte(cfg.KafkaCompression)); err != nil {
			return nil, fmt.Errorf("wrong Kafka compression value %s. Admitted values are "+
				"none, gzip, snappy, lz4, zstd: %w", cfg.KafkaCompression, err)
		}
		transport := kafkago.Transport{}
		if cfg.KafkaEnableTLS {
			tlsConfig, err := buildTLSConfig(cfg)
			if err != nil {
				return nil, err
			}
			transport.TLS = tlsConfig
		}
		return (&exporter.KafkaProto{
			Writer: &kafkago.Writer{
				Addr:      kafkago.TCP(cfg.KafkaBrokers...),
				Topic:     cfg.KafkaTopic,
				BatchSize: cfg.KafkaBatchMessages,
				// Assigning KafkaBatchSize to BatchBytes instead of BatchSize might be confusing here.
				// The reason is that the "standard" Kafka name for this variable is "batch.size",
				// which specifies the size of messages in terms of bytes, and not in terms of entries.
				// We have decided to hide this library implementation detail and expose to the
				// customer the common, standard name and meaning for batch.size
				BatchBytes: int64(cfg.KafkaBatchSize),
				// Segmentio's Kafka-go does not behave as standard Kafka library, and would
				// throttle any Write invocation until reaching the timeout.
				// Since we invoke write once each CacheActiveTimeout, we can safely disable this
				// timeout throttling
				// https://github.com/netobserv/flowlogs-pipeline/pull/233#discussion_r897830057
				BatchTimeout: time.Nanosecond,
				Async:        cfg.KafkaAsync,
				Compression:  compression,
				Transport:    &transport,
				Balancer:     &kafkago.RoundRobin{},
			},
		}).ExportFlows, nil
	case "ipfix+udp":
		if cfg.TargetHost == "" || cfg.TargetPort == 0 {
			return nil, fmt.Errorf("missing target host or port: %s:%d",
				cfg.TargetHost, cfg.TargetPort)
		}
		target := fmt.Sprintf("%s:%d", cfg.TargetHost, cfg.TargetPort)

		ipfix, err := exporter.StartIPFIXExporter(target, "udp")
		if err != nil {
			return nil, err
		}
		return ipfix.ExportFlows, nil
	case "ipfix+tcp":
		if cfg.TargetHost == "" || cfg.TargetPort == 0 {
			return nil, fmt.Errorf("missing target host or port: %s:%d",
				cfg.TargetHost, cfg.TargetPort)
		}
		target := fmt.Sprintf("%s:%d", cfg.TargetHost, cfg.TargetPort)

		ipfix, err := exporter.StartIPFIXExporter(target, "tcp")
		if err != nil {
			return nil, err
		}
		return ipfix.ExportFlows, nil
	//TODO: Add one case here for pcap export
	default:
		return nil, fmt.Errorf("wrong export type %s. Admitted values are grpc, kafka", cfg.Export)
	}

}

// Run a Flows agent. The function will keep running in the same thread
// until the passed context is canceled
func (f *Flows) Run(ctx context.Context) error {
	f.status = StatusStarting
	alog.Info("starting Flows agent")
	graph, err := f.buildAndStartPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	f.status = StatusStarted
	alog.Info("Flows agent successfully started")
	<-ctx.Done()

	f.status = StatusStopping
	alog.Info("stopping Flows agent")
	if err := f.ebpf.Close(); err != nil {
		alog.WithError(err).Warn("eBPF resources not correctly closed")
	}

	alog.Debug("waiting for all nodes to finish their pending work")
	<-graph.Done()

	f.status = StatusStopped
	alog.Info("Flows agent stopped")
	return nil
}

func (f *Flows) Status() Status {
	return f.status
}

// interfacesManager uses an informer to check new/deleted network interfaces. For each running
// interface, it registers a flow ebpfFetcher that will forward new flows to the returned channel
// TODO: consider move this method and "onInterfaceAdded" to another type
func (f *Flows) interfacesManager(ctx context.Context) error {
	slog := alog.WithField("function", "interfacesManager")

	slog.Debug("subscribing for network interface events")
	ifaceEvents, err := f.interfaces.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("instantiating interfaces' informer: %w", err)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				slog.Debug("stopping interfaces' listener")
				return
			case event := <-ifaceEvents:
				slog.WithField("event", event).Debug("received event")
				switch event.Type {
				case ifaces.EventAdded:
					f.onInterfaceAdded(event.Interface)
				case ifaces.EventDeleted:
					// qdiscs, ingress and egress filters are automatically deleted so we don't need to
					// specifically detach them from the ebpfFetcher
				default:
					slog.WithField("event", event).Warn("unknown event type")
				}
			}
		}
	}()

	return nil
}

// buildAndStartPipeline creates the ETL flow processing graph.
// For a more visual view, check the docs/architecture.md document.
func (f *Flows) buildAndStartPipeline(ctx context.Context) (*node.Terminal[[]*flow.Record], error) {

	alog.Debug("registering interfaces' listener in background")
	err := f.interfacesManager(ctx)
	if err != nil {
		return nil, err
	}

	alog.Debug("connecting flows' processing graph")
	alog.Info("connecting flows' processing graph")

	perfTracer := node.AsStart(f.perfTracer.TraceLoop(ctx))
	mapTracer := node.AsStart(f.mapTracer.TraceLoop(ctx))
	rbTracer := node.AsStart(f.rbTracer.TraceLoop(ctx))

	accounter := node.AsMiddle(f.accounter.Account,
		node.ChannelBufferLen(f.cfg.BuffersLength))

	limiter := node.AsMiddle((&flow.CapacityLimiter{}).Limit,
		node.ChannelBufferLen(f.cfg.BuffersLength))

	decorator := node.AsMiddle(flow.Decorate(f.agentIP, f.interfaceNamer),
		node.ChannelBufferLen(f.cfg.BuffersLength))

	ebl := f.cfg.ExporterBufferLength
	if ebl == 0 {
		ebl = f.cfg.BuffersLength
	}
	packetbuffer := node.AsTerminal(f.packetbuffer.Format,
		node.ChannelBufferLen(f.cfg.BuffersLength))

	export := node.AsTerminal(f.exporter,
		node.ChannelBufferLen(ebl))

	pano = f.cfg.EnablePano

	//If pano var is set: Only send to PerfTracer
	if pano {
		perfTracer.SendsTo(accounter)
	} else {
		rbTracer.SendsTo(accounter)
	}

	perfTracer.SendsTo(packetbuffer)
	if f.cfg.Deduper == DeduperFirstCome {
		deduper := node.AsMiddle(flow.Dedupe(f.cfg.DeduperFCExpiry, f.cfg.DeduperJustMark), node.ChannelBufferLen(f.cfg.BuffersLength))
		if !pano {
			mapTracer.SendsTo(deduper)
		}
		accounter.SendsTo(deduper)
		deduper.SendsTo(limiter)
	} else {
		if pano {
			accounter.SendsTo(limiter)
		} else {
			mapTracer.SendsTo(limiter)
			accounter.SendsTo(limiter)
		}
	}
	limiter.SendsTo(decorator)
	decorator.SendsTo(export)

	alog.Debug("starting graph")
	if pano {
		perfTracer.Start()
	} else {
		mapTracer.Start()
		rbTracer.Start()
	}
	return export, nil
}

func (f *Flows) onInterfaceAdded(iface ifaces.Interface) {
	// ignore interfaces that do not match the user configuration acceptance/exclusion lists
	if !f.filter.Allowed(iface.Name) {
		alog.WithField("interface", iface).
			Debug("interface does not match the allow/exclusion filters. Ignoring")
		return
	}
	alog.WithField("interface", iface).Info("interface detected. Registering flow ebpfFetcher")
	if err := f.ebpf.Register(iface); err != nil {
		alog.WithField("interface", iface).WithError(err).
			Warn("can't register flow ebpfFetcher. Ignoring")
		return
	}
}
