// Code generated by bpf2go; DO NOT EDIT.
//go:build arm

package monitor

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadTraffic returns the embedded CollectionSpec for traffic.
func loadTraffic() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TrafficBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load traffic: %w", err)
	}

	return spec, err
}

// loadTrafficObjects loads traffic and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*trafficObjects
//	*trafficPrograms
//	*trafficMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTrafficObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTraffic()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// trafficSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type trafficSpecs struct {
	trafficProgramSpecs
	trafficMapSpecs
	trafficVariableSpecs
}

// trafficProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type trafficProgramSpecs struct {
	CgroupEgress  *ebpf.ProgramSpec `ebpf:"cgroup_egress"`
	CgroupIngress *ebpf.ProgramSpec `ebpf:"cgroup_ingress"`
}

// trafficMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type trafficMapSpecs struct {
	EgressStats  *ebpf.MapSpec `ebpf:"egress_stats"`
	IngressStats *ebpf.MapSpec `ebpf:"ingress_stats"`
}

// trafficVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type trafficVariableSpecs struct {
}

// trafficObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTrafficObjects or ebpf.CollectionSpec.LoadAndAssign.
type trafficObjects struct {
	trafficPrograms
	trafficMaps
	trafficVariables
}

func (o *trafficObjects) Close() error {
	return _TrafficClose(
		&o.trafficPrograms,
		&o.trafficMaps,
	)
}

// trafficMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTrafficObjects or ebpf.CollectionSpec.LoadAndAssign.
type trafficMaps struct {
	EgressStats  *ebpf.Map `ebpf:"egress_stats"`
	IngressStats *ebpf.Map `ebpf:"ingress_stats"`
}

func (m *trafficMaps) Close() error {
	return _TrafficClose(
		m.EgressStats,
		m.IngressStats,
	)
}

// trafficVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadTrafficObjects or ebpf.CollectionSpec.LoadAndAssign.
type trafficVariables struct {
}

// trafficPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTrafficObjects or ebpf.CollectionSpec.LoadAndAssign.
type trafficPrograms struct {
	CgroupEgress  *ebpf.Program `ebpf:"cgroup_egress"`
	CgroupIngress *ebpf.Program `ebpf:"cgroup_ingress"`
}

func (p *trafficPrograms) Close() error {
	return _TrafficClose(
		p.CgroupEgress,
		p.CgroupIngress,
	)
}

func _TrafficClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed traffic_arm_bpfel.o
var _TrafficBytes []byte
