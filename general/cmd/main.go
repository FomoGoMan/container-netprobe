package main

import (
	"fmt"
	"log"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 traffic ../traffic.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 traffic ../traffic.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm traffic ../traffic.c

func main() {
	// 1. 启动测试容器 (Host/Bridge 模式均可)
	containerID := startContainer()
	defer stopContainer(containerID)

	// 2. 获取容器的 CGroup ID
	cgroupID, err := getCgroupID(containerID)
	if err != nil {
		log.Fatalf("获取 CGroup ID 失败: %v", err)
	}
	fmt.Printf("目标容器 CGroup ID: %d\n", cgroupID)

	// 3. 加载并挂载 eBPF 程序
	objs := loadEBPF()
	defer objs.Close()

	// 4. 持续打印流量统计
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var key, value uint64
		iter := objs.cgroup_stats.Iterate()
		if iter.Next(&key, &value) {
			if key == cgroupID {
				fmt.Printf("容器流量统计: %d bytes\n", value)
			}
		}
	}
}

// 启动测试容器并返回容器 ID
func startContainer() string {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "nginx:alpine",
	}, nil, nil, nil, "")
	if err != nil {
		log.Fatal(err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		log.Fatal(err)
	}
	return resp.ID
}

// 停止容器
func stopContainer(containerID string) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	_ = cli.ContainerStop(ctx, containerID, container.StopOptions{})
	_ = cli.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{})
}

// 获取容器的 CGroup ID (兼容 Host/Bridge 模式)
func getCgroupID(containerID string) (uint64, error) {
	// Docker 容器的 CGroup 路径示例: /sys/fs/cgroup/memory/docker/<container-id>
	cgroupPath := filepath.Join("/sys/fs/cgroup/memory/docker", containerID)

	var stat syscall.Stat_t
	if err := syscall.Stat(cgroupPath, &stat); err != nil {
		return 0, fmt.Errorf("stat %s 失败: %v", cgroupPath, err)
	}
	return stat.Ino, nil // Ino 即为 cgroup_id
}

// 加载 eBPF 程序并返回对象
type bpfObjects struct {
	cgroup_stats *ebpf.Map
	Programs     []*ebpf.Program
}

func loadEBPF() *bpfObjects {
	coll, err := ebpf.LoadCollection("ebpf.o")
	if err != nil {
		log.Fatalf("加载 eBPF 失败: %v", err)
	}

	// 挂载到根 CGroup (监控所有流量)
	rootCgroup := "/sys/fs/cgroup"
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    rootCgroup,
		Program: coll.Programs["cgroup_ingress"],
		Attach:  ebpf.AttachCGroupInetIngress,
	})
	if err != nil {
		log.Fatal(err)
	}

	return &bpfObjects{
		cgroup_stats: coll.Maps["cgroup_stats"],
		Programs:     []*ebpf.Program{l.Program()},
	}
}
