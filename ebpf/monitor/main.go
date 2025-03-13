package monitor

// import (
// 	"fmt"
// 	"log"
// 	"path/filepath"
// 	"syscall"
// 	"time"

// 	"github.com/docker/docker/api/types"
// 	"github.com/docker/docker/api/types/container"
// 	"github.com/docker/docker/client"
// 	"golang.org/x/net/context"
// )

// func main() {
// 	// 1. 启动测试容器 (Host/Bridge 模式均可)
// 	containerID := startContainer()
// 	defer stopContainer(containerID)

// 	// 2. 获取容器的 CGroup ID
// 	cgroupID, err := getCgroupID(containerID)
// 	if err != nil {
// 		log.Fatalf("获取 CGroup ID 失败: %v", err)
// 	}
// 	fmt.Printf("目标容器 CGroup ID: %d\n", cgroupID)

// 	// 3. 加载并挂载 eBPF 程序
// 	collector, err := NewCollector()
// 	if err != nil {
// 		log.Fatalf("error new collector %v", err)
// 		return
// 	}

// 	// 4. 持续打印流量统计
// 	ticker := time.NewTicker(2 * time.Second)
// 	defer ticker.Stop()

// 	for range ticker.C {
// 		flowData := collector.Collect()
// 		printStats(flowData)
// 	}
// }

// // 启动测试容器并返回容器 ID
// func startContainer() string {
// 	cli, err := client.NewClientWithOpts(client.FromEnv)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	ctx := context.Background()
// 	resp, err := cli.ContainerCreate(ctx, &container.Config{
// 		Image: "nginx:alpine",
// 	}, nil, nil, nil, "")
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
// 		log.Fatal(err)
// 	}
// 	return resp.ID
// }

// // 停止容器
// func stopContainer(containerID string) {
// 	cli, err := client.NewClientWithOpts(client.FromEnv)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	ctx := context.Background()
// 	_ = cli.ContainerStop(ctx, containerID, container.StopOptions{})
// 	_ = cli.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{})
// }

// // 获取容器的 CGroup ID (兼容 Host/Bridge 模式)
// func getCgroupID(containerID string) (uint64, error) {
// 	// Docker 容器的 CGroup 路径示例: /sys/fs/cgroup/memory/docker/<container-id>
// 	cgroupPath := filepath.Join("/sys/fs/cgroup/memory/docker", containerID)

// 	var stat syscall.Stat_t
// 	if err := syscall.Stat(cgroupPath, &stat); err != nil {
// 		return 0, fmt.Errorf("stat %s 失败: %v", cgroupPath, err)
// 	}
// 	return stat.Ino, nil // Ino 即为 cgroup_id
// }

// func printStats(flowMap types.FlowCgroup) {
// 	fmt.Println("\n=== Network Traffic Statistics ===")
// 	for cGroupId, flows := range flowMap {
// 		fmt.Printf("CgroupId: %v\n", cGroupId)
// 		fmt.Printf("  All InCome :   %10d bytes\n", flows)
// 	}
// 	fmt.Println("================================")
// }
