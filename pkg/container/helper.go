package helper

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"
)

// 启动测试容器并返回容器 ID
func StartContainer() string {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "example",
	}, nil, nil, nil, "")
	if err != nil {
		log.Fatal(err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		log.Fatal(err)
	}
	return resp.ID
}

// 停止容器
func StopContainer(containerID string) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	_ = cli.ContainerStop(ctx, containerID, container.StopOptions{})
	_ = cli.ContainerRemove(ctx, containerID, container.RemoveOptions{})
}

// GetContainerInfo 获取容器的 CGroup 路径
func GetContainerInfo(containerID string) (cgroupPath string, err error) {
	// 创建 Docker 客户端，自动适配 API 版本
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", fmt.Errorf("failed to create Docker client: %v", err)
	}

	// 获取容器详细信息
	info, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %s: %v", containerID, err)
	}

	// 获取 CGroup 路径
	cgroupPath = getCGroupPath(info)
	if cgroupPath == "" {
		return "", fmt.Errorf("failed to determine CGroup path for container %s", containerID)
	}

	return cgroupPath, nil
}

// getCGroupPath 根据容器信息获取 CGroup 路径
func getCGroupPath(info types.ContainerJSON) string {
	// 优先使用 HostConfig.CgroupParent
	if info.HostConfig.CgroupParent != "" {
		return info.HostConfig.CgroupParent
	}

	// 如果 CGroupParent 为空，尝试根据 CGroup 版本生成路径
	if isCGroupV2() {
		// CGroup v2 路径
		return fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope", info.ID)
	} else {
		// CGroup v1 路径
		return fmt.Sprintf("/sys/fs/cgroup/cpu/docker/%s", info.ID)
	}
}

// isCGroupV2 检查当前系统是否使用 CGroup v2
func isCGroupV2() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

func GetCgroupID(cgroupPath string) (uint64, error) {
	// 1. 获取 cgroup 路径的文件信息
	fileInfo, err := os.Stat(cgroupPath)
	if err != nil {
		return 0, err
	}

	// 2. 提取 inode 号（类型为 uint64）
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("无法获取 inode 信息")
	}

	// 3. inode 号即为 cgroup ID（内核行为）
	return stat.Ino, nil
}

func GetPid(containerID string) (int, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	info, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		log.Fatal(err)
	}
	return info.State.Pid, nil
}
