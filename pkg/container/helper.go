package helper

import (
	"fmt"
	"log"
	"os"
	"syscall"

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

func GetContainerInfo(containerID string) (cgroupPath string) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithVersion("1.48"))
	if err != nil {
		log.Fatal(err)
	}

	// 获取容器详细信息
	info, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		log.Fatal(err)
	}

	// 从容器信息中直接获取 CGroup 路径
	cgroupPath = info.HostConfig.CgroupParent
	if cgroupPath == "" {
		// 若使用 cgroup v2，路径可能需要拼接
		cgroupPath = fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope", info.ID)
	}
	log.Printf("CGroup Path: %s", cgroupPath)
	return
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
