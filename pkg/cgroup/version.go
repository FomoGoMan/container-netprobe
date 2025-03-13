package helper

import (
	"io/ioutil"
	"os"
)

type CgroupVersion string

const (
	CgroupV1      CgroupVersion = "v1"
	CgroupV2      CgroupVersion = "v2"
	CgroupUnknown CgroupVersion = "unknown"
)

func DetectCgroupVersion() CgroupVersion {
	// 检查是否存在 cgroup v2 的核心文件 /sys/fs/cgroup/cgroup.controllers
	cgroupV2CheckPath := "/sys/fs/cgroup/cgroup.controllers"
	if _, err := os.Stat(cgroupV2CheckPath); err == nil {
		// 读取文件内容，确认是否为有效 v2 系统
		data, err := ioutil.ReadFile(cgroupV2CheckPath)
		if err == nil && len(data) > 0 {
			return CgroupV2
		}
	}

	// 检查是否存在 cgroup v1 的典型控制器目录（如 cpu）
	cgroupV1CheckPath := "/sys/fs/cgroup/cpu"
	if _, err := os.Stat(cgroupV1CheckPath); err == nil {
		return CgroupV1
	}

	// 若均不符合，返回 unknown
	return CgroupUnknown
}
