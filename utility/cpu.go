package utility

import (
	"io/ioutil"
	"strconv"
	"strings"
)

// 获取系统支持的CPU核心数
func GetNumOfPossibleCpus() int {
	data, _ := ioutil.ReadFile("/sys/devices/system/cpu/possible")
	parts := strings.Split(strings.TrimSpace(string(data)), "-")
	if len(parts) == 2 {
		max, _ := strconv.Atoi(parts[1])
		return max + 1
	}
	return 1 // 默认返回1
}

// 累加所有CPU核心的统计值
func Sum(values []uint64) uint64 {
	var total uint64
	for _, v := range values {
		total += v
	}
	return total
}
