package general

type CGroupInfoGetter interface {
	// full path of cgroup
	GetCgroupPath() string
}

type PidInfoGetter interface {
	GetPid() int
}
