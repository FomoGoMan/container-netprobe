package general

type Collector interface {
	// accumulation traffic value
	CollectTotal(cgroupId uint64) (in, out uint64)
	SetUp() error
	Cleanup()
}

// type CustomCgroup interface {
// 	// get cgroup id
// 	CGroupId() uint64
// 	// get cgroup path
// 	CGroupPath() string
// }
