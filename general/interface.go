package general

type Collector interface {
	// accumulation traffic value
	CollectTotal(cgroupId uint64) (in, out uint64)
}
