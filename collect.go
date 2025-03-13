package collector

type Collector interface {
	// accumulation traffic value
	Collect() (in, out uint64)
}

func NewCollector(containerId string) (Collector, error) {
	return nil, nil
}
