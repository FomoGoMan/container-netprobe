package general

type Collector interface {
	// accumulation traffic value
	CollectTotal() (in, out uint64)
	SetUp() error
	Cleanup()
}

type CollectorWithFraudDetect interface {
	SuspiciousDetector
	Collector
}
