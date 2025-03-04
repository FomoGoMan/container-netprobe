package container

import (
	v0t "ebpf_collector/container/v0"

	v1t "ebpf_collector/container/v1"
	v2t "ebpf_collector/container/v2"
)

type Collector struct {
	inner types.Collector
}

func NewCollector(fileLogger *logger.FileLogger) (*Collector, error) {
	v2c, err := v2t.NewCollector(fileLogger)
	if err == nil {
		fileLogger.Warn("create v2 container collector success")
		return &Collector{inner: v2c}, nil
	}
	fileLogger.Warn("create v2 container collector failed: %v, try v1", err)

	v1c, err := v1t.NewCollector(fileLogger)
	if err == nil {
		fileLogger.Info("create v1 container collector success")
		return &Collector{inner: v1c}, nil
	}

	/*
		fileLogger.Warn("create v1 container collector failed: %v, try v0", err)

		v0c, err := v0t.NewCollector(fileLogger)
		if err == nil {
			fileLogger.Warn("create v0 host collector success")
			return &Collector{inner: v0c}, nil
		}
		fileLogger.Warn("create v0 host collector failed: %v", err)
	*/

	return nil, err
}

func NewV0Collector(fileLogger *logger.FileLogger) (*Collector, error) {
	v0c, err := v0t.NewCollector(fileLogger)
	if err == nil {
		fileLogger.Warn("create v0 host collector success")
		return &Collector{inner: v0c}, nil
	}
	return nil, err
}

func NewV1Collector(fileLogger *logger.FileLogger) (*Collector, error) {
	v1c, err := v1t.NewCollector(fileLogger)
	if err == nil {
		fileLogger.Warn("create v1 container collector success")
		return &Collector{inner: v1c}, nil
	}
	return nil, err
}

func NewV2Collector(fileLogger *logger.FileLogger) (*Collector, error) {
	v2c, err := v2t.NewCollector(fileLogger)
	if err == nil {
		fileLogger.Warn("create v2 container collector success")
		return &Collector{inner: v2c}, nil
	}
	return nil, err
}

func (c *Collector) Collect() types.FlowMap {
	return c.inner.Collect()
}

func (c *Collector) Close() {
	c.inner.Close()
}
