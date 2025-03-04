package traffic

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"go_minion/internal/collector/types"
	"go_minion/pkg/logger"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"
)

const (
	TRAFFIC_DIR  = "./data/"
	TRAFFIC_PY   = "./data/traffic.py"
	TRAFFIC_C    = "./data/traffic.c"
	TRAFFIC_SOCK = "./data/traffic.sock"
)

//go:embed traffic.py
var trafficPy []byte

//go:embed traffic.c
var trafficC []byte

type Collector struct {
	logger *logger.FieldLogger
	server *exec.Cmd
}

func NewCollector(fileLogger *logger.FileLogger) (*Collector, error) {
	c := &Collector{
		logger: logger.NewFieldLogger(fileLogger, "ebpf-host-v0"),
	}

	if err := os.MkdirAll(TRAFFIC_DIR, 0755); err != nil && !os.IsExist(err) {
		c.logger.Error("create data dir failed: %v", err)
		return nil, err
	}

	if err := os.WriteFile(TRAFFIC_PY, trafficPy, 0644); err != nil {
		c.logger.Error("write '%s' failed: %v", TRAFFIC_PY, err)
		return nil, err
	}

	if err := os.WriteFile(TRAFFIC_C, trafficC, 0644); err != nil {
		c.logger.Error("write '%s' failed: %v", TRAFFIC_C, err)
		return nil, err
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	server := exec.Command("python", TRAFFIC_PY, TRAFFIC_SOCK)
	server.Stdout = &stdout
	server.Stderr = &stderr
	if err := server.Start(); err != nil {
		c.logger.Error("start server failed: %v", err)
		return nil, err
	}

	c.server = server
	go func() {
		if err := server.Wait(); err != nil {
			c.logger.Error("server stopped: %v", err)
		}
	}()

	var data []byte
	var err error
	for i := 0; i <= 10; i++ {
		// 此处增加重试等待逻辑，确保Python服务器先启动
		data, err = request("load")
		if err != nil {
			if i != 3 {
				c.logger.Error("load failed: %v, retry after 100ms", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return nil, err
		}
		break
	}
	if string(data) != "success" {
		return nil, fmt.Errorf("load ebpf failed: %s", string(data))
	}

	return c, nil
}

func (c *Collector) Close() {
	if c.server != nil {
		c.server.Process.Signal(os.Interrupt)
	}
}

func (c *Collector) Collect() types.FlowMap {
	flows := make(types.FlowMap)

	data, err := request("flow")
	if err != nil {
		return nil
	}

	var flow types.FlowData
	if err := json.Unmarshal(data, &flow); err != nil {
		c.logger.Error("parse response failed: %v", err)
		return nil
	}

	container := "000000000000"
	flows[container] = &flow
	return flows
}

func request(path string) ([]byte, error) {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _ string, _ string) (net.Conn, error) {
			return net.Dial("unix", TRAFFIC_SOCK)
		},
	}

	client := &http.Client{Transport: transport}
	url := fmt.Sprintf("http://unix/%s", path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}
