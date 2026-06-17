package scanner

import (
	"context"
	"net"
	"strconv"
	"time"
)

func ScanPorts(ctx context.Context, host string, cfg *PortScanConfig) *PortScanResult {
	if cfg == nil {
		cfg = &PortScanConfig{TopN: 100, Timeout: 5 * time.Second}
	}
	result := &PortScanResult{}

	ports := TopPorts(cfg.TopN)
	result.Scanned = len(ports)

	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	open := WorkerPoolInt(ports, cfg.Concurrency, func(port int) bool {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := (&net.Dialer{Timeout: cfg.Timeout}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	})

	for _, port := range open {
		info := PortInfo{
			Port:     port,
			Protocol: "tcp",
			Service:  ServiceName(port),
			State:    "open",
		}
		if cfg.BannerGrab {
			info.Banner = GrabBanner(host, port, cfg.Timeout)
		}
		result.OpenPorts = append(result.OpenPorts, info)
	}
	result.TotalFound = len(result.OpenPorts)
	return result
}

type PortScanConfig struct {
	TopN       int
	Timeout    time.Duration
	Concurrency int
	BannerGrab bool
}
