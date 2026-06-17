package scanner

import (
	"context"
	"net"
	"time"
)

type TraceConfig struct {
	MaxHops   int
	Timeout   time.Duration
	Concurrency int
}

func Traceroute(ctx context.Context, host string, cfg *TraceConfig) *TracerouteResult {
	if cfg == nil {
		cfg = &TraceConfig{MaxHops: 30, Timeout: 3 * time.Second}
	}
	result := &TracerouteResult{}

	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		result.Success = false
		return result
	}
	targetIP := ips[0]

	for ttl := 1; ttl <= cfg.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		start := time.Now()
		hop := probeHop(targetIP, ttl, cfg.Timeout)
		hop.Hop = ttl
		hop.RTT = time.Since(start).String()
		result.Hops = append(result.Hops, hop)

		if hop.Alive && hop.IP != nil && hop.IP.String() == targetIP {
			result.Total = ttl
			result.Success = true
			break
		}
	}

	return result
}

func probeHop(target string, ttl int, timeout time.Duration) HopInfo {
	hop := HopInfo{Alive: false}

	conn, err := net.DialTimeout("tcp", target+":80", timeout)
	if err != nil {
		return hop
	}
	defer conn.Close()

	hop.Alive = true
	if ip := net.ParseIP(target); ip != nil {
		hop.IP = ip
	}

	return hop
}
