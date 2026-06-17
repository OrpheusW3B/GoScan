package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DNSConfig struct {
	Resolver    string
	Timeout     time.Duration
	Concurrency int
}

func EnumerateDNS(ctx context.Context, domain string, cfg *DNSConfig) *DNSResult {
	if cfg == nil {
		cfg = &DNSConfig{Resolver: "8.8.8.8:53", Timeout: 5 * time.Second, Concurrency: 10}
	}
	result := &DNSResult{
		Records: make(map[string][]string),
	}

	c := new(dns.Client)
	c.ReadTimeout = cfg.Timeout

	recordTypes := map[string]uint16{
		"A":     dns.TypeA,
		"AAAA":  dns.TypeAAAA,
		"MX":    dns.TypeMX,
		"NS":    dns.TypeNS,
		"CNAME": dns.TypeCNAME,
		"TXT":   dns.TypeTXT,
		"SOA":   dns.TypeSOA,
		"SRV":   dns.TypeSRV,
		"CAA":   dns.TypeCAA,
		"PTR":   dns.TypePTR,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Concurrency)

	for name, rtype := range recordTypes {
		wg.Add(1)
		sem <- struct{}{}
		go func(recordName string, recordType uint16) {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(domain), recordType)
			r, _, err := c.Exchange(m, cfg.Resolver)
			if err != nil || r == nil || len(r.Answer) == 0 {
				return
			}

			mu.Lock()
			defer mu.Unlock()

			for _, ans := range r.Answer {
				switch rr := ans.(type) {
				case *dns.A:
					result.ARecords = append(result.ARecords, rr.A.String())
					result.Records["A"] = append(result.Records["A"], rr.A.String())
				case *dns.AAAA:
					result.AAAARecords = append(result.AAAARecords, rr.AAAA.String())
					result.Records["AAAA"] = append(result.Records["AAAA"], rr.AAAA.String())
				case *dns.MX:
					result.MXRecords = append(result.MXRecords, MXRecord{
						Host:     rr.Mx,
						Priority: int(rr.Preference),
					})
					result.Records["MX"] = append(result.Records["MX"], fmt.Sprintf("%d %s", rr.Preference, rr.Mx))
				case *dns.NS:
					result.NSRecords = append(result.NSRecords, rr.Ns)
					result.Records["NS"] = append(result.Records["NS"], rr.Ns)
				case *dns.CNAME:
					result.CNAMERecords = append(result.CNAMERecords, rr.Target)
					result.Records["CNAME"] = append(result.Records["CNAME"], rr.Target)
				case *dns.TXT:
					txt := strings.Join(rr.Txt, " ")
					result.TXTRecords = append(result.TXTRecords, txt)
					result.Records["TXT"] = append(result.Records["TXT"], txt)
				case *dns.SOA:
					result.SOARecord = &SOARecord{
						MName:   rr.Ns,
						RName:   rr.Mbox,
						Serial:  rr.Serial,
						Refresh: rr.Refresh,
						Retry:   rr.Retry,
						Expire:  rr.Expire,
						Minimum: rr.Minttl,
					}
				case *dns.SRV:
					result.SRVRecords = append(result.SRVRecords, SRVRecord{
						Target:   rr.Target,
						Port:     rr.Port,
						Priority: rr.Priority,
						Weight:   rr.Weight,
					})
					result.Records["SRV"] = append(result.Records["SRV"], fmt.Sprintf("%s:%d", rr.Target, rr.Port))
				case *dns.CAA:
					result.CAARecords = append(result.CAARecords, CAARecord{
						Flag:  int(rr.Flag),
						Tag:   rr.Tag,
						Value: rr.Value,
					})
					result.Records["CAA"] = append(result.Records["CAA"], fmt.Sprintf("%d %s %s", rr.Flag, rr.Tag, rr.Value))
				}
			}
		}(name, rtype)
	}
	wg.Wait()

	dnssecCheck(ctx, c, domain, cfg.Resolver, result)

	zoneTransferAttempt(ctx, domain, result.NSRecords, cfg, result)

	for _, ip := range result.ARecords {
		ptr, err := net.LookupAddr(ip)
		if err == nil && len(ptr) > 0 {
			result.Records["PTR"] = append(result.Records["PTR"], ptr[0])
		}
	}

	return result
}

func dnssecCheck(ctx context.Context, c *dns.Client, domain, resolver string, result *DNSResult) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	r, _, err := c.Exchange(m, resolver)
	if err == nil && r != nil && len(r.Answer) > 0 {
		result.DNSSEC = "enabled"
	} else {
		result.DNSSEC = "disabled"
	}
}

func zoneTransferAttempt(ctx context.Context, domain string, nsRecords []string, cfg *DNSConfig, result *DNSResult) {
	if result.ZoneTransfer == nil {
		result.ZoneTransfer = &ZoneTransferResult{Success: false}
	}
	for _, ns := range nsRecords {
		ns = strings.TrimSuffix(ns, ".")
		transfer := new(dns.Transfer)
		m := new(dns.Msg)
		m.SetAxfr(dns.Fqdn(domain))
		ch, err := transfer.In(m, ns+":53")
		if err != nil {
			continue
		}
		var records []string
		for env := range ch {
			if env.Error != nil {
				continue
			}
			for _, rr := range env.RR {
				records = append(records, rr.String())
			}
		}
		if len(records) > 0 {
			result.ZoneTransfer.Success = true
			result.ZoneTransfer.Records = records
			return
		}
	}
	result.ZoneTransfer.Error = "zone transfer refused"
}
