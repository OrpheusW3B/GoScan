package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"SCANNER/config"
)

type ModuleResult struct {
	Name   string
	Result interface{}
	Error  error
	Done   bool
}

type Runner struct {
	cfg               *config.Config
	result            *ScanResult
	ctx               context.Context
	cancel             context.CancelFunc
	mu                sync.Mutex
	OnStatus          func(string)
	OnModuleComplete  func(ModuleResult)
}

func NewRunner(cfg *config.Config) *Runner {
	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
		result: &ScanResult{
			Target:    cfg.Target,
			StartTime: time.Now(),
		},
	}
}

func (r *Runner) Result() *ScanResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.result
}

func (r *Runner) Cancel() {
	r.cancel()
}

func (r *Runner) logStatus(msg string) {
	if r.OnStatus != nil {
		r.OnStatus(msg)
	}
}

func (r *Runner) moduleDone(name string, val interface{}, err error) {
	r.mu.Lock()
	switch v := val.(type) {
	case *PortScanResult:
		r.result.PortScan = v
	case *DNSResult:
		r.result.DNS = v
	case *SubdomainResult:
		r.result.Subdomain = v
	case *EmailResult:
		r.result.Email = v
	case *WhoisResult:
		r.result.Whois = v
	case *SSLResult:
		r.result.SSL = v
	case *HTTPResult:
		r.result.HTTP = v
	case *DirectoryResult:
		r.result.Directory = v
	case *TechResult:
		r.result.Tech = v
	case *GeoIPResult:
		r.result.GeoIP = v
	case *TracerouteResult:
		r.result.Traceroute = v
	case *LoginBruteforceResult:
		r.result.LoginBruteforce = v
	}
	r.mu.Unlock()
	if r.OnModuleComplete != nil {
		r.OnModuleComplete(ModuleResult{Name: name, Result: val, Error: err, Done: true})
	}
}

func (r *Runner) Run() (*ScanResult, error) {
	host, port, scheme, err := ExtractHost(r.cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %v", err)
	}
	r.result.Host = host
	r.result.IP = host

	r.logStatus("Resolving hostname...")
	if ip := net.ParseIP(host); ip == nil {
		if resolved, err := ResolveIP(host); err == nil {
			r.result.IP = resolved
			r.logStatus(fmt.Sprintf("Resolved: %s -> %s", host, resolved))
		}
	}
	_ = port
	_ = scheme

	var wg sync.WaitGroup

	module := func(name string, enabled bool, fn func()) {
		if !enabled {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}

	module("portscan", r.cfg.ModuleEnabled("portscan"), func() {
		r.logStatus("Port scan: scanning top 1000 ports...")
		res := ScanPorts(r.ctx, r.result.IP, &PortScanConfig{
			TopN:        100,
			Timeout:     r.cfg.Timeout,
			Concurrency: r.cfg.Threads,
			BannerGrab:  true,
		})
		var err error
		if res.TotalFound == 0 {
			err = fmt.Errorf("no open ports found")
		}
		r.moduleDone("portscan", res, err)
		r.logStatus(fmt.Sprintf("Port scan: %d open ports", res.TotalFound))
	})

	module("dns", r.cfg.ModuleEnabled("dns"), func() {
		r.logStatus("DNS: enumerating records...")
		res := EnumerateDNS(r.ctx, r.result.Host, &DNSConfig{
			Resolver:    r.cfg.Resolvers[0],
			Timeout:     r.cfg.Timeout,
			Concurrency: r.cfg.Threads,
		})
		r.moduleDone("dns", res, nil)
		r.logStatus(fmt.Sprintf("DNS: %d record types", len(res.Records)))
	})

	module("subdomain", r.cfg.ModuleEnabled("subdomain") && r.cfg.ScanSubdomains, func() {
		r.logStatus("Subdomains: discovering...")
		wordlistPath := filepath.Join(r.cfg.WordlistDir, "subdomains.txt")
		res := DiscoverSubdomains(r.ctx, r.result.Host, &SubdomainConfig{
			WordlistPath: wordlistPath,
			MaxResults:   r.cfg.MaxSubdomains,
			Concurrency:  r.cfg.Threads,
			Timeout:      r.cfg.Timeout,
			UseCertSH:    true,
			UseBrute:     true,
		})
		r.moduleDone("subdomain", res, nil)
		r.logStatus(fmt.Sprintf("Subdomains: %d found", res.TotalFound))
	})

	module("email", r.cfg.ModuleEnabled("email"), func() {
		r.logStatus("Email: checking mail config...")
		res := CheckEmail(r.ctx, r.result.Host, &EmailConfig{
			Timeout:   r.cfg.Timeout,
			SMTPCheck: true,
		})
		r.moduleDone("email", res, nil)
		spf := "no"
		if res.SPFRecord != nil && res.SPFRecord.Exists {
			spf = "yes"
		}
		dmarc := "no"
		if res.DMARCRecord != nil && res.DMARCRecord.Exists {
			dmarc = "yes"
		}
		r.logStatus(fmt.Sprintf("Email: SPF=%s DMARC=%s DKIM=%d", spf, dmarc, len(res.DKIMRecords)))
	})

	module("whois", r.cfg.ModuleEnabled("whois"), func() {
		r.logStatus("WHOIS: looking up...")
		res := LookupWhois(r.ctx, r.result.Host, &WhoisConfig{Timeout: r.cfg.Timeout})
		r.moduleDone("whois", res, nil)
		r.logStatus(fmt.Sprintf("WHOIS: %s / %s", res.Registrar, res.Country))
	})

	module("ssl", r.cfg.ModuleEnabled("ssl"), func() {
		r.logStatus("SSL/TLS: scanning...")
		res := ScanSSL(r.ctx, r.result.Host, &SSLConfig{
			Timeout:       r.cfg.Timeout,
			Port:          443,
			ScanCiphers:   true,
			ScanProtocols: true,
			ScanVulns:     true,
		})
		r.moduleDone("ssl", res, nil)
		valid := "valid"
		if !res.Valid {
			valid = "invalid"
		}
		if res.Expired {
			valid = "expired"
		}
		r.logStatus(fmt.Sprintf("SSL/TLS: %s, %d protocols", valid, len(res.Protocols)))
	})

	module("http", r.cfg.ModuleEnabled("http"), func() {
		r.logStatus("HTTP: analyzing...")
		res := AnalyzeHTTP(r.ctx, r.cfg.Target, &HTTPConfig{
			Timeout:        r.cfg.Timeout,
			FollowRedirect: r.cfg.FollowRedirect,
			UserAgent:      r.cfg.UserAgent,
			Cookie:         r.cfg.Cookie,
			SkipSSLVerify:  r.cfg.SkipSSLVerify,
		})
		r.moduleDone("http", res, nil)
		r.logStatus(fmt.Sprintf("HTTP: status %d, server: %s", res.StatusCode, res.Server))
	})

	module("directory", r.cfg.ModuleEnabled("directory") && r.cfg.ScanDirectories, func() {
		r.logStatus("Directories: busting...")
		wordlistPath := filepath.Join(r.cfg.WordlistDir, "directories.txt")
		res := BusterDirectories(r.ctx, r.cfg.Target, &DirectoryConfig{
			WordlistPath: wordlistPath,
			Extensions:   r.cfg.DirectoryExts,
			MaxResults:   r.cfg.MaxDirectories,
			Concurrency:  r.cfg.Threads,
			Timeout:      r.cfg.Timeout,
			UserAgent:    r.cfg.UserAgent,
		})
		r.moduleDone("directory", res, nil)
		r.logStatus(fmt.Sprintf("Directories: %d found", res.TotalFound))
	})

	module("tech", r.cfg.ModuleEnabled("tech"), func() {
		r.logStatus("Tech: detecting...")
		res := DetectTechnologies(r.ctx, r.cfg.Target, &TechConfig{
			Timeout:   r.cfg.Timeout,
			UserAgent: r.cfg.UserAgent,
		})
		r.moduleDone("tech", res, nil)
		r.logStatus(fmt.Sprintf("Tech: %d technologies", len(res.Technologies)))
	})

	module("geoip", r.cfg.ModuleEnabled("geoip"), func() {
		r.logStatus("GeoIP: looking up...")
		res := LookupGeoIP(r.ctx, r.result.IP, &GeoConfig{Timeout: r.cfg.Timeout})
		r.moduleDone("geoip", res, nil)
		r.logStatus(fmt.Sprintf("GeoIP: %s, %s", res.Country, res.ISP))
	})

	module("traceroute", r.cfg.ModuleEnabled("traceroute"), func() {
		r.logStatus("Traceroute: tracing...")
		res := Traceroute(r.ctx, r.result.Host, &TraceConfig{
			MaxHops: 30,
			Timeout: r.cfg.Timeout,
		})
		r.moduleDone("traceroute", res, nil)
		r.logStatus(fmt.Sprintf("Traceroute: %d hops", res.Total))
	})

	module("login", r.cfg.ModuleEnabled("login"), func() {
		r.logStatus("Login bruteforce: trying common credentials...")
		res := BruteForceLogin(r.ctx, r.cfg.Target, &LoginConfig{
			Timeout:   r.cfg.Timeout,
			UserAgent: r.cfg.UserAgent,
		})
		r.moduleDone("login", res, nil)
		found := 0
		if len(res.Found) > 0 {
			found = len(res.Found)
		}
		r.logStatus(fmt.Sprintf("Login: %d attempts, %d found", res.TotalAttempts, found))
	})

	wg.Wait()

	r.result.EndTime = time.Now()
	r.result.Duration = time.Since(r.result.StartTime).String()

	os.MkdirAll(r.cfg.OutputDir, 0755)
	jsonPath := filepath.Join(r.cfg.OutputDir, "scan_result.json")
	if err := SaveJSON(jsonPath, r.result); err != nil {
		r.logStatus("Error: JSON save failed: " + err.Error())
	} else {
		r.logStatus("JSON saved: " + jsonPath)
	}

	htmlPath := filepath.Join(r.cfg.OutputDir, "scan_report.html")
	if err := GenerateHTML(htmlPath, r.result); err != nil {
		r.logStatus("Error: HTML report failed: " + err.Error())
	} else {
		r.logStatus("HTML report: " + htmlPath)
	}

	return r.result, nil
}
