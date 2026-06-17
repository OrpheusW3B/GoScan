package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type SubdomainConfig struct {
	WordlistPath string
	MaxResults   int
	Concurrency  int
	Timeout      time.Duration
	Resolvers    []string
	UseCertSH    bool
	UseBrute     bool
}

func DiscoverSubdomains(ctx context.Context, domain string, cfg *SubdomainConfig) *SubdomainResult {
	if cfg == nil {
		cfg = &SubdomainConfig{
			MaxResults:  100,
			Concurrency: 20,
			Timeout:     5 * time.Second,
			UseCertSH:   true,
			UseBrute:    true,
		}
	}
	result := &SubdomainResult{}
	seen := make(map[string]bool)
	var mu sync.Mutex

	if cfg.UseCertSH {
		select {
		case <-ctx.Done():
			return result
		default:
		}
		certSubs := certSHSubdomains(ctx, domain, cfg.Timeout)
		for _, s := range certSubs {
			if !seen[s] {
				seen[s] = true
				ips, _ := ResolveIPs(s)
				result.Subdomains = append(result.Subdomains, SubdomainInfo{
					Subdomain: s,
					IPs:       ips,
					Source:    "crt.sh",
				})
				if !ContainsString(result.Methods, "crt.sh") {
					result.Methods = append(result.Methods, "crt.sh")
				}
			}
		}
	}

	if cfg.UseBrute && cfg.WordlistPath != "" {
		if _, err := os.Stat(cfg.WordlistPath); err == nil {
			words, err := LoadLines(cfg.WordlistPath)
			if err == nil {
				if cfg.MaxResults > 0 && len(words) > cfg.MaxResults {
					words = words[:cfg.MaxResults]
				}
				var found []string
				found = WorkerPool(words, cfg.Concurrency, func(word string) bool {
					select {
					case <-ctx.Done():
						return false
					default:
					}
					sub := word + "." + domain
					ips, err := net.LookupHost(sub)
					if err != nil || len(ips) == 0 {
						return false
					}
					mu.Lock()
					if seen[sub] {
						mu.Unlock()
						return false
					}
					seen[sub] = true
					mu.Unlock()
					result.Subdomains = append(result.Subdomains, SubdomainInfo{
						Subdomain: sub,
						IPs:       ips,
						Source:    "bruteforce",
					})
					return true
				})
				if len(found) > 0 && !ContainsString(result.Methods, "bruteforce") {
					result.Methods = append(result.Methods, "bruteforce")
				}
				_ = found
			}
		}
	}

	result.TotalFound = len(result.Subdomains)
	return result
}

func certSHSubdomains(ctx context.Context, domain string, timeout time.Duration) []string {
	client := &http.Client{Timeout: timeout}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "SCANNER/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var subs []string
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" || !strings.HasSuffix(name, "."+domain) && name != domain {
				continue
			}
			if name != domain && !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}
	return subs
}

func CreateDefaultSubdomainWordlist(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	words := []string{
		"www", "mail", "ftp", "admin", "blog", "webmail", "vpn", "api", "dev",
		"staging", "test", "ns1", "ns2", "mx", "smtp", "pop3", "imap", "cpanel",
		"whm", "webdisk", "autodiscover", "cpcalendars", "cpcontacts", "direct",
		"server", "remote", "secure", "shop", "store", "m", "mobile", "app",
		"my", "portal", "support", "help", "beta", "status", "docs", "forum",
		"community", "wiki", "demo", "playground", "cdn", "static", "media",
		"img", "images", "assets", "upload", "download", "files", "cloud",
		"backup", "db", "database", "redis", "mysql", "adminer", "phpmyadmin",
		"pma", "webmin", "jenkins", "gitlab", "github", "bitbucket", "jira",
		"confluence", "grafana", "prometheus", "kibana", "elastic", "logstash",
		"zabbix", "nagios", "monitor", "monitoring", "analytics", "tracking",
		"pixel", "events", "api-gateway", "gateway", "proxy", "lb", "loadbalancer",
		"web", "app1", "app2", "node1", "node2", "worker", "queue", "rabbitmq",
		"kafka", "zookeeper", "consul", "etcd", "vault", "secrets", "config",
		"registry", "docker", "kube", "kubernetes", "swarm", "nexus", "artifactory",
		"sonar", "sonarqube", "codeclimate", "sentry", "logs", "syslog", "radius",
		"ldap", "ad", "auth", "login", "sso", "oauth", "token", "keys", "cert",
		"ca", "crl", "ocsp", "time", "ntp", "dns", "ns", "dns1", "dns2",
	}
	return os.WriteFile(path, []byte(strings.Join(words, "\n")), 0644)
}
