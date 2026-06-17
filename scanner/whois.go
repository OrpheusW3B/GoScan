package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type WhoisConfig struct {
	Timeout time.Duration
}

func LookupWhois(ctx context.Context, domain string, cfg *WhoisConfig) *WhoisResult {
	if cfg == nil {
		cfg = &WhoisConfig{Timeout: 10 * time.Second}
	}
	result := &WhoisResult{
		Domain: domain,
	}

	whoisData := queryWhoisHTTP(ctx, domain, cfg.Timeout)
	if whoisData == "" {
		whoisData = queryWhoisRaw(ctx, domain)
	}
	result.Raw = whoisData

	result.Registrar = extractWhoisField(whoisData, "Registrar:")
	result.Org = extractWhoisField(whoisData, "Registrant Organization:")
	if result.Org == "" {
		result.Org = extractWhoisField(whoisData, "OrgName:")
	}
	result.Country = extractWhoisField(whoisData, "Registrant Country:")
	if result.Country == "" {
		result.Country = extractWhoisField(whoisData, "Country:")
	}
	result.CreatedDate = extractWhoisField(whoisData, "Creation Date:")
	if result.CreatedDate == "" {
		result.CreatedDate = extractWhoisField(whoisData, "Created:")
	}
	result.ExpiryDate = extractWhoisField(whoisData, "Registry Expiry Date:")
	if result.ExpiryDate == "" {
		result.ExpiryDate = extractWhoisField(whoisData, "Expiration Date:")
	}
	nameServers := extractWhoisMultiField(whoisData, "Name Server:")
	for _, ns := range nameServers {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			result.NameServers = append(result.NameServers, ns)
		}
	}
	emails := extractWhoisMultiField(whoisData, "Registrant Email:")
	if len(emails) == 0 {
		emails = extractWhoisMultiField(whoisData, "Email:")
	}
	result.Emails = emails

	return result
}

func queryWhoisHTTP(ctx context.Context, domain string, timeout time.Duration) string {
	client := &http.Client{Timeout: timeout}
	url := fmt.Sprintf("https://who.is/whois/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "SCANNER/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func queryWhoisRaw(ctx context.Context, domain string) string {
	conn, err := net.DialTimeout("tcp", "whois.iana.org:43", 10*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "%s\r\n", domain)
	data, _ := io.ReadAll(conn)
	return string(data)
}

func extractWhoisField(data, field string) string {
	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, field) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func extractWhoisMultiField(data, field string) []string {
	var values []string
	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, field) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" {
					values = append(values, val)
				}
			}
		}
	}
	return values
}
