package scanner

import (
	"context"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

type EmailConfig struct {
	Domain      string
	Resolvers   []string
	Timeout     time.Duration
	SMTPCheck   bool
	DKIMSelectors []string
}

func CheckEmail(ctx context.Context, domain string, cfg *EmailConfig) *EmailResult {
	if cfg == nil {
		cfg = &EmailConfig{
			Timeout:     5 * time.Second,
			SMTPCheck:   true,
			DKIMSelectors: []string{"default", "google", "selector1", "selector2", "dkim", "mail", "zoho", "protonmail", "migadu"},
		}
	}
	result := &EmailResult{}

	mxRecords, _ := net.LookupMX(domain)
	for _, mx := range mxRecords {
		result.MXRecords = append(result.MXRecords, MXRecord{
			Host:     mx.Host,
			Priority: int(mx.Pref),
		})
	}

	txtRecords, _ := net.LookupTXT(domain)
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			result.SPFRecord = &SPFResult{
				Exists: true,
				Raw:    txt,
				Valid:  true,
			}
			break
		}
	}
	if result.SPFRecord == nil {
		result.SPFRecord = &SPFResult{Exists: false}
	}

	dmarcDomain := "_dmarc." + domain
	dmarcTxt, _ := net.LookupTXT(dmarcDomain)
	for _, txt := range dmarcTxt {
		if strings.HasPrefix(txt, "v=DMARC1") {
			policy := ""
			for _, part := range strings.Split(txt, ";") {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "p=") {
					policy = strings.TrimPrefix(part, "p=")
				}
			}
			result.DMARCRecord = &DMARCResult{
				Exists: true,
				Raw:    txt,
				Policy: policy,
			}
			break
		}
	}
	if result.DMARCRecord == nil {
		result.DMARCRecord = &DMARCResult{Exists: false}
	}

	for _, selector := range cfg.DKIMSelectors {
		dkimDomain := selector + "._domainkey." + domain
		dkimTxt, _ := net.LookupTXT(dkimDomain)
		for _, txt := range dkimTxt {
			if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "k=rsa") {
				result.DKIMRecords = append(result.DKIMRecords, DKIMResult{
					Selector: selector,
					Exists:   true,
					Raw:      txt,
				})
				break
			}
		}
	}
	if result.DKIMRecords == nil {
		result.DKIMRecords = []DKIMResult{}
	}

	if cfg.SMTPCheck && len(result.MXRecords) > 0 {
		smptResult := smtpCheck(ctx, result.MXRecords[0].Host, cfg.Timeout)
		result.SMTPCheck = smptResult
	}

	commonFormats := []string{
		"admin@" + domain,
		"info@" + domain,
		"support@" + domain,
		"contact@" + domain,
		"sales@" + domain,
		"noreply@" + domain,
		"webmaster@" + domain,
		"postmaster@" + domain,
		"hostmaster@" + domain,
		"abuse@" + domain,
	}
	result.EmailFormats = commonFormats

	return result
}

func smtpCheck(ctx context.Context, mxHost string, timeout time.Duration) *SMTPResult {
	result := &SMTPResult{}
	conn, err := net.DialTimeout("tcp", mxHost+":25", timeout)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	tc := textproto.NewConn(conn)

	line, err := tc.ReadLine()
	if err != nil {
		result.Error = fmt.Sprintf("banner read failed: %v", err)
		return result
	}
	result.Banner = line

	tc.PrintfLine("HELO scanner.local")
	line, _ = tc.ReadLine()

	tc.PrintfLine("MAIL FROM:<check@scanner.local>")
	line, _ = tc.ReadLine()

	tc.PrintfLine("RCPT TO:<test@example.com>")
	line, _ = tc.ReadLine()

	if strings.Contains(line, "250") || strings.Contains(line, "251") {
		result.OpenRelay = true
	}

	tc.PrintfLine("QUIT")
	return result
}
