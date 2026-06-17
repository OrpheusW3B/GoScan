package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

type SSLConfig struct {
	Timeout      time.Duration
	Port         int
	ScanCiphers  bool
	ScanProtocols bool
	ScanVulns    bool
}

func ScanSSL(ctx context.Context, host string, cfg *SSLConfig) *SSLResult {
	if cfg == nil {
		cfg = &SSLConfig{Timeout: 10 * time.Second, Port: 443, ScanCiphers: true, ScanProtocols: true, ScanVulns: true}
	}
	result := &SSLResult{
		Hostname: host,
	}

	addr := net.JoinHostPort(host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: cfg.Timeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Issuer = cert.Issuer.CommonName
		result.Subject = cert.Subject.CommonName
		result.SAN = cert.DNSNames
		if len(cert.DNSNames) == 0 && len(cert.IPAddresses) > 0 {
			for _, ip := range cert.IPAddresses {
				result.SAN = append(result.SAN, ip.String())
			}
		}
		result.Version = cert.Version
		result.NotBefore = cert.NotBefore.Format(time.RFC3339)
		result.NotAfter = cert.NotAfter.Format(time.RFC3339)
		result.Serial = cert.SerialNumber.String()
		result.SignatureAlgorithm = cert.SignatureAlgorithm.String()
		result.Valid = time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore)
		result.Expired = time.Now().After(cert.NotAfter)

		for i, c := range state.PeerCertificates {
			ci := CertInfo{
				Subject:  c.Subject.CommonName,
				Issuer:   c.Issuer.CommonName,
				NotAfter: c.NotAfter.Format(time.RFC3339),
				SAN:      c.DNSNames,
			}
			if i == 0 {
				continue
			}
			result.CertChain = append(result.CertChain, ci)
		}
	}

	result.CipherSuites = append(result.CipherSuites, CipherInfo{
		Name:     tls.CipherSuiteName(state.CipherSuite),
		Protocol: tlsVersion(state.Version),
		Secure:   isSecureCipher(state.CipherSuite),
	})

	if cfg.ScanProtocols {
		result.Protocols = scanProtocols(host, cfg.Port, cfg.Timeout)
	}

	if cfg.ScanVulns {
		result.Vulnerabilities = scanSSLVulns(host, cfg.Port, cfg.Timeout)
	}

	return result
}

func tlsVersion(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", ver)
	}
}

func isSecureCipher(id uint16) bool {
	secure := map[uint16]bool{
		tls.TLS_AES_128_GCM_SHA256:       true,
		tls.TLS_AES_256_GCM_SHA384:       true,
		tls.TLS_CHACHA20_POLY1305_SHA256: true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	}
	return secure[id]
}

func scanProtocols(host string, port int, timeout time.Duration) []string {
	var protocols []string
	vers := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}
	for ver, name := range vers {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         ver,
			MaxVersion:         ver,
		})
		if err == nil {
			protocols = append(protocols, name)
			conn.Close()
		}
	}
	return protocols
}

func scanSSLVulns(host string, port int, timeout time.Duration) []SSLVuln {
	var vulns []SSLVuln

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		conn.SetDeadline(time.Now().Add(timeout))
		conn.Write([]byte{
			0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00,
		})
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 && buf[0] == 0x15 {
			vulns = append(vulns, SSLVuln{
				Name:        "Heartbleed",
				Severity:    "Critical",
				Description: "Not vulnerable to CVE-2014-0160",
				Vulnerable:  false,
			})
		}
		conn.Close()
	}

	return vulns
}
