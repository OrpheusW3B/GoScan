package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPConfig struct {
	Timeout       time.Duration
	FollowRedirect bool
	UserAgent     string
	Cookie        string
	Proxy         string
	SkipSSLVerify bool
}

func AnalyzeHTTP(ctx context.Context, targetURL string, cfg *HTTPConfig) *HTTPResult {
	if cfg == nil {
		cfg = &HTTPConfig{Timeout: 10 * time.Second, FollowRedirect: true, UserAgent: "SCANNER/1.0"}
	}

	result := &HTTPResult{
		URL:             targetURL,
		SecurityHeaders: SecHeaders{},
	}

	client := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !cfg.FollowRedirect && len(via) > 0 {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return result
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	result.ResponseTime = time.Since(start).String()

	result.StatusCode = resp.StatusCode
	result.StatusText = http.StatusText(resp.StatusCode)
	result.Server = resp.Header.Get("Server")
	result.ContentType = resp.Header.Get("Content-Type")
	result.ContentLength = resp.ContentLength

	result.Headers = make(map[string][]string)
	for k, v := range resp.Header {
		result.Headers[k] = v
	}

	result.SecurityHeaders.StrictTransportSecurity = resp.Header.Get("Strict-Transport-Security")
	result.SecurityHeaders.ContentSecurityPolicy = resp.Header.Get("Content-Security-Policy")
	result.SecurityHeaders.XFrameOptions = resp.Header.Get("X-Frame-Options")
	result.SecurityHeaders.XContentTypeOptions = resp.Header.Get("X-Content-Type-Options")
	result.SecurityHeaders.XXSSProtection = resp.Header.Get("X-XSS-Protection")
	result.SecurityHeaders.ReferrerPolicy = resp.Header.Get("Referrer-Policy")
	result.SecurityHeaders.PermissionsPolicy = resp.Header.Get("Permissions-Policy")
	result.SecurityHeaders.CacheControl = resp.Header.Get("Cache-Control")
	result.SecurityHeaders.ExpectCT = resp.Header.Get("Expect-CT")
	result.SecurityHeaders.AccessControlAllowOrigin = resp.Header.Get("Access-Control-Allow-Origin")

	for _, c := range resp.Cookies() {
		sameSite := ""
		switch c.SameSite {
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteNoneMode:
			sameSite = "None"
		}
		ci := CookieInfo{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			SameSite: sameSite,
		}
		result.Cookies = append(result.Cookies, ci)
	}

	if resp.Request != nil && resp.Request.URL != nil {
		result.RedirectChain = append(result.RedirectChain, resp.Request.URL.String())
	}

	result.CORS = checkCORS(ctx, targetURL, cfg)

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*512))
	h := md5.Sum(body)
	result.FaviconHash = fmt.Sprintf("%x", h)

	baseURL := targetURL
	if idx := strings.LastIndex(baseURL, "/"); idx > 8 {
		baseURL = baseURL[:idx]
	}
	result.RobotsTxt = fetchPath(ctx, baseURL+"/robots.txt", cfg)
	result.SitemapXML = fetchPath(ctx, baseURL+"/sitemap.xml", cfg)

	return result
}

func checkCORS(ctx context.Context, targetURL string, cfg *HTTPConfig) *CORSInfo {
	ci := &CORSInfo{}
	client := &http.Client{Timeout: cfg.Timeout}

	req, _ := http.NewRequestWithContext(ctx, "OPTIONS", targetURL, nil)
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return ci
	}
	defer resp.Body.Close()

	ci.AllowOrigin = resp.Header.Get("Access-Control-Allow-Origin")
	ci.AllowCredentials = resp.Header.Get("Access-Control-Allow-Credentials") == "true"
	if methods := resp.Header.Get("Access-Control-Allow-Methods"); methods != "" {
		ci.AllowMethods = strings.Split(methods, ", ")
	}
	if headers := resp.Header.Get("Access-Control-Allow-Headers"); headers != "" {
		ci.AllowHeaders = strings.Split(headers, ", ")
	}
	return ci
}

func fetchPath(ctx context.Context, path string, cfg *HTTPConfig) string {
	client := &http.Client{Timeout: cfg.Timeout}
	req, _ := http.NewRequestWithContext(ctx, "GET", path, nil)
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(body)
}
