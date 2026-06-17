package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type LoginConfig struct {
	Timeout    time.Duration
	UserAgent  string
	Method     string
}

var commonCredentials = []struct {
	Username string
	Password string
}{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "123456"},
	{"admin", "admin123"},
	{"admin", "root"},
	{"root", "root"},
	{"root", "admin"},
	{"root", "toor"},
	{"user", "user"},
	{"user", "password"},
	{"user", "123456"},
	{"guest", "guest"},
	{"test", "test"},
	{"test", "123456"},
	{"admin", "letmein"},
	{"admin", "Passw0rd"},
	{"admin", "p@ssw0rd"},
	{"admin", "changeme"},
	{"admin", "secret"},
	{"admin", "1q2w3e4r"},
	{"admin", "qwerty"},
	{"admin", "welcome"},
	{"admin", "master"},
	{"admin", "login"},
	{"administrator", "administrator"},
	{"administrator", "password"},
	{"Admin", "Admin"},
	{"Admin", "admin"},
	{"Admin", "123456"},
	{"admin", "P@ssw0rd!"},
	{"admin", "Admin@123"},
	{"root", "P@ssw0rd!"},
	{"root", "Root@123"},
	{"tomcat", "tomcat"},
	{"manager", "manager"},
	{"manager", "password"},
	{"jenkins", "jenkins"},
	{"admin", "jenkins"},
	{"oracle", "oracle"},
	{"oracle", "password"},
	{"postgres", "postgres"},
	{"postgres", "password"},
	{"sa", "sa"},
	{"sa", "password"},
	{"sa", "s@password"},
}

type LoginCheckConfig struct {
	UsernameField string
	PasswordField string
	FormAction    string
}

func tryLogin(ctx context.Context, target string, username, password string, cfg *LoginConfig) (int, int64, error) {
	client := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	formData := url.Values{}
	formData.Set("username", username)
	formData.Set("password", password)
	formData.Set("user", username)
	formData.Set("pass", password)
	formData.Set("email", username)
	formData.Set("login", username)
	formData.Set("pwd", password)

	method := "POST"
	if cfg.Method != "" {
		method = cfg.Method
	}

	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(formData.Encode()))
	if err != nil {
		return 0, 0, err
	}

	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return 0, elapsed, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := strings.ToLower(string(body))

	failIndicators := []string{
		"invalid", "incorrect", "failed", "denied", "error",
		"wrong", "not found", "does not exist", "try again",
		"access denied", "forbidden", "bad credentials",
		"login failed", "authentication failed", "invalid credentials",
	}
	isFailure := false
	for _, ind := range failIndicators {
		if strings.Contains(bodyStr, ind) {
			isFailure = true
			break
		}
	}

	bodySize := int64(len(body))

	if resp.StatusCode == 302 || resp.StatusCode == 301 {
		return 1, elapsed, nil
	}
	if resp.StatusCode == 200 && !isFailure && bodySize > 512 {
		return 1, elapsed, nil
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return 0, elapsed, nil
	}

	return 0, elapsed, nil
}

func BruteForceLogin(ctx context.Context, target string, cfg *LoginConfig) *LoginBruteforceResult {
	res := &LoginBruteforceResult{}
	usersSeen := make(map[string]bool)

	for _, cred := range commonCredentials {
		select {
		case <-ctx.Done():
			res.Error = "cancelled"
			return res
		default:
		}

		if !usersSeen[cred.Username] {
			res.TestedUsers = append(res.TestedUsers, cred.Username)
			usersSeen[cred.Username] = true
		}

		success, _elapsed, err := tryLogin(ctx, target, cred.Username, cred.Password, cfg)
		res.TotalAttempts++

		_ = _elapsed

		if err != nil {
			continue
		}

		if success == 1 {
			res.Found = append(res.Found, CredentialFound{
				Username: cred.Username,
				Password: cred.Password,
				URL:      target,
				Method:   cfg.Method,
				Status:   200,
			})
			break
		}
	}

	return res
}
