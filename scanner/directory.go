package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type DirectoryConfig struct {
	WordlistPath string
	Extensions   []string
	MaxResults   int
	Concurrency  int
	Timeout      time.Duration
	FollowRedirect bool
	UserAgent    string
}

func BusterDirectories(ctx context.Context, baseURL string, cfg *DirectoryConfig) *DirectoryResult {
	if cfg == nil {
		cfg = &DirectoryConfig{
			Concurrency:  20,
			Timeout:      5 * time.Second,
			UserAgent:    "SCANNER/1.0",
		}
	}
	result := &DirectoryResult{}

	if cfg.WordlistPath == "" {
		return result
	}

	if _, err := os.Stat(cfg.WordlistPath); os.IsNotExist(err) {
		return result
	}

	words, err := LoadLines(cfg.WordlistPath)
	if err != nil {
		return result
	}

	if cfg.MaxResults > 0 && len(words) > cfg.MaxResults {
		words = words[:cfg.MaxResults]
	}

	baseURL = strings.TrimRight(baseURL, "/")

	var mu sync.Mutex
	entries := WorkerPool(words, cfg.Concurrency, func(word string) bool {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		paths := []string{baseURL + "/" + word}
		for _, ext := range cfg.Extensions {
			paths = append(paths, baseURL+"/"+word+ext)
		}

		for _, path := range paths {
			client := &http.Client{
				Timeout: cfg.Timeout,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if len(via) > 3 {
						return fmt.Errorf("too many redirects")
					}
					return nil
				},
			}
			req, _ := http.NewRequestWithContext(ctx, "GET", path, nil)
			req.Header.Set("User-Agent", cfg.UserAgent)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != 404 && resp.StatusCode != 301 && resp.StatusCode != 302 {
				mu.Lock()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
				title := extractTitle(string(body))
				result.Found = append(result.Found, DirEntry{
					Path:        path,
					StatusCode:  resp.StatusCode,
					Size:        resp.ContentLength,
					ContentType: resp.Header.Get("Content-Type"),
					Title:       title,
				})
				mu.Unlock()
				return true
			}
		}
		return false
	})
	_ = entries
	result.TotalFound = len(result.Found)
	result.Scanned = len(words)
	return result
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start == -1 {
		return ""
	}
	start = strings.Index(lower[start:], ">")
	if start == -1 {
		return ""
	}
	start += start
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

func CreateDefaultDirectoryWordlist(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	words := []string{
		"admin", "administrator", "backup", "bak", "cache", "cgi-bin", "config",
		"conf", "css", "data", "db", "debug", "dev", "dist", "download", "error",
		"errors", "etc", "exports", "fonts", "ftp", "git", "health", "healthz",
		"home", "html", "images", "img", "inc", "include", "includes", "index",
		"install", "js", "json", "jsons", "language", "lib", "library", "local",
		"lock", "log", "login", "logo", "logs", "mail", "manager", "media",
		"metrics", "min", "misc", "mobile", "mock", "models", "modules", "monitor",
		"mysql", "net", "network", "new", "news", "node", "null", "old", "old2",
		"page", "pages", "panel", "pass", "password", "php", "phpmyadmin", "pma",
		"pmd", "pod", "policy", "privacy", "private", "profiler", "public", "query",
		"rss", "sass", "save", "script", "scripts", "search", "secure", "security",
		"server", "service", "services", "session", "sessions", "setup", "shell",
		"show", "signin", "signup", "sitemap", "sitemaps", "skin", "sso", "staff",
		"stage", "staging", "stat", "static", "stats", "status", "store", "svn",
		"swf", "swp", "sys", "system", "temp", "template", "templates", "test",
		"testing", "tests", "tmp", "todo", "tmp", "trash", "tree", "upload",
		"uploads", "user", "users", "var", "vendor", "version", "web", "webapp",
		"webdav", "webmail", "webroot", "www", "xml", "zip",
	}
	return os.WriteFile(path, []byte(strings.Join(words, "\n")), 0644)
}
