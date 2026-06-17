package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type ScanProfile string

const (
	QuickScan ScanProfile = "quick"
	FullScan  ScanProfile = "full"
	Custom    ScanProfile = "custom"
)

type Config struct {
	Target             string        `json:"target"`
	Profile            ScanProfile   `json:"profile"`
	Threads            int           `json:"threads"`
	Timeout            time.Duration `json:"timeout"`
	PortRange          string        `json:"port_range"`
	Resolvers          []string      `json:"resolvers"`
	WordlistDir        string        `json:"wordlist_dir"`
	OutputDir          string        `json:"output_dir"`
	EnableModules      []string      `json:"enable_modules"`
	DisableModules     []string      `json:"disable_modules"`
	MaxSubdomains      int           `json:"max_subdomains"`
	MaxDirectories     int           `json:"max_directories"`
	DirectoryExts      []string      `json:"directory_exts"`
	Proxy              string        `json:"proxy"`
	UserAgent          string        `json:"user_agent"`
	Cookie             string        `json:"cookie"`
	Verbose            bool          `json:"verbose"`
	FollowRedirect     bool          `json:"follow_redirect"`
	SkipSSLVerify      bool          `json:"skip_ssl_verify"`
	ScanSubdomains     bool          `json:"scan_subdomains"`
	ScanDirectories    bool          `json:"scan_directories"`
}

var DefaultResolvers = []string{
	"8.8.8.8:53",
	"1.1.1.1:53",
	"9.9.9.9:53",
	"208.67.222.222:53",
}

func DefaultConfig() *Config {
	wd, _ := os.Getwd()
	return &Config{
		Profile:        QuickScan,
		Threads:        20,
		Timeout:        5 * time.Second,
		PortRange:      "top1000",
		Resolvers:      DefaultResolvers,
		WordlistDir:    filepath.Join(wd, "assets", "wordlists"),
		OutputDir:      filepath.Join(wd, "output"),
		MaxSubdomains:  100,
		MaxDirectories: 200,
		DirectoryExts:  []string{".php", ".asp", ".aspx", ".jsp", ".do", ".html", ".htm", ".txt", ".json", ".xml", ".bak", ".old", ".zip", ".tar.gz", ".sql", ".env", ".config"},
		UserAgent:      "SCANNER/1.0 (Security Research Tool)",
		FollowRedirect: true,
		SkipSSLVerify:  false,
		ScanSubdomains: true,
		ScanDirectories: true,
		Verbose:        false,
		EnableModules:  AllModules(),
	}
}

func AllModules() []string {
	return []string{
		"portscan", "dns", "subdomain", "email", "whois",
		"ssl", "http", "directory", "tech", "geoip", "traceroute",
		"login",
	}
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) ModuleEnabled(name string) bool {
	for _, m := range c.EnableModules {
		if m == name {
			for _, d := range c.DisableModules {
				if d == name {
					return false
				}
			}
			return true
		}
	}
	return false
}
