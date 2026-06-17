package tui

import (
	"SCANNER/config"
	"SCANNER/scanner"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

type state int

const (
	menuState state = iota
	targetInputState
	customizeState
	runningState
	resultsState
	settingsState
	socialState
)

type moduleStatus int

const (
	modulePending moduleStatus = iota
	moduleRunning
	moduleDone
	moduleError
	moduleSkipped
)

type moduleInfo struct {
	Name        string
	Status      moduleStatus
	Summary     string
	Detail      string
	HasResult   bool
	Result      interface{}
}

type model struct {
	state        state
	cfg          *config.Config
	result       *scanner.ScanResult

	moduleCh     chan interface{}

	menuCursor   int
	menuItems    []string

	targetInput  string

	moduleCursor  int
	modules       []moduleOption

	modulesList   []moduleInfo
	statusMsgs    []string
	scanStartTime time.Time
	scanDone      bool
	scanFinalized bool

	showRawJSON   bool

	settingsCursor int
	settingsItems  []string

	spinner  spinner.Model

	width  int
	height int
	quitting bool
}

type moduleOption struct {
	name    string
	enabled bool
}

var defaultModules = []moduleInfo{
	{Name: "portscan", Status: modulePending, Summary: "TCP port scan"},
	{Name: "dns", Status: modulePending, Summary: "DNS records"},
	{Name: "subdomain", Status: modulePending, Summary: "Subdomains"},
	{Name: "email", Status: modulePending, Summary: "Mail security"},
	{Name: "whois", Status: modulePending, Summary: "WHOIS lookup"},
	{Name: "ssl", Status: modulePending, Summary: "SSL/TLS cert"},
	{Name: "http", Status: modulePending, Summary: "HTTP analysis"},
	{Name: "directory", Status: modulePending, Summary: "Dir busting"},
	{Name: "tech", Status: modulePending, Summary: "Web tech"},
	{Name: "geoip", Status: modulePending, Summary: "GeoIP lookup"},
	{Name: "traceroute", Status: modulePending, Summary: "Traceroute"},
	{Name: "login", Status: modulePending, Summary: "Login bruteforce"},
}

func InitialModel() model {
	s := spinner.New()
	s.Style = ProgressStyle
	s.Spinner = spinner.Dot

	mods := make([]moduleInfo, len(defaultModules))
	copy(mods, defaultModules)

	return model{
		state:  menuState,
		cfg:    config.DefaultConfig(),
		menuCursor: 0,
		menuItems: []string{
			"Quick Scan",
			"Full Scan (64 modules)",
			"Custom Scan",
			"View Last Report",
			"Settings",
			"Social",
			"Exit",
		},
		modules: []moduleOption{
			{"Port Scan", true},
			{"DNS Enumeration", true},
			{"Subdomain Discovery", true},
			{"Email Recon", true},
			{"WHOIS Lookup", true},
			{"SSL/TLS Scanner", true},
			{"HTTP Analysis", true},
			{"Directory Busting", true},
			{"Tech Detection", true},
			{"GeoIP Lookup", true},
			{"Traceroute", true},
			{"Login Bruteforce", true},
		},
		modulesList: mods,
		settingsItems: []string{
			"Threads: 20",
			"Timeout: 5s",
			"Port Range: top1000",
			"Max Subdomains: 100",
			"Max Directories: 200",
			"Scan Subdomains: true",
			"Scan Directories: true",
			"Follow Redirects: true",
			"Back to Main Menu",
		},
		spinner: s,
	}
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}
