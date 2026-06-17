package tui

import (
	"fmt"
	"strings"
	"time"

	"SCANNER/config"
	"SCANNER/scanner"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch m.state {
		case menuState:
			return m.handleMenuKey(msg)
		case targetInputState:
			return m.handleTargetInput(msg)
		case customizeState:
			return m.handleCustomizeKey(msg)
		case runningState:
			return m.handleRunningKey(msg)
		case resultsState:
			return m.handleResultsKey(msg)
		case settingsState:
			return m.handleSettingsKey(msg)
		case socialState:
			return m.handleSocialKey(msg)
		}

	case moduleDoneMsg:
		m.applyModuleResult(msg.Name, msg.Result, msg.Error)
		return m, waitForModule(m.moduleCh)

	case statusMsg:
		s := string(msg)
		m.statusMsgs = append(m.statusMsgs, s)
		if len(m.statusMsgs) > 100 {
			m.statusMsgs = m.statusMsgs[len(m.statusMsgs)-100:]
		}
		return m, waitForModule(m.moduleCh)

	case scanCompleteMsg:
		m.scanDone = true
		m.scanFinalized = true
		m.result = msg.Result
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m *model) applyModuleResult(name string, result interface{}, err error) {
	for i, mod := range m.modulesList {
		if mod.Name != name {
			continue
		}
		if err != nil {
			m.modulesList[i].Status = moduleError
			m.modulesList[i].Detail = err.Error()
		} else {
			m.modulesList[i].Status = moduleDone
			m.modulesList[i].HasResult = true
			m.modulesList[i].Result = result
			m.modulesList[i].Detail = summarizeModule(name, result)
		}
		return
	}
}

func (m *model) setAllRunning() {
	for i := range m.modulesList {
		if m.modulesList[i].Status == modulePending {
			m.modulesList[i].Status = moduleRunning
		}
	}
}

func summarizeModule(name string, result interface{}) string {
	switch name {
	case "portscan":
		if r, ok := result.(*scanner.PortScanResult); ok && r != nil {
			return fmt.Sprintf("%d open ports", r.TotalFound)
		}
	case "dns":
		if r, ok := result.(*scanner.DNSResult); ok && r != nil {
			return fmt.Sprintf("A:%d MX:%d NS:%d TXT:%d", len(r.ARecords), len(r.MXRecords), len(r.NSRecords), len(r.TXTRecords))
		}
	case "subdomain":
		if r, ok := result.(*scanner.SubdomainResult); ok && r != nil {
			return fmt.Sprintf("%d found via %s", r.TotalFound, strings.Join(r.Methods, ","))
		}
	case "email":
		if r, ok := result.(*scanner.EmailResult); ok && r != nil {
			spf := "no"
			if r.SPFRecord != nil && r.SPFRecord.Exists {
				spf = "yes"
			}
			dmarc := "no"
			if r.DMARCRecord != nil && r.DMARCRecord.Exists {
				dmarc = r.DMARCRecord.Policy
			}
			return fmt.Sprintf("SPF=%s DMARC=%s DKIM=%d", spf, dmarc, len(r.DKIMRecords))
		}
	case "whois":
		if r, ok := result.(*scanner.WhoisResult); ok && r != nil {
			return fmt.Sprintf("%s / %s", r.Registrar, r.Country)
		}
	case "ssl":
		if r, ok := result.(*scanner.SSLResult); ok && r != nil {
			v := "ok"
			if r.Expired {
				v = "expired"
			} else if !r.Valid {
				v = "invalid"
			}
			return fmt.Sprintf("%s, %d protocols", v, len(r.Protocols))
		}
	case "http":
		if r, ok := result.(*scanner.HTTPResult); ok && r != nil {
			return fmt.Sprintf("status %d, %s", r.StatusCode, r.Server)
		}
	case "directory":
		if r, ok := result.(*scanner.DirectoryResult); ok && r != nil {
			return fmt.Sprintf("%d found / %d scanned", r.TotalFound, r.Scanned)
		}
	case "tech":
		if r, ok := result.(*scanner.TechResult); ok && r != nil {
			return fmt.Sprintf("%d technologies", len(r.Technologies))
		}
	case "geoip":
		if r, ok := result.(*scanner.GeoIPResult); ok && r != nil {
			return fmt.Sprintf("%s, %s", r.Country, r.ISP)
		}
	case "traceroute":
		if r, ok := result.(*scanner.TracerouteResult); ok && r != nil {
			return fmt.Sprintf("%d hops", r.Total)
		}
	case "login":
		if r, ok := result.(*scanner.LoginBruteforceResult); ok && r != nil {
			return fmt.Sprintf("%d attempts, %d found", r.TotalAttempts, len(r.Found))
		}
	}
	return "done"
}

func (m *model) handleMenuKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.menuCursor > 0 {
			m.menuCursor--
		}
	case "down", "j":
		if m.menuCursor < len(m.menuItems)-1 {
			m.menuCursor++
		}
	case "enter", " ":
		switch m.menuCursor {
		case 0:
			m.state = targetInputState
			m.targetInput = ""
			m.cfg.Profile = config.QuickScan
		case 1:
			m.state = targetInputState
			m.targetInput = ""
			m.cfg.Profile = config.FullScan
			m.cfg.EnableModules = config.AllModules()
		case 2:
			m.state = customizeState
			m.moduleCursor = 0
			m.cfg.Profile = config.Custom
		case 3:
			m.state = resultsState
		case 4:
			m.state = settingsState
			m.settingsCursor = 0
		case 5:
			m.state = socialState
		case 6:
			m.quitting = true
			return m, tea.Quit
		}
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m *model) handleTargetInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		target := strings.TrimSpace(m.targetInput)
		if target == "" {
			return m, nil
		}
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}
		m.cfg.Target = target

		m.state = runningState
		m.scanDone = false
		m.scanFinalized = false
		m.statusMsgs = []string{}
		m.scanStartTime = time.Now()

		for i := range m.modulesList {
			m.modulesList[i].Status = modulePending
			m.modulesList[i].HasResult = false
			m.modulesList[i].Result = nil
			m.modulesList[i].Detail = ""
		}
		m.setAllRunning()

		m.moduleCh = make(chan interface{}, 50)
		return m, runScan(m.cfg, m.moduleCh)

	case "esc":
		m.state = menuState
		m.targetInput = ""
		return m, nil

	case "backspace":
		if len(m.targetInput) > 0 {
			m.targetInput = m.targetInput[:len(m.targetInput)-1]
		}

	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	default:
		if msg.Type == tea.KeyRunes {
			m.targetInput += msg.String()
		}
	}
	return m, nil
}

func (m *model) handleCustomizeKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.moduleCursor > 0 {
			m.moduleCursor--
		}
	case "down", "j":
		if m.moduleCursor < len(m.modules) {
			m.moduleCursor++
		}
	case " ":
		if m.moduleCursor < len(m.modules) {
			m.modules[m.moduleCursor].enabled = !m.modules[m.moduleCursor].enabled
		}
	case "enter":
		if m.moduleCursor == len(m.modules) {
			m.cfg.EnableModules = []string{}
			for _, mod := range m.modules {
				if mod.enabled {
					m.cfg.EnableModules = append(m.cfg.EnableModules, mod.name)
				}
			}
			m.state = targetInputState
			m.targetInput = ""
		}
	case "esc":
		m.state = menuState
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m *model) handleRunningKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" || msg.String() == "q" {
		m.quitting = true
		return m, tea.Quit
	}
	if msg.String() == "enter" && m.scanDone {
		m.state = resultsState
		return m, nil
	}
	return m, nil
}

func (m *model) handleResultsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		m.state = menuState
	case "r":
		m.showRawJSON = !m.showRawJSON
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m *model) handleSettingsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.settingsCursor > 0 {
			m.settingsCursor--
		}
	case "down", "j":
		if m.settingsCursor < len(m.settingsItems)-1 {
			m.settingsCursor++
		}
	case "enter":
		if m.settingsCursor == len(m.settingsItems)-1 {
			m.state = menuState
		}
	case "esc":
		m.state = menuState
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}


func (m *model) handleSocialKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.state = menuState
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}
