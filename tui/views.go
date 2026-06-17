package tui

import (
	"fmt"
	"strings"
	"time"

	"SCANNER/scanner"

	"github.com/charmbracelet/lipgloss"
)

func (m model) View() string {
	var content string
	switch m.state {
	case menuState:
		content = m.menuView()
	case targetInputState:
		content = m.targetInputView()
	case customizeState:
		content = m.customizeView()
	case runningState:
		content = m.runningView()
	case resultsState:
		content = m.resultsView()
	case settingsState:
		content = m.settingsView()
	case socialState:
		content = m.socialView()
	default:
		content = "unknown state"
	}

	if m.width > 0 {
		return lipgloss.Place(m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			content,
		)
	}
	return lipgloss.NewStyle().PaddingTop(1).PaddingLeft(4).Render(content)
}

func (m model) menuView() string {
	logo := strings.Join([]string{
		" ▄▄▄▄   ▄▀▀▄   ▄▄▄▄▄   ▄▄▄▄  ▄▀▀▄  █▄▀█▄ ",
		"▄█ ▀▀  ▄█  █▄ ██   ▒█ ▄█ ▀▀ ▓█  █▄ ▓█  █▄",
		"██     ██  ██ ▀▀▄▄▄   ██    ██  ██ ██  ██",
		"▓▓▐▀██ ██  ██   ▀▀▀▒▄ ▓▓    ██▀▀██ ██  ██",
		"▓▓  ▄▄ ▓▓  ▓▓ ▄▄   ▓▓ ▓▓    ▓▓  ▓▓ ▓▓  ▓▓",
		"▀█  ▓▓ ▀█  █▀ ▀█   ██ ▀█    ██  ██ ██  ██",
		" ▀▀▀ ▀  ▀▄▄▀   ▀▀██▀   ▀▀▀  ▀▀  ██ ▀▀  ██",
	}, "\n")

	version := "0.1.0 — 64 Modules"
	tagline := "Pentest suite by orpheus"
	github := lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Render("GitHub")
	discord := lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Render("Discord")

	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(colorLogo(logo)))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render(fmt.Sprintf("  %s  •  %s", version, tagline)))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render(
		fmt.Sprintf("  %s  •  %s", github+" github.com/OrpheusW3B", discord+" p7f0"),
	))
	b.WriteString("\n\n")

	for i, item := range m.menuItems {
		cursor := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("#c9d1d9"))
		if i == m.menuCursor {
			cursor = lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Bold(true).Render("▸")
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Bold(true)
		}
		itemStr := item
		if i < len(m.menuItems)-1 {
			itemStr = "  " + item
		} else {
			itemStr = "  " + item
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", cursor, style.Render(itemStr)))
	}

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("  ↑/↓ navigate  •  Enter select  •  q quit"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d")).
		Padding(1, 2).
		Render(b.String())
}

func (m model) targetInputView() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#a855f7")).Render("Target URL"))
	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render("Enter target URL (e.g., https://example.com):"))
	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#f0f6fc")).Render("▸ " + m.targetInput))
	if time.Now().UnixMilli()/500%2 == 0 {
		b.WriteString("█")
	}
	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("Enter to start  •  Esc to go back"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d")).
		Padding(1, 2).
		Width(50).
		Render(b.String())
}

func (m model) customizeView() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#a855f7")).Render("Custom Scan — Module Selection"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render("Space to toggle  •  Enter when done"))
	b.WriteString("\n\n")

	for i, mod := range m.modules {
		cursor := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("#c9d1d9"))
		if i == m.moduleCursor {
			cursor = lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Bold(true).Render("▸")
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Bold(true)
		}
		check := lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("[ ]")
		if mod.enabled {
			check = lipgloss.NewStyle().Foreground(lipgloss.Color("#3fb950")).Render("[✓]")
		}
		b.WriteString(fmt.Sprintf("  %s %s %s\n", cursor, check, style.Render(mod.name)))
	}

	cursor := "  "
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("#c9d1d9"))
	if m.moduleCursor == len(m.modules) {
		cursor = lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Bold(true).Render("▸")
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Bold(true)
	}
	b.WriteString(fmt.Sprintf("\n  %s %s\n", cursor, style.Render("▶  Start Scan")))

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("  Esc to go back"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d")).
		Padding(1, 2).
		Render(b.String())
}

func (m model) runningView() string {
	elapsed := time.Since(m.scanStartTime).Truncate(time.Second).String()

	var header strings.Builder
	header.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#a855f7")).Render("SCAN IN PROGRESS"))
	header.WriteString("\n")
	header.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render(fmt.Sprintf(
		"Target: %s  •  Elapsed: %s",
		lipgloss.NewStyle().Foreground(lipgloss.Color("#f0f6fc")).Render(m.cfg.Target),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#d29922")).Render(elapsed),
	)))

	var db strings.Builder
	doneCount := 0
	totalCount := 0
	for _, mod := range m.modulesList {
		if mod.Name == "" {
			continue
		}
		totalCount++

		var dot, status, detail string
		switch mod.Status {
		case moduleDone:
			dot = lipgloss.NewStyle().SetString("●").Foreground(lipgloss.Color("#3fb950")).String()
			status = lipgloss.NewStyle().Foreground(lipgloss.Color("#3fb950")).Render("DONE")
			detail = lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render(mod.Detail)
			doneCount++
		case moduleRunning:
			dot = lipgloss.NewStyle().SetString("●").Foreground(lipgloss.Color("#d29922")).String()
			status = lipgloss.NewStyle().Foreground(lipgloss.Color("#d29922")).Render("RUNNING")
			detail = lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render(mod.Detail)
		case moduleError:
			dot = lipgloss.NewStyle().SetString("●").Foreground(lipgloss.Color("#f85149")).String()
			status = lipgloss.NewStyle().Foreground(lipgloss.Color("#f85149")).Render("ERROR")
			detail = lipgloss.NewStyle().Foreground(lipgloss.Color("#f85149")).Render(mod.Detail)
			doneCount++
		case moduleSkipped:
			dot = lipgloss.NewStyle().SetString("○").Foreground(lipgloss.Color("#484f58")).String()
			status = lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("SKIP")
		default:
			dot = lipgloss.NewStyle().SetString("○").Foreground(lipgloss.Color("#484f58")).String()
			status = lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("WAIT")
		}

		name := lipgloss.NewStyle().Width(14).Render(mod.Name)
		db.WriteString(fmt.Sprintf("  %s  %s  %s  %s\n", dot, name, status, detail))
	}

	progressRatio := 0.0
	if totalCount > 0 {
		progressRatio = float64(doneCount) / float64(totalCount)
	}
	barWidth := 30
	filled := int(float64(barWidth) * progressRatio)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	barStr := lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Render(bar)

	progressLine := fmt.Sprintf("  %s  %d/%d modules complete  (%d%%)",
		barStr, doneCount, totalCount, int(progressRatio*100))

	spinnerView := m.spinner.View()

	var statusLines []string
	start := 0
	if len(m.statusMsgs) > 3 {
		start = len(m.statusMsgs) - 3
	}
	for _, msg := range m.statusMsgs[start:] {
		statusLines = append(statusLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#79c0ff")).Render("  • "+msg))
	}
	statusBlock := strings.Join(statusLines, "\n")

	footer := lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("  q/Ctrl+C to cancel")
	if m.scanDone {
		footer = lipgloss.NewStyle().Foreground(lipgloss.Color("#3fb950")).Render("  ✓ Scan complete!  Press Enter for results")
	}

	var full strings.Builder
	full.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(header.String()))
	full.WriteString("\n\n")
	full.WriteString(db.String())
	full.WriteString("\n")
	full.WriteString(progressLine)
	full.WriteString("\n\n")
	if !m.scanDone {
		full.WriteString(fmt.Sprintf("  %s Scanning...\n", spinnerView))
	}
	if statusBlock != "" {
		full.WriteString(statusBlock)
		full.WriteString("\n")
	}
	full.WriteString(footer)

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d")).
		Padding(1, 2).
		Width(70).
		Render(full.String())
}

func (m model) resultsView() string {
	if m.result == nil {
		return lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#30363d")).
			Padding(1, 2).
			Render(
				lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#a855f7")).Render("No Report Available") + "\n\n" +
					lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render("Run a scan first to view results.") + "\n\n" +
					lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("Press Esc to go back"),
			)
	}

	if m.showRawJSON {
		return m.rawJSONView()
	}

	var b strings.Builder

	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#a855f7")).Render("SCAN RESULTS"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render(fmt.Sprintf(
		"Target: %s  •  IP: %s  •  Duration: %s",
		lipgloss.NewStyle().Foreground(lipgloss.Color("#f0f6fc")).Render(m.result.Target),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#f0f6fc")).Render(m.result.IP),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#d29922")).Render(m.result.Duration),
	)))
	b.WriteString("\n\n")

	modules := []struct {
		name   string
		status string
		detail string
	}{
		{"Port Scan", "", ""},
		{"DNS", "", ""},
		{"Subdomains", "", ""},
		{"Email", "", ""},
		{"WHOIS", "", ""},
		{"SSL/TLS", "", ""},
		{"HTTP", "", ""},
		{"Directories", "", ""},
		{"Technologies", "", ""},
		{"GeoIP", "", ""},
		{"Traceroute", "", ""},
		{"Login Bruteforce", "", ""},
	}

	r := m.result
	vals := []string{
		itemOr(r.PortScan != nil, fmt.Sprintf("%d open ports", r.PortScan.TotalFound), "skipped"),
		itemOr(r.DNS != nil, fmt.Sprintf("%d record types", len(r.DNS.Records)), "skipped"),
		itemOr(r.Subdomain != nil, fmt.Sprintf("%d found", r.Subdomain.TotalFound), "skipped"),
		emailSummary(r.Email),
		itemOr(r.Whois != nil, fmt.Sprintf("%s / %s", r.Whois.Registrar, r.Whois.Country), "skipped"),
		sslSummary(r.SSL),
		itemOr(r.HTTP != nil, fmt.Sprintf("status %d, %s", r.HTTP.StatusCode, r.HTTP.Server), "skipped"),
		itemOr(r.Directory != nil, fmt.Sprintf("%d found", r.Directory.TotalFound), "skipped"),
		itemOr(r.Tech != nil, fmt.Sprintf("%d detected", len(r.Tech.Technologies)), "skipped"),
		itemOr(r.GeoIP != nil, fmt.Sprintf("%s, %s", r.GeoIP.Country, r.GeoIP.ISP), "skipped"),
		itemOr(r.Traceroute != nil, fmt.Sprintf("%d hops", r.Traceroute.Total), "skipped"),
		itemOr(r.LoginBruteforce != nil, fmt.Sprintf("%d found / %d attempts", len(r.LoginBruteforce.Found), r.LoginBruteforce.TotalAttempts), "skipped"),
	}

	for i, mod := range modules {
		dot := lipgloss.NewStyle().SetString("●").Foreground(lipgloss.Color("#3fb950")).String()
		if strings.Contains(vals[i], "skipped") {
			dot = lipgloss.NewStyle().SetString("○").Foreground(lipgloss.Color("#484f58")).String()
		}
		name := lipgloss.NewStyle().Width(16).Render(mod.name)
		val := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render(vals[i])
		b.WriteString(fmt.Sprintf("  %s  %s %s\n", dot, name, val))
	}

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("  r toggle JSON  •  Esc back  •  q quit"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d")).
		Padding(1, 2).
		Render(b.String())
}

func (m model) rawJSONView() string {
	var b strings.Builder

	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#a855f7")).Render("RAW SUMMARY"))
	b.WriteString("\n\n")

	r := m.result

	summary := [][2]string{
		{"Target", r.Target},
		{"Host", r.Host},
		{"IP", r.IP},
		{"Duration", r.Duration},
		{"Start", r.StartTime.Format("15:04:05")},
		{"End", r.EndTime.Format("15:04:05")},
	}

	for _, kv := range summary {
		b.WriteString(fmt.Sprintf("  %s: %s\n",
			lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Width(12).Render(kv[0]),
			lipgloss.NewStyle().Foreground(lipgloss.Color("#c9d1d9")).Render(kv[1]),
		))
	}

	b.WriteString("\n")

	entries := []struct {
		name string
		line string
	}{
		{"Port Scan", itemOr(r.PortScan != nil, fmt.Sprintf("Open:%d Scanned:%d", r.PortScan.TotalFound, r.PortScan.Scanned), "skipped")},
		{"DNS", itemOr(r.DNS != nil, fmt.Sprintf("A:%d AAAA:%d MX:%d NS:%d TXT:%d SOA:%v DNSSEC:%s ZT:%v",
			len(r.DNS.ARecords), len(r.DNS.AAAARecords), len(r.DNS.MXRecords), len(r.DNS.NSRecords), len(r.DNS.TXTRecords),
			r.DNS.SOARecord != nil, r.DNS.DNSSEC, r.DNS.ZoneTransfer != nil && r.DNS.ZoneTransfer.Success), "skipped")},
		{"Subdomains", itemOr(r.Subdomain != nil, fmt.Sprintf("Found:%d Methods:%s", r.Subdomain.TotalFound, strings.Join(r.Subdomain.Methods, ",")), "skipped")},
		{"Email", emailSummary(r.Email)},
		{"WHOIS", itemOr(r.Whois != nil, fmt.Sprintf("Reg:%s Org:%s Country:%s Created:%s Expires:%s",
			r.Whois.Registrar, r.Whois.Org, r.Whois.Country, r.Whois.CreatedDate, r.Whois.ExpiryDate), "skipped")},
		{"SSL", sslSummary(r.SSL)},
		{"HTTP", itemOr(r.HTTP != nil, fmt.Sprintf("Status:%d Server:%s CT:%s Len:%d Time:%s",
			r.HTTP.StatusCode, r.HTTP.Server, r.HTTP.ContentType, r.HTTP.ContentLength, r.HTTP.ResponseTime), "skipped")},
		{"Directories", itemOr(r.Directory != nil, fmt.Sprintf("Found:%d Scanned:%d", r.Directory.TotalFound, r.Directory.Scanned), "skipped")},
		{"Tech", itemOr(r.Tech != nil, fmt.Sprintf("Detected:%d", len(r.Tech.Technologies)), "skipped")},
		{"GeoIP", itemOr(r.GeoIP != nil, fmt.Sprintf("Country:%s City:%s ISP:%s ASN:%s Lat:%.2f Lon:%.2f",
			r.GeoIP.Country, r.GeoIP.City, r.GeoIP.ISP, r.GeoIP.ASN, r.GeoIP.Latitude, r.GeoIP.Longitude), "skipped")},
		{"Traceroute", itemOr(r.Traceroute != nil, fmt.Sprintf("Hops:%d Success:%v", r.Traceroute.Total, r.Traceroute.Success), "skipped")},
		{"Login Bruteforce", itemOr(r.LoginBruteforce != nil, fmt.Sprintf("Attempts:%d Found:%d", r.LoginBruteforce.TotalAttempts, len(r.LoginBruteforce.Found)), "skipped")},
	}

	for _, e := range entries {
		val := e.line
		if strings.Contains(val, "skipped") {
			val = lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render(val)
		} else {
			val = lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render(val)
		}
		b.WriteString(fmt.Sprintf("  %s: %s\n",
			lipgloss.NewStyle().Foreground(lipgloss.Color("#c9d1d9")).Width(14).Render(e.name),
			val,
		))
	}

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("  Files: output/scan_result.json  •  output/scan_report.html"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("  r toggle  •  Esc back"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d")).
		Padding(1, 2).
		Render(b.String())
}

func (m model) settingsView() string {
	var b strings.Builder

	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#a855f7")).Render("Settings"))
	b.WriteString("\n\n")

	for i, item := range m.settingsItems {
		cursor := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("#c9d1d9"))
		if i == m.settingsCursor {
			cursor = lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Bold(true).Render("▸")
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#a855f7")).Bold(true)
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", cursor, style.Render(item)))
	}

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("  ↑/↓ navigate  •  Enter select  •  Esc back"))

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d")).
		Padding(1, 2).
		Render(b.String())
}

func (m model) socialView() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#a855f7")).Render("Social"))
	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render("Connect with me:"))
	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#c9d1d9")).Render(
		"  GitHub  —  github.com/OrpheusW3B",
	))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#c9d1d9")).Render(
		"  Discord —  p7f0",
	))
	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58")).Render("  Esc back"))
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d")).
		Padding(1, 2).
		Render(b.String())
}

func purpleGradient(col, maxCol int) string {
	t := 0.0
	if maxCol > 0 {
		t = float64(col) / float64(maxCol)
	}
	r := int((0x2a*(1-t) + 0xa8*t) * 255 / 255)
	g := int((0x0a*(1-t) + 0x55*t) * 255 / 255)
	b := int((0x4e*(1-t) + 0xf7*t) * 255 / 255)
	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

func colorLogo(logo string) string {
	lines := strings.Split(logo, "\n")
	maxW := 0
	for _, line := range lines {
		if len(line) > maxW {
			maxW = len(line)
		}
	}
	var out strings.Builder
	for _, line := range lines {
		for col, ch := range line {
			c := purpleGradient(col, maxW)
			out.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Render(string(ch)))
		}
		out.WriteString("\n")
	}
	return strings.TrimRight(out.String(), "\n")
}


func itemOr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func emailSummary(r *scanner.EmailResult) string {
	if r == nil {
		return "skipped"
	}
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

func sslSummary(r *scanner.SSLResult) string {
	if r == nil {
		return "skipped"
	}
	v := "ok"
	if r.Expired {
		v = "expired"
	} else if !r.Valid {
		v = "invalid"
	}
	return fmt.Sprintf("%s, ciphers:%d protocols:%d vulns:%d", v, len(r.CipherSuites), len(r.Protocols), len(r.Vulnerabilities))
}
