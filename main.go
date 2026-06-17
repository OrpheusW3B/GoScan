package main

import (
	"fmt"
	"os"

	"SCANNER/config"
	"SCANNER/scanner"
	"SCANNER/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	if len(os.Args) > 1 {
		cliMode(os.Args[1:])
		return
	}

	p := tea.NewProgram(tui.InitialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func cliMode(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: SCANNER <target-url> [flags]")
		fmt.Println("       SCANNER (for TUI mode)")
		os.Exit(1)
	}

	target := args[0]
	fmt.Printf("SCANNER — Target: %s\n\n", target)

	cfg := config.DefaultConfig()
	cfg.Target = target

	fmt.Println("Starting full scan...")

	runner := scanner.NewRunner(cfg)
	runner.OnStatus = func(msg string) {
		fmt.Println("  • " + msg)
	}

	result, err := runner.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("            SCAN COMPLETE")
	fmt.Println("========================================")
	fmt.Printf("Target:    %s\n", result.Target)
	fmt.Printf("Host:      %s\n", result.Host)
	fmt.Printf("IP:        %s\n", result.IP)
	fmt.Printf("Duration:  %s\n", result.Duration)

	if result.PortScan != nil {
		fmt.Printf("Port Scan: %d open ports\n", result.PortScan.TotalFound)
	}
	if result.DNS != nil {
		fmt.Printf("DNS: %d record types, DNSSEC: %s\n", len(result.DNS.Records), result.DNS.DNSSEC)
	}
	if result.Subdomain != nil {
		fmt.Printf("Subdomains: %d found\n", result.Subdomain.TotalFound)
	}
	if result.Email != nil {
		spf := "no"
		if result.Email.SPFRecord != nil && result.Email.SPFRecord.Exists {
			spf = "yes"
		}
		dmarc := "no"
		if result.Email.DMARCRecord != nil && result.Email.DMARCRecord.Exists {
			dmarc = "yes"
		}
		fmt.Printf("Email: SPF=%s DMARC=%s DKIM=%d\n", spf, dmarc, len(result.Email.DKIMRecords))
	}
	if result.Whois != nil {
		fmt.Printf("WHOIS: %s / %s\n", result.Whois.Registrar, result.Whois.Country)
	}
	if result.SSL != nil {
		fmt.Printf("SSL: valid=%v expired=%v protocols=%d\n", result.SSL.Valid, result.SSL.Expired, len(result.SSL.Protocols))
	}
	if result.HTTP != nil {
		fmt.Printf("HTTP: status=%d server=%s\n", result.HTTP.StatusCode, result.HTTP.Server)
	}
	if result.Directory != nil {
		fmt.Printf("Directories: %d found\n", result.Directory.TotalFound)
	}
	if result.Tech != nil {
		fmt.Printf("Technologies: %d\n", len(result.Tech.Technologies))
	}
	if result.GeoIP != nil {
		fmt.Printf("GeoIP: %s / %s\n", result.GeoIP.Country, result.GeoIP.ISP)
	}
	if result.Traceroute != nil {
		fmt.Printf("Traceroute: %d hops\n", result.Traceroute.Total)
	}

	fmt.Println()
	fmt.Println("Output saved to output/ directory")
	fmt.Println("  - output/scan_result.json")
	fmt.Println("  - output/scan_report.html")
}
