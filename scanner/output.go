package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func SaveJSON(path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal error: %v", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(path, jsonData, 0644); err != nil {
		return fmt.Errorf("write error: %v", err)
	}
	return nil
}

func LoadJSON(path string, target interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func GenerateHTML(path string, result *ScanResult) error {
	tmplSrc := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SCANNER Report - {{.Target}}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 20px; }
.container { max-width: 1200px; margin: 0 auto; }
.header { background: linear-gradient(135deg, #1f2937, #111827); padding: 30px; border-radius: 12px; margin-bottom: 24px; border: 1px solid #30363d; }
.header h1 { font-size: 24px; color: #58a6ff; }
.header .meta { color: #8b949e; font-size: 14px; margin-top: 8px; }
.section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
.section h2 { font-size: 18px; color: #f0f6fc; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #30363d; }
.section h3 { font-size: 15px; color: #79c0ff; margin: 12px 0 8px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 14px; }
th { color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }
td { color: #c9d1d9; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.badge-open { background: #1a3a2a; color: #3fb950; }
.badge-closed { background: #3d1f1f; color: #f85149; }
.badge-secure { background: #1a3a2a; color: #3fb950; }
.badge-insecure { background: #3d1f1f; color: #f85149; }
.badge-warn { background: #3d2e00; color: #d29922; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
.footer { text-align: center; color: #484f58; font-size: 12px; padding: 20px; }
.key-val { margin: 4px 0; font-size: 14px; }
.key-val .key { color: #8b949e; }
.key-val .val { color: #c9d1d9; }
ul { list-style: none; }
ul li { padding: 4px 0; font-size: 14px; }
ul li:before { content: "\2022"; color: #58a6ff; margin-right: 8px; }
pre { background: #0d1117; padding: 12px; border-radius: 6px; font-size: 13px; overflow-x: auto; }
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>SCANNER Report: {{.Target}}</h1>
<div class="meta">
Target: {{.Target}} | Host: {{.Host}} | IP: {{.IP}}<br>
Duration: {{.Duration}} | Started: {{.StartTime.Format "2006-01-02 15:04:05"}} | Ended: {{.EndTime.Format "2006-01-02 15:04:05"}}
</div>
</div>

{{if .PortScan}}
<div class="section">
<h2>Port Scan</h2>
<p>Found <strong>{{.PortScan.TotalFound}}</strong> open ports (scanned {{.PortScan.Scanned}})</p>
{{if .PortScan.OpenPorts}}
<table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Banner</th></tr></thead>
<tbody>{{range .PortScan.OpenPorts}}
<tr><td>{{.Port}}</td><td>{{.Protocol}}</td><td>{{.Service}}</td><td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;">{{.Banner}}</td></tr>
{{end}}</tbody></table>{{else}}<p>No open ports found.</p>{{end}}
</div>
{{end}}

{{if .DNS}}
<div class="section">
<h2>DNS Records</h2>
<div class="grid-2">
<div><h3>A Records</h3>{{if .DNS.ARecords}}<ul>{{range .DNS.ARecords}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>None</p>{{end}}</div>
<div><h3>AAAA Records</h3>{{if .DNS.AAAARecords}}<ul>{{range .DNS.AAAARecords}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>None</p>{{end}}</div>
<div><h3>MX Records</h3>{{if .DNS.MXRecords}}<ul>{{range .DNS.MXRecords}}<li>{{.Host}} (priority {{.Priority}})</li>{{end}}</ul>{{else}}<p>None</p>{{end}}</div>
<div><h3>NS Records</h3>{{if .DNS.NSRecords}}<ul>{{range .DNS.NSRecords}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>None</p>{{end}}</div>
<div><h3>TXT Records</h3>{{if .DNS.TXTRecords}}<ul>{{range .DNS.TXTRecords}}<li style="word-break:break-all;">{{.}}</li>{{end}}</ul>{{else}}<p>None</p>{{end}}</div>
<div><h3>CNAME Records</h3>{{if .DNS.CNAMERecords}}<ul>{{range .DNS.CNAMERecords}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>None</p>{{end}}</div>
</div>
<h3>SOA Record</h3>{{if .DNS.SOARecord}}<p>MName: {{.DNS.SOARecord.MName}} | RName: {{.DNS.SOARecord.RName}} | Serial: {{.DNS.SOARecord.Serial}}</p>{{else}}<p>None</p>{{end}}
<h3>DNSSEC</h3><p>{{.DNS.DNSSEC}}</p>
<h3>Zone Transfer</h3>{{if .DNS.ZoneTransfer.Success}}<p class="badge badge-warn">VULNERABLE - Zone transfer allowed!</p><ul>{{range .DNS.ZoneTransfer.Records}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>Zone transfer: {{.DNS.ZoneTransfer.Error}}</p>{{end}}
</div>
{{end}}

{{if .Subdomain}}
<div class="section">
<h2>Subdomains ({{.Subdomain.TotalFound}})</h2>
<p>Methods: {{join .Subdomain.Methods ", "}}</p>
{{if .Subdomain.Subdomains}}
<table><thead><tr><th>Subdomain</th><th>IPs</th><th>Source</th></tr></thead>
<tbody>{{range .Subdomain.Subdomains}}<tr><td>{{.Subdomain}}</td><td>{{join .IPs ", "}}</td><td>{{.Source}}</td></tr>{{end}}</tbody></table>{{else}}<p>No subdomains found.</p>{{end}}
</div>
{{end}}

{{if .Email}}
<div class="section">
<h2>Email / Mail Security</h2>
<div class="grid-2">
<div><h3>SPF Record</h3>{{if .Email.SPFRecord.Exists}}<p class="badge badge-secure">Exists</p><p>{{.Email.SPFRecord.Raw}}</p>{{else}}<p class="badge badge-insecure">No SPF record</p>{{end}}</div>
<div><h3>DMARC Record</h3>{{if .Email.DMARCRecord.Exists}}<p class="badge badge-secure">Exists</p><p>Policy: {{.Email.DMARCRecord.Policy}}</p>{{else}}<p class="badge badge-insecure">No DMARC record</p>{{end}}</div>
</div>
<h3>DKIM Records</h3>{{if .Email.DKIMRecords}}<ul>{{range .Email.DKIMRecords}}<li>Selector '{{.Selector}}': exists</li>{{end}}</ul>{{else}}<p>No DKIM records found.</p>{{end}}
<h3>SMTP Check</h3>{{if .Email.SMTPCheck}}<p>Banner: {{.Email.SMTPCheck.Banner}}</p>{{if .Email.SMTPCheck.OpenRelay}}<p class="badge badge-warn">OPEN RELAY DETECTED</p>{{else}}<p class="badge badge-secure">Not open relay</p>{{end}}{{end}}
</div>
{{end}}

{{if .Whois}}
<div class="section">
<h2>WHOIS Information</h2>
<div class="grid-2">
<div><p class="key-val"><span class="key">Domain:</span> <span class="val">{{.Whois.Domain}}</span></p></div>
<div><p class="key-val"><span class="key">Registrar:</span> <span class="val">{{.Whois.Registrar}}</span></p></div>
<div><p class="key-val"><span class="key">Organization:</span> <span class="val">{{.Whois.Org}}</span></p></div>
<div><p class="key-val"><span class="key">Country:</span> <span class="val">{{.Whois.Country}}</span></p></div>
<div><p class="key-val"><span class="key">Created:</span> <span class="val">{{.Whois.CreatedDate}}</span></p></div>
<div><p class="key-val"><span class="key">Expires:</span> <span class="val">{{.Whois.ExpiryDate}}</span></p></div>
</div>
{{if .Whois.NameServers}}<h3>Name Servers</h3><ul>{{range .Whois.NameServers}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Whois.Emails}}<h3>Emails</h3><ul>{{range .Whois.Emails}}<li>{{.}}</li>{{end}}</ul>{{end}}
</div>
{{end}}

{{if .SSL}}
<div class="section">
<h2>SSL/TLS Certificate</h2>
<div class="grid-2">
<div><p class="key-val"><span class="key">Subject:</span> <span class="val">{{.SSL.Subject}}</span></p></div>
<div><p class="key-val"><span class="key">Issuer:</span> <span class="val">{{.SSL.Issuer}}</span></p></div>
<div><p class="key-val"><span class="key">Valid:</span> <span class="val">{{if .SSL.Valid}}<span class="badge badge-secure">Valid</span>{{else}}<span class="badge badge-insecure">Invalid</span>{{end}}</span></p></div>
<div><p class="key-val"><span class="key">Not Before:</span> <span class="val">{{.SSL.NotBefore}}</span></p></div>
<div><p class="key-val"><span class="key">Not After:</span> <span class="val">{{.SSL.NotAfter}}</span></p></div>
</div>
{{if .SSL.SAN}}<h3>Subject Alternative Names</h3><ul>{{range .SSL.SAN}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .SSL.Protocols}}<h3>Supported Protocols</h3><ul>{{range .SSL.Protocols}}<li>{{.}}</li>{{end}}</ul>{{end}}
</div>
{{end}}

{{if .HTTP}}
<div class="section">
<h2>HTTP Analysis</h2>
<div class="grid-2">
<div><p class="key-val"><span class="key">Status:</span> <span class="val">{{.HTTP.StatusCode}} {{.HTTP.StatusText}}</span></p></div>
<div><p class="key-val"><span class="key">Server:</span> <span class="val">{{.HTTP.Server}}</span></p></div>
<div><p class="key-val"><span class="key">Content-Type:</span> <span class="val">{{.HTTP.ContentType}}</span></p></div>
<div><p class="key-val"><span class="key">Response Time:</span> <span class="val">{{.HTTP.ResponseTime}}</span></p></div>
</div>
<h3>Security Headers</h3>
<table><thead><tr><th>Header</th><th>Value</th><th>Status</th></tr></thead>
<tbody>
{{$h := .HTTP.SecurityHeaders}}
<tr><td>Strict-Transport-Security</td><td>{{$h.StrictTransportSecurity}}</td><td>{{if $h.StrictTransportSecurity}}<span class="badge badge-secure">Present</span>{{else}}<span class="badge badge-insecure">Missing</span>{{end}}</td></tr>
<tr><td>Content-Security-Policy</td><td style="word-break:break-all;">{{$h.ContentSecurityPolicy}}</td><td>{{if $h.ContentSecurityPolicy}}<span class="badge badge-secure">Present</span>{{else}}<span class="badge badge-insecure">Missing</span>{{end}}</td></tr>
<tr><td>X-Frame-Options</td><td>{{$h.XFrameOptions}}</td><td>{{if $h.XFrameOptions}}<span class="badge badge-secure">Present</span>{{else}}<span class="badge badge-insecure">Missing</span>{{end}}</td></tr>
<tr><td>X-Content-Type-Options</td><td>{{$h.XContentTypeOptions}}</td><td>{{if $h.XContentTypeOptions}}<span class="badge badge-secure">Present</span>{{else}}<span class="badge badge-insecure">Missing</span>{{end}}</td></tr>
</tbody></table>
{{if .HTTP.Cookies}}<h3>Cookies</h3><table><thead><tr><th>Name</th><th>Secure</th><th>HTTP Only</th></tr></thead>
<tbody>{{range .HTTP.Cookies}}<tr><td>{{.Name}}</td><td>{{if .Secure}}<span class="badge badge-secure">Yes</span>{{else}}<span class="badge badge-insecure">No</span>{{end}}</td><td>{{if .HTTPOnly}}<span class="badge badge-secure">Yes</span>{{else}}<span class="badge badge-warn">No</span>{{end}}</td></tr>{{end}}</tbody></table>{{end}}
{{if .HTTP.RobotsTxt}}<h3>robots.txt</h3><pre>{{.HTTP.RobotsTxt}}</pre>{{end}}
</div>
{{end}}

{{if .Directory}}
<div class="section">
<h2>Directory Busting ({{.Directory.TotalFound}} found)</h2>
{{if .Directory.Found}}
<table><thead><tr><th>Path</th><th>Status</th><th>Size</th><th>Type</th></tr></thead>
<tbody>{{range .Directory.Found}}<tr><td>{{.Path}}</td><td>{{.StatusCode}}</td><td>{{.Size}}</td><td>{{.ContentType}}</td></tr>{{end}}</tbody></table>{{else}}<p>No directories found.</p>{{end}}
</div>
{{end}}

{{if .Tech}}
<div class="section">
<h2>Web Technologies ({{len .Tech.Technologies}})</h2>
<table><thead><tr><th>Technology</th><th>Category</th><th>Version</th><th>Confidence</th></tr></thead>
<tbody>{{range .Tech.Technologies}}<tr><td>{{.Name}}</td><td>{{.Category}}</td><td>{{.Version}}</td><td>{{.Confidence}}%</td></tr>{{end}}</tbody></table>
</div>
{{end}}

{{if .GeoIP}}
<div class="section">
<h2>GeoIP</h2>
<div class="grid-2">
<div><p class="key-val"><span class="key">IP:</span> <span class="val">{{.GeoIP.IP}}</span></p></div>
<div><p class="key-val"><span class="key">Country:</span> <span class="val">{{.GeoIP.Country}} ({{.GeoIP.CountryCode}})</span></p></div>
<div><p class="key-val"><span class="key">City:</span> <span class="val">{{.GeoIP.City}}</span></p></div>
<div><p class="key-val"><span class="key">ISP:</span> <span class="val">{{.GeoIP.ISP}}</span></p></div>
<div><p class="key-val"><span class="key">Organization:</span> <span class="val">{{.GeoIP.Org}}</span></p></div>
<div><p class="key-val"><span class="key">ASN:</span> <span class="val">{{.GeoIP.ASN}}</span></p></div>
</div>
</div>
{{end}}

{{if .LoginBruteforce}}
<div class="section">
<h2>Login Bruteforce ({{.LoginBruteforce.TotalAttempts}} attempts)</h2>
{{if .LoginBruteforce.Found}}
<table><thead><tr><th>Username</th><th>Password</th><th>URL</th><th>Method</th><th>Status</th></tr></thead>
<tbody>{{range .LoginBruteforce.Found}}
<tr><td>{{.Username}}</td><td>{{.Password}}</td><td>{{.URL}}</td><td>{{.Method}}</td><td><span class="badge badge-warn">{{.Status}}</span></td></tr>
{{end}}</tbody></table>{{else}}<p>No credentials found in common wordlist.</p>{{end}}
</div>
{{end}}

<div class="footer">SCANNER v1.0 - Generated {{.EndTime.Format "2006-01-02 15:04:05"}} | JSON: output/scan_result.json</div>
</div>
</body>
</html>`

	funcMap := template.FuncMap{
		"join": strings.Join,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(tmplSrc)
	if err != nil {
		return fmt.Errorf("template parse error: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, result); err != nil {
		return fmt.Errorf("template execute error: %v", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, buf.Bytes(), 0644)
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
