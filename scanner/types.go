package scanner

import (
	"net"
	"time"
)

type ScanResult struct {
	Target        string                `json:"target"`
	Host          string                `json:"host"`
	IP            string                `json:"ip"`
	StartTime     time.Time             `json:"start_time"`
	EndTime       time.Time             `json:"end_time"`
	Duration      string                `json:"duration"`
	PortScan        *PortScanResult        `json:"port_scan,omitempty"`
	DNS             *DNSResult             `json:"dns,omitempty"`
	Subdomain       *SubdomainResult       `json:"subdomain,omitempty"`
	Email           *EmailResult           `json:"email,omitempty"`
	Whois           *WhoisResult           `json:"whois,omitempty"`
	SSL             *SSLResult             `json:"ssl,omitempty"`
	HTTP            *HTTPResult            `json:"http,omitempty"`
	Directory       *DirectoryResult       `json:"directory,omitempty"`
	Tech            *TechResult            `json:"tech,omitempty"`
	GeoIP           *GeoIPResult           `json:"geoip,omitempty"`
	Traceroute      *TracerouteResult      `json:"traceroute,omitempty"`
	LoginBruteforce *LoginBruteforceResult `json:"login_bruteforce,omitempty"`
}

type PortScanResult struct {
	OpenPorts  []PortInfo `json:"open_ports"`
	TotalFound int        `json:"total_found"`
	Scanned    int        `json:"scanned"`
}

type PortInfo struct {
	Port    int    `json:"port"`
	Protocol string `json:"protocol"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
	State   string `json:"state"`
}

type DNSResult struct {
	Records      map[string][]string `json:"records"`
	ARecords     []string            `json:"a_records"`
	AAAARecords  []string            `json:"aaaa_records"`
	MXRecords    []MXRecord          `json:"mx_records"`
	NSRecords    []string            `json:"ns_records"`
	CNAMERecords []string            `json:"cname_records"`
	TXTRecords   []string            `json:"txt_records"`
	SOARecord    *SOARecord          `json:"soa_record,omitempty"`
	SRVRecords   []SRVRecord         `json:"srv_records"`
	CAARecords   []CAARecord         `json:"caa_records"`
	ZoneTransfer *ZoneTransferResult `json:"zone_transfer,omitempty"`
	DNSSEC       string              `json:"dnssec,omitempty"`
}

type MXRecord struct {
	Host     string `json:"host"`
	Priority int    `json:"priority"`
}

type SOARecord struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

type SRVRecord struct {
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
}

type CAARecord struct {
	Flag  int    `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

type ZoneTransferResult struct {
	Success   bool     `json:"success"`
	Records   []string `json:"records,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type SubdomainResult struct {
	Subdomains []SubdomainInfo `json:"subdomains"`
	TotalFound int             `json:"total_found"`
	Methods    []string        `json:"methods"`
}

type SubdomainInfo struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	Source    string   `json:"source"`
}

type EmailResult struct {
	MXRecords    []MXRecord    `json:"mx_records"`
	SPFRecord    *SPFResult    `json:"spf_record,omitempty"`
	DMARCRecord  *DMARCResult  `json:"dmarc_record,omitempty"`
	DKIMRecords  []DKIMResult  `json:"dkim_records"`
	SMTPCheck    *SMTPResult   `json:"smtp_check,omitempty"`
	EmailFormats []string      `json:"email_formats,omitempty"`
}

type SPFResult struct {
	Exists bool   `json:"exists"`
	Raw    string `json:"raw"`
	Valid  bool   `json:"valid"`
}

type DMARCResult struct {
	Exists bool   `json:"exists"`
	Raw    string `json:"raw"`
	Policy string `json:"policy"`
}

type DKIMResult struct {
	Selector string `json:"selector"`
	Exists   bool   `json:"exists"`
	Raw      string `json:"raw"`
}

type SMTPResult struct {
	OpenRelay bool   `json:"open_relay"`
	Banner    string `json:"banner"`
	Error     string `json:"error,omitempty"`
}

type WhoisResult struct {
	Domain      string   `json:"domain"`
	Registrar   string   `json:"registrar"`
	Org         string   `json:"org"`
	Country     string   `json:"country"`
	Emails      []string `json:"emails"`
	CreatedDate string   `json:"created_date"`
	ExpiryDate  string   `json:"expiry_date"`
	NameServers []string `json:"name_servers"`
	Raw         string   `json:"raw,omitempty"`
	IPWhois     string   `json:"ip_whois,omitempty"`
}

type SSLResult struct {
	Hostname          string           `json:"hostname"`
	Valid             bool             `json:"valid"`
	Expired           bool             `json:"expired"`
	Issuer            string           `json:"issuer"`
	Subject           string           `json:"subject"`
	SAN               []string         `json:"san"`
	Version           int              `json:"version"`
	NotBefore         string           `json:"not_before"`
	NotAfter          string           `json:"not_after"`
	Serial            string           `json:"serial"`
	SignatureAlgorithm string          `json:"signature_algorithm"`
	CipherSuites      []CipherInfo     `json:"cipher_suites"`
	Protocols         []string         `json:"protocols"`
	Vulnerabilities   []SSLVuln        `json:"vulnerabilities"`
	HSTSPreload       bool             `json:"hsts_preload"`
	CertChain         []CertInfo       `json:"cert_chain"`
}

type CertInfo struct {
	Subject  string   `json:"subject"`
	Issuer   string   `json:"issuer"`
	NotAfter string   `json:"not_after"`
	SAN      []string `json:"san,omitempty"`
}

type CipherInfo struct {
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	BitSize   int    `json:"bit_size"`
	Secure    bool   `json:"secure"`
}

type SSLVuln struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Vulnerable  bool   `json:"vulnerable"`
}

type HTTPResult struct {
	URL              string              `json:"url"`
	StatusCode       int                 `json:"status_code"`
	StatusText       string              `json:"status_text"`
	Server           string              `json:"server"`
	ContentType      string              `json:"content_type"`
	ContentLength    int64               `json:"content_length"`
	Headers          map[string][]string `json:"headers"`
	SecurityHeaders  SecHeaders          `json:"security_headers"`
	Cookies          []CookieInfo        `json:"cookies"`
	CORS             *CORSInfo           `json:"cors,omitempty"`
	RedirectChain    []string            `json:"redirect_chain"`
	ResponseTime     string              `json:"response_time"`
	RobotsTxt        string              `json:"robots_txt,omitempty"`
	SitemapXML       string              `json:"sitemap_xml,omitempty"`
	FaviconHash      string              `json:"favicon_hash,omitempty"`
}

type SecHeaders struct {
	StrictTransportSecurity string `json:"strict_transport_security"`
	ContentSecurityPolicy   string `json:"content_security_policy"`
	XFrameOptions           string `json:"x_frame_options"`
	XContentTypeOptions     string `json:"x_content_type_options"`
	XXSSProtection          string `json:"x_xss_protection"`
	ReferrerPolicy          string `json:"referrer_policy"`
	PermissionsPolicy       string `json:"permissions_policy"`
	CacheControl            string `json:"cache_control"`
	ExpectCT                string `json:"expect_ct"`
	AccessControlAllowOrigin string `json:"access_control_allow_origin"`
}

type CookieInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

type CORSInfo struct {
	AllowOrigin      string   `json:"allow_origin"`
	AllowMethods     []string `json:"allow_methods"`
	AllowHeaders     []string `json:"allow_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
}

type DirectoryResult struct {
	Found      []DirEntry `json:"found"`
	TotalFound int        `json:"total_found"`
	Scanned    int        `json:"scanned"`
}

type DirEntry struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	ContentType string `json:"content_type,omitempty"`
	Title      string `json:"title,omitempty"`
}

type TechResult struct {
	Technologies []TechInfo `json:"technologies"`
}

type TechInfo struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Version     string   `json:"version,omitempty"`
	Confidence  int      `json:"confidence"`
	Evidence    string   `json:"evidence,omitempty"`
}

type GeoIPResult struct {
	IP           string  `json:"ip"`
	Country      string  `json:"country"`
	CountryCode  string  `json:"country_code"`
	City         string  `json:"city"`
	ISP          string  `json:"isp"`
	Org          string  `json:"org"`
	ASN          string  `json:"asn"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	Timezone     string  `json:"timezone"`
	Hostname     string  `json:"hostname"`
}

type TracerouteResult struct {
	Hops   []HopInfo `json:"hops"`
	Total  int       `json:"total"`
	Success bool     `json:"success"`
}

type HopInfo struct {
	Hop      int    `json:"hop"`
	Host     string `json:"host,omitempty"`
	IP       net.IP `json:"ip"`
	RTT      string `json:"rtt"`
	Alive    bool   `json:"alive"`
}

type LoginBruteforceResult struct {
	TotalAttempts int              `json:"total_attempts"`
	Found         []CredentialFound `json:"found"`
	TestedUsers   []string          `json:"tested_users"`
	Error         string            `json:"error,omitempty"`
}

type CredentialFound struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Method   string `json:"method"`
	Status   int    `json:"status"`
}
