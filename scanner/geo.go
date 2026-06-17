package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type GeoConfig struct {
	Timeout time.Duration
}

func LookupGeoIP(ctx context.Context, ip string, cfg *GeoConfig) *GeoIPResult {
	if cfg == nil {
		cfg = &GeoConfig{Timeout: 10 * time.Second}
	}
	result := &GeoIPResult{
		IP: ip,
	}

	names, _ := net.LookupAddr(ip)
	if len(names) > 0 {
		result.Hostname = names[0]
	}

	client := &http.Client{Timeout: cfg.Timeout}
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "SCANNER/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var geoData struct {
		Country      string  `json:"country"`
		CountryCode  string  `json:"countryCode"`
		City         string  `json:"city"`
		ISP          string  `json:"isp"`
		Org          string  `json:"org"`
		ASN          string  `json:"as"`
		Latitude     float64 `json:"lat"`
		Longitude    float64 `json:"lon"`
		Timezone     string  `json:"timezone"`
		Query        string  `json:"query"`
		Status       string  `json:"status"`
	}

	if err := json.Unmarshal(body, &geoData); err != nil {
		return result
	}

	if geoData.Status == "success" {
		result.Country = geoData.Country
		result.CountryCode = geoData.CountryCode
		result.City = geoData.City
		result.ISP = geoData.ISP
		result.Org = geoData.Org
		result.ASN = geoData.ASN
		result.Latitude = geoData.Latitude
		result.Longitude = geoData.Longitude
		result.Timezone = geoData.Timezone
	}

	return result
}
