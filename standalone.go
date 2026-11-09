package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ==================== ZERO-VPS STANDALONE MODE (STUN + UPnP/NAT-PMP + DDNS) ====================

type DDNSConfig struct {
	Provider string
	Domain   string
	Token    string
	User     string
	ZoneID   string
	Webhook  string
}

type StandaloneConfig struct {
	TargetHost   string
	Mappings     []PortMapping
	VHostAddr    string
	HTTPSAddr    string
	DirectAddr   string
	VHostMap     map[string]uint16
	AllowedPorts map[uint16]struct{}
	EnableUPnP   bool
	EnableTLS    bool
	STUNServer   string
	STUNInterval time.Duration
	DDNS         DDNSConfig
	CertDir      string
	TLSCertFile  string
	TLSKeyFile   string
}

type cachedUDPAddr struct {
	addr      *net.UDPAddr
	expiresAt time.Time
}

var (
	stunCacheMu   sync.RWMutex
	stunAddrCache = make(map[string]cachedUDPAddr)
	stunFailCount atomic.Int32
)

func resolveSTUNAddr(stunAddr string) (*net.UDPAddr, error) {
	now := time.Now()
	stunCacheMu.RLock()
	entry, ok := stunAddrCache[stunAddr]
	stunCacheMu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.addr, nil
	}
	uaddr, err := net.ResolveUDPAddr("udp4", stunAddr)
	if err != nil {
		return nil, err
	}
	stunCacheMu.Lock()
	stunAddrCache[stunAddr] = cachedUDPAddr{
		addr:      uaddr,
		expiresAt: now.Add(5 * time.Minute),
	}
	stunCacheMu.Unlock()
	return uaddr, nil
}

func invalidateSTUNCache(stunAddr string) {
	stunCacheMu.Lock()
	delete(stunAddrCache, stunAddr)
	stunCacheMu.Unlock()
}

// querySTUNPublicIP performs a fast RFC 5389 UDP STUN Binding Request with cached DNS and Transaction ID validation.
func querySTUNPublicIP(stunAddr string, timeout time.Duration) (string, error) {
	perServerTimeout := timeout
	if perServerTimeout > 300*time.Millisecond {
		perServerTimeout = 300 * time.Millisecond
	}
	servers := []string{stunAddr, "stun.cloudflare.com:3478", "stun.l.google.com:19302", "stun1.l.google.com:19302"}
	seen := make(map[string]struct{}, len(servers))
	for _, srv := range servers {
		if srv == "" {
			continue
		}
		if _, dup := seen[srv]; dup {
			continue
		}
		seen[srv] = struct{}{}
		ip, err := singleSTUNQuery(srv, perServerTimeout)
		if err == nil && ip != "" {
			stunFailCount.Store(0)
			return ip, nil
		}
		invalidateSTUNCache(srv)
	}
	// Only fall back to HTTP if UDP STUN failed on startup or 3 consecutive times
	if stunFailCount.Add(1) >= 3 {
		if ip := detectPublicIP(); ip != "" {
			stunFailCount.Store(0)
			return ip, nil
		}
	}
	return "", errors.New("stun public IP detection failed")
}

func singleSTUNQuery(stunAddr string, timeout time.Duration) (string, error) {
	raddr, err := resolveSTUNAddr(stunAddr)
	if err != nil {
		return "", err
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// RFC 5389 Binding Request (20 bytes):
	// Type 0x0001, Length 0x0000, Magic Cookie 0x2112A442, 12-byte random Transaction ID
	var req [20]byte
	binary.BigEndian.PutUint16(req[0:2], 0x0001)
	binary.BigEndian.PutUint16(req[2:4], 0x0000)
	binary.BigEndian.PutUint32(req[4:8], 0x2112A442)
	if _, err := rand.Read(req[8:20]); err != nil {
		return "", err
	}

	if _, err := conn.Write(req[:]); err != nil {
		return "", err
	}
	var resp [512]byte
	n, err := conn.Read(resp[:])
	if err != nil || n < 20 {
		return "", errors.New("short stun response")
	}
	// Verify Binding Success Response (0x0101), Magic Cookie (0x2112A442), and matching 12-byte Transaction ID
	if binary.BigEndian.Uint16(resp[0:2]) != 0x0101 ||
		binary.BigEndian.Uint32(resp[4:8]) != 0x2112A442 ||
		!bytes.Equal(resp[8:20], req[8:20]) {
		return "", errors.New("invalid stun response header or transaction id mismatch")
	}
	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	if 20+msgLen > n {
		msgLen = n - 20
	}
	offset := 20
	for offset+4 <= 20+msgLen {
		attrType := binary.BigEndian.Uint16(resp[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(resp[offset+2 : offset+4]))
		valStart := offset + 4
		if valStart+attrLen > n {
			break
		}
		val := resp[valStart : valStart+attrLen]
		// 0x0020 = XOR-MAPPED-ADDRESS, 0x0001 = MAPPED-ADDRESS, 0x8020 = XOR-MAPPED-ADDRESS (legacy)
		if (attrType == 0x0020 || attrType == 0x8020) && attrLen >= 8 && val[1] == 0x01 {
			var ipBytes [4]byte
			cookie := [4]byte{0x21, 0x12, 0xA4, 0x42}
			for i := 0; i < 4; i++ {
				ipBytes[i] = val[4+i] ^ cookie[i]
			}
			ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
			if !ip.IsLoopback() && !ip.IsUnspecified() {
				return ip.String(), nil
			}
		} else if attrType == 0x0001 && attrLen >= 8 && val[1] == 0x01 {
			ip := net.IPv4(val[4], val[5], val[6], val[7])
			if !ip.IsLoopback() && !ip.IsUnspecified() {
				return ip.String(), nil
			}
		}
		// STUN attributes are padded to 4-byte boundaries
		padded := (attrLen + 3) & ^3
		offset = valStart + padded
	}
	return "", errors.New("no mapped address in stun packet")
}

type upnpEndpoint struct {
	ctrlURL     string
	serviceType string
}

// autoForwardRouterPorts maps public ports on the home router using UPnP IGD (WANPPPConnection & WANIPConnection) and NAT-PMP.
func autoForwardRouterPorts(lanIP string, mappings []PortMapping, vhostAddr, httpsAddr string) int {
	type portSpec struct {
		port  uint16
		proto string
	}
	seen := make(map[string]struct{})
	var specs []portSpec
	addSpec := func(p uint16, proto string) {
		if p == 0 {
			return
		}
		k := fmt.Sprintf("%s:%d", proto, p)
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			specs = append(specs, portSpec{port: p, proto: proto})
		}
	}
	for _, m := range mappings {
		if m.Proto == "udp" {
			addSpec(m.PublicPort, "UDP")
		} else if m.Proto == "both" {
			addSpec(m.PublicPort, "TCP")
			addSpec(m.PublicPort, "UDP")
		} else {
			addSpec(m.PublicPort, "TCP")
		}
	}
	for _, addr := range []string{vhostAddr, httpsAddr} {
		if addr != "" {
			if _, portStr, err := net.SplitHostPort(addr); err == nil {
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
					addSpec(uint16(p), "TCP")
				}
			}
		}
	}

	mappedCount := 0
	endpoints := discoverUPnPEndpoints(1200 * time.Millisecond)
	gwIP := guessDefaultGatewayIP(lanIP)

	for _, sp := range specs {
		ok := false
		for _, ep := range endpoints {
			if err := upnpAddPortMapping(ep.ctrlURL, ep.serviceType, lanIP, sp.port, sp.proto); err == nil {
				ok = true
			}
		}
		if !ok && gwIP != "" {
			if err := natPMPAddPortMapping(gwIP, sp.port, sp.proto); err == nil {
				ok = true
			}
		}
		if ok {
			mappedCount++
		}
	}
	return mappedCount
}

func discoverUPnPEndpoints(timeout time.Duration) []upnpEndpoint {
	ssdpAddr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return nil
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	targets := []string{
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANIPConnection:2",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	}
	for _, st := range targets {
		req := fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: %s\r\n\r\n", st)
		_, _ = conn.WriteToUDP([]byte(req), ssdpAddr)
	}

	var locations []string
	seenLoc := make(map[string]struct{})
	var buf [2048]byte
	for i := 0; i < 4; i++ {
		n, _, err := conn.ReadFromUDP(buf[:])
		if err != nil || n == 0 {
			break
		}
		lines := strings.Split(string(buf[:n]), "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "location:") {
				loc := strings.TrimSpace(line[9:])
				if loc != "" {
					if _, dup := seenLoc[loc]; !dup {
						seenLoc[loc] = struct{}{}
						locations = append(locations, loc)
					}
				}
			}
		}
	}
	if len(locations) == 0 {
		return nil
	}

	client := &http.Client{Timeout: timeout}
	var endpoints []upnpEndpoint
	seenCtrl := make(map[string]struct{})

	type xmlService struct {
		ServiceType string `xml:"serviceType"`
		ControlURL  string `xml:"controlURL"`
	}

	for _, location := range locations {
		resp, err := client.Get(location)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		baseURL, err := url.Parse(location)
		if err != nil {
			continue
		}
		decoder := xml.NewDecoder(bytes.NewReader(body))
		for {
			tok, err := decoder.Token()
			if err != nil {
				break
			}
			if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "service" {
				var s xmlService
				if err := decoder.DecodeElement(&s, &se); err == nil {
					if strings.Contains(s.ServiceType, "WANPPPConnection") || strings.Contains(s.ServiceType, "WANIPConnection") {
						if relURL, err := url.Parse(s.ControlURL); err == nil {
							fullCtrl := baseURL.ResolveReference(relURL).String()
							key := fullCtrl + "|" + s.ServiceType
							if _, dup := seenCtrl[key]; !dup {
								seenCtrl[key] = struct{}{}
								endpoints = append(endpoints, upnpEndpoint{ctrlURL: fullCtrl, serviceType: s.ServiceType})
							}
						}
					}
				}
			}
		}
	}
	return endpoints
}

func discoverUPnPControlURL(timeout time.Duration) (string, string) {
	eps := discoverUPnPEndpoints(timeout)
	if len(eps) == 0 {
		return "", ""
	}
	return eps[0].ctrlURL, eps[0].serviceType
}

func upnpAddPortMapping(ctrlURL, serviceType, lanIP string, port uint16, proto string) error {
	// Try 3600s lease first; if the router requires permanent leases (ErrorCode 725 common on PPTP/MikroTik/Keenetic), retry with 0
	if err := upnpAddPortMappingWithLease(ctrlURL, serviceType, lanIP, port, proto, 3600); err == nil {
		return nil
	}
	return upnpAddPortMappingWithLease(ctrlURL, serviceType, lanIP, port, proto, 0)
}

func upnpAddPortMappingWithLease(ctrlURL, serviceType, lanIP string, port uint16, proto string, leaseSeconds int) error {
	soapBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="%s">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
<NewInternalPort>%d</NewInternalPort>
<NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>driftless</NewPortMappingDescription>
<NewLeaseDuration>%d</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>`, serviceType, port, proto, port, lanIP, leaseSeconds)

	req, err := http.NewRequest("POST", ctrlURL, strings.NewReader(soapBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", fmt.Sprintf("\"%s#AddPortMapping\"", serviceType))
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("upnp status %d", resp.StatusCode)
}

func guessDefaultGatewayIP(lanIP string) string {
	ip := net.ParseIP(lanIP).To4()
	if ip == nil {
		return ""
	}
	return net.IPv4(ip[0], ip[1], ip[2], 1).String()
}

func natPMPAddPortMapping(gatewayIP string, port uint16, proto string) error {
	conn, err := net.DialTimeout("udp4", fmt.Sprintf("%s:5351", gatewayIP), 500*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	var pkt [12]byte
	pkt[0] = 0 // Version 0
	if strings.ToUpper(proto) == "UDP" {
		pkt[1] = 1
	} else {
		pkt[1] = 2
	}
	binary.BigEndian.PutUint16(pkt[4:6], port)
	binary.BigEndian.PutUint16(pkt[6:8], port)
	binary.BigEndian.PutUint32(pkt[8:12], 3600)
	if _, err := conn.Write(pkt[:]); err != nil {
		return err
	}
	var resp [16]byte
	n, err := conn.Read(resp[:])
	if err != nil || n < 16 {
		return errors.New("no nat-pmp reply")
	}
	resultCode := binary.BigEndian.Uint16(resp[2:4])
	if resultCode != 0 {
		return fmt.Errorf("nat-pmp error %d", resultCode)
	}
	return nil
}

// updateDDNS pushes the newly detected public IP to DuckDNS, Cloudflare, No-IP, or a custom webhook.
func updateDDNS(cfg DDNSConfig, newIP string) error {
	client := &http.Client{Timeout: 5 * time.Second}

	if cfg.Webhook != "" {
		targetURL := strings.ReplaceAll(cfg.Webhook, "{ip}", url.QueryEscape(newIP))
		resp, err := client.Get(targetURL)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}

	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		return nil
	}

	switch provider {
	case "duckdns":
		domain := strings.TrimSuffix(strings.TrimSpace(cfg.Domain), ".duckdns.org")
		u := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&ip=%s",
			url.QueryEscape(domain), url.QueryEscape(cfg.Token), url.QueryEscape(newIP))
		resp, err := client.Get(u)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		if !strings.HasPrefix(strings.TrimSpace(string(b)), "OK") {
			return fmt.Errorf("duckdns response: %s", strings.TrimSpace(string(b)))
		}
		return nil

	case "noip", "dyndns":
		u := fmt.Sprintf("https://dynupdate.no-ip.com/nic/update?hostname=%s&myip=%s",
			url.QueryEscape(cfg.Domain), url.QueryEscape(newIP))
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(cfg.User, cfg.Token)
		req.Header.Set("User-Agent", "driftless/"+versionString)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		return fmt.Errorf("no-ip status %d", resp.StatusCode)

	case "cloudflare":
		if cfg.ZoneID == "" || cfg.Token == "" || cfg.Domain == "" {
			return errors.New("cloudflare DDNS requires -ddns-zone, -ddns-token, and -ddns-domain")
		}
		listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s",
			url.PathEscape(cfg.ZoneID), url.QueryEscape(cfg.Domain))
		req, err := http.NewRequest("GET", listURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var listRes struct {
			Result []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&listRes); err != nil {
			return err
		}
		bodyMap := map[string]interface{}{
			"type":    "A",
			"name":    cfg.Domain,
			"content": newIP,
			"ttl":     60,
			"proxied": false,
		}
		payload, _ := json.Marshal(bodyMap)
		method := "POST"
		endpoint := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", url.PathEscape(cfg.ZoneID))
		if len(listRes.Result) > 0 && listRes.Result[0].ID != "" {
			method = "PUT"
			endpoint = fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
				url.PathEscape(cfg.ZoneID), url.PathEscape(listRes.Result[0].ID))
		}
		upReq, err := http.NewRequest(method, endpoint, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		upReq.Header.Set("Authorization", "Bearer "+cfg.Token)
		upReq.Header.Set("Content-Type", "application/json")
		upResp, err := client.Do(upReq)
		if err != nil {
			return err
		}
		defer upResp.Body.Close()
		if upResp.StatusCode >= 200 && upResp.StatusCode < 300 {
			return nil
		}
		return fmt.Errorf("cloudflare status %d", upResp.StatusCode)
	}
	return fmt.Errorf("unsupported -ddns-provider %q", cfg.Provider)
}

const ddnsCacheFile = ".driftless-ddns.json"

func extractDuckFromText(raw string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	if idx := strings.Index(strings.ToLower(s), "duckdns.org/update"); idx != -1 {
		sub := s[idx:]
		if endIdx := strings.IndexAny(sub, " \t\r\n\"'"); endIdx != -1 {
			sub = sub[:endIdx]
		}
		if u, err := url.Parse("https://" + sub); err == nil {
			q := u.Query()
			dom := strings.TrimSpace(q.Get("domains"))
			tok := strings.TrimSpace(q.Get("token"))
			if dom != "" && tok != "" {
				return dom, tok
			}
		}
	}
	if !strings.Contains(s, "://") && strings.Count(s, ":") == 1 {
		parts := strings.SplitN(s, ":", 2)
		dom := strings.TrimSpace(parts[0])
		tok := strings.TrimSpace(parts[1])
		if dom != "" && tok != "" && !strings.ContainsAny(dom, " \t\r\n") && !strings.ContainsAny(tok, " \t\r\n") {
			return dom, tok
		}
	}
	return "", ""
}

func formatDuckDomain(d string) string {
	d = strings.TrimSpace(d)
	if idx := strings.Index(d, ","); idx != -1 {
		d = strings.TrimSpace(d[:idx])
	}
	d = strings.TrimSuffix(strings.ToLower(d), ".duckdns.org")
	if d == "" {
		return ""
	}
	return d + ".duckdns.org"
}

func resolveAndPersistDDNS(cfg DDNSConfig, duckFlag string) DDNSConfig {
	duckFlag = strings.TrimSpace(duckFlag)
	explicitlyProvided := cfg.Provider != "" || cfg.Domain != "" || cfg.Token != "" || cfg.Webhook != "" || duckFlag != ""
	// Opt-in only: do nothing by default unless -duck (or -ddns-*) flag was explicitly passed
	if !explicitlyProvided {
		return DDNSConfig{}
	}

	if duckFlag != "" && !strings.EqualFold(duckFlag, "auto") {
		if dom, tok := extractDuckFromText(duckFlag); dom != "" && tok != "" {
			cfg.Provider = "duckdns"
			cfg.Domain = dom
			cfg.Token = tok
		}
	}

	if cfg.Webhook != "" && cfg.Domain == "" {
		if dom, _ := extractDuckFromText(cfg.Webhook); dom != "" {
			cfg.Domain = formatDuckDomain(dom)
		}
	}

	if cfg.Provider == "" && cfg.Domain != "" && cfg.Token != "" {
		if cfg.ZoneID != "" {
			cfg.Provider = "cloudflare"
		} else if cfg.User != "" {
			cfg.Provider = "noip"
		} else {
			cfg.Provider = "duckdns"
		}
	}

	// If user passed -duck auto, load from saved .driftless-ddns.json, environment variables, or local duckdns script
	if strings.EqualFold(duckFlag, "auto") && cfg.Provider == "" && cfg.Webhook == "" {
		if b, err := os.ReadFile(ddnsCacheFile); err == nil {
			var saved DDNSConfig
			if json.Unmarshal(b, &saved) == nil && (saved.Provider != "" || saved.Webhook != "") {
				cfg = saved
				log.Printf("[duckdns] loaded saved domain (%s) from %s", cfg.Domain, ddnsCacheFile)
			}
		}
		if cfg.Provider == "" && cfg.Webhook == "" {
			if envDuck := os.Getenv("DRIFTLESS_DUCKDNS"); envDuck != "" {
				if dom, tok := extractDuckFromText(envDuck); dom != "" && tok != "" {
					cfg.Provider = "duckdns"
					cfg.Domain = dom
					cfg.Token = tok
				}
			}
		}
		if cfg.Provider == "" && cfg.Webhook == "" {
			candidates := []string{"duckdns.txt", "duck.sh", "duck.bat"}
			if home, err := os.UserHomeDir(); err == nil && home != "" {
				candidates = append(candidates,
					filepath.Join(home, "duckdns", "duck.sh"),
					filepath.Join(home, ".duckdns"),
				)
			}
			for _, path := range candidates {
				if b, err := os.ReadFile(path); err == nil {
					if dom, tok := extractDuckFromText(string(b)); dom != "" && tok != "" {
						cfg.Provider = "duckdns"
						cfg.Domain = dom
						cfg.Token = tok
						log.Printf("[duckdns] found domain %q in %s", formatDuckDomain(dom), path)
						break
					}
				}
			}
		}
	}

	if strings.EqualFold(cfg.Provider, "duckdns") && cfg.Domain != "" {
		cfg.Domain = formatDuckDomain(cfg.Domain)
	}

	if cfg.Provider != "" || cfg.Webhook != "" {
		if b, err := json.MarshalIndent(cfg, "", "  "); err == nil {
			_ = os.WriteFile(ddnsCacheFile, b, 0o600)
		}
	} else if strings.EqualFold(duckFlag, "auto") && cfg.Domain == "" {
		// Bare -duck passed with no saved DuckDNS token: mark Domain="auto" so we generate an automatic domain + cert
		cfg.Domain = "auto"
	}
	return cfg
}

func autoZeroConfigDomain(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip)).To4()
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
		return ""
	}
	return fmt.Sprintf("%d-%d-%d-%d.sslip.io", parsed[0], parsed[1], parsed[2], parsed[3])
}

func printStandaloneBanner(pubIP string, ddns DDNSConfig, mappings []PortMapping) {
	log.Printf("[standalone] ==========================================================")
	if ddns.Domain != "" {
		log.Printf("[standalone] Ready-to-copy domain addresses (%s):", ddns.Domain)
		for _, m := range mappings {
			log.Printf("[standalone]   %s:%d", ddns.Domain, m.PublicPort)
		}
	} else {
		log.Printf("[standalone] Ready-to-copy addresses:")
		for _, m := range mappings {
			log.Printf("[standalone]   %s:%d", pubIP, m.PublicPort)
		}
	}
	log.Printf("[standalone] ==========================================================")
}

func isStandalonePortAllowed(allowed map[uint16]struct{}, port uint16) bool {
	if len(allowed) == 0 {
		return true
	}
	_, ok := allowed[port]
	return ok
}

func runStandalone(ctx context.Context, cfg StandaloneConfig) error {
	sniMgr, err := newSNICertManager(cfg.CertDir, cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return err
	}
	sniMgr.ddns = cfg.DDNS
	if len(cfg.VHostMap) > 0 {
		sniMgr.enableACME = true
	}
	sniMgr.startRenewalScheduler(ctx)
	lanIP := detectLocalLANIP()
	stunFailCount.Store(3) // allow HTTP fallback on initial startup if UDP STUN is blocked
	pubIP, _ := querySTUNPublicIP(cfg.STUNServer, 800*time.Millisecond)
	if pubIP == "" {
		pubIP = lanIP
	}

	log.Printf("[standalone] driftless %s Zero-VPS mode active (LAN=%s, Public IP=%s)", versionString, lanIP, pubIP)
	if cfg.EnableUPnP {
		mapped := autoForwardRouterPorts(lanIP, cfg.Mappings, cfg.VHostAddr, cfg.HTTPSAddr)
		if mapped == 0 {
			log.Printf("[standalone] warning: router UPnP/NAT-PMP mapped 0 ports (verify UPnP is enabled on your active WAN/PPTP interface)")
		} else {
			log.Printf("[standalone] router UPnP/NAT-PMP auto-forwarded %d port rules to %s", mapped, lanIP)
		}
	}

	hasDDNSProvider := cfg.DDNS.Provider != "" || cfg.DDNS.Webhook != ""
	autoSSLIPMode := !hasDDNSProvider && strings.EqualFold(cfg.DDNS.Domain, "auto")
	ddnsSyncedIP := ""
	var lastDDNSAttempt time.Time

	if hasDDNSProvider {
		lastDDNSAttempt = time.Now()
		if err := updateDDNS(cfg.DDNS, pubIP); err != nil {
			log.Printf("[standalone] initial DDNS update warning (will retry automatically): %v", err)
		} else {
			ddnsSyncedIP = pubIP
			log.Printf("[standalone] DDNS updated -> %s (%s)", pubIP, cfg.DDNS.Domain)
		}
	} else if autoSSLIPMode {
		if autoDom := autoZeroConfigDomain(pubIP); autoDom != "" {
			cfg.DDNS.Domain = autoDom
		} else {
			cfg.DDNS.Domain = pubIP
		}
	}
	if cfg.DDNS.Domain != "" {
		sniMgr.ensureDomainCertificate(cfg.DDNS.Domain)
		cfg.EnableTLS = true
	}
	printStandaloneBanner(pubIP, cfg.DDNS, cfg.Mappings)

	// Start local TCP/UDP/VHost listeners (respecting -allow-ports if configured)
	for _, m := range cfg.Mappings {
		if !isStandalonePortAllowed(cfg.AllowedPorts, m.TargetPort) {
			log.Printf("[standalone] skipping port %d -> %d (not in -allow-ports)", m.PublicPort, m.TargetPort)
			continue
		}
		if m.Proto == "udp" || m.Proto == "both" {
			if err := startStandaloneUDP(ctx, cfg.TargetHost, m); err != nil && m.Proto == "udp" {
				return err
			}
		}
		if m.Proto != "udp" {
			if err := startStandaloneTCP(ctx, cfg.TargetHost, m, sniMgr, cfg.EnableTLS || m.Proto == "https"); err != nil {
				return err
			}
		}
	}

	filteredVHosts := make(map[string]uint16, len(cfg.VHostMap))
	for k, port := range cfg.VHostMap {
		if isStandalonePortAllowed(cfg.AllowedPorts, port) {
			filteredVHosts[k] = port
		} else {
			log.Printf("[standalone] skipping vhost %s -> :%d (not in -allow-ports)", k, port)
		}
	}

	if cfg.VHostAddr != "" && len(filteredVHosts) > 0 {
		if err := startStandaloneVHost(ctx, cfg.VHostAddr, cfg.TargetHost, filteredVHosts, sniMgr); err != nil {
			return err
		}
	}
	if cfg.HTTPSAddr != "" && len(filteredVHosts) > 0 {
		if err := startStandaloneVHost(ctx, cfg.HTTPSAddr, cfg.TargetHost, filteredVHosts, sniMgr); err != nil {
			return err
		}
	}

	// 1-second STUN IP change detector + automatic DDNS retry + periodic UPnP lease renewal
	interval := cfg.STUNInterval
	if interval < 250*time.Millisecond {
		interval = time.Second
	}
	stunTicker := time.NewTicker(interval)
	defer stunTicker.Stop()
	upnpTicker := time.NewTicker(20 * time.Minute)
	defer upnpTicker.Stop()

	currentIP := pubIP
	for {
		select {
		case <-ctx.Done():
			log.Printf("[standalone] shutting down cleanly...")
			return nil
		case <-upnpTicker.C:
			if cfg.EnableUPnP {
				lanIP = detectLocalLANIP()
				autoForwardRouterPorts(lanIP, cfg.Mappings, cfg.VHostAddr, cfg.HTTPSAddr)
			}
		case <-stunTicker.C:
			detected, err := querySTUNPublicIP(cfg.STUNServer, 400*time.Millisecond)
			if err == nil && detected != "" && detected != currentIP {
				log.Printf("[standalone] ISP public IP changed: %s -> %s (updating DDNS & UPnP immediately)", currentIP, detected)
				currentIP = detected
				if cfg.EnableUPnP {
					lanIP = detectLocalLANIP()
					autoForwardRouterPorts(lanIP, cfg.Mappings, cfg.VHostAddr, cfg.HTTPSAddr)
				}
				if autoSSLIPMode {
					if autoDom := autoZeroConfigDomain(currentIP); autoDom != "" {
						cfg.DDNS.Domain = autoDom
						sniMgr.ensureDomainCertificate(cfg.DDNS.Domain)
						printStandaloneBanner(currentIP, cfg.DDNS, cfg.Mappings)
					}
				}
				lastDDNSAttempt = time.Time{} // force immediate DDNS update on IP change
			}
			// Retry DDNS automatically if it hasn't synced currentIP yet (e.g. right after PPTP/PPP reconnect)
			if hasDDNSProvider && ddnsSyncedIP != currentIP && time.Since(lastDDNSAttempt) >= 5*time.Second {
				lastDDNSAttempt = time.Now()
				if err := updateDDNS(cfg.DDNS, currentIP); err != nil {
					log.Printf("[standalone] DDNS update error (will retry in 5s): %v", err)
				} else {
					ddnsSyncedIP = currentIP
					log.Printf("[standalone] DDNS record synced -> %s (%s)", currentIP, cfg.DDNS.Domain)
				}
			}
		}
	}
}

func closeWriteSide(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	if pc, ok := c.(*peekedConn); ok {
		if tc, ok := pc.Conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
			return
		}
	}
	if tlsC, ok := c.(*tls.Conn); ok {
		_ = tlsC.CloseWrite()
	}
}

func pipeBidirectional(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWriteSide(b)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWriteSide(a)
	}()
	wg.Wait()
}

func startStandaloneTCP(ctx context.Context, targetHost string, m PortMapping, sniMgr *SNICertManager, useTLS bool) error {
	l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", m.PublicPort))
	if err != nil {
		return err
	}
	log.Printf("[standalone] TCP :%d -> %s:%d (auto-tls=%v)", m.PublicPort, targetHost, m.TargetPort, useTLS)
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if !defaultIPACL.AllowedAddr(c.RemoteAddr()) {
				_ = c.Close()
				continue
			}
			go func(inConn net.Conn) {
				tuneTCPSocket(inConn)
				wrapped := maybeTerminateTLS(inConn, sniMgr, useTLS)
				defer wrapped.Close()
				outConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetHost, m.TargetPort), 5*time.Second)
				if err != nil {
					return
				}
				tuneTCPSocket(outConn)
				defer outConn.Close()
				pipeBidirectional(wrapped, outConn)
			}(c)
		}
	}()
	return nil
}

func startStandaloneUDP(ctx context.Context, targetHost string, m PortMapping) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", m.PublicPort))
	if err != nil {
		return err
	}
	pubConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	log.Printf("[standalone] UDP :%d -> %s:%d", m.PublicPort, targetHost, m.TargetPort)
	go func() {
		<-ctx.Done()
		_ = pubConn.Close()
	}()

	var mu sync.Mutex
	peers := make(map[string]*net.UDPConn)

	go func() {
		buf := make([]byte, maxUDPPacket)
		for {
			n, clientAddr, err := pubConn.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if !defaultIPACL.AllowedAddr(clientAddr) {
				continue
			}
			key := clientAddr.String()
			mu.Lock()
			locConn, ok := peers[key]
			if !ok {
				raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetHost, m.TargetPort))
				if err != nil {
					mu.Unlock()
					continue
				}
				locConn, err = net.DialUDP("udp", nil, raddr)
				if err != nil {
					mu.Unlock()
					continue
				}
				peers[key] = locConn
				go func(k string, cAddr *net.UDPAddr, lc *net.UDPConn) {
					defer func() {
						_ = lc.Close()
						mu.Lock()
						delete(peers, k)
						mu.Unlock()
					}()
					rbuf := make([]byte, maxUDPPacket)
					for {
						_ = lc.SetReadDeadline(time.Now().Add(udpSessionTTL))
						rn, err := lc.Read(rbuf)
						if err != nil {
							return
						}
						_, _ = pubConn.WriteToUDP(rbuf[:rn], cAddr)
					}
				}(key, clientAddr, locConn)
			}
			mu.Unlock()
			_, _ = locConn.Write(buf[:n])
		}
	}()
	return nil
}

func startStandaloneVHost(ctx context.Context, listenAddr, targetHost string, vhostMap map[string]uint16, sniMgr *SNICertManager) error {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	log.Printf("[standalone] HTTP/HTTPS VHost router on %s (%d domains)", listenAddr, len(vhostMap))
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if !defaultIPACL.AllowedAddr(c.RemoteAddr()) {
				_ = c.Close()
				continue
			}
			go func(raw net.Conn) {
				tuneTCPSocket(raw)
				wrapped := maybeTerminateTLS(raw, sniMgr, true)
				defer wrapped.Close()
				_ = wrapped.SetReadDeadline(time.Now().Add(5 * time.Second))
				var captured bytes.Buffer
				tee := io.TeeReader(wrapped, &captured)
				br := bufio.NewReader(tee)
				req, err := http.ReadRequest(br)
				_ = wrapped.SetReadDeadline(time.Time{})
				if err != nil {
					return
				}
				if sniMgr != nil && strings.HasPrefix(req.URL.Path, "/.well-known/acme-challenge/") {
					tok := strings.TrimPrefix(req.URL.Path, "/.well-known/acme-challenge/")
					if keyAuth, ok := sniMgr.getHTTPChallenge(tok); ok {
						resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(keyAuth), keyAuth)
						_, _ = wrapped.Write([]byte(resp))
						return
					}
				}
				host := strings.ToLower(strings.TrimSpace(req.Host))
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				targetPort, ok := matchVHostTarget(vhostMap, host, req.URL.Path)
				if !ok {
					_, _ = wrapped.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 21\r\nConnection: close\r\n\r\ndriftless: unknown host"))
					return
				}
				outConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort), 5*time.Second)
				if err != nil {
					return
				}
				tuneTCPSocket(outConn)
				defer outConn.Close()
				_, _ = outConn.Write(captured.Bytes())
				pipeBidirectional(wrapped, outConn)
			}(c)
		}
	}()
	return nil
}

