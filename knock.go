package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	knockPathPrefix     = "/__driftless_knock/"
	defaultKnockTTL     = 24 * time.Hour
	knockSecretFileName = "knock.secret"
	knockURLFileName    = "knock-url.txt"
)

var defaultKnockController *KnockController

type KnockController struct {
	secret       string
	ttl          time.Duration
	mu           sync.RWMutex
	allowed      map[string]time.Time
	attempts     map[string]authAttempt
	mappedPorts  []PortMapping
	publicHost   string
	primaryPort  uint16
	useTLS       bool
	isStandalone bool
	targetHost   string
	allowedPorts map[uint16]struct{}
}

func loadOrGenerateKnockSecret(certDir, customSecret string) (string, error) {
	if s := strings.TrimSpace(customSecret); s != "" {
		registerSecretForLogRedaction(s)
		return s, nil
	}
	if envSec := strings.TrimSpace(os.Getenv("DRIFTLESS_KNOCK_TOKEN")); envSec != "" {
		registerSecretForLogRedaction(envSec)
		return envSec, nil
	}
	if strings.TrimSpace(certDir) == "" {
		certDir = ".driftless-certs"
	}
	secretPath := filepath.Join(certDir, knockSecretFileName)
	if b, err := os.ReadFile(secretPath); err == nil {
		if saved := strings.TrimSpace(string(b)); len(saved) >= 16 {
			registerSecretForLogRedaction(saved)
			return saved, nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read knock secret %s: %w", secretPath, err)
	}

	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", fmt.Errorf("generate knock secret: %w", err)
	}
	secret := hex.EncodeToString(rnd[:])
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return "", fmt.Errorf("create knock secret dir %s: %w", certDir, err)
	}
	if err := writeFileAtomic0600(secretPath, []byte(secret+"\n")); err != nil {
		return "", fmt.Errorf("save knock secret %s: %w", secretPath, err)
	}
	registerSecretForLogRedaction(secret)
	return secret, nil
}

func newKnockController(certDir, customSecret string, ttl time.Duration, mappings []PortMapping, allowedPorts map[uint16]struct{}, isStandalone bool, targetHost string) (*KnockController, error) {
	secret, err := loadOrGenerateKnockSecret(certDir, customSecret)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = defaultKnockTTL
	}
	var primaryPort uint16 = 8096
	for _, m := range mappings {
		if m.Proto != "udp" {
			primaryPort = m.PublicPort
			break
		}
	}
	if targetHost == "" {
		targetHost = "127.0.0.1"
	}
	return &KnockController{
		secret:       secret,
		ttl:          ttl,
		allowed:      make(map[string]time.Time),
		attempts:     make(map[string]authAttempt),
		mappedPorts:  append([]PortMapping(nil), mappings...),
		primaryPort:  primaryPort,
		useTLS:       true,
		isStandalone: isStandalone,
		targetHost:   targetHost,
		allowedPorts: allowedPorts,
	}, nil
}

func (kc *KnockController) SetPublicEndpoint(host string, useTLS bool, certDir string) {
	if kc == nil {
		return
	}
	kc.mu.Lock()
	kc.publicHost = strings.TrimSpace(host)
	// Magic Knock always requires HTTPS/TLS so the secret in the URL is never transmitted in cleartext
	kc.useTLS = true
	_ = useTLS
	urlStr := kc.magicURLocked()
	kc.mu.Unlock()

	if strings.TrimSpace(certDir) == "" {
		certDir = ".driftless-certs"
	}
	_ = os.MkdirAll(certDir, 0o700)
	urlPath := filepath.Join(certDir, knockURLFileName)
	_ = writeFileAtomic0600(urlPath, []byte(urlStr+"\n"))
}

func (kc *KnockController) MagicURL() string {
	if kc == nil {
		return ""
	}
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return kc.magicURLocked()
}

func (kc *KnockController) magicURLocked() string {
	scheme := "https"
	host := kc.publicHost
	if host == "" {
		host = "YOUR_HOST"
	}
	return fmt.Sprintf("%s://%s:%d%s%s", scheme, host, kc.primaryPort, knockPathPrefix, kc.secret)
}

func (kc *KnockController) PrintBanner(prefix, certDir string) {
	if kc == nil {
		return
	}
	magicURL := kc.MagicURL()
	if strings.TrimSpace(certDir) == "" {
		certDir = ".driftless-certs"
	}
	urlPath := filepath.Join(certDir, knockURLFileName)
	log.Printf("[%s] Zero-Client Phone Knock protection active (TTL=%v; all TCP/UDP ports hidden from scanners until unlocked)", prefix, kc.ttl)
	if tryPrintInteractiveKnockURL(prefix, magicURL) {
		log.Printf("[%s] Phone Magic Knock URL displayed on terminal (saved in %s; run './driftless show-token' anytime to view)", prefix, urlPath)
	} else {
		log.Printf("[%s] Phone Magic Knock URL saved to %s (run './driftless show-token' to view): %s", prefix, urlPath, magicURL)
	}
}

func tryPrintInteractiveKnockURL(prefix, magicURL string) bool {
	if os.Getenv("JOURNAL_STREAM") != "" || os.Getenv("INVOCATION_ID") != "" {
		return false
	}
	outInfo, err1 := os.Stdout.Stat()
	errInfo, err2 := os.Stderr.Stat()
	if err1 != nil || err2 != nil {
		return false
	}
	if (outInfo.Mode()&os.ModeCharDevice) == 0 || (errInfo.Mode()&os.ModeCharDevice) == 0 {
		return false
	}
	ttyFile, err := openControllingTerminal()
	if err != nil {
		return false
	}
	defer ttyFile.Close()
	_, wErr := fmt.Fprintf(ttyFile, "[%s] Open once on your iPhone / Android / laptop to unlock all ports (bookmark it):\n  %s\n", prefix, magicURL)
	return wErr == nil
}

func extractAddrHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	s := addr.String()
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

func (kc *KnockController) IsAllowedAddr(addr net.Addr) bool {
	if kc == nil {
		return true
	}
	host := extractAddrHost(addr)
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	key := normalizeAuthIPKey(host)
	now := time.Now()

	kc.mu.RLock()
	exp, ok := kc.allowed[key]
	kc.mu.RUnlock()
	if !ok || !now.Before(exp) {
		return false
	}
	// Sliding window renewal if more than 1 minute has elapsed
	if exp.Sub(now) < kc.ttl-time.Minute {
		kc.mu.Lock()
		kc.allowed[key] = now.Add(kc.ttl)
		kc.mu.Unlock()
	}
	return true
}

func (kc *KnockController) AuthorizeAddr(addr net.Addr) time.Time {
	host := extractAddrHost(addr)
	key := normalizeAuthIPKey(host)
	now := time.Now()
	exp := now.Add(kc.ttl)

	kc.mu.Lock()
	defer kc.mu.Unlock()
	if len(kc.allowed) >= maxAuthTrackedIPs {
		for k, v := range kc.allowed {
			if now.After(v) {
				delete(kc.allowed, k)
			}
		}
		if len(kc.allowed) >= maxAuthTrackedIPs {
			for k := range kc.allowed {
				delete(kc.allowed, k)
				break
			}
		}
	}
	kc.allowed[key] = exp
	delete(kc.attempts, key)
	return exp
}

func (kc *KnockController) VerifyKnockToken(addr net.Addr, candidate string) (bool, time.Time) {
	host := extractAddrHost(addr)
	key := normalizeAuthIPKey(host)
	now := time.Now()

	kc.mu.Lock()
	a, hasAttempt := kc.attempts[key]
	if hasAttempt && now.Sub(a.first) <= authWindow && a.failures >= maxAuthAttempts {
		kc.mu.Unlock()
		return false, time.Time{}
	}
	kc.mu.Unlock()

	candClean := strings.TrimSpace(candidate)
	if hmac.Equal([]byte(candClean), []byte(kc.secret)) {
		exp := kc.AuthorizeAddr(addr)
		return true, exp
	}

	kc.mu.Lock()
	defer kc.mu.Unlock()
	a, hasAttempt = kc.attempts[key]
	if !hasAttempt || now.Sub(a.first) > authWindow {
		if len(kc.attempts) >= maxAuthTrackedIPs {
			for k := range kc.attempts {
				delete(kc.attempts, k)
				break
			}
		}
		kc.attempts[key] = authAttempt{failures: 1, first: now}
	} else {
		a.failures++
		kc.attempts[key] = a
	}
	return false, time.Time{}
}

func isNetTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func ensurePeekedConn(c net.Conn) (*peekedConn, *bufio.Reader) {
	if pc, ok := c.(*peekedConn); ok && pc.r != nil {
		return pc, pc.r
	}
	br := bufio.NewReaderSize(c, 4096)
	pc := &peekedConn{Conn: c, r: br}
	return pc, br
}

func peekBytesWithTimeout(c net.Conn, n int, timeout time.Duration) ([]byte, *peekedConn, error) {
	pc, br := ensurePeekedConn(c)
	_ = pc.Conn.SetReadDeadline(time.Now().Add(timeout))
	b, err := br.Peek(n)
	_ = pc.Conn.SetReadDeadline(time.Time{})
	if err != nil && br.Buffered() > 0 {
		b, _ = br.Peek(br.Buffered())
	}
	return b, pc, err
}

func (kc *KnockController) hasMappedTargetPort(port uint16) (uint16, bool) {
	if kc != nil {
		for _, m := range kc.mappedPorts {
			if m.TargetPort == port || m.PublicPort == port {
				return m.TargetPort, true
			}
		}
	}
	return 0, false
}

// detectUniversalSinglePortOverride inspects initial bytes on a connection and allows SSH (SSH-2.0-)
// or Microsoft Remote Desktop (X.224 TPKT 0x03 0x00) to be routed to mapped SSH (:22) or RDP (:3389)
// targets even when the client connected through another mapped port (e.g. :8096 or :443).
func detectUniversalSinglePortOverride(hdr []byte, defaultTarget uint16, mappings []PortMapping) uint16 {
	if len(hdr) >= 4 && bytes.HasPrefix(hdr, []byte("SSH-")) {
		for _, m := range mappings {
			if m.TargetPort == 22 || m.PublicPort == 22 {
				return m.TargetPort
			}
		}
	}
	// Microsoft RDP X.224 Connection Request PDU: TPKT version 3 (0x03, 0x00), length >= 11, X.224 CR code 0xE0 in byte 5
	if len(hdr) >= 6 && hdr[0] == 0x03 && hdr[1] == 0x00 && (hdr[5]&0xF0) == 0xE0 {
		for _, m := range mappings {
			if m.TargetPort == 3389 || m.PublicPort == 3389 {
				return m.TargetPort
			}
		}
	}
	return defaultTarget
}

func isKnockHTTPPrefix(hdr []byte) bool {
	return bytes.HasPrefix(hdr, []byte("GET "+knockPathPrefix)) ||
		bytes.HasPrefix(hdr, []byte("HEAD "+knockPathPrefix)) ||
		bytes.HasPrefix(hdr, []byte("POST "+knockPathPrefix))
}

func isHTTPConnectPrefix(hdr []byte) bool {
	return bytes.HasPrefix(hdr, []byte("CONNECT "))
}

func isSOCKS5GreetingPrefix(hdr []byte) bool {
	// RFC 1928: VER=0x05, NMETHODS in 1..16, followed by method 0x00 (No Auth) or 0x02
	if len(hdr) < 3 || hdr[0] != 0x05 {
		return false
	}
	nmethods := int(hdr[1])
	if nmethods < 1 || nmethods > 16 || len(hdr) < 2+nmethods {
		return false
	}
	for i := 0; i < nmethods; i++ {
		if hdr[2+i] == 0x00 || hdr[2+i] == 0x02 {
			return true
		}
	}
	return false
}

// inspectAndPrepareTCPConn enforces -knock protection, serves the Magic Knock Launchpad (/.rdp/proxy.pac),
// handles built-in Knock-authenticated SOCKS5 & HTTP CONNECT proxy requests, and performs Single-Port
// protocol auto-routing (SSH/RDP/HTTP on a single port).
// Returns (wrappedConn, resolvedTargetPort, handledOrClosed).
func inspectAndPrepareTCPConn(
	rawConn net.Conn,
	sniMgr *SNICertManager,
	useTLS bool,
	defaultTargetPort uint16,
	mappings []PortMapping,
	dialPortFn func(conn net.Conn, targetPort uint16, directHost string),
) (net.Conn, uint16, bool) {
	kc := defaultKnockController
	remoteAddr := rawConn.RemoteAddr()

	if kc != nil && !kc.IsAllowedAddr(remoteAddr) {
		// Unauthenticated IP: only allow a valid Magic Knock HTTP(S) request; drop everything else before touching backends.
		wrapped := maybeTerminateTLSWithTimeout(rawConn, sniMgr, true, 1500*time.Millisecond)
		hdr, pc, _ := peekBytesWithTimeout(wrapped, 32, 1500*time.Millisecond)
		if !isKnockHTTPPrefix(hdr) {
			_ = pc.Close()
			return nil, 0, true
		}
		kc.handleKnockHTTPConn(pc, remoteAddr)
		return nil, 0, true
	}

	peekWait := 250 * time.Millisecond
	if defaultTargetPort == 22 || defaultTargetPort == 3389 {
		peekWait = 120 * time.Millisecond
	}
	wrapped := maybeTerminateTLSWithTimeout(rawConn, sniMgr, useTLS, peekWait)
	hdr, pc, _ := peekBytesWithTimeout(wrapped, 32, peekWait)

	if kc != nil && isKnockHTTPPrefix(hdr) {
		kc.handleKnockHTTPConn(pc, remoteAddr)
		return nil, 0, true
	}

	if kc != nil && dialPortFn != nil {
		if isHTTPConnectPrefix(hdr) {
			kc.handleHTTPConnectProxy(pc, dialPortFn)
			return nil, 0, true
		}
		if isSOCKS5GreetingPrefix(hdr) {
			kc.handleSOCKS5Proxy(pc, dialPortFn)
			return nil, 0, true
		}
	}

	resolvedPort := detectUniversalSinglePortOverride(hdr, defaultTargetPort, mappings)
	return pc, resolvedPort, false
}

func isTLSBackedConn(c net.Conn) bool {
	for c != nil {
		if _, ok := c.(*tls.Conn); ok {
			return true
		}
		if pc, ok := c.(*peekedConn); ok {
			c = pc.Conn
			continue
		}
		break
	}
	return false
}

func (kc *KnockController) handleKnockHTTPConn(pc *peekedConn, remoteAddr net.Addr) {
	defer pc.Close()
	_ = pc.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	req, err := http.ReadRequest(pc.r)
	_ = pc.Conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}

	// Refuse plaintext HTTP knock requests so the secret is never accepted over unencrypted connections
	if !isTLSBackedConn(pc) {
		body := "400 Bad Request: HTTPS is required for Magic Knock (use https://)\n"
		resp := fmt.Sprintf("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		_, _ = pc.Write([]byte(resp))
		return
	}

	rel := strings.TrimPrefix(req.URL.Path, knockPathPrefix)
	parts := strings.SplitN(rel, "/", 2)
	candidateTok := parts[0]
	subPath := ""
	if len(parts) > 1 {
		subPath = strings.ToLower(strings.TrimSpace(parts[1]))
	}

	ok, exp := kc.VerifyKnockToken(remoteAddr, candidateTok)
	if !ok {
		body := "404 Not Found\n"
		resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		_, _ = pc.Write([]byte(resp))
		return
	}

	clientIP := extractAddrHost(remoteAddr)
	log.Printf("[knock] unlocked client IP %s until %s", clientIP, exp.Format(time.RFC3339))

	reqHost := strings.TrimSpace(req.Host)
	if h, _, err := net.SplitHostPort(reqHost); err == nil && h != "" {
		reqHost = h
	}
	if reqHost == "" {
		kc.mu.RLock()
		reqHost = kc.publicHost
		kc.mu.RUnlock()
	}
	if reqHost == "" {
		reqHost = "127.0.0.1"
	}

	switch subPath {
	case "connect.rdp", "pc.rdp":
		rdpPort := uint16(3389)
		for _, m := range kc.mappedPorts {
			if m.TargetPort == 3389 {
				rdpPort = m.PublicPort
				break
			}
		}
		rdpContent := fmt.Sprintf(
			"full address:s:%s:%d\r\nprompt for credentials:i:1\r\nadministrative session:i:1\r\nredirectclipboard:i:1\r\naudiomode:i:0\r\n",
			reqHost, rdpPort,
		)
		hdr := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Type: application/x-rdp\r\nContent-Disposition: attachment; filename=\"driftless-%s.rdp\"\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
			reqHost, len(rdpContent),
		)
		_, _ = pc.Write([]byte(hdr + rdpContent))
		return

	case "proxy.pac":
		pacContent := kc.buildPACFile(reqHost)
		hdr := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
			len(pacContent),
		)
		_, _ = pc.Write([]byte(hdr + pacContent))
		return

	case "status.json":
		payload, _ := json.Marshal(map[string]any{
			"status":      "unlocked",
			"client_ip":   clientIP,
			"expires_at":  exp.UTC().Format(time.RFC3339),
			"ttl_seconds": int(time.Until(exp).Seconds()),
			"host":        reqHost,
		})
		hdr := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
			len(payload),
		)
		_, _ = pc.Write(append([]byte(hdr), payload...))
		return
	}

	page := kc.buildLaunchpadHTML(reqHost, clientIP, exp)
	hdr := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
		len(page),
	)
	_, _ = pc.Write([]byte(hdr + page))
}

func (kc *KnockController) buildPACFile(host string) string {
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  if (dnsDomainIs(host, %q) ||
      shExpMatch(host, "*.local") ||
      shExpMatch(host, "*.lan") ||
      shExpMatch(host, "*.home.arpa") ||
      isInNet(host, "192.168.0.0", "255.255.0.0") ||
      isInNet(host, "10.0.0.0", "255.0.0.0") ||
      isInNet(host, "172.16.0.0", "255.240.0.0") ||
      isInNet(host, "127.0.0.0", "255.0.0.0")) {
    return "PROXY %s:%d; SOCKS5 %s:%d; DIRECT";
  }
  return "DIRECT";
}
`, host, host, kc.primaryPort, host, kc.primaryPort)
}

func (kc *KnockController) buildLaunchpadHTML(host, clientIP string, exp time.Time) string {
	safeHost := html.EscapeString(host)
	safeIP := html.EscapeString(clientIP)
	ttlHours := fmt.Sprintf("%.1f h", time.Until(exp).Hours())
	scheme := "https"
	if !kc.useTLS {
		scheme = "http"
	}
	pacURL := fmt.Sprintf("%s://%s:%d%s%s/proxy.pac", scheme, safeHost, kc.primaryPort, knockPathPrefix, kc.secret)
	rdpFileURL := fmt.Sprintf("%s://%s:%d%s%s/connect.rdp", scheme, safeHost, kc.primaryPort, knockPathPrefix, kc.secret)

	var cards strings.Builder
	for _, m := range kc.mappedPorts {
		pub := m.PublicPort
		loc := m.TargetPort
		switch loc {
		case 3389:
			cards.WriteString(fmt.Sprintf(
				`<div class="card"><div><strong>Windows Remote Desktop (RDP :%d)</strong><div class="sub">%s:%d (or single-port %s:%d)</div></div><div class="btns"><a class="btn" href="rdp://full%%20address=s:%s:%d">Open Windows App</a><a class="btn sec" href="%s">Download .rdp</a></div></div>`,
				pub, safeHost, pub, safeHost, kc.primaryPort, safeHost, pub, rdpFileURL,
			))
		case 22:
			cards.WriteString(fmt.Sprintf(
				`<div class="card"><div><strong>SSH / SFTP Terminal (:%d)</strong><div class="sub">%s:%d (WebSSH / Termius / SFTP)</div></div><div class="btns"><a class="btn" href="ssh://%s:%d">Open SSH</a><a class="btn sec" href="sftp://%s:%d">Open SFTP</a></div></div>`,
				pub, safeHost, pub, safeHost, pub, safeHost, pub,
			))
		default:
			portScheme := scheme
			if m.Proto == "https" || pub == 443 {
				portScheme = "https"
			}
			cards.WriteString(fmt.Sprintf(
				`<div class="card"><div><strong>Port :%d (Local :%d · %s)</strong><div class="sub">%s://%s:%d</div></div><div class="btns"><a class="btn" href="%s://%s:%d">Open in Browser</a></div></div>`,
				pub, loc, strings.ToUpper(m.Proto), portScheme, safeHost, pub, portScheme, safeHost, pub,
			))
		}
	}

	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>driftless - Device Unlocked</title>
<style>
body{margin:0;padding:20px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#090d16;color:#f1f5f9}
.wrap{max-width:640px;margin:0 auto;display:flex;flex-direction:column;gap:14px}
.badge{display:inline-block;padding:6px 10px;border-radius:6px;background:#064e3b;color:#6ee7b7;font-size:13px;font-weight:600}
.box{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px}
.card{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:10px;padding:12px 0;border-bottom:1px solid #1f2937}
.card:last-child{border-bottom:none}
.sub{font-size:12px;color:#94a3b8;font-family:monospace;margin-top:3px}
.btns{display:flex;gap:8px;flex-wrap:wrap}
.btn{padding:8px 12px;border-radius:6px;background:#38bdf8;color:#090d16;text-decoration:none;font-weight:600;font-size:13px}
.btn.sec{background:#1e293b;color:#e2e8f0;border:1px solid #334155}
code{display:block;padding:10px;background:#030712;border:1px solid #1e293b;border-radius:6px;font-size:12px;color:#38bdf8;word-break:break-all;margin-top:6px}
</style>
</head>
<body>
<div class="wrap">
  <div class="box">
    <span class="badge">All TCP &amp; UDP Ports Unlocked (%s)</span>
    <h2 style="margin:10px 0 4px;font-size:18px">Your IP (%s) is authorized</h2>
    <p style="margin:0;font-size:13px;color:#94a3b8">You can now connect from any native app on this device (Windows App RDP, Termius SSH, Jellyfin, Moonlight, Minecraft). Save this page to your bookmarks to unlock again anytime your mobile IP changes.</p>
  </div>
  <div class="box">
    <div style="font-size:13px;font-weight:600;margin-bottom:6px;color:#cbd5e1">One-Tap App Launchers</div>
    %s
  </div>
  <div class="box">
    <div style="font-size:13px;font-weight:600;color:#cbd5e1">Universal Proxy &amp; Auto-PAC (iOS / Android Wi-Fi Proxy -&gt; Automatic)</div>
    <p style="margin:4px 0 0;font-size:12px;color:#94a3b8">Routes %s and local home LAN (192.168.x.x) through port %d without installing any VPN app:</p>
    <code>%s</code>
  </div>
</div>
</body>
</html>`, ttlHours, safeIP, cards.String(), safeHost, kc.primaryPort, pacURL)
}

func (kc *KnockController) resolveProxyDestination(targetAddr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(targetAddr))
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, errors.New("invalid proxy target port")
	}
	port := uint16(p)
	if len(kc.allowedPorts) > 0 {
		if _, ok := kc.allowedPorts[port]; !ok {
			return "", 0, fmt.Errorf("port %d is not in -allow-ports", port)
		}
	}

	hostLower := strings.ToLower(strings.TrimSpace(host))
	kc.mu.RLock()
	pubHost := strings.ToLower(kc.publicHost)
	kc.mu.RUnlock()

	// Map public domain, localhost, or 127.0.0.1 to the Home PC's local target
	if hostLower == "localhost" || hostLower == "127.0.0.1" || (pubHost != "" && hostLower == pubHost) {
		if mappedLoc, ok := kc.hasMappedTargetPort(port); ok {
			port = mappedLoc
		}
		return kc.targetHost, port, nil
	}

	// In standalone mode on the Home PC, also allow unlocked devices to reach private RFC1918 LAN IPs (e.g. 192.168.1.1 router) while blocking 169.254.169.254 metadata
	ip := net.ParseIP(hostLower)
	if ip != nil {
		v4 := ip.To4()
		if v4 == nil || v4.IsLinkLocalUnicast() || v4[0] == 169 {
			return "", 0, errors.New("blocked unsafe proxy target IP")
		}
		if v4.IsLoopback() {
			return kc.targetHost, port, nil
		}
		if kc.isStandalone && v4.IsPrivate() {
			return v4.String(), port, nil
		}
	}
	return "", 0, errors.New("proxy only routes to home host and private LAN")
}

func (kc *KnockController) handleHTTPConnectProxy(pc *peekedConn, dialPortFn func(conn net.Conn, targetPort uint16, directHost string)) {
	_ = pc.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	req, err := http.ReadRequest(pc.r)
	_ = pc.Conn.SetReadDeadline(time.Time{})
	if err != nil || req.Method != http.MethodConnect {
		_ = pc.Close()
		return
	}
	directHost, targetPort, err := kc.resolveProxyDestination(req.Host)
	if err != nil {
		_, _ = pc.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
		_ = pc.Close()
		return
	}
	if _, err := pc.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = pc.Close()
		return
	}
	dialPortFn(pc, targetPort, directHost)
}

func (kc *KnockController) handleSOCKS5Proxy(pc *peekedConn, dialPortFn func(conn net.Conn, targetPort uint16, directHost string)) {
	_ = pc.Conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(pc, hdr[:]); err != nil || hdr[0] != 0x05 {
		_ = pc.Close()
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(pc, methods); err != nil {
		_ = pc.Close()
		return
	}
	// Reply: SOCKS5 No Authentication Required (since caller IP is already verified via KnockController)
	if _, err := pc.Write([]byte{0x05, 0x00}); err != nil {
		_ = pc.Close()
		return
	}

	var reqHdr [4]byte
	if _, err := io.ReadFull(pc, reqHdr[:]); err != nil || reqHdr[0] != 0x05 || reqHdr[1] != 0x01 {
		_, _ = pc.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = pc.Close()
		return
	}
	var host string
	switch reqHdr[3] {
	case 0x01: // IPv4
		var ip4 [4]byte
		if _, err := io.ReadFull(pc, ip4[:]); err != nil {
			_ = pc.Close()
			return
		}
		host = net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3]).String()
	case 0x03: // Domain name
		var dlen [1]byte
		if _, err := io.ReadFull(pc, dlen[:]); err != nil || dlen[0] == 0 {
			_ = pc.Close()
			return
		}
		dbuf := make([]byte, int(dlen[0]))
		if _, err := io.ReadFull(pc, dbuf); err != nil {
			_ = pc.Close()
			return
		}
		host = string(dbuf)
	default:
		_, _ = pc.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = pc.Close()
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(pc, portBuf[:]); err != nil {
		_ = pc.Close()
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	_ = pc.Conn.SetDeadline(time.Time{})

	directHost, targetPort, err := kc.resolveProxyDestination(fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		_, _ = pc.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = pc.Close()
		return
	}
	if _, err := pc.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		_ = pc.Close()
		return
	}
	dialPortFn(pc, targetPort, directHost)
}
