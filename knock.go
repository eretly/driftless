package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
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
	defaultKnockTTL     = 1 * time.Hour
	knockSecretFileName = "knock.secret"
	knockURLFileName    = "knock-url.txt"
)

var defaultKnockController *KnockController

type KnockController struct {
	secret        string
	ttl           time.Duration
	mu            sync.RWMutex
	allowed       map[string]map[uint16]time.Time // IP key -> port (0 = all mapped ports) -> expiration
	attempts      map[string]authAttempt
	mappedPorts   []PortMapping
	publicHost    string
	primaryPort   uint16
	useTLS        bool
	isStandalone  bool
	targetHost    string
	allowedPorts  map[uint16]struct{}
	caCertPEM     []byte
	caFingerprint string
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
		allowed:      make(map[string]map[uint16]time.Time),
		attempts:     make(map[string]authAttempt),
		mappedPorts:  append([]PortMapping(nil), mappings...),
		primaryPort:  primaryPort,
		useTLS:       true,
		isStandalone: isStandalone,
		targetHost:   targetHost,
		allowedPorts: allowedPorts,
	}, nil
}

func (kc *KnockController) SetRootCA(caPEM []byte, fingerprint string) {
	if kc == nil {
		return
	}
	kc.mu.Lock()
	kc.caCertPEM = append([]byte(nil), caPEM...)
	kc.caFingerprint = fingerprint
	kc.mu.Unlock()
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
	_, wErr := fmt.Fprintf(ttyFile, "[%s] Open once on your iPhone / Android / laptop to unlock mapped ports (bookmark it):\n  %s\n", prefix, magicURL)
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
	return kc.IsAllowedPort(addr, 0)
}

func (kc *KnockController) IsAllowedPort(addr net.Addr, port uint16) bool {
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
	portsMap, ok := kc.allowed[key]
	if !ok || len(portsMap) == 0 {
		kc.mu.RUnlock()
		return false
	}
	if expAll, hasAll := portsMap[0]; hasAll && now.Before(expAll) {
		kc.mu.RUnlock()
		return true
	}
	if port == 0 {
		for _, exp := range portsMap {
			if now.Before(exp) {
				kc.mu.RUnlock()
				return true
			}
		}
		kc.mu.RUnlock()
		return false
	}
	expPort, hasPort := portsMap[port]
	kc.mu.RUnlock()
	return hasPort && now.Before(expPort)
}

func (kc *KnockController) AuthorizeAddr(addr net.Addr) time.Time {
	return kc.AuthorizeAddrPort(addr, 0)
}

func (kc *KnockController) AuthorizeAddrPort(addr net.Addr, port uint16) time.Time {
	host := extractAddrHost(addr)
	key := normalizeAuthIPKey(host)
	now := time.Now()
	exp := now.Add(kc.ttl)

	kc.mu.Lock()
	defer kc.mu.Unlock()
	if len(kc.allowed) >= maxAuthTrackedIPs {
		for k, portMap := range kc.allowed {
			active := false
			for p, v := range portMap {
				if now.After(v) {
					delete(portMap, p)
				} else {
					active = true
				}
			}
			if !active {
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
	portMap, ok := kc.allowed[key]
	if !ok {
		portMap = make(map[uint16]time.Time)
		kc.allowed[key] = portMap
	}
	portMap[port] = exp
	if port > 0 {
		for _, m := range kc.mappedPorts {
			if m.PublicPort == port || m.TargetPort == port {
				portMap[m.PublicPort] = exp
				portMap[m.TargetPort] = exp
			}
		}
	}
	delete(kc.attempts, key)
	return exp
}

func (kc *KnockController) RevokeAddr(addr net.Addr) {
	if kc == nil {
		return
	}
	host := extractAddrHost(addr)
	key := normalizeAuthIPKey(host)
	kc.mu.Lock()
	delete(kc.allowed, key)
	kc.mu.Unlock()
}

func (kc *KnockController) RevokeAll() int {
	if kc == nil {
		return 0
	}
	kc.mu.Lock()
	n := len(kc.allowed)
	kc.allowed = make(map[string]map[uint16]time.Time)
	kc.mu.Unlock()
	return n
}

func (kc *KnockController) VerifyKnockToken(addr net.Addr, candidate string) (bool, time.Time) {
	return kc.VerifyKnockTokenForPort(addr, candidate, 0)
}

func (kc *KnockController) VerifyKnockTokenForPort(addr net.Addr, candidate string, port uint16) (bool, time.Time) {
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
		exp := kc.AuthorizeAddrPort(addr, port)
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

// inspectAndPrepareTCPConn enforces -knock protection, serves the Magic Knock Launchpad (/.rdp/revoke/ca.crt),
// and performs Single-Port protocol auto-routing (SSH/RDP/HTTP on a single port).
// Returns (wrappedConn, resolvedTargetPort, handledOrClosed).
func inspectAndPrepareTCPConn(
	rawConn net.Conn,
	sniMgr *SNICertManager,
	useTLS bool,
	defaultTargetPort uint16,
	mappings []PortMapping,
) (net.Conn, uint16, bool) {
	kc := defaultKnockController
	remoteAddr := rawConn.RemoteAddr()

	if kc != nil && !kc.IsAllowedAddr(remoteAddr) {
		// Unauthenticated IP: only allow a valid Magic Knock HTTPS request; drop everything else before touching backends.
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

	resolvedPort := detectUniversalSinglePortOverride(hdr, defaultTargetPort, mappings)
	if kc != nil && !kc.IsAllowedPort(remoteAddr, resolvedPort) && !kc.IsAllowedPort(remoteAddr, defaultTargetPort) {
		_ = pc.Close()
		return nil, 0, true
	}
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

	var requestedPort uint16
	if qPort := strings.TrimSpace(req.URL.Query().Get("port")); qPort != "" {
		if p, err := strconv.Atoi(qPort); err == nil && p > 0 && p <= 65535 {
			requestedPort = uint16(p)
		}
	} else if strings.HasPrefix(subPath, "port/") {
		pStr := strings.TrimPrefix(subPath, "port/")
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 && p <= 65535 {
			requestedPort = uint16(p)
			subPath = ""
		}
	}

	clientIP := extractAddrHost(remoteAddr)

	// Handle immediate IP revocation before re-authorizing
	if subPath == "revoke" || req.URL.Query().Get("revoke") == "1" {
		if !hmac.Equal([]byte(strings.TrimSpace(candidateTok)), []byte(kc.secret)) {
			body := "404 Not Found\n"
			resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			_, _ = pc.Write([]byte(resp))
			return
		}
		revokedAll := false
		if req.URL.Query().Get("all") == "1" {
			n := kc.RevokeAll()
			revokedAll = true
			log.Printf("[knock] revoked all unlocked IPs (%d entries) on request from %s", n, clientIP)
		} else {
			kc.RevokeAddr(remoteAddr)
			log.Printf("[knock] revoked access for client IP %s", clientIP)
		}
		payload, _ := json.Marshal(map[string]any{
			"status":      "revoked",
			"client_ip":   clientIP,
			"revoked_all": revokedAll,
		})
		hdr := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
			len(payload),
		)
		_, _ = pc.Write(append([]byte(hdr), payload...))
		return
	}

	ok, exp := kc.VerifyKnockTokenForPort(remoteAddr, candidateTok, requestedPort)
	if !ok {
		body := "404 Not Found\n"
		resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		_, _ = pc.Write([]byte(resp))
		return
	}

	if requestedPort > 0 {
		log.Printf("[knock] unlocked client IP %s for port %d until %s", clientIP, requestedPort, exp.Format(time.RFC3339))
	} else {
		log.Printf("[knock] unlocked client IP %s for all mapped ports until %s", clientIP, exp.Format(time.RFC3339))
	}

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

	case "ca.crt":
		kc.mu.RLock()
		caPEM := kc.caCertPEM
		kc.mu.RUnlock()
		if len(caPEM) == 0 {
			body := "404 Not Found\n"
			resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			_, _ = pc.Write([]byte(resp))
			return
		}
		hdr := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Type: application/x-x509-ca-cert\r\nContent-Disposition: attachment; filename=\"driftless-root-ca.crt\"\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
			len(caPEM),
		)
		_, _ = pc.Write(append([]byte(hdr), caPEM...))
		return

	case "status.json":
		payload, _ := json.Marshal(map[string]any{
			"status":         "unlocked",
			"client_ip":      clientIP,
			"unlocked_port":  requestedPort,
			"expires_at":     exp.UTC().Format(time.RFC3339),
			"ttl_seconds":    int(time.Until(exp).Seconds()),
			"host":           reqHost,
			"ca_fingerprint": kc.caFingerprint,
		})
		hdr := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
			len(payload),
		)
		_, _ = pc.Write(append([]byte(hdr), payload...))
		return
	}

	page := kc.buildLaunchpadHTML(reqHost, clientIP, requestedPort, exp)
	hdr := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
		len(page),
	)
	_, _ = pc.Write([]byte(hdr + page))
}

func (kc *KnockController) buildLaunchpadHTML(host, clientIP string, unlockedPort uint16, exp time.Time) string {
	safeHost := html.EscapeString(host)
	safeIP := html.EscapeString(clientIP)
	ttlMins := int(time.Until(exp).Minutes())
	ttlLabel := fmt.Sprintf("%d min", ttlMins)
	if ttlMins >= 120 {
		ttlLabel = fmt.Sprintf("%.1f h", time.Until(exp).Hours())
	}
	scheme := "https"
	rdpFileURL := fmt.Sprintf("%s://%s:%d%s%s/connect.rdp", scheme, safeHost, kc.primaryPort, knockPathPrefix, kc.secret)
	revokeURL := fmt.Sprintf("%s://%s:%d%s%s/revoke", scheme, safeHost, kc.primaryPort, knockPathPrefix, kc.secret)
	caURL := fmt.Sprintf("%s://%s:%d%s%s/ca.crt", scheme, safeHost, kc.primaryPort, knockPathPrefix, kc.secret)

	scopeBadge := fmt.Sprintf("Mapped TCP &amp; UDP Ports Unlocked (%s)", ttlLabel)
	if unlockedPort > 0 {
		scopeBadge = fmt.Sprintf("Port :%d Unlocked (%s)", unlockedPort, ttlLabel)
	}

	var cards strings.Builder
	for _, m := range kc.mappedPorts {
		pub := m.PublicPort
		loc := m.TargetPort
		portOnlyURL := fmt.Sprintf("%s://%s:%d%s%s?port=%d", scheme, safeHost, kc.primaryPort, knockPathPrefix, kc.secret, pub)
		switch loc {
		case 3389:
			cards.WriteString(fmt.Sprintf(
				`<div class="card"><div><strong>Windows Remote Desktop (RDP :%d)</strong><div class="sub">%s:%d (or single-port %s:%d)</div></div><div class="btns"><a class="btn" href="rdp://full%%20address=s:%s:%d">Open Windows App</a><a class="btn sec" href="%s">Download .rdp</a><a class="btn sec" href="%s">Unlock :%d Only</a></div></div>`,
				pub, safeHost, pub, safeHost, kc.primaryPort, safeHost, pub, rdpFileURL, portOnlyURL, pub,
			))
		case 22:
			cards.WriteString(fmt.Sprintf(
				`<div class="card"><div><strong>SSH / SFTP Terminal (:%d)</strong><div class="sub">%s:%d (WebSSH / Termius / SFTP)</div></div><div class="btns"><a class="btn" href="ssh://%s:%d">Open SSH</a><a class="btn sec" href="sftp://%s:%d">Open SFTP</a><a class="btn sec" href="%s">Unlock :%d Only</a></div></div>`,
				pub, safeHost, pub, safeHost, pub, safeHost, pub, portOnlyURL, pub,
			))
		default:
			portScheme := scheme
			if m.Proto == "https" || pub == 443 {
				portScheme = "https"
			}
			cards.WriteString(fmt.Sprintf(
				`<div class="card"><div><strong>Port :%d (Local :%d - %s)</strong><div class="sub">%s://%s:%d</div></div><div class="btns"><a class="btn" href="%s://%s:%d">Open in Browser</a><a class="btn sec" href="%s">Unlock :%d Only</a></div></div>`,
				pub, loc, strings.ToUpper(m.Proto), portScheme, safeHost, pub, portScheme, safeHost, pub, portOnlyURL, pub,
			))
		}
	}

	caBox := ""
	kc.mu.RLock()
	caFP := kc.caFingerprint
	hasCA := len(kc.caCertPEM) > 0
	kc.mu.RUnlock()
	if hasCA && caFP != "" {
		caBox = fmt.Sprintf(`  <div class="box">
    <div style="font-size:13px;font-weight:600;color:#cbd5e1">TLS Root CA Verification (No Public Domain / IP Mode)</div>
    <p style="margin:4px 0 8px;font-size:12px;color:#94a3b8">For public domains (e.g. DuckDNS), driftless issues a real Let's Encrypt certificate automatically. If connecting via raw IP or .sslip.io, you can verify or install this server's persistent Root CA once to prevent MITM:</p>
    <div class="sub">Root CA SHA-256: %s</div>
    <div class="btns" style="margin-top:8px"><a class="btn sec" href="%s">Download Root CA (ca.crt)</a></div>
  </div>`, html.EscapeString(caFP), caURL)
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
.sub{font-size:12px;color:#94a3b8;font-family:monospace;margin-top:3px;word-break:break-all}
.btns{display:flex;gap:8px;flex-wrap:wrap}
.btn{padding:8px 12px;border-radius:6px;background:#38bdf8;color:#090d16;text-decoration:none;font-weight:600;font-size:13px}
.btn.sec{background:#1e293b;color:#e2e8f0;border:1px solid #334155}
.btn.danger{background:#7f1d1d;color:#fecaca;border:1px solid #991b1b}
</style>
</head>
<body>
<div class="wrap">
  <div class="box">
    <span class="badge">%s</span>
    <h2 style="margin:10px 0 4px;font-size:18px">Your IP (%s) is authorized</h2>
    <p style="margin:0 0 12px;font-size:13px;color:#94a3b8">You can now connect from native apps on this device (WebSSH, Termius, Windows App RDP, Jellyfin, Moonlight). Save this page to your bookmarks to unlock again when your mobile IP changes.</p>
    <div class="btns">
      <a class="btn danger" href="%s">Revoke My IP Now</a>
      <a class="btn sec" href="%s?all=1">Revoke All Unlocked IPs</a>
    </div>
  </div>
  <div class="box">
    <div style="font-size:13px;font-weight:600;margin-bottom:6px;color:#cbd5e1">One-Tap App Launchers &amp; Per-Port Knock</div>
    %s
  </div>
%s
</div>
</body>
</html>`, scopeBadge, safeIP, revokeURL, revokeURL, cards.String(), caBox)
}
