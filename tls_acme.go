package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func ensurePeekedConn(c net.Conn) (*peekedConn, *bufio.Reader) {
	if pc, ok := c.(*peekedConn); ok {
		return pc, pc.r
	}
	br := bufio.NewReaderSize(c, 4096)
	pc := &peekedConn{Conn: c, r: br}
	return pc, br
}


type SNICertManager struct {
	mu                    sync.RWMutex
	certDir               string
	certFile              string
	keyFile               string
	caCert                *x509.Certificate
	caKey                 ed25519.PrivateKey
	caPEM                 []byte
	caFingerprint         string
	cache                 map[string]*tls.Certificate
	static                *tls.Certificate
	defaultDomain         string
	enableACME            bool
	allowSelfSignedPublic bool
	acmeDirectory         string
	ddns                  DDNSConfig
	challengeMu           sync.RWMutex
	httpChallenges        map[string]string
	alpnChallenges        map[string]*tls.Certificate
	issueMu               sync.Mutex
	domainLocks           map[string]*sync.Mutex
}

func newSNICertManager(certDir, certFile, keyFile string) (*SNICertManager, error) {
	if certDir == "" {
		certDir = ".driftless-certs"
	}
	m := &SNICertManager{
		certDir:        certDir,
		certFile:       certFile,
		keyFile:        keyFile,
		cache:          make(map[string]*tls.Certificate),
		enableACME:     false,
		acmeDirectory:  "https://acme-v02.api.letsencrypt.org/directory",
		httpChallenges: make(map[string]string),
		alpnChallenges: make(map[string]*tls.Certificate),
		domainLocks:    make(map[string]*sync.Mutex),
	}
	if certFile != "" && keyFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load -tls-cert/-tls-key: %w", err)
		}
		m.static = &c
		return m, nil
	}

	caCertPath := filepath.Join(certDir, "ca-root.crt")
	caKeyPath := filepath.Join(certDir, "ca-root.key")
	if certBytes, errC := os.ReadFile(caCertPath); errC == nil {
		if keyBytes, errK := os.ReadFile(caKeyPath); errK == nil {
			if cBlock, _ := pem.Decode(certBytes); cBlock != nil {
				if kBlock, _ := pem.Decode(keyBytes); kBlock != nil {
					if parsedCA, errP := x509.ParseCertificate(cBlock.Bytes); errP == nil && time.Now().Before(parsedCA.NotAfter) {
						if parsedKey, errPK := x509.ParsePKCS8PrivateKey(kBlock.Bytes); errPK == nil {
							if edKey, ok := parsedKey.(ed25519.PrivateKey); ok {
								sum := sha256.Sum256(parsedCA.Raw)
								m.caCert = parsedCA
								m.caKey = edKey
								m.caPEM = certBytes
								m.caFingerprint = hex.EncodeToString(sum[:])
								return m, nil
							}
						}
					}
				}
			}
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"driftless Auto-TLS CA"}, CommonName: "driftless Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, pub, priv)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if privDER, errM := x509.MarshalPKCS8PrivateKey(priv); errM == nil {
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		_ = os.MkdirAll(certDir, 0o700)
		_ = writeFileAtomic0600(caCertPath, caPEM)
		_ = writeFileAtomic0600(caKeyPath, keyPEM)
	}
	sum := sha256.Sum256(caCert.Raw)
	m.caCert = caCert
	m.caKey = priv
	m.caPEM = caPEM
	m.caFingerprint = hex.EncodeToString(sum[:])
	return m, nil
}

func (m *SNICertManager) lockDomain(domain string) *sync.Mutex {
	m.issueMu.Lock()
	lk, ok := m.domainLocks[domain]
	if !ok {
		lk = &sync.Mutex{}
		m.domainLocks[domain] = lk
	}
	m.issueMu.Unlock()
	lk.Lock()
	return lk
}

func isSafeDomainName(host string) bool {
	if host == "" || len(host) > 253 || strings.Contains(host, "..") {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return host[0] != '.' && host[0] != '-' && filepath.Base(host) == host
}

func isValidACMEToken(tok string) bool {
	if len(tok) == 0 || len(tok) > 128 {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (m *SNICertManager) setHTTPChallenge(token, keyAuth string) {
	m.challengeMu.Lock()
	m.httpChallenges[token] = keyAuth
	m.challengeMu.Unlock()
}

func (m *SNICertManager) deleteHTTPChallenge(token string) {
	m.challengeMu.Lock()
	delete(m.httpChallenges, token)
	m.challengeMu.Unlock()
}

func (m *SNICertManager) getHTTPChallenge(token string) (string, bool) {
	if !isValidACMEToken(token) {
		return "", false
	}
	m.challengeMu.RLock()
	val, ok := m.httpChallenges[token]
	m.challengeMu.RUnlock()
	return val, ok
}

// buildTLSALPN01Cert builds an RFC 8737 self-signed TLS-ALPN-01 validation certificate for port 443 (works without port 80).
func buildTLSALPN01Cert(domain, keyAuth string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(keyAuth))
	// ASN.1 DER encoding of OCTET STRING of length 32: 0x04, 0x20, followed by 32-byte digest
	extVal := append([]byte{0x04, 0x20}, sum[:]...)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{1, 3, 6, 1, 5, 5, 7, 1, 31}, // id-pe-acmeIdentifier (RFC 8737)
				Critical: true,
				Value:    extVal,
			},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (m *SNICertManager) setALPNChallenge(domain, keyAuth string) {
	if c, err := buildTLSALPN01Cert(strings.ToLower(domain), keyAuth); err == nil {
		m.challengeMu.Lock()
		m.alpnChallenges[strings.ToLower(domain)] = c
		m.challengeMu.Unlock()
	}
}

func (m *SNICertManager) deleteALPNChallenge(domain string) {
	m.challengeMu.Lock()
	delete(m.alpnChallenges, strings.ToLower(domain))
	m.challengeMu.Unlock()
}

// certNeedsRenewal returns true if cert is nil, unparseable, or expires within renewalThreshold (default 30 days).
func certNeedsRenewal(cert *tls.Certificate, renewalThreshold time.Duration) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return true
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}
	return time.Until(leaf.NotAfter) < renewalThreshold
}

func isAutoIPDomain(host string) bool {
	return strings.HasSuffix(host, ".sslip.io") || strings.HasSuffix(host, ".nip.io")
}

func isPublicACMEDomain(host string) bool {
	if !isSafeDomainName(host) || host == "localhost" || net.ParseIP(host) != nil {
		return false
	}
	if !strings.Contains(host, ".") {
		return false
	}
	for _, reserved := range []string{".local", ".localhost", ".internal", ".test", ".invalid", ".example.com"} {
		if strings.HasSuffix(host, reserved) {
			return false
		}
	}
	return true
}

// ensureDomainCertificate checks if a valid non-expiring certificate for domain already exists on disk;
// if it exists, it loads and uses it without recreating. Otherwise, it creates and saves it to disk.
func (m *SNICertManager) ensureDomainCertificate(domain string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !isSafeDomainName(domain) {
		return
	}
	m.mu.Lock()
	m.defaultDomain = domain
	m.enableACME = true
	m.mu.Unlock()

	candidates := [][2]string{
		{filepath.Join(m.certDir, domain+".crt"), filepath.Join(m.certDir, domain+".key")},
		{filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem"), filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")},
	}
	for _, pair := range candidates {
		if _, err := os.Stat(pair[0]); err == nil {
			if c, err := tls.LoadX509KeyPair(pair[0], pair[1]); err == nil && !certNeedsRenewal(&c, 30*24*time.Hour) {
				m.mu.Lock()
				m.cache[domain] = &c
				m.mu.Unlock()
				log.Printf("[tls] using existing certificate for %s (%s)", domain, pair[0])
				return
			}
		}
	}

	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: domain}); err == nil {
		log.Printf("[tls] created and saved certificate for %s in %s", domain, m.certDir)
	}
}

// startRenewalScheduler runs a periodic background scheduler (every 12 hours) to renew certificates before they expire.
func (m *SNICertManager) startRenewalScheduler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.renewExpiringCertificates()
			}
		}
	}()
}

func (m *SNICertManager) renewExpiringCertificates() {
	m.mu.RLock()
	var domains []string
	for host, cert := range m.cache {
		if host != "" && host != "localhost" && certNeedsRenewal(cert, 30*24*time.Hour) {
			domains = append(domains, host)
		}
	}
	m.mu.RUnlock()

	if entries, err := os.ReadDir(m.certDir); err == nil {
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() && strings.HasSuffix(name, ".crt") {
				dom := strings.TrimSuffix(name, ".crt")
				if isSafeDomainName(dom) {
					crtPath := filepath.Join(m.certDir, dom+".crt")
					keyPath := filepath.Join(m.certDir, dom+".key")
					if c, err := tls.LoadX509KeyPair(crtPath, keyPath); err == nil && certNeedsRenewal(&c, 30*24*time.Hour) {
						domains = append(domains, dom)
					}
				}
			}
		}
	}

	seen := make(map[string]struct{}, len(domains))
	for _, dom := range domains {
		if _, dup := seen[dom]; dup {
			continue
		}
		seen[dom] = struct{}{}
		_ = m.renewDomainIfNeeded(dom)
	}
}

func (m *SNICertManager) renewDomainIfNeeded(host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if !isSafeDomainName(host) || host == "localhost" {
		return nil
	}
	domLock := m.lockDomain(host)
	defer domLock.Unlock()

	m.mu.RLock()
	cached, ok := m.cache[host]
	m.mu.RUnlock()
	if ok && !certNeedsRenewal(cached, 30*24*time.Hour) {
		return nil
	}

	if m.enableACME && isPublicACMEDomain(host) {
		acmeCert, err := m.obtainACMECertificate(host)
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.cache[host] = acmeCert
		m.mu.Unlock()
		log.Printf("[tls] renewed ACME certificate for %s", host)
		return nil
	}

	tlsCert, err := m.issueLocalCACertificate(host)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.cache[host] = tlsCert
	m.mu.Unlock()
	return nil
}

func (m *SNICertManager) issueLocalCACertificate(host string) (*tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, pub, m.caKey)
	if err != nil {
		return nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if host != "localhost" && isSafeDomainName(host) {
		_ = os.MkdirAll(m.certDir, 0o700)
		_ = writeFileAtomic0600(filepath.Join(m.certDir, host+".crt"), certPEM)
		_ = writeFileAtomic0600(filepath.Join(m.certDir, host+".key"), keyPEM)
	}
	return &tlsCert, nil
}

func (m *SNICertManager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.static != nil {
		return m.static, nil
	}
	host := ""
	if hello != nil {
		host = strings.ToLower(strings.TrimSpace(hello.ServerName))
		// Serve RFC 8737 TLS-ALPN-01 challenge on port 443 (works without HTTP port 80)
		for _, proto := range hello.SupportedProtos {
			if proto == "acme-tls/1" {
				m.challengeMu.RLock()
				alpnCert, ok := m.alpnChallenges[host]
				m.challengeMu.RUnlock()
				if ok && alpnCert != nil {
					return alpnCert, nil
				}
			}
		}
	}
	if host == "" {
		m.mu.RLock()
		def := m.defaultDomain
		m.mu.RUnlock()
		if def != "" {
			host = def
		} else {
			host = "localhost"
		}
	}

	m.mu.RLock()
	cached, ok := m.cache[host]
	m.mu.RUnlock()
	if ok && cached != nil {
		if !certNeedsRenewal(cached, 30*24*time.Hour) {
			return cached, nil
		}
		// If within 30-day renewal window but still valid today, renew asynchronously without blocking the TLS handshake
		if !certNeedsRenewal(cached, 0) {
			go func(h string) { _ = m.renewDomainIfNeeded(h) }(host)
			return cached, nil
		}
	}

	domLock := m.lockDomain(host)
	defer domLock.Unlock()

	m.mu.RLock()
	cached, ok = m.cache[host]
	m.mu.RUnlock()
	if ok && cached != nil && !certNeedsRenewal(cached, 30*24*time.Hour) {
		return cached, nil
	}

	// 1. Check persisted certificates on disk (if it exists and is valid, use it without recreating)
	var existingValid *tls.Certificate
	if host != "localhost" && isSafeDomainName(host) {
		candidates := [][2]string{
			{filepath.Join(m.certDir, host+".crt"), filepath.Join(m.certDir, host+".key")},
			{filepath.Join("/etc/letsencrypt/live", host, "fullchain.pem"), filepath.Join("/etc/letsencrypt/live", host, "privkey.pem")},
		}
		for _, pair := range candidates {
			if _, err := os.Stat(pair[0]); err == nil {
				if c, err := tls.LoadX509KeyPair(pair[0], pair[1]); err == nil {
					if !certNeedsRenewal(&c, 30*24*time.Hour) {
						m.mu.Lock()
						m.cache[host] = &c
						m.mu.Unlock()
						return &c, nil
					}
					if !certNeedsRenewal(&c, 0) {
						cCopy := c
						existingValid = &cCopy
					}
				}
			}
		}
	}

	// 2. Built-in RFC 8555 ACME v2 automatic certificate issuance (supports TLS-ALPN-01 on :443, DNS-01 via DuckDNS, and HTTP-01 on :80)
	if m.enableACME && isPublicACMEDomain(host) {
		acmeCert, err := m.obtainACMECertificate(host)
		if err == nil && acmeCert != nil {
			m.mu.Lock()
			m.cache[host] = acmeCert
			m.mu.Unlock()
			return acmeCert, nil
		}
		// If renewal failed temporarily but we still have an unexpired certificate on disk, keep serving it
		if existingValid != nil {
			m.mu.Lock()
			m.cache[host] = existingValid
			m.mu.Unlock()
			return existingValid, nil
		}
		// For custom public domains, do NOT silently fall back to an untrusted self-signed certificate unless explicitly enabled
		if !m.allowSelfSignedPublic && !isAutoIPDomain(host) {
			return nil, fmt.Errorf("acme certificate issuance failed for public domain %s: %w", host, err)
		}
	}

	tlsCert, err := m.issueLocalCACertificate(host)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.cache[host] = tlsCert
	m.mu.Unlock()
	return tlsCert, nil
}

func (m *SNICertManager) loadOrCreateACMEAccountKey() (*ecdsa.PrivateKey, error) {
	_ = os.MkdirAll(m.certDir, 0o700)
	keyPath := filepath.Join(m.certDir, "acme-account.key")
	if b, err := os.ReadFile(keyPath); err == nil {
		if block, _ := pem.Decode(b); block != nil {
			if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if der, err := x509.MarshalECPrivateKey(k); err == nil {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		_ = writeFileAtomic0600(keyPath, pemBytes)
	}
	return k, nil
}

// obtainACMECertificate implements an RFC 8555 ACME v2 client supporting TLS-ALPN-01 (:443), DNS-01 (DuckDNS TXT), and HTTP-01 (:80).
func (m *SNICertManager) obtainACMECertificate(domain string) (*tls.Certificate, error) {
	if !isSafeDomainName(domain) {
		return nil, errors.New("unsafe domain name")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	httpClient := &http.Client{Timeout: 8 * time.Second}

	dirReq, err := http.NewRequestWithContext(ctx, "GET", m.acmeDirectory, nil)
	if err != nil {
		return nil, err
	}
	dirResp, err := httpClient.Do(dirReq)
	if err != nil {
		return nil, err
	}
	defer dirResp.Body.Close()
	var dir struct {
		NewNonce   string `json:"newNonce"`
		NewAccount string `json:"newAccount"`
		NewOrder   string `json:"newOrder"`
	}
	if err := json.NewDecoder(dirResp.Body).Decode(&dir); err != nil || dir.NewNonce == "" {
		return nil, errors.New("invalid acme directory")
	}

	acctKey, err := m.loadOrCreateACMEAccountKey()
	if err != nil {
		return nil, err
	}
	b64 := base64.RawURLEncoding.EncodeToString
	pad32 := func(b []byte) []byte {
		if len(b) >= 32 {
			return b[len(b)-32:]
		}
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return out
	}
	xBytes := pad32(acctKey.PublicKey.X.Bytes())
	yBytes := pad32(acctKey.PublicKey.Y.Bytes())
	jwkJSON := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, b64(xBytes), b64(yBytes))
	jwkHash := sha256.Sum256([]byte(jwkJSON))
	thumbprint := b64(jwkHash[:])

	getNonce := func() (string, error) {
		req, err := http.NewRequestWithContext(ctx, "HEAD", dir.NewNonce, nil)
		if err != nil {
			return "", err
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return "", err
		}
		_ = resp.Body.Close()
		return resp.Header.Get("Replay-Nonce"), nil
	}

	var kid string
	acmePost := func(targetURL string, payload interface{}) ([]byte, http.Header, error) {
		nonce, err := getNonce()
		if err != nil || nonce == "" {
			return nil, nil, errors.New("failed to get acme nonce")
		}
		var payloadB64 string
		if payload != nil {
			raw, err := json.Marshal(payload)
			if err != nil {
				return nil, nil, err
			}
			payloadB64 = b64(raw)
		}
		var protectedMap map[string]interface{}
		if kid == "" {
			var jwkObj map[string]string
			_ = json.Unmarshal([]byte(jwkJSON), &jwkObj)
			protectedMap = map[string]interface{}{
				"alg":   "ES256",
				"jwk":   jwkObj,
				"nonce": nonce,
				"url":   targetURL,
			}
		} else {
			protectedMap = map[string]interface{}{
				"alg":   "ES256",
				"kid":   kid,
				"nonce": nonce,
				"url":   targetURL,
			}
		}
		protRaw, _ := json.Marshal(protectedMap)
		protB64 := b64(protRaw)
		signingInput := protB64 + "." + payloadB64
		digest := sha256.Sum256([]byte(signingInput))
		rSig, sSig, err := ecdsa.Sign(rand.Reader, acctKey, digest[:])
		if err != nil {
			return nil, nil, err
		}
		sigBytes := append(pad32(rSig.Bytes()), pad32(sSig.Bytes())...)
		jwsBody, _ := json.Marshal(map[string]string{
			"protected": protB64,
			"payload":   payloadB64,
			"signature": b64(sigBytes),
		})
		req, err := http.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(jwsBody))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, resp.Header, fmt.Errorf("acme status %d: %s", resp.StatusCode, string(body))
		}
		return body, resp.Header, nil
	}

	_, hdr, err := acmePost(dir.NewAccount, map[string]interface{}{"termsOfServiceAgreed": true})
	if err != nil {
		return nil, err
	}
	kid = hdr.Get("Location")
	if kid == "" {
		return nil, errors.New("missing acme account location")
	}

	orderBody, orderHdr, err := acmePost(dir.NewOrder, map[string]interface{}{
		"identifiers": []map[string]string{{"type": "dns", "value": domain}},
	})
	if err != nil {
		return nil, err
	}
	orderURL := orderHdr.Get("Location")
	var order struct {
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
		Certificate    string   `json:"certificate"`
	}
	if err := json.Unmarshal(orderBody, &order); err != nil || len(order.Authorizations) == 0 {
		return nil, errors.New("invalid acme order")
	}

	authzBody, _, err := acmePost(order.Authorizations[0], nil)
	if err != nil {
		return nil, err
	}
	var authz struct {
		Challenges []struct {
			Type  string `json:"type"`
			URL   string `json:"url"`
			Token string `json:"token"`
		} `json:"challenges"`
	}
	if err := json.Unmarshal(authzBody, &authz); err != nil {
		return nil, err
	}

	var chalURL, chalToken, chalType string
	hasDuckDNS := strings.EqualFold(m.ddns.Provider, "duckdns") && m.ddns.Token != "" && strings.HasSuffix(domain, ".duckdns.org")
	for _, ch := range authz.Challenges {
		if !isValidACMEToken(ch.Token) {
			continue
		}
		if hasDuckDNS && ch.Type == "dns-01" {
			chalURL, chalToken, chalType = ch.URL, ch.Token, ch.Type
			break
		}
		if ch.Type == "tls-alpn-01" && chalURL == "" {
			chalURL, chalToken, chalType = ch.URL, ch.Token, ch.Type
		}
		if ch.Type == "http-01" {
			chalURL, chalToken, chalType = ch.URL, ch.Token, ch.Type
		}
	}
	if chalURL == "" || chalToken == "" {
		return nil, errors.New("no supported acme challenge offered")
	}

	keyAuth := chalToken + "." + thumbprint
	m.setHTTPChallenge(chalToken, keyAuth)
	defer m.deleteHTTPChallenge(chalToken)
	m.setALPNChallenge(domain, keyAuth)
	defer m.deleteALPNChallenge(domain)

	if chalType == "dns-01" && hasDuckDNS {
		dnsDigest := sha256.Sum256([]byte(keyAuth))
		txtVal := b64(dnsDigest[:])
		sub := strings.TrimSuffix(domain, ".duckdns.org")
		txtURL := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&txt=%s", url.QueryEscape(sub), url.QueryEscape(m.ddns.Token), url.QueryEscape(txtVal))
		if resp, err := httpClient.Get(txtURL); err == nil {
			_ = resp.Body.Close()
		}
		defer func() {
			clrURL := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&txt=&clear=true", url.QueryEscape(sub), url.QueryEscape(m.ddns.Token))
			if resp, err := httpClient.Get(clrURL); err == nil {
				_ = resp.Body.Close()
			}
		}()
	}

	if _, _, err := acmePost(chalURL, map[string]string{}); err != nil {
		return nil, err
	}

	for i := 0; i < 12; i++ {
		time.Sleep(500 * time.Millisecond)
		b, _, err := acmePost(order.Authorizations[0], nil)
		if err != nil {
			return nil, err
		}
		var st struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(b, &st)
		if st.Status == "valid" {
			break
		}
		if st.Status == "invalid" {
			return nil, fmt.Errorf("acme %s validation failed", chalType)
		}
	}

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, certPrivKey)
	if err != nil {
		return nil, err
	}
	if _, _, err := acmePost(order.Finalize, map[string]string{"csr": b64(csrDER)}); err != nil {
		return nil, err
	}

	var certURL string
	for i := 0; i < 12; i++ {
		if orderURL == "" {
			break
		}
		b, _, err := acmePost(orderURL, nil)
		if err != nil {
			break
		}
		var st struct {
			Status      string `json:"status"`
			Certificate string `json:"certificate"`
		}
		_ = json.Unmarshal(b, &st)
		if st.Certificate != "" {
			certURL = st.Certificate
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	if certURL == "" {
		return nil, errors.New("acme certificate URL not ready")
	}

	certPEM, _, err := acmePost(certURL, nil)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(certPrivKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	_ = os.MkdirAll(m.certDir, 0o700)
	_ = writeFileAtomic0600(filepath.Join(m.certDir, domain+".crt"), certPEM)
	_ = writeFileAtomic0600(filepath.Join(m.certDir, domain+".key"), keyPEM)
	log.Printf("[auto-tls] obtained trusted Let's Encrypt certificate for %s via ACME %s", domain, chalType)
	return &tlsCert, nil
}

func (m *SNICertManager) tlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate:   m.getCertificate,
		MinVersion:       tls.VersionTLS12,
		NextProtos:       []string{"acme-tls/1", "http/1.1"},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

// maybeTerminateTLS peeks at the first byte of conn; if it is a TLS ClientHello (0x16) and autoTLS is enabled, wraps in TLS server.
func maybeTerminateTLS(c net.Conn, sniMgr *SNICertManager, enableTLS bool) net.Conn {
	return maybeTerminateTLSWithTimeout(c, sniMgr, enableTLS, 3*time.Second)
}

func maybeTerminateTLSWithTimeout(c net.Conn, sniMgr *SNICertManager, enableTLS bool, peekTimeout time.Duration) net.Conn {
	if !enableTLS || sniMgr == nil {
		return c
	}
	if peekTimeout <= 0 {
		peekTimeout = 3 * time.Second
	}
	pc, br := ensurePeekedConn(c)
	_ = pc.Conn.SetReadDeadline(time.Now().Add(peekTimeout))
	b, err := br.Peek(1)
	_ = pc.Conn.SetReadDeadline(time.Time{})
	if err == nil && len(b) == 1 && b[0] == 0x16 {
		tlsConn := tls.Server(pc, sniMgr.tlsConfig())
		_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			_ = tlsConn.Close()
			return tlsConn
		}
		_ = tlsConn.SetDeadline(time.Time{})
		// RFC 8737 Section 4: Once the TLS-ALPN-01 handshake completes, close the connection immediately
		if tlsConn.ConnectionState().NegotiatedProtocol == "acme-tls/1" {
			_ = tlsConn.Close()
			return tlsConn
		}
		return tlsConn
	}
	return pc
}

func loadGatewayCert(certDir string) (*tls.Config, string, error) {
	if strings.TrimSpace(certDir) == "" {
		certDir = ".driftless-certs"
	}
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")
	var certPEM, keyPEM []byte
	if certDir != "" {
		c, errC := os.ReadFile(certPath)
		k, errK := os.ReadFile(keyPath)
		if errC == nil && errK == nil {
			if _, pairErr := tls.X509KeyPair(c, k); pairErr == nil {
				if blk, _ := pem.Decode(c); blk != nil {
					if parsed, pErr := x509.ParseCertificate(blk.Bytes); pErr == nil && time.Now().Before(parsed.NotAfter) {
						certPEM, keyPEM = c, k
					}
				}
			}
			if certPEM == nil {
				ts := time.Now().UnixNano()
				_ = os.Rename(certPath, fmt.Sprintf("%s.corrupt-%d", certPath, ts))
				_ = os.Rename(keyPath, fmt.Sprintf("%s.corrupt-%d", keyPath, ts))
				log.Printf("[gateway] WARNING: existing gateway certificate in %s was invalid or expired; preserved backup and regenerating fresh Ed25519 certificate", certDir)
			}
		}
	}
	if certPEM == nil || keyPEM == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", err
		}
		tpl := x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, pub, priv)
		if err != nil {
			return nil, "", err
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, "", err
		}
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		if certDir != "" {
			if err := os.MkdirAll(certDir, 0o700); err != nil {
				return nil, "", fmt.Errorf("mkdir %s: %w", certDir, err)
			}
			if err := writeFileAtomic0600(certPath, certPEM); err != nil {
				return nil, "", fmt.Errorf("write cert.pem: %w", err)
			}
			if err := writeFileAtomic0600(keyPath, keyPEM); err != nil {
				return nil, "", fmt.Errorf("write key.pem: %w", err)
			}
		}
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, "", errors.New("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(cert.Raw)
	fp := hex.EncodeToString(sum[:])
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", err
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{alpnProtocol}}, fp, nil
}

var (
	agentTOFUMu   sync.Mutex
	agentTOFUPins = make(map[string][]byte)
)

func makeAgentTLS(fingerprint string) (*tls.Config, error) {
	return makeAgentTLSForGateway(fingerprint, "default")
}

func makeAgentTLSForGateway(fingerprint, gatewayAddr string) (*tls.Config, error) {
	var wantPrefixes [][]byte
	for _, part := range strings.Split(fingerprint, ",") {
		fpClean := strings.ToLower(strings.TrimSpace(part))
		if fpClean == "" {
			continue
		}
		decoded, err := hex.DecodeString(fpClean)
		if err != nil || len(decoded) < 8 || len(decoded) > sha256.Size {
			return nil, errors.New("invalid -fingerprint: expected 16..64 hex chars (SHA-256)")
		}
		wantPrefixes = append(wantPrefixes, decoded)
	}
	gwKey := strings.TrimSpace(gatewayAddr)
	if gwKey == "" {
		gwKey = "default"
	}

	return &tls.Config{
		InsecureSkipVerify: true, // Custom cryptographic certificate pinning in VerifyPeerCertificate below
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpnProtocol},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificate presented by gateway")
			}
			parsed, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("invalid gateway x509 certificate: %w", err)
			}
			now := time.Now()
			if now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
				return errors.New("gateway certificate is expired or not yet valid")
			}
			sum := sha256.Sum256(rawCerts[0])
			if len(wantPrefixes) > 0 {
				for _, wp := range wantPrefixes {
					if hmac.Equal(sum[:len(wp)], wp) {
						return nil
					}
				}
				return fmt.Errorf("certificate fingerprint mismatch: got %x, none of %d configured prefixes matched", sum[:8], len(wantPrefixes))
			}
			// Automatic Trust-On-First-Use (TOFU) certificate pinning per gateway address
			agentTOFUMu.Lock()
			defer agentTOFUMu.Unlock()
			pinned := agentTOFUPins[gwKey]
			if len(pinned) == 0 {
				agentTOFUPins[gwKey] = append([]byte(nil), sum[:]...)
				log.Printf("[agent] pinned gateway %s TLS certificate (sha256: %x)", gwKey, sum[:8])
				return nil
			}
			if !hmac.Equal(sum[:], pinned) {
				return fmt.Errorf("MITM alert: gateway %s certificate changed mid-session (got %x, pinned %x)", gwKey, sum[:8], pinned[:8])
			}
			return nil
		},
	}, nil
}

func configureGatewayMTLS(tlsConf *tls.Config, clientCAFile string) error {
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("failed to parse client CA PEM")
	}
	tlsConf.ClientCAs = pool
	tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
	return nil
}

func configureAgentMTLS(tlsConf *tls.Config, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	tlsConf.Certificates = []tls.Certificate{cert}
	return nil
}

