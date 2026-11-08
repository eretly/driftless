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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	versionString = "v1.3.0"
	alpnProtocol  = "driftless-v1"
	cmdAuth       = uint8(0)
	cmdNewConn    = uint8(1)
	cmdResume     = uint8(2)
	cmdAuthNonce  = uint8(3)
	cmdAuthResp   = uint8(4)
	cmdAuthOK     = uint8(5)
	cmdUDPFlow    = uint8(6)

	frameData = uint8(1)
	frameAck  = uint8(2)
	frameFin  = uint8(3)

	maxChunkSize    = 32 * 1024
	maxUDPPacket    = 65507
	authTimeout     = 5 * time.Second
	maxAuthAttempts = 10
	authWindow      = 1 * time.Minute
	nonceLen        = 32
	udpSessionTTL   = 60 * time.Second
)

var (
	globalBufferedBytes atomic.Int64
)

type Session struct {
	id         uint64
	targetPort uint16
	tcpConn    net.Conn
	maxBuf     int64
	maxGlobal  int64
	createdAt  time.Time

	mu           sync.Mutex
	cond         *sync.Cond
	outBuf       []byte
	outBase      int
	baseOffset   uint64 // Confirmed (ACKed) offset by remote peer
	inOffset     uint64 // Bytes committed to our local TCP socket
	localEOF     bool
	remoteEOF    bool
	closed       bool
	activeStream quic.Stream
	streamGen    uint64
	lastActive   time.Time
	writeMutex   sync.Mutex
}

func tuneTCPSocket(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

func newSession(id uint64, targetPort uint16, conn net.Conn, maxBuf, maxGlobal int64, initialOutData []byte) *Session {
	tuneTCPSocket(conn)
	now := time.Now()
	s := &Session{
		id:         id,
		targetPort: targetPort,
		tcpConn:    conn,
		maxBuf:     maxBuf,
		maxGlobal:  maxGlobal,
		createdAt:  now,
		outBuf:     make([]byte, 0, 64*1024),
		lastActive: now,
	}
	if len(initialOutData) > 0 {
		s.outBuf = append(s.outBuf, initialOutData...)
		globalBufferedBytes.Add(int64(len(initialOutData)))
	}
	s.cond = sync.NewCond(&s.mu)
	go s.readFromTCP()
	return s
}

func (s *Session) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *Session) bufferedBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.outBuf) - s.outBase)
}

func (s *Session) writeAllTCP(data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := s.tcpConn.Write(data[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (s *Session) readFromTCP() {
	buf := make([]byte, maxChunkSize)
	for {
		n, err := s.tcpConn.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.lastActive = time.Now()
			for (int64(len(s.outBuf)-s.outBase) >= s.maxBuf || globalBufferedBytes.Load() >= s.maxGlobal) && !s.closed {
				s.cond.Wait()
			}
			if s.closed {
				s.mu.Unlock()
				return
			}
			s.outBuf = append(s.outBuf, buf[:n]...)
			globalBufferedBytes.Add(int64(n))
			s.cond.Broadcast()
			s.mu.Unlock()
		}
		if err != nil {
			s.mu.Lock()
			s.localEOF = true
			s.cond.Broadcast()
			s.mu.Unlock()
			return
		}
	}
}

func (s *Session) trimAcked(ackOffset uint64) {
	if ackOffset <= s.baseOffset {
		return
	}
	trim := ackOffset - s.baseOffset
	pending := int64(len(s.outBuf) - s.outBase)
	if trim > uint64(pending) {
		trim = uint64(pending)
	}
	s.outBase += int(trim)
	s.baseOffset += trim
	globalBufferedBytes.Add(-int64(trim))
	if s.outBase > 0 && s.outBase*2 >= len(s.outBuf) {
		remaining := len(s.outBuf) - s.outBase
		copy(s.outBuf, s.outBuf[s.outBase:])
		s.outBuf = s.outBuf[:remaining]
		s.outBase = 0
	}
	s.cond.Broadcast()
}

func (s *Session) closeSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		pending := int64(len(s.outBuf) - s.outBase)
		if pending > 0 {
			globalBufferedBytes.Add(-pending)
		}
		s.outBuf = nil
		s.outBase = 0
		_ = s.tcpConn.Close()
		if s.activeStream != nil {
			_ = s.activeStream.Close()
		}
		s.cond.Broadcast()
	}
}

func bridgeSessionStream(s *Session, stream quic.Stream) {
	s.mu.Lock()
	if s.activeStream != nil {
		_ = s.activeStream.Close()
	}
	s.streamGen++
	myGen := s.streamGen
	s.activeStream = stream
	myInOffset := s.inOffset
	s.lastActive = time.Now()
	s.mu.Unlock()

	defer stream.Close()

	var hdr [8]byte
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	binary.BigEndian.PutUint64(hdr[:], myInOffset)
	if _, err := stream.Write(hdr[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		return
	}
	_ = stream.SetDeadline(time.Time{})
	peerAckedOffset := binary.BigEndian.Uint64(hdr[:])

	s.mu.Lock()
	if peerAckedOffset < s.baseOffset {
		s.mu.Unlock()
		s.closeSession()
		return
	}
	s.trimAcked(peerAckedOffset)
	s.mu.Unlock()

	var streamWriteMu sync.Mutex
	sendFrame := func(b []byte) error {
		streamWriteMu.Lock()
		defer streamWriteMu.Unlock()
		_ = stream.SetWriteDeadline(time.Now().Add(8 * time.Second))
		total := 0
		for total < len(b) {
			n, err := stream.Write(b[total:])
			if n > 0 {
				total += n
			}
			if err != nil {
				_ = stream.SetWriteDeadline(time.Time{})
				return err
			}
		}
		_ = stream.SetWriteDeadline(time.Time{})
		return nil
	}

	doneSending := make(chan struct{})
	go func() {
		defer close(doneSending)
		sentOffset := peerAckedOffset
		finSent := false
		// Reusable zero-allocation frame buffer: 1 byte type + 4 bytes length + maxChunkSize payload
		frameBuf := make([]byte, 5+maxChunkSize)

		for {
			s.mu.Lock()
			if sentOffset < s.baseOffset {
				sentOffset = s.baseOffset
			}
			totalAvailable := s.baseOffset + uint64(len(s.outBuf)-s.outBase)
			for totalAvailable <= sentOffset && (!s.localEOF || finSent) && !s.closed && s.streamGen == myGen {
				s.cond.Wait()
				totalAvailable = s.baseOffset + uint64(len(s.outBuf)-s.outBase)
			}
			if s.closed || s.streamGen != myGen {
				s.mu.Unlock()
				return
			}

			chunkLen := 0
			if totalAvailable > sentOffset {
				startIdx := int(sentOffset-s.baseOffset) + s.outBase
				endIdx := len(s.outBuf)
				if endIdx-startIdx > maxChunkSize {
					endIdx = startIdx + maxChunkSize
				}
				chunkLen = endIdx - startIdx
				copy(frameBuf[5:5+chunkLen], s.outBuf[startIdx:endIdx])
			}
			shouldSendFin := s.localEOF && !finSent && (sentOffset+uint64(chunkLen) == totalAvailable)
			s.mu.Unlock()

			if chunkLen > 0 {
				frameBuf[0] = frameData
				binary.BigEndian.PutUint32(frameBuf[1:5], uint32(chunkLen))
				if err := sendFrame(frameBuf[:5+chunkLen]); err != nil {
					return
				}
				sentOffset += uint64(chunkLen)
				s.touch()
			}

			if shouldSendFin {
				if err := sendFrame([]byte{frameFin}); err != nil {
					return
				}
				finSent = true
			}

			s.mu.Lock()
			allAcked := finSent && s.baseOffset == totalAvailable && s.remoteEOF
			s.mu.Unlock()
			if allAcked {
				return
			}
		}
	}()

	var fType [1]byte
	var lenBuf [4]byte
	var ackBuf [8]byte
	payloadBuf := make([]byte, maxChunkSize)

	for {
		if _, err := io.ReadFull(stream, fType[:]); err != nil {
			return
		}
		switch fType[0] {
		case frameData:
			if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
				return
			}
			length := binary.BigEndian.Uint32(lenBuf[:])
			if length == 0 || length > maxChunkSize*2 {
				s.closeSession()
				return
			}
			if int(length) > len(payloadBuf) {
				payloadBuf = make([]byte, length)
			}
			if _, err := io.ReadFull(stream, payloadBuf[:length]); err != nil {
				return
			}

			s.writeMutex.Lock()
			written, wErr := s.writeAllTCP(payloadBuf[:length])
			var newInOffset uint64
			if written > 0 {
				s.mu.Lock()
				s.inOffset += uint64(written)
				newInOffset = s.inOffset
				s.lastActive = time.Now()
				s.mu.Unlock()
			}
			s.writeMutex.Unlock()

			if written > 0 {
				var ackFrame [9]byte
				ackFrame[0] = frameAck
				binary.BigEndian.PutUint64(ackFrame[1:9], newInOffset)
				_ = sendFrame(ackFrame[:])
			}
			if wErr != nil {
				s.closeSession()
				return
			}

		case frameAck:
			if _, err := io.ReadFull(stream, ackBuf[:]); err != nil {
				return
			}
			ackOffset := binary.BigEndian.Uint64(ackBuf[:])
			s.mu.Lock()
			s.trimAcked(ackOffset)
			s.lastActive = time.Now()
			allDone := s.localEOF && s.baseOffset == (s.baseOffset+uint64(len(s.outBuf)-s.outBase)) && s.remoteEOF
			s.mu.Unlock()
			if allDone {
				s.closeSession()
				return
			}

		case frameFin:
			if tcp, ok := s.tcpConn.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			s.mu.Lock()
			s.remoteEOF = true
			s.cond.Broadcast()
			allDone := s.localEOF && (len(s.outBuf)-s.outBase == 0)
			s.mu.Unlock()
			if allDone {
				s.closeSession()
				return
			}

		default:
			s.closeSession()
			return
		}
	}
}

// ==================== BUILT-IN TLS / SNI ENGINE ====================

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

type SNICertManager struct {
	mu             sync.RWMutex
	certDir        string
	certFile       string
	keyFile        string
	caCert         *x509.Certificate
	caKey          ed25519.PrivateKey
	cache          map[string]*tls.Certificate
	static         *tls.Certificate
	defaultDomain  string
	enableACME     bool
	acmeDirectory  string
	challengeMu    sync.RWMutex
	httpChallenges map[string]string
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
	}
	if certFile != "" && keyFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load -tls-cert/-tls-key: %w", err)
		}
		m.static = &c
		return m, nil
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
	m.caCert = caCert
	m.caKey = priv
	return m, nil
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
	m.challengeMu.RLock()
	val, ok := m.httpChallenges[token]
	m.challengeMu.RUnlock()
	return val, ok
}

func isPublicACMEDomain(host string) bool {
	if host == "" || host == "localhost" || net.ParseIP(host) != nil {
		return false
	}
	if !strings.Contains(host, ".") || strings.ContainsAny(host, "/\\:") {
		return false
	}
	for _, reserved := range []string{".local", ".localhost", ".internal", ".test", ".invalid", ".example.com", ".sslip.io", ".nip.io"} {
		if strings.HasSuffix(host, reserved) {
			return false
		}
	}
	return true
}

// ensureDomainCertificate checks if a certificate for domain already exists on disk;
// if it exists, it loads and uses it without recreating. Otherwise, it creates and saves it to disk.
func (m *SNICertManager) ensureDomainCertificate(domain string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
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
			if c, err := tls.LoadX509KeyPair(pair[0], pair[1]); err == nil {
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

func (m *SNICertManager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.static != nil {
		return m.static, nil
	}
	host := ""
	if hello != nil {
		host = strings.ToLower(strings.TrimSpace(hello.ServerName))
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
	if ok {
		return cached, nil
	}

	// 1. Check persisted certificates on disk (if it exists, just use it and do not recreate)
	if host != "localhost" && !strings.Contains(host, "/") && !strings.Contains(host, "\\") {
		candidates := [][2]string{
			{filepath.Join(m.certDir, host+".crt"), filepath.Join(m.certDir, host+".key")},
			{filepath.Join("/etc/letsencrypt/live", host, "fullchain.pem"), filepath.Join("/etc/letsencrypt/live", host, "privkey.pem")},
		}
		for _, pair := range candidates {
			if _, err := os.Stat(pair[0]); err == nil {
				if c, err := tls.LoadX509KeyPair(pair[0], pair[1]); err == nil {
					m.mu.Lock()
					m.cache[host] = &c
					m.mu.Unlock()
					return &c, nil
				}
			}
		}
	}

	// 2. Built-in RFC 8555 ACME v2 HTTP-01 automatic certificate issuance when enabled
	if m.enableACME && isPublicACMEDomain(host) {
		if acmeCert, err := m.obtainACMECertificate(host); err == nil && acmeCert != nil {
			m.mu.Lock()
			m.cache[host] = acmeCert
			m.mu.Unlock()
			return acmeCert, nil
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if cached, ok := m.cache[host]; ok {
		return cached, nil
	}

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
	if host != "localhost" && !strings.ContainsAny(host, "/\\:") {
		_ = os.MkdirAll(m.certDir, 0o700)
		_ = os.WriteFile(filepath.Join(m.certDir, host+".crt"), certPEM, 0o600)
		_ = os.WriteFile(filepath.Join(m.certDir, host+".key"), keyPEM, 0o600)
	}
	m.cache[host] = &tlsCert
	return &tlsCert, nil
}

// obtainACMECertificate implements an RFC 8555 ACME v2 HTTP-01 client (Let's Encrypt) using pure Go stdlib.
func (m *SNICertManager) obtainACMECertificate(domain string) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

	acctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	var chalURL, chalToken string
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			chalURL = ch.URL
			chalToken = ch.Token
			break
		}
	}
	if chalURL == "" || chalToken == "" {
		return nil, errors.New("no http-01 challenge offered")
	}

	keyAuth := chalToken + "." + thumbprint
	m.setHTTPChallenge(chalToken, keyAuth)
	defer m.deleteHTTPChallenge(chalToken)

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
			return nil, errors.New("acme http-01 validation failed")
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
	_ = os.WriteFile(filepath.Join(m.certDir, domain+".crt"), certPEM, 0o600)
	_ = os.WriteFile(filepath.Join(m.certDir, domain+".key"), keyPEM, 0o600)
	log.Printf("[auto-tls] obtained trusted Let's Encrypt certificate for %s via ACME HTTP-01", domain)
	return &tlsCert, nil
}

func (m *SNICertManager) tlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.getCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// maybeTerminateTLS peeks at the first byte of conn; if it is a TLS ClientHello (0x16) and autoTLS is enabled, wraps in TLS server.
func maybeTerminateTLS(c net.Conn, sniMgr *SNICertManager, enableTLS bool) net.Conn {
	if !enableTLS || sniMgr == nil {
		return c
	}
	br := bufio.NewReaderSize(c, 4096)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	pc := &peekedConn{Conn: c, r: br}
	if err == nil && len(b) == 1 && b[0] == 0x16 {
		tlsConn := tls.Server(pc, sniMgr.tlsConfig())
		_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			_ = tlsConn.Close()
			return pc
		}
		_ = tlsConn.SetDeadline(time.Time{})
		return tlsConn
	}
	return pc
}

// ==================== UDP FORWARDING ENGINE ====================

type gwUDPSession struct {
	id         uint64
	targetPort uint16
	clientAddr *net.UDPAddr
	pubConn    *net.UDPConn
	mu         sync.Mutex
	stream     quic.Stream
	lastActive time.Time
}

func writeUDPPacket(w io.Writer, payload []byte) error {
	if len(payload) > maxUDPPacket {
		return errors.New("udp packet too large")
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(payload)))
	copy(frame[2:], payload)
	total := 0
	for total < len(frame) {
		n, err := w.Write(frame[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func readUDPPacket(r io.Reader, buf []byte) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(lenBuf[:]))
	if length > len(buf) {
		return nil, errors.New("udp frame exceeds buffer")
	}
	if _, err := io.ReadFull(r, buf[:length]); err != nil {
		return nil, err
	}
	return buf[:length], nil
}

// ==================== GATEWAY ====================

type PortMapping struct {
	BindIP     string // default "0.0.0.0" (or "127.0.0.1" when using local reverse proxy)
	PublicPort uint16
	TargetPort uint16
	Proto      string // "both", "tcp", "udp", "http", "https"
}

type authAttempt struct {
	failures int
	first    time.Time
}

type Gateway struct {
	token           string
	mu              sync.RWMutex
	activeAgent     quic.Connection
	agentEpoch      uint64
	agentPubIP      string
	agentLanIP      string
	sessions        map[uint64]*Session
	pendingSessions []*Session
	udpSessions     map[string]*gwUDPSession
	udpByID         map[uint64]*gwUDPSession
	nextID          atomic.Uint64
	maxMem          int64
	maxBuf          int64
	sessionTTL      time.Duration
	authAttempts    map[string]authAttempt
	authMu          sync.Mutex
	sniMgr          *SNICertManager
	enableTLS       bool
}

func runGateway(ctx context.Context, quicAddr, token, directHTTPAddr, vhostAddr, httpsAddr string, vhostMap map[string]uint16, mappings []PortMapping, maxMem, maxBuf int64, quicIdle, quicKeepalive, sessionTTL time.Duration, certDir, tlsCertFile, tlsKeyFile string, enableTLS, sameLAN bool) error {
	sniMgr, err := newSNICertManager(certDir, tlsCertFile, tlsKeyFile)
	if err != nil {
		return fmt.Errorf("tls manager init: %w", err)
	}

	gw := &Gateway{
		token:        token,
		sessions:     make(map[uint64]*Session),
		udpSessions:  make(map[string]*gwUDPSession),
		udpByID:      make(map[uint64]*gwUDPSession),
		maxMem:       maxMem,
		maxBuf:       maxBuf,
		sessionTTL:   sessionTTL,
		authAttempts: make(map[string]authAttempt),
		sniMgr:       sniMgr,
		enableTLS:    enableTLS,
	}

	tlsConf, fp, err := loadGatewayCert(certDir)
	if err != nil {
		return fmt.Errorf("gateway cert error: %w", err)
	}

	quicConf := &quic.Config{
		KeepAlivePeriod:            quicKeepalive,
		MaxIdleTimeout:             quicIdle,
		MaxStreamReceiveWindow:     uint64(maxBuf),
		MaxConnectionReceiveWindow: uint64(maxBuf) * 4,
		MaxIncomingStreams:         4096,
		MaxIncomingUniStreams:      1024,
	}

	listener, err := quic.ListenAddr(quicAddr, tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("quic listen %s: %w", quicAddr, err)
	}
	defer listener.Close()

	_, quicPort, _ := net.SplitHostPort(quicAddr)
	if quicPort == "" {
		quicPort = "4242"
	}
	pubIP := detectPublicIP()
	if pubIP == "" {
		pubIP = "YOUR_VPS_IP"
	}

	log.Printf("[gateway] driftless %s listening on %s (cert sha256: %s)", versionString, quicAddr, fp[:16])
	log.Printf("[gateway] ==========================================================")
	log.Printf("[gateway] Run this command on your Home PC to connect:")
	log.Printf("[gateway]   ./driftless client -quic %s:%s -token %s -fingerprint %s", pubIP, quicPort, token, fp[:16])
	log.Printf("[gateway] ==========================================================")

	go gw.cleanupLoop(ctx)

	if directHTTPAddr != "" {
		go gw.startDirectRedirector(ctx, directHTTPAddr, mappings, sameLAN)
	}

	if vhostAddr != "" && len(vhostMap) > 0 {
		if err := gw.listenHTTPVHostRouter(ctx, vhostAddr, vhostMap, true); err != nil {
			return err
		}
	}
	if httpsAddr != "" && len(vhostMap) > 0 {
		if err := gw.listenHTTPVHostRouter(ctx, httpsAddr, vhostMap, true); err != nil {
			return err
		}
	}

	for _, m := range mappings {
		switch m.Proto {
		case "udp":
			if err := gw.listenPublicUDPPort(ctx, m); err != nil {
				return err
			}
		case "tcp", "http", "https":
			if err := gw.listenPublicPort(ctx, m); err != nil {
				return err
			}
		case "both":
			if err := gw.listenPublicPort(ctx, m); err != nil {
				return err
			}
			if err := gw.listenPublicUDPPort(ctx, m); err != nil {
				log.Printf("[gateway] note: UDP :%d not bound (%v), TCP :%d is active", m.PublicPort, err, m.PublicPort)
			}
		}
	}

	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			go gw.authenticateAndServeAgent(ctx, conn)
		}
	}()

	<-ctx.Done()
	log.Printf("[gateway] shutting down cleanly...")
	return nil
}

func matchVHostTarget(vhostMap map[string]uint16, host, reqPath string) (uint16, bool) {
	if reqPath == "" {
		reqPath = "/"
	}
	// 1. Longest matching domain+path rule (e.g. "app.example.com/api:4000")
	bestLen := -1
	var bestPort uint16
	for pattern, port := range vhostMap {
		slashIdx := strings.IndexByte(pattern, '/')
		if slashIdx == -1 {
			continue
		}
		patHost := pattern[:slashIdx]
		patPath := pattern[slashIdx:]
		if (patHost == host || patHost == "*") && strings.HasPrefix(reqPath, patPath) {
			if len(patPath) > bestLen {
				bestLen = len(patPath)
				bestPort = port
			}
		}
	}
	if bestLen >= 0 {
		return bestPort, true
	}
	// 2. Exact host match
	if port, ok := vhostMap[host]; ok {
		return port, true
	}
	// 3. Wildcard subdomain match (e.g. "*.example.com")
	if dotIdx := strings.IndexByte(host, '.'); dotIdx != -1 {
		if port, ok := vhostMap["*"+host[dotIdx:]]; ok {
			return port, true
		}
	}
	// 4. Catch-all "*"
	if port, ok := vhostMap["*"]; ok {
		return port, true
	}
	return 0, false
}

func (gw *Gateway) listenHTTPVHostRouter(ctx context.Context, listenAddr string, vhostMap map[string]uint16, allowAutoTLS bool) error {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("vhost listen %s: %w", listenAddr, err)
	}
	log.Printf("[gateway] HTTP/HTTPS VHost router active on %s (%d routes, auto-TLS=%v)", listenAddr, len(vhostMap), allowAutoTLS)
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
			go gw.handleVHostClient(c, vhostMap, allowAutoTLS)
		}
	}()
	return nil
}

func (gw *Gateway) handleVHostClient(rawConn net.Conn, vhostMap map[string]uint16, allowAutoTLS bool) {
	tuneTCPSocket(rawConn)
	c := maybeTerminateTLS(rawConn, gw.sniMgr, allowAutoTLS || gw.enableTLS)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var captured bytes.Buffer
	tee := io.TeeReader(c, &captured)
	br := bufio.NewReader(tee)

	req, err := http.ReadRequest(br)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
		return
	}

	// Serve built-in RFC 8555 ACME HTTP-01 challenge automatically if active
	if gw.sniMgr != nil && strings.HasPrefix(req.URL.Path, "/.well-known/acme-challenge/") {
		tok := strings.TrimPrefix(req.URL.Path, "/.well-known/acme-challenge/")
		if keyAuth, ok := gw.sniMgr.getHTTPChallenge(tok); ok {
			resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(keyAuth), keyAuth)
			_, _ = c.Write([]byte(resp))
			_ = c.Close()
			return
		}
	}

	host := strings.ToLower(strings.TrimSpace(req.Host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	targetPort, ok := matchVHostTarget(vhostMap, host, req.URL.Path)
	if !ok {
		_, _ = c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 21\r\nConnection: close\r\n\r\ndriftless: unknown host"))
		_ = c.Close()
		return
	}

	gw.startResumableSession(c, targetPort, captured.Bytes())
}

func (gw *Gateway) listenPublicUDPPort(ctx context.Context, m PortMapping) error {
	bindIP := m.BindIP
	if bindIP == "" {
		bindIP = "0.0.0.0"
	}
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", bindIP, m.PublicPort))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp %d: %w", m.PublicPort, err)
	}
	log.Printf("[gateway] forwarding UDP :%d -> agent :%d", m.PublicPort, m.TargetPort)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	go func() {
		buf := make([]byte, maxUDPPacket)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if n == 0 {
				continue
			}
			pkt := append([]byte(nil), buf[:n]...)
			gw.forwardUDPToAgent(conn, clientAddr, m.TargetPort, pkt)
		}
	}()
	return nil
}

func (gw *Gateway) forwardUDPToAgent(pubConn *net.UDPConn, clientAddr *net.UDPAddr, targetPort uint16, pkt []byte) {
	key := fmt.Sprintf("%s->%d", clientAddr.String(), targetPort)

	gw.mu.Lock()
	agent := gw.activeAgent
	if agent == nil {
		gw.mu.Unlock()
		return
	}
	us, exists := gw.udpSessions[key]
	if !exists {
		id := gw.nextID.Add(1)
		us = &gwUDPSession{
			id:         id,
			targetPort: targetPort,
			clientAddr: clientAddr,
			pubConn:    pubConn,
			lastActive: time.Now(),
		}
		gw.udpSessions[key] = us
		gw.udpByID[id] = us
	}
	gw.mu.Unlock()

	us.mu.Lock()
	us.lastActive = time.Now()
	st := us.stream
	us.mu.Unlock()

	if st != nil {
		if err := writeUDPPacket(st, pkt); err == nil {
			return
		}
	}

	newSt, err := agent.OpenStreamSync(context.Background())
	if err != nil {
		return
	}
	var hdr [11]byte
	hdr[0] = cmdUDPFlow
	binary.BigEndian.PutUint64(hdr[1:9], us.id)
	binary.BigEndian.PutUint16(hdr[9:11], us.targetPort)
	if _, err := newSt.Write(hdr[:]); err != nil {
		_ = newSt.Close()
		return
	}
	if err := writeUDPPacket(newSt, pkt); err != nil {
		_ = newSt.Close()
		return
	}

	us.mu.Lock()
	if us.stream != nil {
		_ = us.stream.Close()
	}
	us.stream = newSt
	us.mu.Unlock()

	go gw.readUDPFromAgentStream(us, newSt)
}

func (gw *Gateway) readUDPFromAgentStream(us *gwUDPSession, st quic.Stream) {
	defer st.Close()
	buf := make([]byte, maxUDPPacket)
	for {
		pkt, err := readUDPPacket(st, buf)
		if err != nil {
			return
		}
		us.mu.Lock()
		us.lastActive = time.Now()
		us.mu.Unlock()
		_, _ = us.pubConn.WriteToUDP(pkt, us.clientAddr)
	}
}

func (gw *Gateway) authenticateAndServeAgent(ctx context.Context, conn quic.Connection) {
	peerHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if !gw.authAllowed(peerHost) {
		log.Printf("[gateway] rate limit exceeded for %s", peerHost)
		_ = conn.CloseWithError(1, "rate limited")
		return
	}

	authCtx, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	authStream, err := conn.AcceptStream(authCtx)
	if err != nil {
		_ = conn.CloseWithError(2, "auth timeout")
		return
	}

	var hdr [1]byte
	if _, err := io.ReadFull(authStream, hdr[:]); err != nil || hdr[0] != cmdAuth {
		gw.noteAuthFail(peerHost)
		_ = authStream.Close()
		_ = conn.CloseWithError(3, "bad header")
		return
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		_ = conn.CloseWithError(4, "internal error")
		return
	}
	nonceMsg := append([]byte{cmdAuthNonce, byte(len(nonce))}, nonce...)
	if _, err := authStream.Write(nonceMsg); err != nil {
		_ = authStream.Close()
		_ = conn.CloseWithError(5, "nonce write")
		return
	}

	var rhdr [2]byte
	if _, err := io.ReadFull(authStream, rhdr[:]); err != nil || rhdr[0] != cmdAuthResp || int(rhdr[1]) != nonceLen {
		gw.noteAuthFail(peerHost)
		_ = authStream.Close()
		_ = conn.CloseWithError(6, "bad auth response")
		return
	}
	mac := make([]byte, nonceLen)
	if _, err := io.ReadFull(authStream, mac); err != nil {
		gw.noteAuthFail(peerHost)
		_ = authStream.Close()
		_ = conn.CloseWithError(7, "bad mac")
		return
	}
	var lhdr [1]byte
	if _, err := io.ReadFull(authStream, lhdr[:]); err != nil {
		gw.noteAuthFail(peerHost)
		_ = authStream.Close()
		_ = conn.CloseWithError(8, "bad lan header")
		return
	}
	lanIP := ""
	if lhdr[0] > 0 {
		lanIPB := make([]byte, int(lhdr[0]))
		if _, err := io.ReadFull(authStream, lanIPB); err != nil {
			_ = authStream.Close()
			_ = conn.CloseWithError(9, "bad lan")
			return
		}
		lanIP = string(lanIPB)
	}

	expected := hmac.New(sha256.New, []byte(gw.token))
	expected.Write(nonce)
	if !hmac.Equal(mac, expected.Sum(nil)) {
		gw.noteAuthFail(peerHost)
		log.Printf("[gateway] rejected agent with wrong token from %s", peerHost)
		_ = authStream.Close()
		_ = conn.CloseWithError(10, "unauthorized")
		return
	}
	_, _ = authStream.Write([]byte{cmdAuthOK})
	_ = authStream.Close()
	gw.authReset(peerHost)

	gw.mu.Lock()
	gw.agentEpoch++
	myEpoch := gw.agentEpoch
	oldConn := gw.activeAgent
	gw.activeAgent = conn
	gw.agentPubIP = peerHost
	gw.agentLanIP = lanIP
	gw.mu.Unlock()

	if oldConn != nil && oldConn != conn {
		_ = oldConn.CloseWithError(0, "superseded by new agent connection")
	}

	log.Printf("[gateway] home agent online (epoch #%d): wan=%s lan=%s", myEpoch, peerHost, lanIP)
	gw.flushPendingSessions(conn)
	gw.handleAgentStreams(ctx, conn, myEpoch)
}

func (gw *Gateway) noteAuthFail(ip string) {
	gw.authMu.Lock()
	defer gw.authMu.Unlock()
	now := time.Now()
	a, ok := gw.authAttempts[ip]
	if !ok || now.Sub(a.first) > authWindow {
		gw.authAttempts[ip] = authAttempt{failures: 1, first: now}
		return
	}
	a.failures++
	gw.authAttempts[ip] = a
}

func (gw *Gateway) authAllowed(ip string) bool {
	gw.authMu.Lock()
	defer gw.authMu.Unlock()
	a, ok := gw.authAttempts[ip]
	if !ok || time.Since(a.first) > authWindow {
		return true
	}
	return a.failures < maxAuthAttempts
}

func (gw *Gateway) authReset(ip string) {
	gw.authMu.Lock()
	delete(gw.authAttempts, ip)
	gw.authMu.Unlock()
}

func (gw *Gateway) evictOldestSessionIfNeeded() {
	for globalBufferedBytes.Load()+gw.maxBuf > gw.maxMem {
		gw.mu.Lock()
		var oldestID uint64
		var oldestSess *Session
		for id, s := range gw.sessions {
			if s.closed {
				delete(gw.sessions, id)
				continue
			}
			if oldestSess == nil || s.lastActive.Before(oldestSess.lastActive) {
				oldestID = id
				oldestSess = s
			}
		}
		if oldestSess != nil {
			delete(gw.sessions, oldestID)
		}
		gw.mu.Unlock()

		if oldestSess == nil {
			break
		}
		log.Printf("[gateway] FIFO RAM guard: evicting stalled session #%d to free memory for new connections", oldestID)
		oldestSess.closeSession()
	}
}

func (gw *Gateway) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			gw.mu.Lock()
			for id, sess := range gw.sessions {
				sess.mu.Lock()
				expired := !sess.closed && now.Sub(sess.lastActive) > gw.sessionTTL
				closed := sess.closed
				sess.mu.Unlock()
				if expired {
					log.Printf("[gateway] session #%d expired after %v inactivity", id, gw.sessionTTL)
					sess.closeSession()
					delete(gw.sessions, id)
				} else if closed {
					delete(gw.sessions, id)
				}
			}
			for key, us := range gw.udpSessions {
				us.mu.Lock()
				expired := now.Sub(us.lastActive) > udpSessionTTL
				st := us.stream
				us.mu.Unlock()
				if expired {
					if st != nil {
						_ = st.Close()
					}
					delete(gw.udpSessions, key)
					delete(gw.udpByID, us.id)
				}
			}
			gw.mu.Unlock()

			gw.authMu.Lock()
			for ip, a := range gw.authAttempts {
				if now.Sub(a.first) > authWindow {
					delete(gw.authAttempts, ip)
				}
			}
			gw.authMu.Unlock()
		}
	}
}

func (gw *Gateway) flushPendingSessions(agent quic.Connection) {
	gw.mu.Lock()
	pending := gw.pendingSessions
	gw.pendingSessions = nil
	gw.mu.Unlock()
	for _, sess := range pending {
		sess.mu.Lock()
		closed := sess.closed
		sess.mu.Unlock()
		if !closed {
			gw.openStreamToAgent(agent, sess, cmdNewConn)
		}
	}
}

func (gw *Gateway) startDirectRedirector(ctx context.Context, listenAddr string, mappings []PortMapping, sameLAN bool) {
	defaultTargetPort := uint16(8096)
	defaultScheme := "http"
	for _, m := range mappings {
		if m.Proto != "udp" {
			defaultTargetPort = m.TargetPort
			if m.Proto == "https" {
				defaultScheme = "https"
			}
			break
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gw.mu.RLock()
		pubIP := gw.agentPubIP
		lanIP := gw.agentLanIP
		gw.mu.RUnlock()
		if lanIP == "" {
			http.Error(w, "agent offline", http.StatusServiceUnavailable)
			return
		}

		portStr := r.URL.Query().Get("port")
		targetPort := defaultTargetPort
		if portStr != "" {
			if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
				targetPort = uint16(p)
			}
		}

		clientHost, _, _ := net.SplitHostPort(r.RemoteAddr)
		targetHost := pubIP
		isLAN := clientHost == "127.0.0.1" || clientHost == lanIP || (sameLAN && clientHost == pubIP)
		if !isLAN {
			cIP, lIP := net.ParseIP(clientHost).To4(), net.ParseIP(lanIP).To4()
			if cIP != nil && lIP != nil && cIP[0] == lIP[0] && cIP[1] == lIP[1] && cIP[2] == lIP[2] {
				isLAN = true
			}
		}
		if isLAN {
			targetHost = lanIP
		}
		if targetHost == "" {
			http.Error(w, "target address unavailable", http.StatusServiceUnavailable)
			return
		}

		target := fmt.Sprintf("%s://%s:%d%s", defaultScheme, targetHost, targetPort, r.URL.Path)
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})

	srv := &http.Server{Addr: listenAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Printf("[gateway] direct LAN/WAN redirector active on %s", listenAddr)
	_ = srv.ListenAndServe()
}

func (gw *Gateway) listenPublicPort(ctx context.Context, m PortMapping) error {
	bindIP := m.BindIP
	if bindIP == "" {
		bindIP = "0.0.0.0"
	}
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindIP, m.PublicPort))
	if err != nil {
		return fmt.Errorf("listen port %d: %w", m.PublicPort, err)
	}
	useTLS := gw.enableTLS || m.Proto == "https"
	log.Printf("[gateway] forwarding TCP %s:%d -> agent :%d (auto-tls=%v)", bindIP, m.PublicPort, m.TargetPort, useTLS)
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
			go func(raw net.Conn) {
				wrapped := maybeTerminateTLS(raw, gw.sniMgr, useTLS)
				gw.startResumableSession(wrapped, m.TargetPort, nil)
			}(c)
		}
	}()
	return nil
}

func (gw *Gateway) startResumableSession(c net.Conn, targetPort uint16, initialOutData []byte) {
	if globalBufferedBytes.Load()+gw.maxBuf > gw.maxMem {
		gw.evictOldestSessionIfNeeded()
	}
	id := gw.nextID.Add(1)
	sess := newSession(id, targetPort, c, gw.maxBuf, gw.maxMem, initialOutData)
	gw.mu.Lock()
	gw.sessions[id] = sess
	agent := gw.activeAgent
	if agent == nil {
		gw.pendingSessions = append(gw.pendingSessions, sess)
		gw.mu.Unlock()
		return
	}
	gw.mu.Unlock()
	gw.openStreamToAgent(agent, sess, cmdNewConn)
}

func (gw *Gateway) openStreamToAgent(agent quic.Connection, sess *Session, cmd uint8) {
	st, err := agent.OpenStreamSync(context.Background())
	if err != nil {
		return
	}
	var hdr [11]byte
	hdr[0] = cmd
	binary.BigEndian.PutUint64(hdr[1:9], sess.id)
	binary.BigEndian.PutUint16(hdr[9:11], sess.targetPort)
	if _, err := st.Write(hdr[:]); err != nil {
		_ = st.Close()
		return
	}
	go bridgeSessionStream(sess, st)
}

func (gw *Gateway) handleAgentStreams(ctx context.Context, conn quic.Connection, epoch uint64) {
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			gw.mu.Lock()
			if gw.agentEpoch == epoch {
				gw.activeAgent = nil
				log.Printf("[gateway] agent disconnected (epoch #%d), holding active sessions in RAM...", epoch)
			}
			gw.mu.Unlock()
			return
		}
		go func(s quic.Stream) {
			var hdr [11]byte
			if _, err := io.ReadFull(s, hdr[:]); err != nil {
				_ = s.Close()
				return
			}
			cmd := hdr[0]
			sessID := binary.BigEndian.Uint64(hdr[1:9])

			if cmd == cmdUDPFlow {
				gw.mu.RLock()
				us, ok := gw.udpByID[sessID]
				gw.mu.RUnlock()
				if !ok {
					_ = s.Close()
					return
				}
				us.mu.Lock()
				if us.stream != nil {
					_ = us.stream.Close()
				}
				us.stream = s
				us.lastActive = time.Now()
				us.mu.Unlock()
				gw.readUDPFromAgentStream(us, s)
				return
			}

			gw.mu.RLock()
			sess, ok := gw.sessions[sessID]
			gw.mu.RUnlock()
			if !ok || sess.closed {
				_ = s.Close()
				return
			}
			log.Printf("[gateway] session #%d seamlessly resumed on new IP", sessID)
			bridgeSessionStream(sess, s)
		}(st)
	}
}

// ==================== AGENT ====================

type agentUDPSession struct {
	id         uint64
	targetPort uint16
	localConn  net.Conn
	mu         sync.Mutex
	stream     quic.Stream
	lastActive time.Time
}

type Agent struct {
	gatewayAddr  string
	targetHost   string
	token        string
	lanIP        string
	maxBuf       int64
	maxMem       int64
	sessionTTL   time.Duration
	allowedPorts map[uint16]struct{}
	mu           sync.RWMutex
	sessions     map[uint64]*Session
	udpSessions  map[uint64]*agentUDPSession
}

func (ag *Agent) allowedPort(port uint16) bool {
	if len(ag.allowedPorts) == 0 {
		return true
	}
	_, ok := ag.allowedPorts[port]
	return ok
}

func nextBackoff(step int) time.Duration {
	schedule := []time.Duration{
		150 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		3 * time.Second,
		5 * time.Second,
		10 * time.Second,
	}
	if step < 0 {
		step = 0
	}
	if step >= len(schedule) {
		step = len(schedule) - 1
	}
	base := schedule[step]
	jitter := time.Duration(mrand.Int63n(int64(base/4 + 1)))
	return base + jitter
}

func runAgent(ctx context.Context, gatewayAddr, targetHost, token, lanIP, fingerprint string, maxBuf, maxMem int64, quicIdle, quicKeepalive, sessionTTL time.Duration, allowedPorts map[uint16]struct{}) error {
	ag := &Agent{
		gatewayAddr:  gatewayAddr,
		targetHost:   targetHost,
		token:        token,
		lanIP:        lanIP,
		maxBuf:       maxBuf,
		maxMem:       maxMem,
		sessionTTL:   sessionTTL,
		allowedPorts: allowedPorts,
		sessions:     make(map[uint64]*Session),
		udpSessions:  make(map[uint64]*agentUDPSession),
	}

	tlsConf, err := makeAgentTLS(fingerprint)
	if err != nil {
		return fmt.Errorf("agent tls: %w", err)
	}
	quicConf := &quic.Config{
		KeepAlivePeriod:            quicKeepalive,
		MaxIdleTimeout:             quicIdle,
		MaxStreamReceiveWindow:     uint64(maxBuf),
		MaxConnectionReceiveWindow: uint64(maxBuf) * 4,
		MaxIncomingStreams:         4096,
		MaxIncomingUniStreams:      1024,
	}

	go ag.cleanupSessions(ctx)

	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		conn, err := quic.DialAddr(ctx, gatewayAddr, tlsConf, quicConf)
		if err != nil {
			delay := nextBackoff(attempt)
			attempt++
			sleepWithContext(ctx, delay)
			continue
		}
		if err := ag.sendAuth(ctx, conn); err != nil {
			_ = conn.CloseWithError(1, "auth failed")
			log.Printf("[agent] auth error: %v", err)
			delay := nextBackoff(attempt)
			attempt++
			sleepWithContext(ctx, delay)
			continue
		}
		attempt = 0
		log.Printf("[agent] connected to VPS %s - all local services are online and protected!", gatewayAddr)
		ag.resumeActiveSessions(conn)
		ag.acceptGatewayStreams(ctx, conn)
		if ctx.Err() != nil {
			_ = conn.CloseWithError(0, "agent shutting down")
			return nil
		}
		log.Printf("[agent] ISP IP changed or link blipped - freezing sockets & reconnecting...")
		sleepWithContext(ctx, nextBackoff(0))
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (ag *Agent) evictOldestSessionIfNeeded() {
	for globalBufferedBytes.Load()+ag.maxBuf > ag.maxMem {
		ag.mu.Lock()
		var oldestID uint64
		var oldestSess *Session
		for id, s := range ag.sessions {
			if s.closed {
				delete(ag.sessions, id)
				continue
			}
			if oldestSess == nil || s.lastActive.Before(oldestSess.lastActive) {
				oldestID = id
				oldestSess = s
			}
		}
		if oldestSess != nil {
			delete(ag.sessions, oldestID)
		}
		ag.mu.Unlock()

		if oldestSess == nil {
			break
		}
		log.Printf("[agent] FIFO RAM guard: evicting stalled session #%d to free memory", oldestID)
		oldestSess.closeSession()
	}
}

func (ag *Agent) cleanupSessions(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			ag.mu.Lock()
			for id, sess := range ag.sessions {
				sess.mu.Lock()
				expired := !sess.closed && now.Sub(sess.lastActive) > ag.sessionTTL
				closed := sess.closed
				sess.mu.Unlock()
				if expired {
					sess.closeSession()
					delete(ag.sessions, id)
				} else if closed {
					delete(ag.sessions, id)
				}
			}
			for id, us := range ag.udpSessions {
				us.mu.Lock()
				expired := now.Sub(us.lastActive) > udpSessionTTL
				st := us.stream
				lc := us.localConn
				us.mu.Unlock()
				if expired {
					if st != nil {
						_ = st.Close()
					}
					if lc != nil {
						_ = lc.Close()
					}
					delete(ag.udpSessions, id)
				}
			}
			ag.mu.Unlock()
		}
	}
}

func (ag *Agent) sendAuth(ctx context.Context, conn quic.Connection) error {
	authCtx, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	st, err := conn.OpenStreamSync(authCtx)
	if err != nil {
		return err
	}
	defer st.Close()

	if _, err := st.Write([]byte{cmdAuth}); err != nil {
		return err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(st, hdr[:]); err != nil || hdr[0] != cmdAuthNonce || int(hdr[1]) != nonceLen {
		return errors.New("expected valid auth nonce from gateway")
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(st, nonce); err != nil {
		return err
	}

	mac := hmac.New(sha256.New, []byte(ag.token))
	mac.Write(nonce)
	sum := mac.Sum(nil)

	lanIP := ag.lanIP
	if lanIP == "" {
		lanIP = detectLocalLANIP()
	}
	resp := make([]byte, 0, 3+len(sum)+len(lanIP))
	resp = append(resp, cmdAuthResp, byte(len(sum)))
	resp = append(resp, sum...)
	resp = append(resp, byte(len(lanIP)))
	resp = append(resp, []byte(lanIP)...)
	if _, err := st.Write(resp); err != nil {
		return err
	}

	var okByte [1]byte
	if _, err := io.ReadFull(st, okByte[:]); err != nil || okByte[0] != cmdAuthOK {
		return errors.New("invalid token rejected by gateway")
	}
	return nil
}

func (ag *Agent) resumeActiveSessions(conn quic.Connection) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	for id, sess := range ag.sessions {
		if sess.closed {
			delete(ag.sessions, id)
			continue
		}
		go func(s *Session) {
			st, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				return
			}
			var hdr [11]byte
			hdr[0] = cmdResume
			binary.BigEndian.PutUint64(hdr[1:9], s.id)
			binary.BigEndian.PutUint16(hdr[9:11], s.targetPort)
			if _, err := st.Write(hdr[:]); err != nil {
				_ = st.Close()
				return
			}
			bridgeSessionStream(s, st)
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				ag.mu.Lock()
				delete(ag.sessions, s.id)
				ag.mu.Unlock()
			}
		}(sess)
	}

	for _, us := range ag.udpSessions {
		go func(u *agentUDPSession) {
			st, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				return
			}
			var hdr [11]byte
			hdr[0] = cmdUDPFlow
			binary.BigEndian.PutUint64(hdr[1:9], u.id)
			binary.BigEndian.PutUint16(hdr[9:11], u.targetPort)
			if _, err := st.Write(hdr[:]); err != nil {
				_ = st.Close()
				return
			}
			u.mu.Lock()
			if u.stream != nil {
				_ = u.stream.Close()
			}
			u.stream = st
			u.mu.Unlock()
			ag.readUDPFromGatewayStream(u, st)
		}(us)
	}
}

func (ag *Agent) acceptGatewayStreams(ctx context.Context, conn quic.Connection) {
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(s quic.Stream) {
			var hdr [11]byte
			if _, err := io.ReadFull(s, hdr[:]); err != nil {
				_ = s.Close()
				return
			}
			cmd := hdr[0]
			sessID := binary.BigEndian.Uint64(hdr[1:9])
			targetPort := binary.BigEndian.Uint16(hdr[9:11])

			if !ag.allowedPort(targetPort) {
				log.Printf("[agent] blocked port %d (not in -allow-ports)", targetPort)
				_ = s.Close()
				return
			}

			if cmd == cmdUDPFlow {
				ag.handleUDPStream(sessID, targetPort, s)
				return
			}

			if globalBufferedBytes.Load()+ag.maxBuf > ag.maxMem {
				ag.evictOldestSessionIfNeeded()
			}

			ag.mu.Lock()
			sess, exists := ag.sessions[sessID]
			if !exists && cmd == cmdNewConn {
				c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ag.targetHost, targetPort), 5*time.Second)
				if err != nil {
					ag.mu.Unlock()
					_ = s.Close()
					return
				}
				sess = newSession(sessID, targetPort, c, ag.maxBuf, ag.maxMem, nil)
				ag.sessions[sessID] = sess
			}
			ag.mu.Unlock()
			if sess == nil || sess.closed {
				_ = s.Close()
				return
			}
			bridgeSessionStream(sess, s)
			sess.mu.Lock()
			closed := sess.closed
			sess.mu.Unlock()
			if closed {
				ag.mu.Lock()
				delete(ag.sessions, sessID)
				ag.mu.Unlock()
			}
		}(st)
	}
}

func (ag *Agent) handleUDPStream(sessID uint64, targetPort uint16, st quic.Stream) {
	ag.mu.Lock()
	us, exists := ag.udpSessions[sessID]
	if !exists {
		c, err := net.Dial("udp", fmt.Sprintf("%s:%d", ag.targetHost, targetPort))
		if err != nil {
			ag.mu.Unlock()
			_ = st.Close()
			return
		}
		us = &agentUDPSession{
			id:         sessID,
			targetPort: targetPort,
			localConn:  c,
			stream:     st,
			lastActive: time.Now(),
		}
		ag.udpSessions[sessID] = us
		go ag.readFromLocalUDP(us)
	} else {
		us.mu.Lock()
		if us.stream != nil {
			_ = us.stream.Close()
		}
		us.stream = st
		us.lastActive = time.Now()
		us.mu.Unlock()
	}
	ag.mu.Unlock()

	ag.readUDPFromGatewayStream(us, st)
}

func (ag *Agent) readUDPFromGatewayStream(us *agentUDPSession, st quic.Stream) {
	defer st.Close()
	buf := make([]byte, maxUDPPacket)
	for {
		pkt, err := readUDPPacket(st, buf)
		if err != nil {
			return
		}
		us.mu.Lock()
		us.lastActive = time.Now()
		lc := us.localConn
		us.mu.Unlock()
		if lc != nil {
			_, _ = lc.Write(pkt)
		}
	}
}

func (ag *Agent) readFromLocalUDP(us *agentUDPSession) {
	buf := make([]byte, maxUDPPacket)
	for {
		n, err := us.localConn.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		us.mu.Lock()
		us.lastActive = time.Now()
		st := us.stream
		us.mu.Unlock()
		if st != nil {
			_ = writeUDPPacket(st, buf[:n])
		}
	}
}

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
	VHostMap     map[string]uint16
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

// autoForwardRouterPorts maps public ports on the home router using UPnP IGD and NAT-PMP.
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
	ctrlURL, serviceType := discoverUPnPControlURL(1200 * time.Millisecond)
	gwIP := guessDefaultGatewayIP(lanIP)

	for _, sp := range specs {
		ok := false
		if ctrlURL != "" {
			if err := upnpAddPortMapping(ctrlURL, serviceType, lanIP, sp.port, sp.proto); err == nil {
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

func discoverUPnPControlURL(timeout time.Duration) (string, string) {
	ssdpAddr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return "", ""
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	targets := []string{
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
	}
	for _, st := range targets {
		req := fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: %s\r\n\r\n", st)
		_, _ = conn.WriteToUDP([]byte(req), ssdpAddr)
	}

	var buf [2048]byte
	n, _, err := conn.ReadFromUDP(buf[:])
	if err != nil || n == 0 {
		return "", ""
	}
	lines := strings.Split(string(buf[:n]), "\r\n")
	var location string
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "location:") {
			location = strings.TrimSpace(line[9:])
			break
		}
	}
	if location == "" {
		return "", ""
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(location)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", ""
	}

	type xmlService struct {
		ServiceType string `xml:"serviceType"`
		ControlURL  string `xml:"controlURL"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var foundCtrl, foundType string
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "service" {
			var s xmlService
			if err := decoder.DecodeElement(&s, &se); err == nil {
				if strings.Contains(s.ServiceType, "WANIPConnection") || strings.Contains(s.ServiceType, "WANPPPConnection") {
					foundCtrl = s.ControlURL
					foundType = s.ServiceType
					break
				}
			}
		}
	}
	if foundCtrl == "" {
		return "", ""
	}
	baseURL, err := url.Parse(location)
	if err != nil {
		return "", ""
	}
	relURL, err := url.Parse(foundCtrl)
	if err != nil {
		return "", ""
	}
	return baseURL.ResolveReference(relURL).String(), foundType
}

func upnpAddPortMapping(ctrlURL, serviceType, lanIP string, port uint16, proto string) error {
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
<NewLeaseDuration>3600</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>`, serviceType, port, proto, port, lanIP)

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

func runStandalone(ctx context.Context, cfg StandaloneConfig) error {
	sniMgr, err := newSNICertManager(cfg.CertDir, cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return err
	}
	lanIP := detectLocalLANIP()
	stunFailCount.Store(3) // allow HTTP fallback on initial startup if UDP STUN is blocked
	pubIP, _ := querySTUNPublicIP(cfg.STUNServer, 800*time.Millisecond)
	if pubIP == "" {
		pubIP = lanIP
	}

	log.Printf("[standalone] driftless %s Zero-VPS mode active (LAN=%s, Public IP=%s)", versionString, lanIP, pubIP)
	if cfg.EnableUPnP {
		mapped := autoForwardRouterPorts(lanIP, cfg.Mappings, cfg.VHostAddr, cfg.HTTPSAddr)
		log.Printf("[standalone] router UPnP/NAT-PMP auto-forwarded %d port rules to %s", mapped, lanIP)
	}
	if cfg.DDNS.Provider != "" || cfg.DDNS.Webhook != "" {
		if err := updateDDNS(cfg.DDNS, pubIP); err != nil {
			log.Printf("[standalone] initial DDNS update warning: %v", err)
		} else {
			log.Printf("[standalone] DDNS updated -> %s (%s)", pubIP, cfg.DDNS.Domain)
		}
	} else if strings.EqualFold(cfg.DDNS.Domain, "auto") {
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

	// Start local TCP/UDP/VHost listeners
	for _, m := range cfg.Mappings {
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

	if cfg.VHostAddr != "" && len(cfg.VHostMap) > 0 {
		if err := startStandaloneVHost(ctx, cfg.VHostAddr, cfg.TargetHost, cfg.VHostMap, sniMgr); err != nil {
			return err
		}
	}
	if cfg.HTTPSAddr != "" && len(cfg.VHostMap) > 0 {
		if err := startStandaloneVHost(ctx, cfg.HTTPSAddr, cfg.TargetHost, cfg.VHostMap, sniMgr); err != nil {
			return err
		}
	}

	// 1-second STUN IP change detector + periodic UPnP lease renewal
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
				if cfg.DDNS.Provider != "" || cfg.DDNS.Webhook != "" {
					if err := updateDDNS(cfg.DDNS, currentIP); err != nil {
						log.Printf("[standalone] DDNS update error: %v", err)
					} else {
						log.Printf("[standalone] DDNS record updated to %s in real time!", currentIP)
					}
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

// ==================== HELPERS & CLI ====================

func detectPublicIP() string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}

func detectLocalLANIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "virbr") ||
			strings.HasPrefix(name, "vethernet") || strings.Contains(name, "wsl") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
				continue
			}
			ip := ipNet.IP.To4()
			if ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168) {
				return ip.String()
			}
		}
	}
	return "127.0.0.1"
}

func parseMappingsWithDefault(raw string, defaultBothUDP bool) ([]PortMapping, error) {
	var res []PortMapping
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		proto := "tcp"
		if defaultBothUDP {
			proto = "both"
		}
		lower := strings.ToLower(pair)
		switch {
		case strings.HasSuffix(lower, "/udp"):
			proto = "udp"
			pair = pair[:len(pair)-4]
		case strings.HasSuffix(lower, "/tcp"):
			proto = "tcp"
			pair = pair[:len(pair)-4]
		case strings.HasSuffix(lower, "/https"):
			proto = "https"
			pair = pair[:len(pair)-6]
		case strings.HasSuffix(lower, "/tls"):
			proto = "https"
			pair = pair[:len(pair)-4]
		case strings.HasSuffix(lower, "/http"):
			proto = "http"
			pair = pair[:len(pair)-5]
		}

		// Support shorthand single port "8096" ("8096:8096") or local bind "127.0.0.1:8080:80"
		bindIP := "0.0.0.0"
		p := strings.Split(pair, ":")
		if len(p) == 1 {
			p = []string{p[0], p[0]}
		} else if len(p) >= 3 && net.ParseIP(p[0]) != nil {
			bindIP = p[0]
			p = p[1:]
		}
		if len(p) < 2 || len(p) > 3 {
			return nil, fmt.Errorf("invalid port mapping %q (expected PORT, PUBLIC:LOCAL, or 127.0.0.1:PUBLIC:LOCAL)", pair)
		}
		pub, err1 := strconv.Atoi(p[0])
		loc, err2 := strconv.Atoi(p[1])
		if err1 != nil || err2 != nil || pub <= 0 || pub > 65535 || loc <= 0 || loc > 65535 {
			return nil, fmt.Errorf("port out of range (1..65535) in %q", pair)
		}
		if len(p) == 3 {
			sub := strings.ToLower(strings.TrimSpace(p[2]))
			if sub == "tls" {
				sub = "https"
			}
			if sub != "http" && sub != "https" && sub != "udp" && sub != "tcp" && sub != "both" {
				return nil, fmt.Errorf("invalid protocol/scheme in %q", pair)
			}
			proto = sub
		}
		res = append(res, PortMapping{BindIP: bindIP, PublicPort: uint16(pub), TargetPort: uint16(loc), Proto: proto})
	}
	if len(res) == 0 {
		return nil, errors.New("at least one port mapping is required")
	}
	return res, nil
}

func parseMappings(raw string) ([]PortMapping, error) {
	return parseMappingsWithDefault(raw, true)
}

func parseVHosts(raw string) (map[string]uint16, error) {
	res := make(map[string]uint16)
	if strings.TrimSpace(raw) == "" {
		return res, nil
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid -vhosts entry %q (expected domain.com:LOCAL_PORT)", entry)
		}
		domain := strings.ToLower(strings.TrimSpace(parts[0]))
		port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port in -vhosts entry %q", entry)
		}
		res[domain] = uint16(port)
	}
	return res, nil
}

func loadGatewayCert(certDir string) (*tls.Config, string, error) {
	var certPEM, keyPEM []byte
	if certDir != "" {
		c, errC := os.ReadFile(certDir + "/cert.pem")
		k, errK := os.ReadFile(certDir + "/key.pem")
		if errC == nil && errK == nil {
			certPEM, keyPEM = c, k
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
			if err := os.WriteFile(certDir+"/cert.pem", certPEM, 0o600); err != nil {
				return nil, "", fmt.Errorf("write cert.pem: %w", err)
			}
			if err := os.WriteFile(certDir+"/key.pem", keyPEM, 0o600); err != nil {
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

func makeAgentTLS(fingerprint string) (*tls.Config, error) {
	var wantPrefix []byte
	fpClean := strings.ToLower(strings.TrimSpace(fingerprint))
	if fpClean != "" {
		decoded, err := hex.DecodeString(fpClean)
		if err != nil || len(decoded) < 8 || len(decoded) > sha256.Size {
			return nil, errors.New("invalid -fingerprint: expected 16..64 hex chars (SHA-256)")
		}
		wantPrefix = decoded
	}

	var tofuMu sync.Mutex
	var tofuPinned []byte

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
			if len(wantPrefix) > 0 {
				if !hmac.Equal(sum[:len(wantPrefix)], wantPrefix) {
					return fmt.Errorf("certificate fingerprint mismatch: got %x, want prefix %x", sum[:len(wantPrefix)], wantPrefix)
				}
				return nil
			}
			// Automatic Trust-On-First-Use (TOFU) certificate pinning across all reconnects
			tofuMu.Lock()
			defer tofuMu.Unlock()
			if len(tofuPinned) == 0 {
				tofuPinned = append([]byte(nil), sum[:]...)
				log.Printf("[agent] pinned gateway TLS certificate (sha256: %x)", sum[:8])
				return nil
			}
			if !hmac.Equal(sum[:], tofuPinned) {
				return fmt.Errorf("MITM alert: gateway certificate changed mid-session (got %x, pinned %x)", sum[:8], tofuPinned[:8])
			}
			return nil
		},
	}, nil
}

func loadOrGenerateToken(isServer bool, tokenFlag, tokenFile string) (string, error) {
	if tokenFlag != "" {
		return strings.TrimSpace(tokenFlag), nil
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if tok := os.Getenv("DRIFTLESS_TOKEN"); tok != "" {
		return strings.TrimSpace(tok), nil
	}
	if isServer {
		var b [8]byte
		_, _ = rand.Read(b[:])
		autoTok := hex.EncodeToString(b[:])
		log.Printf("[gateway] no -token specified; auto-generated password: %s", autoTok)
		return autoTok, nil
	}
	return "", errors.New("password required: run './driftless client -quic VPS_IP:4242 -token YOUR_PASSWORD'")
}

func main() {
	defaultMode := "agent"
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "server", "gateway":
			defaultMode = "gateway"
			os.Args = append(os.Args[:1], os.Args[2:]...)
		case "client", "agent":
			defaultMode = "agent"
			os.Args = append(os.Args[:1], os.Args[2:]...)
		case "standalone", "direct", "p2p":
			defaultMode = "standalone"
			os.Args = append(os.Args[:1], os.Args[2:]...)
		case "version", "-v", "--version":
			fmt.Printf("driftless %s (TCP/UDP/HTTP-VHost/Auto-TLS/Zero-VPS STUN+UPnP)\n", versionString)
			return
		}
	}

	mode := flag.String("mode", defaultMode, "'server' (VPS), 'client' (Home PC to VPS), or 'standalone' (Zero-VPS Home PC)")
	quicAddr := flag.String("quic", "0.0.0.0:4242", "gateway QUIC address (e.g. VPS_IP:4242)")
	tokenFlag := flag.String("token", "", "shared secret password (auto-generated on server if omitted)")
	tokenFile := flag.String("token-file", "", "path to file containing shared secret password")
	ports := flag.String("ports", "8080:80,8096:8096", "PUBLIC:LOCAL or PORT mappings (forwards both TCP+UDP by default)")
	udpDefault := flag.Bool("udp", true, "forward UDP alongside TCP by default on all mapped ports")
	enableTLS := flag.Bool("tls", false, "enable automatic HTTPS/TLS termination on mapped TCP ports")
	httpsAddr := flag.String("https", "", "optional HTTPS VHost router listen address (e.g. :443 or :8443)")
	tlsCertFile := flag.String("tls-cert", "", "optional path to custom TLS certificate PEM file")
	tlsKeyFile := flag.String("tls-key", "", "optional path to custom TLS private key PEM file")
	vhostAddr := flag.String("vhost-addr", "", "optional HTTP/HTTPS Host router listen address (e.g. :80)")
	vhosts := flag.String("vhosts", "", "comma-separated domain:LOCAL_PORT mappings (e.g. app.example.com:3000,media.example.com:8096)")
	direct := flag.String("direct", ":8888", "direct LAN/WAN HTTP redirector listen address (empty to disable)")
	host := flag.String("host", "127.0.0.1", "local target host on agent/standalone")
	maxBuf := flag.Int64("max-buf", 16*1024*1024, "max per-session ring buffer in bytes (default 16 MiB)")
	maxMem := flag.Int64("max-mem", 256*1024*1024, "max global buffered bytes across all sessions (default 256 MiB)")
	sessionTTL := flag.Duration("session-ttl", 90*time.Second, "how long to hold frozen sessions during an IP outage")
	quicIdle := flag.Duration("quic-idle-timeout", 8*time.Second, "QUIC idle timeout before reconnect")
	quicKeepalive := flag.Duration("quic-keepalive", 2*time.Second, "QUIC keepalive period")
	certDir := flag.String("cert-dir", "", "directory to persist gateway cert.pem/key.pem")
	fingerprint := flag.String("fingerprint", "", "optional gateway SHA-256 cert fingerprint for strict pinning")
	lanIP := flag.String("lan-ip", "", "override auto-detected agent LAN IP")
	allowPorts := flag.String("allow-ports", "", "optional whitelist of local ports on agent (e.g. 80,8096,25565)")
	sameLAN := flag.Bool("same-lan", true, "redirect clients sharing the same WAN IP directly to agent LAN IP")

	// Standalone / Zero-VPS mode flags
	enableUPnP := flag.Bool("upnp", true, "automatically open ports on home router via UPnP IGD / NAT-PMP (standalone mode)")
	stunServer := flag.String("stun", "stun.l.google.com:19302", "STUN server for 5ms external IP change detection (standalone mode)")
	stunInterval := flag.Duration("stun-interval", 1*time.Second, "how often to check external IP via STUN (standalone mode)")
	duckShort := flag.String("duck", "", "shorthand DuckDNS 'subdomain:token' or update URL (saved automatically for next runs)")
	ddnsProvider := flag.String("ddns-provider", "", "built-in Dynamic DNS provider: 'duckdns', 'cloudflare', or 'noip'")
	ddnsDomain := flag.String("ddns-domain", "", "domain/subdomain to update when IP changes (e.g. myhome.duckdns.org)")
	ddnsToken := flag.String("ddns-token", "", "API token or password for Dynamic DNS provider")
	ddnsUser := flag.String("ddns-user", "", "username for No-IP / DynDNS provider")
	ddnsZone := flag.String("ddns-zone", "", "Cloudflare Zone ID (when -ddns-provider=cloudflare)")
	ddnsURL := flag.String("ddns-url", "", "custom DDNS webhook URL (replaces {ip} with current external IP)")
	// Allow bare '-duck' or '--duck' without arguments on CLI (rewritten to '-duck=auto')
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "-duck" || os.Args[i] == "--duck" {
			if i+1 >= len(os.Args) || strings.HasPrefix(os.Args[i+1], "-") {
				os.Args[i] = "-duck=auto"
			}
		}
	}
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *mode == "standalone" || *mode == "direct" || *mode == "p2p" {
		mappings, err := parseMappingsWithDefault(*ports, *udpDefault)
		if err != nil {
			log.Fatalf("[standalone] %v", err)
		}
		vhostMap, err := parseVHosts(*vhosts)
		if err != nil {
			log.Fatalf("[standalone] %v", err)
		}
		if *vhostAddr == "" && len(vhostMap) > 0 {
			*vhostAddr = "0.0.0.0:80"
		}
		ddnsCfg := resolveAndPersistDDNS(DDNSConfig{
			Provider: *ddnsProvider,
			Domain:   *ddnsDomain,
			Token:    *ddnsToken,
			User:     *ddnsUser,
			ZoneID:   *ddnsZone,
			Webhook:  *ddnsURL,
		}, *duckShort)
		cfg := StandaloneConfig{
			TargetHost:   *host,
			Mappings:     mappings,
			VHostAddr:    *vhostAddr,
			HTTPSAddr:    *httpsAddr,
			VHostMap:     vhostMap,
			EnableUPnP:   *enableUPnP,
			EnableTLS:    *enableTLS,
			STUNServer:   *stunServer,
			STUNInterval: *stunInterval,
			CertDir:      *certDir,
			TLSCertFile:  *tlsCertFile,
			TLSKeyFile:   *tlsKeyFile,
			DDNS:         ddnsCfg,
		}
		if err := runStandalone(ctx, cfg); err != nil {
			log.Fatalf("[standalone] %v", err)
		}
		return
	}

	isServer := *mode == "gateway" || *mode == "server"
	token, err := loadOrGenerateToken(isServer, *tokenFlag, *tokenFile)
	if err != nil {
		log.Fatalf("[driftless] %v", err)
	}

	if isServer {
		mappings, err := parseMappingsWithDefault(*ports, *udpDefault)
		if err != nil {
			log.Fatalf("[gateway] %v", err)
		}
		vhostMap, err := parseVHosts(*vhosts)
		if err != nil {
			log.Fatalf("[gateway] %v", err)
		}
		if *vhostAddr == "" && len(vhostMap) > 0 {
			*vhostAddr = "0.0.0.0:80"
		}
		ddnsCfg := resolveAndPersistDDNS(DDNSConfig{
			Provider: *ddnsProvider,
			Domain:   *ddnsDomain,
			Token:    *ddnsToken,
			User:     *ddnsUser,
			ZoneID:   *ddnsZone,
			Webhook:  *ddnsURL,
		}, *duckShort)
		if ddnsCfg.Domain != "" {
			pubIP := detectPublicIP()
			if ddnsCfg.Provider != "" || ddnsCfg.Webhook != "" {
				if pubIP != "" {
					if err := updateDDNS(ddnsCfg, pubIP); err == nil {
						log.Printf("[gateway] DuckDNS/DDNS updated -> %s (%s)", pubIP, ddnsCfg.Domain)
					}
				}
			} else if strings.EqualFold(ddnsCfg.Domain, "auto") {
				if autoDom := autoZeroConfigDomain(pubIP); autoDom != "" {
					ddnsCfg.Domain = autoDom
				} else if pubIP != "" {
					ddnsCfg.Domain = pubIP
				}
			}
			*enableTLS = true
			if sm, err := newSNICertManager(*certDir, *tlsCertFile, *tlsKeyFile); err == nil {
				sm.ensureDomainCertificate(ddnsCfg.Domain)
			}
		}
		if err := runGateway(ctx, *quicAddr, token, *direct, *vhostAddr, *httpsAddr, vhostMap, mappings, *maxMem, *maxBuf, *quicIdle, *quicKeepalive, *sessionTTL, *certDir, *tlsCertFile, *tlsKeyFile, *enableTLS, *sameLAN); err != nil {
			log.Fatalf("[gateway] %v", err)
		}
	} else {
		var portsAllow map[uint16]struct{}
		if *allowPorts != "" {
			portsAllow = make(map[uint16]struct{})
			for _, p := range strings.Split(*allowPorts, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				port, err := strconv.Atoi(p)
				if err != nil || port <= 0 || port > 65535 {
					log.Fatalf("[agent] invalid port in -allow-ports: %s", p)
				}
				portsAllow[uint16(port)] = struct{}{}
			}
		}
		if err := runAgent(ctx, *quicAddr, *host, token, *lanIP, *fingerprint, *maxBuf, *maxMem, *quicIdle, *quicKeepalive, *sessionTTL, portsAllow); err != nil {
			log.Fatalf("[agent] %v", err)
		}
	}
}
