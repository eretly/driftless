package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type PortMapping struct {
	BindIP        string // default "0.0.0.0" (or "127.0.0.1" when using local reverse proxy)
	PublicPort    uint16
	TargetPort    uint16
	Proto         string // "both", "tcp", "udp", "http", "https"
	RouterTCPPort uint16 // optional local ephemeral bridge port in standalone mode when PublicPort is already bound
	RouterUDPPort uint16
}

type authAttempt struct {
	failures int
	first    time.Time
}

type Gateway struct {
	token           string
	tokens          []string
	certSHA256      []byte
	mu              sync.RWMutex
	activeAgent     TunnelConn
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
	ipACL           *IPACL
	mappings        []PortMapping
}

func parseTokensList(raw string) []string {
	var res []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			res = append(res, part)
		}
	}
	return res
}

// computeClientAuthMAC binds the Gateway's TLS certificate SHA-256 digest, the one-time server nonce,
// and the agent's reported LAN IP into the HMAC-SHA256 proof (RFC 5929 tls-server-end-point channel binding).
func computeClientAuthMAC(token string, nonce, certSHA256 []byte, lanIP string) []byte {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte("driftless-v1.5-client:"))
	h.Write(certSHA256)
	h.Write(nonce)
	h.Write([]byte(lanIP))
	return h.Sum(nil)
}

// computeServerAuthMAC provides mutual authentication so the Agent can cryptographically verify
// that the Gateway actually possesses the shared secret token and owns the presented TLS certificate.
func computeServerAuthMAC(token string, nonce, certSHA256, clientMAC []byte) []byte {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte("driftless-v1.5-server:"))
	h.Write(certSHA256)
	h.Write(nonce)
	h.Write(clientMAC)
	return h.Sum(nil)
}

func (gw *Gateway) verifyAgentMAC(nonce, mac []byte, lanIP string) (bool, int, string) {
	tokens := gw.tokens
	if len(tokens) == 0 && gw.token != "" {
		tokens = []string{gw.token}
	}
	matched := false
	matchedSlot := 0
	matchedTok := ""
	for i, tok := range tokens {
		expectedBound := computeClientAuthMAC(tok, nonce, gw.certSHA256, lanIP)
		legacy := hmac.New(sha256.New, []byte(tok))
		legacy.Write(nonce)
		expectedLegacy := legacy.Sum(nil)
		if hmac.Equal(mac, expectedBound) || hmac.Equal(mac, expectedLegacy) {
			matched = true
			if matchedSlot == 0 {
				matchedSlot = i + 1
				matchedTok = tok
			}
		}
	}
	return matched, matchedSlot, matchedTok
}

func (gw *Gateway) closeAllSessions() {
	gw.mu.Lock()
	sessions := make([]*Session, 0, len(gw.sessions))
	for id, s := range gw.sessions {
		sessions = append(sessions, s)
		delete(gw.sessions, id)
	}
	gw.pendingSessions = nil
	udpSessions := make([]*gwUDPSession, 0, len(gw.udpSessions))
	for k, u := range gw.udpSessions {
		udpSessions = append(udpSessions, u)
		delete(gw.udpSessions, k)
		delete(gw.udpByID, u.id)
		metricActiveUDPSessions.Add(-1)
	}
	activeAg := gw.activeAgent
	gw.activeAgent = nil
	gw.mu.Unlock()

	for _, s := range sessions {
		s.closeSession()
	}
	for _, u := range udpSessions {
		u.mu.Lock()
		st := u.stream
		u.releasePendingLocked()
		u.mu.Unlock()
		if st != nil {
			_ = st.Close()
		}
	}
	if activeAg != nil {
		_ = activeAg.CloseWithError(0, "gateway shutting down")
	}
}

func runGateway(ctx context.Context, quicAddr, token, directHTTPAddr, vhostAddr, httpsAddr string, vhostMap map[string]uint16, mappings []PortMapping, maxMem, maxBuf int64, quicIdle, quicKeepalive, sessionTTL time.Duration, certDir, tlsCertFile, tlsKeyFile string, enableTLS, sameLAN bool) error {
	registerSecretForLogRedaction(token)
	sniMgr, err := newSNICertManager(certDir, tlsCertFile, tlsKeyFile)
	if err != nil {
		return fmt.Errorf("tls manager init: %w", err)
	}
	if len(vhostMap) > 0 {
		sniMgr.enableACME = true
	}
	if defaultKnockController != nil {
		sniMgr.allowSelfSignedPublic = true
		enableTLS = true
	}
	sniMgr.startRenewalScheduler(ctx)

	tokList := parseTokensList(token)
	primaryTok := token
	if len(tokList) > 0 {
		primaryTok = tokList[0]
	}

	tlsConf, fp, err := loadGatewayCert(certDir)
	if err != nil {
		return fmt.Errorf("gateway cert error: %w", err)
	}
	certDigest, _ := hex.DecodeString(fp)
	if defaultClientCAFile != "" {
		if err := configureGatewayMTLS(tlsConf, defaultClientCAFile); err != nil {
			return fmt.Errorf("gateway mTLS config: %w", err)
		}
	}

	gw := &Gateway{
		token:        primaryTok,
		tokens:       tokList,
		certSHA256:   certDigest,
		sessions:     make(map[uint64]*Session),
		udpSessions:  make(map[string]*gwUDPSession),
		udpByID:      make(map[uint64]*gwUDPSession),
		maxMem:       maxMem,
		maxBuf:       maxBuf,
		sessionTTL:   sessionTTL,
		authAttempts: make(map[string]authAttempt),
		sniMgr:       sniMgr,
		enableTLS:    enableTLS,
		ipACL:        defaultIPACL,
		mappings:     append([]PortMapping(nil), mappings...),
	}
	defer gw.closeAllSessions()

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

	// Also listen on TCP (TLS-Mux) on the same address so agents behind UDP-blocking firewalls can fall back automatically
	tcpMuxListener, tcpMuxErr := tls.Listen("tcp", quicAddr, tlsConf)
	if tcpMuxErr == nil {
		defer tcpMuxListener.Close()
		go func() {
			<-ctx.Done()
			_ = tcpMuxListener.Close()
		}()
		go func() {
			for {
				c, err := tcpMuxListener.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				go func(raw net.Conn) {
					if tlsC, ok := raw.(*tls.Conn); ok {
						_ = tlsC.SetDeadline(time.Now().Add(5 * time.Second))
						if err := tlsC.Handshake(); err != nil {
							_ = raw.Close()
							return
						}
						_ = tlsC.SetDeadline(time.Time{})
					}
					muxConn := newTCPMuxConn(raw, false, quicKeepalive, quicIdle)
					gw.authenticateAndServeAgent(ctx, muxConn)
				}(c)
			}
		}()
	}

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
			go gw.authenticateAndServeAgent(ctx, &quicTunnelConn{conn: conn})
		}
	}()

	quicHost, quicPort, _ := net.SplitHostPort(quicAddr)
	if quicPort == "" {
		quicPort = "4242"
	}
	var pubIP string
	if quicHost == "127.0.0.1" || quicHost == "localhost" || quicHost == "::1" {
		pubIP = quicHost
	} else {
		pubIP = detectPublicIP()
	}
	if pubIP == "" {
		pubIP = "YOUR_VPS_IP"
	}

	cmdDir := strings.TrimSpace(certDir)
	if cmdDir == "" {
		cmdDir = ".driftless-certs"
	}
	if err := os.MkdirAll(cmdDir, 0o700); err != nil {
		log.Printf("[gateway] ERROR: failed to create directory %s for client connect command: %v", cmdDir, err)
		return fmt.Errorf("create directory %s: %w", cmdDir, err)
	}
	connectCmdPath := cmdDir + "/client-connect.cmd"
	connectCmdLine := fmt.Sprintf("./driftless client -quic %s:%s -token %s -fingerprint %s", pubIP, quicPort, primaryTok, fp[:16])
	if err := writeFileAtomic0600(connectCmdPath, []byte(connectCmdLine+"\n")); err != nil {
		log.Printf("[gateway] ERROR: failed to save client connect command file %s: %v", connectCmdPath, err)
		return fmt.Errorf("save client connect command file %s: %w", connectCmdPath, err)
	}

	log.Printf("[gateway] driftless %s listening on %s (QUIC+TCP-Mux, cert sha256: %s, auth=[token=valid, hidden, slots=%d])", versionString, quicAddr, fp[:16], len(tokList))
	log.Printf("[gateway] ==========================================================")
	if tryPrintInteractiveTerminalCommand(connectCmdLine) {
		log.Printf("[gateway] Ready-to-copy command displayed on terminal (saved in %s; run './driftless show-token' anytime to view again)", connectCmdPath)
	} else {
		log.Printf("[gateway] Client connection command saved to %s (run './driftless show-token' to view)", connectCmdPath)
		log.Printf("[gateway]   ./driftless client -quic %s:%s -token [token=valid,hidden] -fingerprint %s", pubIP, quicPort, fp[:16])
	}
	if defaultKnockController != nil {
		defaultKnockController.SetPublicEndpoint(pubIP, enableTLS, cmdDir)
		defaultKnockController.PrintBanner("gateway", cmdDir)
	}
	log.Printf("[gateway] ==========================================================")

	<-ctx.Done()
	log.Printf("[gateway] shutting down cleanly...")
	return nil
}

// tryPrintInteractiveTerminalCommand writes the ready-to-copy client command directly to the
// controlling terminal device (/dev/tty on Unix, CONOUT$ on Windows) ONLY when the process is
// running in an interactive terminal session (both stdout and stderr are character devices and
// not under systemd/journald). This prints the command automatically on screen for the user
// while ensuring secrets never enter stdout/stderr pipes, Docker logs, journald, or log files.
func tryPrintInteractiveTerminalCommand(connectCmdLine string) bool {
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
	_, wErr := fmt.Fprintf(ttyFile, "[gateway] Copy and run on your Home PC:\n  %s\n", connectCmdLine)
	return wErr == nil
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
			if !gw.ipACL.AllowedAddr(c.RemoteAddr()) {
				_ = c.Close()
				continue
			}
			go gw.handleVHostClient(c, vhostMap, allowAutoTLS)
		}
	}()
	return nil
}

const maxVHostHeaderBytes = 64 * 1024

func (gw *Gateway) handleVHostClient(rawConn net.Conn, vhostMap map[string]uint16, allowAutoTLS bool) {
	tuneTCPSocket(rawConn)
	c := maybeTerminateTLS(rawConn, gw.sniMgr, allowAutoTLS || gw.enableTLS)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var captured bytes.Buffer
	limited := io.LimitReader(c, maxVHostHeaderBytes)
	tee := io.TeeReader(limited, &captured)
	br := bufio.NewReaderSize(tee, 4096)

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

	if defaultKnockController != nil {
		if strings.HasPrefix(req.URL.Path, knockPathPrefix) {
			pc := &peekedConn{Conn: c, r: bufio.NewReader(io.MultiReader(bytes.NewReader(captured.Bytes()), br))}
			defaultKnockController.handleKnockHTTPConn(pc, rawConn.RemoteAddr())
			return
		}
		if !defaultKnockController.IsAllowedAddr(rawConn.RemoteAddr()) {
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
		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if n == 0 || !gw.ipACL.AllowedAddr(clientAddr) || (defaultKnockController != nil && !defaultKnockController.IsAllowedAddr(clientAddr)) {
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
	us, exists := gw.udpSessions[key]
	if !exists {
		clientIP := ""
		if clientAddr != nil && clientAddr.IP != nil {
			clientIP = clientAddr.IP.String()
		}
		if clientIP != "" {
			ipCount := 0
			for _, existing := range gw.udpSessions {
				if existing.clientAddr != nil && existing.clientAddr.IP != nil && existing.clientAddr.IP.String() == clientIP {
					ipCount++
				}
			}
			if ipCount >= maxUDPSessionsPerIP {
				gw.mu.Unlock()
				return
			}
		}
		if len(gw.udpSessions) >= maxGatewayUDPSessions {
			var oldestKey string
			var oldestUS *gwUDPSession
			for k, existing := range gw.udpSessions {
				if oldestUS == nil || existing.lastActive.Before(oldestUS.lastActive) {
					oldestKey = k
					oldestUS = existing
				}
			}
			if oldestUS != nil {
				oldestUS.mu.Lock()
				oldestSt := oldestUS.stream
				oldestUS.releasePendingLocked()
				oldestUS.mu.Unlock()
				if oldestSt != nil {
					_ = oldestSt.Close()
				}
				delete(gw.udpSessions, oldestKey)
				delete(gw.udpByID, oldestUS.id)
				metricActiveUDPSessions.Add(-1)
			}
		}
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
		metricActiveUDPSessions.Add(1)
	}
	gw.mu.Unlock()

	us.mu.Lock()
	us.lastActive = time.Now()
	st := us.stream
	if agent == nil || st == nil {
		us.enqueuePacketLocked(pkt)
		us.mu.Unlock()
		if agent != nil && us.dialing.CompareAndSwap(false, true) {
			go func(a TunnelConn, session *gwUDPSession) {
				defer session.dialing.Store(false)
				gw.flushUDPSessionToAgent(a, session)
			}(agent, us)
		}
		return
	}
	us.mu.Unlock()

	if err := writeUDPPacket(st, pkt); err == nil {
		return
	}

	us.mu.Lock()
	if us.stream == st {
		_ = us.stream.Close()
		us.stream = nil
	}
	us.enqueuePacketLocked(pkt)
	us.mu.Unlock()

	if us.dialing.CompareAndSwap(false, true) {
		go func(a TunnelConn, session *gwUDPSession) {
			defer session.dialing.Store(false)
			gw.flushUDPSessionToAgent(a, session)
		}(agent, us)
	}
}

func (gw *Gateway) readUDPFromAgentStream(us *gwUDPSession, st TunnelStream) {
	defer st.Close()
	bufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufPtr)
	buf := *bufPtr
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

func (gw *Gateway) authenticateAndServeAgent(ctx context.Context, conn TunnelConn) {
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
	_ = authStream.SetDeadline(time.Now().Add(authTimeout))

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

	matched, keySlot, matchedTok := gw.verifyAgentMAC(nonce, mac, lanIP)
	if !matched {
		gw.noteAuthFail(peerHost)
		log.Printf("[gateway] rejected agent from %s (auth=[token=invalid, hidden], nonce=[one-time, rejected])", peerHost)
		_ = authStream.Close()
		_ = conn.CloseWithError(10, "unauthorized")
		return
	}
	conn.SetAuthenticated()
	_ = authStream.SetDeadline(time.Time{})
	serverMAC := computeServerAuthMAC(matchedTok, nonce, gw.certSHA256, mac)
	okReply := append([]byte{cmdAuthOK}, serverMAC...)
	_, _ = authStream.Write(okReply)
	_ = authStream.Close()
	gw.authReset(peerHost)

	metricActiveTransportName.Store(conn.TransportName())
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

	log.Printf("[gateway] home agent online (epoch #%d, transport=%s, auth=[token=valid, hidden, slot=%d], nonce=[one-time, verified]): wan=%s lan=%s", myEpoch, conn.TransportName(), keySlot, peerHost, lanIP)
	gw.flushPendingSessions(conn)
	gw.handleAgentStreams(ctx, conn, myEpoch)
}


const maxAuthTrackedIPs = 10000

// normalizeAuthIPKey normalizes IPv4 to /32 and IPv6 to its /64 subnet prefix so an attacker
// rotating addresses inside a routed IPv6 /64 cannot bypass brute-force rate limiting or exhaust RAM.
func normalizeAuthIPKey(host string) string {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if v6 := ip.To16(); v6 != nil {
		return v6.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return host
}

func (gw *Gateway) noteAuthFail(ip string) {
	key := normalizeAuthIPKey(ip)
	gw.authMu.Lock()
	defer gw.authMu.Unlock()
	now := time.Now()
	a, ok := gw.authAttempts[key]
	if !ok || now.Sub(a.first) > authWindow {
		if !ok && len(gw.authAttempts) >= maxAuthTrackedIPs {
			for k, v := range gw.authAttempts {
				if now.Sub(v.first) > authWindow {
					delete(gw.authAttempts, k)
					break
				}
			}
			if len(gw.authAttempts) >= maxAuthTrackedIPs {
				for k := range gw.authAttempts {
					delete(gw.authAttempts, k)
					break
				}
			}
		}
		gw.authAttempts[key] = authAttempt{failures: 1, first: now}
		return
	}
	a.failures++
	gw.authAttempts[key] = a
}

func (gw *Gateway) authAllowed(ip string) bool {
	key := normalizeAuthIPKey(ip)
	gw.authMu.Lock()
	defer gw.authMu.Unlock()
	a, ok := gw.authAttempts[key]
	if !ok || time.Since(a.first) > authWindow {
		return true
	}
	return a.failures < maxAuthAttempts
}

func (gw *Gateway) authReset(ip string) {
	key := normalizeAuthIPKey(ip)
	gw.authMu.Lock()
	delete(gw.authAttempts, key)
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
				if expired {
					us.releasePendingLocked()
				}
				us.mu.Unlock()
				if expired {
					if st != nil {
						_ = st.Close()
					}
					delete(gw.udpSessions, key)
					delete(gw.udpByID, us.id)
					metricActiveUDPSessions.Add(-1)
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


func (gw *Gateway) flushPendingSessions(agent TunnelConn) {
	gw.mu.Lock()
	pending := gw.pendingSessions
	gw.pendingSessions = nil
	seen := make(map[uint64]struct{}, len(pending))
	for _, s := range pending {
		seen[s.id] = struct{}{}
	}
	for _, s := range gw.sessions {
		if _, ok := seen[s.id]; ok {
			continue
		}
		s.mu.Lock()
		needsOpen := !s.closed && s.activeStream == nil && s.streamGen == 0
		s.mu.Unlock()
		if needsOpen {
			pending = append(pending, s)
		}
	}
	var udpList []*gwUDPSession
	for _, us := range gw.udpSessions {
		udpList = append(udpList, us)
	}
	gw.mu.Unlock()
	for _, sess := range pending {
		sess.mu.Lock()
		closed := sess.closed
		hasStream := sess.activeStream != nil
		sess.mu.Unlock()
		if !closed && !hasStream {
			gw.openStreamToAgent(agent, sess, cmdNewConn)
		}
	}
	for _, us := range udpList {
		us.mu.Lock()
		hasPending := len(us.pendingPkts) > 0
		us.mu.Unlock()
		if hasPending && us.dialing.CompareAndSwap(false, true) {
			go func(session *gwUDPSession) {
				defer session.dialing.Store(false)
				gw.flushUDPSessionToAgent(agent, session)
			}(us)
		}
	}
}

func (gw *Gateway) flushUDPSessionToAgent(agent TunnelConn, us *gwUDPSession) {
	openCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	newSt, err := agent.OpenStreamSync(openCtx)
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
	if err := us.replayPendingToStream(newSt); err != nil {
		_ = newSt.Close()
		return
	}
	go gw.readUDPFromAgentStream(us, newSt)
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
			if !gw.ipACL.AllowedAddr(c.RemoteAddr()) {
				_ = c.Close()
				continue
			}
			go func(raw net.Conn) {
				tuneTCPSocket(raw)
				var initData []byte
				if defaultProxyProtocol {
					initData = formatProxyProtoV1(raw.RemoteAddr(), raw.LocalAddr())
				}
				if defaultKnockController != nil || len(gw.mappings) > 1 {
					wrapped, resolvedTarget, handled := inspectAndPrepareTCPConn(raw, gw.sniMgr, useTLS, m.TargetPort, gw.mappings, func(proxyConn net.Conn, targetPort uint16, _ string) {
						gw.startResumableSession(proxyConn, targetPort, initData)
					})
					if handled {
						return
					}
					gw.startResumableSession(wrapped, resolvedTarget, initData)
					return
				}
				wrapped := maybeTerminateTLS(raw, gw.sniMgr, useTLS)
				gw.startResumableSession(wrapped, m.TargetPort, initData)
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
	if sess.closed {
		return
	}
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

func (gw *Gateway) openStreamToAgent(agent TunnelConn, sess *Session, cmd uint8) {
	openCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := agent.OpenStreamSync(openCtx)
	if err != nil {
		if cmd == cmdNewConn {
			gw.mu.Lock()
			gw.pendingSessions = append(gw.pendingSessions, sess)
			gw.mu.Unlock()
		}
		return
	}
	var hdr [11]byte
	hdr[0] = cmd
	binary.BigEndian.PutUint64(hdr[1:9], sess.id)
	binary.BigEndian.PutUint16(hdr[9:11], sess.targetPort)
	if _, err := st.Write(hdr[:]); err != nil {
		_ = st.Close()
		if cmd == cmdNewConn {
			gw.mu.Lock()
			gw.pendingSessions = append(gw.pendingSessions, sess)
			gw.mu.Unlock()
		}
		return
	}
	go bridgeSessionStream(sess, st)
}

func (gw *Gateway) handleAgentStreams(ctx context.Context, conn TunnelConn, epoch uint64) {
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			gw.mu.Lock()
			if gw.agentEpoch == epoch {
				gw.activeAgent = nil
				for _, us := range gw.udpSessions {
					us.mu.Lock()
					if us.stream != nil {
						_ = us.stream.Close()
						us.stream = nil
					}
					us.mu.Unlock()
				}
				log.Printf("[gateway] agent disconnected (epoch #%d), holding active sessions in RAM...", epoch)
			}
			gw.mu.Unlock()
			return
		}
		go func(s TunnelStream) {
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
				_ = us.replayPendingToStream(s)
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

