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
	"encoding/json"
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
	BindIP        string `json:"bind_ip,omitempty"` // default "0.0.0.0" (or "127.0.0.1" when using local reverse proxy)
	PublicPort    uint16 `json:"public_port"`
	TargetPort    uint16 `json:"target_port"`
	Proto         string `json:"proto"`             // "both", "tcp", "udp", "http", "https"
	NodeID        string `json:"node_id,omitempty"` // optional target agent NodeID for multi-agent Gateway routing
	RouterTCPPort uint16 `json:"-"`                 // optional local ephemeral bridge port in standalone mode when PublicPort is already bound
	RouterUDPPort uint16 `json:"-"`
}

type VHostRoute struct {
	Domain     string `json:"domain"`
	TargetPort uint16 `json:"target_port"`
	NodeID     string `json:"node_id,omitempty"`
}

type AgentRegistration struct {
	NodeID   string        `json:"node_id"`
	LanIP    string        `json:"lan_ip"`
	Mappings []PortMapping `json:"mappings,omitempty"`
	VHosts   []VHostRoute  `json:"vhosts,omitempty"`
}

type connectedAgent struct {
	nodeID   string
	conn     TunnelConn
	epoch    uint64
	pubIP    string
	lanIP    string
	mappings []PortMapping
	vhosts   []VHostRoute
}

type authAttempt struct {
	failures int
	first    time.Time
}

type Gateway struct {
	ctx             context.Context
	token           string
	tokens          []string
	certSHA256      []byte
	mu              sync.RWMutex
	activeAgent     TunnelConn
	defaultNodeID   string
	agents          map[string]*connectedAgent
	agentEpoch      uint64
	agentPubIP      string
	agentLanIP      string
	vhostRoutes     map[string]VHostRoute
	portRoutes      map[uint16]PortMapping
	portConflicts   []string
	boundTCPPorts   map[uint16]bool
	boundUDPPorts   map[uint16]bool
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
// and the agent's registration payload (or LAN IP) into the HMAC-SHA256 proof (RFC 5929 tls-server-end-point channel binding).
func computeClientAuthMAC(token string, nonce, certSHA256 []byte, authPayload string) []byte {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte("driftless-v1.5-client:"))
	h.Write(certSHA256)
	h.Write(nonce)
	h.Write([]byte(authPayload))
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

func (gw *Gateway) verifyAgentMAC(nonce, mac []byte, authPayload string) (bool, int, string) {
	tokens := gw.tokens
	if len(tokens) == 0 && gw.token != "" {
		tokens = []string{gw.token}
	}
	matched := false
	matchedSlot := 0
	matchedTok := ""
	for i, tok := range tokens {
		expectedBound := computeClientAuthMAC(tok, nonce, gw.certSHA256, authPayload)
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
	var agentConns []TunnelConn
	for _, ag := range gw.agents {
		if ag.conn != nil {
			agentConns = append(agentConns, ag.conn)
			ag.conn = nil
		}
	}
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
	for _, c := range agentConns {
		_ = c.CloseWithError(0, "gateway shutting down")
	}
}

// resolveAgentLocked returns the active TunnelConn and canonical nodeID for a target nodeID (or default agent if empty).
// Caller must hold gw.mu (RLock or Lock).
func (gw *Gateway) resolveAgentLocked(nodeID string) (TunnelConn, string) {
	nodeID = strings.ToLower(strings.TrimSpace(nodeID))
	if nodeID != "" {
		if ag, ok := gw.agents[nodeID]; ok && ag != nil && ag.conn != nil {
			return ag.conn, ag.nodeID
		}
		return nil, nodeID
	}
	if gw.defaultNodeID != "" {
		if ag, ok := gw.agents[gw.defaultNodeID]; ok && ag != nil && ag.conn != nil {
			return ag.conn, ag.nodeID
		}
	}
	for _, ag := range gw.agents {
		if ag != nil && ag.conn != nil {
			return ag.conn, ag.nodeID
		}
	}
	return gw.activeAgent, gw.defaultNodeID
}

func (gw *Gateway) resolvePublicPortRoute(defaultMapping PortMapping) PortMapping {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	if route, ok := gw.portRoutes[defaultMapping.PublicPort]; ok {
		return route
	}
	return defaultMapping
}

func runGateway(ctx context.Context, quicAddr, token, directHTTPAddr, vhostAddr, httpsAddr string, vhostMap map[string]uint16, mappings []PortMapping, maxMem, maxBuf int64, quicIdle, quicKeepalive, sessionTTL time.Duration, certDir, tlsCertFile, tlsKeyFile string, enableTLS, sameLAN bool) error {
	registerSecretForLogRedaction(token)
	sniMgr, err := newSNICertManager(certDir, tlsCertFile, tlsKeyFile)
	if err != nil {
		return fmt.Errorf("tls manager init: %w", err)
	}
	sniMgr.ddns = defaultGatewayDDNS
	if len(vhostMap) > 0 || vhostAddr != "" || httpsAddr != "" || defaultGatewayDDNS.Domain != "" {
		sniMgr.enableACME = true
	}
	if defaultGatewayDDNS.Domain != "" {
		go sniMgr.ensureDomainCertificate(defaultGatewayDDNS.Domain)
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

	initialVHostRoutes := make(map[string]VHostRoute, len(vhostMap))
	for dom, port := range vhostMap {
		initialVHostRoutes[dom] = VHostRoute{
			Domain:     dom,
			TargetPort: port,
			NodeID:     defaultVHostNodeMap[dom],
		}
	}
	initialPortRoutes := make(map[uint16]PortMapping, len(mappings))
	for _, m := range mappings {
		initialPortRoutes[m.PublicPort] = m
	}

	gw := &Gateway{
		ctx:           ctx,
		token:         primaryTok,
		tokens:        tokList,
		certSHA256:    certDigest,
		agents:        make(map[string]*connectedAgent),
		vhostRoutes:   initialVHostRoutes,
		portRoutes:    initialPortRoutes,
		boundTCPPorts: make(map[uint16]bool),
		boundUDPPorts: make(map[uint16]bool),
		sessions:      make(map[uint64]*Session),
		udpSessions:   make(map[string]*gwUDPSession),
		udpByID:       make(map[uint64]*gwUDPSession),
		maxMem:        maxMem,
		maxBuf:        maxBuf,
		sessionTTL:    sessionTTL,
		authAttempts:  make(map[string]authAttempt),
		sniMgr:        sniMgr,
		enableTLS:     enableTLS,
		mappings:      append([]PortMapping(nil), mappings...),
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

	go gw.cleanupLoop(ctx)

	if directHTTPAddr != "" {
		go gw.startDirectRedirector(ctx, directHTTPAddr, mappings, sameLAN)
	}

	if vhostAddr != "" {
		if err := gw.listenHTTPVHostRouter(ctx, vhostAddr, vhostMap, true); err != nil {
			return err
		}
	}
	if httpsAddr != "" {
		if err := gw.listenHTTPVHostRouter(ctx, httpsAddr, vhostMap, true); err != nil {
			return err
		}
	}

	for _, m := range mappings {
		if err := gw.ensurePublicPortListeners(ctx, m, true); err != nil {
			return err
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

	// Also listen on TCP (TLS-Mux) on the same address so agents behind UDP-blocking firewalls can fall back automatically.
	// The bind can transiently fail on Windows when the TCP port is still held by a socket in TIME_WAIT or by another
	// process that grabbed the number between the UDP probe and this bind, so retry briefly before degrading to QUIC-only.
	tcpMuxEnabled := false
	tcpMuxListener, tcpMuxErr := listenTCPMuxWithRetry(ctx, quicAddr, tlsConf)
	if tcpMuxErr != nil {
		log.Printf("[gateway] WARNING: TCP-Mux listener on %s unavailable (%v); agents can only connect over QUIC/UDP until restart", quicAddr, tcpMuxErr)
	} else {
		tcpMuxEnabled = true
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

	transportLabel := "QUIC"
	if tcpMuxEnabled {
		transportLabel = "QUIC+TCP-Mux"
	}
	log.Printf("[gateway] driftless %s listening on %s (%s, cert sha256: %s, auth=[token=valid, hidden, slots=%d])", versionString, quicAddr, transportLabel, fp[:16], len(tokList))
	log.Printf("[gateway] ==========================================================")
	if tryPrintInteractiveTerminalCommand(connectCmdLine) {
		log.Printf("[gateway] Ready-to-copy command displayed on terminal (saved in %s; run './driftless show-token' anytime to view again)", connectCmdPath)
	} else {
		log.Printf("[gateway] Client connection command saved to %s (run './driftless show-token' to view)", connectCmdPath)
		log.Printf("[gateway]   ./driftless client -quic %s:%s -token [token=valid,hidden] -fingerprint %s", pubIP, quicPort, fp[:16])
	}
	log.Printf("[gateway] ==========================================================")

	<-ctx.Done()
	log.Printf("[gateway] shutting down cleanly...")
	return nil
}

func (gw *Gateway) recordConflict(msg string) {
	gw.mu.Lock()
	gw.portConflicts = append(gw.portConflicts, msg)
	gw.mu.Unlock()
	log.Printf("[gateway] CONFLICT: %s", msg)
}

func (gw *Gateway) Conflicts() []string {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return append([]string(nil), gw.portConflicts...)
}

func (gw *Gateway) ensurePublicPortListeners(ctx context.Context, m PortMapping, strict bool) error {
	reqNode := strings.ToLower(strings.TrimSpace(m.NodeID))
	gw.mu.Lock()
	if existing, ok := gw.portRoutes[m.PublicPort]; ok {
		exNode := strings.ToLower(strings.TrimSpace(existing.NodeID))
		if exNode != "" && reqNode != "" && exNode != reqNode {
			gw.mu.Unlock()
			conflictErr := fmt.Errorf("public port :%d requested by agent %q is already assigned to agent %q", m.PublicPort, reqNode, exNode)
			gw.recordConflict(conflictErr.Error())
			return conflictErr
		}
	}
	needTCP := (m.Proto == "tcp" || m.Proto == "http" || m.Proto == "https" || m.Proto == "both") && !gw.boundTCPPorts[m.PublicPort]
	needUDP := (m.Proto == "udp" || m.Proto == "both") && !gw.boundUDPPorts[m.PublicPort]
	if needTCP {
		gw.boundTCPPorts[m.PublicPort] = true
	}
	if needUDP {
		gw.boundUDPPorts[m.PublicPort] = true
	}
	gw.mu.Unlock()

	if needTCP {
		if err := gw.listenPublicPort(ctx, m); err != nil {
			gw.mu.Lock()
			delete(gw.boundTCPPorts, m.PublicPort)
			gw.mu.Unlock()
			conflictMsg := fmt.Sprintf("could not bind TCP :%d for agent %q: %v", m.PublicPort, nodeLabel(m.NodeID), err)
			gw.recordConflict(conflictMsg)
			return err
		}
	}
	if needUDP {
		if err := gw.listenPublicUDPPort(ctx, m); err != nil {
			gw.mu.Lock()
			delete(gw.boundUDPPorts, m.PublicPort)
			gw.mu.Unlock()
			if strict || m.Proto == "udp" {
				conflictMsg := fmt.Sprintf("could not bind UDP :%d for agent %q: %v", m.PublicPort, nodeLabel(m.NodeID), err)
				gw.recordConflict(conflictMsg)
				return err
			}
			log.Printf("[gateway] note: UDP :%d not bound (%v)", m.PublicPort, err)
		}
	}

	gw.mu.Lock()
	gw.portRoutes[m.PublicPort] = m
	gw.mu.Unlock()
	return nil
}

// listenTCPMuxWithRetry binds the TLS-mux (agent TCP fallback) listener, retrying briefly on
// transient bind failures such as WSAEADDRINUSE from a socket still in TIME_WAIT.
func listenTCPMuxWithRetry(ctx context.Context, addr string, tlsConf *tls.Config) (net.Listener, error) {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
		}
		l, err := tls.Listen("tcp", addr, tlsConf)
		if err == nil {
			return l, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// tryPrintInteractiveTerminalCommand writes the ready-to-copy client command directly to the
// controlling terminal device (/dev/tty on Unix, CONOUT$ on Windows) ONLY when the process is
// running in an interactive terminal session.
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
	routes := make(map[string]VHostRoute, len(vhostMap))
	for k, port := range vhostMap {
		routes[k] = VHostRoute{Domain: k, TargetPort: port}
	}
	r, ok := matchVHostRoute(routes, host, reqPath)
	return r.TargetPort, ok
}

func matchVHostRoute(routes map[string]VHostRoute, host, reqPath string) (VHostRoute, bool) {
	if reqPath == "" {
		reqPath = "/"
	}
	// 1. Longest matching domain+path rule (e.g. "app.example.com/api:4000")
	bestLen := -1
	var bestRoute VHostRoute
	for pattern, route := range routes {
		slashIdx := strings.IndexByte(pattern, '/')
		if slashIdx == -1 {
			continue
		}
		patHost := pattern[:slashIdx]
		patPath := pattern[slashIdx:]
		if (patHost == host || patHost == "*") && strings.HasPrefix(reqPath, patPath) {
			if len(patPath) > bestLen {
				bestLen = len(patPath)
				bestRoute = route
			}
		}
	}
	if bestLen >= 0 {
		return bestRoute, true
	}
	// 2. Exact host match
	if route, ok := routes[host]; ok {
		return route, true
	}
	// 3. Wildcard subdomain match (e.g. "*.example.com")
	if dotIdx := strings.IndexByte(host, '.'); dotIdx != -1 {
		if route, ok := routes["*"+host[dotIdx:]]; ok {
			return route, true
		}
	}
	// 4. Catch-all "*"
	if route, ok := routes["*"]; ok {
		return route, true
	}
	return VHostRoute{}, false
}

func (gw *Gateway) resolveVHostRoute(fallbackMap map[string]uint16, host, reqPath string) (VHostRoute, bool) {
	gw.mu.RLock()
	routesCopy := make(map[string]VHostRoute, len(fallbackMap)+len(gw.vhostRoutes))
	for k, port := range fallbackMap {
		routesCopy[k] = VHostRoute{Domain: k, TargetPort: port, NodeID: defaultVHostNodeMap[k]}
	}
	for k, r := range gw.vhostRoutes {
		routesCopy[k] = r
	}
	gw.mu.RUnlock()
	return matchVHostRoute(routesCopy, host, reqPath)
}

func (gw *Gateway) listenHTTPVHostRouter(ctx context.Context, listenAddr string, vhostMap map[string]uint16, allowAutoTLS bool) error {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("vhost listen %s: %w", listenAddr, err)
	}
	log.Printf("[gateway] HTTP/HTTPS VHost router active on %s (%d static routes, auto-TLS=%v)", listenAddr, len(vhostMap), allowAutoTLS)
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

	host := strings.ToLower(strings.TrimSpace(req.Host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	route, ok := gw.resolveVHostRoute(vhostMap, host, req.URL.Path)
	if !ok {
		_, _ = c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 21\r\nConnection: close\r\n\r\ndriftless: unknown host"))
		_ = c.Close()
		return
	}

	gw.startResumableSessionForNode(c, route.NodeID, route.TargetPort, captured.Bytes())
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
	log.Printf("[gateway] forwarding UDP :%d -> agent :%d (node=%s)", m.PublicPort, m.TargetPort, nodeLabel(m.NodeID))

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
			if n == 0 {
				continue
			}
			pkt := append([]byte(nil), buf[:n]...)
			route := gw.resolvePublicPortRoute(m)
			gw.forwardUDPToAgentNode(conn, clientAddr, route.NodeID, route.TargetPort, pkt)
		}
	}()
	return nil
}

func nodeLabel(nodeID string) string {
	if strings.TrimSpace(nodeID) == "" {
		return "default"
	}
	return nodeID
}

func (gw *Gateway) forwardUDPToAgent(pubConn *net.UDPConn, clientAddr *net.UDPAddr, targetPort uint16, pkt []byte) {
	gw.forwardUDPToAgentNode(pubConn, clientAddr, "", targetPort, pkt)
}

func (gw *Gateway) forwardUDPToAgentNode(pubConn *net.UDPConn, clientAddr *net.UDPAddr, nodeID string, targetPort uint16, pkt []byte) {
	normNode := strings.ToLower(strings.TrimSpace(nodeID))
	key := fmt.Sprintf("%s->%s:%d", clientAddr.String(), normNode, targetPort)

	gw.mu.Lock()
	agent, resolvedNode := gw.resolveAgentLocked(normNode)
	if normNode == "" {
		normNode = resolvedNode
	}
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
			var oldestLastActive time.Time
			for k, existing := range gw.udpSessions {
				existing.mu.Lock()
				exLast := existing.lastActive
				existing.mu.Unlock()
				if oldestUS == nil || exLast.Before(oldestLastActive) {
					oldestKey = k
					oldestUS = existing
					oldestLastActive = exLast
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
			nodeID:     normNode,
			targetPort: targetPort,
			clientAddr: clientAddr,
			pubConn:    pubConn,
			lastActive: time.Now(),
		}
		gw.udpSessions[key] = us
		gw.udpByID[id] = us
		metricActiveUDPSessions.Add(1)
	} else if us.nodeID == "" && normNode != "" {
		us.nodeID = normNode
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

func decodeAgentAuthPayload(raw string) AgentRegistration {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") {
		var reg AgentRegistration
		if err := json.Unmarshal([]byte(trimmed), &reg); err == nil {
			reg.NodeID = strings.ToLower(strings.TrimSpace(reg.NodeID))
			if reg.NodeID == "" {
				reg.NodeID = "default"
			}
			return reg
		}
	}
	return AgentRegistration{
		NodeID: "default",
		LanIP:  trimmed,
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
	payloadLen := int(lhdr[0])
	if payloadLen == 255 {
		var extLen [2]byte
		if _, err := io.ReadFull(authStream, extLen[:]); err != nil {
			_ = authStream.Close()
			_ = conn.CloseWithError(8, "bad extended payload length")
			return
		}
		payloadLen = int(binary.BigEndian.Uint16(extLen[:]))
	}
	authPayload := ""
	if payloadLen > 0 {
		payloadB := make([]byte, payloadLen)
		if _, err := io.ReadFull(authStream, payloadB); err != nil {
			_ = authStream.Close()
			_ = conn.CloseWithError(9, "bad auth payload")
			return
		}
		authPayload = string(payloadB)
	}

	matched, keySlot, matchedTok := gw.verifyAgentMAC(nonce, mac, authPayload)
	if !matched {
		gw.noteAuthFail(peerHost)
		log.Printf("[gateway] rejected agent from %s (auth=[token=invalid, hidden], nonce=[one-time, rejected])", peerHost)
		_ = authStream.Close()
		_ = conn.CloseWithError(10, "unauthorized")
		return
	}
	conn.SetAuthenticated()
	_ = authStream.SetDeadline(time.Time{})
	gw.authReset(peerHost)

	reg := decodeAgentAuthPayload(authPayload)
	nodeID := reg.NodeID
	if nodeID == "" {
		nodeID = "default"
	}

	metricActiveTransportName.Store(conn.TransportName())
	var authConflicts []string

	gw.mu.Lock()
	gw.agentEpoch++
	myEpoch := gw.agentEpoch

	var oldConn TunnelConn
	if prevAg, exists := gw.agents[nodeID]; exists && prevAg != nil {
		oldConn = prevAg.conn
	}
	agEntry := &connectedAgent{
		nodeID:   nodeID,
		conn:     conn,
		epoch:    myEpoch,
		pubIP:    peerHost,
		lanIP:    reg.LanIP,
		mappings: reg.Mappings,
		vhosts:   reg.VHosts,
	}
	gw.agents[nodeID] = agEntry
	// Only update defaultNodeID if none is set yet, if this is the "default" node, or if the current default node is offline
	if gw.defaultNodeID == "" || nodeID == "default" {
		gw.defaultNodeID = nodeID
	} else if curDef, ok := gw.agents[gw.defaultNodeID]; !ok || curDef == nil || curDef.conn == nil {
		gw.defaultNodeID = nodeID
	}
	gw.activeAgent = conn
	gw.agentPubIP = peerHost
	gw.agentLanIP = reg.LanIP

	for _, vh := range reg.VHosts {
		dom := strings.ToLower(strings.TrimSpace(vh.Domain))
		if dom != "" && vh.TargetPort > 0 {
			if existingVH, exists := gw.vhostRoutes[dom]; exists && existingVH.NodeID != "" && existingVH.NodeID != nodeID {
				cMsg := fmt.Sprintf("vhost %q requested by agent %q is already assigned to agent %q", dom, nodeID, existingVH.NodeID)
				gw.portConflicts = append(gw.portConflicts, cMsg)
				authConflicts = append(authConflicts, cMsg)
				log.Printf("[gateway] CONFLICT: %s", cMsg)
				continue
			}
			gw.vhostRoutes[dom] = VHostRoute{
				Domain:     dom,
				TargetPort: vh.TargetPort,
				NodeID:     nodeID,
			}
			log.Printf("[gateway] registered VHost %s -> agent %q :%d", dom, nodeID, vh.TargetPort)
		}
	}
	gw.mu.Unlock()

	for _, pm := range reg.Mappings {
		pm.NodeID = nodeID
		if pm.Proto == "" {
			pm.Proto = "both"
		}
		if gw.ctx != nil {
			if err := gw.ensurePublicPortListeners(gw.ctx, pm, false); err != nil {
				authConflicts = append(authConflicts, err.Error())
			}
		} else {
			gw.mu.Lock()
			if existingPM, ok := gw.portRoutes[pm.PublicPort]; ok && existingPM.NodeID != "" && existingPM.NodeID != nodeID {
				cMsg := fmt.Sprintf("public port :%d requested by agent %q is already assigned to agent %q", pm.PublicPort, nodeID, existingPM.NodeID)
				gw.portConflicts = append(gw.portConflicts, cMsg)
				authConflicts = append(authConflicts, cMsg)
				gw.mu.Unlock()
				log.Printf("[gateway] CONFLICT: %s", cMsg)
			} else {
				gw.portRoutes[pm.PublicPort] = pm
				gw.mu.Unlock()
			}
		}
	}

	// Send cmdAuthOK + serverMAC ONLY AFTER all VHosts and public port listeners for this Agent are bound and ready
	serverMAC := computeServerAuthMAC(matchedTok, nonce, gw.certSHA256, mac)
	okReply := append([]byte{cmdAuthOK}, serverMAC...)
	if len(authConflicts) > 0 {
		conflictNotice := strings.Join(authConflicts, "; ")
		if len(conflictNotice) > 65000 {
			conflictNotice = conflictNotice[:65000]
		}
		var cLen [2]byte
		binary.BigEndian.PutUint16(cLen[:], uint16(len(conflictNotice)))
		okReply = append(okReply, cLen[0], cLen[1])
		okReply = append(okReply, []byte(conflictNotice)...)
	}
	_, _ = authStream.Write(okReply)
	_ = authStream.Close()

	if oldConn != nil && oldConn != conn {
		_ = oldConn.CloseWithError(0, "superseded by new agent connection for node "+nodeID)
	}

	log.Printf("[gateway] home agent %q online (epoch #%d, transport=%s, auth=[token=valid, hidden, slot=%d], nonce=[one-time, verified]): wan=%s lan=%s", nodeID, myEpoch, conn.TransportName(), keySlot, peerHost, reg.LanIP)
	gw.flushPendingSessionsForNode(nodeID, conn)
	gw.handleAgentStreams(ctx, nodeID, conn, myEpoch)
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
		var oldestLastActive time.Time
		for id, s := range gw.sessions {
			closed, lastAct := s.snapshotStatus()
			if closed {
				delete(gw.sessions, id)
				continue
			}
			if oldestSess == nil || lastAct.Before(oldestLastActive) {
				oldestID = id
				oldestSess = s
				oldestLastActive = lastAct
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

func sessionMatchesNode(sessNodeID, connectedNodeID, defaultNodeID string) bool {
	sessNodeID = strings.ToLower(strings.TrimSpace(sessNodeID))
	connectedNodeID = strings.ToLower(strings.TrimSpace(connectedNodeID))
	defaultNodeID = strings.ToLower(strings.TrimSpace(defaultNodeID))
	if sessNodeID != "" {
		return sessNodeID == connectedNodeID
	}
	return connectedNodeID == "default" || connectedNodeID == defaultNodeID
}

func (gw *Gateway) flushPendingSessionsForNode(nodeID string, agent TunnelConn) {
	gw.mu.Lock()
	var remainingPending []*Session
	var pending []*Session
	seen := make(map[uint64]struct{})
	for _, s := range gw.pendingSessions {
		if sessionMatchesNode(s.nodeID, nodeID, gw.defaultNodeID) {
			if s.nodeID == "" {
				s.nodeID = nodeID
			}
			pending = append(pending, s)
			seen[s.id] = struct{}{}
		} else {
			remainingPending = append(remainingPending, s)
		}
	}
	gw.pendingSessions = remainingPending

	for _, s := range gw.sessions {
		if _, ok := seen[s.id]; ok {
			continue
		}
		if !sessionMatchesNode(s.nodeID, nodeID, gw.defaultNodeID) {
			continue
		}
		s.mu.Lock()
		needsOpen := !s.closed && s.activeStream == nil && s.streamGen == 0
		s.mu.Unlock()
		if needsOpen {
			if s.nodeID == "" {
				s.nodeID = nodeID
			}
			pending = append(pending, s)
		}
	}
	var udpList []*gwUDPSession
	for _, us := range gw.udpSessions {
		if sessionMatchesNode(us.nodeID, nodeID, gw.defaultNodeID) {
			if us.nodeID == "" {
				us.nodeID = nodeID
			}
			udpList = append(udpList, us)
		}
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
	// If a WAN drop occurred while cmdNewConn was in flight, the Agent never received the session
	// and therefore will not send cmdResume for it. Check after 120ms and re-open any still-streamless sessions.
	go func(nID string, a TunnelConn) {
		time.Sleep(120 * time.Millisecond)
		gw.mu.RLock()
		curAg, ok := gw.agents[nID]
		if !ok || curAg == nil || curAg.conn != a {
			gw.mu.RUnlock()
			return
		}
		var orphaned []*Session
		for _, s := range gw.sessions {
			if !sessionMatchesNode(s.nodeID, nID, gw.defaultNodeID) {
				continue
			}
			s.mu.Lock()
			needRecovery := !s.closed && s.activeStream == nil
			s.mu.Unlock()
			if needRecovery {
				orphaned = append(orphaned, s)
			}
		}
		gw.mu.RUnlock()
		for _, s := range orphaned {
			s.mu.Lock()
			stillNeed := !s.closed && s.activeStream == nil
			s.mu.Unlock()
			if stillNeed {
				gw.openStreamToAgent(a, s, cmdNewConn)
			}
		}
	}(nodeID, agent)
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

func (gw *Gateway) handleProbeHTTP(w http.ResponseWriter, r *http.Request) {
	gw.mu.RLock()
	tokens := append([]string(nil), gw.tokens...)
	if len(tokens) == 0 && gw.token != "" {
		tokens = []string{gw.token}
	}
	var agentIPs []string
	if gw.agentPubIP != "" {
		agentIPs = append(agentIPs, gw.agentPubIP)
	}
	for _, ag := range gw.agents {
		if ag != nil && ag.conn != nil && ag.pubIP != "" {
			agentIPs = append(agentIPs, ag.pubIP)
		}
	}
	gw.mu.RUnlock()
	serveExternalProbeHTTP(w, r, tokens, agentIPs, true)
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
	mux.HandleFunc("/probe", gw.handleProbeHTTP)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		nodeParam := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("node")))
		gw.mu.RLock()
		pubIP := gw.agentPubIP
		lanIP := gw.agentLanIP
		if nodeParam != "" {
			if ag, ok := gw.agents[nodeParam]; ok && ag != nil {
				pubIP = ag.pubIP
				lanIP = ag.lanIP
			}
		}
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
	log.Printf("[gateway] direct LAN/WAN redirector & external reachability probe active on %s", listenAddr)
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
	log.Printf("[gateway] forwarding TCP %s:%d -> agent :%d (node=%s, auto-tls=%v)", bindIP, m.PublicPort, m.TargetPort, nodeLabel(m.NodeID), useTLS)
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
				var initData []byte
				if defaultProxyProtocol {
					initData = formatProxyProtoV1(raw.RemoteAddr(), raw.LocalAddr())
				}
				route := gw.resolvePublicPortRoute(m)
				wrapped := maybeTerminateTLS(raw, gw.sniMgr, useTLS || route.Proto == "https")
				gw.startResumableSessionForNode(wrapped, route.NodeID, route.TargetPort, initData)
			}(c)
		}
	}()
	return nil
}

func (gw *Gateway) startResumableSession(c net.Conn, targetPort uint16, initialOutData []byte) {
	gw.startResumableSessionForNode(c, "", targetPort, initialOutData)
}

func (gw *Gateway) startResumableSessionForNode(c net.Conn, nodeID string, targetPort uint16, initialOutData []byte) {
	if globalBufferedBytes.Load()+gw.maxBuf > gw.maxMem {
		gw.evictOldestSessionIfNeeded()
	}
	id := gw.nextID.Add(1)
	sess := newSession(id, targetPort, c, gw.maxBuf, gw.maxMem, initialOutData)
	if sess.closed {
		return
	}
	gw.mu.Lock()
	agent, resolvedNode := gw.resolveAgentLocked(nodeID)
	sess.nodeID = resolvedNode
	gw.sessions[id] = sess
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

func (gw *Gateway) handleAgentStreams(ctx context.Context, nodeID string, conn TunnelConn, epoch uint64) {
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			gw.mu.Lock()
			if ag, ok := gw.agents[nodeID]; ok && ag != nil && ag.epoch == epoch {
				ag.conn = nil
				if gw.activeAgent == conn {
					gw.activeAgent = nil
					for _, other := range gw.agents {
						if other != nil && other.conn != nil {
							gw.activeAgent = other.conn
							if gw.defaultNodeID == nodeID {
								gw.defaultNodeID = other.nodeID
							}
							break
						}
					}
				}
				for _, us := range gw.udpSessions {
					if us.nodeID == nodeID || (us.nodeID == "" && nodeID == "default") {
						us.mu.Lock()
						if us.stream != nil {
							_ = us.stream.Close()
							us.stream = nil
						}
						us.mu.Unlock()
					}
				}
				log.Printf("[gateway] agent %q disconnected (epoch #%d), holding its active sessions in RAM without affecting other agents...", nodeID, epoch)
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
				usNode := ""
				if ok && us != nil {
					usNode = us.nodeID
				}
				gw.mu.RUnlock()
				if !ok || us == nil || (usNode != "" && usNode != nodeID) {
					_ = s.Close()
					return
				}
				_ = us.replayPendingToStream(s)
				gw.readUDPFromAgentStream(us, s)
				return
			}

			gw.mu.RLock()
			sess, ok := gw.sessions[sessID]
			sessNode := ""
			if ok && sess != nil {
				sessNode = sess.nodeID
			}
			gw.mu.RUnlock()
			if !ok || sess == nil || (sessNode != "" && sessNode != nodeID) {
				_ = s.Close()
				return
			}
			if closed, _ := sess.snapshotStatus(); closed {
				_ = s.Close()
				return
			}
			log.Printf("[gateway] session #%d seamlessly resumed on agent %q", sessID, nodeID)
			bridgeSessionStream(sess, s)
		}(st)
	}
}
