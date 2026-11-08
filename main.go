package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	versionString = "v1.0.0"
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

func newSession(id uint64, targetPort uint16, conn net.Conn, maxBuf, maxGlobal int64, initialOutData []byte) *Session {
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
	binary.BigEndian.PutUint64(hdr[:], myInOffset)
	if _, err := stream.Write(hdr[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		return
	}
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
		total := 0
		for total < len(b) {
			n, err := stream.Write(b[total:])
			if n > 0 {
				total += n
			}
			if err != nil {
				return err
			}
		}
		return nil
	}

	doneSending := make(chan struct{})
	go func() {
		defer close(doneSending)
		sentOffset := peerAckedOffset
		finSent := false

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

			var chunk []byte
			if totalAvailable > sentOffset {
				startIdx := int(sentOffset-s.baseOffset) + s.outBase
				endIdx := len(s.outBuf)
				if endIdx-startIdx > maxChunkSize {
					endIdx = startIdx + maxChunkSize
				}
				chunk = append([]byte(nil), s.outBuf[startIdx:endIdx]...)
			}
			shouldSendFin := s.localEOF && !finSent && (sentOffset+uint64(len(chunk)) == totalAvailable)
			s.mu.Unlock()

			if len(chunk) > 0 {
				frame := make([]byte, 5+len(chunk))
				frame[0] = frameData
				binary.BigEndian.PutUint32(frame[1:5], uint32(len(chunk)))
				copy(frame[5:], chunk)
				if err := sendFrame(frame); err != nil {
					return
				}
				sentOffset += uint64(len(chunk))
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
	PublicPort uint16
	TargetPort uint16
	Proto      string // "tcp", "udp", "http", "https"
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
}

func runGateway(ctx context.Context, quicAddr, token, directHTTPAddr, vhostAddr string, vhostMap map[string]uint16, mappings []PortMapping, maxMem, maxBuf int64, quicIdle, quicKeepalive, sessionTTL time.Duration, certDir string, sameLAN bool) error {
	gw := &Gateway{
		token:        token,
		sessions:     make(map[uint64]*Session),
		udpSessions:  make(map[string]*gwUDPSession),
		udpByID:      make(map[uint64]*gwUDPSession),
		maxMem:       maxMem,
		maxBuf:       maxBuf,
		sessionTTL:   sessionTTL,
		authAttempts: make(map[string]authAttempt),
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

	log.Printf("[gateway] driftless %s listening on %s (cert sha256: %s)", versionString, quicAddr, fp[:16]+"...")
	log.Printf("[gateway] ==========================================================")
	log.Printf("[gateway] Run this command on your Home PC to connect:")
	log.Printf("[gateway]   ./driftless client -quic %s:%s -token %s", pubIP, quicPort, token)
	log.Printf("[gateway] ==========================================================")

	go gw.cleanupLoop(ctx)

	if directHTTPAddr != "" {
		go gw.startDirectRedirector(ctx, directHTTPAddr, mappings, sameLAN)
	}

	if vhostAddr != "" && len(vhostMap) > 0 {
		if err := gw.listenHTTPVHostRouter(ctx, vhostAddr, vhostMap); err != nil {
			return err
		}
	}

	for _, m := range mappings {
		if m.Proto == "udp" {
			if err := gw.listenPublicUDPPort(ctx, m); err != nil {
				return err
			}
		} else {
			if err := gw.listenPublicPort(ctx, m); err != nil {
				return err
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

func (gw *Gateway) listenHTTPVHostRouter(ctx context.Context, listenAddr string, vhostMap map[string]uint16) error {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("vhost listen %s: %w", listenAddr, err)
	}
	log.Printf("[gateway] HTTP Host/Subdomain router active on %s (%d domains)", listenAddr, len(vhostMap))
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
			go gw.handleVHostClient(c, vhostMap)
		}
	}()
	return nil
}

func (gw *Gateway) handleVHostClient(c net.Conn, vhostMap map[string]uint16) {
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

	host := strings.ToLower(strings.TrimSpace(req.Host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	targetPort, ok := vhostMap[host]
	if !ok {
		targetPort, ok = vhostMap["*"]
	}
	if !ok {
		_, _ = c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 21\r\nConnection: close\r\n\r\ndriftless: unknown host"))
		_ = c.Close()
		return
	}

	gw.startResumableSession(c, targetPort, captured.Bytes())
}

func (gw *Gateway) listenPublicUDPPort(ctx context.Context, m PortMapping) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", m.PublicPort))
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

// evictOldestSessionIfNeeded implements FIFO memory protection when global RAM approaches maxMem.
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
	l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", m.PublicPort))
	if err != nil {
		return fmt.Errorf("listen port %d: %w", m.PublicPort, err)
	}
	log.Printf("[gateway] forwarding TCP :%d -> agent :%d", m.PublicPort, m.TargetPort)
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
			go gw.startResumableSession(c, m.TargetPort, nil)
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

// nextBackoff implements smart staged exponential backoff (150ms -> 500ms -> 1s -> 3s -> 10s max) with random jitter.
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

func parseMappings(raw string) ([]PortMapping, error) {
	var res []PortMapping
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		proto := "tcp"
		if strings.HasSuffix(strings.ToLower(pair), "/udp") {
			proto = "udp"
			pair = pair[:len(pair)-4]
		} else if strings.HasSuffix(strings.ToLower(pair), "/tcp") {
			proto = "tcp"
			pair = pair[:len(pair)-4]
		}

		p := strings.Split(pair, ":")
		if len(p) < 2 || len(p) > 3 {
			return nil, fmt.Errorf("invalid port mapping %q (expected PUBLIC:LOCAL or PUBLIC:LOCAL/udp)", pair)
		}
		pub, err1 := strconv.Atoi(p[0])
		loc, err2 := strconv.Atoi(p[1])
		if err1 != nil || err2 != nil || pub <= 0 || pub > 65535 || loc <= 0 || loc > 65535 {
			return nil, fmt.Errorf("port out of range (1..65535) in %q", pair)
		}
		if len(p) == 3 {
			sub := strings.ToLower(strings.TrimSpace(p[2]))
			if sub != "http" && sub != "https" && sub != "udp" && sub != "tcp" {
				return nil, fmt.Errorf("invalid protocol/scheme in %q", pair)
			}
			proto = sub
		}
		res = append(res, PortMapping{PublicPort: uint16(pub), TargetPort: uint16(loc), Proto: proto})
	}
	if len(res) == 0 {
		return nil, errors.New("at least one port mapping is required")
	}
	return res, nil
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
	if fingerprint == "" {
		return &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{alpnProtocol},
		}, nil
	}
	want, err := hex.DecodeString(fingerprint)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("invalid -fingerprint: expected 64 hex chars (SHA-256)")
	}
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{alpnProtocol},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificate presented by gateway")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !hmac.Equal(sum[:], want) {
				return fmt.Errorf("certificate fingerprint mismatch: got %x, want %x", sum, want)
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
		case "version", "-v", "--version":
			fmt.Printf("driftless %s (TCP/UDP/HTTP-VHost over QUIC)\n", versionString)
			return
		}
	}

	mode := flag.String("mode", defaultMode, "'gateway' (or 'server') / 'agent' (or 'client')")
	quicAddr := flag.String("quic", "0.0.0.0:4242", "gateway QUIC address (e.g. VPS_IP:4242)")
	tokenFlag := flag.String("token", "", "shared secret password (auto-generated on server if omitted)")
	tokenFile := flag.String("token-file", "", "path to file containing shared secret password")
	ports := flag.String("ports", "8080:80,8096:8096", "PUBLIC:LOCAL mappings (add /udp for UDP, e.g. 25565:25565/udp)")
	vhostAddr := flag.String("vhost-addr", "", "optional HTTP Host router listen address (e.g. :80)")
	vhosts := flag.String("vhosts", "", "comma-separated domain:LOCAL_PORT mappings (e.g. app.example.com:3000,media.example.com:8096)")
	direct := flag.String("direct", ":8888", "direct LAN/WAN HTTP redirector listen address (empty to disable)")
	host := flag.String("host", "127.0.0.1", "local target host on agent")
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
	flag.Parse()

	isServer := *mode == "gateway" || *mode == "server"
	token, err := loadOrGenerateToken(isServer, *tokenFlag, *tokenFile)
	if err != nil {
		log.Fatalf("[driftless] %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if isServer {
		mappings, err := parseMappings(*ports)
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
		if err := runGateway(ctx, *quicAddr, token, *direct, *vhostAddr, vhostMap, mappings, *maxMem, *maxBuf, *quicIdle, *quicKeepalive, *sessionTTL, *certDir, *sameLAN); err != nil {
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
