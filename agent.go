package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type Agent struct {
	gatewayAddr     string
	gatewayAddrs    []string
	lastConnectedGW string
	transport       string
	targetHost      string
	token           string
	lanIP           string
	maxBuf          int64
	maxMem          int64
	sessionTTL      time.Duration
	allowedPorts    map[uint16]struct{}
	mu              sync.RWMutex
	sessions        map[uint64]*Session
	udpSessions     map[uint64]*agentUDPSession
}

func (ag *Agent) allowedPort(port uint16) bool {
	if len(ag.allowedPorts) == 0 {
		return true
	}
	_, ok := ag.allowedPorts[port]
	return ok
}

func (ag *Agent) closeAllSessionsForFailover() {
	ag.mu.Lock()
	sessions := make([]*Session, 0, len(ag.sessions))
	for id, s := range ag.sessions {
		sessions = append(sessions, s)
		delete(ag.sessions, id)
	}
	udpSessions := make([]*agentUDPSession, 0, len(ag.udpSessions))
	for id, u := range ag.udpSessions {
		udpSessions = append(udpSessions, u)
		delete(ag.udpSessions, id)
	}
	ag.mu.Unlock()

	for _, s := range sessions {
		s.closeSession()
	}
	for _, u := range udpSessions {
		u.mu.Lock()
		st := u.stream
		lc := u.localConn
		u.releasePendingLocked()
		u.mu.Unlock()
		if st != nil {
			_ = st.Close()
		}
		if lc != nil {
			_ = lc.Close()
		}
	}
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
	var gwList []string
	for _, a := range strings.Split(gatewayAddr, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			gwList = append(gwList, a)
		}
	}
	if len(gwList) == 0 {
		gwList = []string{gatewayAddr}
	}
	tokList := parseTokensList(token)
	primaryTok := token
	if len(tokList) > 0 {
		primaryTok = tokList[0]
	}

	ag := &Agent{
		gatewayAddr:  gwList[0],
		gatewayAddrs: gwList,
		transport:    defaultTransportMode,
		targetHost:   targetHost,
		token:        primaryTok,
		lanIP:        lanIP,
		maxBuf:       maxBuf,
		maxMem:       maxMem,
		sessionTTL:   sessionTTL,
		allowedPorts: allowedPorts,
		sessions:     make(map[uint64]*Session),
		udpSessions:  make(map[uint64]*agentUDPSession),
	}

	// Validate fingerprint syntax upfront before entering connect loop
	if _, err := makeAgentTLSForGateway(fingerprint, ag.gatewayAddrs[0]); err != nil {
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
	gwIdx := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		targetGW := ag.gatewayAddrs[gwIdx%len(ag.gatewayAddrs)]
		tlsConf, err := makeAgentTLSForGateway(fingerprint, targetGW)
		if err != nil {
			return fmt.Errorf("agent tls (%s): %w", targetGW, err)
		}
		if defaultClientCert != "" && defaultClientKey != "" {
			if err := configureAgentMTLS(tlsConf, defaultClientCert, defaultClientKey); err != nil {
				return fmt.Errorf("agent mTLS config: %w", err)
			}
		}
		conn, err := dialTunnelGateway(ctx, targetGW, ag.transport, tlsConf, quicConf)
		if err != nil {
			gwIdx++
			// Only sleep backoff once we have tried all configured gateways in the failover ring
			if len(ag.gatewayAddrs) <= 1 || gwIdx%len(ag.gatewayAddrs) == 0 {
				delay := nextBackoff(attempt)
				attempt++
				sleepWithContext(ctx, delay)
			}
			continue
		}
		if err := ag.sendAuth(ctx, conn); err != nil {
			_ = conn.CloseWithError(1, "auth failed")
			log.Printf("[agent] auth error on %s: %v", targetGW, err)
			gwIdx++
			if len(ag.gatewayAddrs) <= 1 || gwIdx%len(ag.gatewayAddrs) == 0 {
				delay := nextBackoff(attempt)
				attempt++
				sleepWithContext(ctx, delay)
			}
			continue
		}
		conn.SetAuthenticated()
		attempt = 0
		metricActiveTransportName.Store(conn.TransportName())
		log.Printf("[agent] connected to VPS %s via %s - all local services are online and protected!", targetGW, conn.TransportName())
		if ag.lastConnectedGW != "" && ag.lastConnectedGW != targetGW {
			log.Printf("[agent] failed over from %s to new gateway %s - resetting stale gateway session state", ag.lastConnectedGW, targetGW)
			ag.closeAllSessionsForFailover()
		} else {
			ag.resumeActiveSessions(conn)
		}
		ag.lastConnectedGW = targetGW
		ag.acceptGatewayStreams(ctx, conn)
		if ctx.Err() != nil {
			_ = conn.CloseWithError(0, "agent shutting down")
			return nil
		}
		if len(ag.gatewayAddrs) > 1 {
			// Immediately advance to the next gateway in the HA pool without waiting on the dead node
			gwIdx++
			log.Printf("[agent] gateway %s disconnected - failing over immediately to %s...", targetGW, ag.gatewayAddrs[gwIdx%len(ag.gatewayAddrs)])
			continue
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
				if expired {
					us.releasePendingLocked()
				}
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

func (ag *Agent) sendAuth(ctx context.Context, conn TunnelConn) error {
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

func (ag *Agent) resumeActiveSessions(conn TunnelConn) {
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
			_ = u.replayPendingToStream(st)
			ag.readUDPFromGatewayStream(u, st)
		}(us)
	}
}

func (ag *Agent) acceptGatewayStreams(ctx context.Context, conn TunnelConn) {
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
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
			ag.mu.Unlock()
			if !exists && cmd == cmdNewConn {
				c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ag.targetHost, targetPort), 5*time.Second)
				if err != nil {
					_ = s.Close()
					return
				}
				ag.mu.Lock()
				if existing, raced := ag.sessions[sessID]; raced {
					ag.mu.Unlock()
					_ = c.Close()
					sess = existing
				} else {
					sess = newSession(sessID, targetPort, c, ag.maxBuf, ag.maxMem, nil)
					ag.sessions[sessID] = sess
					ag.mu.Unlock()
				}
			}
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

func (ag *Agent) handleUDPStream(sessID uint64, targetPort uint16, st TunnelStream) {
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
		ag.mu.Unlock()
		go ag.readFromLocalUDP(us)
	} else {
		ag.mu.Unlock()
		_ = us.replayPendingToStream(st)
	}

	ag.readUDPFromGatewayStream(us, st)
}

func (ag *Agent) readUDPFromGatewayStream(us *agentUDPSession, st TunnelStream) {
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
		lc := us.localConn
		us.mu.Unlock()
		if lc != nil {
			_, _ = lc.Write(pkt)
		}
	}
}

func (ag *Agent) readFromLocalUDP(us *agentUDPSession) {
	bufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufPtr)
	buf := *bufPtr
	for {
		n, err := us.localConn.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		us.mu.Lock()
		us.lastActive = time.Now()
		st := us.stream
		if st == nil {
			us.enqueuePacketLocked(pkt)
			us.mu.Unlock()
			continue
		}
		us.mu.Unlock()
		if err := writeUDPPacket(st, pkt); err != nil {
			us.mu.Lock()
			if us.stream == st {
				_ = us.stream.Close()
				us.stream = nil
			}
			us.enqueuePacketLocked(pkt)
			us.mu.Unlock()
		}
	}
}

