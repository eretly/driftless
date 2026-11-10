package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	muxFrameWindowUpdate = uint8(6)
	maxMuxStreamWindow   = 4 * 1024 * 1024  // 4 MiB per-stream flow-control window
	maxMuxConnBuffer     = 32 * 1024 * 1024 // 32 MiB max buffered bytes per tcpMuxConn
	maxGlobalMuxBuffer   = 64 * 1024 * 1024 // 64 MiB max buffered bytes across all tcpMuxConns
	maxMuxActiveStreams  = 4096
	maxPreAuthMuxStreams = 1
	maxPreAuthMuxBuffer  = 8 * 1024
)

var globalMuxBufferedBytes atomic.Int64

// ==================== MODULAR TRANSPORT & STREAM MULTIPLEXER ====================

type TunnelStream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type TunnelConn interface {
	OpenStreamSync(context.Context) (TunnelStream, error)
	AcceptStream(context.Context) (TunnelStream, error)
	RemoteAddr() net.Addr
	CloseWithError(uint64, string) error
	TransportName() string
	SetAuthenticated()
	PeerCertHash() []byte
}

type quicTunnelConn struct {
	conn quic.Connection
}

func (q *quicTunnelConn) OpenStreamSync(ctx context.Context) (TunnelStream, error) {
	return q.conn.OpenStreamSync(ctx)
}

func (q *quicTunnelConn) AcceptStream(ctx context.Context) (TunnelStream, error) {
	return q.conn.AcceptStream(ctx)
}

func (q *quicTunnelConn) RemoteAddr() net.Addr {
	return q.conn.RemoteAddr()
}

func (q *quicTunnelConn) CloseWithError(code uint64, reason string) error {
	return q.conn.CloseWithError(quic.ApplicationErrorCode(code), reason)
}

func (q *quicTunnelConn) TransportName() string {
	return "quic"
}

func (q *quicTunnelConn) SetAuthenticated() {}

func (q *quicTunnelConn) PeerCertHash() []byte {
	cs := q.conn.ConnectionState().TLS
	if len(cs.PeerCertificates) > 0 && len(cs.PeerCertificates[0].Raw) > 0 {
		sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
		return sum[:]
	}
	return nil
}

// tcpMuxConn multiplexes multiple independent full-duplex streams over a single TLS/TCP connection
// when UDP/QUIC is blocked by corporate firewalls or strict NATs.
type tcpMuxConn struct {
	conn          net.Conn
	writeMu       sync.Mutex
	mu            sync.Mutex
	streams       map[uint32]*tcpMuxStream
	nextID        uint32
	acceptCh      chan TunnelStream
	closed        bool
	closeOnce     sync.Once
	closedCh      chan struct{}
	lastActive    atomic.Int64
	authenticated atomic.Bool
	bufferedBytes atomic.Int64
}

type tcpMuxStream struct {
	id            uint32
	parent        *tcpMuxConn
	mu            sync.Mutex
	cond          *sync.Cond
	inBuf         []byte
	sendWindow    int64
	recvCredit    int64
	remoteClosed  bool
	localClosed   bool
	readDeadline  time.Time
	writeDeadline time.Time
}

func newTCPMuxConn(c net.Conn, isClient bool, keepalive, idleTimeout time.Duration) *tcpMuxConn {
	tuneTCPSocket(c)
	startID := uint32(2)
	if isClient {
		startID = 1
	}
	mc := &tcpMuxConn{
		conn:     c,
		streams:  make(map[uint32]*tcpMuxStream),
		nextID:   startID,
		acceptCh: make(chan TunnelStream, 256),
		closedCh: make(chan struct{}),
	}
	if isClient {
		mc.authenticated.Store(true)
	}
	mc.lastActive.Store(time.Now().UnixNano())
	go mc.readLoop()
	if keepalive > 0 || idleTimeout > 0 {
		go mc.keepaliveLoop(keepalive, idleTimeout)
	}
	return mc
}

func (mc *tcpMuxConn) SetAuthenticated() {
	mc.authenticated.Store(true)
}

func (mc *tcpMuxConn) reserveMuxBytes(n int64) bool {
	if n <= 0 {
		return true
	}
	connLimit := int64(maxMuxConnBuffer)
	if !mc.authenticated.Load() {
		connLimit = maxPreAuthMuxBuffer
	}
	for {
		cur := mc.bufferedBytes.Load()
		if cur+n > connLimit {
			return false
		}
		if mc.bufferedBytes.CompareAndSwap(cur, cur+n) {
			break
		}
	}
	for {
		gcur := globalMuxBufferedBytes.Load()
		if gcur+n > maxGlobalMuxBuffer {
			mc.bufferedBytes.Add(-n)
			return false
		}
		if globalMuxBufferedBytes.CompareAndSwap(gcur, gcur+n) {
			return true
		}
	}
}

func (mc *tcpMuxConn) releaseMuxBytes(n int64) {
	if n <= 0 {
		return
	}
	mc.bufferedBytes.Add(-n)
	globalMuxBufferedBytes.Add(-n)
}

func (mc *tcpMuxConn) TransportName() string {
	return "tcp-mux"
}

func (mc *tcpMuxConn) PeerCertHash() []byte {
	if tlsC, ok := mc.conn.(*tls.Conn); ok {
		cs := tlsC.ConnectionState()
		if len(cs.PeerCertificates) > 0 && len(cs.PeerCertificates[0].Raw) > 0 {
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			return sum[:]
		}
		if len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0 {
			sum := sha256.Sum256(cs.VerifiedChains[0][0].Raw)
			return sum[:]
		}
	}
	return nil
}

func (mc *tcpMuxConn) RemoteAddr() net.Addr {
	return mc.conn.RemoteAddr()
}

func (mc *tcpMuxConn) writeFrame(fType uint8, streamID uint32, payload []byte) error {
	mc.writeMu.Lock()
	defer mc.writeMu.Unlock()
	select {
	case <-mc.closedCh:
		return net.ErrClosed
	default:
	}
	var hdr [9]byte
	hdr[0] = fType
	binary.BigEndian.PutUint32(hdr[1:5], streamID)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	_ = mc.conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	if _, err := mc.conn.Write(hdr[:]); err != nil {
		_ = mc.conn.SetWriteDeadline(time.Time{})
		return err
	}
	if len(payload) > 0 {
		if _, err := mc.conn.Write(payload); err != nil {
			_ = mc.conn.SetWriteDeadline(time.Time{})
			return err
		}
	}
	_ = mc.conn.SetWriteDeadline(time.Time{})
	return nil
}

func (mc *tcpMuxConn) writeWindowUpdate(streamID uint32, delta uint32) error {
	if delta == 0 {
		return nil
	}
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], delta)
	return mc.writeFrame(muxFrameWindowUpdate, streamID, buf[:])
}

func (mc *tcpMuxConn) OpenStreamSync(ctx context.Context) (TunnelStream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-mc.closedCh:
		return nil, net.ErrClosed
	default:
	}
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return nil, net.ErrClosed
	}
	if len(mc.streams) >= maxMuxActiveStreams {
		mc.mu.Unlock()
		return nil, errors.New("tcp-mux: max active streams reached")
	}
	id := mc.nextID
	mc.nextID += 2
	st := &tcpMuxStream{
		id:         id,
		parent:     mc,
		sendWindow: maxMuxStreamWindow,
	}
	st.cond = sync.NewCond(&st.mu)
	mc.streams[id] = st
	mc.mu.Unlock()

	if err := mc.writeFrame(muxFrameOpen, id, nil); err != nil {
		mc.mu.Lock()
		delete(mc.streams, id)
		mc.mu.Unlock()
		return nil, err
	}
	return st, nil
}

func (mc *tcpMuxConn) AcceptStream(ctx context.Context) (TunnelStream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-mc.closedCh:
		return nil, net.ErrClosed
	case st, ok := <-mc.acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return st, nil
	}
}

func (mc *tcpMuxConn) CloseWithError(_ uint64, _ string) error {
	mc.closeOnce.Do(func() {
		mc.mu.Lock()
		mc.closed = true
		var totalFreed int64
		for _, st := range mc.streams {
			st.mu.Lock()
			totalFreed += int64(len(st.inBuf))
			st.inBuf = nil
			st.remoteClosed = true
			st.localClosed = true
			st.cond.Broadcast()
			st.mu.Unlock()
		}
		mc.streams = make(map[uint32]*tcpMuxStream)
		mc.mu.Unlock()
		if totalFreed > 0 {
			mc.releaseMuxBytes(totalFreed)
		}
		close(mc.closedCh)
		_ = mc.conn.Close()
	})
	return nil
}

func (mc *tcpMuxConn) keepaliveLoop(keepalive, idleTimeout time.Duration) {
	if keepalive <= 0 {
		keepalive = 2 * time.Second
	}
	if idleTimeout <= 0 {
		idleTimeout = 10 * time.Second
	}
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()
	for {
		select {
		case <-mc.closedCh:
			return
		case <-ticker.C:
			last := time.Unix(0, mc.lastActive.Load())
			if time.Since(last) > idleTimeout {
				_ = mc.CloseWithError(1, "mux idle timeout")
				return
			}
			if err := mc.writeFrame(muxFramePing, 0, nil); err != nil {
				_ = mc.CloseWithError(1, "mux ping error")
				return
			}
		}
	}
}

func (mc *tcpMuxConn) readLoop() {
	defer func() {
		_ = mc.CloseWithError(0, "eof")
	}()
	var hdr [9]byte
	for {
		if _, err := io.ReadFull(mc.conn, hdr[:]); err != nil {
			return
		}
		mc.lastActive.Store(time.Now().UnixNano())
		fType := hdr[0]
		streamID := binary.BigEndian.Uint32(hdr[1:5])
		length := binary.BigEndian.Uint32(hdr[5:9])
		maxFrame := uint32(maxChunkSize * 4)
		if !mc.authenticated.Load() {
			maxFrame = maxPreAuthMuxBuffer
		}
		if length > maxFrame {
			_ = mc.CloseWithError(1, "mux frame exceeds limit")
			return
		}
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(mc.conn, payload); err != nil {
				return
			}
		}
		switch fType {
		case muxFrameOpen:
			mc.mu.Lock()
			if mc.closed {
				mc.mu.Unlock()
				return
			}
			maxAllowedStreams := maxMuxActiveStreams
			if !mc.authenticated.Load() {
				maxAllowedStreams = maxPreAuthMuxStreams
			}
			st, exists := mc.streams[streamID]
			if !exists {
				if len(mc.streams) >= maxAllowedStreams {
					mc.mu.Unlock()
					_ = mc.CloseWithError(1, "mux stream limit exceeded")
					return
				}
				st = &tcpMuxStream{
					id:         streamID,
					parent:     mc,
					sendWindow: maxMuxStreamWindow,
				}
				st.cond = sync.NewCond(&st.mu)
				mc.streams[streamID] = st
			}
			mc.mu.Unlock()
			if !exists {
				// Non-blocking enqueue so readLoop never deadlocks if acceptCh is full
				select {
				case mc.acceptCh <- st:
				case <-mc.closedCh:
					return
				default:
					mc.mu.Lock()
					delete(mc.streams, streamID)
					mc.mu.Unlock()
					_ = mc.writeFrame(muxFrameClose, streamID, nil)
				}
			}
		case muxFrameData:
			mc.mu.Lock()
			st, exists := mc.streams[streamID]
			mc.mu.Unlock()
			if exists && len(payload) > 0 {
				st.mu.Lock()
				if !st.remoteClosed && !st.localClosed {
					if len(st.inBuf)+len(payload) <= maxMuxStreamWindow*2 && mc.reserveMuxBytes(int64(len(payload))) {
						st.inBuf = append(st.inBuf, payload...)
						st.cond.Broadcast()
					} else {
						st.remoteClosed = true
						st.cond.Broadcast()
						st.mu.Unlock()
						_ = mc.writeFrame(muxFrameClose, streamID, nil)
						continue
					}
				}
				st.mu.Unlock()
			}
		case muxFrameWindowUpdate:
			if len(payload) == 4 {
				delta := binary.BigEndian.Uint32(payload)
				mc.mu.Lock()
				st := mc.streams[streamID]
				mc.mu.Unlock()
				if st != nil && delta > 0 {
					st.mu.Lock()
					st.sendWindow += int64(delta)
					st.cond.Broadcast()
					st.mu.Unlock()
				}
			}
		case muxFrameClose:
			mc.mu.Lock()
			st, exists := mc.streams[streamID]
			if exists {
				delete(mc.streams, streamID)
			}
			mc.mu.Unlock()
			if exists {
				st.mu.Lock()
				st.remoteClosed = true
				st.cond.Broadcast()
				st.mu.Unlock()
			}
		case muxFramePing:
			_ = mc.writeFrame(muxFramePong, 0, nil)
		case muxFramePong:
		}
	}
}

func (s *tcpMuxStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	for len(s.inBuf) == 0 && !s.remoteClosed && !s.localClosed {
		if !s.readDeadline.IsZero() {
			rem := time.Until(s.readDeadline)
			if rem <= 0 {
				s.mu.Unlock()
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.AfterFunc(rem, func() {
				s.mu.Lock()
				s.cond.Broadcast()
				s.mu.Unlock()
			})
			s.cond.Wait()
			timer.Stop()
			if len(s.inBuf) == 0 && !s.remoteClosed && !s.localClosed && time.Now().After(s.readDeadline) {
				s.mu.Unlock()
				return 0, os.ErrDeadlineExceeded
			}
		} else {
			s.cond.Wait()
		}
	}
	if len(s.inBuf) > 0 {
		n := copy(p, s.inBuf)
		s.inBuf = s.inBuf[n:]
		if len(s.inBuf) == 0 {
			s.inBuf = nil
		}
		s.recvCredit += int64(n)
		var sendDelta uint32
		if s.recvCredit >= maxMuxStreamWindow/4 {
			sendDelta = uint32(s.recvCredit)
			s.recvCredit = 0
		}
		s.mu.Unlock()
		s.parent.releaseMuxBytes(int64(n))
		if sendDelta > 0 {
			_ = s.parent.writeWindowUpdate(s.id, sendDelta)
		}
		return n, nil
	}
	s.mu.Unlock()
	return 0, io.EOF
}

func (s *tcpMuxStream) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		s.mu.Lock()
		for s.sendWindow <= 0 && !s.localClosed && !s.remoteClosed {
			if !s.writeDeadline.IsZero() {
				rem := time.Until(s.writeDeadline)
				if rem <= 0 {
					s.mu.Unlock()
					return total, os.ErrDeadlineExceeded
				}
				timer := time.AfterFunc(rem, func() {
					s.mu.Lock()
					s.cond.Broadcast()
					s.mu.Unlock()
				})
				s.cond.Wait()
				timer.Stop()
				if s.sendWindow <= 0 && time.Now().After(s.writeDeadline) {
					s.mu.Unlock()
					return total, os.ErrDeadlineExceeded
				}
			} else {
				s.cond.Wait()
			}
		}
		if s.localClosed {
			s.mu.Unlock()
			return total, net.ErrClosed
		}
		if !s.writeDeadline.IsZero() && time.Now().After(s.writeDeadline) {
			s.mu.Unlock()
			return total, os.ErrDeadlineExceeded
		}
		chunk := len(p) - total
		if chunk > maxChunkSize {
			chunk = maxChunkSize
		}
		if s.sendWindow > 0 && int64(chunk) > s.sendWindow {
			chunk = int(s.sendWindow)
		}
		s.sendWindow -= int64(chunk)
		s.mu.Unlock()

		if err := s.parent.writeFrame(muxFrameData, s.id, p[total:total+chunk]); err != nil {
			return total, err
		}
		total += chunk
	}
	return total, nil
}

func (s *tcpMuxStream) Close() error {
	s.mu.Lock()
	if s.localClosed {
		s.mu.Unlock()
		return nil
	}
	s.localClosed = true
	freed := int64(len(s.inBuf))
	s.inBuf = nil
	s.cond.Broadcast()
	s.mu.Unlock()

	if freed > 0 {
		s.parent.releaseMuxBytes(freed)
	}

	s.parent.mu.Lock()
	delete(s.parent.streams, s.id)
	s.parent.mu.Unlock()

	_ = s.parent.writeFrame(muxFrameClose, s.id, nil)
	return nil
}

func (s *tcpMuxStream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.cond.Broadcast()
	s.mu.Unlock()
	return nil
}

func (s *tcpMuxStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.mu.Unlock()
	return nil
}

func dialTunnelGateway(ctx context.Context, addr, mode string, tlsConf *tls.Config, quicConf *quic.Config) (TunnelConn, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "auto"
	}
	if mode == "quic" || mode == "auto" {
		qCtx := ctx
		var cancel context.CancelFunc
		if mode == "auto" {
			qCtx, cancel = context.WithTimeout(ctx, 2500*time.Millisecond)
		}
		qConn, err := quic.DialAddr(qCtx, addr, tlsConf, quicConf)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return &quicTunnelConn{conn: qConn}, nil
		}
		if mode == "quic" {
			return nil, err
		}
	}
	// TCP-Mux fallback (or explicit -transport tcp)
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tuneTCPSocket(rawConn)
	tlsConn := tls.Client(rawConn, tlsConf)
	_ = tlsConn.SetDeadline(time.Now().Add(4 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return newTCPMuxConn(tlsConn, true, quicConf.KeepAlivePeriod, quicConf.MaxIdleTimeout), nil
}
