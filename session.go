package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Session struct {
	id         uint64
	nodeID     string
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
	activeStream TunnelStream
	streamGen    uint64
	lastActive   time.Time
	writeMutex   sync.Mutex
}

func tuneTCPSocket(c net.Conn) {
	for c != nil {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(30 * time.Second)
			return
		}
		if pc, ok := c.(*peekedConn); ok {
			c = pc.Conn
			continue
		}
		break
	}
}

// isTransientUDPReadError returns true when a connected UDP socket receives an ICMP Port Unreachable
// notification (ECONNREFUSED on Linux/macOS, WSAECONNREFUSED / WSAECONNRESET on Windows) while a
// local UDP game/voice server is restarting. Ignoring this error keeps the UDP session alive 24/7.
func isTransientUDPReadError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "forcibly closed")
}

// tryReserveGlobalMemory atomically reserves delta bytes against maxGlobal so concurrent
// TCP sessions can never overshoot the process-wide -max-mem limit.
func tryReserveGlobalMemory(delta, maxGlobal int64) bool {
	if delta <= 0 {
		return true
	}
	for {
		cur := globalBufferedBytes.Load()
		if maxGlobal > 0 && cur+delta > maxGlobal {
			return false
		}
		if globalBufferedBytes.CompareAndSwap(cur, cur+delta) {
			return true
		}
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
		initLen := int64(len(initialOutData))
		if initLen <= maxBuf && tryReserveGlobalMemory(initLen, maxGlobal) {
			s.outBuf = append(s.outBuf, initialOutData...)
		} else {
			_ = conn.Close()
			s.closed = true
			s.cond = sync.NewCond(&s.mu)
			return s
		}
	}
	metricActiveTCPSessions.Add(1)
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
	bufPtr := chunkBufPool.Get().(*[]byte)
	defer chunkBufPool.Put(bufPtr)
	buf := (*bufPtr)[:maxChunkSize]
	for {
		s.mu.Lock()
		for !s.closed && (int64(len(s.outBuf)-s.outBase) >= s.maxBuf || (s.maxGlobal > 0 && globalBufferedBytes.Load() >= s.maxGlobal)) {
			s.cond.Wait()
		}
		if s.closed {
			s.mu.Unlock()
			return
		}
		remSession := s.maxBuf - int64(len(s.outBuf)-s.outBase)
		readLimit := maxChunkSize
		if remSession > 0 && remSession < int64(readLimit) {
			readLimit = int(remSession)
		}
		s.mu.Unlock()

		n, err := s.tcpConn.Read(buf[:readLimit])
		if n > 0 {
			s.mu.Lock()
			s.lastActive = time.Now()
			for !s.closed && (int64(len(s.outBuf)-s.outBase)+int64(n) > s.maxBuf || !tryReserveGlobalMemory(int64(n), s.maxGlobal)) {
				s.cond.Wait()
			}
			if s.closed {
				s.mu.Unlock()
				return
			}
			s.outBuf = append(s.outBuf, buf[:n]...)
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

func (s *Session) snapshotStatus() (closed bool, lastActive time.Time) {
	s.mu.Lock()
	closed = s.closed
	lastActive = s.lastActive
	s.mu.Unlock()
	return closed, lastActive
}

func (s *Session) closeSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		metricActiveTCPSessions.Add(-1)
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

func bridgeSessionStream(s *Session, stream TunnelStream) {
	s.writeMutex.Lock()
	s.mu.Lock()
	if s.activeStream != nil {
		_ = s.activeStream.Close()
	}
	s.streamGen++
	myGen := s.streamGen
	if myGen > 1 {
		metricResumedSessions.Add(1)
	}
	s.activeStream = stream
	myInOffset := s.inOffset
	s.lastActive = time.Now()
	s.cond.Broadcast()
	s.mu.Unlock()
	s.writeMutex.Unlock()

	defer func() {
		_ = stream.Close()
		s.mu.Lock()
		if s.activeStream == stream {
			s.activeStream = nil
		}
		s.cond.Broadcast()
		s.mu.Unlock()
	}()

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
	maxValidOffset := s.baseOffset + uint64(len(s.outBuf)-s.outBase)
	if peerAckedOffset < s.baseOffset || peerAckedOffset > maxValidOffset {
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
		// Reusable pooled frame buffer: 1 byte type + 4 bytes length + maxChunkSize payload
		frameBufPtr := chunkBufPool.Get().(*[]byte)
		defer chunkBufPool.Put(frameBufPtr)
		frameBuf := *frameBufPtr

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

	br := bufio.NewReaderSize(stream, maxChunkSize*2)
	var fType [1]byte
	var lenBuf [4]byte
	var ackBuf [8]byte
	payloadBuf := make([]byte, maxChunkSize)
	lastAckedOffset := myInOffset

	for {
		if _, err := io.ReadFull(br, fType[:]); err != nil {
			return
		}
		switch fType[0] {
		case frameData:
			if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
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
			if _, err := io.ReadFull(br, payloadBuf[:length]); err != nil {
				return
			}

			s.writeMutex.Lock()
			s.mu.Lock()
			if s.closed || s.streamGen != myGen {
				s.mu.Unlock()
				s.writeMutex.Unlock()
				return
			}
			s.mu.Unlock()
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

			// Smart ACK coalescing: immediate ACK when buffer drains (0ms interactive latency)
			// or every 256 KiB during continuous bulk streaming (8x fewer ACK frames).
			if written > 0 && (newInOffset-lastAckedOffset >= 256*1024 || br.Buffered() == 0 || wErr != nil) {
				var ackFrame [9]byte
				ackFrame[0] = frameAck
				binary.BigEndian.PutUint64(ackFrame[1:9], newInOffset)
				_ = sendFrame(ackFrame[:])
				lastAckedOffset = newInOffset
			}
			if wErr != nil {
				s.closeSession()
				return
			}

		case frameAck:
			if _, err := io.ReadFull(br, ackBuf[:]); err != nil {
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
			closeWriteSide(s.tcpConn)
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

// formatProxyProtoV1 formats a HAProxy PROXY protocol v1 header so backend services
// (Nginx, Caddy, Minecraft/BungeeCord) can see the real public client IP.
func formatProxyProtoV1(clientAddr, localAddr net.Addr) []byte {
	cTCP, ok1 := clientAddr.(*net.TCPAddr)
	lTCP, ok2 := localAddr.(*net.TCPAddr)
	if !ok1 || !ok2 || cTCP == nil || lTCP == nil {
		return []byte("PROXY UNKNOWN\r\n")
	}
	proto := "TCP4"
	srcIP := cTCP.IP.String()
	dstIP := lTCP.IP.String()
	if cTCP.IP.To4() == nil {
		proto = "TCP6"
		if lTCP.IP.To4() != nil {
			dstIP = "::ffff:" + lTCP.IP.String()
		}
	}
	return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", proto, srcIP, dstIP, cTCP.Port, lTCP.Port))
}

const (
	maxUDPBufferedPkts      = 1024
	maxPerSessionUDPBytes   = 4 * 1024 * 1024  // 4 MiB max buffered UDP datagrams per session
	maxGlobalUDPBufferBytes = 64 * 1024 * 1024 // 64 MiB max buffered UDP datagrams across process
	maxGatewayUDPSessions   = 4096
	maxUDPSessionsPerIP     = 64
)

var globalUDPBufferedBytes atomic.Int64

// tryReserveGlobalUDPMemory atomically reserves delta bytes against maxGlobalUDPBufferBytes
// using a compare-and-swap loop so concurrent UDP sessions can never exceed the global 64 MiB cap.
func tryReserveGlobalUDPMemory(delta, maxGlobal int64) bool {
	if delta <= 0 {
		return true
	}
	for {
		cur := globalUDPBufferedBytes.Load()
		if maxGlobal > 0 && cur+delta > maxGlobal {
			return false
		}
		if globalUDPBufferedBytes.CompareAndSwap(cur, cur+delta) {
			return true
		}
	}
}

const maxUDPReplayAge = 2 * time.Second

type gwUDPSession struct {
	id          uint64
	nodeID      string
	targetPort  uint16
	clientAddr  *net.UDPAddr
	pubConn     *net.UDPConn
	mu          sync.Mutex
	stream      TunnelStream
	pendingPkts [][]byte
	pendingAt   []time.Time
	queuedBytes int64
	lastActive  time.Time
	dialing     atomic.Bool
}

func (us *gwUDPSession) dropOldestPendingLocked() {
	if len(us.pendingPkts) == 0 {
		return
	}
	droppedLen := int64(len(us.pendingPkts[0]))
	us.pendingPkts[0] = nil
	us.pendingPkts = us.pendingPkts[1:]
	if len(us.pendingAt) > 0 {
		us.pendingAt = us.pendingAt[1:]
	}
	us.queuedBytes -= droppedLen
	globalUDPBufferedBytes.Add(-droppedLen)
	metricUDPDroppedTotal.Add(1)
}

func (us *gwUDPSession) enqueuePacketLocked(pkt []byte) {
	pktLen := int64(len(pkt))
	if pktLen > maxPerSessionUDPBytes {
		metricUDPDroppedTotal.Add(1)
		return
	}
	now := time.Now()
	for len(us.pendingPkts) > 0 && len(us.pendingAt) > 0 && now.Sub(us.pendingAt[0]) > maxUDPReplayAge {
		us.dropOldestPendingLocked()
	}
	cp := append([]byte(nil), pkt...)
	metricUDPQueuedTotal.Add(1)
	for len(us.pendingPkts) > 0 && (len(us.pendingPkts) >= maxUDPBufferedPkts || us.queuedBytes+pktLen > maxPerSessionUDPBytes) {
		us.dropOldestPendingLocked()
	}
	for !tryReserveGlobalUDPMemory(pktLen, maxGlobalUDPBufferBytes) {
		if len(us.pendingPkts) == 0 {
			metricUDPDroppedTotal.Add(1)
			return
		}
		us.dropOldestPendingLocked()
	}
	us.pendingPkts = append(us.pendingPkts, cp)
	us.pendingAt = append(us.pendingAt, now)
	us.queuedBytes += pktLen
}

// detachPendingForReplayLocked detaches fresh queued packets (<= maxUDPReplayAge) for stream replay
// while immediately releasing stale packets so outdated datagrams are never replayed after a long outage.
func (us *gwUDPSession) detachPendingForReplayLocked() [][]byte {
	if len(us.pendingPkts) == 0 {
		return nil
	}
	now := time.Now()
	rawPkts := us.pendingPkts
	rawAt := us.pendingAt
	us.pendingPkts = nil
	us.pendingAt = nil
	us.queuedBytes = 0

	out := make([][]byte, 0, len(rawPkts))
	for i, pkt := range rawPkts {
		rawPkts[i] = nil
		if pkt == nil {
			continue
		}
		if i < len(rawAt) && !rawAt[i].IsZero() && now.Sub(rawAt[i]) > maxUDPReplayAge {
			globalUDPBufferedBytes.Add(-int64(len(pkt)))
			metricUDPDroppedTotal.Add(1)
			continue
		}
		out = append(out, pkt)
	}
	return out
}

func (us *gwUDPSession) restoreUnsentReplayLocked(unsent [][]byte) {
	if len(unsent) == 0 {
		return
	}
	now := time.Now()
	combined := make([][]byte, 0, len(unsent)+len(us.pendingPkts))
	combinedAt := make([]time.Time, 0, len(unsent)+len(us.pendingPkts))
	var addedBytes int64
	for i, pkt := range unsent {
		unsent[i] = nil
		if pkt != nil {
			combined = append(combined, pkt)
			combinedAt = append(combinedAt, now)
			addedBytes += int64(len(pkt))
		}
	}
	for i, pkt := range us.pendingPkts {
		us.pendingPkts[i] = nil
		if pkt != nil {
			combined = append(combined, pkt)
			if i < len(us.pendingAt) {
				combinedAt = append(combinedAt, us.pendingAt[i])
			} else {
				combinedAt = append(combinedAt, now)
			}
		}
	}
	us.pendingPkts = combined
	us.pendingAt = combinedAt
	us.queuedBytes += addedBytes
	for len(us.pendingPkts) > 0 && (len(us.pendingPkts) > maxUDPBufferedPkts || us.queuedBytes > maxPerSessionUDPBytes) {
		us.dropOldestPendingLocked()
	}
}

// replayPendingToStream attaches st to the session and writes all queued packets while holding
// their globalUDPBufferedBytes reservation until each packet leaves memory and its slice slot is nilled.
func (us *gwUDPSession) replayPendingToStream(st TunnelStream) error {
	us.mu.Lock()
	if us.stream != nil && us.stream != st {
		_ = us.stream.Close()
	}
	us.stream = st
	us.lastActive = time.Now()
	queued := us.detachPendingForReplayLocked()
	us.mu.Unlock()

	for idx, qPkt := range queued {
		if err := writeUDPPacket(st, qPkt); err != nil {
			us.mu.Lock()
			us.restoreUnsentReplayLocked(queued[idx:])
			us.mu.Unlock()
			return err
		}
		pktLen := int64(len(qPkt))
		queued[idx] = nil
		globalUDPBufferedBytes.Add(-pktLen)
		metricUDPReplayedTotal.Add(1)
	}
	return nil
}

func (us *gwUDPSession) releasePendingLocked() {
	for i := range us.pendingPkts {
		us.pendingPkts[i] = nil
	}
	if us.queuedBytes > 0 {
		globalUDPBufferedBytes.Add(-us.queuedBytes)
		us.queuedBytes = 0
	}
	us.pendingPkts = nil
	us.pendingAt = nil
}

// writeUDPPacket uses udpFramePool to combine the 2-byte length header and payload into a single
// write with zero heap allocations on the hot UDP forwarding path.
func writeUDPPacket(w io.Writer, payload []byte) error {
	if len(payload) > maxUDPPacket {
		return errors.New("udp packet too large")
	}
	need := 2 + len(payload)
	bufPtr := udpFramePool.Get().(*[]byte)
	buf := *bufPtr
	if need <= len(buf) {
		binary.BigEndian.PutUint16(buf[0:2], uint16(len(payload)))
		copy(buf[2:need], payload)
		total := 0
		for total < need {
			n, err := w.Write(buf[total:need])
			if n > 0 {
				total += n
			}
			if err != nil {
				udpFramePool.Put(bufPtr)
				return err
			}
		}
		udpFramePool.Put(bufPtr)
		return nil
	}
	udpFramePool.Put(bufPtr)
	frame := make([]byte, need)
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

type agentUDPSession struct {
	id          uint64
	targetPort  uint16
	localConn   net.Conn
	mu          sync.Mutex
	stream      TunnelStream
	pendingPkts [][]byte
	pendingAt   []time.Time
	queuedBytes int64
	lastActive  time.Time
}

func (u *agentUDPSession) dropOldestPendingLocked() {
	if len(u.pendingPkts) == 0 {
		return
	}
	droppedLen := int64(len(u.pendingPkts[0]))
	u.pendingPkts[0] = nil
	u.pendingPkts = u.pendingPkts[1:]
	if len(u.pendingAt) > 0 {
		u.pendingAt = u.pendingAt[1:]
	}
	u.queuedBytes -= droppedLen
	globalUDPBufferedBytes.Add(-droppedLen)
	metricUDPDroppedTotal.Add(1)
}

func (u *agentUDPSession) enqueuePacketLocked(pkt []byte) {
	pktLen := int64(len(pkt))
	if pktLen > maxPerSessionUDPBytes {
		metricUDPDroppedTotal.Add(1)
		return
	}
	now := time.Now()
	for len(u.pendingPkts) > 0 && len(u.pendingAt) > 0 && now.Sub(u.pendingAt[0]) > maxUDPReplayAge {
		u.dropOldestPendingLocked()
	}
	cp := append([]byte(nil), pkt...)
	metricUDPQueuedTotal.Add(1)
	for len(u.pendingPkts) > 0 && (len(u.pendingPkts) >= maxUDPBufferedPkts || u.queuedBytes+pktLen > maxPerSessionUDPBytes) {
		u.dropOldestPendingLocked()
	}
	for !tryReserveGlobalUDPMemory(pktLen, maxGlobalUDPBufferBytes) {
		if len(u.pendingPkts) == 0 {
			metricUDPDroppedTotal.Add(1)
			return
		}
		u.dropOldestPendingLocked()
	}
	u.pendingPkts = append(u.pendingPkts, cp)
	u.pendingAt = append(u.pendingAt, now)
	u.queuedBytes += pktLen
}

func (u *agentUDPSession) detachPendingForReplayLocked() [][]byte {
	if len(u.pendingPkts) == 0 {
		return nil
	}
	now := time.Now()
	rawPkts := u.pendingPkts
	rawAt := u.pendingAt
	u.pendingPkts = nil
	u.pendingAt = nil
	u.queuedBytes = 0

	out := make([][]byte, 0, len(rawPkts))
	for i, pkt := range rawPkts {
		rawPkts[i] = nil
		if pkt == nil {
			continue
		}
		if i < len(rawAt) && !rawAt[i].IsZero() && now.Sub(rawAt[i]) > maxUDPReplayAge {
			globalUDPBufferedBytes.Add(-int64(len(pkt)))
			metricUDPDroppedTotal.Add(1)
			continue
		}
		out = append(out, pkt)
	}
	return out
}

func (u *agentUDPSession) restoreUnsentReplayLocked(unsent [][]byte) {
	if len(unsent) == 0 {
		return
	}
	now := time.Now()
	combined := make([][]byte, 0, len(unsent)+len(u.pendingPkts))
	combinedAt := make([]time.Time, 0, len(unsent)+len(u.pendingPkts))
	var addedBytes int64
	for i, pkt := range unsent {
		unsent[i] = nil
		if pkt != nil {
			combined = append(combined, pkt)
			combinedAt = append(combinedAt, now)
			addedBytes += int64(len(pkt))
		}
	}
	for i, pkt := range u.pendingPkts {
		u.pendingPkts[i] = nil
		if pkt != nil {
			combined = append(combined, pkt)
			if i < len(u.pendingAt) {
				combinedAt = append(combinedAt, u.pendingAt[i])
			} else {
				combinedAt = append(combinedAt, now)
			}
		}
	}
	u.pendingPkts = combined
	u.pendingAt = combinedAt
	u.queuedBytes += addedBytes
	for len(u.pendingPkts) > 0 && (len(u.pendingPkts) > maxUDPBufferedPkts || u.queuedBytes > maxPerSessionUDPBytes) {
		u.dropOldestPendingLocked()
	}
}

func (u *agentUDPSession) replayPendingToStream(st TunnelStream) error {
	u.mu.Lock()
	if u.stream != nil && u.stream != st {
		_ = u.stream.Close()
	}
	u.stream = st
	u.lastActive = time.Now()
	queued := u.detachPendingForReplayLocked()
	u.mu.Unlock()

	for idx, qPkt := range queued {
		if err := writeUDPPacket(st, qPkt); err != nil {
			u.mu.Lock()
			u.restoreUnsentReplayLocked(queued[idx:])
			u.mu.Unlock()
			return err
		}
		pktLen := int64(len(qPkt))
		queued[idx] = nil
		globalUDPBufferedBytes.Add(-pktLen)
		metricUDPReplayedTotal.Add(1)
	}
	return nil
}

func (u *agentUDPSession) releasePendingLocked() {
	for i := range u.pendingPkts {
		u.pendingPkts[i] = nil
	}
	if u.queuedBytes > 0 {
		globalUDPBufferedBytes.Add(-u.queuedBytes)
		u.queuedBytes = 0
	}
	u.pendingPkts = nil
	u.pendingAt = nil
}
