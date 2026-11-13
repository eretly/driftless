package main

import (
	"bytes"
	"context"
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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	allocatedPortsMu sync.Mutex
	allocatedPorts   = make(map[string]bool)
)

func getFreePort(t *testing.T, network string) int {
	t.Helper()
	for attempt := 0; attempt < 64; attempt++ {
		var port int
		if network == "udp" {
			addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			l, err := net.ListenUDP("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			port = l.LocalAddr().(*net.UDPAddr).Port
			_ = l.Close()
		} else {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port = l.Addr().(*net.TCPAddr).Port
			_ = l.Close()
		}
		// A gateway binds UDP (QUIC) and TCP (TLS-mux) on the same numeric port, so a
		// port handed out for one protocol must be free for both, and the same number
		// must never be reused for a second listener inside this test binary.
		tcpKey := fmt.Sprintf("tcp:%d", port)
		udpKey := fmt.Sprintf("udp:%d", port)
		allocatedPortsMu.Lock()
		taken := allocatedPorts[tcpKey] || allocatedPorts[udpKey]
		if !taken {
			allocatedPorts[tcpKey] = true
			allocatedPorts[udpKey] = true
		}
		allocatedPortsMu.Unlock()
		if taken {
			continue
		}
		if !portBindable("tcp", port) || !portBindable("udp", port) {
			continue
		}
		return port
	}
	t.Fatalf("failed to allocate unique free %s port", network)
	return 0
}

// portBindable reports whether the numeric port can be bound for the given protocol
// right now. Both the wildcard and the loopback address are probed because Windows
// permits a specific-address bind alongside a wildcard bind, and a port still in
// TIME_WAIT (very common on busy CI machines) rejects a fresh listener even though
// the UDP probe that picked the number succeeded.
func portBindable(network string, port int) bool {
	if network == "tcp" {
		for _, host := range []string{"0.0.0.0", "127.0.0.1"} {
			l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				return false
			}
			_ = l.Close()
		}
		return true
	}
	for _, host := range []string{"0.0.0.0", "127.0.0.1"} {
		u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: port})
		if err != nil {
			return false
		}
		_ = u.Close()
	}
	return true
}

func waitForTCPListener(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for TCP listener at %s", addr)
}

// waitForTCPListenerOrGatewayExit waits until addr accepts TCP connections, but
// fails fast with the real startup error if runGateway returned before binding.
func waitForTCPListenerOrGatewayExit(t *testing.T, addr string, timeout time.Duration, gwErrCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		select {
		case gwErr := <-gwErrCh:
			t.Fatalf("gateway exited before TCP listener at %s became ready: %v", addr, gwErr)
		default:
		}
		time.Sleep(15 * time.Millisecond)
	}
	select {
	case gwErr := <-gwErrCh:
		t.Fatalf("gateway exited before TCP listener at %s became ready: %v", addr, gwErr)
	default:
	}
	t.Fatalf("timed out waiting for TCP listener at %s", addr)
}

func waitForTCPEchoReady(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	probe := []byte("ready-probe")
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			rem := time.Until(deadline)
			if rem > 1500*time.Millisecond {
				rem = 1500 * time.Millisecond
			}
			_ = c.SetDeadline(time.Now().Add(rem))
			_, wErr := c.Write(probe)
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			got, rErr := io.ReadAll(c)
			_ = c.Close()
			if wErr == nil && rErr == nil && bytes.Equal(got, probe) {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for end-to-end TCP tunnel readiness at %s", addr)
}

func TestEndToEndTCPUDPAndVHostWithAutoTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tcpTargetPort := getFreePort(t, "tcp")
	udpTargetPort := getFreePort(t, "udp")
	vhostTargetPort := getFreePort(t, "tcp")

	publicTCPPort := getFreePort(t, "tcp")
	publicUDPPort := getFreePort(t, "udp")
	vhostListenPort := getFreePort(t, "tcp")
	quicPort := getFreePort(t, "udp")

	// 1. Local TCP echo server
	tcpListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpTargetPort))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		for {
			c, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. Local UDP echo server (simulating game server / VoIP)
	udpAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", udpTargetPort))
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpConn.WriteToUDP(buf[:n], raddr)
		}
	}()

	// 3. Local HTTP backend for VHost routing
	vhostListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", vhostTargetPort))
	if err != nil {
		t.Fatal(err)
	}
	defer vhostListener.Close()
	go func() {
		for {
			c, err := vhostListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nvhost-ok!!"))
			}(c)
		}
	}()

	mappings := []PortMapping{
		{PublicPort: uint16(publicTCPPort), TargetPort: uint16(tcpTargetPort), Proto: "both"},
		{PublicPort: uint16(publicUDPPort), TargetPort: uint16(udpTargetPort), Proto: "udp"},
	}
	vhosts := map[string]uint16{
		"app.local": uint16(vhostTargetPort),
	}
	quicAddr := fmt.Sprintf("127.0.0.1:%d", quicPort)
	vhostAddr := fmt.Sprintf("127.0.0.1:%d", vhostListenPort)

	gwErrCh := make(chan error, 1)
	go func() {
		gwErrCh <- runGateway(ctx, quicAddr, "test-secret", "", vhostAddr, "", vhosts, mappings, 64*1024*1024, 4*1024*1024, 4*time.Second, 1*time.Second, 30*time.Second, "", "", "", false, false)
	}()

	waitForTCPListenerOrGatewayExit(t, quicAddr, 15*time.Second, gwErrCh)

	go func() {
		_ = runAgent(ctx, quicAddr, "127.0.0.1", "test-secret", "192.168.1.50", "", 4*1024*1024, 64*1024*1024, 4*time.Second, 1*time.Second, 30*time.Second, nil)
	}()

	waitForTCPEchoReady(t, fmt.Sprintf("127.0.0.1:%d", publicTCPPort), 5*time.Second)

	// Verify TCP
	clientTCP, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", publicTCPPort), 3*time.Second)
	if err != nil {
		t.Fatalf("tcp dial failed: %v", err)
	}
	defer clientTCP.Close()
	payload := make([]byte, 256*1024)
	_, _ = rand.Read(payload)
	go func() {
		_, _ = clientTCP.Write(payload)
		if tc, ok := clientTCP.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	gotTCP, err := io.ReadAll(clientTCP)
	if err != nil || !bytes.Equal(payload, gotTCP) {
		t.Fatalf("tcp mismatch: err=%v, len=%d", err, len(gotTCP))
	}

	// Verify UDP
	clientUDP, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", publicUDPPort))
	if err != nil {
		t.Fatalf("udp dial failed: %v", err)
	}
	defer clientUDP.Close()
	udpMsg := []byte("hello-udp-game-packet-12345")
	if _, err := clientUDP.Write(udpMsg); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	_ = clientUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
	udpReply := make([]byte, 128)
	n, err := clientUDP.Read(udpReply)
	if err != nil || !bytes.Equal(udpMsg, udpReply[:n]) {
		t.Fatalf("udp mismatch: err=%v, got=%q", err, string(udpReply[:n]))
	}

	// Verify Plain HTTP VHost Router
	vhostConn, err := net.DialTimeout("tcp", vhostAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("vhost dial: %v", err)
	}
	defer vhostConn.Close()
	_, _ = vhostConn.Write([]byte("GET / HTTP/1.1\r\nHost: app.local\r\nConnection: close\r\n\r\n"))
	vhostResp, err := io.ReadAll(vhostConn)
	if err != nil || !bytes.Contains(vhostResp, []byte("vhost-ok!!")) {
		t.Fatalf("vhost routing failed: err=%v, resp=%q", err, string(vhostResp))
	}

	// Verify Auto-TLS HTTPS on the exact same VHost port
	tlsConn, err := tls.Dial("tcp", vhostAddr, &tls.Config{
		ServerName:         "app.local",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("auto-tls vhost dial failed: %v", err)
	}
	defer tlsConn.Close()
	_, _ = tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: app.local\r\nConnection: close\r\n\r\n"))
	tlsResp, err := io.ReadAll(tlsConn)
	if err != nil || !bytes.Contains(tlsResp, []byte("vhost-ok!!")) {
		t.Fatalf("auto-tls vhost routing failed: err=%v, resp=%q", err, string(tlsResp))
	}
}

func TestSTUNTransactionIDAndStandaloneHalfClose(t *testing.T) {
	// 1. Test local RFC 5389 STUN responder with XOR-MAPPED-ADDRESS (0x0020) and Transaction ID check
	stunPort := getFreePort(t, "udp")
	stunAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", stunPort))
	stunServer, err := net.ListenUDP("udp", stunAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer stunServer.Close()

	go func() {
		buf := make([]byte, 256)
		n, raddr, err := stunServer.ReadFromUDP(buf)
		if err != nil || n < 20 {
			return
		}
		var resp [32]byte
		binary.BigEndian.PutUint16(resp[0:2], 0x0101) // Binding Success Response
		binary.BigEndian.PutUint16(resp[2:4], 12)     // Message Length: 12 bytes
		binary.BigEndian.PutUint32(resp[4:8], 0x2112A442)
		copy(resp[8:20], buf[8:20]) // Echo exact 12-byte Transaction ID

		// XOR-MAPPED-ADDRESS attribute (0x0020) for 203.0.113.45
		binary.BigEndian.PutUint16(resp[20:22], 0x0020)
		binary.BigEndian.PutUint16(resp[22:24], 8)
		resp[24] = 0x00
		resp[25] = 0x01 // IPv4
		binary.BigEndian.PutUint16(resp[26:28], 12345^0x2112)
		ip := [4]byte{203, 0, 113, 45}
		cookie := [4]byte{0x21, 0x12, 0xA4, 0x42}
		for i := 0; i < 4; i++ {
			resp[28+i] = ip[i] ^ cookie[i]
		}
		_, _ = stunServer.WriteToUDP(resp[:], raddr)
	}()

	gotIP, err := singleSTUNQuery(fmt.Sprintf("127.0.0.1:%d", stunPort), 500*time.Millisecond)
	if err != nil || gotIP != "203.0.113.45" {
		t.Fatalf("expected STUN IP 203.0.113.45, got %q (err=%v)", gotIP, err)
	}

	dom, tok := extractDuckFromText("https://www.duckdns.org/update?domains=myhomepc&token=abc-123-xyz&ip=")
	if dom != "myhomepc" || tok != "abc-123-xyz" {
		t.Fatalf("extractDuckFromText URL failed: dom=%q tok=%q", dom, tok)
	}
	if formatDuckDomain(dom) != "myhomepc.duckdns.org" {
		t.Fatalf("formatDuckDomain failed: %q", formatDuckDomain(dom))
	}
	if autoZeroConfigDomain("203.0.113.45") != "203-0-113-45.sslip.io" {
		t.Fatalf("autoZeroConfigDomain failed: %q", autoZeroConfigDomain("203.0.113.45"))
	}

	// Verify VHost path-prefix routing and wildcard subdomain matching
	vhMap, err := parseVHosts("site.com:3000,site.com/api:4000,*.sub.site.com:5000")
	if err != nil {
		t.Fatalf("parseVHosts failed: %v", err)
	}
	if port, ok := matchVHostTarget(vhMap, "site.com", "/api/v1/users"); !ok || port != 4000 {
		t.Fatalf("expected path route /api/v1/users -> 4000, got %d (ok=%v)", port, ok)
	}
	if port, ok := matchVHostTarget(vhMap, "site.com", "/index.html"); !ok || port != 3000 {
		t.Fatalf("expected root route /index.html -> 3000, got %d (ok=%v)", port, ok)
	}
	if port, ok := matchVHostTarget(vhMap, "dev.sub.site.com", "/"); !ok || port != 5000 {
		t.Fatalf("expected wildcard route dev.sub.site.com -> 5000, got %d (ok=%v)", port, ok)
	}

	// Verify local loopback port binding syntax (127.0.0.1:8080:80) for Caddy/Nginx integration
	pm, err := parseMappingsWithDefault("127.0.0.1:8080:80,8096", true)
	if err != nil || len(pm) != 2 || pm[0].BindIP != "127.0.0.1" || pm[0].PublicPort != 8080 || pm[0].TargetPort != 80 {
		t.Fatalf("unexpected PortMapping parse result: %+v (err=%v)", pm, err)
	}

	// Verify -duck certificate creation and reuse from disk without recreating
	tmpCerts := t.TempDir()
	mgr1, err := newSNICertManager(tmpCerts, "", "")
	if err != nil {
		t.Fatalf("newSNICertManager 1: %v", err)
	}
	mgr1.ensureDomainCertificate("myhomepc.local")
	c1, err := mgr1.getCertificate(&tls.ClientHelloInfo{ServerName: "myhomepc.local"})
	if err != nil || c1 == nil || len(c1.Certificate) == 0 {
		t.Fatalf("expected created cert, got err=%v", err)
	}

	mgr2, err := newSNICertManager(tmpCerts, "", "")
	if err != nil {
		t.Fatalf("newSNICertManager 2: %v", err)
	}
	mgr2.ensureDomainCertificate("myhomepc.local")
	c2, err := mgr2.getCertificate(&tls.ClientHelloInfo{ServerName: "myhomepc.local"})
	if err != nil || c2 == nil || !bytes.Equal(c1.Certificate[0], c2.Certificate[0]) {
		t.Fatalf("expected existing cert on disk to be reused without recreating")
	}

	// Verify RFC 8737 TLS-ALPN-01 challenge works without HTTP port 80
	mgr2.setALPNChallenge("myhomepc.local", "token123.thumbprint456")
	alpnCert, err := mgr2.getCertificate(&tls.ClientHelloInfo{
		ServerName:      "myhomepc.local",
		SupportedProtos: []string{"acme-tls/1"},
	})
	if err != nil || alpnCert == nil || bytes.Equal(alpnCert.Certificate[0], c2.Certificate[0]) {
		t.Fatalf("expected dedicated RFC 8737 TLS-ALPN-01 challenge cert on acme-tls/1")
	}
	mgr2.deleteALPNChallenge("myhomepc.local")

	// Verify background renewal detection (threshold > 400 days forces immediate renewal of 365-day cert)
	if !certNeedsRenewal(c2, 400*24*time.Hour) {
		t.Fatalf("expected 365-day cert to require renewal when threshold is 400 days")
	}
	if certNeedsRenewal(c2, 30*24*time.Hour) {
		t.Fatalf("fresh 365-day cert should not require renewal at 30-day threshold")
	}

	// Verify public domains do NOT silently fall back to untrusted self-signed certificates when ACME fails
	mgr2.enableACME = true
	mgr2.acmeDirectory = "http://127.0.0.1:1/unreachable-acme-dir"
	if _, err := mgr2.getCertificate(&tls.ClientHelloInfo{ServerName: "public-app.org"}); err == nil {
		t.Fatalf("expected error when ACME fails for public domain without allowSelfSignedPublic")
	}

	// Verify sslip.io / nip.io are recognized as public ACME domains
	if !isPublicACMEDomain("46-175-172-190.sslip.io") || !isPublicACMEDomain("46-175-172-190.nip.io") {
		t.Fatalf("expected sslip.io and nip.io to be eligible for public ACME issuance")
	}

	// Verify standalone -allow-ports filtering
	allowSet := map[uint16]struct{}{8096: {}, 25565: {}}
	if !isStandalonePortAllowed(allowSet, 8096) || isStandalonePortAllowed(allowSet, 22) {
		t.Fatalf("unexpected isStandalonePortAllowed result")
	}
}

func TestMidStreamNetworkOutageAndIPChangeSessionRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tcpTargetPort := getFreePort(t, "tcp")
	udpTargetPort := getFreePort(t, "udp")
	publicTCPPort := getFreePort(t, "tcp")
	publicUDPPort := getFreePort(t, "udp")
	gwQuicPort := getFreePort(t, "udp")
	proxyQuicPort := getFreePort(t, "udp")

	// Local TCP echo server
	tcpListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpTargetPort))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		for {
			c, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// Local UDP echo server
	udpAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", udpTargetPort))
	udpServer, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpServer.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := udpServer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpServer.WriteToUDP(buf[:n], raddr)
		}
	}()

	// Simulated ISP router / NAT proxy between Agent and Gateway
	gwUDPAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", gwQuicPort))
	proxyListenAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", proxyQuicPort))
	agentSideConn, err := net.ListenUDP("udp", proxyListenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer agentSideConn.Close()

	gwSideConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}

	type natState struct {
		blackout  bool
		agentAddr *net.UDPAddr
		gwConn    *net.UDPConn
	}
	var natMu = make(chan func(*natState), 64)
	state := &natState{gwConn: gwSideConn}
	go func() {
		for fn := range natMu {
			fn(state)
		}
	}()

	startGWReader := func(c *net.UDPConn) {
		go func() {
			buf := make([]byte, 65535)
			for {
				n, _, err := c.ReadFromUDP(buf)
				if err != nil {
					return
				}
				pkt := append([]byte(nil), buf[:n]...)
				natMu <- func(st *natState) {
					if !st.blackout && st.agentAddr != nil && st.gwConn == c {
						_, _ = agentSideConn.WriteToUDP(pkt, st.agentAddr)
					}
				}
			}
		}()
	}
	startGWReader(gwSideConn)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := agentSideConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			addrCopy := *raddr
			natMu <- func(st *natState) {
				st.agentAddr = &addrCopy
				if !st.blackout && st.gwConn != nil {
					_, _ = st.gwConn.WriteToUDP(pkt, gwUDPAddr)
				}
			}
		}
	}()

	mappings := []PortMapping{
		{PublicPort: uint16(publicTCPPort), TargetPort: uint16(tcpTargetPort), Proto: "tcp"},
		{PublicPort: uint16(publicUDPPort), TargetPort: uint16(udpTargetPort), Proto: "udp"},
	}
	gwAddr := fmt.Sprintf("127.0.0.1:%d", gwQuicPort)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyQuicPort)

	// Use fast 500ms QUIC idle timeout so link drop + IP change triggers reconnect in < 1 second
	go func() {
		if err := runGateway(ctx, gwAddr, "resume-secret", "", "", "", nil, mappings, 64*1024*1024, 4*1024*1024, 500*time.Millisecond, 150*time.Millisecond, 30*time.Second, t.TempDir(), "", "", false, false); err != nil {
			log.Printf("[test] gateway on %s exited before shutdown: %v", gwAddr, err)
		}
	}()
	waitForTCPListener(t, gwAddr, 15*time.Second)

	go func() {
		_ = runAgent(ctx, proxyAddr, "127.0.0.1", "resume-secret", "192.168.1.50", "", 4*1024*1024, 64*1024*1024, 500*time.Millisecond, 150*time.Millisecond, 30*time.Second, nil)
	}()
	waitForTCPEchoReady(t, fmt.Sprintf("127.0.0.1:%d", publicTCPPort), 5*time.Second)

	// Open long-lived TCP stream and UDP session before outage
	clientConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", publicTCPPort), 3*time.Second)
	if err != nil {
		t.Fatalf("dial public tcp failed: %v", err)
	}
	defer clientConn.Close()

	udpClient, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", publicUDPPort))
	if err != nil {
		t.Fatalf("dial public udp failed: %v", err)
	}
	defer udpClient.Close()

	part1 := make([]byte, 128*1024)
	part2 := make([]byte, 128*1024)
	_, _ = rand.Read(part1)
	_, _ = rand.Read(part2)

	if _, err := clientConn.Write(part1); err != nil {
		t.Fatalf("write part1 failed: %v", err)
	}
	gotPart1 := make([]byte, len(part1))
	_ = clientConn.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := io.ReadFull(clientConn, gotPart1); err != nil || !bytes.Equal(part1, gotPart1) {
		t.Fatalf("part1 mismatch before outage: err=%v", err)
	}

	// Simulate ISP blackout and new external IP/port assignment
	doneBlackout := make(chan struct{})
	natMu <- func(st *natState) {
		st.blackout = true
		_ = st.gwConn.Close()
		close(doneBlackout)
	}
	<-doneBlackout

	time.Sleep(850 * time.Millisecond)

	udpOutagePkt := []byte("buffered-udp-packet-during-ip-change")
	_, _ = udpClient.Write(udpOutagePkt)

	errCh := make(chan error, 1)
	go func() {
		_, wErr := clientConn.Write(part2)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		errCh <- wErr
	}()

	// Restore connection on a new UDP socket
	newGWConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer newGWConn.Close()
	startGWReader(newGWConn)
	natMu <- func(st *natState) {
		st.gwConn = newGWConn
		st.blackout = false
	}

	// Read remaining TCP data and buffered UDP datagram after reconnect
	_ = clientConn.SetReadDeadline(time.Now().Add(6 * time.Second))
	gotPart2, err := io.ReadAll(clientConn)
	if wErr := <-errCh; wErr != nil {
		t.Fatalf("write part2 during outage failed: %v", wErr)
	}
	if err != nil || !bytes.Equal(part2, gotPart2) {
		t.Fatalf("mid-stream session recovery failed after IP change: err=%v, got=%d bytes, want=%d bytes", err, len(gotPart2), len(part2))
	}

	_ = udpClient.SetReadDeadline(time.Now().Add(4 * time.Second))
	udpBuf := make([]byte, 128)
	un, uerr := udpClient.Read(udpBuf)
	if uerr != nil || !bytes.Equal(udpBuf[:un], udpOutagePkt) {
		t.Fatalf("buffered udp packet replay failed after IP change: err=%v, got=%q", uerr, string(udpBuf[:un]))
	}
}

func TestTCPMuxFallbackAndTokenRotation(t *testing.T) {

	// IPv6 /64 prefix normalization for auth brute-force protection
	k1 := normalizeAuthIPKey("2001:db8:abcd:1234::1")
	k2 := normalizeAuthIPKey("2001:db8:abcd:1234:ffff:eeee:dddd:cccc")
	if k1 != k2 || k1 != "2001:db8:abcd:1234::/64" {
		t.Fatalf("expected identical IPv6 /64 auth key, got %q and %q", k1, k2)
	}

	// HAProxy PROXY protocol v1 header formatting
	ppHdr := string(formatProxyProtoV1(
		&net.TCPAddr{IP: net.ParseIP("203.0.113.50"), Port: 54321},
		&net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 25565},
	))
	if ppHdr != "PROXY TCP4 203.0.113.50 198.51.100.10 54321 25565\r\n" {
		t.Fatalf("unexpected PROXY protocol v1 header: %q", ppHdr)
	}

	// Multiplexed TLS/TCP fallback (-transport tcp) + multi-token rotation ("new-tok,old-tok")
	prevTransport := defaultTransportMode
	defaultTransportMode = "tcp"
	defer func() {
		defaultTransportMode = prevTransport
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tcpTargetPort := getFreePort(t, "tcp")
	publicTCPPort := getFreePort(t, "tcp")
	muxPort := getFreePort(t, "tcp")

	tcpListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpTargetPort))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		for {
			c, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	mappings := []PortMapping{
		{PublicPort: uint16(publicTCPPort), TargetPort: uint16(tcpTargetPort), Proto: "tcp"},
	}
	gwAddr := fmt.Sprintf("127.0.0.1:%d", muxPort)

	// Gateway accepts both "new-rotated-tok" and "legacy-agent-tok"
	go func() {
		if err := runGateway(ctx, gwAddr, "new-rotated-tok,legacy-agent-tok", "", "", "", nil, mappings, 32*1024*1024, 4*1024*1024, 4*time.Second, 1*time.Second, 30*time.Second, t.TempDir(), "", "", false, false); err != nil {
			log.Printf("[test] gateway on %s exited before shutdown: %v", gwAddr, err)
		}
	}()
	waitForTCPListener(t, gwAddr, 15*time.Second)

	// Agent connects using "legacy-agent-tok" over TCP-Mux transport and includes an unreachable first gateway to test failover
	failoverAddrs := fmt.Sprintf("127.0.0.1:1,%s", gwAddr)
	go func() {
		_ = runAgent(ctx, failoverAddrs, "127.0.0.1", "legacy-agent-tok", "192.168.1.77", "", 4*1024*1024, 32*1024*1024, 4*time.Second, 1*time.Second, 30*time.Second, nil)
	}()
	waitForTCPEchoReady(t, fmt.Sprintf("127.0.0.1:%d", publicTCPPort), 5*time.Second)

	clientConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", publicTCPPort), 3*time.Second)
	if err != nil {
		t.Fatalf("tcp dial through TCP-Mux tunnel failed: %v", err)
	}
	defer clientConn.Close()

	msg := []byte("multiplexed-tls-tcp-fallback-and-token-rotation-ok")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if tc, ok := clientConn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := io.ReadAll(clientConn)
	if err != nil || !bytes.Equal(reply, msg) {
		t.Fatalf("tcp-mux echo mismatch: err=%v, got=%q", err, string(reply))
	}
}

func TestHardeningMultiGatewayFailoverAndResourceLimits(t *testing.T) {
	// STUN server normalization
	stunList := buildSTUNServerList("stun://my.custom.stun, extra.stun.org:19302")
	if len(stunList) < 3 || stunList[0] != "my.custom.stun:3478" || stunList[1] != "extra.stun.org:19302" || stunList[2] != "stun.cloudflare.com:3478" {
		t.Fatalf("unexpected STUN server list: %v", stunList)
	}

	// Global memory budget enforcement (TCP and UDP)
	baseMem := globalBufferedBytes.Load()
	maxCap := baseMem + 1024
	if !tryReserveGlobalMemory(512, maxCap) {
		t.Fatalf("expected 512B reservation within 1024B cap to succeed")
	}
	if tryReserveGlobalMemory(600, maxCap) {
		t.Fatalf("expected 600B reservation exceeding 1024B cap to be rejected")
	}
	globalBufferedBytes.Add(-512)

	baseUDPMem := globalUDPBufferedBytes.Load()
	maxUDPCap := baseUDPMem + 1024
	if !tryReserveGlobalUDPMemory(512, maxUDPCap) {
		t.Fatalf("expected 512B UDP reservation within 1024B cap to succeed")
	}
	if tryReserveGlobalUDPMemory(600, maxUDPCap) {
		t.Fatalf("expected 600B UDP reservation exceeding 1024B cap to be rejected")
	}
	globalUDPBufferedBytes.Add(-512)

	// 128-bit default token generation & persistence with 0600 permissions
	_ = os.RemoveAll(".driftless-certs")
	tok, err := loadOrGenerateToken(true, "", "")
	if err != nil || len(tok) < 32 {
		t.Fatalf("expected >= 128-bit (32 hex chars) auto-generated token, got len=%d err=%v", len(tok), err)
	}
	if fi, statErr := os.Stat(".driftless-certs/token.secret"); statErr != nil {
		t.Fatalf("expected .driftless-certs/token.secret to exist: %v", statErr)
	} else if perm := fi.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Fatalf("expected .driftless-certs/token.secret to have 0600 permissions, got %04o", perm)
	}
	tok2, err := loadOrGenerateToken(true, "", "")
	if err != nil || tok2 != tok {
		t.Fatalf("expected persisted token %q to reload identically, got %q (err=%v)", tok, tok2, err)
	}
	// Ensure loadOrGenerateToken fails when token persistence fails
	_ = os.RemoveAll(".driftless-certs")
	if err := os.WriteFile(".driftless-certs", []byte("conflict"), 0o600); err != nil {
		t.Fatalf("write file .driftless-certs: %v", err)
	}
	_, persistErr := loadOrGenerateToken(true, "", "")
	_ = os.RemoveAll(".driftless-certs")
	if persistErr == nil {
		t.Fatalf("expected loadOrGenerateToken to fail when .driftless-certs/token.secret cannot be persisted")
	}

	// Pre-auth tcpMuxConn stream & buffer protection
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	serverMux := newTCPMuxConn(c1, false, 4*time.Second, 1*time.Second)
	clientMux := newTCPMuxConn(c2, true, 4*time.Second, 1*time.Second)
	defer serverMux.CloseWithError(0, "test done")
	defer clientMux.CloseWithError(0, "test done")

	st1, err := clientMux.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("first pre-auth stream open failed: %v", err)
	}
	_, _ = st1.Write([]byte("hi"))
	st2, err := clientMux.OpenStreamSync(context.Background())
	if err == nil {
		_, _ = st2.Write([]byte("overflow"))
	}
	select {
	case <-serverMux.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected unauthenticated serverMux to close when peer opens > maxPreAuthMuxStreams")
	}

	// Multi-Gateway failover (Gateway #1 stops -> Agent switches to Gateway #2)
	tcpTargetPort := getFreePort(t, "tcp")
	tcpListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpTargetPort))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		for {
			c, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	gw1Port := getFreePort(t, "udp")
	gw1PubPort := getFreePort(t, "tcp")
	gw2Port := getFreePort(t, "udp")
	gw2PubPort := getFreePort(t, "tcp")

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	agentCtx, cancelAgent := context.WithCancel(context.Background())
	defer cancelAgent()

	gw1Addr := fmt.Sprintf("127.0.0.1:%d", gw1Port)
	gw2Addr := fmt.Sprintf("127.0.0.1:%d", gw2Port)

	go func() {
		if err := runGateway(ctx1, gw1Addr, "ha-secret", "", "", "", nil, []PortMapping{
			{PublicPort: uint16(gw1PubPort), TargetPort: uint16(tcpTargetPort), Proto: "tcp"},
		}, 32*1024*1024, 4*1024*1024, 600*time.Millisecond, 150*time.Millisecond, 30*time.Second, t.TempDir(), "", "", false, false); err != nil {
			log.Printf("[test] gateway on %s exited before shutdown: %v", gw1Addr, err)
		}
	}()
	go func() {
		if err := runGateway(ctx2, gw2Addr, "ha-secret", "", "", "", nil, []PortMapping{
			{PublicPort: uint16(gw2PubPort), TargetPort: uint16(tcpTargetPort), Proto: "tcp"},
		}, 32*1024*1024, 4*1024*1024, 600*time.Millisecond, 150*time.Millisecond, 30*time.Second, t.TempDir(), "", "", false, false); err != nil {
			log.Printf("[test] gateway on %s exited before shutdown: %v", gw2Addr, err)
		}
	}()
	waitForTCPListener(t, gw1Addr, 15*time.Second)
	waitForTCPListener(t, gw2Addr, 15*time.Second)

	go func() {
		_ = runAgent(agentCtx, fmt.Sprintf("%s,%s", gw1Addr, gw2Addr), "127.0.0.1", "ha-secret", "192.168.1.90", "", 4*1024*1024, 32*1024*1024, 600*time.Millisecond, 150*time.Millisecond, 30*time.Second, nil)
	}()
	waitForTCPEchoReady(t, fmt.Sprintf("127.0.0.1:%d", gw1PubPort), 5*time.Second)

	// Verify traffic through Gateway #1
	cGW1, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", gw1PubPort), 3*time.Second)
	if err != nil {
		t.Fatalf("dial gw1 public port failed: %v", err)
	}
	msg1 := []byte("via-gateway-1")
	_, _ = cGW1.Write(msg1)
	if tc, ok := cGW1.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = cGW1.SetReadDeadline(time.Now().Add(3 * time.Second))
	got1, err := io.ReadAll(cGW1)
	_ = cGW1.Close()
	if err != nil || !bytes.Equal(got1, msg1) {
		t.Fatalf("gw1 echo failed: err=%v, got=%q", err, string(got1))
	}

	// Shut down Gateway #1 completely and verify Agent fails over to Gateway #2 (which has a different self-signed TLS cert!)
	cancel1()
	waitForTCPEchoReady(t, fmt.Sprintf("127.0.0.1:%d", gw2PubPort), 5*time.Second)

	cGW2, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", gw2PubPort), 3*time.Second)
	if err != nil {
		t.Fatalf("dial gw2 public port after failover failed: %v", err)
	}
	msg2 := []byte("via-gateway-2-after-failover")
	_, _ = cGW2.Write(msg2)
	if tc, ok := cGW2.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = cGW2.SetReadDeadline(time.Now().Add(3 * time.Second))
	got2, err := io.ReadAll(cGW2)
	_ = cGW2.Close()
	if err != nil || !bytes.Equal(got2, msg2) {
		t.Fatalf("gw2 echo after failover failed: err=%v, got=%q", err, string(got2))
	}
}

func TestUPnPLifecycleAllowPortsAndUDPReplayBudget(t *testing.T) {
	// Ensure -allow-ports filtering runs before UPnP port forwarding
	rawMappings := []PortMapping{
		{PublicPort: 25565, TargetPort: 25565, Proto: "tcp"},
		{PublicPort: 2222, TargetPort: 22, Proto: "tcp"}, // disallowed SSH port
		{PublicPort: 19132, TargetPort: 19132, Proto: "udp"},
	}
	rawVHosts := map[string]uint16{
		"app.example.com":   3000,
		"admin.example.com": 9090, // disallowed admin port
	}
	allowed := map[uint16]struct{}{
		25565: {},
		19132: {},
		3000:  {},
	}
	filteredMappings, filteredVHosts := filterStandaloneConfigByAllowedPorts(rawMappings, rawVHosts, allowed)
	if len(filteredMappings) != 2 || filteredMappings[0].TargetPort != 25565 || filteredMappings[1].TargetPort != 19132 {
		t.Fatalf("expected only allowed ports 25565 & 19132 after filter, got %+v", filteredMappings)
	}
	if len(filteredVHosts) != 1 || filteredVHosts["app.example.com"] != 3000 {
		t.Fatalf("expected only allowed vhost port 3000 after filter, got %+v", filteredVHosts)
	}

	// Mock UPnP IGD (WANPPPConnection:1) server
	var upnpMu sync.Mutex
	activeRouterRules := make(map[string]bool)
	var lease3600Attempts int
	var deleteCalls int
	var failDeletePort int

	mux := http.NewServeMux()
	mux.HandleFunc("/ctl/WANPPP", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		bodyStr := string(bodyBytes)
		soapAction := r.Header.Get("SOAPAction")

		upnpMu.Lock()
		defer upnpMu.Unlock()

		if strings.Contains(soapAction, "AddPortMapping") {
			if strings.Contains(bodyStr, "<NewLeaseDuration>3600</NewLeaseDuration>") {
				lease3600Attempts++
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
				return
			}
			var port int
			var proto string
			if i := strings.Index(bodyStr, "<NewExternalPort>"); i >= 0 {
				_, _ = fmt.Sscanf(bodyStr[i:], "<NewExternalPort>%d</NewExternalPort>", &port)
			}
			if i := strings.Index(bodyStr, "<NewProtocol>"); i >= 0 {
				end := strings.Index(bodyStr[i:], "</NewProtocol>")
				if end > len("<NewProtocol>") {
					proto = bodyStr[i+len("<NewProtocol>") : i+end]
				}
			}
			activeRouterRules[fmt.Sprintf("%s:%d", proto, port)] = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>`))
			return
		}

		if strings.Contains(soapAction, "DeletePortMapping") {
			deleteCalls++
			var port int
			var proto string
			if i := strings.Index(bodyStr, "<NewExternalPort>"); i >= 0 {
				_, _ = fmt.Sscanf(bodyStr[i:], "<NewExternalPort>%d</NewExternalPort>", &port)
			}
			if i := strings.Index(bodyStr, "<NewProtocol>"); i >= 0 {
				end := strings.Index(bodyStr[i:], "</NewProtocol>")
				if end > len("<NewProtocol>") {
					proto = bodyStr[i+len("<NewProtocol>") : i+end]
				}
			}
			if failDeletePort > 0 && port == failDeletePort {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			delete(activeRouterRules, fmt.Sprintf("%s:%d", proto, port))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	})

	srv := &http.Server{Handler: mux}
	upnpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upnpLn.Close()
	go func() { _ = srv.Serve(upnpLn) }()
	defer srv.Close()

	ctrlURL := fmt.Sprintf("http://%s/ctl/WANPPP", upnpLn.Addr().String())
	svcType := "urn:schemas-upnp-org:service:WANPPPConnection:1"
	mockEndpoints := []upnpEndpoint{{ctrlURL: ctrlURL, serviceType: svcType}}

	// Forward filtered ports via UPnP (simulating PPTP router that requires LeaseDuration=0 fallback)
	mapped := autoForwardRouterPortsWithEndpoints("192.168.1.50", filteredMappings, "0.0.0.0:8080", "", mockEndpoints, "")
	if mapped != 3 {
		t.Fatalf("expected 3 UPnP port rules (25565/TCP, 19132/UDP, 8080/TCP), got %d", mapped)
	}

	upnpMu.Lock()
	if lease3600Attempts != 3 {
		upnpMu.Unlock()
		t.Fatalf("expected 3 initial 3600s lease attempts before permanent lease fallback, got %d", lease3600Attempts)
	}
	if activeRouterRules["TCP:2222"] || activeRouterRules["TCP:22"] {
		upnpMu.Unlock()
		t.Fatalf("SECURITY BUG: disallowed port 2222->22 was forwarded via UPnP!")
	}
	if !activeRouterRules["TCP:25565"] || !activeRouterRules["UDP:19132"] || !activeRouterRules["TCP:8080"] {
		upnpMu.Unlock()
		t.Fatalf("missing expected UPnP rules on router: %+v", activeRouterRules)
	}
	// Simulate router failing to delete port 8080 on first shutdown attempt
	failDeletePort = 8080
	upnpMu.Unlock()

	// Verify crash-recovery state file (.driftless-upnp-state.json) was persisted
	if _, err := os.Stat(upnpStateFile); err != nil {
		t.Fatalf("expected %s to exist while UPnP mappings are active: %v", upnpStateFile, err)
	}

	// First shutdown attempt: 2 rules deleted, 1 rule (8080) fails -> state file MUST remain with only port 8080!
	removed, cleanErr := cleanupActiveUPnPMappings()
	if cleanErr != nil || removed != 2 {
		t.Fatalf("expected 2 UPnP rules deleted without persistence error when port 8080 fails, got removed=%d err=%v", removed, cleanErr)
	}
	if _, err := os.Stat(upnpStateFile); err != nil {
		t.Fatalf("expected %s to be retained when a UPnP DeletePortMapping call fails: %v", upnpStateFile, err)
	}

	// Router recovers on next startup -> cleanupStaleUPnPState retries remaining rule (8080) and deletes state file
	upnpMu.Lock()
	failDeletePort = 0
	upnpMu.Unlock()

	staleRemoved, staleErr := cleanupStaleUPnPState()
	if staleErr != nil || staleRemoved != 1 {
		t.Fatalf("expected 1 remaining stale UPnP rule (8080) deleted on retry without error, got removed=%d err=%v", staleRemoved, staleErr)
	}
	upnpMu.Lock()
	if len(activeRouterRules) != 0 || deleteCalls != 4 {
		upnpMu.Unlock()
		t.Fatalf("expected 0 remaining router rules and 4 total DeletePortMapping calls, got rules=%+v deletes=%d", activeRouterRules, deleteCalls)
	}
	upnpMu.Unlock()
	if _, err := os.Stat(upnpStateFile); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be deleted after all rules are removed", upnpStateFile)
	}

	// UDP global memory budget stays reserved during replay and is released after write finishes
	baseUDP := globalUDPBufferedBytes.Load()
	us := &gwUDPSession{
		id: 777,
	}
	pktPayload := make([]byte, 4096)
	us.mu.Lock()
	us.enqueuePacketLocked(pktPayload)
	us.enqueuePacketLocked(pktPayload)
	us.mu.Unlock()

	if got := globalUDPBufferedBytes.Load() - baseUDP; got != 8192 {
		t.Fatalf("expected 8192 UDP bytes reserved after enqueue, got %d", got)
	}

	// Detach for replay: globalUDPBufferedBytes MUST still hold the 8192-byte reservation while in-flight!
	us.mu.Lock()
	detached := us.detachPendingForReplayLocked()
	us.mu.Unlock()
	if len(detached) != 2 {
		t.Fatalf("expected 2 detached packets, got %d", len(detached))
	}
	if got := globalUDPBufferedBytes.Load() - baseUDP; got != 8192 {
		t.Fatalf("UDP replay memory leak/accounting bug: expected 8192 bytes still reserved during replay, got %d", got)
	}

	// Restore and replay through a real TunnelStream pair to verify full release to 0 after stream write
	us.mu.Lock()
	us.restoreUnsentReplayLocked(detached)
	us.mu.Unlock()

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	serverMux := newTCPMuxConn(p1, false, 4*time.Second, 1*time.Second)
	clientMux := newTCPMuxConn(p2, true, 4*time.Second, 1*time.Second)
	serverMux.SetAuthenticated()
	clientMux.SetAuthenticated()
	defer serverMux.CloseWithError(0, "done")
	defer clientMux.CloseWithError(0, "done")

	go func() {
		st, err := serverMux.AcceptStream(context.Background())
		if err == nil {
			_, _ = io.Copy(io.Discard, st)
		}
	}()

	outSt, err := clientMux.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync failed: %v", err)
	}
	if err := us.replayPendingToStream(outSt); err != nil {
		t.Fatalf("replayPendingToStream failed: %v", err)
	}
	if got := globalUDPBufferedBytes.Load() - baseUDP; got != 0 {
		t.Fatalf("expected 0 UDP bytes reserved after replayPendingToStream completed, got %d", got)
	}

	// Secret/token log redaction
	registerSecretForLogRedaction("super-secret-pass-98765")
	sanitized := sanitizeLogString("auth with super-secret-pass-98765 and https://www.duckdns.org/update?domains=home&token=duck-raw-tok-111&ip=1.2.3.4")
	if strings.Contains(sanitized, "super-secret-pass-98765") || strings.Contains(sanitized, "duck-raw-tok-111") {
		t.Fatalf("SECURITY BUG: secret leaked in sanitized log string: %q", sanitized)
	}
	if !strings.Contains(sanitized, "[token=hidden]") {
		t.Fatalf("expected [token=hidden] placeholder in sanitized log string, got %q", sanitized)
	}

	// UPnP state file write failure surfaces error and rolls back router rule
	_ = os.RemoveAll(upnpStateFile)
	if err := os.MkdirAll(upnpStateFile, 0o700); err != nil {
		t.Fatalf("mkdir %s failed: %v", upnpStateFile, err)
	}
	writeErr := recordTrackedRouterMapping(trackedRouterMapping{
		Kind:        "upnp",
		CtrlURL:     ctrlURL,
		ServiceType: svcType,
		LANIP:       "192.168.1.50",
		Port:        9999,
		Proto:       "TCP",
	})
	if writeErr == nil {
		_ = os.RemoveAll(upnpStateFile)
		t.Fatalf("expected recordTrackedRouterMapping to return an explicit error when %s cannot be written", upnpStateFile)
	}

	upnpMu.Lock()
	deleteCallsBeforeRollback := deleteCalls
	upnpMu.Unlock()
	mappedOnWriteFail := autoForwardRouterPortsWithEndpoints("192.168.1.50", []PortMapping{{PublicPort: 9999, TargetPort: 9999, Proto: "tcp"}}, "", "", mockEndpoints, "")
	if mappedOnWriteFail != 0 {
		_ = os.RemoveAll(upnpStateFile)
		t.Fatalf("expected 0 successful mappings when state file %s cannot be persisted, got %d", upnpStateFile, mappedOnWriteFail)
	}
	upnpMu.Lock()
	stillOnRouter := activeRouterRules["TCP:9999"]
	rollbackDeletes := deleteCalls - deleteCallsBeforeRollback
	upnpMu.Unlock()
	if stillOnRouter || rollbackDeletes != 1 {
		_ = os.RemoveAll(upnpStateFile)
		t.Fatalf("expected UPnP rule TCP:9999 to be immediately rolled back on state-file write error (stillOnRouter=%v, rollbackDeletes=%d)", stillOnRouter, rollbackDeletes)
	}

	// Recovery after a failed rollback (state file write fails and router refuses DeletePortMapping)
	upnpMu.Lock()
	failDeletePort = 9999
	deleteCallsBeforeFailedRollback := deleteCalls
	upnpMu.Unlock()

	mappedOnFailedRollback := autoForwardRouterPortsWithEndpoints("192.168.1.50", []PortMapping{{PublicPort: 9999, TargetPort: 9999, Proto: "tcp"}}, "", "", mockEndpoints, "")
	_ = os.RemoveAll(upnpStateFile)
	if mappedOnFailedRollback != 0 {
		t.Fatalf("expected 0 successful mappings when state file write & rollback both fail, got %d", mappedOnFailedRollback)
	}
	upnpMu.Lock()
	retryAttempts := deleteCalls - deleteCallsBeforeFailedRollback
	stillOnRouterAfterFailedRollback := activeRouterRules["TCP:9999"]
	failDeletePort = 0
	upnpMu.Unlock()
	if retryAttempts != 3 || !stillOnRouterAfterFailedRollback {
		t.Fatalf("expected 3 rollback delete attempts and rule still on router when router rejects delete (attempts=%d, onRouter=%v)", retryAttempts, stillOnRouterAfterFailedRollback)
	}
	fbStatePath := resolveUPnPFallbackStateFile()
	if _, err := os.Stat(fbStatePath); err != nil {
		t.Fatalf("expected fallback state file %s to exist after failed rollback: %v", fbStatePath, err)
	}

	upnpStateMu.Lock()
	activeUPnPMappings = nil
	upnpStateMu.Unlock()
	recoveredDeletes, recErr := cleanupStaleUPnPState()
	upnpMu.Lock()
	stillOnRouterAfterRecovery := activeRouterRules["TCP:9999"]
	upnpMu.Unlock()
	if recErr != nil || recoveredDeletes != 1 || stillOnRouterAfterRecovery {
		t.Fatalf("expected failed-rollback rule TCP:9999 to be recovered and deleted by cleanupStaleUPnPState (recovered=%d, stillOnRouter=%v, err=%v)", recoveredDeletes, stillOnRouterAfterRecovery, recErr)
	}

	// Atomic 0600 file write
	atomicTestPath := ".driftless-atomic-test.json"
	defer os.Remove(atomicTestPath)
	if err := writeFileAtomic0600(atomicTestPath, []byte(`{"v":1}`)); err != nil {
		t.Fatalf("writeFileAtomic0600 initial write failed: %v", err)
	}
	if err := writeFileAtomic0600(atomicTestPath, []byte(`{"v":2,"ok":true}`)); err != nil {
		t.Fatalf("writeFileAtomic0600 overwrite failed: %v", err)
	}
	gotAtomic, err := os.ReadFile(atomicTestPath)
	if err != nil || string(gotAtomic) != `{"v":2,"ok":true}` {
		t.Fatalf("unexpected content after atomic overwrite: %q (err=%v)", string(gotAtomic), err)
	}

	// Per-instance fallback state file isolation
	upnpInstanceIDOverride = "instance-alpha"
	fbAlpha := resolveUPnPFallbackStateFile()
	upnpInstanceIDOverride = "instance-beta"
	fbBeta := resolveUPnPFallbackStateFile()
	if fbAlpha == fbBeta {
		upnpInstanceIDOverride = ""
		t.Fatalf("expected distinct fallback state files per instance, got identical %s", fbAlpha)
	}
	upnpInstanceIDOverride = "instance-alpha"
	upnpStateMu.Lock()
	activeUPnPMappings = []trackedRouterMapping{{InstanceID: "instance-alpha", Kind: "upnp", CtrlURL: ctrlURL, ServiceType: svcType, Port: 7001, Proto: "TCP"}}
	if err := saveFallbackRouterMappingsLocked(); err != nil {
		upnpStateMu.Unlock()
		upnpInstanceIDOverride = ""
		t.Fatalf("saveFallbackRouterMappingsLocked for alpha failed: %v", err)
	}
	activeUPnPMappings = nil
	upnpStateMu.Unlock()

	upnpInstanceIDOverride = "instance-beta"
	upnpStateMu.Lock()
	_ = saveTrackedRouterMappingsLocked()
	upnpStateMu.Unlock()
	if _, err := os.Stat(fbAlpha); err != nil {
		upnpInstanceIDOverride = ""
		t.Fatalf("instance-beta deleted instance-alpha's fallback state file %s: %v", fbAlpha, err)
	}
	_ = os.Remove(fbAlpha)
	_ = os.Remove(fbBeta)
	upnpInstanceIDOverride = ""

	// Abort remaining port mappings when primary write, rollback, and fallback write all fail
	_ = os.MkdirAll(upnpStateFile, 0o700)
	origFallbackDir := upnpFallbackStateDir
	upnpFallbackStateDir = filepath.Join(os.TempDir(), "nonexistent-driftless-fb-dir-999999")
	upnpMu.Lock()
	failDeletePort = 9999
	upnpMu.Unlock()

	abortedCount := autoForwardRouterPortsWithEndpoints("192.168.1.50", []PortMapping{
		{PublicPort: 9999, TargetPort: 9999, Proto: "tcp"},
		{PublicPort: 9998, TargetPort: 9998, Proto: "tcp"},
	}, "", "", mockEndpoints, "")
	upnpFallbackStateDir = origFallbackDir
	_ = os.RemoveAll(upnpStateFile)
	upnpMu.Lock()
	port9998Created := activeRouterRules["TCP:9998"]
	failDeletePort = 0
	upnpMu.Unlock()
	if abortedCount != 0 || port9998Created {
		t.Fatalf("expected critical failure on port 9999 to abort before mapping port 9998 (abortedCount=%d, port9998Created=%v)", abortedCount, port9998Created)
	}
	_, _ = cleanupActiveUPnPMappings()

	// Corrupted state file preservation (.corrupt-*) and JSON object salvage
	upnpMu.Lock()
	activeRouterRules["TCP:7777"] = true
	upnpMu.Unlock()
	corruptContent := fmt.Sprintf(`[{"kind":"upnp","ctrl_url":%q,"service_type":%q,"port":7777,"proto":"TCP"}, CORRUPTED_TAIL`, ctrlURL, svcType)
	if err := writeFileAtomic0600(upnpStateFile, []byte(corruptContent)); err != nil {
		t.Fatalf("write corrupt test state file: %v", err)
	}
	salvagedRemoved, salvErr := cleanupStaleUPnPState()
	matches, _ := filepath.Glob(upnpStateFile + ".corrupt-*")
	for _, m := range matches {
		_ = os.Remove(m)
	}
	upnpMu.Lock()
	port7777StillOnRouter := activeRouterRules["TCP:7777"]
	upnpMu.Unlock()
	if len(matches) == 0 {
		t.Fatalf("expected corrupted state file %s to be preserved as %s.corrupt-* for diagnostics", upnpStateFile, upnpStateFile)
	}
	if salvErr != nil || salvagedRemoved != 1 || port7777StillOnRouter {
		t.Fatalf("expected intact mapping TCP:7777 inside corrupted state file to be salvaged and deleted from router (salvagedRemoved=%d, stillOnRouter=%v, err=%v)", salvagedRemoved, port7777StillOnRouter, salvErr)
	}

	// Cross-process lock enforcement and dead-PID recovery
	lockPath := resolveUPnPStateLockFile()
	_ = os.Remove(lockPath)
	origLockTimeout := upnpLockAcquireTimeout
	upnpLockAcquireTimeout = 60 * time.Millisecond
	livePayload := fmt.Sprintf("%d:active-holder-token\n", os.Getpid())
	if err := os.WriteFile(lockPath, []byte(livePayload), 0o600); err != nil {
		upnpLockAcquireTimeout = origLockTimeout
		t.Fatalf("write live lock file: %v", err)
	}
	fnExecutedOnContention := false
	lockErr := withUPnPStateFileLock(func() error {
		fnExecutedOnContention = true
		return nil
	})
	if lockErr == nil || fnExecutedOnContention {
		_ = os.Remove(lockPath)
		upnpLockAcquireTimeout = origLockTimeout
		t.Fatalf("SECURITY/CONCURRENCY BUG: withUPnPStateFileLock must fail and NOT execute fn() when lock is held by an active process (err=%v, executed=%v)", lockErr, fnExecutedOnContention)
	}
	if rawAfter, err := os.ReadFile(lockPath); err != nil || string(rawAfter) != livePayload {
		_ = os.Remove(lockPath)
		upnpLockAcquireTimeout = origLockTimeout
		t.Fatalf("timed-out waiter corrupted or deleted active holder's lock file: err=%v content=%q", err, string(rawAfter))
	}
	deadPayload := "99999999:dead-holder-token\n"
	if err := os.WriteFile(lockPath, []byte(deadPayload), 0o600); err != nil {
		_ = os.Remove(lockPath)
		upnpLockAcquireTimeout = origLockTimeout
		t.Fatalf("write dead lock file: %v", err)
	}
	fnExecutedAfterDeadRecovery := false
	recLockErr := withUPnPStateFileLock(func() error {
		fnExecutedAfterDeadRecovery = true
		return nil
	})
	upnpLockAcquireTimeout = origLockTimeout
	_ = os.Remove(lockPath)
	if recLockErr != nil || !fnExecutedAfterDeadRecovery {
		t.Fatalf("expected dead-PID lock to be recovered and fn() executed (err=%v, executed=%v)", recLockErr, fnExecutedAfterDeadRecovery)
	}

	// UPnP SSRF guard (including HTTP redirect target validation)
	if isSafeRouterURL("http://169.254.169.254/latest/meta-data") || isSafeRouterURL("http://93.184.216.34:1900/ctl") || isSafeRouterURL("ftp://192.168.1.1/ctl") {
		t.Fatalf("SECURITY BUG: isSafeRouterURL allowed unsafe/SSRF URL")
	}
	if !isSafeRouterURL("http://192.168.1.1:1900/ctl") || !isSafeRouterURL("http://10.0.0.1:5000/ipc") || !isSafeRouterURL("http://127.0.0.1:45678/ctl") {
		t.Fatalf("expected isSafeRouterURL to allow valid RFC1918 and loopback router URLs")
	}
	redirMux := http.NewServeMux()
	redirMux.HandleFunc("/ssrf-meta", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	})
	redirMux.HandleFunc("/ssrf-crosshost", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.168.1.254:80/admin", http.StatusFound)
	})
	redirSrv := &http.Server{Handler: redirMux}
	redirLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer redirLn.Close()
	go func() { _ = redirSrv.Serve(redirLn) }()
	defer redirSrv.Close()

	safeClient := newSafeRouterHTTPClient(500 * time.Millisecond)
	if resp, err := safeClient.Get(fmt.Sprintf("http://%s/ssrf-meta", redirLn.Addr().String())); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("SECURITY BUG: newSafeRouterHTTPClient followed HTTP redirect to 169.254.169.254")
	}
	if resp, err := safeClient.Get(fmt.Sprintf("http://%s/ssrf-crosshost", redirLn.Addr().String())); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("SECURITY BUG: newSafeRouterHTTPClient followed cross-host HTTP redirect")
	}

	// Mutual channel-bound HMAC authentication
	nonce := []byte("0123456789abcdef0123456789abcdef")
	realCertHash := []byte("real-gateway-cert-sha256-digest!")
	mitmCertHash := []byte("mitm-gateway-cert-sha256-digest!")
	cMAC := computeClientAuthMAC("secret-tok", nonce, realCertHash, "192.168.1.50")
	mitmCMAC := computeClientAuthMAC("secret-tok", nonce, mitmCertHash, "192.168.1.50")
	if bytes.Equal(cMAC, mitmCMAC) {
		t.Fatalf("SECURITY BUG: channel-bound client MAC did not change when TLS certificate digest changed")
	}
	sMAC := computeServerAuthMAC("secret-tok", nonce, realCertHash, cMAC)
	wrongSMAC := computeServerAuthMAC("wrong-tok", nonce, realCertHash, cMAC)
	if bytes.Equal(sMAC, wrongSMAC) {
		t.Fatalf("SECURITY BUG: mutual server MAC did not change with different token")
	}

	// Self-healing loadGatewayCert when cert.pem/key.pem on disk is corrupted
	corruptCertDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(corruptCertDir, "cert.pem"), []byte("CORRUPTED_PEM_DATA"), 0o600)
	_ = os.WriteFile(filepath.Join(corruptCertDir, "key.pem"), []byte("CORRUPTED_KEY_DATA"), 0o600)
	if _, healedFP, healErr := loadGatewayCert(corruptCertDir); healErr != nil || len(healedFP) != 64 {
		t.Fatalf("expected loadGatewayCert to self-heal corrupted cert.pem/key.pem, got fp=%q err=%v", healedFP, healErr)
	}
}

func TestPCPv2RandomNonceAndSpoofedResponseRejection(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var mu sync.Mutex
	spoofNonceMode := false
	spoofPortMode := false
	recordedNonces := make([][12]byte, 0, 4)

	go func() {
		var buf [128]byte
		for {
			n, raddr, err := conn.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if n < 60 || buf[0] != 2 || buf[1] != 1 {
				continue
			}
			var reqNonce [12]byte
			copy(reqNonce[:], buf[24:36])

			mu.Lock()
			doSpoofNonce := spoofNonceMode
			doSpoofPort := spoofPortMode
			recordedNonces = append(recordedNonces, reqNonce)
			mu.Unlock()

			var resp [60]byte
			copy(resp[:], buf[:60])
			resp[0] = 2
			resp[1] = 0x81 // R=1 Response, Opcode=1 MAP
			resp[3] = 0    // ResultCode 0 (Success)
			if doSpoofNonce {
				// Corrupt echoed 96-bit Mapping Nonce
				resp[24] ^= 0xff
				resp[35] ^= 0xaa
			}
			if doSpoofPort {
				// Corrupt echoed internal port
				binary.BigEndian.PutUint16(resp[40:42], 65000)
			}
			_, _ = conn.WriteToUDP(resp[:], raddr)
		}
	}()

	gwAddr := conn.LocalAddr().String()

	// 1. Two independent PCP mapping creations for the exact same parameters MUST generate cryptographically distinct random 96-bit nonces
	nonceHex1, err1 := pcpSetPortMapping(gwAddr, "192.168.1.50", 25565, 25565, "TCP", 3600, "")
	if err1 != nil {
		t.Fatalf("first pcpSetPortMapping failed: %v", err1)
	}
	nonceHex2, err2 := pcpSetPortMapping(gwAddr, "192.168.1.50", 25565, 25565, "TCP", 3600, "")
	if err2 != nil {
		t.Fatalf("second pcpSetPortMapping failed: %v", err2)
	}
	if len(nonceHex1) != 24 || len(nonceHex2) != 24 {
		t.Fatalf("expected 24-hex-char (12-byte) PCP nonces, got %q and %q", nonceHex1, nonceHex2)
	}
	if nonceHex1 == nonceHex2 {
		t.Fatalf("SECURITY BUG: PCP Mapping Nonces are deterministic (%q == %q); RFC 6887 requires random 96-bit nonces", nonceHex1, nonceHex2)
	}

	// 2. Passing an existing saved nonce (for renewal or deletion) must transmit that exact 96-bit nonce
	reusedHex, err3 := pcpSetPortMapping(gwAddr, "192.168.1.50", 25565, 25565, "TCP", 0, nonceHex1)
	if err3 != nil || reusedHex != nonceHex1 {
		t.Fatalf("expected saved PCP nonce %q to be reused on deletion, got %q (err=%v)", nonceHex1, reusedHex, err3)
	}
	mu.Lock()
	if len(recordedNonces) < 3 {
		mu.Unlock()
		t.Fatalf("expected at least 3 recorded PCP packets, got %d", len(recordedNonces))
	}
	rawNonce1, _ := hex.DecodeString(nonceHex1)
	if !bytes.Equal(recordedNonces[2][:], rawNonce1) {
		mu.Unlock()
		t.Fatalf("expected third packet to carry saved nonce %x, got %x", rawNonce1, recordedNonces[2])
	}
	// 3. Enable spoofed nonce mode and verify pcpSetPortMapping rejects the forged response
	spoofNonceMode = true
	mu.Unlock()

	if _, spoofErr := pcpSetPortMapping(gwAddr, "192.168.1.50", 25565, 25565, "TCP", 3600, ""); spoofErr == nil {
		t.Fatalf("SECURITY BUG: pcpSetPortMapping accepted a PCP response with a mismatched 96-bit Mapping Nonce")
	}

	// 4. Enable spoofed internal port mode and verify pcpSetPortMapping rejects the forged response
	mu.Lock()
	spoofNonceMode = false
	spoofPortMode = true
	mu.Unlock()

	if _, spoofPortErr := pcpSetPortMapping(gwAddr, "192.168.1.50", 25565, 25565, "TCP", 3600, ""); spoofPortErr == nil {
		t.Fatalf("SECURITY BUG: pcpSetPortMapping accepted a PCP response with a mismatched internal port")
	}
}

func TestMultiRouterVendorSimulationAndStress(t *testing.T) {
	// D-Link / Netgear / ZyXEL / Huawei XML description with <URLBase> and multiline whitespace-padded tags
	rawXML := []byte(`<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <URLBase>
    http://192.168.0.1:5431/upnp/
  </URLBase>
  <device>
    <serviceList>
      <service>
        <serviceType>
          urn:schemas-upnp-org:service:WANIPConnection:2
        </serviceType>
        <controlURL>
          control/WANIPConn2
        </controlURL>
      </service>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:2</serviceType>
        <controlURL>http://198.51.100.99:1900/ssrf-attempt</controlURL>
      </service>
    </serviceList>
  </device>
</root>`)
	eps := parseUPnPDescriptionXML("http://192.168.0.1:1900/rootDesc.xml", nil, rawXML)
	if len(eps) != 1 || eps[0].ctrlURL != "http://192.168.0.1:5431/upnp/control/WANIPConn2" || eps[0].serviceType != "urn:schemas-upnp-org:service:WANIPConnection:2" {
		t.Fatalf("unexpected parsed <URLBase> UPnP endpoints: %+v", eps)
	}

	// Asuswrt / TP-Link / Netgear / OpenWrt IGDv2 router simulation:
	// - Port 25565 has a stale conflict (718 ConflictInMappingEntry) until DeletePortMapping is called first
	// - Port 8096 rejects AddPortMapping with 606 Action Not Authorized and requires IGDv2 AddAnyPortMapping
	// - Simulates router reboot clearing memory so subsequent DeletePortMapping returns 714 NoSuchEntryInArray
	var routerMu sync.Mutex
	staleConflictCleared := false
	routerRebooted := false
	igdv2Rules := make(map[string]bool)

	igdv2Mux := http.NewServeMux()
	igdv2Mux.HandleFunc("/ctl/IGDv2", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		bodyStr := string(bodyBytes)
		soapAction := r.Header.Get("SOAPAction")

		routerMu.Lock()
		defer routerMu.Unlock()

		var port int
		var proto string
		if i := strings.Index(bodyStr, "<NewExternalPort>"); i >= 0 {
			_, _ = fmt.Sscanf(bodyStr[i:], "<NewExternalPort>%d</NewExternalPort>", &port)
		}
		if i := strings.Index(bodyStr, "<NewProtocol>"); i >= 0 {
			end := strings.Index(bodyStr[i:], "</NewProtocol>")
			if end > len("<NewProtocol>") {
				proto = strings.TrimSpace(bodyStr[i+len("<NewProtocol>") : i+end])
			}
		}
		ruleKey := fmt.Sprintf("%s:%d", proto, port)

		if strings.Contains(soapAction, "#AddPortMapping") {
			if port == 25565 && !staleConflictCleared {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode><errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
				return
			}
			if port == 8096 {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>606</errorCode><errorDescription>Action Not Authorized</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
				return
			}
			igdv2Rules[ruleKey] = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>`))
			return
		}

		if strings.Contains(soapAction, "#AddAnyPortMapping") {
			igdv2Rules[ruleKey] = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(fmt.Sprintf(`<s:Envelope><s:Body><u:AddAnyPortMappingResponse><NewReservedPort>%d</NewReservedPort></u:AddAnyPortMappingResponse></s:Body></s:Envelope>`, port)))
			return
		}

		if strings.Contains(soapAction, "#DeletePortMapping") {
			if port == 25565 && !staleConflictCleared {
				staleConflictCleared = true
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>`))
				return
			}
			if routerRebooted || !igdv2Rules[ruleKey] {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>714</errorCode><errorDescription>NoSuchEntryInArray</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
				return
			}
			delete(igdv2Rules, ruleKey)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	})

	igdv2Srv := &http.Server{Handler: igdv2Mux}
	igdv2Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer igdv2Ln.Close()
	go func() { _ = igdv2Srv.Serve(igdv2Ln) }()
	defer igdv2Srv.Close()

	igdv2Ctrl := fmt.Sprintf("http://%s/ctl/IGDv2", igdv2Ln.Addr().String())
	igdv2Endpoints := []upnpEndpoint{{
		ctrlURL:     igdv2Ctrl,
		serviceType: "urn:schemas-upnp-org:service:WANIPConnection:2",
	}}
	mappedIGDv2 := autoForwardRouterPortsWithEndpoints("192.168.1.50", []PortMapping{
		{PublicPort: 25565, TargetPort: 25565, Proto: "tcp"},
		{PublicPort: 8096, TargetPort: 8096, Proto: "tcp"},
	}, "", "", igdv2Endpoints, "")
	if mappedIGDv2 != 2 {
		t.Fatalf("expected 2 ports mapped across 718 conflict recovery and IGDv2 AddAnyPortMapping, got %d", mappedIGDv2)
	}

	// Simulate router reboot wiping its internal table so DeletePortMapping returns 714 NoSuchEntryInArray
	routerMu.Lock()
	routerRebooted = true
	igdv2Rules = make(map[string]bool)
	routerMu.Unlock()

	removedAfterReboot, cleanErr := cleanupActiveUPnPMappings()
	if cleanErr != nil || removedAfterReboot != 2 {
		t.Fatalf("expected 714 NoSuchEntryInArray after router reboot to be treated as idempotent success (removed=%d, err=%v)", removedAfterReboot, cleanErr)
	}
	if _, err := os.Stat(upnpStateFile); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be removed after 714 NoSuchEntryInArray cleanup", upnpStateFile)
	}

	// Apple / Ubiquiti / FreeBSD RFC 6886 NAT-PMP v0 UDP router simulation
	natpmpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer natpmpConn.Close()
	var natpmpMu sync.Mutex
	natpmpActive := make(map[string]bool)
	go func() {
		var buf [64]byte
		for {
			n, raddr, err := natpmpConn.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if n < 12 || buf[0] != 0 {
				continue
			}
			op := buf[1]
			intPort := binary.BigEndian.Uint16(buf[4:6])
			extPort := binary.BigEndian.Uint16(buf[6:8])
			lifetime := binary.BigEndian.Uint32(buf[8:12])
			proto := "TCP"
			if op == 1 {
				proto = "UDP"
			}
			key := fmt.Sprintf("%s:%d", proto, intPort)
			natpmpMu.Lock()
			if lifetime == 0 {
				delete(natpmpActive, key)
			} else {
				natpmpActive[key] = true
			}
			natpmpMu.Unlock()

			var resp [16]byte
			resp[0] = 0
			resp[1] = 128 + op
			binary.BigEndian.PutUint16(resp[2:4], 0) // ResultCode 0 (Success)
			binary.BigEndian.PutUint32(resp[4:8], 1000)
			binary.BigEndian.PutUint16(resp[8:10], intPort)
			binary.BigEndian.PutUint16(resp[10:12], extPort)
			binary.BigEndian.PutUint32(resp[12:16], lifetime)
			_, _ = natpmpConn.WriteToUDP(resp[:], raddr)
		}
	}()

	natpmpGW := natpmpConn.LocalAddr().String()
	mappedNATPMP := autoForwardRouterPortsWithEndpoints("192.168.1.50", []PortMapping{
		{PublicPort: 27015, TargetPort: 27015, Proto: "both"},
	}, "", "", nil, natpmpGW)
	if mappedNATPMP != 2 {
		t.Fatalf("expected 2 NAT-PMP rules (TCP+UDP 27015), got %d", mappedNATPMP)
	}
	natpmpMu.Lock()
	if !natpmpActive["TCP:27015"] || !natpmpActive["UDP:27015"] {
		natpmpMu.Unlock()
		t.Fatalf("expected TCP:27015 and UDP:27015 active on NAT-PMP server, got %+v", natpmpActive)
	}
	natpmpMu.Unlock()
	if rem, err := cleanupActiveUPnPMappings(); err != nil || rem != 2 {
		t.Fatalf("expected 2 NAT-PMP rules cleaned up, got rem=%d err=%v", rem, err)
	}

	// MikroTik v7 / OPNsense / ISP CPE RFC 6887 PCP v2 UDP router simulation (rejects NAT-PMP v0 with ResultCode=1)
	pcpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer pcpConn.Close()
	var pcpMu sync.Mutex
	pcpActive := make(map[string][12]byte)
	go func() {
		var buf [128]byte
		for {
			n, raddr, err := pcpConn.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			// Reject NAT-PMP v0 with ResultCode = 1 (Unsupported Version) to trigger RFC 6887 PCP v2 fallback
			if n == 12 && buf[0] == 0 {
				var reject [16]byte
				reject[0] = 0
				reject[1] = 128 + buf[1]
				binary.BigEndian.PutUint16(reject[2:4], 1) // ResultCode 1 = Unsupported Version
				_, _ = pcpConn.WriteToUDP(reject[:], raddr)
				continue
			}
			if n < 60 || buf[0] != 2 || buf[1] != 1 {
				continue
			}
			lifetime := binary.BigEndian.Uint32(buf[4:8])
			var nonce [12]byte
			copy(nonce[:], buf[24:36])
			protoNum := buf[36]
			intPort := binary.BigEndian.Uint16(buf[40:42])
			extPort := binary.BigEndian.Uint16(buf[42:44])
			if extPort == 0 {
				extPort = intPort
			}
			proto := "TCP"
			if protoNum == 17 {
				proto = "UDP"
			}
			key := fmt.Sprintf("%s:%d", proto, intPort)

			pcpMu.Lock()
			if lifetime == 0 {
				// Verify persisted RFC 6887 random 96-bit Mapping Nonce matches creation nonce
				if savedNonce, exists := pcpActive[key]; exists && savedNonce == nonce {
					delete(pcpActive, key)
				}
			} else {
				pcpActive[key] = nonce
			}
			pcpMu.Unlock()

			var resp [60]byte
			copy(resp[:], buf[:60])
			resp[0] = 2
			resp[1] = 0x81 // R=1 Response, Opcode=1 MAP
			resp[3] = 0    // Success
			binary.BigEndian.PutUint16(resp[42:44], extPort)
			_, _ = pcpConn.WriteToUDP(resp[:], raddr)
		}
	}()

	pcpGW := pcpConn.LocalAddr().String()
	mappedPCP := autoForwardRouterPortsWithEndpoints("192.168.1.50", []PortMapping{
		{PublicPort: 51820, TargetPort: 51820, Proto: "both"},
	}, "", "", nil, pcpGW)
	if mappedPCP != 2 {
		t.Fatalf("expected 2 PCP v2 rules (TCP+UDP 51820) after NAT-PMP v0 fallback, got %d", mappedPCP)
	}
	pcpMu.Lock()
	if len(pcpActive) != 2 {
		pcpMu.Unlock()
		t.Fatalf("expected 2 active PCP v2 mappings on router, got %d", len(pcpActive))
	}
	pcpMu.Unlock()

	// Simulate renewal preserving the exact random 96-bit Mapping Nonce
	renewedPCP := autoForwardRouterPortsWithEndpoints("192.168.1.50", []PortMapping{
		{PublicPort: 51820, TargetPort: 51820, Proto: "both"},
	}, "", "", nil, pcpGW)
	if renewedPCP != 2 {
		t.Fatalf("expected 2 PCP v2 rules renewed, got %d", renewedPCP)
	}

	// Simulate crash recovery cleanup for PCP v2 (verifying persisted 96-bit Mapping Nonce deletes rules)
	upnpStateMu.Lock()
	activeUPnPMappings = nil
	upnpStateMu.Unlock()
	pcpRecovered, pcpErr := cleanupStaleUPnPState()
	pcpMu.Lock()
	remainingPCP := len(pcpActive)
	pcpMu.Unlock()
	if pcpErr != nil || pcpRecovered != 2 || remainingPCP != 0 {
		t.Fatalf("expected PCP v2 mappings to be recovered and deleted with matching persisted 96-bit nonce (recovered=%d, remaining=%d, err=%v)", pcpRecovered, remainingPCP, pcpErr)
	}

	// Concurrent stress test across lock manager, XML parser, state salvage, and channel-bound HMACs
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := 0; iter < 10; iter++ {
				_ = parseUPnPDescriptionXML("http://192.168.1.1:1900/igd.xml", nil, rawXML)
				_ = discoverCandidateGatewayIPs("192.168.1.50", eps)
				_ = withUPnPStateFileLock(func() error {
					return nil
				})
			}
		}(worker)
	}
	wg.Wait()
}

func TestTLSManagerUDPReplayFreshnessAndSmartPortBridge(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Verify SNICertManager Root CA persistence and on-the-fly leaf certificate signing
	sniMgr, err := newSNICertManager(tmpDir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sniMgr.caPEM) == 0 || len(sniMgr.caFingerprint) != 64 {
		t.Fatalf("expected SNICertManager to persist Root CA PEM and 64-char SHA-256 fingerprint")
	}
	cert, err := sniMgr.getCertificate(&tls.ClientHelloInfo{ServerName: "mypc.duckdns.org"})
	if err != nil || cert == nil {
		t.Fatalf("expected SNICertManager to issue certificate for mypc.duckdns.org, got err=%v", err)
	}

	// 2. Verify 2-second UDP replay freshness window drops stale UDP packets while replaying fresh ones
	us := &gwUDPSession{id: 901, targetPort: 51820}
	us.mu.Lock()
	us.enqueuePacketLocked([]byte("stale-udp-pkt"))
	us.pendingAt[0] = time.Now().Add(-3 * time.Second) // older than maxUDPReplayAge (2s)
	us.enqueuePacketLocked([]byte("fresh-udp-pkt"))
	det := us.detachPendingForReplayLocked()
	us.mu.Unlock()
	if len(det) != 1 || string(det[0]) != "fresh-udp-pkt" {
		t.Fatalf("expected stale UDP packet (>2s) to be dropped and only fresh-udp-pkt retained, got %d packets", len(det))
	}
	globalUDPBufferedBytes.Add(-int64(len(det[0])))

	// 3. Verify Smart Ephemeral Port Bridging in Standalone Mode when TargetPort is already bound
	backendLn, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	occupiedPort := uint16(backendLn.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("BRIDGED-OK"))
			}(conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridgeMappings := []PortMapping{
		{BindIP: "0.0.0.0", PublicPort: occupiedPort, TargetPort: occupiedPort, Proto: "tcp"},
	}
	if err := startStandaloneTCP(ctx, "127.0.0.1", &bridgeMappings[0], nil, false); err != nil {
		t.Fatalf("expected startStandaloneTCP to succeed via ephemeral port bridging when port %d is occupied, got error: %v", occupiedPort, err)
	}
	bridgedPort := bridgeMappings[0].RouterTCPPort
	if bridgedPort == 0 || bridgedPort == occupiedPort {
		t.Fatalf("expected RouterTCPPort to be an ephemeral bridge port != %d, got %d", occupiedPort, bridgedPort)
	}

	dialConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", bridgedPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial ephemeral bridge port %d: %v", bridgedPort, err)
	}
	defer dialConn.Close()
	_ = dialConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	gotBridge, err := io.ReadAll(dialConn)
	if err != nil || string(gotBridge) != "BRIDGED-OK" {
		t.Fatalf("expected BRIDGED-OK through standalone ephemeral bridge port %d -> %d, got %q (err=%v)", bridgedPort, occupiedPort, string(gotBridge), err)
	}
}

func TestProductionChaosWANFlapsBackendRestartsAndRouterReboot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	prevTransport := defaultTransportMode
	defaultTransportMode = "tcp"
	defer func() {
		defaultTransportMode = prevTransport
	}()

	// 1. Local TCP echo server (simulating an active SSH/RDP/Website stream that must survive WAN flaps)
	tcpTargetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpTargetLn.Close()
	tcpTargetPort := uint16(tcpTargetLn.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := tcpTargetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. Local UDP game server that will be STOPPED and RESTARTED mid-session to verify 24/7 resilience
	udpTargetPort := uint16(getFreePort(t, "udp"))
	startLocalUDPServer := func(port uint16, tag string) *net.UDPConn {
		uaddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		uc, err := net.ListenUDP("udp", uaddr)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			buf := make([]byte, 2048)
			for {
				n, raddr, err := uc.ReadFromUDP(buf)
				if err != nil {
					return
				}
				reply := append([]byte(tag+":"), buf[:n]...)
				_, _ = uc.WriteToUDP(reply, raddr)
			}
		}()
		return uc
	}
	udpSrv1 := startLocalUDPServer(udpTargetPort, "v1")
	defer func() {
		if udpSrv1 != nil {
			_ = udpSrv1.Close()
		}
	}()

	gwPort := getFreePort(t, "tcp")
	pubTCPPort := uint16(getFreePort(t, "tcp"))
	pubUDPPort := uint16(getFreePort(t, "udp"))

	// Fault-injecting TCP WAN proxy between Agent and Gateway so we can sever the WAN link multiple times mid-stream
	wanProxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wanProxyLn.Close()

	var proxyMu sync.Mutex
	var activeWANConns []net.Conn
	severAllWANLinks := func() {
		proxyMu.Lock()
		conns := activeWANConns
		activeWANConns = nil
		proxyMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	}

	gwAddr := fmt.Sprintf("127.0.0.1:%d", gwPort)
	go func() {
		for {
			inC, err := wanProxyLn.Accept()
			if err != nil {
				return
			}
			outC, err := net.DialTimeout("tcp", gwAddr, 2*time.Second)
			if err != nil {
				_ = inC.Close()
				continue
			}
			proxyMu.Lock()
			activeWANConns = append(activeWANConns, inC, outC)
			proxyMu.Unlock()
			go pipeBidirectional(inC, outC)
		}
	}()

	mappings := []PortMapping{
		{PublicPort: pubTCPPort, TargetPort: tcpTargetPort, Proto: "tcp"},
		{PublicPort: pubUDPPort, TargetPort: udpTargetPort, Proto: "udp"},
	}

	certDir := t.TempDir()
	go func() {
		if err := runGateway(ctx, gwAddr, "chaos-secret-token", "", "", "", nil, mappings, 64*1024*1024, 8*1024*1024, 2*time.Second, 250*time.Millisecond, 30*time.Second, certDir, "", "", false, false); err != nil {
			log.Printf("[test] gateway on %s exited before shutdown: %v", gwAddr, err)
		}
	}()
	waitForTCPListener(t, gwAddr, 15*time.Second)

	go func() {
		_ = runAgent(ctx, wanProxyLn.Addr().String(), "127.0.0.1", "chaos-secret-token", "192.168.1.50", "", 8*1024*1024, 64*1024*1024, 2*time.Second, 250*time.Millisecond, 30*time.Second, nil)
	}()
	waitForTCPEchoReady(t, fmt.Sprintf("127.0.0.1:%d", pubTCPPort), 5*time.Second)

	// Part A: Stream 1.5 MiB over a single TCP connection while severing the WAN link twice mid-transfer
	clientConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubTCPPort), 3*time.Second)
	if err != nil {
		t.Fatalf("failed to dial public TCP port: %v", err)
	}
	defer clientConn.Close()

	totalBytes := 1536 * 1024
	sendPayload := make([]byte, totalBytes)
	_, _ = rand.Read(sendPayload)
	wantHash := sha256.Sum256(sendPayload)

	resumedBefore := metricResumedSessions.Load()
	phase1Done := make(chan struct{})
	phase2Done := make(chan struct{})
	writeErrCh := make(chan error, 1)

	go func() {
		// Phase 1: Write first 256 KiB and wait until reader confirms epoch #1 is actively streaming
		if _, wErr := clientConn.Write(sendPayload[:256*1024]); wErr != nil {
			writeErrCh <- wErr
			return
		}
		<-phase1Done

		// Flap #1: Sever the WAN tunnel mid-stream and write 640 KiB while the tunnel is reconnecting
		severAllWANLinks()
		if _, wErr := clientConn.Write(sendPayload[256*1024 : 896*1024]); wErr != nil {
			writeErrCh <- wErr
			return
		}
		<-phase2Done

		// Flap #2: Sever the WAN tunnel a second time on the same TCP session and write remaining 640 KiB
		severAllWANLinks()
		if _, wErr := clientConn.Write(sendPayload[896*1024:]); wErr != nil {
			writeErrCh <- wErr
			return
		}
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		writeErrCh <- nil
	}()

	_ = clientConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	receivedPayload := make([]byte, totalBytes)
	if _, err := io.ReadFull(clientConn, receivedPayload[:256*1024]); err != nil {
		t.Fatalf("Phase 1 TCP read failed: %v", err)
	}
	close(phase1Done)

	if _, err := io.ReadFull(clientConn, receivedPayload[256*1024:896*1024]); err != nil {
		t.Fatalf("Phase 2 TCP read across WAN flap #1 failed: %v", err)
	}
	close(phase2Done)

	if _, err := io.ReadFull(clientConn, receivedPayload[896*1024:]); err != nil {
		t.Fatalf("Phase 3 TCP read across WAN flap #2 failed: %v", err)
	}
	if wErr := <-writeErrCh; wErr != nil {
		t.Fatalf("TCP stream write failed: %v", wErr)
	}
	gotHash := sha256.Sum256(receivedPayload)
	if gotHash != wantHash {
		t.Fatalf("SHA-256 mismatch after multi-flap WAN outage: got %x, want %x", gotHash[:8], wantHash[:8])
	}
	if metricResumedSessions.Load() < resumedBefore+2 {
		t.Fatalf("expected metricResumedSessions to increment by at least 2 after 2 WAN flaps (before=%d, after=%d)", resumedBefore, metricResumedSessions.Load())
	}

	// Part B: Verify Local UDP Server Restart Resilience (ECONNREFUSED / WSAECONNREFUSED immunity)
	udpClient, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", pubUDPPort))
	if err != nil {
		t.Fatalf("failed to dial public UDP port: %v", err)
	}
	defer udpClient.Close()

	sendAndRecvUDP := func(msg, wantPrefix string) {
		for attempt := 0; attempt < 15; attempt++ {
			_, _ = udpClient.Write([]byte(msg))
			_ = udpClient.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			var rbuf [256]byte
			n, rErr := udpClient.Read(rbuf[:])
			if rErr == nil && strings.HasPrefix(string(rbuf[:n]), wantPrefix) {
				return
			}
		}
		t.Fatalf("failed to receive expected UDP reply %q for %q", wantPrefix, msg)
	}

	// 1) Initial UDP packet reaches v1 server
	sendAndRecvUDP("ping1", "v1:ping1")

	// 2) Stop the local UDP server and send packets while it is down (triggers ICMP Port Unreachable / ECONNREFUSED on connected UDP socket)
	_ = udpSrv1.Close()
	udpSrv1 = nil
	for i := 0; i < 4; i++ {
		_, _ = udpClient.Write([]byte("while-down"))
		time.Sleep(25 * time.Millisecond)
	}

	// 3) Restart the local UDP server on the exact same port (v2) and verify the existing UDP session immediately works without restarting driftless
	udpSrv2 := startLocalUDPServer(udpTargetPort, "v2")
	defer udpSrv2.Close()
	sendAndRecvUDP("ping2", "v2:ping2")
}

func TestMultiAgentSingleGatewayTCPUDPVHostsAndIsolation(t *testing.T) {
	prevTransport := defaultTransportMode
	defaultTransportMode = "tcp"
	defer func() {
		defaultTransportMode = prevTransport
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Start local services on 3 simulated Home PCs (pc1, pc2, pc3)
	// pc1: HTTP media server ("media.example.com") + dedicated TCP service
	pc1HTTPPort := uint16(getFreePort(t, "tcp"))
	pc1TCPPort := uint16(getFreePort(t, "tcp"))
	pc1PubTCPPort := uint16(getFreePort(t, "tcp"))

	// pc2: HTTP website ("site.example.com") + dedicated TCP service
	pc2HTTPPort := uint16(getFreePort(t, "tcp"))
	pc2TCPPort := uint16(getFreePort(t, "tcp"))
	pc2PubTCPPort := uint16(getFreePort(t, "tcp"))

	// pc3: HTTP game status ("game.example.com") + UDP game server
	pc3HTTPPort := uint16(getFreePort(t, "tcp"))
	pc3UDPPort := uint16(getFreePort(t, "udp"))
	pc3PubUDPPort := uint16(getFreePort(t, "udp"))

	startHTTPBackend := func(port uint16, nodeTag string) *http.Server {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = fmt.Fprintf(w, "NODE=%s HOST=%s PATH=%s", nodeTag, r.Host, r.URL.Path)
			}),
		}
		go func() { _ = srv.Serve(ln) }()
		return srv
	}

	startTCPBackend := func(port uint16, nodeTag string) net.Listener {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					buf, _ := io.ReadAll(conn)
					_, _ = fmt.Fprintf(conn, "%s:%s", nodeTag, string(buf))
				}(c)
			}
		}()
		return ln
	}

	startUDPBackend := func(port uint16, nodeTag string) *net.UDPConn {
		uaddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		uc, err := net.ListenUDP("udp", uaddr)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			var buf [2048]byte
			for {
				n, raddr, err := uc.ReadFromUDP(buf[:])
				if err != nil {
					return
				}
				reply := fmt.Sprintf("%s:%s", nodeTag, string(buf[:n]))
				_, _ = uc.WriteToUDP([]byte(reply), raddr)
			}
		}()
		return uc
	}

	srv1 := startHTTPBackend(pc1HTTPPort, "pc1")
	defer srv1.Close()
	srv2 := startHTTPBackend(pc2HTTPPort, "pc2")
	defer srv2.Close()
	srv3 := startHTTPBackend(pc3HTTPPort, "pc3")
	defer srv3.Close()

	tcpLn1 := startTCPBackend(pc1TCPPort, "pc1")
	defer tcpLn1.Close()
	tcpLn2 := startTCPBackend(pc2TCPPort, "pc2")
	defer tcpLn2.Close()
	udpConn3 := startUDPBackend(pc3UDPPort, "pc3")
	defer udpConn3.Close()

	// 2. Start a single VPS Gateway with shared HTTP vhost listener
	gwTunnelPort := getFreePort(t, "tcp")
	gwHTTPPort := getFreePort(t, "tcp")
	gwAddr := fmt.Sprintf("127.0.0.1:%d", gwTunnelPort)
	httpBindAddr := fmt.Sprintf("127.0.0.1:%d", gwHTTPPort)

	go func() {
		if err := runGateway(
			ctx,
			gwAddr,
			"multi-node-secret-token",
			"",
			httpBindAddr,
			"",
			nil,
			nil,
			64*1024*1024,
			8*1024*1024,
			2*time.Second,
			250*time.Millisecond,
			30*time.Second,
			t.TempDir(),
			"",
			"",
			false,
			false,
		); err != nil {
			log.Printf("[test] gateway on %s exited before shutdown: %v", gwAddr, err)
		}
	}()

	// Wait deterministically until Gateway's tunnel listener and HTTP VHost listener are actually ready
	waitForTCPListener(t, gwAddr, 15*time.Second)
	waitForTCPListener(t, httpBindAddr, 15*time.Second)

	// Helper to query HTTP vhost through the shared Gateway HTTP port
	checkVHost := func(hostHeader, path, wantSubstr string) error {
		client := &http.Client{Timeout: 1500 * time.Millisecond}
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s%s", httpBindAddr, path), nil)
		if err != nil {
			return err
		}
		req.Host = hostHeader
		req.Close = true
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), wantSubstr) {
			return fmt.Errorf("status=%d body=%q (want %q)", resp.StatusCode, string(body), wantSubstr)
		}
		return nil
	}

	// Helper to test dedicated TCP port forwarding
	checkTCPPort := func(pubPort uint16, payload, wantReply string) error {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), 1500*time.Millisecond)
		if err != nil {
			return err
		}
		defer c.Close()
		if _, err := c.Write([]byte(payload)); err != nil {
			return err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		got, err := io.ReadAll(c)
		if err != nil || string(got) != wantReply {
			return fmt.Errorf("err=%v got=%q want=%q", err, string(got), wantReply)
		}
		return nil
	}

	// Helper to test dedicated UDP port forwarding
	checkUDPPort := func(pubPort uint16, payload, wantReply string) error {
		uc, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", pubPort))
		if err != nil {
			return err
		}
		defer uc.Close()
		for attempt := 0; attempt < 10; attempt++ {
			_, _ = uc.Write([]byte(payload))
			_ = uc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			var buf [256]byte
			n, rErr := uc.Read(buf[:])
			if rErr == nil && string(buf[:n]) == wantReply {
				return nil
			}
		}
		return fmt.Errorf("failed to receive UDP reply %q on port %d", wantReply, pubPort)
	}

	waitUntilReady := func(desc string, fn func() error) {
		t.Helper()
		deadline := time.Now().Add(6 * time.Second)
		var lastErr error
		for time.Now().Before(deadline) {
			if err := fn(); err == nil {
				return
			} else {
				lastErr = err
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s: %v", desc, lastErr)
	}

	// 3. Connect 3 concurrent Agents (pc1, pc2, pc3) to the same Gateway, each registering its own vhosts and TCP/UDP ports
	pc1Ctx, pc1Cancel := context.WithCancel(ctx)
	defer pc1Cancel()
	pc2Ctx, pc2Cancel := context.WithCancel(ctx)
	defer pc2Cancel()
	pc3Ctx, pc3Cancel := context.WithCancel(ctx)
	defer pc3Cancel()

	startPC1Agent := func(agentCtx context.Context) {
		go func() {
			_ = runAgentWithServices(
				agentCtx,
				"pc1",
				gwAddr,
				"127.0.0.1",
				"multi-node-secret-token",
				"192.168.1.101",
				"",
				[]PortMapping{{PublicPort: pc1PubTCPPort, TargetPort: pc1TCPPort, Proto: "tcp"}},
				[]VHostRoute{{Domain: "media.example.com", NodeID: "pc1", TargetPort: pc1HTTPPort}},
				8*1024*1024,
				64*1024*1024,
				2*time.Second,
				250*time.Millisecond,
				30*time.Second,
				nil,
			)
		}()
	}

	startPC1Agent(pc1Ctx)
	go func() {
		_ = runAgentWithServices(
			pc2Ctx,
			"pc2",
			gwAddr,
			"127.0.0.1",
			"multi-node-secret-token",
			"192.168.1.102",
			"",
			[]PortMapping{{PublicPort: pc2PubTCPPort, TargetPort: pc2TCPPort, Proto: "tcp"}},
			[]VHostRoute{{Domain: "site.example.com", NodeID: "pc2", TargetPort: pc2HTTPPort}},
			8*1024*1024,
			64*1024*1024,
			2*time.Second,
			250*time.Millisecond,
			30*time.Second,
			nil,
		)
	}()
	go func() {
		_ = runAgentWithServices(
			pc3Ctx,
			"pc3",
			gwAddr,
			"127.0.0.1",
			"multi-node-secret-token",
			"192.168.1.103",
			"",
			[]PortMapping{{PublicPort: pc3PubUDPPort, TargetPort: pc3UDPPort, Proto: "udp"}},
			[]VHostRoute{{Domain: "game.example.com", NodeID: "pc3", TargetPort: pc3HTTPPort}},
			8*1024*1024,
			64*1024*1024,
			2*time.Second,
			250*time.Millisecond,
			30*time.Second,
			nil,
		)
	}()

	// 4. Wait for actual readiness of each Agent's routes and verify all 3 Agents work simultaneously through the single Gateway
	waitUntilReady("pc1 vhost", func() error {
		return checkVHost("media.example.com", "/stream", "NODE=pc1 HOST=media.example.com PATH=/stream")
	})
	waitUntilReady("pc2 vhost", func() error {
		return checkVHost("site.example.com", "/index", "NODE=pc2 HOST=site.example.com PATH=/index")
	})
	waitUntilReady("pc3 vhost", func() error {
		return checkVHost("game.example.com", "/status", "NODE=pc3 HOST=game.example.com PATH=/status")
	})
	waitUntilReady("pc1 TCP port", func() error {
		return checkTCPPort(pc1PubTCPPort, "hello-pc1", "pc1:hello-pc1")
	})
	waitUntilReady("pc2 TCP port", func() error {
		return checkTCPPort(pc2PubTCPPort, "hello-pc2", "pc2:hello-pc2")
	})
	waitUntilReady("pc3 UDP port", func() error {
		return checkUDPPort(pc3PubUDPPort, "udp-pkt-3", "pc3:udp-pkt-3")
	})

	// 5. Verify Public Port & VHost Conflict Detection and Traffic Isolation:
	// Connect a 4th rogue/misconfigured agent ("pc-conflict") that attempts to claim pc1's public TCP port,
	// pc3's public UDP port, and pc1's "media.example.com" VHost.
	// Gateway must report the conflict back to the agent and MUST NOT redirect pc1/pc3 traffic to pc-conflict.
	lastAgentAuthConflict.Store("")
	conflictCtx, conflictCancel := context.WithCancel(ctx)
	defer conflictCancel()
	go func() {
		_ = runAgentWithServices(
			conflictCtx,
			"pc-conflict",
			gwAddr,
			"127.0.0.1",
			"multi-node-secret-token",
			"192.168.1.199",
			"",
			[]PortMapping{
				{PublicPort: pc1PubTCPPort, TargetPort: pc2TCPPort, Proto: "tcp"},
				{PublicPort: pc3PubUDPPort, TargetPort: pc3UDPPort, Proto: "udp"},
			},
			[]VHostRoute{{Domain: "media.example.com", NodeID: "pc-conflict", TargetPort: pc2HTTPPort}},
			8*1024*1024,
			64*1024*1024,
			2*time.Second,
			250*time.Millisecond,
			30*time.Second,
			nil,
		)
	}()

	waitUntilReady("conflict notification from gateway", func() error {
		msg, _ := lastAgentAuthConflict.Load().(string)
		if !strings.Contains(msg, "media.example.com") || !strings.Contains(msg, fmt.Sprintf("port :%d", pc1PubTCPPort)) {
			return fmt.Errorf("expected conflict report for media.example.com and port :%d, got %q", pc1PubTCPPort, msg)
		}
		return nil
	})
	conflictCancel()

	// Verify traffic on pc1PubTCPPort and media.example.com still routes strictly to pc1 (never hijacked by pc-conflict)
	if err := checkVHost("media.example.com", "/check-isolation", "NODE=pc1 HOST=media.example.com PATH=/check-isolation"); err != nil {
		t.Fatalf("pc1 vhost was hijacked or broken after conflict attempt: %v", err)
	}
	if err := checkTCPPort(pc1PubTCPPort, "verify-owner", "pc1:verify-owner"); err != nil {
		t.Fatalf("pc1 TCP port was hijacked or broken after conflict attempt: %v", err)
	}

	// 6. Disconnect pc1 -> verify pc2 and pc3 continue working without any interruption
	pc1Cancel()
	waitUntilReady("pc1 disconnect detection", func() error {
		if err := checkVHost("media.example.com", "/should-503", "NODE=pc1"); err == nil {
			return fmt.Errorf("expected pc1 vhost to return 503 while pc1 is offline")
		}
		return nil
	})

	if err := checkVHost("site.example.com", "/still-alive", "NODE=pc2 HOST=site.example.com PATH=/still-alive"); err != nil {
		t.Fatalf("pc2 vhost failed after pc1 disconnected: %v", err)
	}
	if err := checkTCPPort(pc2PubTCPPort, "after-pc1-drop", "pc2:after-pc1-drop"); err != nil {
		t.Fatalf("pc2 TCP port failed after pc1 disconnected: %v", err)
	}
	if err := checkVHost("game.example.com", "/still-alive", "NODE=pc3 HOST=game.example.com PATH=/still-alive"); err != nil {
		t.Fatalf("pc3 vhost failed after pc1 disconnected: %v", err)
	}
	if err := checkUDPPort(pc3PubUDPPort, "udp-after-pc1-drop", "pc3:udp-after-pc1-drop"); err != nil {
		t.Fatalf("pc3 UDP port failed after pc1 disconnected: %v", err)
	}

	// 7. Reconnect pc1 -> verify pc1 automatically resumes serving vhost and TCP port
	pc1Ctx2, pc1Cancel2 := context.WithCancel(ctx)
	defer pc1Cancel2()
	startPC1Agent(pc1Ctx2)

	waitUntilReady("pc1 vhost after reconnect", func() error {
		return checkVHost("media.example.com", "/recovered", "NODE=pc1 HOST=media.example.com PATH=/recovered")
	})
	waitUntilReady("pc1 TCP port after reconnect", func() error {
		return checkTCPPort(pc1PubTCPPort, "reconnected-pc1", "pc1:reconnected-pc1")
	})
}

func TestProduction24x7WebsiteUnderLoadAndIPRotation(t *testing.T) {
	// 1. Mock RFC 5389 STUN server that dynamically rotates simulated WAN IPs
	stunConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer stunConn.Close()

	var currentSimulatedIP atomic.Value
	currentSimulatedIP.Store("198.51.100.10")

	go func() {
		var buf [512]byte
		for {
			n, raddr, err := stunConn.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint16(buf[0:2]) != 0x0001 {
				continue
			}
			ipStr := currentSimulatedIP.Load().(string)
			ip := net.ParseIP(ipStr).To4()
			var resp [32]byte
			binary.BigEndian.PutUint16(resp[0:2], 0x0101) // Binding Success Response
			binary.BigEndian.PutUint16(resp[2:4], 12)     // Attribute length
			binary.BigEndian.PutUint32(resp[4:8], 0x2112A442)
			copy(resp[8:20], buf[8:20])                     // Echo 12-byte Transaction ID
			binary.BigEndian.PutUint16(resp[20:22], 0x0020) // XOR-MAPPED-ADDRESS
			binary.BigEndian.PutUint16(resp[22:24], 8)
			resp[24] = 0
			resp[25] = 0x01 // IPv4
			cookie := [4]byte{0x21, 0x12, 0xA4, 0x42}
			binary.BigEndian.PutUint16(resp[26:28], uint16(raddr.Port)^0x2112)
			for i := 0; i < 4; i++ {
				resp[28+i] = ip[i] ^ cookie[i]
			}
			_, _ = stunConn.WriteToUDP(resp[:], raddr)
		}
	}()

	// 2. Mock DDNS webhook server recording every dynamic IP update
	var ddnsMu sync.Mutex
	var ddnsUpdates []string
	ddnsSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.URL.Query().Get("ip")
			ddnsMu.Lock()
			ddnsUpdates = append(ddnsUpdates, ip)
			ddnsMu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		}),
	}
	ddnsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ddnsLn.Close()
	go func() { _ = ddnsSrv.Serve(ddnsLn) }()
	defer ddnsSrv.Close()

	// 3. Local 24/7 Website backend
	siteLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer siteLn.Close()
	siteBackendPort := uint16(siteLn.Addr().(*net.TCPAddr).Port)
	var totalSiteHits atomic.Int64
	siteSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hit := totalSiteHits.Add(1)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintf(w, "SITE-ONLINE-HIT-%d", hit)
		}),
	}
	go func() { _ = siteSrv.Serve(siteLn) }()
	defer siteSrv.Close()

	pubSitePort := uint16(getFreePort(t, "tcp"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := StandaloneConfig{
		TargetHost:   "127.0.0.1",
		Mappings:     []PortMapping{{BindIP: "127.0.0.1", PublicPort: pubSitePort, TargetPort: siteBackendPort, Proto: "tcp"}},
		EnableUPnP:   false,
		EnableTLS:    false,
		STUNServer:   stunConn.LocalAddr().String(),
		STUNInterval: 250 * time.Millisecond,
		CertDir:      t.TempDir(),
		DDNS: DDNSConfig{
			Domain:  "mysite.duckdns.org",
			Webhook: fmt.Sprintf("http://%s/ddns?ip={ip}", ddnsLn.Addr().String()),
		},
	}

	doneStandalone := make(chan error, 1)
	go func() {
		doneStandalone <- runStandalone(ctx, cfg)
	}()
	waitForTCPListener(t, fmt.Sprintf("127.0.0.1:%d", pubSitePort), 15*time.Second)

	// 4. Hammer the website with 16 concurrent workers while rotating the ISP WAN IP 3 times
	var wg sync.WaitGroup
	var errCount atomic.Int32
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 2 * time.Second}
			for i := 0; i < 15; i++ {
				resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", pubSitePort))
				if err != nil {
					errCount.Add(1)
					continue
				}
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != 200 || !strings.HasPrefix(string(b), "SITE-ONLINE-HIT-") {
					errCount.Add(1)
				}
				time.Sleep(15 * time.Millisecond)
			}
		}()
	}

	// Rotate ISP WAN IP while traffic is actively flowing
	for _, nextIP := range []string{"198.51.100.11", "198.51.100.12", "198.51.100.13"} {
		time.Sleep(280 * time.Millisecond)
		currentSimulatedIP.Store(nextIP)
	}

	wg.Wait()
	time.Sleep(350 * time.Millisecond)
	cancel()
	<-doneStandalone

	if errCount.Load() != 0 {
		t.Fatalf("expected 0 HTTP errors during 24/7 website load + WAN IP rotations, got %d", errCount.Load())
	}
	if totalSiteHits.Load() < 240 {
		t.Fatalf("expected at least 240 successful website hits, got %d", totalSiteHits.Load())
	}

	ddnsMu.Lock()
	updates := append([]string(nil), ddnsUpdates...)
	ddnsMu.Unlock()
	if len(updates) < 2 || updates[len(updates)-1] != "198.51.100.13" {
		t.Fatalf("expected DDNS to automatically track IP rotations ending at 198.51.100.13, got updates=%v", updates)
	}

	// 5. Verify copyWithIdleTimeout cleans up abandoned half-open connections without leaking sockets
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	doneIdle := make(chan struct{})
	go func() {
		defer close(doneIdle)
		copyWithIdleTimeout(s1, s2, 60*time.Millisecond)
	}()
	select {
	case <-doneIdle:
	case <-time.After(1 * time.Second):
		t.Fatalf("expected copyWithIdleTimeout to terminate idle half-open connections within 60ms")
	}
}

func TestProductionStopRestartPersistenceAndReachabilityCheck(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	// 0. Domain classification separation: sslip.io vs DuckDNS vs custom user domain
	sslipCfg := resolveAndPersistDDNS(DDNSConfig{}, "auto")
	if sslipCfg.Domain != "auto" || sslipCfg.DomainKind != "ip-based (sslip.io)" {
		t.Fatalf("expected bare -duck without saved token to be classified as temporary ip-based (sslip.io), got %+v", sslipCfg)
	}
	if _, statErr := os.Stat(ddnsCacheFile); !os.IsNotExist(statErr) {
		t.Fatalf("temporary sslip.io configuration must NOT be persisted as a permanent user domain in %s", ddnsCacheFile)
	}

	// 1. First run: user passes '-duck mypc:secretDuckToken123'
	cfg1 := resolveAndPersistDDNS(DDNSConfig{}, "mypc:secretDuckToken123")
	if cfg1.Provider != "duckdns" || cfg1.Domain != "mypc.duckdns.org" || cfg1.Token != "secretDuckToken123" || cfg1.DomainKind != "ddns (duckdns)" {
		t.Fatalf("unexpected first-run DDNS config: %+v", cfg1)
	}

	// 2. Second run (after stopping and restarting PC): user passes bare '-duck' OR no flags at all
	cfg2 := resolveAndPersistDDNS(DDNSConfig{}, "auto")
	if cfg2.Provider != "duckdns" || cfg2.Domain != "mypc.duckdns.org" || cfg2.Token != "secretDuckToken123" || cfg2.DomainKind != "ddns (duckdns)" {
		t.Fatalf("expected bare '-duck' on restart to reload saved DuckDNS domain & token, got: %+v", cfg2)
	}
	cfgRestoredDefault := resolveAndPersistDDNS(DDNSConfig{}, "")
	if cfgRestoredDefault.Provider != "duckdns" || cfgRestoredDefault.Domain != "mypc.duckdns.org" || cfgRestoredDefault.Token != "secretDuckToken123" {
		t.Fatalf("expected restart without flags to restore saved DDNS config from %s, got: %+v", ddnsCacheFile, cfgRestoredDefault)
	}

	// Custom static domain classification
	customCfg := resolveAndPersistDDNS(DDNSConfig{Domain: "media.mycustomdomain.com"}, "")
	if customCfg.DomainKind != "custom-domain" {
		t.Fatalf("expected custom user domain to have DomainKind='custom-domain', got %q", customCfg.DomainKind)
	}

	// 3. Gateway token persistence across stop/restart
	tok1, err := loadOrGenerateToken(true, "", "")
	if err != nil || len(tok1) < 32 {
		t.Fatalf("expected loadOrGenerateToken to generate and persist token, got err=%v", err)
	}
	tok2, err := loadOrGenerateToken(true, "", "")
	if err != nil || tok1 != tok2 {
		t.Fatalf("expected loadOrGenerateToken on restart to reload identical token (%q != %q, err=%v)", tok1, tok2, err)
	}

	// 4. Honest External Reachability Verification:
	// Without an external probe, a local dial to our own IP must NEVER be reported as proof of internet reachability.
	if !isCGNATOrPrivateIP("100.64.12.34") || !isCGNATOrPrivateIP("10.0.0.1") || isCGNATOrPrivateIP("198.51.100.42") {
		t.Fatalf("unexpected CGNAT/private IP classification")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	closedPort := uint16(getFreePort(t, "tcp"))

	// Start a local UDP service via startStandaloneUDP to test UDP probe confirmation
	udpCtx, udpCancel := context.WithCancel(context.Background())
	defer udpCancel()
	udpBackendAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpBackend, err := net.ListenUDP("udp", udpBackendAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpBackend.Close()
	udpTargetPort := uint16(udpBackend.LocalAddr().(*net.UDPAddr).Port)
	openUDPPort := uint16(getFreePort(t, "udp"))
	udpMapping := PortMapping{BindIP: "127.0.0.1", PublicPort: openUDPPort, TargetPort: udpTargetPort, Proto: "udp"}
	if err := startStandaloneUDP(udpCtx, "127.0.0.1", &udpMapping); err != nil {
		t.Fatalf("startStandaloneUDP failed: %v", err)
	}

	// Also start a silent UDP service (ordinary UDP server that reads datagrams without replying to generic probes)
	silentUDPAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	silentUDPConn, err := net.ListenUDP("udp", silentUDPAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer silentUDPConn.Close()
	silentUDPPort := uint16(silentUDPConn.LocalAddr().(*net.UDPAddr).Port)
	closedUDPPort := uint16(getFreePort(t, "udp"))

	// 4a. Without external probe (-probe-url=""), checkExternalReachability must report local service OK
	// but explicitly mark ExternalStatus as "unverified-from-internet" ("не удалось проверить извне")
	repNoProbe := checkExternalReachabilityWithProbe("127.0.0.1", "127.0.0.1", DDNSConfig{}, []PortMapping{
		{PublicPort: openPort, TargetPort: openPort, Proto: "tcp"},
		{PublicPort: openUDPPort, TargetPort: udpTargetPort, Proto: "udp", RouterUDPPort: openUDPPort},
		{PublicPort: silentUDPPort, TargetPort: silentUDPPort, Proto: "udp"},
	}, "", 250*time.Millisecond)
	if repNoProbe.ExternalProbeUsed {
		t.Fatalf("expected ExternalProbeUsed=false when probeURL is empty")
	}
	if !strings.HasPrefix(repNoProbe.LocalServiceStatus[openPort], "ok") {
		t.Fatalf("expected LocalServiceStatus[%d] to be ok, got %q", openPort, repNoProbe.LocalServiceStatus[openPort])
	}
	if !strings.Contains(repNoProbe.ExternalStatus[openPort], "unverified-from-internet") || !strings.Contains(repNoProbe.PortStatus[openPort], "не удалось проверить извне") {
		t.Fatalf("expected honest unverified-from-internet status when no external probe is configured, got ExternalStatus=%q PortStatus=%q",
			repNoProbe.ExternalStatus[openPort], repNoProbe.PortStatus[openPort])
	}
	if !strings.Contains(repNoProbe.ExternalStatus[openUDPPort], "unverified-from-internet") {
		t.Fatalf("expected UDP port without probe to report unverified-from-internet, got %q", repNoProbe.ExternalStatus[openUDPPort])
	}
	if !strings.HasPrefix(repNoProbe.LocalServiceStatus[silentUDPPort], "open|silent") {
		t.Fatalf("expected silent UDP service on :%d to report open|silent locally, got %q", silentUDPPort, repNoProbe.LocalServiceStatus[silentUDPPort])
	}

	// 4b. With an independent external probe server (handleExternalProbeHTTP), TCP and UDP (confirmed, silent, and closed) are accurately classified
	probeMux := http.NewServeMux()
	probeMux.HandleFunc("/probe", handleExternalProbeHTTP)
	probeMux.HandleFunc("/gw-probe", func(w http.ResponseWriter, r *http.Request) {
		serveExternalProbeHTTP(w, r, []string{"gw-probe-secret-token"}, nil, true)
	})
	probeSrv := &http.Server{Handler: probeMux}
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probeLn.Close()
	go func() { _ = probeSrv.Serve(probeLn) }()
	defer probeSrv.Close()
	probeURL := fmt.Sprintf("http://%s/probe", probeLn.Addr().String())
	gwProbeURL := fmt.Sprintf("http://%s/gw-probe", probeLn.Addr().String())

	repWithProbe := checkExternalReachabilityWithProbe("127.0.0.1", "127.0.0.1", DDNSConfig{}, []PortMapping{
		{PublicPort: openPort, TargetPort: openPort, Proto: "tcp"},
		{PublicPort: closedPort, TargetPort: closedPort, Proto: "tcp"},
		{PublicPort: openUDPPort, TargetPort: udpTargetPort, Proto: "udp", RouterUDPPort: openUDPPort},
		{PublicPort: silentUDPPort, TargetPort: silentUDPPort, Proto: "udp"},
		{PublicPort: closedUDPPort, TargetPort: closedUDPPort, Proto: "udp"},
	}, probeURL, 250*time.Millisecond)

	if !repWithProbe.ExternalProbeUsed {
		t.Fatalf("expected ExternalProbeUsed=true when probeURL is provided")
	}
	if !strings.HasPrefix(repWithProbe.ExternalStatus[openPort], "verified-from-internet") || !strings.HasPrefix(repWithProbe.PortStatus[openPort], "reachable") {
		t.Fatalf("expected open TCP port %d with external probe to be verified-from-internet, got ExternalStatus=%q PortStatus=%q",
			openPort, repWithProbe.ExternalStatus[openPort], repWithProbe.PortStatus[openPort])
	}
	if !strings.HasPrefix(repWithProbe.ExternalStatus[closedPort], "unreachable-from-internet") || strings.HasPrefix(repWithProbe.PortStatus[closedPort], "reachable") {
		t.Fatalf("expected closed TCP port %d with external probe to be unreachable-from-internet, got ExternalStatus=%q PortStatus=%q",
			closedPort, repWithProbe.ExternalStatus[closedPort], repWithProbe.PortStatus[closedPort])
	}
	if !strings.HasPrefix(repWithProbe.ExternalStatus[openUDPPort], "verified-from-internet") || !strings.HasPrefix(repWithProbe.PortStatus[openUDPPort], "reachable") {
		t.Fatalf("expected open UDP port %d with external probe response confirmation to be verified-from-internet, got ExternalStatus=%q PortStatus=%q",
			openUDPPort, repWithProbe.ExternalStatus[openUDPPort], repWithProbe.PortStatus[openUDPPort])
	}
	// Ordinary silent UDP service must report unconfirmed-udp rather than unreachable-from-internet
	if !strings.HasPrefix(repWithProbe.ExternalStatus[silentUDPPort], "unconfirmed-udp") {
		t.Fatalf("expected silent UDP service on :%d to report unconfirmed-udp rather than unreachable, got ExternalStatus=%q",
			silentUDPPort, repWithProbe.ExternalStatus[silentUDPPort])
	}
	// Closed UDP port: Linux delivers ICMP Port Unreachable (unreachable-from-internet), whereas Windows
	// may suppress ICMP on UDP and time out (unconfirmed-udp). In both cases it must never be verified/reachable.
	closedUDPExt := repWithProbe.ExternalStatus[closedUDPPort]
	if !strings.HasPrefix(closedUDPExt, "unreachable-from-internet") && !strings.HasPrefix(closedUDPExt, "unconfirmed-udp") {
		t.Fatalf("expected closed UDP port %d to report unreachable-from-internet or unconfirmed-udp, got ExternalStatus=%q",
			closedUDPPort, closedUDPExt)
	}
	if strings.HasPrefix(repWithProbe.PortStatus[closedUDPPort], "reachable") {
		t.Fatalf("expected closed UDP port %d PortStatus not to be reachable, got %q",
			closedUDPPort, repWithProbe.PortStatus[closedUDPPort])
	}

	// 4c. Verify /probe SSRF & arbitrary third-party host scanning protection + Gateway token authentication
	httpClient := &http.Client{Timeout: 2 * time.Second}
	for _, forbiddenHost := range []string{"10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "8.8.8.8"} {
		resp, err := httpClient.Get(fmt.Sprintf("%s?proto=tcp&host=%s&port=%d", probeURL, forbiddenHost, openPort))
		if err != nil {
			t.Fatalf("probe request for forbidden host %s failed: %v", forbiddenHost, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected /probe to reject target host %s with 403 Forbidden, got HTTP %d", forbiddenHost, resp.StatusCode)
		}
	}

	// Gateway /gw-probe must reject unauthenticated or wrong-token requests with 401 Unauthorized
	unauthResp, err := httpClient.Get(fmt.Sprintf("%s?proto=tcp&host=127.0.0.1&port=%d", gwProbeURL, openPort))
	if err != nil {
		t.Fatalf("unauthenticated gw-probe request failed: %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated Gateway /probe request to return 401 Unauthorized, got HTTP %d", unauthResp.StatusCode)
	}

	// Gateway /gw-probe with valid token and caller-owned IP succeeds
	authResp, err := httpClient.Get(fmt.Sprintf("%s?proto=tcp&host=127.0.0.1&port=%d&token=gw-probe-secret-token", gwProbeURL, openPort))
	if err != nil {
		t.Fatalf("authenticated gw-probe request failed: %v", err)
	}
	_ = authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("expected authenticated Gateway /probe request for caller IP to return 200 OK, got HTTP %d", authResp.StatusCode)
	}
}

func TestDDNSAPIErrorHandlingAndStandaloneRouterRebootRecovery(t *testing.T) {
	// 1. Test DDNS API error handling (DuckDNS KO, No-IP badauth/nohost, Webhook error, invalid IP)
	if err := updateDDNS(DDNSConfig{Provider: "duckdns", Domain: "mypc.duckdns.org", Token: "tok"}, "not-an-ip"); err == nil {
		t.Fatalf("expected updateDDNS to reject invalid IP")
	}

	var webhookMode atomic.Value
	webhookMode.Store("KO")
	ddnsMockLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ddnsMockLn.Close()
	ddnsMockSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mode := webhookMode.Load().(string)
			switch mode {
			case "KO":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("KO"))
			case "badauth":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("badauth"))
			case "500":
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("server error"))
			default:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			}
		}),
	}
	go func() { _ = ddnsMockSrv.Serve(ddnsMockLn) }()
	defer ddnsMockSrv.Close()

	whCfg := DDNSConfig{
		Domain:  "mypc.duckdns.org",
		Webhook: fmt.Sprintf("http://%s/update?domain={domain}&ip={ip}", ddnsMockLn.Addr().String()),
	}
	if err := updateDDNS(whCfg, "198.51.100.25"); err == nil {
		t.Fatalf("expected updateDDNS to fail when DDNS server responds with 'KO'")
	}
	webhookMode.Store("badauth")
	if err := updateDDNS(whCfg, "198.51.100.25"); err == nil {
		t.Fatalf("expected updateDDNS to fail when DDNS server responds with 'badauth'")
	}
	webhookMode.Store("500")
	if err := updateDDNS(whCfg, "198.51.100.25"); err == nil {
		t.Fatalf("expected updateDDNS to fail when DDNS server responds with HTTP 500")
	}
	webhookMode.Store("OK")
	if err := updateDDNS(whCfg, "198.51.100.25"); err != nil {
		t.Fatalf("expected updateDDNS to succeed when DDNS server responds with 'OK', got %v", err)
	}

	// 2. Test automatic UPnP port re-mapping in runStandalone after Router Reboot & WAN Outage
	stunConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer stunConn.Close()

	var stunOnline atomic.Bool
	stunOnline.Store(true)
	var stunIP atomic.Value
	stunIP.Store("203.0.113.10")

	go func() {
		var buf [256]byte
		for {
			n, raddr, err := stunConn.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if !stunOnline.Load() || n < 20 {
				continue
			}
			ip := net.ParseIP(stunIP.Load().(string)).To4()
			var resp [32]byte
			binary.BigEndian.PutUint16(resp[0:2], 0x0101)
			binary.BigEndian.PutUint16(resp[2:4], 12)
			binary.BigEndian.PutUint32(resp[4:8], 0x2112A442)
			copy(resp[8:20], buf[8:20])
			binary.BigEndian.PutUint16(resp[20:22], 0x0020)
			binary.BigEndian.PutUint16(resp[22:24], 8)
			resp[24] = 0
			resp[25] = 0x01
			cookie := [4]byte{0x21, 0x12, 0xA4, 0x42}
			binary.BigEndian.PutUint16(resp[26:28], uint16(raddr.Port)^0x2112)
			for i := 0; i < 4; i++ {
				resp[28+i] = ip[i] ^ cookie[i]
			}
			_, _ = stunConn.WriteToUDP(resp[:], raddr)
		}
	}()

	var routerMu sync.Mutex
	routerPortTable := make(map[string]bool)
	routerAddCount := 0

	routerMux := http.NewServeMux()
	routerMux.HandleFunc("/ctl/IGD", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		bodyStr := string(bodyBytes)
		soapAction := r.Header.Get("SOAPAction")

		var port int
		var proto string
		if i := strings.Index(bodyStr, "<NewExternalPort>"); i >= 0 {
			_, _ = fmt.Sscanf(bodyStr[i:], "<NewExternalPort>%d</NewExternalPort>", &port)
		}
		if i := strings.Index(bodyStr, "<NewProtocol>"); i >= 0 {
			end := strings.Index(bodyStr[i:], "</NewProtocol>")
			if end > len("<NewProtocol>") {
				proto = strings.TrimSpace(bodyStr[i+len("<NewProtocol>") : i+end])
			}
		}
		key := fmt.Sprintf("%s:%d", proto, port)

		routerMu.Lock()
		defer routerMu.Unlock()
		if strings.Contains(soapAction, "#AddPortMapping") {
			routerPortTable[key] = true
			routerAddCount++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>`))
			return
		}
		if strings.Contains(soapAction, "#DeletePortMapping") {
			delete(routerPortTable, key)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	})
	routerSrv := &http.Server{Handler: routerMux}
	routerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer routerLn.Close()
	go func() { _ = routerSrv.Serve(routerLn) }()
	defer routerSrv.Close()

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	backendPort := uint16(backendLn.Addr().(*net.TCPAddr).Port)
	pubPort := uint16(getFreePort(t, "tcp"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := StandaloneConfig{
		TargetHost:          "127.0.0.1",
		Mappings:            []PortMapping{{BindIP: "127.0.0.1", PublicPort: pubPort, TargetPort: backendPort, Proto: "tcp"}},
		EnableUPnP:          true,
		STUNServer:          stunConn.LocalAddr().String(),
		STUNInterval:        80 * time.Millisecond,
		UPnPRefreshInterval: 150 * time.Millisecond,
		CertDir:             t.TempDir(),
		MockUPnPEndpoints: []upnpEndpoint{{
			ctrlURL:     fmt.Sprintf("http://%s/ctl/IGD", routerLn.Addr().String()),
			serviceType: "urn:schemas-upnp-org:service:WANIPConnection:1",
		}},
	}

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- runStandalone(ctx, cfg)
	}()

	ruleKey := fmt.Sprintf("TCP:%d", pubPort)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		routerMu.Lock()
		active := routerPortTable[ruleKey]
		routerMu.Unlock()
		if active {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	routerMu.Lock()
	if !routerPortTable[ruleKey] {
		routerMu.Unlock()
		t.Fatalf("expected initial UPnP rule %s to be created on router", ruleKey)
	}
	// Simulate router reboot + brief WAN outage wiping the router's port-forwarding table
	routerPortTable = make(map[string]bool)
	routerMu.Unlock()

	stunOnline.Store(false)
	time.Sleep(120 * time.Millisecond)
	stunIP.Store("203.0.113.11")
	stunOnline.Store(true)

	// Wait for runStandalone to detect WAN restoration / IP change and automatically re-apply the wiped UPnP rule
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		routerMu.Lock()
		reapplied := routerPortTable[ruleKey]
		routerMu.Unlock()
		if reapplied {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	routerMu.Lock()
	reapplied := routerPortTable[ruleKey]
	routerMu.Unlock()
	cancel()
	<-doneCh

	if !reapplied {
		t.Fatalf("expected runStandalone to automatically re-apply UPnP rule %s after router reboot and WAN recovery", ruleKey)
	}
}

func TestV156AuditFixesCertDirDynuProtoBothAndEviction(t *testing.T) {
	// 1. Custom -cert-dir token persistence and retrieval
	customCertDir := filepath.Join(t.TempDir(), "custom-certs")
	_ = os.Unsetenv("DRIFTLESS_TOKEN")
	tok1, err := loadOrGenerateTokenInDir(true, "", "", customCertDir)
	if err != nil || len(tok1) < 32 {
		t.Fatalf("loadOrGenerateTokenInDir failed: tok=%q err=%v", tok1, err)
	}
	if _, err := os.Stat(filepath.Join(customCertDir, "token.secret")); err != nil {
		t.Fatalf("expected token.secret in custom cert dir %s: %v", customCertDir, err)
	}
	tok2, err := loadOrGenerateTokenInDir(true, "", "", customCertDir)
	if err != nil || tok2 != tok1 {
		t.Fatalf("expected persisted token %q from custom cert dir, got %q (err=%v)", tok1, tok2, err)
	}
	if err := printSavedTokenAndCommandInDir(customCertDir); err != nil {
		t.Fatalf("printSavedTokenAndCommandInDir failed: %v", err)
	}

	// 2. Dynu DDNS provider validation
	if err := updateDDNS(DDNSConfig{Provider: "dynu", Domain: "", Token: ""}, "198.51.100.1"); err == nil {
		t.Fatalf("expected dynu updateDDNS with empty domain/token to return error")
	}

	// 3. Proto: "both" reachability check populates both TCP ExternalStatus and UDPStatus
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	bothPort := uint16(tcpLn.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	udpAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", bothPort))
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	go func() {
		buf := make([]byte, 256)
		for {
			n, raddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if bytes.HasPrefix(buf[:n], []byte(udpProbeMagicPrefix)) {
				nonce := string(buf[len(udpProbeMagicPrefix):n])
				_, _ = udpConn.WriteToUDP([]byte(udpProbeRespPrefix+nonce), raddr)
			}
		}
	}()

	directPort := getFreePort(t, "tcp")
	directAddr := fmt.Sprintf("127.0.0.1:%d", directPort)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hostVal atomic.Value
	hostVal.Store("myhome.example.com")
	startStandaloneDirectRedirector(ctx, directAddr, "127.0.0.1", &hostVal, []PortMapping{{PublicPort: bothPort, TargetPort: bothPort, Proto: "both"}}, true)

	probeURL := fmt.Sprintf("http://%s/probe", directAddr)
	rep := checkExternalReachabilityWithProbe("127.0.0.1", "127.0.0.1", DDNSConfig{}, []PortMapping{
		{PublicPort: bothPort, TargetPort: bothPort, Proto: "both"},
	}, probeURL, 300*time.Millisecond)
	if !strings.HasPrefix(rep.ExternalStatus[bothPort], "verified-from-internet") {
		t.Fatalf("expected TCP ExternalStatus on Proto=both port %d to be verified-from-internet, got %q", bothPort, rep.ExternalStatus[bothPort])
	}
	if !strings.HasPrefix(rep.UDPStatus[bothPort], "verified-from-internet") {
		t.Fatalf("expected UDPStatus on Proto=both port %d to be verified-from-internet, got %q", bothPort, rep.UDPStatus[bothPort])
	}

	// Verify DirectAddr HTTP 307 redirect
	noRedirClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 2 * time.Second,
	}
	resp, err := noRedirClient.Get(fmt.Sprintf("http://%s/dashboard", directAddr))
	if err != nil {
		t.Fatalf("direct redirector request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected HTTP 307 from standalone direct redirector, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, fmt.Sprintf("https://myhome.example.com:%d/dashboard", bothPort)) {
		t.Fatalf("unexpected redirect Location %q", loc)
	}

	// 4. Concurrent session status updates and FIFO RAM eviction safety
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	s := newSession(1, bothPort, c1, 4096, 8192, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			s.mu.Lock()
			s.lastActive = time.Now()
			s.mu.Unlock()
		}
	}()
	for i := 0; i < 50; i++ {
		_, _ = s.snapshotStatus()
	}
	<-done
	s.closeSession()
}

// getFreePort must never hand out a port number twice inside one test binary and must
// only hand out numbers that are bindable for BOTH TCP and UDP, because a gateway binds
// QUIC (UDP) and the agent TCP-mux fallback (TCP) on the same numeric port.
func TestFreePortAllocatorReservesBothProtocols(t *testing.T) {
	seen := make(map[int]bool)
	for i := 0; i < 200; i++ {
		network := "tcp"
		if i%2 == 0 {
			network = "udp"
		}
		port := getFreePort(t, network)
		if seen[port] {
			t.Fatalf("port %d handed out twice from %s allocation", port, network)
		}
		seen[port] = true
		for _, host := range []string{"0.0.0.0", "127.0.0.1"} {
			l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				t.Fatalf("port %d from %s allocation is not TCP-bindable on %s: %v", port, network, host, err)
			}
			_ = l.Close()
		}
		u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
		if err != nil {
			t.Fatalf("port %d from %s allocation is not UDP-bindable: %v", port, network, err)
		}
		_ = u.Close()
	}
}

// A port number still held by a listener must be rejected by the allocator probe. This is
// the class of Windows failure that made CI flake hard to read: the UDP probe picked a
// number, the TCP side could not bind it, the TCP-mux error was swallowed, and the test
// readiness wait ran into its timeout with no explanation. Both the wildcard and the
// loopback address are probed because Windows permits a specific-address bind alongside a
// wildcard bind, and Hyper-V/WinNAT reserved ranges (common on CI runners) reject binds
// with WSAEACCES.
func TestPortBindableRejectsHeldListener(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "127.0.0.1"} {
		held, err := net.Listen("tcp", host+":0")
		if err != nil {
			t.Fatal(err)
		}
		heldPort := held.Addr().(*net.TCPAddr).Port
		if portBindable("tcp", heldPort) {
			_ = held.Close()
			t.Fatalf("portBindable accepted TCP port %d on %s that is actively held by a listener", heldPort, host)
		}
		_ = held.Close()
		if !portBindable("tcp", heldPort) {
			t.Fatalf("portBindable rejected TCP port %d on %s after the listener was closed", heldPort, host)
		}
	}
}

// If the TCP-mux bind cannot be satisfied the gateway must keep serving QUIC and say so
// loudly instead of silently pretending both transports are up.
func TestGatewayDegradesToQUICOnlyWhenTCPMuxPortBusy(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", held.Addr().(*net.TCPAddr).Port)

	logBuf := &lockedLogBuffer{}
	prevWriter := log.Writer()
	log.SetOutput(logBuf)
	defer log.SetOutput(prevWriter)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runGateway(ctx, addr, "mux-conflict-token", "", "", "", nil, nil, 8*1024*1024, 1024*1024, time.Second, 200*time.Millisecond, 5*time.Second, t.TempDir(), "", "", false, false)
	}()
	select {
	case gwErr := <-done:
		cancel()
		t.Fatalf("gateway exited instead of degrading to QUIC-only: %v", gwErr)
	case <-time.After(3 * time.Second):
	}
	cancel()
	select {
	case gwErr := <-done:
		if gwErr != nil {
			t.Fatalf("gateway returned error on shutdown: %v", gwErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not shut down after context cancel")
	}

	out := logBuf.String()
	if !strings.Contains(out, "TCP-Mux listener on "+addr+" unavailable") {
		t.Fatalf("expected explicit TCP-Mux warning, got log:\n%s", out)
	}
	if !strings.Contains(out, "(QUIC, cert sha256:") {
		t.Fatalf("expected transport label to report QUIC-only, got log:\n%s", out)
	}
}

type lockedLogBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedLogBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLogBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestV158RouterStaleOverwriteLoopbackSTUNAndBlockedUDPFallback(t *testing.T) {
	// 1. Loopback STUN isolation: when pinned to 127.0.0.1:PORT and offline, querySTUNPublicIP must NOT leak to external internet
	closedSTUNPort := getFreePort(t, "udp")
	stunFailCount.Store(5)
	if ip, err := querySTUNPublicIP(fmt.Sprintf("127.0.0.1:%d", closedSTUNPort), 80*time.Millisecond); err == nil || ip != "" {
		t.Fatalf("expected loopback STUN failure to return error without external IP leak, got ip=%q err=%v", ip, err)
	}

	// 2. VPN/virtual adapter filtering and /16 + /24 candidate gateway discovery
	for _, vpnName := range []string{"wg0", "tun0", "tailscale0", "vEthernet (WSL)", "docker0", "radmin0", "vmnet8", "lo", "lo0"} {
		if !isVirtualOrVPNInterfaceName(vpnName) {
			t.Fatalf("expected %q to be classified as virtual/VPN interface", vpnName)
		}
	}
	for _, realName := range []string{"eth0", "en0", "wlan0", "Ethernet", "Wi-Fi", "Local Area Connection", "Local Area Connection 2"} {
		if isVirtualOrVPNInterfaceName(realName) {
			t.Fatalf("expected %q to be classified as physical LAN interface", realName)
		}
	}
	gws := discoverCandidateGatewayIPs("10.0.5.42", nil)
	found10001 := false
	for _, g := range gws {
		if g == "10.0.0.1" {
			found10001 = true
		}
	}
	if !found10001 {
		t.Fatalf("expected 10.0.0.1 in candidate gateways for 10.0.5.42, got %v", gws)
	}

	// 3. Router UPnP overwrite & ownership protection via GetSpecificPortMappingEntry:
	// - Port 8096: stale rule owned by driftless (127.0.0.1) returns 501 Action Failed -> verified via GetSpecificPortMappingEntry -> deleted & recreated.
	// - Port 9000: rule owned by another LAN device (192.168.1.250, "PlayStation 5") returns 501 Action Failed -> must NOT be deleted.
	// - Port 9001: router returns 606 Action Not Authorized -> must NOT trigger DeletePortMapping.
	var staleRuleDeleted atomic.Bool
	var foreignRuleDeleted atomic.Bool
	var authErrDeleted atomic.Bool
	var unsupportedGetDeleted atomic.Bool

	routerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer routerLn.Close()
	routerSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, _ := io.ReadAll(r.Body)
			bodyStr := string(bodyBytes)
			sa := r.Header.Get("SOAPAction")

			if strings.Contains(sa, "#GetSpecificPortMappingEntry") {
				switch {
				case strings.Contains(bodyStr, "<NewExternalPort>8096</NewExternalPort>"):
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:GetSpecificPortMappingEntryResponse><NewInternalPort>8096</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>driftless</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration></u:GetSpecificPortMappingEntryResponse></s:Body></s:Envelope>`))
				case strings.Contains(bodyStr, "<NewExternalPort>9000</NewExternalPort>"):
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:GetSpecificPortMappingEntryResponse><NewInternalPort>9000</NewInternalPort><NewInternalClient>192.168.1.250</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>PlayStation 5</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration></u:GetSpecificPortMappingEntryResponse></s:Body></s:Envelope>`))
				case strings.Contains(bodyStr, "<NewExternalPort>9002</NewExternalPort>"):
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>401</errorCode><errorDescription>Invalid Action</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
				default:
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>714</errorCode><errorDescription>NoSuchEntryInArray</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
				}
				return
			}
			if strings.Contains(sa, "#DeletePortMapping") {
				switch {
				case strings.Contains(bodyStr, "<NewExternalPort>8096</NewExternalPort>"):
					staleRuleDeleted.Store(true)
				case strings.Contains(bodyStr, "<NewExternalPort>9000</NewExternalPort>"):
					foreignRuleDeleted.Store(true)
				case strings.Contains(bodyStr, "<NewExternalPort>9001</NewExternalPort>"):
					authErrDeleted.Store(true)
				case strings.Contains(bodyStr, "<NewExternalPort>9002</NewExternalPort>"):
					unsupportedGetDeleted.Store(true)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>`))
				return
			}
			if strings.Contains(sa, "#AddPortMapping") {
				switch {
				case strings.Contains(bodyStr, "<NewExternalPort>8096</NewExternalPort>"):
					if !staleRuleDeleted.Load() {
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>501</errorCode><errorDescription>Action Failed</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
						return
					}
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>`))
					return
				case strings.Contains(bodyStr, "<NewExternalPort>9000</NewExternalPort>"), strings.Contains(bodyStr, "<NewExternalPort>9002</NewExternalPort>"):
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>501</errorCode><errorDescription>Action Failed</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
					return
				case strings.Contains(bodyStr, "<NewExternalPort>9001</NewExternalPort>"):
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>606</errorCode><errorDescription>Action Not Authorized</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
					return
				}
			}
			w.WriteHeader(http.StatusBadRequest)
		}),
	}
	go func() { _ = routerSrv.Serve(routerLn) }()
	defer routerSrv.Close()

	ctrlURL := fmt.Sprintf("http://%s/ctl/IGD", routerLn.Addr().String())
	if err := upnpAddPortMappingExtInt(ctrlURL, "urn:schemas-upnp-org:service:WANIPConnection:1", "127.0.0.1", 8096, 8096, "TCP"); err != nil {
		t.Fatalf("expected upnpAddPortMappingExtInt to recover from 501 Action Failed on own stale rule, got %v", err)
	}
	if !staleRuleDeleted.Load() {
		t.Fatalf("expected DeletePortMapping to be called on our own stale rule (port 8096)")
	}

	if err := upnpAddPortMappingExtInt(ctrlURL, "urn:schemas-upnp-org:service:WANIPConnection:1", "127.0.0.1", 9000, 9000, "TCP"); err == nil {
		t.Fatalf("expected foreign rule on port 9000 to fail without deleting another device's mapping")
	}
	if foreignRuleDeleted.Load() {
		t.Fatalf("expected DeletePortMapping NOT to be called when GetSpecificPortMappingEntry shows rule belongs to another LAN IP/device")
	}

	_ = upnpAddPortMappingExtInt(ctrlURL, "urn:schemas-upnp-org:service:WANIPConnection:1", "127.0.0.1", 9001, 9001, "TCP")
	if authErrDeleted.Load() {
		t.Fatalf("expected DeletePortMapping NOT to be called on 606 Action Not Authorized")
	}

	_ = upnpAddPortMappingExtInt(ctrlURL, "urn:schemas-upnp-org:service:WANIPConnection:1", "127.0.0.1", 9002, 9002, "TCP")
	if unsupportedGetDeleted.Load() {
		t.Fatalf("expected DeletePortMapping NOT to be called on 501 when GetSpecificPortMappingEntry is unsupported")
	}

	// 4. Blocked-UDP Fallback: when UDP packets to the Gateway port are dropped by the network,
	// an Agent in "auto" transport mode must automatically fall back to TCP-Mux and forward both TCP and UDP traffic.
	localTCPTarget, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localTCPTarget.Close()
	localTCPPort := uint16(localTCPTarget.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := localTCPTarget.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	localUDPTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localUDPTarget.Close()
	localUDPPort := uint16(localUDPTarget.LocalAddr().(*net.UDPAddr).Port)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := localUDPTarget.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = localUDPTarget.WriteTo(append([]byte("UDP-FALLBACK-OK:"), buf[:n]...), addr)
		}
	}()

	gwPort := getFreePort(t, "both")
	gwAddr := fmt.Sprintf("127.0.0.1:%d", gwPort)
	pubTCPPort := getFreePort(t, "tcp")
	pubUDPPort := getFreePort(t, "udp")

	// Start a proxy endpoint where UDP is completely blackholed (drops all packets) while TCP is forwarded to gwAddr
	proxyPort := getFreePort(t, "both")
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	blackholeUDP, err := net.ListenPacket("udp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer blackholeUDP.Close()
	tcpProxyLn, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpProxyLn.Close()
	go func() {
		for {
			inConn, err := tcpProxyLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				outConn, err := net.DialTimeout("tcp", gwAddr, 2*time.Second)
				if err != nil {
					return
				}
				defer outConn.Close()
				go func() { _, _ = io.Copy(outConn, c) }()
				_, _ = io.Copy(c, outConn)
			}(inConn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	prevTransport := defaultTransportMode
	defaultTransportMode = "auto"
	defer func() { defaultTransportMode = prevTransport }()

	certDir := t.TempDir()
	token := "v158-blocked-udp-fallback-token"
	mappings := []PortMapping{
		{BindIP: "127.0.0.1", PublicPort: uint16(pubTCPPort), TargetPort: localTCPPort, Proto: "tcp"},
		{BindIP: "127.0.0.1", PublicPort: uint16(pubUDPPort), TargetPort: localUDPPort, Proto: "udp"},
	}

	go func() {
		_ = runGateway(ctx, gwAddr, token, "", "", "", nil, mappings, 32*1024*1024, 4*1024*1024, 4*time.Second, 1*time.Second, 10*time.Second, certDir, "", "", false, false)
	}()
	waitForTCPListener(t, gwAddr, 3*time.Second)

	go func() {
		_ = runAgentWithServices(ctx, "pc-auto-fallback", proxyAddr, "127.0.0.1", token, "127.0.0.1", "", nil, nil, 4*1024*1024, 32*1024*1024, 4*time.Second, 1*time.Second, 10*time.Second, nil)
	}()

	// Verify TCP traffic succeeds after automatic fallback from blocked UDP (QUIC) to TCP-Mux
	var tcpOK bool
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubTCPPort), 300*time.Millisecond)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = c.Write([]byte("HELLO-OVER-TCPMUX"))
			buf := make([]byte, 32)
			n, rErr := c.Read(buf)
			_ = c.Close()
			if rErr == nil && string(buf[:n]) == "HELLO-OVER-TCPMUX" {
				tcpOK = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !tcpOK {
		t.Fatalf("expected agent in 'auto' mode to fall back to tcp-mux when UDP is blocked and forward TCP traffic")
	}

	// Verify UDP traffic is also encapsulated over TCP-Mux when UDP to Gateway is blocked
	udpClient, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", pubUDPPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	_ = udpClient.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := udpClient.Write([]byte("PING-UDP")); err != nil {
		t.Fatal(err)
	}
	ubuf := make([]byte, 128)
	un, err := udpClient.Read(ubuf)
	if err != nil || string(ubuf[:un]) != "UDP-FALLBACK-OK:PING-UDP" {
		t.Fatalf("expected UDP over tcp-mux fallback to return 'UDP-FALLBACK-OK:PING-UDP', got %q (err=%v)", string(ubuf[:un]), err)
	}
}


