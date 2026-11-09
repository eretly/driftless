package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// dialTCPWithRetry waits for the gateway to bind its public listeners. The
// gateway does a synchronous public-IP lookup before binding, so fixed sleeps
// are flaky on slow/blocked networks and under the race detector.
func dialTCPWithRetry(t *testing.T, addr string, timeout time.Duration) net.Conn {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			return c
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("dial %s failed after %v: %v", addr, timeout, lastErr)
	return nil
}

func getFreePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.ListenUDP("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
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

	go func() {
		_ = runGateway(ctx, quicAddr, "test-secret", "", vhostAddr, "", vhosts, mappings, 64*1024*1024, 4*1024*1024, 4*time.Second, 1*time.Second, 30*time.Second, "", "", "", false, false)
	}()

	time.Sleep(150 * time.Millisecond)

	go func() {
		_ = runAgent(ctx, quicAddr, "127.0.0.1", "test-secret", "192.168.1.50", "", 4*1024*1024, 64*1024*1024, 4*time.Second, 1*time.Second, 30*time.Second, nil)
	}()

	time.Sleep(300 * time.Millisecond)

	// Verify TCP
	clientTCP := dialTCPWithRetry(t, fmt.Sprintf("127.0.0.1:%d", publicTCPPort), 10*time.Second)
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

	// 1a. Local TCP echo server that keeps the connection open across multiple chunks
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

	// 1b. Local UDP echo server
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

	// 2. Simulated ISP router / NAT proxy between Agent and Gateway
	// Allows blacking out the link mid-transfer and rebinding to a new source UDP socket (simulating ISP IP/NAT change)
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
		_ = runGateway(ctx, gwAddr, "resume-secret", "", "", "", nil, mappings, 64*1024*1024, 4*1024*1024, 500*time.Millisecond, 150*time.Millisecond, 30*time.Second, t.TempDir(), "", "", false, false)
	}()
	time.Sleep(100 * time.Millisecond)

	go func() {
		_ = runAgent(ctx, proxyAddr, "127.0.0.1", "resume-secret", "192.168.1.50", "", 4*1024*1024, 64*1024*1024, 500*time.Millisecond, 150*time.Millisecond, 30*time.Second, nil)
	}()
	time.Sleep(250 * time.Millisecond)

	// 3. Open a long-lived TCP stream and UDP session before outage
	clientConn := dialTCPWithRetry(t, fmt.Sprintf("127.0.0.1:%d", publicTCPPort), 10*time.Second)
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

	// 4. Simulate ISP blackout + new external IP/port assignment while TCP & UDP sessions stay open
	doneBlackout := make(chan struct{})
	natMu <- func(st *natState) {
		st.blackout = true
		_ = st.gwConn.Close()
		close(doneBlackout)
	}
	<-doneBlackout

	// Wait well past the 500ms QUIC idle timeout so activeAgent is cleared even
	// when the race detector slows down timer/goroutine scheduling.
	time.Sleep(1500 * time.Millisecond)

	// Send UDP datagram and TCP Part 2 WHILE the home internet is completely down!
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

	// Restore ISP connection on a brand new UDP socket (simulating new dynamic IP after router reconnect)
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

	// 5. Read Part 2 from TCP and buffered datagram from UDP after automatic QUIC reconnect
	_ = clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	gotPart2, err := io.ReadAll(clientConn)
	if wErr := <-errCh; wErr != nil {
		t.Fatalf("write part2 during outage failed: %v", wErr)
	}
	if err != nil || !bytes.Equal(part2, gotPart2) {
		t.Fatalf("mid-stream session recovery failed after IP change: err=%v, got=%d bytes, want=%d bytes", err, len(gotPart2), len(part2))
	}

	_ = udpClient.SetReadDeadline(time.Now().Add(8 * time.Second))
	udpBuf := make([]byte, 128)
	un, uerr := udpClient.Read(udpBuf)
	if uerr != nil || !bytes.Equal(udpBuf[:un], udpOutagePkt) {
		t.Fatalf("buffered udp packet replay failed after IP change: err=%v, got=%q", uerr, string(udpBuf[:un]))
	}
}

func TestStandaloneRouterPortSpecsRespectAllowPorts(t *testing.T) {
	mappings := []PortMapping{
		{PublicPort: 8096, TargetPort: 8096, Proto: "both"},
		{PublicPort: 22, TargetPort: 22, Proto: "tcp"},
		{PublicPort: 27015, TargetPort: 27015, Proto: "udp"},
	}
	allowed := map[uint16]struct{}{8096: {}, 27015: {}}

	var filtered []PortMapping
	for _, m := range mappings {
		if isStandalonePortAllowed(allowed, m.TargetPort) {
			filtered = append(filtered, m)
		}
	}
	vhosts := map[string]uint16{"app.test": 8096, "ssh.test": 22}
	filteredVHosts := make(map[string]uint16)
	for k, port := range vhosts {
		if isStandalonePortAllowed(allowed, port) {
			filteredVHosts[k] = port
		}
	}

	specs := standaloneRouterPortSpecs(filtered, filteredVHosts, ":80", ":443")
	got := make(map[string]bool, len(specs))
	for _, sp := range specs {
		got[routerPortKey(sp.port, sp.proto)] = true
	}
	for _, want := range []string{"TCP:8096", "UDP:8096", "UDP:27015", "TCP:80", "TCP:443"} {
		if !got[want] {
			t.Fatalf("expected router forward %s, got %+v", want, specs)
		}
	}
	for _, banned := range []string{"TCP:22", "UDP:22", "TCP:27015"} {
		if got[banned] {
			t.Fatalf("router forward for disallowed port was created: %s", banned)
		}
	}

	// If every vhost target is filtered out, the vhost listeners never start,
	// so their ports must not be forwarded either.
	if specs := standaloneRouterPortSpecs(nil, nil, ":80", ":443"); len(specs) != 0 {
		t.Fatalf("expected no forwards without allowed listeners, got %+v", specs)
	}
}

func TestRouterPortForwarderPersistsState(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), upnpStateFile)
	f := newRouterPortForwarder(stateFile)
	f.track(routerPortForward{
		ControlURL:  "http://192.168.1.1:5000/ctl/IPConn",
		ServiceType: "urn:schemas-upnp-org:service:WANIPConnection:1",
		Port:        8096,
		Proto:       "TCP",
		InternalIP:  "192.168.1.20",
	})
	f.save()

	reloaded := newRouterPortForwarder(stateFile)
	if len(reloaded.records) != 1 {
		t.Fatalf("expected 1 persisted mapping, got %d", len(reloaded.records))
	}
	rec := reloaded.records[0]
	if rec.Port != 8096 || rec.Proto != "TCP" || rec.InternalIP != "192.168.1.20" {
		t.Fatalf("unexpected reloaded mapping: %+v", rec)
	}

	// An empty record set removes the state file so a later run does not try
	// to clean up mappings that no longer exist.
	reloaded.records = nil
	reloaded.save()
	if _, err := os.Stat(stateFile); !os.IsNotExist(err) {
		t.Fatalf("expected state file to be removed, got err=%v", err)
	}
}

func TestRouterPortForwarderCloseDeletesTrackedMappings(t *testing.T) {
	const serviceType = "urn:schemas-upnp-org:service:WANIPConnection:1"
	var mu sync.Mutex
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		deleted = append(deleted, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stateFile := filepath.Join(t.TempDir(), upnpStateFile)
	f := newRouterPortForwarder(stateFile)
	f.track(routerPortForward{
		ControlURL:  srv.URL,
		ServiceType: serviceType,
		Port:        25565,
		Proto:       "TCP",
		InternalIP:  "192.168.1.20",
	})
	f.save()
	f.Close()

	mu.Lock()
	got := append([]string(nil), deleted...)
	mu.Unlock()
	if len(got) != 1 || !strings.Contains(got[0], "<NewExternalPort>25565</NewExternalPort>") {
		t.Fatalf("expected one DeletePortMapping request for port 25565, got %v", got)
	}
	if _, err := os.Stat(stateFile); !os.IsNotExist(err) {
		t.Fatalf("expected state file to be removed after close, got err=%v", err)
	}
}

func TestUPnPDeletePortMappingSendsValidSOAP(t *testing.T) {
	const serviceType = "urn:schemas-upnp-org:service:WANIPConnection:1"
	var gotAction, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAction = r.Header.Get("SOAPAction")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := upnpDeletePortMapping(srv.URL, serviceType, 8096, "TCP"); err != nil {
		t.Fatalf("delete port mapping failed: %v", err)
	}
	if gotAction != `"`+serviceType+`#DeletePortMapping"` {
		t.Fatalf("unexpected SOAPAction: %q", gotAction)
	}
	for _, want := range []string{"<NewExternalPort>8096</NewExternalPort>", "<NewProtocol>TCP</NewProtocol>", "<NewRemoteHost></NewRemoteHost>"} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("SOAP body missing %q: %s", want, gotBody)
		}
	}
}
