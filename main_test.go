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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

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
		_ = runGateway(ctx, gwAddr, "resume-secret", "", "", "", nil, mappings, 64*1024*1024, 4*1024*1024, 500*time.Millisecond, 150*time.Millisecond, 30*time.Second, t.TempDir(), "", "", false, false)
	}()
	time.Sleep(100 * time.Millisecond)

	go func() {
		_ = runAgent(ctx, proxyAddr, "127.0.0.1", "resume-secret", "192.168.1.50", "", 4*1024*1024, 64*1024*1024, 500*time.Millisecond, 150*time.Millisecond, 30*time.Second, nil)
	}()
	time.Sleep(250 * time.Millisecond)

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

func TestTCPMuxFallbackTokenRotationAndIPACL(t *testing.T) {
	// IP/CIDR ACL filtering
	acl, err := parseIPACL("192.168.10.0/24, 203.0.113.99")
	if err != nil {
		t.Fatalf("parseIPACL failed: %v", err)
	}
	if !acl.AllowedAddr(&net.TCPAddr{IP: net.ParseIP("192.168.10.42"), Port: 5000}) {
		t.Fatalf("expected 192.168.10.42 to be allowed by CIDR 192.168.10.0/24")
	}
	if !acl.AllowedAddr(&net.TCPAddr{IP: net.ParseIP("203.0.113.99"), Port: 5000}) {
		t.Fatalf("expected 203.0.113.99 to be allowed by exact IP rule")
	}
	if acl.AllowedAddr(&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 5000}) {
		t.Fatalf("expected 198.51.100.7 to be rejected by IPACL")
	}

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
		_ = runGateway(ctx, gwAddr, "new-rotated-tok,legacy-agent-tok", "", "", "", nil, mappings, 32*1024*1024, 4*1024*1024, 4*time.Second, 1*time.Second, 30*time.Second, t.TempDir(), "", "", false, false)
	}()
	time.Sleep(120 * time.Millisecond)

	// Agent connects using "legacy-agent-tok" over TCP-Mux transport and includes an unreachable first gateway to test failover
	failoverAddrs := fmt.Sprintf("127.0.0.1:1,%s", gwAddr)
	go func() {
		_ = runAgent(ctx, failoverAddrs, "127.0.0.1", "legacy-agent-tok", "192.168.1.77", "", 4*1024*1024, 32*1024*1024, 4*time.Second, 1*time.Second, 30*time.Second, nil)
	}()
	time.Sleep(450 * time.Millisecond)

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
	} else if perm := fi.Mode().Perm(); perm != 0o600 {
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
		_ = runGateway(ctx1, gw1Addr, "ha-secret", "", "", "", nil, []PortMapping{
			{PublicPort: uint16(gw1PubPort), TargetPort: uint16(tcpTargetPort), Proto: "tcp"},
		}, 32*1024*1024, 4*1024*1024, 600*time.Millisecond, 150*time.Millisecond, 30*time.Second, t.TempDir(), "", "", false, false)
	}()
	go func() {
		_ = runGateway(ctx2, gw2Addr, "ha-secret", "", "", "", nil, []PortMapping{
			{PublicPort: uint16(gw2PubPort), TargetPort: uint16(tcpTargetPort), Proto: "tcp"},
		}, 32*1024*1024, 4*1024*1024, 600*time.Millisecond, 150*time.Millisecond, 30*time.Second, t.TempDir(), "", "", false, false)
	}()
	time.Sleep(150 * time.Millisecond)

	go func() {
		_ = runAgent(agentCtx, fmt.Sprintf("%s,%s", gw1Addr, gw2Addr), "127.0.0.1", "ha-secret", "192.168.1.90", "", 4*1024*1024, 32*1024*1024, 600*time.Millisecond, 150*time.Millisecond, 30*time.Second, nil)
	}()
	time.Sleep(300 * time.Millisecond)

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
	time.Sleep(900 * time.Millisecond)

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
				// Verify RFC 6887 deterministic 96-bit Mapping Nonce matches creation nonce
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

	// Simulate crash recovery cleanup for PCP v2 (verifying deterministic 96-bit Mapping Nonce deletes rules)
	upnpStateMu.Lock()
	activeUPnPMappings = nil
	upnpStateMu.Unlock()
	pcpRecovered, pcpErr := cleanupStaleUPnPState()
	pcpMu.Lock()
	remainingPCP := len(pcpActive)
	pcpMu.Unlock()
	if pcpErr != nil || pcpRecovered != 2 || remainingPCP != 0 {
		t.Fatalf("expected PCP v2 mappings to be recovered and deleted with matching 96-bit nonce (recovered=%d, remaining=%d, err=%v)", pcpRecovered, remainingPCP, pcpErr)
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


