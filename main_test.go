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
}


