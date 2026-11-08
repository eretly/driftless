package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
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
