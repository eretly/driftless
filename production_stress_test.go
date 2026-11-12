package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
		_ = runGateway(
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
		)
	}()
	time.Sleep(150 * time.Millisecond)

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
	time.Sleep(350 * time.Millisecond)

	// Helper to query HTTP vhost through the shared Gateway HTTP port
	checkVHost := func(hostHeader, path, wantSubstr string) error {
		client := &http.Client{Timeout: 3 * time.Second}
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
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), 3*time.Second)
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
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
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

	// 4. Verify all 3 Agents work simultaneously through the single Gateway
	if err := checkVHost("media.example.com", "/stream", "NODE=pc1 HOST=media.example.com PATH=/stream"); err != nil {
		t.Fatalf("pc1 vhost failed: %v", err)
	}
	if err := checkVHost("site.example.com", "/index", "NODE=pc2 HOST=site.example.com PATH=/index"); err != nil {
		t.Fatalf("pc2 vhost failed: %v", err)
	}
	if err := checkVHost("game.example.com", "/status", "NODE=pc3 HOST=game.example.com PATH=/status"); err != nil {
		t.Fatalf("pc3 vhost failed: %v", err)
	}
	if err := checkTCPPort(pc1PubTCPPort, "hello-pc1", "pc1:hello-pc1"); err != nil {
		t.Fatalf("pc1 TCP port failed: %v", err)
	}
	if err := checkTCPPort(pc2PubTCPPort, "hello-pc2", "pc2:hello-pc2"); err != nil {
		t.Fatalf("pc2 TCP port failed: %v", err)
	}
	if err := checkUDPPort(pc3PubUDPPort, "udp-pkt-3", "pc3:udp-pkt-3"); err != nil {
		t.Fatalf("pc3 UDP port failed: %v", err)
	}

	// 5. Disconnect pc1 -> verify pc2 and pc3 continue working without any interruption
	pc1Cancel()
	time.Sleep(250 * time.Millisecond)

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

	// 6. Reconnect pc1 -> verify pc1 automatically resumes serving vhost and TCP port
	pc1Ctx2, pc1Cancel2 := context.WithCancel(ctx)
	defer pc1Cancel2()
	startPC1Agent(pc1Ctx2)
	time.Sleep(350 * time.Millisecond)

	if err := checkVHost("media.example.com", "/recovered", "NODE=pc1 HOST=media.example.com PATH=/recovered"); err != nil {
		t.Fatalf("pc1 vhost failed after reconnect: %v", err)
	}
	if err := checkTCPPort(pc1PubTCPPort, "reconnected-pc1", "pc1:reconnected-pc1"); err != nil {
		t.Fatalf("pc1 TCP port failed after reconnect: %v", err)
	}
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
			copy(resp[8:20], buf[8:20])                    // Echo 12-byte Transaction ID
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
	time.Sleep(150 * time.Millisecond)

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

	// 1. First run: user passes '-duck mypc:secretDuckToken123'
	cfg1 := resolveAndPersistDDNS(DDNSConfig{}, "mypc:secretDuckToken123")
	if cfg1.Provider != "duckdns" || cfg1.Domain != "mypc.duckdns.org" || cfg1.Token != "secretDuckToken123" {
		t.Fatalf("unexpected first-run DDNS config: %+v", cfg1)
	}

	// 2. Second run (after stopping and restarting PC): user passes bare '-duck' (which CLI rewrites to '-duck=auto')
	cfg2 := resolveAndPersistDDNS(DDNSConfig{}, "auto")
	if cfg2.Provider != "duckdns" || cfg2.Domain != "mypc.duckdns.org" || cfg2.Token != "secretDuckToken123" {
		t.Fatalf("expected bare '-duck' on restart to reload saved DuckDNS domain & token, got: %+v", cfg2)
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

	// 4. External reachability & CGNAT detection (checkExternalReachability)
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

	repOpen := checkExternalReachability("127.0.0.1", "127.0.0.1", DDNSConfig{}, []PortMapping{
		{PublicPort: openPort, TargetPort: openPort, Proto: "tcp"},
	}, 500*time.Millisecond)
	if !strings.HasPrefix(repOpen.PortStatus[openPort], "reachable") {
		t.Fatalf("expected open TCP port %d to be reported reachable, got %q", openPort, repOpen.PortStatus[openPort])
	}

	repClosed := checkExternalReachability("127.0.0.1", "127.0.0.1", DDNSConfig{}, []PortMapping{
		{PublicPort: closedPort, TargetPort: closedPort, Proto: "tcp"},
	}, 300*time.Millisecond)
	if strings.HasPrefix(repClosed.PortStatus[closedPort], "reachable") {
		t.Fatalf("expected closed TCP port %d to be reported unreachable, got %q", closedPort, repClosed.PortStatus[closedPort])
	}
}
