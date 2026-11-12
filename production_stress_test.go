package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestProductionBuiltInSSHAndUserPassAuth(t *testing.T) {
	tmpDir := t.TempDir()
	up, err := initUserPassAuth(tmpDir, "alex", "superSecretPass99", "", true, true)
	if err != nil || up == nil {
		t.Fatalf("initUserPassAuth failed: %v", err)
	}
	prevUP := defaultUserPassAuth
	defaultUserPassAuth = up
	defer func() {
		defaultUserPassAuth = prevUP
	}()

	// Local HTTP backend on ephemeral port to test -http-auth and Single-Port SSH auto-routing on the same port
	webBackendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer webBackendLn.Close()
	webBackendPort := uint16(webBackendLn.Addr().(*net.TCPAddr).Port)

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("WEB-24X7-OK"))
	})
	webSrv := &http.Server{Handler: mux}
	go func() { _ = webSrv.Serve(webBackendLn) }()
	defer webSrv.Close()

	pubWebPort := uint16(getFreePort(t, "tcp"))
	pubSSHPort := uint16(getFreePort(t, "tcp"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mappings := []PortMapping{
		{BindIP: "127.0.0.1", PublicPort: pubWebPort, TargetPort: webBackendPort, Proto: "tcp"},
		{BindIP: "127.0.0.1", PublicPort: pubSSHPort, TargetPort: 22, Proto: "tcp"},
	}
	for i := range mappings {
		if err := startStandaloneTCP(ctx, "127.0.0.1", &mappings[i], mappings, nil, false); err != nil {
			t.Fatalf("startStandaloneTCP failed: %v", err)
		}
	}

	// 1. Verify wrong SSH password is rejected
	badSSHConfig := &ssh.ClientConfig{
		User:            "alex",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	if badClient, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", pubSSHPort), badSSHConfig); err == nil {
		_ = badClient.Close()
		t.Fatalf("expected SSH login with wrong password to fail")
	}

	// 2. Verify valid SSH login (-user alex -pass superSecretPass99) on dedicated SSH port & command execution
	goodSSHConfig := &ssh.ClientConfig{
		User:            "alex",
		Auth:            []ssh.AuthMethod{ssh.Password("superSecretPass99")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", pubSSHPort), goodSSHConfig)
	if err != nil {
		t.Fatalf("expected built-in SSHv2 login on port %d to succeed, got: %v", pubSSHPort, err)
	}
	defer sshClient.Close()

	sess1, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("failed to open SSH session: %v", err)
	}
	out1, err := sess1.CombinedOutput("echo DRIFTLESS_SSH_EXEC_OK")
	_ = sess1.Close()
	if err != nil || !strings.Contains(string(out1), "DRIFTLESS_SSH_EXEC_OK") {
		t.Fatalf("expected SSH exec output 'DRIFTLESS_SSH_EXEC_OK', got %q (err=%v)", string(out1), err)
	}

	// 3. Verify interactive SSH shell session (used by WebSSH / Termius on Android & iPhone)
	sessShell, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("failed to open interactive SSH shell session: %v", err)
	}
	stdinPipe, err := sessShell.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var shellOut bytes.Buffer
	sessShell.Stdout = &shellOut
	sessShell.Stderr = &shellOut
	if err := sessShell.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty failed: %v", err)
	}
	if err := sessShell.Shell(); err != nil {
		t.Fatalf("Shell() start failed: %v", err)
	}
	_, _ = io.WriteString(stdinPipe, "echo WEBSSH_INTERACTIVE_OK\nexit\n")
	_ = sessShell.Wait()
	_ = sessShell.Close()
	if !strings.Contains(shellOut.String(), "WEBSSH_INTERACTIVE_OK") {
		t.Fatalf("expected interactive shell output to contain WEBSSH_INTERACTIVE_OK, got:\n%s", shellOut.String())
	}

	// 4. Verify Single-Port Universal SSH Auto-Routing: connect SSH client to the WEB port (pubWebPort)!
	sshOnWebClient, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", pubWebPort), goodSSHConfig)
	if err != nil {
		t.Fatalf("expected Single-Port SSH auto-routing on web port %d to succeed, got: %v", pubWebPort, err)
	}
	defer sshOnWebClient.Close()
	sess2, err := sshOnWebClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out2, err := sess2.CombinedOutput("echo SINGLE_PORT_SSH_OK")
	_ = sess2.Close()
	if err != nil || !strings.Contains(string(out2), "SINGLE_PORT_SSH_OK") {
		t.Fatalf("expected Single-Port SSH output 'SINGLE_PORT_SSH_OK', got %q (err=%v)", string(out2), err)
	}

	// 5. Verify HTTP Basic Auth (-http-auth) on the exact same web port (pubWebPort)
	httpClient := &http.Client{Timeout: 3 * time.Second}
	webURL := fmt.Sprintf("http://127.0.0.1:%d/hello", pubWebPort)

	// Unauthenticated HTTP request must receive 401 Unauthorized
	respUnauth, err := httpClient.Get(webURL)
	if err != nil {
		t.Fatalf("unauthenticated HTTP GET failed: %v", err)
	}
	_ = respUnauth.Body.Close()
	if respUnauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when -http-auth is enabled, got %d", respUnauth.StatusCode)
	}

	// Authenticated HTTP request with -user alex -pass superSecretPass99 must receive 200 OK
	reqAuth, _ := http.NewRequest("GET", webURL, nil)
	reqAuth.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alex:superSecretPass99")))
	respAuth, err := httpClient.Do(reqAuth)
	if err != nil {
		t.Fatalf("authenticated HTTP GET failed: %v", err)
	}
	bodyAuth, _ := io.ReadAll(respAuth.Body)
	_ = respAuth.Body.Close()
	if respAuth.StatusCode != http.StatusOK || string(bodyAuth) != "WEB-24X7-OK" {
		t.Fatalf("expected 200 OK with WEB-24X7-OK, got status=%d body=%q", respAuth.StatusCode, string(bodyAuth))
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
		t.Fatalf("expected copyWithIdleTimeout to terminate idle half-open connection within 60ms")
	}
}

func TestProductionStopRestartPersistence(t *testing.T) {
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

	// 3. First run of SSH Auth: auto-creates credentials and Ed25519 host key
	certDir := filepath.Join(tmpDir, ".driftless-certs")
	up1, err := initUserPassAuth(certDir, "", "", "", false, true)
	if err != nil || up1 == nil {
		t.Fatalf("expected initUserPassAuth on port 22 to auto-create credentials, got err=%v", err)
	}
	signer1, err := loadOrCreateSSHHostSigner(certDir)
	if err != nil {
		t.Fatal(err)
	}
	fp1 := ssh.FingerprintSHA256(signer1.PublicKey())

	// 4. Second run after stop/restart: must reload the exact same username, password, and SSH host key
	up2, err := initUserPassAuth(certDir, "", "", "", false, true)
	if err != nil || up2 == nil {
		t.Fatalf("expected initUserPassAuth on restart to reload saved credentials, got err=%v", err)
	}
	signer2, err := loadOrCreateSSHHostSigner(certDir)
	if err != nil {
		t.Fatal(err)
	}
	fp2 := ssh.FingerprintSHA256(signer2.PublicKey())

	if up1.User != up2.User || up1.Pass != up2.Pass {
		t.Fatalf("expected SSH credentials to persist across restart (%s:%s != %s:%s)", up1.User, up1.Pass, up2.User, up2.Pass)
	}
	if fp1 != fp2 {
		t.Fatalf("expected SSH Ed25519 host key fingerprint to persist across restart (%s != %s)", fp1, fp2)
	}
}
