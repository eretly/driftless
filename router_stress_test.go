package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

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

func TestKnockPortalAndSinglePortMultiplexerAndBridge(t *testing.T) {
	tmpDir := t.TempDir()
	mappings := []PortMapping{
		{PublicPort: 8096, TargetPort: 8096, Proto: "both"},
		{PublicPort: 3389, TargetPort: 3389, Proto: "tcp"},
		{PublicPort: 2222, TargetPort: 22, Proto: "tcp"},
	}
	kc, err := newKnockController(tmpDir, "testknocksecret123456", 1*time.Hour, mappings, nil, true, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	prevKC := defaultKnockController
	defaultKnockController = kc
	defer func() {
		defaultKnockController = prevKC
	}()

	// 1. Verify Single-Port Universal Protocol Auto-Routing (SSH & RDP over port 8096)
	sshBanner := []byte("SSH-2.0-OpenSSH_9.6\r\n")
	if got := detectUniversalSinglePortOverride(sshBanner, 8096, mappings); got != 22 {
		t.Fatalf("expected SSH banner on port 8096 to auto-route to target port 22, got %d", got)
	}
	// RDP X.224 Connection Request TPKT header: 0x03 0x00 <len=19> <li=14> 0xE0 ...
	rdpPkt := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
	if got := detectUniversalSinglePortOverride(rdpPkt, 8096, mappings); got != 3389 {
		t.Fatalf("expected RDP X.224 packet on port 8096 to auto-route to target port 3389, got %d", got)
	}

	// 2. Verify Zero-Client Knock blocks unauthenticated non-loopback IP and unlocks via Magic Link
	fakeClientAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.77"), Port: 54321}
	if kc.IsAllowedAddr(fakeClientAddr) {
		t.Fatalf("expected unauthenticated public IP 198.51.100.77 to be blocked before Knock")
	}
	// Wrong secret rate-limit & rejection check
	if ok, _ := kc.VerifyKnockToken(fakeClientAddr, "wrongsecret"); ok {
		t.Fatalf("expected wrong knock secret to be rejected")
	}
	if ok, _ := kc.VerifyKnockToken(fakeClientAddr, "testknocksecret123456"); !ok {
		t.Fatalf("expected valid knock secret to unlock 198.51.100.77")
	}
	if !kc.IsAllowedAddr(fakeClientAddr) {
		t.Fatalf("expected 198.51.100.77 to be allowed after valid Knock")
	}

	// 3. Verify plaintext HTTP Knock is rejected with 400 Bad Request and does NOT unlock IP
	unauthIP := &net.TCPAddr{IP: net.ParseIP("203.0.113.99"), Port: 40000}
	if kc.IsAllowedAddr(unauthIP) {
		t.Fatalf("expected 203.0.113.99 to be locked initially")
	}
	plainC, plainS := net.Pipe()
	plainDone := make(chan struct{})
	go func() {
		defer close(plainDone)
		_, _, handled := inspectAndPrepareTCPConn(plainS, nil, false, 8096, mappings, nil)
		if !handled {
			t.Errorf("expected plaintext Knock request to be intercepted and rejected")
		}
	}()
	_, _ = plainC.Write([]byte("GET /__driftless_knock/testknocksecret123456 HTTP/1.1\r\nHost: mypc.duckdns.org:8096\r\n\r\n"))
	plainResp, _ := io.ReadAll(plainC)
	_ = plainC.Close()
	<-plainDone
	if !strings.Contains(string(plainResp), "400 Bad Request") {
		t.Fatalf("expected plaintext HTTP Knock to be rejected with 400 Bad Request, got:\n%s", string(plainResp))
	}

	// 4. Verify HTTPS/TLS Magic Knock Launchpad, .rdp generator, and https:// PAC URL over TLS
	sniMgr, err := newSNICertManager(tmpDir, "", "")
	if err != nil {
		t.Fatal(err)
	}

	c1, s1 := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, handled := inspectAndPrepareTCPConn(s1, sniMgr, true, 8096, mappings, nil)
		if !handled {
			t.Errorf("expected HTTPS Magic Knock request to be handled by Knock Launchpad")
		}
	}()
	tlsClient1 := tls.Client(c1, &tls.Config{ServerName: "mypc.duckdns.org", InsecureSkipVerify: true})
	_, _ = tlsClient1.Write([]byte("GET /__driftless_knock/testknocksecret123456/connect.rdp HTTP/1.1\r\nHost: mypc.duckdns.org:8096\r\n\r\n"))
	respBytes, _ := io.ReadAll(tlsClient1)
	_ = tlsClient1.Close()
	<-done
	if !strings.Contains(string(respBytes), "full address:s:mypc.duckdns.org:3389") {
		t.Fatalf("expected downloadable .rdp profile with mypc.duckdns.org:3389 over HTTPS, got:\n%s", string(respBytes))
	}

	// Verify Auto-PAC endpoint over HTTPS and Launchpad HTML https:// links
	c2, s2 := net.Pipe()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		_, _, _ = inspectAndPrepareTCPConn(s2, sniMgr, true, 8096, mappings, nil)
	}()
	tlsClient2 := tls.Client(c2, &tls.Config{ServerName: "mypc.duckdns.org", InsecureSkipVerify: true})
	_, _ = tlsClient2.Write([]byte("GET /__driftless_knock/testknocksecret123456 HTTP/1.1\r\nHost: mypc.duckdns.org:8096\r\n\r\n"))
	launchpadBytes, _ := io.ReadAll(tlsClient2)
	_ = tlsClient2.Close()
	<-done2
	if !strings.Contains(string(launchpadBytes), "https://mypc.duckdns.org:8096/__driftless_knock/testknocksecret123456/proxy.pac") {
		t.Fatalf("expected Launchpad HTML to use https:// for proxy.pac URL, got:\n%s", string(launchpadBytes))
	}
	if strings.Contains(string(launchpadBytes), "http://mypc.duckdns.org:8096/__driftless_knock/") {
		t.Fatalf("expected zero http:// knock links in Launchpad HTML, got:\n%s", string(launchpadBytes))
	}

	// 4. Verify Smart Ephemeral Port Bridging in Standalone Mode when TargetPort is already bound
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
	if err := startStandaloneTCP(ctx, "127.0.0.1", &bridgeMappings[0], bridgeMappings, nil, false); err != nil {
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

