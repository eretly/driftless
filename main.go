package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	versionString = "v1.4.0"
	alpnProtocol  = "driftless-v1"
	cmdAuth       = uint8(0)
	cmdNewConn    = uint8(1)
	cmdResume     = uint8(2)
	cmdAuthNonce  = uint8(3)
	cmdAuthResp   = uint8(4)
	cmdAuthOK     = uint8(5)
	cmdUDPFlow    = uint8(6)

	frameData = uint8(1)
	frameAck  = uint8(2)
	frameFin  = uint8(3)

	muxFrameOpen  = uint8(1)
	muxFrameData  = uint8(2)
	muxFrameClose = uint8(3)
	muxFramePing  = uint8(4)
	muxFramePong  = uint8(5)

	maxChunkSize    = 32 * 1024
	maxUDPPacket    = 65507
	authTimeout     = 5 * time.Second
	maxAuthAttempts = 10
	authWindow      = 1 * time.Minute
	nonceLen        = 32
	udpSessionTTL   = 90 * time.Second
)

var (
	globalBufferedBytes       atomic.Int64
	metricActiveTCPSessions   atomic.Int64
	metricActiveUDPSessions   atomic.Int64
	metricResumedSessions     atomic.Uint64
	metricUDPQueuedTotal      atomic.Uint64
	metricUDPReplayedTotal    atomic.Uint64
	metricUDPDroppedTotal     atomic.Uint64
	metricActiveTransportName atomic.Value

	defaultTransportMode = "auto"
	defaultIPACL         *IPACL
	defaultClientCAFile  string
	defaultClientCert    string
	defaultClientKey     string

	chunkBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 5+maxChunkSize)
			return &b
		},
	}
	defaultProxyProtocol bool
	udpBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, maxUDPPacket)
			return &b
		},
	}
	udpFramePool = sync.Pool{
		New: func() any {
			b := make([]byte, 2+maxUDPPacket)
			return &b
		},
	}
)


// ==================== IP / CIDR ACCESS CONTROL LIST (ACL) ====================

type IPACL struct {
	ips  map[string]struct{}
	nets []*net.IPNet
}

func parseIPACL(raw string) (*IPACL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	acl := &IPACL{ips: make(map[string]struct{})}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			_, ipNet, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR in -allow-ips %q: %w", part, err)
			}
			acl.nets = append(acl.nets, ipNet)
		} else {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP in -allow-ips %q", part)
			}
			acl.ips[ip.String()] = struct{}{}
		}
	}
	return acl, nil
}

func (acl *IPACL) AllowedAddr(addr net.Addr) bool {
	if acl == nil || (len(acl.ips) == 0 && len(acl.nets) == 0) {
		return true
	}
	if addr == nil {
		return false
	}
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if _, ok := acl.ips[ip.String()]; ok {
		return true
	}
	for _, n := range acl.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ==================== OBSERVABILITY & METRICS SERVER ====================

func startMetricsServer(ctx context.Context, listenAddr string) {
	if strings.TrimSpace(listenAddr) == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		trName, _ := metricActiveTransportName.Load().(string)
		if trName == "" {
			trName = "quic"
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP driftless_buffered_bytes Current bytes held in session recovery ring buffers\n")
		fmt.Fprintf(w, "# TYPE driftless_buffered_bytes gauge\n")
		fmt.Fprintf(w, "driftless_buffered_bytes %d\n", globalBufferedBytes.Load())
		fmt.Fprintf(w, "# HELP driftless_active_tcp_sessions Current active TCP sessions\n")
		fmt.Fprintf(w, "# TYPE driftless_active_tcp_sessions gauge\n")
		fmt.Fprintf(w, "driftless_active_tcp_sessions %d\n", metricActiveTCPSessions.Load())
		fmt.Fprintf(w, "# HELP driftless_active_udp_sessions Current active UDP sessions\n")
		fmt.Fprintf(w, "# TYPE driftless_active_udp_sessions gauge\n")
		fmt.Fprintf(w, "driftless_active_udp_sessions %d\n", metricActiveUDPSessions.Load())
		fmt.Fprintf(w, "# HELP driftless_resumed_sessions_total Total TCP sessions seamlessly resumed across IP changes\n")
		fmt.Fprintf(w, "# TYPE driftless_resumed_sessions_total counter\n")
		fmt.Fprintf(w, "driftless_resumed_sessions_total %d\n", metricResumedSessions.Load())
		fmt.Fprintf(w, "# HELP driftless_udp_packets_queued_total Total UDP packets queued during link transitions\n")
		fmt.Fprintf(w, "# TYPE driftless_udp_packets_queued_total counter\n")
		fmt.Fprintf(w, "driftless_udp_packets_queued_total %d\n", metricUDPQueuedTotal.Load())
		fmt.Fprintf(w, "# HELP driftless_udp_packets_replayed_total Total UDP packets replayed after reconnect\n")
		fmt.Fprintf(w, "# TYPE driftless_udp_packets_replayed_total counter\n")
		fmt.Fprintf(w, "driftless_udp_packets_replayed_total %d\n", metricUDPReplayedTotal.Load())
		fmt.Fprintf(w, "# HELP driftless_udp_packets_dropped_total Total UDP packets dropped due to queue overflow\n")
		fmt.Fprintf(w, "# TYPE driftless_udp_packets_dropped_total counter\n")
		fmt.Fprintf(w, "driftless_udp_packets_dropped_total %d\n", metricUDPDroppedTotal.Load())
		fmt.Fprintf(w, "driftless_transport_info{version=%q,transport=%q} 1\n", versionString, trName)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		trName, _ := metricActiveTransportName.Load().(string)
		if trName == "" {
			trName = "quic"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               versionString,
			"transport":             trName,
			"buffered_bytes":        globalBufferedBytes.Load(),
			"active_tcp_sessions":   metricActiveTCPSessions.Load(),
			"active_udp_sessions":   metricActiveUDPSessions.Load(),
			"resumed_sessions":      metricResumedSessions.Load(),
			"udp_queued_packets":    metricUDPQueuedTotal.Load(),
			"udp_replayed_packets":  metricUDPReplayedTotal.Load(),
			"udp_dropped_packets":   metricUDPDroppedTotal.Load(),
		})
	})
	srv := &http.Server{Addr: listenAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Printf("[metrics] observability server active on http://%s/metrics and /status", listenAddr)
	go func() {
		_ = srv.ListenAndServe()
	}()
}


// ==================== HELPERS & CLI ====================

func detectPublicIP() string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}

func detectLocalLANIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "virbr") ||
			strings.HasPrefix(name, "vethernet") || strings.Contains(name, "wsl") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
				continue
			}
			ip := ipNet.IP.To4()
			if ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168) {
				return ip.String()
			}
		}
	}
	return "127.0.0.1"
}

func parseMappingsWithDefault(raw string, defaultBothUDP bool) ([]PortMapping, error) {
	var res []PortMapping
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		proto := "tcp"
		if defaultBothUDP {
			proto = "both"
		}
		lower := strings.ToLower(pair)
		switch {
		case strings.HasSuffix(lower, "/udp"):
			proto = "udp"
			pair = pair[:len(pair)-4]
		case strings.HasSuffix(lower, "/tcp"):
			proto = "tcp"
			pair = pair[:len(pair)-4]
		case strings.HasSuffix(lower, "/https"):
			proto = "https"
			pair = pair[:len(pair)-6]
		case strings.HasSuffix(lower, "/tls"):
			proto = "https"
			pair = pair[:len(pair)-4]
		case strings.HasSuffix(lower, "/http"):
			proto = "http"
			pair = pair[:len(pair)-5]
		}

		// Support shorthand single port "8096" ("8096:8096") or local bind "127.0.0.1:8080:80"
		bindIP := "0.0.0.0"
		p := strings.Split(pair, ":")
		if len(p) == 1 {
			p = []string{p[0], p[0]}
		} else if len(p) >= 3 && net.ParseIP(p[0]) != nil {
			bindIP = p[0]
			p = p[1:]
		}
		if len(p) < 2 || len(p) > 3 {
			return nil, fmt.Errorf("invalid port mapping %q (expected PORT, PUBLIC:LOCAL, or 127.0.0.1:PUBLIC:LOCAL)", pair)
		}
		pub, err1 := strconv.Atoi(p[0])
		loc, err2 := strconv.Atoi(p[1])
		if err1 != nil || err2 != nil || pub <= 0 || pub > 65535 || loc <= 0 || loc > 65535 {
			return nil, fmt.Errorf("port out of range (1..65535) in %q", pair)
		}
		if len(p) == 3 {
			sub := strings.ToLower(strings.TrimSpace(p[2]))
			if sub == "tls" {
				sub = "https"
			}
			if sub != "http" && sub != "https" && sub != "udp" && sub != "tcp" && sub != "both" {
				return nil, fmt.Errorf("invalid protocol/scheme in %q", pair)
			}
			proto = sub
		}
		res = append(res, PortMapping{BindIP: bindIP, PublicPort: uint16(pub), TargetPort: uint16(loc), Proto: proto})
	}
	if len(res) == 0 {
		return nil, errors.New("at least one port mapping is required")
	}
	return res, nil
}

func parseMappings(raw string) ([]PortMapping, error) {
	return parseMappingsWithDefault(raw, true)
}

func parseVHosts(raw string) (map[string]uint16, error) {
	res := make(map[string]uint16)
	if strings.TrimSpace(raw) == "" {
		return res, nil
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid -vhosts entry %q (expected domain.com:LOCAL_PORT)", entry)
		}
		domain := strings.ToLower(strings.TrimSpace(parts[0]))
		port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port in -vhosts entry %q", entry)
		}
		res[domain] = uint16(port)
	}
	return res, nil
}


func loadOrGenerateToken(isServer bool, tokenFlag, tokenFile string) (string, error) {
	if tokenFlag != "" {
		return strings.TrimSpace(tokenFlag), nil
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if tok := os.Getenv("DRIFTLESS_TOKEN"); tok != "" {
		return strings.TrimSpace(tok), nil
	}
	if isServer {
		const defaultTokenPath = ".driftless-certs/token.secret"
		if b, err := os.ReadFile(defaultTokenPath); err == nil {
			if saved := strings.TrimSpace(string(b)); len(saved) >= 16 {
				log.Printf("[gateway] loaded persistent token from %s", defaultTokenPath)
				return saved, nil
			}
		}
		var b [16]byte // 128-bit cryptographic token (32 hex chars)
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("generate token: %w", err)
		}
		autoTok := hex.EncodeToString(b[:])
		if err := os.MkdirAll(".driftless-certs", 0o700); err == nil {
			_ = os.WriteFile(defaultTokenPath, []byte(autoTok+"\n"), 0o600)
		}
		log.Printf("[gateway] no -token specified; generated 128-bit password (saved to %s): %s", defaultTokenPath, autoTok)
		return autoTok, nil
	}
	return "", errors.New("password required: run './driftless client -quic VPS_IP:4242 -token YOUR_PASSWORD'")
}

func main() {
	defaultMode := "agent"
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "server", "gateway":
			defaultMode = "gateway"
			os.Args = append(os.Args[:1], os.Args[2:]...)
		case "client", "agent":
			defaultMode = "agent"
			os.Args = append(os.Args[:1], os.Args[2:]...)
		case "standalone", "direct", "p2p":
			defaultMode = "standalone"
			os.Args = append(os.Args[:1], os.Args[2:]...)
		case "version", "-v", "--version":
			fmt.Printf("driftless %s (QUIC+TCP-Mux/TCP/UDP/HTTP-VHost/Auto-TLS/Zero-VPS STUN+UPnP)\n", versionString)
			return
		}
	}

	mode := flag.String("mode", defaultMode, "'server' (VPS), 'client' (Home PC to VPS), or 'standalone' (Zero-VPS Home PC)")
	quicAddr := flag.String("quic", "0.0.0.0:4242", "gateway address or comma-separated failover list (e.g. VPS1:4242,VPS2:4242)")
	transportMode := flag.String("transport", "auto", "tunnel transport: 'auto' (QUIC with automatic TCP-Mux fallback), 'quic', or 'tcp'")
	tokenFlag := flag.String("token", "", "shared secret password or comma-separated rotation list (auto-generated on server if omitted)")
	tokenFile := flag.String("token-file", "", "path to file containing shared secret password")
	ports := flag.String("ports", "8080:80,8096:8096", "PUBLIC:LOCAL or PORT mappings (forwards both TCP+UDP by default)")
	udpDefault := flag.Bool("udp", true, "forward UDP alongside TCP by default on all mapped ports")
	enableTLS := flag.Bool("tls", false, "enable automatic HTTPS/TLS termination on mapped TCP ports")
	httpsAddr := flag.String("https", "", "optional HTTPS VHost router listen address (e.g. :443 or :8443)")
	tlsCertFile := flag.String("tls-cert", "", "optional path to custom TLS certificate PEM file")
	tlsKeyFile := flag.String("tls-key", "", "optional path to custom TLS private key PEM file")
	vhostAddr := flag.String("vhost-addr", "", "optional HTTP/HTTPS Host router listen address (e.g. :80)")
	vhosts := flag.String("vhosts", "", "comma-separated domain:LOCAL_PORT mappings (e.g. app.example.com:3000,media.example.com:8096)")
	direct := flag.String("direct", ":8888", "direct LAN/WAN HTTP redirector listen address (empty to disable)")
	host := flag.String("host", "127.0.0.1", "local target host on agent/standalone")
	maxBuf := flag.Int64("max-buf", 16*1024*1024, "max per-session ring buffer in bytes (default 16 MiB)")
	maxMem := flag.Int64("max-mem", 256*1024*1024, "max global buffered bytes across all sessions (default 256 MiB)")
	sessionTTL := flag.Duration("session-ttl", 90*time.Second, "how long to hold frozen sessions during an IP outage")
	quicIdle := flag.Duration("quic-idle-timeout", 8*time.Second, "QUIC/Mux idle timeout before reconnect")
	quicKeepalive := flag.Duration("quic-keepalive", 2*time.Second, "QUIC/Mux keepalive period")
	certDir := flag.String("cert-dir", "", "directory to persist gateway cert.pem/key.pem")
	fingerprint := flag.String("fingerprint", "", "optional gateway SHA-256 cert fingerprint for strict pinning")
	lanIP := flag.String("lan-ip", "", "override auto-detected agent LAN IP")
	allowPorts := flag.String("allow-ports", "", "optional whitelist of local ports on agent/standalone (e.g. 80,8096,25565)")
	allowIPs := flag.String("allow-ips", "", "optional IP/CIDR ACL whitelist for public listeners (e.g. 192.168.1.0/24,203.0.113.5)")
	clientCA := flag.String("client-ca", "", "optional CA PEM file on server to require mTLS client certificates from agents")
	clientCert := flag.String("client-cert", "", "optional mTLS client certificate PEM file on agent")
	clientKey := flag.String("client-key", "", "optional mTLS client private key PEM file on agent")
	metricsAddr := flag.String("metrics", "", "optional observability listen address for /metrics (Prometheus) and /status (JSON)")
	sameLAN := flag.Bool("same-lan", true, "redirect clients sharing the same WAN IP directly to agent LAN IP")
	proxyProto := flag.Bool("proxy-protocol", false, "prepend HAProxy PROXY protocol v1 header so backend services see real client IP")

	// Standalone / Zero-VPS mode flags
	enableUPnP := flag.Bool("upnp", true, "automatically open ports on home router via UPnP IGD / NAT-PMP (standalone mode)")
	stunServer := flag.String("stun", "stun.cloudflare.com:3478", "STUN server or comma-separated list for 5ms external IP change detection (standalone mode)")
	stunInterval := flag.Duration("stun-interval", 1*time.Second, "how often to check external IP via STUN (standalone mode)")
	duckShort := flag.String("duck", "", "shorthand DuckDNS 'subdomain:token' or update URL (saved automatically for next runs)")
	ddnsProvider := flag.String("ddns-provider", "", "built-in Dynamic DNS provider: 'duckdns', 'cloudflare', or 'noip'")
	ddnsDomain := flag.String("ddns-domain", "", "domain/subdomain to update when IP changes (e.g. myhome.duckdns.org)")
	ddnsToken := flag.String("ddns-token", "", "API token or password for Dynamic DNS provider")
	ddnsUser := flag.String("ddns-user", "", "username for No-IP / DynDNS provider")
	ddnsZone := flag.String("ddns-zone", "", "Cloudflare Zone ID (when -ddns-provider=cloudflare)")
	ddnsURL := flag.String("ddns-url", "", "custom DDNS webhook URL (replaces {ip} with current external IP)")
	// Allow bare '-duck' or '--duck' without arguments on CLI (rewritten to '-duck=auto')
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "-duck" || os.Args[i] == "--duck" {
			if i+1 >= len(os.Args) || strings.HasPrefix(os.Args[i+1], "-") {
				os.Args[i] = "-duck=auto"
			}
		}
	}
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	defaultTransportMode = strings.ToLower(strings.TrimSpace(*transportMode))
	defaultClientCAFile = strings.TrimSpace(*clientCA)
	defaultClientCert = strings.TrimSpace(*clientCert)
	defaultClientKey = strings.TrimSpace(*clientKey)
	defaultProxyProtocol = *proxyProto

	if *allowIPs != "" {
		acl, err := parseIPACL(*allowIPs)
		if err != nil {
			log.Fatalf("[driftless] %v", err)
		}
		defaultIPACL = acl
	}

	if *metricsAddr != "" {
		startMetricsServer(ctx, *metricsAddr)
	}

	var portsAllow map[uint16]struct{}
	if *allowPorts != "" {
		portsAllow = make(map[uint16]struct{})
		for _, p := range strings.Split(*allowPorts, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			port, err := strconv.Atoi(p)
			if err != nil || port <= 0 || port > 65535 {
				log.Fatalf("[driftless] invalid port in -allow-ports: %s", p)
			}
			portsAllow[uint16(port)] = struct{}{}
		}
	}

	if *mode == "standalone" || *mode == "direct" || *mode == "p2p" {
		mappings, err := parseMappingsWithDefault(*ports, *udpDefault)
		if err != nil {
			log.Fatalf("[standalone] %v", err)
		}
		vhostMap, err := parseVHosts(*vhosts)
		if err != nil {
			log.Fatalf("[standalone] %v", err)
		}
		if *vhostAddr == "" && len(vhostMap) > 0 {
			*vhostAddr = "0.0.0.0:80"
		}
		ddnsCfg := resolveAndPersistDDNS(DDNSConfig{
			Provider: *ddnsProvider,
			Domain:   *ddnsDomain,
			Token:    *ddnsToken,
			User:     *ddnsUser,
			ZoneID:   *ddnsZone,
			Webhook:  *ddnsURL,
		}, *duckShort)
		cfg := StandaloneConfig{
			TargetHost:   *host,
			Mappings:     mappings,
			VHostAddr:    *vhostAddr,
			HTTPSAddr:    *httpsAddr,
			DirectAddr:   *direct,
			VHostMap:     vhostMap,
			AllowedPorts: portsAllow,
			EnableUPnP:   *enableUPnP,
			EnableTLS:    *enableTLS,
			STUNServer:   *stunServer,
			STUNInterval: *stunInterval,
			CertDir:      *certDir,
			TLSCertFile:  *tlsCertFile,
			TLSKeyFile:   *tlsKeyFile,
			DDNS:         ddnsCfg,
		}
		if err := runStandalone(ctx, cfg); err != nil {
			log.Fatalf("[standalone] %v", err)
		}
		return
	}

	isServer := *mode == "gateway" || *mode == "server"
	token, err := loadOrGenerateToken(isServer, *tokenFlag, *tokenFile)
	if err != nil {
		log.Fatalf("[driftless] %v", err)
	}

	if isServer {
		mappings, err := parseMappingsWithDefault(*ports, *udpDefault)
		if err != nil {
			log.Fatalf("[gateway] %v", err)
		}
		vhostMap, err := parseVHosts(*vhosts)
		if err != nil {
			log.Fatalf("[gateway] %v", err)
		}
		if *vhostAddr == "" && len(vhostMap) > 0 {
			*vhostAddr = "0.0.0.0:80"
		}
		ddnsCfg := resolveAndPersistDDNS(DDNSConfig{
			Provider: *ddnsProvider,
			Domain:   *ddnsDomain,
			Token:    *ddnsToken,
			User:     *ddnsUser,
			ZoneID:   *ddnsZone,
			Webhook:  *ddnsURL,
		}, *duckShort)
		if ddnsCfg.Domain != "" {
			pubIP := detectPublicIP()
			if ddnsCfg.Provider != "" || ddnsCfg.Webhook != "" {
				if pubIP != "" {
					if err := updateDDNS(ddnsCfg, pubIP); err == nil {
						log.Printf("[gateway] DuckDNS/DDNS updated -> %s (%s)", pubIP, ddnsCfg.Domain)
					}
				}
			} else if strings.EqualFold(ddnsCfg.Domain, "auto") {
				if autoDom := autoZeroConfigDomain(pubIP); autoDom != "" {
					ddnsCfg.Domain = autoDom
				} else if pubIP != "" {
					ddnsCfg.Domain = pubIP
				}
			}
			*enableTLS = true
			if sm, err := newSNICertManager(*certDir, *tlsCertFile, *tlsKeyFile); err == nil {
				sm.ensureDomainCertificate(ddnsCfg.Domain)
			}
		}
		if err := runGateway(ctx, *quicAddr, token, *direct, *vhostAddr, *httpsAddr, vhostMap, mappings, *maxMem, *maxBuf, *quicIdle, *quicKeepalive, *sessionTTL, *certDir, *tlsCertFile, *tlsKeyFile, *enableTLS, *sameLAN); err != nil {
			log.Fatalf("[gateway] %v", err)
		}
	} else {
		if err := runAgent(ctx, *quicAddr, *host, token, *lanIP, *fingerprint, *maxBuf, *maxMem, *quicIdle, *quicKeepalive, *sessionTTL, portsAllow); err != nil {
			log.Fatalf("[agent] %v", err)
		}
	}
}

