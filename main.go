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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	versionString = "v1.5.8"
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
	defaultClientCAFile  string
	defaultClientCert    string
	defaultClientKey     string
	defaultAgentNodeID      string
	defaultAgentMappings    []PortMapping
	defaultAgentVHosts      []VHostRoute
	defaultVHostNodeMap     = make(map[string]string)
	defaultExternalProbeURL string
	defaultProbeAuthToken   string
	defaultCertDir          string
	defaultGatewayDDNS      DDNSConfig
	lastAgentAuthConflict   atomic.Value

	chunkBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 5+maxChunkSize)
			return &b
		},
	}
	defaultProxyProtocol bool
	udpBufPool           = sync.Pool{
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
			"version":              versionString,
			"transport":            trName,
			"buffered_bytes":       globalBufferedBytes.Load(),
			"active_tcp_sessions":  metricActiveTCPSessions.Load(),
			"active_udp_sessions":  metricActiveUDPSessions.Load(),
			"resumed_sessions":     metricResumedSessions.Load(),
			"udp_queued_packets":   metricUDPQueuedTotal.Load(),
			"udp_replayed_packets": metricUDPReplayedTotal.Load(),
			"udp_dropped_packets":  metricUDPDroppedTotal.Load(),
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

func joinHostPortUint16(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func detectPublicIP() string {
	endpoints := []string{
		"https://api4.ipify.org",
		"https://checkip.amazonaws.com",
		"https://icanhazip.com",
		"https://ifconfig.me/ip",
	}
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	for _, ep := range endpoints {
		req, err := http.NewRequest("GET", ep, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "driftless/"+versionString)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, rErr := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		if rErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		ipStr := strings.TrimSpace(string(b))
		if parsed := net.ParseIP(ipStr); parsed != nil && parsed.To4() != nil {
			return parsed.To4().String()
		}
	}
	return ""
}

func hasInterfacePrefix(n, prefix string) bool {
	if !strings.HasPrefix(n, prefix) {
		return false
	}
	if len(n) == len(prefix) {
		return true
	}
	next := n[len(prefix)]
	return (next >= '0' && next <= '9') || next == '-' || next == '_' || next == '.' || next == ' ' || next == '('
}

func isVirtualOrVPNInterfaceName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || strings.HasPrefix(n, "local area connection") {
		return false
	}
	if n == "lo" || n == "lo0" {
		return true
	}
	for _, prefix := range []string{
		"docker", "br-", "veth", "virbr", "vethernet", "vmnet", "vboxnet",
		"tailscale", "zerotier", "zt", "wg", "tun", "tap", "utun",
		"radmin", "hamachi", "nordlynx", "proton", "warp",
	} {
		if hasInterfacePrefix(n, prefix) {
			return true
		}
	}
	for _, sub := range []string{"wsl", "hyper-v", "virtualbox", "vmware", "loopback", "tap-", "vpn", "wireguard", "tailscale", "zerotier", "radmin"} {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func detectLocalLANIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	allowedIPs := make(map[string]bool)
	var preferred192 []string
	var fallbackPrivate []string

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		if isVirtualOrVPNInterfaceName(iface.Name) {
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
			// Skip VirtualBox default host-only subnet 192.168.56.0/24 unless no other LAN IP exists
			if ip[0] == 192 && ip[1] == 168 && ip[2] == 56 {
				fallbackPrivate = append(fallbackPrivate, ip.String())
				continue
			}
			if ip[0] == 192 && ip[1] == 168 {
				s := ip.String()
				allowedIPs[s] = true
				preferred192 = append(preferred192, s)
			} else if ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) {
				s := ip.String()
				allowedIPs[s] = true
				fallbackPrivate = append(fallbackPrivate, s)
			}
		}
	}

	// Ask OS routing table which physical interface routes to standard LAN/WAN targets (0 packets sent over network)
	for _, probeDst := range []string{"192.168.1.1:80", "192.168.0.1:80", "1.1.1.1:80"} {
		if c, err := net.Dial("udp4", probeDst); err == nil {
			localAddr, ok := c.LocalAddr().(*net.UDPAddr)
			_ = c.Close()
			if ok && localAddr != nil && localAddr.IP != nil {
				if v4 := localAddr.IP.To4(); v4 != nil && allowedIPs[v4.String()] {
					return v4.String()
				}
			}
		}
	}

	if len(preferred192) > 0 {
		return preferred192[0]
	}
	if len(fallbackPrivate) > 0 {
		return fallbackPrivate[0]
	}
	return "127.0.0.1"
}

func isProtocolToken(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "http", "https", "tls", "udp", "tcp", "both":
		return true
	}
	return false
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

		bindIP := "0.0.0.0"
		nodeID := ""
		p := strings.Split(pair, ":")
		if len(p) == 1 {
			p = []string{p[0], p[0]}
		} else if len(p) >= 3 && net.ParseIP(p[0]) != nil {
			bindIP = p[0]
			p = p[1:]
		}
		// Support PUBLIC:NODE_ID:LOCAL (e.g. "25565:pc3:25565") when middle token is not a protocol and last token is a port number
		if len(p) == 3 && !isProtocolToken(p[2]) {
			if _, errLast := strconv.Atoi(p[2]); errLast == nil {
				nodeID = sanitizeNodeID(p[1])
				p = []string{p[0], p[2]}
			}
		}
		if len(p) < 2 || len(p) > 3 {
			return nil, fmt.Errorf("invalid port mapping %q (expected PORT, PUBLIC:LOCAL, PUBLIC:NODE:LOCAL, or 127.0.0.1:PUBLIC:LOCAL)", pair)
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
		res = append(res, PortMapping{BindIP: bindIP, PublicPort: uint16(pub), TargetPort: uint16(loc), Proto: proto, NodeID: nodeID})
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
	routes, err := parseVHostRoutes(raw)
	if err != nil {
		return nil, err
	}
	res := make(map[string]uint16, len(routes))
	for _, r := range routes {
		res[r.Domain] = r.TargetPort
		if r.NodeID != "" {
			defaultVHostNodeMap[r.Domain] = r.NodeID
		}
	}
	return res, nil
}

func parseVHostRoutes(raw string) ([]VHostRoute, error) {
	var res []VHostRoute
	if strings.TrimSpace(raw) == "" {
		return res, nil
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		normalized := strings.ReplaceAll(entry, "=", ":")
		parts := strings.Split(normalized, ":")
		var domain, nodeID, portStr string
		switch len(parts) {
		case 2:
			domain = strings.ToLower(strings.TrimSpace(parts[0]))
			portStr = strings.TrimSpace(parts[1])
		case 3:
			domain = strings.ToLower(strings.TrimSpace(parts[0]))
			nodeID = sanitizeNodeID(parts[1])
			portStr = strings.TrimSpace(parts[2])
		default:
			return nil, fmt.Errorf("invalid -vhosts entry %q (expected domain.com:LOCAL_PORT or domain.com:NODE_ID:LOCAL_PORT)", entry)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port in -vhosts entry %q", entry)
		}
		res = append(res, VHostRoute{Domain: domain, TargetPort: uint16(port), NodeID: nodeID})
	}
	return res, nil
}

var (
	redactedSecretsMu sync.RWMutex
	redactedSecrets   []string
)

type secretRedactingWriter struct {
	w io.Writer
}

func (srw *secretRedactingWriter) Write(p []byte) (int, error) {
	sanitized := sanitizeLogString(string(p))
	_, err := srw.w.Write([]byte(sanitized))
	return len(p), err
}

func init() {
	log.SetOutput(&secretRedactingWriter{w: os.Stderr})
}

func registerSecretForLogRedaction(raw string) {
	redactedSecretsMu.Lock()
	defer redactedSecretsMu.Unlock()
	for _, part := range strings.Split(raw, ",") {
		sec := strings.TrimSpace(part)
		if len(sec) < 4 {
			continue
		}
		exists := false
		for _, cur := range redactedSecrets {
			if cur == sec {
				exists = true
				break
			}
		}
		if !exists {
			redactedSecrets = append(redactedSecrets, sec)
		}
	}
}

func redactURLQuerySecrets(s string) string {
	for _, key := range []string{"?token=", "&token=", "?password=", "&password=", "?pass=", "&pass=", "?secret=", "&secret=", "?key=", "&key="} {
		searchFrom := 0
		for {
			lower := strings.ToLower(s[searchFrom:])
			idx := strings.Index(lower, key)
			if idx == -1 {
				break
			}
			valStart := searchFrom + idx + len(key)
			if strings.HasPrefix(s[valStart:], "[token=") {
				searchFrom = valStart + 7
				continue
			}
			valEnd := valStart
			for valEnd < len(s) && !strings.ContainsRune("& \t\r\n\"')]>#", rune(s[valEnd])) {
				valEnd++
			}
			if valEnd > valStart {
				s = s[:valStart] + "[token=hidden]" + s[valEnd:]
				searchFrom = valStart + len("[token=hidden]")
			} else {
				searchFrom = valStart
			}
		}
	}
	return s
}

func sanitizeLogString(s string) string {
	redactedSecretsMu.RLock()
	secrets := append([]string(nil), redactedSecrets...)
	redactedSecretsMu.RUnlock()

	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, "[token=hidden]")
		}
	}
	return redactURLQuerySecrets(s)
}

// writeFileAtomic0600 writes data to targetPath atomically using a temporary file in the same
// directory (0600 mode), explicit fsync (tmpFile.Sync), close, atomic os.Rename, and parent directory sync.
func writeFileAtomic0600(targetPath string, data []byte) error {
	if fi, err := os.Stat(targetPath); err == nil && fi.IsDir() {
		return fmt.Errorf("target path %s is a directory", targetPath)
	}
	dir := filepath.Dir(targetPath)
	base := filepath.Base(targetPath)
	tmpFile, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	cleanupTmp := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmpFile.Chmod(0o600); err != nil {
		cleanupTmp()
		return err
	}
	n, err := tmpFile.Write(data)
	if err != nil {
		cleanupTmp()
		return err
	}
	if n != len(data) {
		cleanupTmp()
		return io.ErrShortWrite
	}
	if err := tmpFile.Sync(); err != nil {
		cleanupTmp()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := syncParentDir(dir); err != nil {
		return err
	}
	return nil
}

func syncParentDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		log.Printf("[driftless] WARNING: failed to open parent directory %s for fsync: %v", dir, err)
		return fmt.Errorf("open parent directory %s for fsync: %w", dir, err)
	}
	syncErr := dirFile.Sync()
	closeErr := dirFile.Close()
	if syncErr != nil && !errors.Is(syncErr, syscall.EINVAL) && !errors.Is(syncErr, syscall.ENOTSUP) && !errors.Is(syncErr, syscall.EBADF) {
		log.Printf("[driftless] WARNING: failed to fsync parent directory %s: %v", dir, syncErr)
		return fmt.Errorf("fsync parent directory %s: %w", dir, syncErr)
	}
	if closeErr != nil {
		log.Printf("[driftless] WARNING: failed to close parent directory %s after fsync: %v", dir, closeErr)
		return fmt.Errorf("close parent directory %s: %w", dir, closeErr)
	}
	return nil
}

func resolveTokenCertDir(certDir string) string {
	dir := strings.TrimSpace(certDir)
	if dir == "" {
		dir = ".driftless-certs"
	}
	return dir
}

func loadOrGenerateToken(isServer bool, tokenFlag, tokenFile string) (string, error) {
	return loadOrGenerateTokenInDir(isServer, tokenFlag, tokenFile, defaultCertDir)
}

func loadOrGenerateTokenInDir(isServer bool, tokenFlag, tokenFile, certDir string) (string, error) {
	if tokenFlag != "" {
		tok := strings.TrimSpace(tokenFlag)
		registerSecretForLogRedaction(tok)
		return tok, nil
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", err
		}
		tok := strings.TrimSpace(string(b))
		registerSecretForLogRedaction(tok)
		return tok, nil
	}
	if tok := os.Getenv("DRIFTLESS_TOKEN"); tok != "" {
		trimmed := strings.TrimSpace(tok)
		registerSecretForLogRedaction(trimmed)
		return trimmed, nil
	}
	if isServer {
		dir := resolveTokenCertDir(certDir)
		tokenPath := filepath.Join(dir, "token.secret")
		if b, err := os.ReadFile(tokenPath); err == nil {
			if saved := strings.TrimSpace(string(b)); len(saved) >= 16 {
				registerSecretForLogRedaction(saved)
				log.Printf("[gateway] loaded persistent token from %s [token=valid, hidden]", tokenPath)
				return saved, nil
			}
		} else if !os.IsNotExist(err) {
			log.Printf("[gateway] ERROR: failed to read persistent token file %s: %v", tokenPath, err)
			return "", fmt.Errorf("read persistent token file %s: %w", tokenPath, err)
		}
		var b [16]byte // 128-bit cryptographic token (32 hex chars)
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("generate token: %w", err)
		}
		autoTok := hex.EncodeToString(b[:])
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.Printf("[gateway] ERROR: failed to create token directory %s: %v", dir, err)
			return "", fmt.Errorf("create token directory %s: %w", dir, err)
		}
		if err := writeFileAtomic0600(tokenPath, []byte(autoTok+"\n")); err != nil {
			log.Printf("[gateway] ERROR: failed to persist generated token to %s: %v", tokenPath, err)
			return "", fmt.Errorf("persist generated token to %s: %w", tokenPath, err)
		}
		registerSecretForLogRedaction(autoTok)
		log.Printf("[gateway] no -token specified; generated 128-bit password (saved to %s with mode 0600; run './driftless show-token' or 'cat %s' to view) [token=valid, hidden]", tokenPath, tokenPath)
		return autoTok, nil
	}
	return "", errors.New("password required: run './driftless client -quic VPS_IP:4242 -token YOUR_PASSWORD'")
}

func printSavedTokenAndCommand() error {
	return printSavedTokenAndCommandInDir(defaultCertDir)
}

func printSavedTokenAndCommandInDir(certDir string) error {
	dir := resolveTokenCertDir(certDir)
	tokenPath := filepath.Join(dir, "token.secret")
	cmdPath := filepath.Join(dir, "client-connect.cmd")
	standaloneInfoPath := filepath.Join(dir, "standalone-info.txt")

	tokBytes, tokErr := os.ReadFile(tokenPath)
	cmdBytes, cmdErr := os.ReadFile(cmdPath)
	infoBytes, infoErr := os.ReadFile(standaloneInfoPath)
	if tokErr != nil && cmdErr != nil && infoErr != nil {
		return fmt.Errorf("no saved token or connection info found in %s/ (start './driftless server' or './driftless standalone' first): %w", dir, tokErr)
	}
	if tokErr == nil {
		fmt.Fprintf(os.Stdout, "Token (%s):\n  %s\n", tokenPath, strings.TrimSpace(string(tokBytes)))
	}
	if cmdErr == nil {
		fmt.Fprintf(os.Stdout, "Ready-to-copy Home PC command (%s):\n  %s\n", cmdPath, strings.TrimSpace(string(cmdBytes)))
	}
	if infoErr == nil {
		fmt.Fprintf(os.Stdout, "Standalone Connection Summary (%s):\n%s\n", standaloneInfoPath, strings.TrimSpace(string(infoBytes)))
	}
	return nil
}

func runInteractiveCheck(stunAddr, targetHost, portsRaw, duckFlag, probeURL string) {
	stunFailCount.Store(3)
	pubIP, _ := querySTUNPublicIP(stunAddr, 1200*time.Millisecond)
	if pubIP == "" && !isLoopbackOnlySTUNList(stunAddr) {
		pubIP = detectPublicIP()
	}
	mappings, _ := parseMappingsWithDefault(portsRaw, true)
	ddns := resolveAndPersistDDNS(DDNSConfig{}, duckFlag)
	rep := checkExternalReachabilityWithProbe(pubIP, targetHost, ddns, mappings, probeURL, 1500*time.Millisecond)
	out, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(out))
}

func main() {
	defaultMode := "agent"
	runCheckCmd := false
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
		case "check", "diagnose":
			runCheckCmd = true
			os.Args = append(os.Args[:1], os.Args[2:]...)
		case "show-token", "token", "connect-cmd":
			customDir := ""
			for i := 2; i < len(os.Args); i++ {
				if (os.Args[i] == "-cert-dir" || os.Args[i] == "--cert-dir") && i+1 < len(os.Args) {
					customDir = os.Args[i+1]
				} else if strings.HasPrefix(os.Args[i], "-cert-dir=") {
					customDir = strings.TrimPrefix(os.Args[i], "-cert-dir=")
				} else if strings.HasPrefix(os.Args[i], "--cert-dir=") {
					customDir = strings.TrimPrefix(os.Args[i], "--cert-dir=")
				}
			}
			if err := printSavedTokenAndCommandInDir(customDir); err != nil {
				fmt.Fprintf(os.Stderr, "[driftless] %v\n", err)
				os.Exit(1)
			}
			return
		case "version", "-v", "--version":
			fmt.Printf("driftless %s (QUIC+TCP-Mux/TCP/UDP/HTTP-VHost/Auto-TLS/Zero-VPS STUN+UPnP)\n", versionString)
			return
		}
	}

	mode := flag.String("mode", defaultMode, "'server' (VPS Gateway), 'client' (Home PC Agent), or 'standalone' (Zero-VPS Home PC)")
	nodeIDFlag := flag.String("id", "", "unique node ID / computer name for this Agent when connecting multiple Home PCs to one VPS Gateway (e.g. pc1, media-pc)")
	nodeAliasFlag := flag.String("node", "", "alias for -id (unique node ID / computer name for multi-agent Gateway routing)")
	quicAddr := flag.String("quic", "0.0.0.0:4242", "gateway address or comma-separated failover list (e.g. VPS1:4242,VPS2:4242)")
	gatewayAlias := flag.String("gateway", "", "alias for -quic (gateway address or comma-separated failover list)")
	gwShortAlias := flag.String("gw", "", "alias for -quic (gateway address or comma-separated failover list)")
	vps2Addr := flag.String("vps2", "", "optional second backup VPS gateway address for automatic failover (e.g. BACKUP_VPS_IP:4242)")
	transportMode := flag.String("transport", "auto", "tunnel transport: 'auto' (QUIC with automatic TCP-Mux fallback), 'quic', or 'tcp'")
	tokenFlag := flag.String("token", "", "shared secret tunnel password or comma-separated rotation list (auto-generated on server if omitted)")
	tokenFile := flag.String("token-file", "", "path to file containing shared secret tunnel password")
	ports := flag.String("ports", "8080:80,8096:8096", "PUBLIC:LOCAL, PORT, or PUBLIC:NODE_ID:LOCAL mappings (forwards both TCP+UDP by default)")
	udpDefault := flag.Bool("udp", true, "forward UDP alongside TCP by default on all mapped ports")
	enableTLS := flag.Bool("tls", false, "enable automatic HTTPS/TLS termination on mapped TCP ports")
	httpsAddr := flag.String("https", "", "optional HTTPS VHost router listen address (e.g. :443 or :8443)")
	tlsCertFile := flag.String("tls-cert", "", "optional path to custom TLS certificate PEM file")
	tlsKeyFile := flag.String("tls-key", "", "optional path to custom TLS private key PEM file")
	domainShort := flag.String("domain", "", "custom domain to bind automatically with Auto-TLS (e.g. mysite.com or media.mysite.com:8096)")
	vhostAddr := flag.String("vhost-addr", "", "optional HTTP/HTTPS Host router listen address (e.g. :80)")
	vhosts := flag.String("vhosts", "", "comma-separated domain:LOCAL_PORT or domain:NODE_ID:LOCAL_PORT mappings (e.g. media.example.com:pc1:8096,site.example.com:pc2:3000)")
	vhostSingular := flag.String("vhost", "", "alias for -vhosts")
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
	clientCA := flag.String("client-ca", "", "optional CA PEM file on server to require mTLS client certificates from agents")
	clientCert := flag.String("client-cert", "", "optional mTLS client certificate PEM file on agent")
	clientKey := flag.String("client-key", "", "optional mTLS client private key PEM file on agent")
	metricsAddr := flag.String("metrics", "", "optional observability listen address for /metrics (Prometheus) and /status (JSON)")
	sameLAN := flag.Bool("same-lan", true, "redirect clients sharing the same WAN IP directly to agent LAN IP")
	proxyProto := flag.Bool("proxy-protocol", false, "prepend HAProxy PROXY protocol v1 header so backend services see real client IP")

	// Standalone / Zero-VPS mode flags
	enableUPnP := flag.Bool("upnp", true, "automatically open ports on home router via UPnP IGD / NAT-PMP / PCP (standalone mode)")
	stunServer := flag.String("stun", "stun.cloudflare.com:3478", "STUN server or comma-separated list for 5ms external IP change detection (standalone mode)")
	stunInterval := flag.Duration("stun-interval", 1*time.Second, "how often to check external IP via STUN (standalone mode)")
	probeURL := flag.String("probe-url", "", "optional external probe endpoint (e.g. http://VPS_IP:8888/probe) for independent internet TCP/UDP reachability verification")
	duckShort := flag.String("duck", "", "automatic zero-config domain & DuckDNS sync (just pass -duck)")
	ddnsProvider := flag.String("ddns-provider", "", "built-in Dynamic DNS provider: 'duckdns', 'cloudflare', 'noip', or 'dynu'")
	ddnsDomain := flag.String("ddns-domain", "", "domain/subdomain to update when IP changes (e.g. myhome.duckdns.org)")
	ddnsToken := flag.String("ddns-token", "", "API token or password for Dynamic DNS provider")
	ddnsUser := flag.String("ddns-user", "", "username for No-IP / DynDNS / Dynu provider")
	ddnsZone := flag.String("ddns-zone", "", "Cloudflare Zone ID (when -ddns-provider=cloudflare)")
	ddnsURL := flag.String("ddns-url", "", "custom DDNS webhook URL (replaces {ip} with current external IP)")

	portsExplicit := false
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "-ports" || arg == "--ports" || strings.HasPrefix(arg, "-ports=") || strings.HasPrefix(arg, "--ports=") {
			portsExplicit = true
		}
		if arg == "-duck" || arg == "--duck" {
			if i+1 >= len(os.Args) || strings.HasPrefix(os.Args[i+1], "-") {
				os.Args[i] = "-duck=auto"
			}
		}
	}
	flag.Parse()

	if strings.TrimSpace(*gatewayAlias) != "" {
		*quicAddr = strings.TrimSpace(*gatewayAlias)
	}
	if strings.TrimSpace(*gwShortAlias) != "" {
		*quicAddr = strings.TrimSpace(*gwShortAlias)
	}
	if strings.TrimSpace(*vhostSingular) != "" {
		if *vhosts == "" {
			*vhosts = strings.TrimSpace(*vhostSingular)
		} else {
			*vhosts = *vhosts + "," + strings.TrimSpace(*vhostSingular)
		}
	}
	if strings.TrimSpace(*vps2Addr) != "" {
		second := strings.TrimSpace(*vps2Addr)
		if !strings.Contains(second, ":") {
			second += ":4242"
		}
		*quicAddr = strings.TrimSpace(*quicAddr) + "," + second
	}
	if d := strings.TrimSpace(*domainShort); d != "" {
		*enableTLS = true
		if strings.Contains(d, ":") {
			if *vhosts == "" {
				*vhosts = d
			} else {
				*vhosts = *vhosts + "," + d
			}
		} else if *ddnsDomain == "" {
			*ddnsDomain = d
		}
	}
	defaultCertDir = strings.TrimSpace(*certDir)
	defaultExternalProbeURL = strings.TrimSpace(*probeURL)
	defaultProbeAuthToken = strings.TrimSpace(*tokenFlag)
	if defaultProbeAuthToken == "" && strings.TrimSpace(*tokenFile) != "" {
		if b, err := os.ReadFile(strings.TrimSpace(*tokenFile)); err == nil {
			defaultProbeAuthToken = strings.TrimSpace(string(b))
		}
	}

	if runCheckCmd {
		runInteractiveCheck(*stunServer, *host, *ports, *duckShort, defaultExternalProbeURL)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	defaultTransportMode = strings.ToLower(strings.TrimSpace(*transportMode))
	defaultClientCAFile = strings.TrimSpace(*clientCA)
	defaultClientCert = strings.TrimSpace(*clientCert)
	defaultClientKey = strings.TrimSpace(*clientKey)
	defaultProxyProtocol = *proxyProto

	chosenNodeID := strings.TrimSpace(*nodeIDFlag)
	if chosenNodeID == "" {
		chosenNodeID = strings.TrimSpace(*nodeAliasFlag)
	}
	defaultAgentNodeID = sanitizeNodeID(chosenNodeID)

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
		vhostMap, err := parseVHosts(*vhosts)
		if err != nil {
			log.Fatalf("[standalone] %v", err)
		}
		var mappings []PortMapping
		if strings.TrimSpace(*ports) != "" || len(vhostMap) == 0 {
			mappings, err = parseMappingsWithDefault(*ports, *udpDefault)
			if err != nil {
				log.Fatalf("[standalone] %v", err)
			}
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
			ProbeURL:     defaultExternalProbeURL,
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
		var mappings []PortMapping
		if strings.TrimSpace(*ports) != "" {
			mappings, err = parseMappingsWithDefault(*ports, *udpDefault)
			if err != nil {
				log.Fatalf("[gateway] %v", err)
			}
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
					ddnsCfg.DomainKind = "ip-based (sslip.io)"
				} else if pubIP != "" {
					ddnsCfg.Domain = pubIP
					ddnsCfg.DomainKind = "raw-ip"
				}
			}
			*enableTLS = true
		}
		defaultGatewayDDNS = ddnsCfg
		if err := runGateway(ctx, *quicAddr, token, *direct, *vhostAddr, *httpsAddr, vhostMap, mappings, *maxMem, *maxBuf, *quicIdle, *quicKeepalive, *sessionTTL, *certDir, *tlsCertFile, *tlsKeyFile, *enableTLS, *sameLAN); err != nil {
			log.Fatalf("[gateway] %v", err)
		}
	} else {
		var agentMappings []PortMapping
		if portsExplicit {
			parsed, err := parseMappingsWithDefault(*ports, *udpDefault)
			if err != nil {
				log.Fatalf("[agent] %v", err)
			}
			agentMappings = parsed
		}
		var agentVHosts []VHostRoute
		if strings.TrimSpace(*vhosts) != "" {
			parsedVH, err := parseVHostRoutes(*vhosts)
			if err != nil {
				log.Fatalf("[agent] %v", err)
			}
			agentVHosts = parsedVH
		}
		defaultAgentMappings = agentMappings
		defaultAgentVHosts = agentVHosts
		if err := runAgentWithServices(ctx, defaultAgentNodeID, *quicAddr, *host, token, *lanIP, *fingerprint, agentMappings, agentVHosts, *maxBuf, *maxMem, *quicIdle, *quicKeepalive, *sessionTTL, portsAllow); err != nil {
			log.Fatalf("[agent] %v", err)
		}
	}
}
