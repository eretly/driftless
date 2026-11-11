package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DDNSConfig struct {
	Provider string
	Domain   string
	Token    string
	User     string
	ZoneID   string
	Webhook  string
}

type StandaloneConfig struct {
	TargetHost   string
	Mappings     []PortMapping
	VHostAddr    string
	HTTPSAddr    string
	DirectAddr   string
	VHostMap     map[string]uint16
	AllowedPorts map[uint16]struct{}
	EnableUPnP   bool
	EnableTLS    bool
	STUNServer   string
	STUNInterval time.Duration
	DDNS         DDNSConfig
	CertDir      string
	TLSCertFile  string
	TLSKeyFile   string
}

type cachedUDPAddr struct {
	addr      *net.UDPAddr
	expiresAt time.Time
}

var (
	stunCacheMu   sync.RWMutex
	stunAddrCache = make(map[string]cachedUDPAddr)
	stunFailCount atomic.Int32
)

func normalizeSTUNAddr(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "stun://")
	s = strings.TrimPrefix(s, "stun:")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		// If user passed hostname or IPv4 without port (e.g. -stun stun.cloudflare.com), default to standard RFC 5389 port 3478
		return s + ":3478"
	}
	return s
}

func buildSTUNServerList(stunAddr string) []string {
	var list []string
	for _, part := range strings.Split(stunAddr, ",") {
		if norm := normalizeSTUNAddr(part); norm != "" {
			list = append(list, norm)
		}
	}
	defaults := []string{
		"stun.cloudflare.com:3478",
		"stun.nextcloud.com:443",
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
	}
	list = append(list, defaults...)
	seen := make(map[string]struct{}, len(list))
	var out []string
	for _, srv := range list {
		if _, dup := seen[srv]; !dup {
			seen[srv] = struct{}{}
			out = append(out, srv)
		}
	}
	return out
}

func resolveSTUNAddr(stunAddr string) (*net.UDPAddr, error) {
	stunAddr = normalizeSTUNAddr(stunAddr)
	now := time.Now()
	stunCacheMu.RLock()
	entry, ok := stunAddrCache[stunAddr]
	stunCacheMu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.addr, nil
	}
	uaddr, err := net.ResolveUDPAddr("udp4", stunAddr)
	if err != nil {
		return nil, err
	}
	stunCacheMu.Lock()
	stunAddrCache[stunAddr] = cachedUDPAddr{
		addr:      uaddr,
		expiresAt: now.Add(5 * time.Minute),
	}
	stunCacheMu.Unlock()
	return uaddr, nil
}

func invalidateSTUNCache(stunAddr string) {
	stunAddr = normalizeSTUNAddr(stunAddr)
	stunCacheMu.Lock()
	delete(stunAddrCache, stunAddr)
	stunCacheMu.Unlock()
}

// querySTUNPublicIP performs a fast RFC 5389 UDP STUN Binding Request with cached DNS and Transaction ID validation.
func querySTUNPublicIP(stunAddr string, timeout time.Duration) (string, error) {
	perServerTimeout := timeout
	if perServerTimeout > 300*time.Millisecond {
		perServerTimeout = 300 * time.Millisecond
	}
	servers := buildSTUNServerList(stunAddr)
	for _, srv := range servers {
		ip, err := singleSTUNQuery(srv, perServerTimeout)
		if err == nil && ip != "" {
			stunFailCount.Store(0)
			return ip, nil
		}
		invalidateSTUNCache(srv)
	}
	// Only fall back to HTTP if UDP STUN failed on startup or 3 consecutive times
	if stunFailCount.Add(1) >= 3 {
		if ip := detectPublicIP(); ip != "" {
			stunFailCount.Store(0)
			return ip, nil
		}
	}
	return "", errors.New("stun public IP detection failed")
}

func singleSTUNQuery(stunAddr string, timeout time.Duration) (string, error) {
	raddr, err := resolveSTUNAddr(stunAddr)
	if err != nil {
		return "", err
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// RFC 5389 Binding Request (20 bytes):
	// Type 0x0001, Length 0x0000, Magic Cookie 0x2112A442, 12-byte random Transaction ID
	var req [20]byte
	binary.BigEndian.PutUint16(req[0:2], 0x0001)
	binary.BigEndian.PutUint16(req[2:4], 0x0000)
	binary.BigEndian.PutUint32(req[4:8], 0x2112A442)
	if _, err := rand.Read(req[8:20]); err != nil {
		return "", err
	}

	if _, err := conn.Write(req[:]); err != nil {
		return "", err
	}
	var resp [512]byte
	n, err := conn.Read(resp[:])
	if err != nil || n < 20 {
		return "", errors.New("short stun response")
	}
	// Verify Binding Success Response (0x0101), Magic Cookie (0x2112A442), and matching 12-byte Transaction ID
	if binary.BigEndian.Uint16(resp[0:2]) != 0x0101 ||
		binary.BigEndian.Uint32(resp[4:8]) != 0x2112A442 ||
		!bytes.Equal(resp[8:20], req[8:20]) {
		return "", errors.New("invalid stun response header or transaction id mismatch")
	}
	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	if 20+msgLen > n {
		msgLen = n - 20
	}
	offset := 20
	for offset+4 <= 20+msgLen {
		attrType := binary.BigEndian.Uint16(resp[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(resp[offset+2 : offset+4]))
		valStart := offset + 4
		if valStart+attrLen > n {
			break
		}
		val := resp[valStart : valStart+attrLen]
		// 0x0020 = XOR-MAPPED-ADDRESS, 0x0001 = MAPPED-ADDRESS, 0x8020 = XOR-MAPPED-ADDRESS (legacy)
		if (attrType == 0x0020 || attrType == 0x8020) && attrLen >= 8 && val[1] == 0x01 {
			var ipBytes [4]byte
			cookie := [4]byte{0x21, 0x12, 0xA4, 0x42}
			for i := 0; i < 4; i++ {
				ipBytes[i] = val[4+i] ^ cookie[i]
			}
			ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
			if !ip.IsLoopback() && !ip.IsUnspecified() {
				return ip.String(), nil
			}
		} else if attrType == 0x0001 && attrLen >= 8 && val[1] == 0x01 {
			ip := net.IPv4(val[4], val[5], val[6], val[7])
			if !ip.IsLoopback() && !ip.IsUnspecified() {
				return ip.String(), nil
			}
		}
		// STUN attributes are padded to 4-byte boundaries
		padded := (attrLen + 3) & ^3
		offset = valStart + padded
	}
	return "", errors.New("no mapped address in stun packet")
}

type upnpEndpoint struct {
	ctrlURL     string
	serviceType string
}

type trackedRouterMapping struct {
	InstanceID   string `json:"instance_id,omitempty"`
	Kind         string `json:"kind"` // "upnp", "natpmp", or "pcp"
	CtrlURL      string `json:"ctrl_url,omitempty"`
	ServiceType  string `json:"service_type,omitempty"`
	GatewayIP    string `json:"gateway_ip,omitempty"`
	LANIP        string `json:"lan_ip,omitempty"`
	Port         uint16 `json:"port"`
	InternalPort uint16 `json:"internal_port,omitempty"`
	Proto        string `json:"proto"`
	PCPNonce     string `json:"pcp_nonce,omitempty"`
}

const upnpStateFile = ".driftless-upnp-state.json"

var (
	upnpStateMu            sync.Mutex
	activeUPnPMappings     []trackedRouterMapping
	upnpInstanceIDOverride string
	upnpFallbackStateDir   = os.TempDir()
	upnpLockAcquireTimeout = 2 * time.Second
)

func currentUPnPInstanceID() string {
	if upnpInstanceIDOverride != "" {
		return upnpInstanceIDOverride
	}
	absPath, err := filepath.Abs(upnpStateFile)
	if err != nil {
		absPath = upnpStateFile
	}
	if realDir, err := filepath.EvalSymlinks(filepath.Dir(absPath)); err == nil {
		absPath = filepath.Join(realDir, filepath.Base(absPath))
	}
	sum := sha256.Sum256([]byte(absPath))
	return fmt.Sprintf("%x", sum[:8])
}

func resolveUPnPFallbackStateFile() string {
	baseDir := upnpFallbackStateDir
	if baseDir == "" {
		baseDir = os.TempDir()
	}
	return filepath.Join(baseDir, fmt.Sprintf(".driftless-upnp-state-fallback-%s.json", currentUPnPInstanceID()))
}

func resolveUPnPStateLockFile() string {
	baseDir := upnpFallbackStateDir
	if baseDir == "" {
		baseDir = os.TempDir()
	}
	return filepath.Join(baseDir, fmt.Sprintf(".driftless-upnp-state-%s.lock", currentUPnPInstanceID()))
}

func parseLockFilePayload(raw []byte) (int, string, bool) {
	s := strings.TrimSpace(string(raw))
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	tok := strings.TrimSpace(parts[1])
	if err != nil || pid <= 0 || tok == "" {
		return 0, "", false
	}
	return pid, tok, true
}

func releaseUPnPStateFileLock(lockPath, expectedPayload string) {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return
	}
	if string(raw) != expectedPayload {
		// Lock does not belong to us; never remove another owner's lock.
		return
	}
	_ = os.Remove(lockPath)
}

// withUPnPStateFileLock acquires an exclusive cross-process lock file scoped to the current
// installation before reading, writing, or removing UPnP state files.
// If the lock cannot be acquired within upnpLockAcquireTimeout, it returns an error and NEVER executes fn().
// Stale locks are only recovered if the recorded owner PID is no longer alive in the OS kernel.
func withUPnPStateFileLock(fn func() error) error {
	lockPath := resolveUPnPStateLockFile()
	var tokBytes [16]byte
	if _, err := rand.Read(tokBytes[:]); err != nil {
		return fmt.Errorf("generate lock owner token: %w", err)
	}
	ownerToken := hex.EncodeToString(tokBytes[:])
	payload := fmt.Sprintf("%d:%s\n", os.Getpid(), ownerToken)

	timeout := upnpLockAcquireTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, writeErr := f.Write([]byte(payload))
			syncErr := f.Sync()
			closeErr := f.Close()
			if writeErr != nil || syncErr != nil || closeErr != nil {
				_ = os.Remove(lockPath)
				if writeErr != nil {
					return fmt.Errorf("write UPnP state lock %s: %w", lockPath, writeErr)
				}
				if syncErr != nil {
					return fmt.Errorf("sync UPnP state lock %s: %w", lockPath, syncErr)
				}
				return fmt.Errorf("close UPnP state lock %s: %w", lockPath, closeErr)
			}
			// Verify ownership in case of concurrent filesystem intervention
			if verifyRaw, rErr := os.ReadFile(lockPath); rErr != nil || string(verifyRaw) != payload {
				return fmt.Errorf("verify UPnP state lock ownership for %s failed", lockPath)
			}
			defer releaseUPnPStateFileLock(lockPath, payload)
			return fn()
		}

		if !os.IsExist(err) {
			return fmt.Errorf("acquire UPnP state lock %s: %w", lockPath, err)
		}

		// Inspect existing lock file: only recover if the owner process is confirmed dead by the OS kernel.
		if raw, rErr := os.ReadFile(lockPath); rErr == nil {
			if holderPID, holderTok, ok := parseLockFilePayload(raw); ok {
				if holderPID != os.Getpid() && !isLockOwnerProcessAlive(holderPID) {
					deadPath := fmt.Sprintf("%s.dead-%s", lockPath, holderTok)
					if os.Rename(lockPath, deadPath) == nil {
						_ = os.Remove(deadPath)
						continue
					}
				}
			}
		}

		if time.Now().After(deadline) {
			log.Printf("[standalone] ERROR: timed out waiting for UPnP state lock %s; refusing unlocked state modification", lockPath)
			return fmt.Errorf("timed out acquiring UPnP state lock %s: %w", lockPath, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sameTrackedRouterMapping(a, b trackedRouterMapping) bool {
	return a.Kind == b.Kind &&
		a.CtrlURL == b.CtrlURL &&
		a.ServiceType == b.ServiceType &&
		a.GatewayIP == b.GatewayIP &&
		a.Port == b.Port &&
		strings.EqualFold(a.Proto, b.Proto)
}

func appendUniqueTrackedMapping(list []trackedRouterMapping, m trackedRouterMapping) []trackedRouterMapping {
	if m.InstanceID == "" {
		m.InstanceID = currentUPnPInstanceID()
	}
	for _, ex := range list {
		if sameTrackedRouterMapping(ex, m) {
			return list
		}
	}
	return append(list, m)
}

func removeInstanceFallbackStateFileLocked() error {
	fbPath := resolveUPnPFallbackStateFile()
	if fbPath == "" {
		return nil
	}
	instID := currentUPnPInstanceID()
	if raw, err := os.ReadFile(fbPath); err == nil && len(raw) > 0 {
		var existing []trackedRouterMapping
		if json.Unmarshal(raw, &existing) == nil && len(existing) > 0 {
			for _, m := range existing {
				if m.InstanceID != "" && m.InstanceID != instID {
					log.Printf("[standalone] WARNING: refusing to delete fallback state file %s owned by another instance (%s != %s)", fbPath, m.InstanceID, instID)
					return fmt.Errorf("fallback state file %s belongs to instance %s", fbPath, m.InstanceID)
				}
			}
		}
	}
	if err := os.Remove(fbPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func saveTrackedRouterMappingsLocked() error {
	return withUPnPStateFileLock(func() error {
		instID := currentUPnPInstanceID()
		for i := range activeUPnPMappings {
			if activeUPnPMappings[i].InstanceID == "" {
				activeUPnPMappings[i].InstanceID = instID
			}
		}
		if len(activeUPnPMappings) == 0 {
			fbErr := removeInstanceFallbackStateFileLocked()
			if err := os.Remove(upnpStateFile); err != nil && !os.IsNotExist(err) {
				log.Printf("[standalone] ERROR: failed to remove UPnP state file %s: %v", upnpStateFile, err)
				return err
			}
			if fbErr != nil {
				log.Printf("[standalone] ERROR: failed to remove fallback UPnP state file %s: %v", resolveUPnPFallbackStateFile(), fbErr)
				return fbErr
			}
			return nil
		}
		raw, err := json.MarshalIndent(activeUPnPMappings, "", "  ")
		if err != nil {
			log.Printf("[standalone] ERROR: failed to serialize UPnP state for %s: %v (WARNING: router port mappings will not be guaranteed to be removed automatically after a crash)", upnpStateFile, err)
			return err
		}
		if err := writeFileAtomic0600(upnpStateFile, raw); err != nil {
			log.Printf("[standalone] ERROR: failed to save UPnP state file %s: %v (WARNING: router port mappings will not be guaranteed to be removed automatically after a crash or restart)", upnpStateFile, err)
			return err
		}
		if fbErr := removeInstanceFallbackStateFileLocked(); fbErr != nil {
			log.Printf("[standalone] WARNING: saved UPnP state file %s, but failed to clean up fallback state file %s: %v", upnpStateFile, resolveUPnPFallbackStateFile(), fbErr)
			return fbErr
		}
		return nil
	})
}

func saveFallbackRouterMappingsLocked() error {
	return withUPnPStateFileLock(func() error {
		fbPath := resolveUPnPFallbackStateFile()
		if fbPath == "" {
			return errors.New("empty fallback UPnP state file path")
		}
		if len(activeUPnPMappings) == 0 {
			return removeInstanceFallbackStateFileLocked()
		}
		instID := currentUPnPInstanceID()
		for i := range activeUPnPMappings {
			if activeUPnPMappings[i].InstanceID == "" {
				activeUPnPMappings[i].InstanceID = instID
			}
		}
		raw, err := json.MarshalIndent(activeUPnPMappings, "", "  ")
		if err != nil {
			log.Printf("[standalone] CRITICAL: failed to serialize fallback UPnP state for %s: %v", fbPath, err)
			return err
		}
		if err := writeFileAtomic0600(fbPath, raw); err != nil {
			log.Printf("[standalone] CRITICAL: failed to save fallback UPnP state file %s: %v (automatic router rule recovery after a crash CANNOT be guaranteed!)", fbPath, err)
			return err
		}
		return nil
	})
}

func recordTrackedRouterMapping(m trackedRouterMapping) error {
	upnpStateMu.Lock()
	defer upnpStateMu.Unlock()
	if m.InstanceID == "" {
		m.InstanceID = currentUPnPInstanceID()
	}
	for i, ex := range activeUPnPMappings {
		if sameTrackedRouterMapping(ex, m) {
			if m.PCPNonce != "" {
				activeUPnPMappings[i].PCPNonce = m.PCPNonce
			}
			return saveTrackedRouterMappingsLocked()
		}
	}
	activeUPnPMappings = append(activeUPnPMappings, m)
	if err := saveTrackedRouterMappingsLocked(); err != nil {
		activeUPnPMappings = activeUPnPMappings[:len(activeUPnPMappings)-1]
		return err
	}
	return nil
}

func existingPCPNonceForGatewayPort(gatewayIP string, port uint16, proto string) string {
	upnpStateMu.Lock()
	defer upnpStateMu.Unlock()
	for _, ex := range activeUPnPMappings {
		if ex.GatewayIP == gatewayIP && ex.Port == port && strings.EqualFold(ex.Proto, proto) && ex.PCPNonce != "" {
			return ex.PCPNonce
		}
	}
	return ""
}

// rollbackOrRetainRouterMapping attempts to immediately delete a newly created UPnP/NAT-PMP rule
// when persisting the state file fails. If the rollback deletion also fails after retries, the rule
// is retained in activeUPnPMappings and atomically saved to the per-instance fallback state file.
// Returns a non-nil error if both router rollback AND fallback persistence fail so the caller can abort further mappings.
func rollbackOrRetainRouterMapping(m trackedRouterMapping) error {
	if m.InstanceID == "" {
		m.InstanceID = currentUPnPInstanceID()
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(25 * time.Millisecond)
		}
		if err := deleteSingleRouterMapping(m); err == nil {
			log.Printf("[standalone] rolled back %s mapping %s/%d because state file %s could not be saved", strings.ToUpper(m.Kind), m.Proto, m.Port, upnpStateFile)
			return nil
		} else {
			lastErr = err
		}
	}
	fbPath := resolveUPnPFallbackStateFile()
	upnpStateMu.Lock()
	activeUPnPMappings = appendUniqueTrackedMapping(activeUPnPMappings, m)
	var persistErr error
	if err := saveTrackedRouterMappingsLocked(); err != nil {
		persistErr = saveFallbackRouterMappingsLocked()
	}
	upnpStateMu.Unlock()
	if persistErr != nil {
		log.Printf("[standalone] CRITICAL: failed to rollback %s mapping %s/%d (%v) AND failed to persist fallback state %s (%v); recovery after crash is NOT guaranteed", strings.ToUpper(m.Kind), m.Proto, m.Port, lastErr, fbPath, persistErr)
		return fmt.Errorf("rollback failed (%v) and fallback state write failed (%w)", lastErr, persistErr)
	}
	log.Printf("[standalone] ERROR: failed to rollback %s mapping %s/%d after state-file write error: %v (retained in memory and fallback state %s for recovery cleanup)", strings.ToUpper(m.Kind), m.Proto, m.Port, lastErr, fbPath)
	return nil
}

func deleteSingleRouterMapping(m trackedRouterMapping) error {
	intPort := m.InternalPort
	if intPort == 0 {
		intPort = m.Port
	}
	if m.Kind == "upnp" && m.CtrlURL != "" && m.ServiceType != "" {
		return upnpDeletePortMapping(m.CtrlURL, m.ServiceType, m.Port, m.Proto)
	}
	if m.Kind == "pcp" && m.GatewayIP != "" {
		targetAddr, err := normalizeGatewayUDPAddr(m.GatewayIP)
		if err != nil {
			return err
		}
		_, err = pcpSetPortMapping(targetAddr, m.LANIP, intPort, 0, m.Proto, 0, m.PCPNonce)
		return err
	}
	if m.Kind == "natpmp" && m.GatewayIP != "" {
		_, _, err := natPMPSetPortMappingWithNonce(m.GatewayIP, m.LANIP, intPort, 0, m.Proto, 0, m.PCPNonce)
		return err
	}
	return nil
}

// cleanupRouterMappingsList attempts to delete each rule on the router and returns
// both the count of deleted rules and the slice of rules whose deletion failed.
func cleanupRouterMappingsList(list []trackedRouterMapping) (int, []trackedRouterMapping) {
	removed := 0
	var failed []trackedRouterMapping
	for _, m := range list {
		if err := deleteSingleRouterMapping(m); err == nil {
			removed++
		} else {
			failed = append(failed, m)
		}
	}
	return removed, failed
}

// salvageTrackedMappingsFromCorruptJSON scans raw bytes from a partially corrupted state file
// and extracts any intact JSON objects representing valid trackedRouterMapping entries.
func salvageTrackedMappingsFromCorruptJSON(raw []byte) []trackedRouterMapping {
	var salvaged []trackedRouterMapping
	inString := false
	escaped := false
	depth := 0
	objStart := -1
	for i, b := range raw {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		if b == '"' {
			inString = true
			continue
		}
		if b == '{' {
			if depth == 0 {
				objStart = i
			}
			depth++
		} else if b == '}' && depth > 0 {
			depth--
			if depth == 0 && objStart >= 0 {
				var m trackedRouterMapping
				if err := json.Unmarshal(raw[objStart:i+1], &m); err == nil && m.Port > 0 && m.Proto != "" && (m.Kind == "upnp" || m.Kind == "natpmp" || m.Kind == "pcp") {
					salvaged = appendUniqueTrackedMapping(salvaged, m)
				}
				objStart = -1
			}
		}
	}
	return salvaged
}

func loadTrackedMappingsFromFile(path string) ([]trackedRouterMapping, bool) {
	if path == "" {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	var list []trackedRouterMapping
	if err := json.Unmarshal(raw, &list); err != nil {
		corruptPath := fmt.Sprintf("%s.corrupt-%d", path, time.Now().UnixNano())
		if renErr := os.Rename(path, corruptPath); renErr != nil {
			log.Printf("[standalone] WARNING: corrupted UPnP state file %s (%v); failed to rename to %s (%v), keeping file in place for diagnostics", path, err, corruptPath, renErr)
		} else {
			log.Printf("[standalone] WARNING: corrupted UPnP state file %s (%v); preserved diagnostic copy at %s", path, err, corruptPath)
		}
		salvaged := salvageTrackedMappingsFromCorruptJSON(raw)
		if len(salvaged) > 0 {
			log.Printf("[standalone] salvaged %d valid UPnP/NAT-PMP rule(s) from corrupted state file %s", len(salvaged), path)
			return salvaged, true
		}
		return nil, false
	}
	if len(list) == 0 {
		_ = os.Remove(path)
		return nil, false
	}
	instID := currentUPnPInstanceID()
	var owned []trackedRouterMapping
	for _, m := range list {
		if m.InstanceID == "" || m.InstanceID == instID {
			owned = appendUniqueTrackedMapping(owned, m)
		}
	}
	return owned, len(owned) > 0
}

func cleanupStaleUPnPState() (int, error) {
	fbPath := resolveUPnPFallbackStateFile()
	primaryList, hasPrimary := loadTrackedMappingsFromFile(upnpStateFile)
	fallbackList, hasFallback := loadTrackedMappingsFromFile(fbPath)
	if !hasPrimary && !hasFallback {
		return 0, nil
	}
	var stale []trackedRouterMapping
	for _, m := range primaryList {
		stale = appendUniqueTrackedMapping(stale, m)
	}
	for _, m := range fallbackList {
		stale = appendUniqueTrackedMapping(stale, m)
	}
	if len(stale) == 0 {
		return 0, nil
	}

	removed, failed := cleanupRouterMappingsList(stale)
	upnpStateMu.Lock()
	var kept []trackedRouterMapping
	for _, cur := range activeUPnPMappings {
		wasDeleted := false
		for _, st := range stale {
			if sameTrackedRouterMapping(cur, st) {
				stillFailed := false
				for _, fm := range failed {
					if sameTrackedRouterMapping(st, fm) {
						stillFailed = true
						break
					}
				}
				if !stillFailed {
					wasDeleted = true
				}
				break
			}
		}
		if !wasDeleted {
			kept = appendUniqueTrackedMapping(kept, cur)
		}
	}
	for _, fm := range failed {
		kept = appendUniqueTrackedMapping(kept, fm)
	}
	activeUPnPMappings = kept
	var persistErr error
	if err := saveTrackedRouterMappingsLocked(); err != nil {
		if fbErr := saveFallbackRouterMappingsLocked(); fbErr != nil {
			persistErr = fmt.Errorf("primary state save failed (%v) and fallback state save failed (%w)", err, fbErr)
			log.Printf("[standalone] CRITICAL: failed to persist remaining stale UPnP state: %v (automatic recovery of %d router rule(s) is NOT guaranteed)", persistErr, len(activeUPnPMappings))
		} else {
			log.Printf("[standalone] WARNING: primary UPnP state save failed (%v); saved %d remaining stale rule(s) to fallback %s", err, len(activeUPnPMappings), fbPath)
		}
	}
	upnpStateMu.Unlock()

	if removed > 0 {
		log.Printf("[standalone] cleaned up %d stale UPnP/NAT-PMP router port rule(s) from previous session", removed)
	}
	if len(failed) > 0 {
		log.Printf("[standalone] %d stale UPnP/NAT-PMP rule(s) could not be deleted yet (retained in %s for retry)", len(failed), upnpStateFile)
	}
	return removed, persistErr
}

func cleanupActiveUPnPMappings() (int, error) {
	upnpStateMu.Lock()
	toRemove := append([]trackedRouterMapping(nil), activeUPnPMappings...)
	upnpStateMu.Unlock()

	if len(toRemove) == 0 {
		upnpStateMu.Lock()
		var persistErr error
		if err := saveTrackedRouterMappingsLocked(); err != nil {
			if fbErr := saveFallbackRouterMappingsLocked(); fbErr != nil {
				persistErr = fmt.Errorf("primary state cleanup failed (%v) and fallback state cleanup failed (%w)", err, fbErr)
			}
		}
		upnpStateMu.Unlock()
		if persistErr != nil {
			log.Printf("[standalone] ERROR: failed to clean up empty UPnP state files: %v", persistErr)
		}
		return 0, persistErr
	}

	removed, failed := cleanupRouterMappingsList(toRemove)

	upnpStateMu.Lock()
	var remaining []trackedRouterMapping
	for _, cur := range activeUPnPMappings {
		wasAttempted := false
		for _, att := range toRemove {
			if sameTrackedRouterMapping(cur, att) {
				wasAttempted = true
				break
			}
		}
		if !wasAttempted {
			remaining = appendUniqueTrackedMapping(remaining, cur)
		}
	}
	for _, fm := range failed {
		remaining = appendUniqueTrackedMapping(remaining, fm)
	}
	activeUPnPMappings = remaining
	var persistErr error
	if err := saveTrackedRouterMappingsLocked(); err != nil {
		if fbErr := saveFallbackRouterMappingsLocked(); fbErr != nil {
			persistErr = fmt.Errorf("primary state save failed (%v) and fallback state save failed (%w)", err, fbErr)
			log.Printf("[standalone] CRITICAL: failed to persist remaining UPnP state on shutdown: %v (automatic recovery of %d router rule(s) on next startup is NOT guaranteed)", persistErr, len(activeUPnPMappings))
		} else {
			log.Printf("[standalone] WARNING: primary UPnP state save failed (%v); saved %d remaining rule(s) to fallback %s", err, len(activeUPnPMappings), resolveUPnPFallbackStateFile())
		}
	}
	upnpStateMu.Unlock()

	if removed > 0 {
		log.Printf("[standalone] removed %d UPnP/NAT-PMP router port rule(s) on shutdown", removed)
	}
	if len(failed) > 0 {
		log.Printf("[standalone] warning: %d UPnP/NAT-PMP rule(s) could not be removed (router unreachable); kept in %s for next startup cleanup", len(failed), upnpStateFile)
	}
	return removed, persistErr
}

// autoForwardRouterPorts maps public ports on the home router using UPnP IGD (v1 & v2), NAT-PMP (RFC 6886), and PCP (RFC 6887).
func autoForwardRouterPorts(lanIP string, mappings []PortMapping, vhostAddr, httpsAddr string) int {
	endpoints := discoverUPnPEndpoints(1200 * time.Millisecond)
	candidates := discoverCandidateGatewayIPs(lanIP, endpoints)
	gwIP := ""
	if len(candidates) > 0 {
		gwIP = strings.Join(candidates, ",")
	}
	return autoForwardRouterPortsWithEndpoints(lanIP, mappings, vhostAddr, httpsAddr, endpoints, gwIP)
}

func autoForwardRouterPortsWithEndpoints(lanIP string, mappings []PortMapping, vhostAddr, httpsAddr string, endpoints []upnpEndpoint, gwIP string) int {
	type portSpec struct {
		extPort uint16
		intPort uint16
		proto   string
	}
	seen := make(map[string]struct{})
	var specs []portSpec
	addSpec := func(extP, intP uint16, proto string) {
		if extP == 0 {
			return
		}
		if intP == 0 {
			intP = extP
		}
		k := fmt.Sprintf("%s:%d", proto, extP)
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			specs = append(specs, portSpec{extPort: extP, intPort: intP, proto: proto})
		}
	}
	for _, m := range mappings {
		tcpInt := m.RouterTCPPort
		if tcpInt == 0 {
			tcpInt = m.PublicPort
		}
		udpInt := m.RouterUDPPort
		if udpInt == 0 {
			udpInt = m.PublicPort
		}
		if m.Proto == "udp" {
			addSpec(m.PublicPort, udpInt, "UDP")
		} else if m.Proto == "both" {
			addSpec(m.PublicPort, tcpInt, "TCP")
			addSpec(m.PublicPort, udpInt, "UDP")
		} else {
			addSpec(m.PublicPort, tcpInt, "TCP")
		}
	}
	for _, addr := range []string{vhostAddr, httpsAddr} {
		if addr != "" {
			if _, portStr, err := net.SplitHostPort(addr); err == nil {
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
					addSpec(uint16(p), uint16(p), "TCP")
				}
			}
		}
	}

	var gwCandidates []string
	for _, part := range strings.Split(gwIP, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			gwCandidates = append(gwCandidates, part)
		}
	}

	mappedCount := 0
	for _, sp := range specs {
		ok := false
		stateWriteFailed := false
		for _, ep := range endpoints {
			if err := upnpAddPortMappingExtInt(ep.ctrlURL, ep.serviceType, lanIP, sp.extPort, sp.intPort, sp.proto); err == nil {
				rule := trackedRouterMapping{
					InstanceID:   currentUPnPInstanceID(),
					Kind:         "upnp",
					CtrlURL:      ep.ctrlURL,
					ServiceType:  ep.serviceType,
					LANIP:        lanIP,
					Port:         sp.extPort,
					InternalPort: sp.intPort,
					Proto:        sp.proto,
				}
				if err := recordTrackedRouterMapping(rule); err != nil {
					stateWriteFailed = true
					if rbErr := rollbackOrRetainRouterMapping(rule); rbErr != nil {
						log.Printf("[standalone] CRITICAL: aborting remaining UPnP/NAT-PMP port mappings due to unrecoverable state & rollback failure: %v", rbErr)
						return mappedCount
					}
					break
				}
				ok = true
			}
		}
		if !ok && !stateWriteFailed && len(gwCandidates) > 0 {
			for _, candidateGW := range gwCandidates {
				prevNonce := existingPCPNonceForGatewayPort(candidateGW, sp.extPort, sp.proto)
				if kind, pcpNonce, err := natPMPSetPortMappingWithNonce(candidateGW, lanIP, sp.intPort, sp.extPort, sp.proto, 3600, prevNonce); err == nil {
					rule := trackedRouterMapping{
						InstanceID:   currentUPnPInstanceID(),
						Kind:         kind,
						GatewayIP:    candidateGW,
						LANIP:        lanIP,
						Port:         sp.extPort,
						InternalPort: sp.intPort,
						Proto:        sp.proto,
						PCPNonce:     pcpNonce,
					}
					if err := recordTrackedRouterMapping(rule); err != nil {
						if rbErr := rollbackOrRetainRouterMapping(rule); rbErr != nil {
							log.Printf("[standalone] CRITICAL: aborting remaining NAT-PMP/PCP port mappings due to unrecoverable state & rollback failure: %v", rbErr)
							return mappedCount
						}
					} else {
						ok = true
					}
					break
				}
			}
		}
		if ok {
			mappedCount++
		}
	}
	return mappedCount
}

// isSafeRouterURL ensures UPnP SSDP Location and SOAP ControlURL endpoints point strictly
// to private RFC1918 LAN addresses or loopback (127.0.0.1 for local tests), blocking SSRF
// to cloud metadata (169.254.169.254) or external internet hosts.
func isSafeRouterURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4.IsPrivate() || v4.IsLoopback()
}

// newSafeRouterHTTPClient returns an HTTP client for UPnP discovery and SOAP requests
// that enforces SSRF checks on both HTTP redirects (requiring same-host RFC1918/loopback targets)
// and the underlying TCP socket dialer.
func newSafeRouterHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid router address %q: %w", addr, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return nil, fmt.Errorf("blocked non-literal router host %q", host)
			}
			v4 := ip.To4()
			if v4 == nil || (!v4.IsPrivate() && !v4.IsLoopback()) {
				return nil, fmt.Errorf("blocked unsafe router dial IP %q", host)
			}
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(v4.String(), port))
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many UPnP HTTP redirects")
			}
			if req == nil || req.URL == nil || !isSafeRouterURL(req.URL.String()) {
				return fmt.Errorf("blocked unsafe UPnP HTTP redirect target")
			}
			if len(via) > 0 && via[0].URL != nil && !strings.EqualFold(via[0].URL.Hostname(), req.URL.Hostname()) {
				return fmt.Errorf("blocked cross-host UPnP HTTP redirect from %q to %q", via[0].URL.Hostname(), req.URL.Hostname())
			}
			return nil
		},
	}
}

func discoverUPnPEndpoints(timeout time.Duration) []upnpEndpoint {
	ssdpAddr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return nil
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	targets := []string{
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:2",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANIPConnection:2",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		"upnp:rootdevice",
	}
	for _, st := range targets {
		req := fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: %s\r\n\r\n", st)
		_, _ = conn.WriteToUDP([]byte(req), ssdpAddr)
	}

	var locations []string
	seenLoc := make(map[string]struct{})
	var buf [2048]byte
	for i := 0; i < 16; i++ {
		n, _, err := conn.ReadFromUDP(buf[:])
		if err != nil || n == 0 {
			break
		}
		lines := strings.Split(string(buf[:n]), "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "location:") {
				loc := strings.TrimSpace(line[9:])
				if loc != "" && isSafeRouterURL(loc) {
					if _, dup := seenLoc[loc]; !dup {
						seenLoc[loc] = struct{}{}
						locations = append(locations, loc)
					}
				}
			}
		}
	}
	if len(locations) == 0 {
		return nil
	}

	client := newSafeRouterHTTPClient(timeout)
	var endpoints []upnpEndpoint
	seenCtrl := make(map[string]struct{})

	for _, location := range locations {
		resp, err := client.Get(location)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		var finalReqURL *url.URL
		if resp.Request != nil {
			finalReqURL = resp.Request.URL
		}
		for _, ep := range parseUPnPDescriptionXML(location, finalReqURL, body) {
			key := ep.ctrlURL + "|" + ep.serviceType
			if _, dup := seenCtrl[key]; !dup {
				seenCtrl[key] = struct{}{}
				endpoints = append(endpoints, ep)
			}
		}
	}
	return endpoints
}

// parseUPnPDescriptionXML extracts WANIPConnection and WANPPPConnection (v1 & v2) services
// from a router's UPnP root description XML, honoring optional <URLBase> tags (D-Link, Netgear,
// ZyXEL, TP-Link) and trimming multiline whitespace inside tags (Huawei, ZTE, Realtek SDK).
func parseUPnPDescriptionXML(location string, finalReqURL *url.URL, body []byte) []upnpEndpoint {
	baseURL, err := url.Parse(strings.TrimSpace(location))
	if err != nil || !isSafeRouterURL(baseURL.String()) {
		return nil
	}
	if finalReqURL != nil && isSafeRouterURL(finalReqURL.String()) && strings.EqualFold(baseURL.Hostname(), finalReqURL.Hostname()) {
		baseURL = finalReqURL
	}

	type xmlService struct {
		ServiceType string `xml:"serviceType"`
		ControlURL  string `xml:"controlURL"`
	}

	var endpoints []upnpEndpoint
	seenCtrl := make(map[string]struct{})
	decoder := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if strings.EqualFold(se.Name.Local, "URLBase") {
			var rawBase string
			if err := decoder.DecodeElement(&rawBase, &se); err == nil {
				rawBase = strings.TrimSpace(rawBase)
				if rawBase != "" && isSafeRouterURL(rawBase) {
					if parsedBase, err := url.Parse(rawBase); err == nil && strings.EqualFold(parsedBase.Hostname(), baseURL.Hostname()) {
						baseURL = parsedBase
					}
				}
			}
			continue
		}
		if strings.EqualFold(se.Name.Local, "service") {
			var s xmlService
			if err := decoder.DecodeElement(&s, &se); err == nil {
				svcType := strings.TrimSpace(s.ServiceType)
				ctrlRaw := strings.TrimSpace(s.ControlURL)
				if svcType == "" || ctrlRaw == "" {
					continue
				}
				if strings.Contains(svcType, "WANPPPConnection") || strings.Contains(svcType, "WANIPConnection") {
					if relURL, err := url.Parse(ctrlRaw); err == nil {
						fullCtrl := baseURL.ResolveReference(relURL).String()
						if !isSafeRouterURL(fullCtrl) || !strings.EqualFold(baseURL.Hostname(), relURLHostOrBase(baseURL, relURL)) {
							continue
						}
						key := fullCtrl + "|" + svcType
						if _, dup := seenCtrl[key]; !dup {
							seenCtrl[key] = struct{}{}
							endpoints = append(endpoints, upnpEndpoint{ctrlURL: fullCtrl, serviceType: svcType})
						}
					}
				}
			}
		}
	}
	return endpoints
}

func relURLHostOrBase(baseURL, relURL *url.URL) string {
	if relURL != nil && relURL.Host != "" {
		return relURL.Hostname()
	}
	if baseURL != nil {
		return baseURL.Hostname()
	}
	return ""
}

func discoverUPnPControlURL(timeout time.Duration) (string, string) {
	eps := discoverUPnPEndpoints(timeout)
	if len(eps) == 0 {
		return "", ""
	}
	return eps[0].ctrlURL, eps[0].serviceType
}

func isUPnPConflictError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "718") || strings.Contains(msg, "ConflictInMappingEntry") || strings.Contains(msg, "729")
}

func upnpAddPortMapping(ctrlURL, serviceType, lanIP string, port uint16, proto string) error {
	return upnpAddPortMappingExtInt(ctrlURL, serviceType, lanIP, port, port, proto)
}

func upnpAddPortMappingExtInt(ctrlURL, serviceType, lanIP string, extPort, intPort uint16, proto string) error {
	if intPort == 0 {
		intPort = extPort
	}
	// 1. Standard dynamic lease (3600s) required by OpenWrt/pfSense/OPNsense miniupnpd IGDv2
	err := upnpAddPortMappingWithLease(ctrlURL, serviceType, lanIP, extPort, intPort, proto, 3600)
	if err == nil {
		return nil
	}
	// 2. If port already has a conflicting/stale mapping (ErrorCode 718 on Asuswrt/TP-Link/Netgear/miniupnpd), delete and retry 3600s
	if isUPnPConflictError(err) {
		_ = upnpDeletePortMapping(ctrlURL, serviceType, extPort, proto)
		if retryErr := upnpAddPortMappingWithLease(ctrlURL, serviceType, lanIP, extPort, intPort, proto, 3600); retryErr == nil {
			return nil
		}
	}
	// 3. Permanent lease fallback (NewLeaseDuration=0) required by MikroTik, Keenetic, D-Link, Fritz!Box, and PPTP routers (ErrorCode 725)
	permErr := upnpAddPortMappingWithLease(ctrlURL, serviceType, lanIP, extPort, intPort, proto, 0)
	if permErr == nil {
		return nil
	}
	if isUPnPConflictError(permErr) {
		_ = upnpDeletePortMapping(ctrlURL, serviceType, extPort, proto)
		if retryPermErr := upnpAddPortMappingWithLease(ctrlURL, serviceType, lanIP, extPort, intPort, proto, 0); retryPermErr == nil {
			return nil
		}
	}
	// 4. Strict IGDv2 fallback: AddAnyPortMapping (when AddPortMapping is disabled with 606 Action Not Authorized on WANIPConnection:2 / WANPPPConnection:2)
	if strings.HasSuffix(strings.TrimSpace(serviceType), ":2") {
		if anyErr := upnpAddAnyPortMappingIGDv2(ctrlURL, serviceType, lanIP, extPort, intPort, proto, 3600); anyErr == nil {
			return nil
		}
	}
	return permErr
}

func upnpAddPortMappingWithLease(ctrlURL, serviceType, lanIP string, extPort, intPort uint16, proto string, leaseSeconds int) error {
	if !isSafeRouterURL(ctrlURL) {
		return fmt.Errorf("unsafe router UPnP control URL %q", ctrlURL)
	}
	proto = strings.ToUpper(strings.TrimSpace(proto))
	soapBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="%s">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
<NewInternalPort>%d</NewInternalPort>
<NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>driftless</NewPortMappingDescription>
<NewLeaseDuration>%d</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>`, serviceType, extPort, proto, intPort, lanIP, leaseSeconds)

	req, err := http.NewRequest("POST", ctrlURL, strings.NewReader(soapBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", fmt.Sprintf("\"%s#AddPortMapping\"", serviceType))
	client := newSafeRouterHTTPClient(1500 * time.Millisecond)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	_ = resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("upnp status %d (%s)", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
}

func upnpAddAnyPortMappingIGDv2(ctrlURL, serviceType, lanIP string, extPort, intPort uint16, proto string, leaseSeconds int) error {
	if !isSafeRouterURL(ctrlURL) {
		return fmt.Errorf("unsafe router UPnP control URL %q", ctrlURL)
	}
	proto = strings.ToUpper(strings.TrimSpace(proto))
	soapBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddAnyPortMapping xmlns:u="%s">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
<NewInternalPort>%d</NewInternalPort>
<NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>driftless</NewPortMappingDescription>
<NewLeaseDuration>%d</NewLeaseDuration>
</u:AddAnyPortMapping>
</s:Body>
</s:Envelope>`, serviceType, extPort, proto, intPort, lanIP, leaseSeconds)

	req, err := http.NewRequest("POST", ctrlURL, strings.NewReader(soapBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", fmt.Sprintf("\"%s#AddAnyPortMapping\"", serviceType))
	client := newSafeRouterHTTPClient(1500 * time.Millisecond)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upnp AddAnyPortMapping status %d", resp.StatusCode)
	}
	bodyStr := string(bodyBytes)
	if idx := strings.Index(bodyStr, "<NewReservedPort>"); idx >= 0 {
		var reserved int
		if _, err := fmt.Sscanf(bodyStr[idx:], "<NewReservedPort>%d</NewReservedPort>", &reserved); err == nil && reserved > 0 && reserved <= 65535 {
			if uint16(reserved) != extPort {
				_ = upnpDeletePortMapping(ctrlURL, serviceType, uint16(reserved), proto)
				return fmt.Errorf("router assigned mismatched external port %d instead of %d", reserved, extPort)
			}
		}
	}
	return nil
}

func upnpDeletePortMapping(ctrlURL, serviceType string, port uint16, proto string) error {
	if !isSafeRouterURL(ctrlURL) {
		return fmt.Errorf("unsafe router UPnP control URL %q", ctrlURL)
	}
	proto = strings.ToUpper(strings.TrimSpace(proto))
	soapBody := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:DeletePortMapping xmlns:u="%s">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
</u:DeletePortMapping>
</s:Body>
</s:Envelope>`, serviceType, port, proto)

	req, err := http.NewRequest("POST", ctrlURL, strings.NewReader(soapBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("SOAPAction", fmt.Sprintf("\"%s#DeletePortMapping\"", serviceType))
	client := newSafeRouterHTTPClient(1500 * time.Millisecond)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	_ = resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	bodyStr := string(bodyBytes)
	// UPnP ErrorCode 714 (NoSuchEntryInArray) or 713 (SpecifiedArrayIndexInvalid) means the mapping
	// already expired or was cleared when the router rebooted; treat deletion as idempotent success.
	if strings.Contains(bodyStr, "714") || strings.Contains(bodyStr, "NoSuchEntryInArray") ||
		strings.Contains(bodyStr, "713") || strings.Contains(bodyStr, "SpecifiedArrayIndexInvalid") {
		return nil
	}
	return fmt.Errorf("upnp delete status %d", resp.StatusCode)
}

func guessDefaultGatewayIP(lanIP string) string {
	ip := net.ParseIP(lanIP).To4()
	if ip == nil {
		return ""
	}
	return net.IPv4(ip[0], ip[1], ip[2], 1).String()
}

// discoverCandidateGatewayIPs returns private RFC1918 gateway IPs in priority order:
// SSDP-discovered router IPs, Linux /proc/net/route default gateway, subnet .1, and subnet .254.
func discoverCandidateGatewayIPs(lanIP string, endpoints []upnpEndpoint) []string {
	seen := make(map[string]struct{})
	var list []string
	addCandidate := func(ipStr string) {
		ip := net.ParseIP(strings.TrimSpace(ipStr)).To4()
		if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
			return
		}
		s := ip.String()
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			list = append(list, s)
		}
	}
	for _, ep := range endpoints {
		if u, err := url.Parse(ep.ctrlURL); err == nil {
			addCandidate(u.Hostname())
		}
	}
	if rawRoute, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(rawRoute), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[1] == "00000000" && len(fields[2]) == 8 {
				if gwHex, err := strconv.ParseUint(fields[2], 16, 32); err == nil && gwHex != 0 {
					gwIP := net.IPv4(byte(gwHex), byte(gwHex>>8), byte(gwHex>>16), byte(gwHex>>24))
					addCandidate(gwIP.String())
				}
			}
		}
	}
	if gw1 := guessDefaultGatewayIP(lanIP); gw1 != "" {
		addCandidate(gw1)
	}
	if ip := net.ParseIP(lanIP).To4(); ip != nil {
		addCandidate(net.IPv4(ip[0], ip[1], ip[2], 254).String())
	}
	return list
}

func natPMPAddPortMapping(gatewayIP string, port uint16, proto string) error {
	return natPMPAddPortMappingWithLAN(gatewayIP, detectLocalLANIP(), port, proto)
}

func natPMPAddPortMappingWithLAN(gatewayIP, lanIP string, port uint16, proto string) error {
	return natPMPSetPortMappingWithLAN(gatewayIP, lanIP, port, port, proto, 3600)
}

func natPMPDeletePortMapping(gatewayIP string, port uint16, proto string) error {
	return natPMPDeletePortMappingWithLAN(gatewayIP, detectLocalLANIP(), port, proto)
}

func natPMPDeletePortMappingWithLAN(gatewayIP, lanIP string, port uint16, proto string) error {
	return natPMPSetPortMappingWithLAN(gatewayIP, lanIP, port, 0, proto, 0)
}

func natPMPSetPortMapping(gatewayIP string, intPort, extPort uint16, proto string, lifetime uint32) error {
	return natPMPSetPortMappingWithLAN(gatewayIP, detectLocalLANIP(), intPort, extPort, proto, lifetime)
}

func normalizeGatewayUDPAddr(gatewayIP string) (string, error) {
	gatewayIP = strings.TrimSpace(gatewayIP)
	host := gatewayIP
	port := "5351"
	if h, p, err := net.SplitHostPort(gatewayIP); err == nil {
		host = h
		port = p
	}
	ip := net.ParseIP(host).To4()
	if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
		return "", fmt.Errorf("unsafe NAT-PMP/PCP gateway IP %q", gatewayIP)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// natPMPSetPortMappingWithLAN attempts RFC 6886 NAT-PMP (v0) first and automatically falls back
// to RFC 6887 PCP (Port Control Protocol v2) if the router requires version 2 on UDP port 5351.
func natPMPSetPortMappingWithLAN(gatewayIP, lanIP string, intPort, extPort uint16, proto string, lifetime uint32) error {
	_, _, err := natPMPSetPortMappingWithNonce(gatewayIP, lanIP, intPort, extPort, proto, lifetime, "")
	return err
}

// natPMPSetPortMappingWithNonce attempts RFC 6886 NAT-PMP (v0) first and automatically falls back
// to RFC 6887 PCP (Port Control Protocol v2) if the router requires version 2 on UDP port 5351.
// Returns the mapping kind ("natpmp" or "pcp") and the hex-encoded 96-bit PCP Mapping Nonce (if PCP was used).
func natPMPSetPortMappingWithNonce(gatewayIP, lanIP string, intPort, extPort uint16, proto string, lifetime uint32, pcpNonceHex string) (string, string, error) {
	targetAddr, err := normalizeGatewayUDPAddr(gatewayIP)
	if err != nil {
		return "", "", err
	}
	conn, err := net.DialTimeout("udp4", targetAddr, 500*time.Millisecond)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	var pkt [12]byte
	pkt[0] = 0 // NAT-PMP Version 0
	if strings.EqualFold(strings.TrimSpace(proto), "UDP") {
		pkt[1] = 1
	} else {
		pkt[1] = 2
	}
	binary.BigEndian.PutUint16(pkt[4:6], intPort)
	binary.BigEndian.PutUint16(pkt[6:8], extPort)
	binary.BigEndian.PutUint32(pkt[8:12], lifetime)
	if _, err := conn.Write(pkt[:]); err != nil {
		return "", "", err
	}
	var resp [64]byte
	n, err := conn.Read(resp[:])
	if err != nil || n < 4 {
		return "", "", errors.New("no nat-pmp reply")
	}
	resultCode := binary.BigEndian.Uint16(resp[2:4])
	// If router replies with PCP version 2 or NAT-PMP ResultCode 1 (Unsupported Version), fall back to RFC 6887 PCP v2
	if resp[0] == 2 || resultCode == 1 {
		usedNonce, pcpErr := pcpSetPortMapping(targetAddr, lanIP, intPort, extPort, proto, lifetime, pcpNonceHex)
		if pcpErr != nil {
			return "", "", pcpErr
		}
		return "pcp", usedNonce, nil
	}
	if n < 16 || resp[0] != 0 || resp[1] != 128+pkt[1] {
		return "", "", fmt.Errorf("invalid nat-pmp response header")
	}
	if resultCode != 0 {
		return "", "", fmt.Errorf("nat-pmp error %d", resultCode)
	}
	if lifetime > 0 {
		assignedPort := binary.BigEndian.Uint16(resp[10:12])
		if assignedPort != extPort {
			return "", "", fmt.Errorf("nat-pmp assigned mismatched port %d instead of %d", assignedPort, extPort)
		}
	}
	return "natpmp", "", nil
}

// pcpSetPortMapping implements RFC 6887 Port Control Protocol (PCP v2) MAP requests (60 bytes)
// using a cryptographically random 96-bit Mapping Nonce (or existing persisted nonceHex for renewals/deletions)
// and verifies that the server's response echoes the exact 96-bit Mapping Nonce, protocol, and internal port.
func pcpSetPortMapping(targetAddr, lanIP string, intPort, extPort uint16, proto string, lifetime uint32, nonceHex string) (string, error) {
	conn, err := net.DialTimeout("udp4", targetAddr, 500*time.Millisecond)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	clientIP := net.ParseIP(strings.TrimSpace(lanIP)).To4()
	if clientIP == nil {
		if localUDP, ok := conn.LocalAddr().(*net.UDPAddr); ok && localUDP.IP != nil {
			clientIP = localUDP.IP.To4()
		}
	}
	if clientIP == nil {
		clientIP = net.IPv4(127, 0, 0, 1)
	}

	var nonce [12]byte
	if decoded, err := hex.DecodeString(strings.TrimSpace(nonceHex)); err == nil && len(decoded) == 12 {
		copy(nonce[:], decoded)
	} else {
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", fmt.Errorf("failed to generate random PCP mapping nonce: %w", err)
		}
	}
	usedNonceHex := hex.EncodeToString(nonce[:])

	var pkt [60]byte
	pkt[0] = 2 // PCP Version 2
	pkt[1] = 1 // R=0 (Request), Opcode=1 (MAP)
	binary.BigEndian.PutUint32(pkt[4:8], lifetime)
	// Client IPv4-mapped IPv6 address (::ffff:a.b.c.d) in bytes 8..23
	pkt[18] = 0xff
	pkt[19] = 0xff
	copy(pkt[20:24], clientIP)

	// 96-bit cryptographically random Mapping Nonce in bytes 24..35 (RFC 6887 Section 11.1)
	copy(pkt[24:36], nonce[:])

	if strings.EqualFold(strings.TrimSpace(proto), "UDP") {
		pkt[36] = 17 // IANA UDP protocol number
	} else {
		pkt[36] = 6 // IANA TCP protocol number
	}
	binary.BigEndian.PutUint16(pkt[40:42], intPort)
	binary.BigEndian.PutUint16(pkt[42:44], extPort)
	// Suggested External IP Address (::ffff:0.0.0.0) in bytes 44..59
	pkt[54] = 0xff
	pkt[55] = 0xff

	if _, err := conn.Write(pkt[:]); err != nil {
		return "", err
	}
	var resp [60]byte
	n, err := conn.Read(resp[:])
	if err != nil || n < 60 {
		return "", errors.New("no pcp v2 reply")
	}
	if resp[0] != 2 || resp[1] != 0x81 {
		return "", fmt.Errorf("invalid pcp v2 response header")
	}
	if !bytes.Equal(resp[24:36], nonce[:]) {
		return "", errors.New("pcp v2 response mapping nonce mismatch")
	}
	if resp[36] != pkt[36] || binary.BigEndian.Uint16(resp[40:42]) != intPort {
		return "", errors.New("pcp v2 response protocol or internal port mismatch")
	}
	if resp[3] != 0 {
		return "", fmt.Errorf("pcp v2 error %d", resp[3])
	}
	if lifetime > 0 {
		assignedPort := binary.BigEndian.Uint16(resp[42:44])
		if assignedPort != extPort {
			_, _ = pcpSetPortMapping(targetAddr, lanIP, intPort, 0, proto, 0, usedNonceHex)
			return "", fmt.Errorf("pcp v2 assigned mismatched port %d instead of %d", assignedPort, extPort)
		}
	}
	return usedNonceHex, nil
}

// updateDDNS pushes the newly detected public IP to DuckDNS, Cloudflare, No-IP, or a custom webhook.
func updateDDNS(cfg DDNSConfig, newIP string) error {
	client := &http.Client{Timeout: 5 * time.Second}

	if cfg.Webhook != "" {
		targetURL := strings.ReplaceAll(cfg.Webhook, "{ip}", url.QueryEscape(newIP))
		resp, err := client.Get(targetURL)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}

	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		return nil
	}

	switch provider {
	case "duckdns":
		domain := strings.TrimSuffix(strings.TrimSpace(cfg.Domain), ".duckdns.org")
		u := fmt.Sprintf("https://www.duckdns.org/update?domains=%s&token=%s&ip=%s",
			url.QueryEscape(domain), url.QueryEscape(cfg.Token), url.QueryEscape(newIP))
		resp, err := client.Get(u)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		if !strings.HasPrefix(strings.TrimSpace(string(b)), "OK") {
			return fmt.Errorf("duckdns response: %s", strings.TrimSpace(string(b)))
		}
		return nil

	case "noip", "dyndns":
		u := fmt.Sprintf("https://dynupdate.no-ip.com/nic/update?hostname=%s&myip=%s",
			url.QueryEscape(cfg.Domain), url.QueryEscape(newIP))
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(cfg.User, cfg.Token)
		req.Header.Set("User-Agent", "driftless/"+versionString)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		return fmt.Errorf("no-ip status %d", resp.StatusCode)

	case "cloudflare":
		if cfg.ZoneID == "" || cfg.Token == "" || cfg.Domain == "" {
			return errors.New("cloudflare DDNS requires -ddns-zone, -ddns-token, and -ddns-domain")
		}
		listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s",
			url.PathEscape(cfg.ZoneID), url.QueryEscape(cfg.Domain))
		req, err := http.NewRequest("GET", listURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var listRes struct {
			Result []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&listRes); err != nil {
			return err
		}
		bodyMap := map[string]interface{}{
			"type":    "A",
			"name":    cfg.Domain,
			"content": newIP,
			"ttl":     60,
			"proxied": false,
		}
		payload, _ := json.Marshal(bodyMap)
		method := "POST"
		endpoint := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", url.PathEscape(cfg.ZoneID))
		if len(listRes.Result) > 0 && listRes.Result[0].ID != "" {
			method = "PUT"
			endpoint = fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
				url.PathEscape(cfg.ZoneID), url.PathEscape(listRes.Result[0].ID))
		}
		upReq, err := http.NewRequest(method, endpoint, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		upReq.Header.Set("Authorization", "Bearer "+cfg.Token)
		upReq.Header.Set("Content-Type", "application/json")
		upResp, err := client.Do(upReq)
		if err != nil {
			return err
		}
		defer upResp.Body.Close()
		if upResp.StatusCode >= 200 && upResp.StatusCode < 300 {
			return nil
		}
		return fmt.Errorf("cloudflare status %d", upResp.StatusCode)
	}
	return fmt.Errorf("unsupported -ddns-provider %q", cfg.Provider)
}

const ddnsCacheFile = ".driftless-ddns.json"

func extractDuckFromText(raw string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	if idx := strings.Index(strings.ToLower(s), "duckdns.org/update"); idx != -1 {
		sub := s[idx:]
		if endIdx := strings.IndexAny(sub, " \t\r\n\"'"); endIdx != -1 {
			sub = sub[:endIdx]
		}
		if u, err := url.Parse("https://" + sub); err == nil {
			q := u.Query()
			dom := strings.TrimSpace(q.Get("domains"))
			tok := strings.TrimSpace(q.Get("token"))
			if dom != "" && tok != "" {
				return dom, tok
			}
		}
	}
	if !strings.Contains(s, "://") && strings.Count(s, ":") == 1 {
		parts := strings.SplitN(s, ":", 2)
		dom := strings.TrimSpace(parts[0])
		tok := strings.TrimSpace(parts[1])
		if dom != "" && tok != "" && !strings.ContainsAny(dom, " \t\r\n") && !strings.ContainsAny(tok, " \t\r\n") {
			return dom, tok
		}
	}
	return "", ""
}

func formatDuckDomain(d string) string {
	d = strings.TrimSpace(d)
	if idx := strings.Index(d, ","); idx != -1 {
		d = strings.TrimSpace(d[:idx])
	}
	d = strings.TrimSuffix(strings.ToLower(d), ".duckdns.org")
	if d == "" {
		return ""
	}
	return d + ".duckdns.org"
}

func resolveAndPersistDDNS(cfg DDNSConfig, duckFlag string) DDNSConfig {
	duckFlag = strings.TrimSpace(duckFlag)
	explicitlyProvided := cfg.Provider != "" || cfg.Domain != "" || cfg.Token != "" || cfg.Webhook != "" || duckFlag != ""
	// Opt-in only: do nothing by default unless -duck (or -ddns-*) flag was explicitly passed
	if !explicitlyProvided {
		return DDNSConfig{}
	}

	if duckFlag != "" && !strings.EqualFold(duckFlag, "auto") {
		if dom, tok := extractDuckFromText(duckFlag); dom != "" && tok != "" {
			cfg.Provider = "duckdns"
			cfg.Domain = dom
			cfg.Token = tok
		}
	}

	if cfg.Webhook != "" && cfg.Domain == "" {
		if dom, _ := extractDuckFromText(cfg.Webhook); dom != "" {
			cfg.Domain = formatDuckDomain(dom)
		}
	}

	if cfg.Provider == "" && cfg.Domain != "" && cfg.Token != "" {
		if cfg.ZoneID != "" {
			cfg.Provider = "cloudflare"
		} else if cfg.User != "" {
			cfg.Provider = "noip"
		} else {
			cfg.Provider = "duckdns"
		}
	}

	// If user passed -duck auto, load from saved .driftless-ddns.json, environment variables, or local duckdns script
	if strings.EqualFold(duckFlag, "auto") && cfg.Provider == "" && cfg.Webhook == "" {
		if b, err := os.ReadFile(ddnsCacheFile); err == nil {
			var saved DDNSConfig
			if json.Unmarshal(b, &saved) == nil && (saved.Provider != "" || saved.Webhook != "") {
				cfg = saved
				log.Printf("[duckdns] loaded saved domain (%s) from %s", cfg.Domain, ddnsCacheFile)
			}
		}
		if cfg.Provider == "" && cfg.Webhook == "" {
			if envDuck := os.Getenv("DRIFTLESS_DUCKDNS"); envDuck != "" {
				if dom, tok := extractDuckFromText(envDuck); dom != "" && tok != "" {
					cfg.Provider = "duckdns"
					cfg.Domain = dom
					cfg.Token = tok
				}
			}
		}
		if cfg.Provider == "" && cfg.Webhook == "" {
			candidates := []string{"duckdns.txt", "duck.sh", "duck.bat"}
			if home, err := os.UserHomeDir(); err == nil && home != "" {
				candidates = append(candidates,
					filepath.Join(home, "duckdns", "duck.sh"),
					filepath.Join(home, ".duckdns"),
				)
			}
			for _, path := range candidates {
				if b, err := os.ReadFile(path); err == nil {
					if dom, tok := extractDuckFromText(string(b)); dom != "" && tok != "" {
						cfg.Provider = "duckdns"
						cfg.Domain = dom
						cfg.Token = tok
						log.Printf("[duckdns] found domain %q in %s", formatDuckDomain(dom), path)
						break
					}
				}
			}
		}
	}

	if strings.EqualFold(cfg.Provider, "duckdns") && cfg.Domain != "" {
		cfg.Domain = formatDuckDomain(cfg.Domain)
	}

	if cfg.Token != "" {
		registerSecretForLogRedaction(cfg.Token)
	}
	if cfg.Provider != "" || cfg.Webhook != "" {
		if b, err := json.MarshalIndent(cfg, "", "  "); err == nil {
			if wErr := writeFileAtomic0600(ddnsCacheFile, b); wErr != nil {
				log.Printf("[duckdns] WARNING: failed to persist DDNS configuration to %s: %v", ddnsCacheFile, wErr)
			}
		}
	} else if strings.EqualFold(duckFlag, "auto") && cfg.Domain == "" {
		// Bare -duck passed with no saved DuckDNS token: mark Domain="auto" so we generate an automatic domain + cert
		cfg.Domain = "auto"
	}
	return cfg
}

func autoZeroConfigDomain(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip)).To4()
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
		return ""
	}
	return fmt.Sprintf("%d-%d-%d-%d.sslip.io", parsed[0], parsed[1], parsed[2], parsed[3])
}

func printStandaloneBanner(pubIP string, ddns DDNSConfig, mappings []PortMapping) {
	log.Printf("[standalone] ==========================================================")
	if ddns.Domain != "" {
		log.Printf("[standalone] Ready-to-copy domain addresses (%s):", ddns.Domain)
		for _, m := range mappings {
			log.Printf("[standalone]   %s:%d", ddns.Domain, m.PublicPort)
		}
	} else {
		log.Printf("[standalone] Ready-to-copy addresses:")
		for _, m := range mappings {
			log.Printf("[standalone]   %s:%d", pubIP, m.PublicPort)
		}
	}
	log.Printf("[standalone] ==========================================================")
}

func isStandalonePortAllowed(allowed map[uint16]struct{}, port uint16) bool {
	if len(allowed) == 0 {
		return true
	}
	_, ok := allowed[port]
	return ok
}

func filterStandaloneConfigByAllowedPorts(mappings []PortMapping, vhostMap map[string]uint16, allowed map[uint16]struct{}) ([]PortMapping, map[string]uint16) {
	var allowedMappings []PortMapping
	for _, m := range mappings {
		if isStandalonePortAllowed(allowed, m.TargetPort) {
			allowedMappings = append(allowedMappings, m)
		} else {
			log.Printf("[standalone] skipping port %d -> %d (not in -allow-ports)", m.PublicPort, m.TargetPort)
		}
	}
	filteredVHosts := make(map[string]uint16, len(vhostMap))
	for k, port := range vhostMap {
		if isStandalonePortAllowed(allowed, port) {
			filteredVHosts[k] = port
		} else {
			log.Printf("[standalone] skipping vhost %s -> :%d (not in -allow-ports)", k, port)
		}
	}
	return allowedMappings, filteredVHosts
}

func isAddrInUseError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") || strings.Contains(msg, "only one usage of each socket address")
}

func runStandalone(ctx context.Context, cfg StandaloneConfig) error {
	// Filter mappings and vhosts against -allow-ports BEFORE opening any UPnP/NAT-PMP router ports or local listeners
	allowedMappings, filteredVHosts := filterStandaloneConfigByAllowedPorts(cfg.Mappings, cfg.VHostMap, cfg.AllowedPorts)
	cfg.Mappings = allowedMappings
	cfg.VHostMap = filteredVHosts
	upnpVHostAddr := cfg.VHostAddr
	upnpHTTPSAddr := cfg.HTTPSAddr
	if len(filteredVHosts) == 0 {
		upnpVHostAddr = ""
		upnpHTTPSAddr = ""
	}

	sniMgr, err := newSNICertManager(cfg.CertDir, cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return err
	}
	sniMgr.ddns = cfg.DDNS
	if len(filteredVHosts) > 0 {
		sniMgr.enableACME = true
	}
	sniMgr.startRenewalScheduler(ctx)
	lanIP := detectLocalLANIP()
	stunFailCount.Store(3) // allow HTTP fallback on initial startup if UDP STUN is blocked
	pubIP, _ := querySTUNPublicIP(cfg.STUNServer, 800*time.Millisecond)
	if pubIP == "" {
		pubIP = lanIP
	}

	log.Printf("[standalone] driftless %s Zero-VPS mode active (LAN=%s, Public IP=%s)", versionString, lanIP, pubIP)

	hasDDNSProvider := cfg.DDNS.Provider != "" || cfg.DDNS.Webhook != ""
	autoSSLIPMode := !hasDDNSProvider && strings.EqualFold(cfg.DDNS.Domain, "auto")
	ddnsSyncedIP := ""
	var lastDDNSAttempt time.Time

	if hasDDNSProvider {
		lastDDNSAttempt = time.Now()
		if err := updateDDNS(cfg.DDNS, pubIP); err != nil {
			log.Printf("[standalone] initial DDNS update warning (will retry automatically): %v", err)
		} else {
			ddnsSyncedIP = pubIP
			log.Printf("[standalone] DDNS updated -> %s (%s)", pubIP, cfg.DDNS.Domain)
		}
	} else if autoSSLIPMode {
		if autoDom := autoZeroConfigDomain(pubIP); autoDom != "" {
			cfg.DDNS.Domain = autoDom
		} else {
			cfg.DDNS.Domain = pubIP
		}
	}
	if defaultKnockController != nil {
		defaultKnockController.SetRootCA(sniMgr.caPEM, sniMgr.caFingerprint)
		cfg.EnableTLS = true
	}
	if cfg.DDNS.Domain != "" {
		sniMgr.ensureDomainCertificate(cfg.DDNS.Domain)
		cfg.EnableTLS = true
	}

	// Start local TCP/UDP/VHost listeners BEFORE UPnP/NAT-PMP/PCP mapping so if a local service
	// (e.g. Jellyfin :8096, Windows RDP :3389, SSH :22) is already bound to 0.0.0.0:PublicPort,
	// driftless can bind an ephemeral local bridge port (RouterTCPPort/RouterUDPPort) and map
	// Router ExternalPort -> driftless EphemeralPort -> Local Service without any port conflict.
	for i := range allowedMappings {
		m := &allowedMappings[i]
		if m.Proto == "udp" || m.Proto == "both" {
			if err := startStandaloneUDP(ctx, cfg.TargetHost, m); err != nil && m.Proto == "udp" {
				return err
			}
		}
		if m.Proto != "udp" {
			if err := startStandaloneTCP(ctx, cfg.TargetHost, m, allowedMappings, sniMgr, cfg.EnableTLS || m.Proto == "https"); err != nil {
				return err
			}
		}
	}

	if cfg.VHostAddr != "" && len(filteredVHosts) > 0 {
		if err := startStandaloneVHost(ctx, cfg.VHostAddr, cfg.TargetHost, filteredVHosts, sniMgr); err != nil {
			return err
		}
	}
	if cfg.HTTPSAddr != "" && len(filteredVHosts) > 0 {
		if err := startStandaloneVHost(ctx, cfg.HTTPSAddr, cfg.TargetHost, filteredVHosts, sniMgr); err != nil {
			return err
		}
	}

	if cfg.EnableUPnP {
		if _, err := cleanupStaleUPnPState(); err != nil {
			log.Printf("[standalone] ERROR: stale UPnP state cleanup could not persist remaining state: %v", err)
		}
		mapped := autoForwardRouterPorts(lanIP, allowedMappings, upnpVHostAddr, upnpHTTPSAddr)
		if mapped == 0 {
			log.Printf("[standalone] warning: router UPnP/NAT-PMP mapped 0 ports (verify UPnP is enabled on your active WAN/PPTP interface)")
		} else {
			log.Printf("[standalone] router UPnP/NAT-PMP auto-forwarded %d port rules to %s", mapped, lanIP)
		}
		defer func() {
			if _, err := cleanupActiveUPnPMappings(); err != nil {
				log.Printf("[standalone] CRITICAL: shutdown UPnP cleanup failed to persist remaining state: %v", err)
			}
		}()
	}

	printStandaloneBanner(pubIP, cfg.DDNS, allowedMappings)
	if defaultKnockController != nil {
		hostForKnock := pubIP
		if cfg.DDNS.Domain != "" {
			hostForKnock = cfg.DDNS.Domain
		}
		defaultKnockController.SetPublicEndpoint(hostForKnock, cfg.EnableTLS, cfg.CertDir)
		defaultKnockController.PrintBanner("standalone", cfg.CertDir)
	}

	// 1-second STUN IP change detector + automatic DDNS retry + periodic UPnP lease renewal
	interval := cfg.STUNInterval
	if interval < 250*time.Millisecond {
		interval = time.Second
	}
	stunTicker := time.NewTicker(interval)
	defer stunTicker.Stop()
	upnpTicker := time.NewTicker(20 * time.Minute)
	defer upnpTicker.Stop()

	currentIP := pubIP
	for {
		select {
		case <-ctx.Done():
			log.Printf("[standalone] shutting down cleanly...")
			return nil
		case <-upnpTicker.C:
			if cfg.EnableUPnP {
				lanIP = detectLocalLANIP()
				autoForwardRouterPorts(lanIP, allowedMappings, upnpVHostAddr, upnpHTTPSAddr)
			}
		case <-stunTicker.C:
			detected, err := querySTUNPublicIP(cfg.STUNServer, 400*time.Millisecond)
			if err == nil && detected != "" && detected != currentIP {
				log.Printf("[standalone] ISP public IP changed: %s -> %s (updating DDNS & UPnP immediately)", currentIP, detected)
				currentIP = detected
				if cfg.EnableUPnP {
					lanIP = detectLocalLANIP()
					autoForwardRouterPorts(lanIP, allowedMappings, upnpVHostAddr, upnpHTTPSAddr)
				}
				if autoSSLIPMode {
					if autoDom := autoZeroConfigDomain(currentIP); autoDom != "" {
						cfg.DDNS.Domain = autoDom
						sniMgr.ensureDomainCertificate(cfg.DDNS.Domain)
						printStandaloneBanner(currentIP, cfg.DDNS, allowedMappings)
					}
				}
				if defaultKnockController != nil {
					hostForKnock := currentIP
					if cfg.DDNS.Domain != "" {
						hostForKnock = cfg.DDNS.Domain
					}
					defaultKnockController.SetPublicEndpoint(hostForKnock, cfg.EnableTLS, cfg.CertDir)
				}
				lastDDNSAttempt = time.Time{} // force immediate DDNS update on IP change
			}
			// Retry DDNS automatically if it hasn't synced currentIP yet (e.g. right after PPTP/PPP reconnect)
			if hasDDNSProvider && ddnsSyncedIP != currentIP && time.Since(lastDDNSAttempt) >= 5*time.Second {
				lastDDNSAttempt = time.Now()
				if err := updateDDNS(cfg.DDNS, currentIP); err != nil {
					log.Printf("[standalone] DDNS update error (will retry in 5s): %v", err)
				} else {
					ddnsSyncedIP = currentIP
					log.Printf("[standalone] DDNS record synced -> %s (%s)", currentIP, cfg.DDNS.Domain)
				}
			}
		}
	}
}

func closeWriteSide(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	if pc, ok := c.(*peekedConn); ok {
		if tc, ok := pc.Conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
			return
		}
	}
	if tlsC, ok := c.(*tls.Conn); ok {
		_ = tlsC.CloseWrite()
	}
}

func pipeBidirectional(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWriteSide(b)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWriteSide(a)
	}()
	wg.Wait()
}

func startStandaloneTCP(ctx context.Context, targetHost string, m *PortMapping, allMappings []PortMapping, sniMgr *SNICertManager, useTLS bool) error {
	l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", m.PublicPort))
	if err != nil {
		if m.PublicPort == m.TargetPort && isAddrInUseError(err) {
			needsBridge := useTLS || defaultKnockController != nil || defaultIPACL != nil || defaultProxyProtocol
			if needsBridge {
				bridgeLn, bErr := net.Listen("tcp", "0.0.0.0:0")
				if bErr == nil {
					if tcpAddr, ok := bridgeLn.Addr().(*net.TCPAddr); ok && tcpAddr.Port > 0 {
						m.RouterTCPPort = uint16(tcpAddr.Port)
						l = bridgeLn
						log.Printf("[standalone] TCP :%d is bound by local service; bridging router external port %d -> local proxy :%d -> %s:%d", m.PublicPort, m.PublicPort, m.RouterTCPPort, targetHost, m.TargetPort)
					} else {
						_ = bridgeLn.Close()
					}
				}
			}
			if l == nil {
				log.Printf("[standalone] TCP :%d already bound by local service (UPnP forwards directly to :%d)", m.PublicPort, m.TargetPort)
				return nil
			}
		} else {
			return err
		}
	} else {
		m.RouterTCPPort = m.PublicPort
		log.Printf("[standalone] TCP :%d -> %s:%d (auto-tls=%v)", m.PublicPort, targetHost, m.TargetPort, useTLS)
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	pubPort := m.PublicPort
	defTargetPort := m.TargetPort
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if !defaultIPACL.AllowedAddr(c.RemoteAddr()) {
				_ = c.Close()
				continue
			}
			go func(inConn net.Conn) {
				tuneTCPSocket(inConn)
				dialLocalOrLAN := func(srcConn net.Conn, dstPort uint16, dstHost string) {
					defer srcConn.Close()
					if dstHost == "" {
						dstHost = targetHost
					}
					outConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", dstHost, dstPort), 5*time.Second)
					if err != nil {
						return
					}
					if pubPort == dstPort && outConn.LocalAddr().String() == inConn.RemoteAddr().String() {
						_ = outConn.Close()
						return
					}
					tuneTCPSocket(outConn)
					defer outConn.Close()
					if defaultProxyProtocol {
						if _, err := outConn.Write(formatProxyProtoV1(inConn.RemoteAddr(), inConn.LocalAddr())); err != nil {
							return
						}
					}
					pipeBidirectional(srcConn, outConn)
				}

				if defaultKnockController != nil || len(allMappings) > 1 {
					wrapped, resolvedPort, handled := inspectAndPrepareTCPConn(inConn, sniMgr, useTLS, defTargetPort, allMappings)
					if handled {
						return
					}
					dialLocalOrLAN(wrapped, resolvedPort, targetHost)
					return
				}

				wrapped := maybeTerminateTLS(inConn, sniMgr, useTLS)
				dialLocalOrLAN(wrapped, defTargetPort, targetHost)
			}(c)
		}
	}()
	return nil
}

func startStandaloneUDP(ctx context.Context, targetHost string, m *PortMapping) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", m.PublicPort))
	if err != nil {
		return err
	}
	pubConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		if m.PublicPort == m.TargetPort && isAddrInUseError(err) {
			if defaultKnockController != nil || defaultIPACL != nil {
				bAddr, _ := net.ResolveUDPAddr("udp", "0.0.0.0:0")
				if bridgeUDP, bErr := net.ListenUDP("udp", bAddr); bErr == nil {
					if uAddr, ok := bridgeUDP.LocalAddr().(*net.UDPAddr); ok && uAddr.Port > 0 {
						m.RouterUDPPort = uint16(uAddr.Port)
						pubConn = bridgeUDP
						log.Printf("[standalone] UDP :%d is bound by local service; bridging router external UDP port %d -> local proxy :%d -> %s:%d", m.PublicPort, m.PublicPort, m.RouterUDPPort, targetHost, m.TargetPort)
					} else {
						_ = bridgeUDP.Close()
					}
				}
			}
			if pubConn == nil {
				log.Printf("[standalone] UDP :%d already bound by local service (UPnP forwards directly to :%d)", m.PublicPort, m.TargetPort)
				return nil
			}
		} else {
			return err
		}
	} else {
		m.RouterUDPPort = m.PublicPort
		log.Printf("[standalone] UDP :%d -> %s:%d", m.PublicPort, targetHost, m.TargetPort)
	}
	go func() {
		<-ctx.Done()
		_ = pubConn.Close()
	}()

	var mu sync.Mutex
	peers := make(map[string]*net.UDPConn)
	perIPCount := make(map[string]int)
	dstPort := m.TargetPort

	go func() {
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr
		defer udpBufPool.Put(bufPtr)
		for {
			n, clientAddr, err := pubConn.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if !defaultIPACL.AllowedAddr(clientAddr) || (defaultKnockController != nil && !defaultKnockController.IsAllowedPort(clientAddr, dstPort) && !defaultKnockController.IsAllowedPort(clientAddr, m.PublicPort)) {
				continue
			}
			key := clientAddr.String()
			clientIP := ""
			if clientAddr != nil && clientAddr.IP != nil {
				clientIP = clientAddr.IP.String()
			}
			mu.Lock()
			locConn, ok := peers[key]
			if !ok {
				if len(peers) >= maxGatewayUDPSessions || (clientIP != "" && perIPCount[clientIP] >= maxUDPSessionsPerIP) {
					mu.Unlock()
					continue
				}
				raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetHost, dstPort))
				if err != nil {
					mu.Unlock()
					continue
				}
				locConn, err = net.DialUDP("udp", nil, raddr)
				if err != nil {
					mu.Unlock()
					continue
				}
				peers[key] = locConn
				if clientIP != "" {
					perIPCount[clientIP]++
				}
				go func(k, cIP string, cAddr *net.UDPAddr, lc *net.UDPConn) {
					defer func() {
						_ = lc.Close()
						mu.Lock()
						delete(peers, k)
						if cIP != "" {
							perIPCount[cIP]--
							if perIPCount[cIP] <= 0 {
								delete(perIPCount, cIP)
							}
						}
						mu.Unlock()
					}()
					rbufPtr := udpBufPool.Get().(*[]byte)
					rbuf := *rbufPtr
					defer udpBufPool.Put(rbufPtr)
					for {
						_ = lc.SetReadDeadline(time.Now().Add(udpSessionTTL))
						rn, err := lc.Read(rbuf)
						if err != nil {
							return
						}
						_, _ = pubConn.WriteToUDP(rbuf[:rn], cAddr)
					}
				}(key, clientIP, clientAddr, locConn)
			}
			mu.Unlock()
			_, _ = locConn.Write(buf[:n])
		}
	}()
	return nil
}

func startStandaloneVHost(ctx context.Context, listenAddr, targetHost string, vhostMap map[string]uint16, sniMgr *SNICertManager) error {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	log.Printf("[standalone] HTTP/HTTPS VHost router on %s (%d domains)", listenAddr, len(vhostMap))
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if !defaultIPACL.AllowedAddr(c.RemoteAddr()) {
				_ = c.Close()
				continue
			}
			go func(raw net.Conn) {
				tuneTCPSocket(raw)
				wrapped := maybeTerminateTLS(raw, sniMgr, true)
				defer wrapped.Close()
				_ = wrapped.SetReadDeadline(time.Now().Add(5 * time.Second))
				var captured bytes.Buffer
				limited := io.LimitReader(wrapped, maxVHostHeaderBytes)
				tee := io.TeeReader(limited, &captured)
				br := bufio.NewReaderSize(tee, 4096)
				req, err := http.ReadRequest(br)
				_ = wrapped.SetReadDeadline(time.Time{})
				if err != nil {
					return
				}
				if sniMgr != nil && strings.HasPrefix(req.URL.Path, "/.well-known/acme-challenge/") {
					tok := strings.TrimPrefix(req.URL.Path, "/.well-known/acme-challenge/")
					if keyAuth, ok := sniMgr.getHTTPChallenge(tok); ok {
						resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(keyAuth), keyAuth)
						_, _ = wrapped.Write([]byte(resp))
						return
					}
				}
				if defaultKnockController != nil {
					if strings.HasPrefix(req.URL.Path, knockPathPrefix) {
						pc := &peekedConn{Conn: wrapped, r: bufio.NewReader(io.MultiReader(bytes.NewReader(captured.Bytes()), br))}
						defaultKnockController.handleKnockHTTPConn(pc, raw.RemoteAddr())
						return
					}
					if !defaultKnockController.IsAllowedAddr(raw.RemoteAddr()) {
						return
					}
				}
				host := strings.ToLower(strings.TrimSpace(req.Host))
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				targetPort, ok := matchVHostTarget(vhostMap, host, req.URL.Path)
				if !ok {
					_, _ = wrapped.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 21\r\nConnection: close\r\n\r\ndriftless: unknown host"))
					return
				}
				if defaultKnockController != nil && !defaultKnockController.IsAllowedPort(raw.RemoteAddr(), targetPort) {
					return
				}
				outConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort), 5*time.Second)
				if err != nil {
					return
				}
				tuneTCPSocket(outConn)
				defer outConn.Close()
				_, _ = outConn.Write(captured.Bytes())
				pipeBidirectional(wrapped, outConn)
			}(c)
		}
	}()
	return nil
}

