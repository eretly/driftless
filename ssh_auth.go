package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	sshHostKeyFileName = "ssh_host_ed25519_key"
	sshAuthFileName    = "ssh-auth.txt"
)

type UserPassAuth struct {
	User        string
	Pass        string
	RequireHTTP bool
	AutoCreated bool
	mu          sync.Mutex
	attempts    map[string]authAttempt
	sshConfig   *ssh.ServerConfig
}

var defaultUserPassAuth *UserPassAuth

func initUserPassAuth(certDir, userFlag, passFlag, authFlag string, requireHTTP, hasPort22 bool) (*UserPassAuth, error) {
	if strings.TrimSpace(certDir) == "" {
		certDir = ".driftless-certs"
	}
	user := strings.TrimSpace(userFlag)
	pass := strings.TrimSpace(passFlag)
	if a := strings.TrimSpace(authFlag); a != "" {
		if idx := strings.IndexByte(a, ':'); idx > 0 {
			user = strings.TrimSpace(a[:idx])
			pass = strings.TrimSpace(a[idx+1:])
		} else {
			pass = a
		}
	}
	if envAuth := strings.TrimSpace(os.Getenv("DRIFTLESS_AUTH")); envAuth != "" && user == "" && pass == "" {
		if idx := strings.IndexByte(envAuth, ':'); idx > 0 {
			user = strings.TrimSpace(envAuth[:idx])
			pass = strings.TrimSpace(envAuth[idx+1:])
		}
	}

	authFilePath := filepath.Join(certDir, sshAuthFileName)
	autoCreated := false

	// If user or pass was provided, persist it so next run remembers it automatically
	if user != "" || pass != "" {
		if user == "" {
			user = "admin"
		}
		if pass == "" {
			var rnd [6]byte
			_, _ = rand.Read(rnd[:])
			pass = hex.EncodeToString(rnd[:])
			autoCreated = true
		}
		_ = os.MkdirAll(certDir, 0o700)
		_ = writeFileAtomic0600(authFilePath, []byte(fmt.Sprintf("%s:%s\n", user, pass)))
	} else if hasPort22 && !isLocalTCPPortOpen("127.0.0.1", 22) {
		// Port 22 is in -ports and no local system sshd is running: load saved credentials or auto-create them
		if raw, err := os.ReadFile(authFilePath); err == nil {
			line := strings.TrimSpace(string(raw))
			if idx := strings.IndexByte(line, ':'); idx > 0 {
				user = strings.TrimSpace(line[:idx])
				pass = strings.TrimSpace(line[idx+1:])
			}
		}
		if user == "" || pass == "" {
			user = "admin"
			var rnd [6]byte
			if _, err := rand.Read(rnd[:]); err != nil {
				return nil, err
			}
			pass = hex.EncodeToString(rnd[:])
			autoCreated = true
			_ = os.MkdirAll(certDir, 0o700)
			_ = writeFileAtomic0600(authFilePath, []byte(fmt.Sprintf("%s:%s\n", user, pass)))
		}
	} else {
		return nil, nil
	}

	registerSecretForLogRedaction(pass)

	hostSigner, err := loadOrCreateSSHHostSigner(certDir)
	if err != nil {
		return nil, err
	}

	up := &UserPassAuth{
		User:        user,
		Pass:        pass,
		RequireHTTP: requireHTTP,
		AutoCreated: autoCreated,
		attempts:    make(map[string]authAttempt),
	}

	sshCfg := &ssh.ServerConfig{
		MaxAuthTries: 6,
		PasswordCallback: func(c ssh.ConnMetadata, candidatePass []byte) (*ssh.Permissions, error) {
			if !up.VerifyCredentials(c.RemoteAddr(), c.User(), string(candidatePass)) {
				return nil, errors.New("invalid username or password")
			}
			return &ssh.Permissions{}, nil
		},
	}
	sshCfg.AddHostKey(hostSigner)
	up.sshConfig = sshCfg
	return up, nil
}

func isLocalTCPPortOpen(host string, port uint16) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 150*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func loadOrCreateSSHHostSigner(certDir string) (ssh.Signer, error) {
	if strings.TrimSpace(certDir) == "" {
		certDir = ".driftless-certs"
	}
	keyPath := filepath.Join(certDir, sshHostKeyFileName)
	if b, err := os.ReadFile(keyPath); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if parsed, errP := x509.ParsePKCS8PrivateKey(blk.Bytes); errP == nil {
				if edKey, ok := parsed.(ed25519.PrivateKey); ok {
					if signer, errS := ssh.NewSignerFromKey(edKey); errS == nil {
						return signer, nil
					}
				}
			}
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_ = os.MkdirAll(certDir, 0o700)
	_ = writeFileAtomic0600(keyPath, pemBytes)
	return ssh.NewSignerFromKey(priv)
}

func (up *UserPassAuth) VerifyCredentials(addr net.Addr, candidateUser, candidatePass string) bool {
	if up == nil {
		return true
	}
	host := extractAddrHost(addr)
	key := normalizeAuthIPKey(host)
	now := time.Now()

	up.mu.Lock()
	a, hasAttempt := up.attempts[key]
	if hasAttempt && now.Sub(a.first) <= authWindow && a.failures >= maxAuthAttempts {
		up.mu.Unlock()
		return false
	}
	up.mu.Unlock()

	userMatch := hmac.Equal([]byte(strings.TrimSpace(candidateUser)), []byte(up.User))
	passMatch := hmac.Equal([]byte(candidatePass), []byte(up.Pass))
	if userMatch && passMatch {
		up.mu.Lock()
		delete(up.attempts, key)
		up.mu.Unlock()
		return true
	}

	up.mu.Lock()
	defer up.mu.Unlock()
	a, hasAttempt = up.attempts[key]
	if !hasAttempt || now.Sub(a.first) > authWindow {
		if len(up.attempts) >= maxAuthTrackedIPs {
			for k := range up.attempts {
				delete(up.attempts, k)
				break
			}
		}
		up.attempts[key] = authAttempt{failures: 1, first: now}
	} else {
		a.failures++
		up.attempts[key] = a
	}
	return false
}

func (up *UserPassAuth) CheckHTTPBasicAuth(req *http.Request, remoteAddr net.Addr) bool {
	if up == nil || !up.RequireHTTP {
		return true
	}
	if req == nil {
		return false
	}
	authHdr := strings.TrimSpace(req.Header.Get("Authorization"))
	if !strings.HasPrefix(authHdr, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authHdr[6:]))
	if err != nil {
		return false
	}
	idx := bytes.IndexByte(decoded, ':')
	if idx < 0 {
		return false
	}
	return up.VerifyCredentials(remoteAddr, string(decoded[:idx]), string(decoded[idx+1:]))
}

func writeHTTPBasicAuthChallenge(w io.Writer) {
	body := "401 Unauthorized: login and password required\n"
	resp := fmt.Sprintf(
		"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"driftless\"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body,
	)
	_, _ = w.Write([]byte(resp))
}

func defaultShellCommand() (string, []string) {
	if runtime.GOOS == "windows" {
		if ps, err := exec.LookPath("powershell.exe"); err == nil {
			return ps, []string{"-NoLogo"}
		}
		return "cmd.exe", nil
	}
	for _, sh := range []string{"/bin/bash", "/bin/sh", "sh"} {
		if p, err := exec.LookPath(sh); err == nil {
			return p, nil
		}
	}
	return "/bin/sh", nil
}

func execSingleCommand(cmdLine string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd.exe", "/C", cmdLine)
	}
	return exec.Command("/bin/sh", "-c", cmdLine)
}

// ServeConn handles an incoming SSHv2 connection (e.g. from WebSSH / Termius on Android or iPhone),
// authenticating with -user and -pass and providing both interactive shell and command execution.
func (up *UserPassAuth) ServeConn(c net.Conn) {
	defer c.Close()
	if up == nil || up.sshConfig == nil {
		return
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	sshConn, chans, reqs, err := ssh.NewServerConn(c, up.sshConfig)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go up.handleSSHSessionChannel(channel, requests)
	}
}

func sendSSHExitStatus(ch ssh.Channel, code uint32) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], code)
	_, _ = ch.SendRequest("exit-status", false, payload[:])
}

func (up *UserPassAuth) handleSSHSessionChannel(ch ssh.Channel, in <-chan *ssh.Request) {
	defer ch.Close()
	var envVars []string
	for req := range in {
		switch req.Type {
		case "pty-req", "window-change":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "env":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			// Parse SSH env key/value (uint32 len + key + uint32 len + val)
			if len(req.Payload) >= 8 {
				kLen := int(binary.BigEndian.Uint32(req.Payload[0:4]))
				if 4+kLen+4 <= len(req.Payload) {
					key := string(req.Payload[4 : 4+kLen])
					vLen := int(binary.BigEndian.Uint32(req.Payload[4+kLen : 8+kLen]))
					if 8+kLen+vLen <= len(req.Payload) {
						val := string(req.Payload[8+kLen : 8+kLen+vLen])
						if !strings.ContainsRune(key, '=') && !strings.ContainsRune(key, 0) && !strings.ContainsRune(val, 0) {
							envVars = append(envVars, key+"="+val)
						}
					}
				}
			}
		case "exec":
			if len(req.Payload) < 4 {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				return
			}
			cmdLen := int(binary.BigEndian.Uint32(req.Payload[0:4]))
			if 4+cmdLen > len(req.Payload) {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				return
			}
			cmdStr := string(req.Payload[4 : 4+cmdLen])
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			cmd := execSingleCommand(cmdStr)
			if len(envVars) > 0 {
				cmd.Env = append(os.Environ(), envVars...)
			}
			cmd.Stdin = ch
			cmd.Stdout = ch
			cmd.Stderr = ch.Stderr()
			err := cmd.Run()
			exitCode := uint32(0)
			if err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					exitCode = uint32(exitErr.ExitCode())
				} else {
					exitCode = 1
				}
			}
			sendSSHExitStatus(ch, exitCode)
			return

		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			shBin, shArgs := defaultShellCommand()
			cmd := exec.Command(shBin, shArgs...)
			if len(envVars) > 0 {
				cmd.Env = append(os.Environ(), envVars...)
			}
			stdinPipe, errIn := cmd.StdinPipe()
			stdoutPipe, errOut := cmd.StdoutPipe()
			stderrPipe, errErr := cmd.StderrPipe()
			if errIn != nil || errOut != nil || errErr != nil {
				sendSSHExitStatus(ch, 1)
				return
			}
			if err := cmd.Start(); err != nil {
				_, _ = fmt.Fprintf(ch, "Failed to start shell (%s): %v\r\n", shBin, err)
				sendSSHExitStatus(ch, 1)
				return
			}
			_, _ = fmt.Fprintf(ch, "Connected to driftless SSH (%s/%s)\r\n", runtime.GOOS, runtime.GOARCH)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, _ = io.Copy(ch, stdoutPipe)
			}()
			go func() {
				defer wg.Done()
				_, _ = io.Copy(ch.Stderr(), stderrPipe)
			}()
			go func() {
				_, _ = io.Copy(stdinPipe, ch)
				_ = stdinPipe.Close()
			}()
			wg.Wait()
			err := cmd.Wait()
			exitCode := uint32(0)
			if err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					exitCode = uint32(exitErr.ExitCode())
				} else {
					exitCode = 1
				}
			}
			sendSSHExitStatus(ch, exitCode)
			return

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (up *UserPassAuth) PrintBanner(prefix, host string, sshPort uint16) {
	if up == nil {
		return
	}
	if host == "" {
		host = "YOUR_HOST"
	}
	if sshPort == 0 {
		sshPort = 22
	}
	log.Printf("[%s] Built-in Auth active (User=%s, Pass=[token=valid, hidden], SSH=:%d, HTTP-Basic=%v)", prefix, up.User, sshPort, up.RequireHTTP)
	if tryPrintInteractiveSSHAuth(prefix, host, sshPort, up.User, up.Pass) {
		log.Printf("[%s] Phone / WebSSH / AnyDesk login credentials displayed on terminal (run './driftless show-token' anytime to view)", prefix)
	} else {
		log.Printf("[%s] Phone / WebSSH login saved to .driftless-certs/%s (run './driftless show-token' to view)", prefix, sshAuthFileName)
	}
}

func tryPrintInteractiveSSHAuth(prefix, host string, sshPort uint16, user, pass string) bool {
	if os.Getenv("JOURNAL_STREAM") != "" || os.Getenv("INVOCATION_ID") != "" {
		return false
	}
	outInfo, err1 := os.Stdout.Stat()
	errInfo, err2 := os.Stderr.Stat()
	if err1 != nil || err2 != nil {
		return false
	}
	if (outInfo.Mode()&os.ModeCharDevice) == 0 || (errInfo.Mode()&os.ModeCharDevice) == 0 {
		return false
	}
	ttyFile, err := openControllingTerminal()
	if err != nil {
		return false
	}
	defer ttyFile.Close()
	_, wErr := fmt.Fprintf(ttyFile, "[%s] Connect from Phone (WebSSH / Termius):\n  Host: %s   Port: %d   User: %s   Password: %s\n", prefix, host, sshPort, user, pass)
	return wErr == nil
}
