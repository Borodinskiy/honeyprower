package deploy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// mockSSHServer implements an in-memory SSH server for unit tests.
type mockSSHServer struct {
	listener net.Listener
	port     int
	hostKey  ssh.Signer

	mu            sync.Mutex
	commands      []string
	files         map[string][]byte
	sudoPasswords []string

	allowedUsers   map[string]string        // username -> password
	allowedPubKeys map[string]ssh.PublicKey // username -> public key
	failCommands   map[string]string        // command substring -> stderr
}

func newMockSSHServer(t *testing.T) *mockSSHServer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer from host key: %v", err)
	}

	s := &mockSSHServer{
		hostKey:        signer,
		files:          make(map[string][]byte),
		allowedUsers:   make(map[string]string),
		allowedPubKeys: make(map[string]ssh.PublicKey),
		failCommands:   make(map[string]string),
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			expectedPass, ok := s.allowedUsers[conn.User()]
			if ok && expectedPass == string(password) {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for user %s", conn.User())
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			expectedKey, ok := s.allowedPubKeys[conn.User()]
			if ok && bytes.Equal(expectedKey.Marshal(), key.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("public key rejected for user %s", conn.User())
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on 127.0.0.1:0: %v", err)
	}
	s.listener = listener
	s.port = listener.Addr().(*net.TCPAddr).Port

	go s.serve(serverConfig)

	t.Cleanup(func() {
		_ = listener.Close()
	})

	return s
}

func (s *mockSSHServer) serve(config *ssh.ServerConfig) {
	for {
		tcpConn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(tcpConn, config)
	}
}

func (s *mockSSHServer) handleConn(tcpConn net.Conn, config *ssh.ServerConfig) {
	defer tcpConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			continue
		}

		go s.handleSession(channel, requests)
	}
}

func (s *mockSSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "exec":
			var payload struct {
				Command string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)

			cmd := payload.Command

			s.mu.Lock()
			s.commands = append(s.commands, cmd)
			failStderr, shouldFail := s.failCommands[cmd]
			if !shouldFail {
				for k, v := range s.failCommands {
					if strings.Contains(cmd, k) {
						failStderr = v
						shouldFail = true
						break
					}
				}
			}
			s.mu.Unlock()

			if strings.HasPrefix(cmd, "cat > ") {
				remotePath := strings.TrimSpace(strings.TrimPrefix(cmd, "cat > "))
				data, _ := io.ReadAll(channel)
				s.mu.Lock()
				s.files[remotePath] = data
				s.mu.Unlock()
			} else if strings.HasPrefix(cmd, "sudo ") {
				reader := bufio.NewReader(channel)
				pass, _ := reader.ReadString('\n')
				s.mu.Lock()
				s.sudoPasswords = append(s.sudoPasswords, strings.TrimSuffix(pass, "\n"))
				s.mu.Unlock()
			}

			if shouldFail {
				_, _ = channel.Stderr().Write([]byte(failStderr))
				exitStatus := struct{ Status uint32 }{Status: 1}
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(exitStatus))
				return
			}

			exitStatus := struct{ Status uint32 }{Status: 0}
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(exitStatus))
			return

		case "env":
			_ = req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func generateClientKeyPair(t *testing.T) (privPEM string, pubKey ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 client key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal pkcs8: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	privPEM = string(pem.EncodeToMemory(pemBlock))

	pubKey, err = ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}
	return privPEM, pubKey
}

func createTestBinary(t *testing.T, content []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "honeyforge-agent")
	if err := os.WriteFile(binPath, content, 0755); err != nil {
		t.Fatalf("failed to create temp binary: %v", err)
	}
	return binPath
}

func TestDeploy_RootSuccess(t *testing.T) {
	server := newMockSSHServer(t)
	server.allowedUsers["root"] = "secretroot"

	binContent := []byte("#!/bin/sh\necho honeyforge-agent")
	binPath := createTestBinary(t, binContent)
	cfgContent := []byte(`{"agent_id":"test-agent-01","listen_port":8080}`)
	svcContent := []byte("[Unit]\nDescription=HoneyForge Agent Service\n[Service]\nExecStart=/usr/local/bin/honeyforge-agent\n[Install]\nWantedBy=multi-user.target\n")

	deployer := NewSSHDeployer()
	deployer.Timeout = 5 * time.Second

	target := TargetConfig{
		Host:     "127.0.0.1",
		Port:     server.port,
		Username: "root",
		Password: "secretroot",
		UseSudo:  false,
	}
	payload := Payload{
		BinaryPath:     binPath,
		ConfigJSON:     cfgContent,
		ServiceContent: svcContent,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := deployer.Deploy(ctx, target, payload)
	if err != nil {
		t.Fatalf("Deploy returned unexpected error: %v", err)
	}

	// Verify all 3 files delivered with correct content
	server.mu.Lock()
	defer server.mu.Unlock()

	if !bytes.Equal(server.files["/tmp/hf_agent_bin"], binContent) {
		t.Errorf("binary content mismatch: got %q, want %q", server.files["/tmp/hf_agent_bin"], binContent)
	}
	if !bytes.Equal(server.files["/tmp/hf_agent_cfg"], cfgContent) {
		t.Errorf("config content mismatch: got %q, want %q", server.files["/tmp/hf_agent_cfg"], cfgContent)
	}
	if !bytes.Equal(server.files["/tmp/hf_agent_svc"], svcContent) {
		t.Errorf("service content mismatch: got %q, want %q", server.files["/tmp/hf_agent_svc"], svcContent)
	}

	// Verify commands were executed directly without sudo
	expectedCommands := []string{
		"cat > /tmp/hf_agent_bin",
		"mv /tmp/hf_agent_bin /usr/local/bin/honeyforge-agent && chmod 0755 /usr/local/bin/honeyforge-agent",
		"cat > /tmp/hf_agent_cfg",
		"mkdir -p /etc/honeyforge && mv /tmp/hf_agent_cfg /etc/honeyforge/config.json && chmod 0644 /etc/honeyforge/config.json",
		"cat > /tmp/hf_agent_svc",
		"mv /tmp/hf_agent_svc /etc/systemd/system/honeyforge-agent.service && chmod 0644 /etc/systemd/system/honeyforge-agent.service",
		activateCmd,
		verifyCmd,
	}

	if len(server.commands) != len(expectedCommands) {
		t.Fatalf("expected %d commands, got %d: %v", len(expectedCommands), len(server.commands), server.commands)
	}

	for i, expected := range expectedCommands {
		if server.commands[i] != expected {
			t.Errorf("command %d mismatch: got %q, want %q", i, server.commands[i], expected)
		}
	}
}

func TestDeploy_SudoSuccess(t *testing.T) {
	server := newMockSSHServer(t)
	server.allowedUsers["deployuser"] = "userpass"

	binContent := []byte("binary-payload-data")
	binPath := createTestBinary(t, binContent)
	cfgContent := []byte(`{"enabled":true}`)
	svcContent := []byte("[Service]\nExecStart=/usr/local/bin/honeyforge-agent\n")

	deployer := NewSSHDeployer()
	deployer.Timeout = 5 * time.Second

	target := TargetConfig{
		Host:         "127.0.0.1",
		Port:         server.port,
		Username:     "deployuser",
		Password:     "userpass",
		RootPassword: "rootpassword123",
		UseSudo:      true,
	}
	payload := Payload{
		BinaryPath:     binPath,
		ConfigJSON:     cfgContent,
		ServiceContent: svcContent,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := deployer.Deploy(ctx, target, payload)
	if err != nil {
		t.Fatalf("Deploy with sudo returned unexpected error: %v", err)
	}

	server.mu.Lock()
	defer server.mu.Unlock()

	// Verify all 3 files delivered
	if !bytes.Equal(server.files["/tmp/hf_agent_bin"], binContent) {
		t.Errorf("binary content mismatch")
	}
	if !bytes.Equal(server.files["/tmp/hf_agent_cfg"], cfgContent) {
		t.Errorf("config content mismatch")
	}
	if !bytes.Equal(server.files["/tmp/hf_agent_svc"], svcContent) {
		t.Errorf("service content mismatch")
	}

	// Verify sudo was used for privileged commands and sudo password was passed to stdin
	sudoCmdCount := 0
	for _, cmd := range server.commands {
		if strings.HasPrefix(cmd, "sudo -S -p ''") {
			sudoCmdCount++
		}
	}
	if sudoCmdCount != 5 {
		t.Errorf("expected 5 sudo commands (install bin, install cfg, install svc, systemctl, verify), got %d: %v", sudoCmdCount, server.commands)
	}

	// Verify the sudo password passed on stdin
	if len(server.sudoPasswords) != 5 {
		t.Fatalf("expected 5 sudo password prompts, got %d", len(server.sudoPasswords))
	}
	for i, pass := range server.sudoPasswords {
		if pass != "rootpassword123" {
			t.Errorf("sudo password %d mismatch: got %q, want %q", i, pass, "rootpassword123")
		}
	}

	// Also verify that cat commands did NOT use sudo
	for remotePath := range server.files {
		catCmd := fmt.Sprintf("cat > %s", remotePath)
		found := false
		for _, cmd := range server.commands {
			if cmd == catCmd {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected command %q to be executed without sudo", catCmd)
		}
	}
}

func TestDeploy_SudoFallbackToUserPassword(t *testing.T) {
	server := newMockSSHServer(t)
	server.allowedUsers["deployuser"] = "userpass"

	binContent := []byte("binary-payload-data")
	binPath := createTestBinary(t, binContent)

	deployer := NewSSHDeployer()
	deployer.Timeout = 5 * time.Second

	target := TargetConfig{
		Host:         "127.0.0.1",
		Port:         server.port,
		Username:     "deployuser",
		Password:     "userpass",
		RootPassword: "", // Empty, should fallback to Password
		UseSudo:      true,
	}
	payload := Payload{
		BinaryPath: binPath,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := deployer.Deploy(ctx, target, payload)
	if err != nil {
		t.Fatalf("Deploy returned unexpected error: %v", err)
	}

	server.mu.Lock()
	defer server.mu.Unlock()

	for _, pass := range server.sudoPasswords {
		if pass != "userpass" {
			t.Errorf("expected sudo password to fallback to user password %q, got %q", "userpass", pass)
		}
	}
}

func TestDeploy_PrivateKeyAuth(t *testing.T) {
	server := newMockSSHServer(t)
	privPEM, pubKey := generateClientKeyPair(t)
	server.allowedPubKeys["keyuser"] = pubKey

	binContent := []byte("binary-data-key-auth")
	binPath := createTestBinary(t, binContent)

	deployer := NewSSHDeployer()
	deployer.Timeout = 5 * time.Second

	target := TargetConfig{
		Host:       "127.0.0.1",
		Port:       server.port,
		Username:   "keyuser",
		PrivateKey: privPEM,
		UseSudo:    false,
	}
	payload := Payload{
		BinaryPath: binPath,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := deployer.Deploy(ctx, target, payload)
	if err != nil {
		t.Fatalf("Deploy with private key auth failed: %v", err)
	}

	server.mu.Lock()
	defer server.mu.Unlock()

	if !bytes.Equal(server.files["/tmp/hf_agent_bin"], binContent) {
		t.Errorf("binary content mismatch")
	}
}

func TestDeploy_Errors(t *testing.T) {
	server := newMockSSHServer(t)
	server.allowedUsers["root"] = "rootpass"

	validBin := createTestBinary(t, []byte("valid-binary"))
	emptyBin := createTestBinary(t, []byte{})

	deployer := NewSSHDeployer()
	deployer.Timeout = 2 * time.Second

	t.Run("missing target host", func(t *testing.T) {
		target := TargetConfig{
			Username: "root",
			Password: "rootpass",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: validBin})
		if err == nil || !strings.Contains(err.Error(), "host") {
			t.Errorf("expected host error, got: %v", err)
		}
	})

	t.Run("non-existent host port connection failure", func(t *testing.T) {
		// Pick an unassigned localhost port
		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     59998,
			Username: "root",
			Password: "rootpass",
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		err := deployer.Deploy(ctx, target, Payload{BinaryPath: validBin})
		if err == nil {
			t.Error("expected connection error, got nil")
		}
	})

	t.Run("invalid credentials authentication failure", func(t *testing.T) {
		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
			Password: "wrongpassword",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: validBin})
		if err == nil {
			t.Error("expected auth failure error, got nil")
		}
	})

	t.Run("missing binary path", func(t *testing.T) {
		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
			Password: "rootpass",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: ""})
		if err == nil || !strings.Contains(err.Error(), "binary") {
			t.Errorf("expected binary path error, got: %v", err)
		}
	})

	t.Run("non-existent binary file", func(t *testing.T) {
		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
			Password: "rootpass",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: "/nonexistent/path/honeyforge-agent"})
		if err == nil {
			t.Error("expected file not found error, got nil")
		}
	})

	t.Run("empty binary file", func(t *testing.T) {
		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
			Password: "rootpass",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: emptyBin})
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected empty binary error, got: %v", err)
		}
	})

	t.Run("binary path is directory", func(t *testing.T) {
		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
			Password: "rootpass",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: t.TempDir()})
		if err == nil || !strings.Contains(err.Error(), "directory") {
			t.Errorf("expected directory error, got: %v", err)
		}
	})

	t.Run("missing authentication method", func(t *testing.T) {
		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: validBin})
		if err == nil || !strings.Contains(err.Error(), "authentication") {
			t.Errorf("expected missing auth error, got: %v", err)
		}
	})

	t.Run("malformed private key", func(t *testing.T) {
		target := TargetConfig{
			Host:       "127.0.0.1",
			Port:       server.port,
			Username:   "root",
			PrivateKey: "-----BEGIN RSA PRIVATE KEY-----\ncorrupted\n-----END RSA PRIVATE KEY-----",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: validBin})
		if err == nil || !strings.Contains(err.Error(), "private key") {
			t.Errorf("expected private key parse error, got: %v", err)
		}
	})

	t.Run("systemctl activation failure with stderr reported", func(t *testing.T) {
		server.mu.Lock()
		server.failCommands["systemctl daemon-reload"] = "Job for honeyforge-agent.service failed because the control process exited with error code."
		server.mu.Unlock()

		defer func() {
			server.mu.Lock()
			delete(server.failCommands, "systemctl daemon-reload")
			server.mu.Unlock()
		}()

		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
			Password: "rootpass",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: validBin})
		if err == nil {
			t.Fatal("expected systemctl error, got nil")
		}
		if !strings.Contains(err.Error(), "Job for honeyforge-agent.service failed") {
			t.Errorf("expected error to contain stderr details, got: %v", err)
		}
	})

	t.Run("agent not running after start reports journal", func(t *testing.T) {
		server.mu.Lock()
		server.failCommands["systemctl is-active"] = "status=216/GROUP"
		server.mu.Unlock()

		defer func() {
			server.mu.Lock()
			delete(server.failCommands, "systemctl is-active")
			server.mu.Unlock()
		}()

		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
			Password: "rootpass",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: validBin})
		if err == nil {
			t.Fatal("expected verification error, got nil")
		}
		if !strings.Contains(err.Error(), "is not running") || !strings.Contains(err.Error(), "216/GROUP") {
			t.Errorf("expected not-running error with journal, got: %v", err)
		}
	})

	t.Run("missing target username", func(t *testing.T) {
		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Password: "rootpass",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: validBin})
		if err == nil || !strings.Contains(err.Error(), "username") {
			t.Errorf("expected username error, got: %v", err)
		}
	})

	t.Run("upload failure with stderr reported", func(t *testing.T) {
		server.mu.Lock()
		server.failCommands["cat > /tmp/hf_agent_bin"] = "read-only file system"
		server.mu.Unlock()

		defer func() {
			server.mu.Lock()
			delete(server.failCommands, "cat > /tmp/hf_agent_bin")
			server.mu.Unlock()
		}()

		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
			Password: "rootpass",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: validBin})
		if err == nil {
			t.Fatal("expected upload failure error, got nil")
		}
		if !strings.Contains(err.Error(), "read-only file system") {
			t.Errorf("expected upload error to contain stderr details, got: %v", err)
		}
	})

	t.Run("install command failure with stderr reported", func(t *testing.T) {
		server.mu.Lock()
		server.failCommands["mv /tmp/hf_agent_bin /usr/local/bin/honeyforge-agent"] = "permission denied"
		server.mu.Unlock()

		defer func() {
			server.mu.Lock()
			delete(server.failCommands, "mv /tmp/hf_agent_bin /usr/local/bin/honeyforge-agent")
			server.mu.Unlock()
		}()

		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
			Password: "rootpass",
		}
		err := deployer.Deploy(context.Background(), target, Payload{BinaryPath: validBin})
		if err == nil {
			t.Fatal("expected install failure error, got nil")
		}
		if !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("expected install error to contain stderr details, got: %v", err)
		}
	})

	t.Run("context cancelled before completion", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // immediately cancelled

		target := TargetConfig{
			Host:     "127.0.0.1",
			Port:     server.port,
			Username: "root",
			Password: "rootpass",
		}
		err := deployer.Deploy(ctx, target, Payload{BinaryPath: validBin})
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled error, got: %v", err)
		}
	})
}

func TestTargetConfig_UnmarshalJSON(t *testing.T) {
	// Test snake_case JSON
	snakeJSON := []byte(`{
		"host": "192.168.1.100",
		"port": 2222,
		"username": "deploy",
		"password": "pass",
		"private_key": "privkey",
		"root_password": "rootpass",
		"use_sudo": true
	}`)

	var cfg1 TargetConfig
	if err := cfg1.UnmarshalJSON(snakeJSON); err != nil {
		t.Fatalf("failed to unmarshal snake_case JSON: %v", err)
	}
	if cfg1.Host != "192.168.1.100" || cfg1.Port != 2222 || cfg1.Username != "deploy" ||
		cfg1.Password != "pass" || cfg1.PrivateKey != "privkey" || cfg1.RootPassword != "rootpass" || !cfg1.UseSudo {
		t.Errorf("snake_case unmarshal mismatch: %+v", cfg1)
	}

	// Test camelCase JSON
	camelJSON := []byte(`{
		"host": "10.0.0.1",
		"port": 22,
		"username": "admin",
		"privateKey": "key2",
		"rootPassword": "root2",
		"useSudo": false
	}`)

	var cfg2 TargetConfig
	if err := cfg2.UnmarshalJSON(camelJSON); err != nil {
		t.Fatalf("failed to unmarshal camelCase JSON: %v", err)
	}
	if cfg2.Host != "10.0.0.1" || cfg2.PrivateKey != "key2" || cfg2.RootPassword != "root2" || cfg2.UseSudo {
		t.Errorf("camelCase unmarshal mismatch: %+v", cfg2)
	}

	// Test invalid JSON
	var cfg3 TargetConfig
	if err := cfg3.UnmarshalJSON([]byte("invalid json")); err == nil {
		t.Error("expected error for invalid json, got nil")
	}
}
