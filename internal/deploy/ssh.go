package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var _ Deployer = (*SSHDeployer)(nil)

// SSHDeployer implements Deployer over SSH.
type SSHDeployer struct {
	Timeout time.Duration
}

// NewSSHDeployer returns a new SSHDeployer with default settings.
func NewSSHDeployer() *SSHDeployer {
	return &SSHDeployer{
		Timeout: 30 * time.Second,
	}
}

// Deploy uploads the binary, config, and systemd unit to the remote server and activates the service.
func (d *SSHDeployer) Deploy(ctx context.Context, target TargetConfig, payload Payload) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// 1. Validate payload binary
	if payload.BinaryPath == "" {
		return errors.New("binary path is required")
	}
	binInfo, err := os.Stat(payload.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to stat binary file %q: %w", payload.BinaryPath, err)
	}
	if binInfo.IsDir() {
		return fmt.Errorf("binary path %q is a directory", payload.BinaryPath)
	}
	binData, err := os.ReadFile(payload.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to read binary file %q: %w", payload.BinaryPath, err)
	}
	if len(binData) == 0 {
		return fmt.Errorf("binary file %q is empty", payload.BinaryPath)
	}

	// 2. Validate target configuration
	if target.Host == "" {
		return errors.New("target host is required")
	}
	if target.Username == "" {
		return errors.New("target username is required")
	}

	port := target.Port
	if port <= 0 {
		port = 22
	}

	var authMethods []ssh.AuthMethod
	if target.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(target.PrivateKey))
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if target.Password != "" {
		authMethods = append(authMethods, ssh.Password(target.Password))
	}
	if len(authMethods) == 0 {
		return errors.New("no authentication method provided: password or private key required")
	}

	// 3. Establish SSH connection
	clientConfig := &ssh.ClientConfig{
		User:            target.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         d.Timeout,
	}

	addr := fmt.Sprintf("%s:%d", target.Host, port)
	dialer := net.Dialer{Timeout: d.Timeout}
	netConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer netConn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, addr, clientConfig)
	if err != nil {
		return fmt.Errorf("ssh handshake failed with %s: %w", addr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	// Terminate client connection early if context is cancelled
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
			_ = netConn.Close()
		case <-done:
		}
	}()

	// 4. Deliver files and move them to destination locations
	// Step 4.1: Agent binary
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.uploadFile(client, "/tmp/hf_agent_bin", binData); err != nil {
		return fmt.Errorf("failed to upload agent binary: %w", err)
	}
	binInstallCmd := "mv /tmp/hf_agent_bin /usr/local/bin/honeyforge-agent && chmod 0755 /usr/local/bin/honeyforge-agent"
	if err := d.runCommand(client, target, binInstallCmd); err != nil {
		return fmt.Errorf("failed to install agent binary: %w", err)
	}

	// Step 4.2: Trap config
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.uploadFile(client, "/tmp/hf_agent_cfg", payload.ConfigJSON); err != nil {
		return fmt.Errorf("failed to upload agent config: %w", err)
	}
	cfgInstallCmd := "mkdir -p /etc/honeyforge && mv /tmp/hf_agent_cfg /etc/honeyforge/config.json && chmod 0644 /etc/honeyforge/config.json"
	if err := d.runCommand(client, target, cfgInstallCmd); err != nil {
		return fmt.Errorf("failed to install agent config: %w", err)
	}

	// Step 4.3: Systemd unit file
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.uploadFile(client, "/tmp/hf_agent_svc", payload.ServiceContent); err != nil {
		return fmt.Errorf("failed to upload service unit: %w", err)
	}
	svcInstallCmd := "mv /tmp/hf_agent_svc /etc/systemd/system/honeyforge-agent.service && chmod 0644 /etc/systemd/system/honeyforge-agent.service"
	if err := d.runCommand(client, target, svcInstallCmd); err != nil {
		return fmt.Errorf("failed to install service unit: %w", err)
	}

	// 5. Activate service
	if err := ctx.Err(); err != nil {
		return err
	}
	activationCmd := activateCmd
	if err := d.runCommand(client, target, activationCmd); err != nil {
		return fmt.Errorf("failed to activate honeyforge-agent service: %w", err)
	}

	// 6. Make sure the agent stays up: a crash on start (bad unit, missing glibc,
	// busy port) is otherwise invisible because systemctl restart returns at once.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.runCommand(client, target, verifyCmd); err != nil {
		return fmt.Errorf("honeyforge-agent service is not running: %w", err)
	}

	return nil
}

// activateCmd resets SELinux labels first: files moved from /tmp keep user_tmp_t and systemd refuses to exec them (203/EXEC).
const activateCmd = "if command -v restorecon >/dev/null 2>&1; then restorecon -F /usr/local/bin/honeyforge-agent /etc/honeyforge/config.json /etc/systemd/system/honeyforge-agent.service; fi; " +
	"systemctl daemon-reload && systemctl enable honeyforge-agent.service && systemctl restart honeyforge-agent.service"

// verifyCmd waits for the agent to settle and prints its journal tail to stderr when it is not active.
const verifyCmd = "sleep 3; systemctl is-active --quiet honeyforge-agent.service || { journalctl -u honeyforge-agent.service -n 15 --no-pager >&2; exit 1; }"

func (d *SSHDeployer) uploadFile(client *ssh.Client, remotePath string, content []byte) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	session.Stdin = bytes.NewReader(content)
	var stderr bytes.Buffer
	session.Stderr = &stderr

	cmd := fmt.Sprintf("cat > %s", remotePath)
	if err := session.Run(cmd); err != nil {
		errStr := strings.TrimSpace(stderr.String())
		if errStr != "" {
			return fmt.Errorf("failed to upload %s: %w, stderr: %s", remotePath, err, errStr)
		}
		return fmt.Errorf("failed to upload %s: %w", remotePath, err)
	}
	return nil
}

func (d *SSHDeployer) runCommand(client *ssh.Client, target TargetConfig, cmd string) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var finalCmd string
	if target.UseSudo && target.Username != "root" {
		finalCmd = fmt.Sprintf("sudo -S -p '' bash -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''"))
		sudoPass := target.RootPassword
		if sudoPass == "" {
			sudoPass = target.Password
		}
		session.Stdin = strings.NewReader(sudoPass + "\n")
	} else {
		finalCmd = cmd
	}

	var stderr bytes.Buffer
	session.Stderr = &stderr

	if err := session.Run(finalCmd); err != nil {
		errStr := strings.TrimSpace(stderr.String())
		if errStr != "" {
			return fmt.Errorf("command %q failed: %w, stderr: %s", finalCmd, err, errStr)
		}
		return fmt.Errorf("command %q failed: %w", finalCmd, err)
	}
	return nil
}
