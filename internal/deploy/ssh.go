package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var _ Deployer = (*SSHDeployer)(nil)

// SSHDeployer implements Deployer over SSH.
type SSHDeployer struct {
	Timeout        time.Duration
	MaxRetries     int
	CheckPreflight bool
	CheckHealth    bool
}

// NewSSHDeployer returns a new SSHDeployer with default settings.
func NewSSHDeployer() *SSHDeployer {
	return &SSHDeployer{
		Timeout:    30 * time.Second,
		MaxRetries: 3,
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

	// 2. Establish SSH connection with retry resilience
	client, netConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer client.Close()
	defer netConn.Close()

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

	// Pre-flight verification (if enabled)
	if d.CheckPreflight || target.CheckPreflight {
		if err := d.runPreflight(ctx, client, target); err != nil {
			return fmt.Errorf("pre-flight check failed: %w", err)
		}
	}

	// 3. Deliver files and move them to destination locations
	// Step 3.1: Agent binary
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

	// Step 3.2: Trap config
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

	// Step 3.3: Systemd unit file
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

	// 4. Activate service (graceful reload/restart)
	if err := ctx.Err(); err != nil {
		return err
	}
	activationCmd := "systemctl daemon-reload && systemctl enable honeyforge-agent.service && systemctl restart honeyforge-agent.service"
	if err := d.runCommand(client, target, activationCmd); err != nil {
		return fmt.Errorf("failed to activate honeyforge-agent service: %w", err)
	}

	// Post-install health check (if enabled)
	if d.CheckHealth || target.CheckHealth {
		if err := d.checkActiveState(ctx, client, target, 3*time.Second); err != nil {
			return fmt.Errorf("post-install health check failed: %w", err)
		}
	}

	return nil
}

// Status checks service status using systemctl and bound ports using ss/netstat.
func (d *SSHDeployer) Status(ctx context.Context, target TargetConfig) (*ServiceStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, netConn, err := d.connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	defer netConn.Close()

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

	status := &ServiceStatus{}

	// 1. Run systemctl is-active honeyforge-agent.service
	stdout, stderr, exitCode, err := d.runCommandWithOutput(client, target, "systemctl is-active honeyforge-agent.service")
	if err != nil {
		return nil, fmt.Errorf("failed to check service status: %w", err)
	}

	subState := strings.TrimSpace(stdout)
	if subState == "" {
		subState = strings.TrimSpace(stderr)
	}
	if subState == "" {
		if exitCode == 0 {
			subState = "active"
		} else {
			subState = "inactive"
		}
	}

	status.SubState = subState
	status.Active = (exitCode == 0 && subState == "active")
	status.Loaded = !strings.Contains(strings.ToLower(subState), "not-found") &&
		!strings.Contains(strings.ToLower(subState), "could not be found")

	var rawBuilder strings.Builder
	rawBuilder.WriteString(fmt.Sprintf("systemctl is-active: %s\n", subState))

	// 2. Check bound ports via ss -tlpn || netstat -tlpn
	portsOut, portsErr, _, _ := d.runCommandWithOutput(client, target, "ss -tlpn || netstat -tlpn")
	rawBuilder.WriteString(fmt.Sprintf("ports output:\n%s", portsOut))
	if portsErr != "" {
		rawBuilder.WriteString(fmt.Sprintf("\nports stderr:\n%s", portsErr))
	}
	status.Listening = parseListeningPorts(portsOut)

	// 3. Query uptime if active
	if status.Active {
		uptimeOut, _, uExit, _ := d.runCommandWithOutput(client, target, "systemctl show -p ActiveEnterTimestamp --value honeyforge-agent.service")
		if uExit == 0 && strings.TrimSpace(uptimeOut) != "" {
			status.Uptime = strings.TrimSpace(uptimeOut)
		}
	}

	status.RawOutput = rawBuilder.String()
	return status, nil
}

// Restart restarts honeyforge-agent.service and checks that it successfully reached active state.
func (d *SSHDeployer) Restart(ctx context.Context, target TargetConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, netConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer client.Close()
	defer netConn.Close()

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

	cmd := "systemctl restart honeyforge-agent.service"
	if err := d.runCommand(client, target, cmd); err != nil {
		return fmt.Errorf("failed to restart honeyforge-agent service: %w", err)
	}

	return d.checkActiveState(ctx, client, target, 3*time.Second)
}

// Stop stops honeyforge-agent.service.
func (d *SSHDeployer) Stop(ctx context.Context, target TargetConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, netConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer client.Close()
	defer netConn.Close()

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

	cmd := "systemctl stop honeyforge-agent.service"
	if err := d.runCommand(client, target, cmd); err != nil {
		return fmt.Errorf("failed to stop honeyforge-agent service: %w", err)
	}
	return nil
}

// Uninstall cleanly stops, disables, and removes honeyforge-agent artifacts from the remote system.
func (d *SSHDeployer) Uninstall(ctx context.Context, target TargetConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, netConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer client.Close()
	defer netConn.Close()

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

	cmd := "systemctl stop honeyforge-agent.service 2>/dev/null; systemctl disable honeyforge-agent.service 2>/dev/null; rm -f /etc/systemd/system/honeyforge-agent.service /usr/local/bin/honeyforge-agent; rm -rf /etc/honeyforge; systemctl daemon-reload 2>/dev/null"
	if err := d.runCommand(client, target, cmd); err != nil {
		return fmt.Errorf("failed to uninstall honeyforge-agent service: %w", err)
	}
	return nil
}

// PreflightCheck verifies write permissions and disk space on /tmp and /usr/local/bin.
func (d *SSHDeployer) PreflightCheck(ctx context.Context, target TargetConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, netConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer client.Close()
	defer netConn.Close()

	return d.runPreflight(ctx, client, target)
}

// HealthCheck verifies that honeyforge-agent service is in active state within 3 seconds.
func (d *SSHDeployer) HealthCheck(ctx context.Context, target TargetConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, netConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer client.Close()
	defer netConn.Close()

	return d.checkActiveState(ctx, client, target, 3*time.Second)
}

func (d *SSHDeployer) runPreflight(ctx context.Context, client *ssh.Client, target TargetConfig) error {
	cmd := "test -w /tmp && ( [ -w /usr/local/bin ] || [ $(id -u) -eq 0 ] ) && df -Pk /tmp /usr/local/bin >/dev/null"
	if err := d.runCommand(client, target, cmd); err != nil {
		return fmt.Errorf("insufficient write permissions or disk space on /tmp or /usr/local/bin: %w", err)
	}
	return nil
}

func (d *SSHDeployer) checkActiveState(ctx context.Context, client *ssh.Client, target TargetConfig, maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	checkCmd := "systemctl is-active honeyforge-agent.service"
	var lastStatus string

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		stdout, stderr, exitCode, err := d.runCommandWithOutput(client, target, checkCmd)
		status := strings.TrimSpace(stdout)
		if status == "" {
			status = strings.TrimSpace(stderr)
		}
		lastStatus = status

		if err == nil && exitCode == 0 && status == "active" {
			return nil
		}

		if time.Now().Add(250 * time.Millisecond).After(deadline) {
			break
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}

	return fmt.Errorf("service failed to reach active state within %v (last status: %s)", maxWait, lastStatus)
}

func (d *SSHDeployer) connect(ctx context.Context, target TargetConfig) (*ssh.Client, net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	if target.Host == "" {
		return nil, nil, errors.New("target host is required")
	}
	if target.Username == "" {
		return nil, nil, errors.New("target username is required")
	}

	port := target.Port
	if port <= 0 {
		port = 22
	}

	var authMethods []ssh.AuthMethod
	if target.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(target.PrivateKey))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if target.Password != "" {
		authMethods = append(authMethods, ssh.Password(target.Password))
	}
	if len(authMethods) == 0 {
		return nil, nil, errors.New("no authentication method provided: password or private key required")
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	clientConfig := &ssh.ClientConfig{
		User:            target.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	addr := fmt.Sprintf("%s:%d", target.Host, port)
	maxRetries := d.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	var lastErr error
	backoff := 50 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}

		dialer := net.Dialer{Timeout: timeout}
		netConn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = fmt.Errorf("failed to connect to %s: %w", addr, err)
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			continue
		}

		sshConn, chans, reqs, err := ssh.NewClientConn(netConn, addr, clientConfig)
		if err != nil {
			_ = netConn.Close()
			lastErr = fmt.Errorf("ssh handshake failed with %s: %w", addr, err)
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			if isAuthError(err) {
				return nil, nil, lastErr
			}
			continue
		}

		client := ssh.NewClient(sshConn, chans, reqs)
		return client, netConn, nil
	}

	return nil, nil, lastErr
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "password rejected") ||
		strings.Contains(msg, "public key rejected") ||
		strings.Contains(msg, "auth failed") ||
		strings.Contains(msg, "authentication failed")
}

var portRegex = regexp.MustCompile(`(?::|\*)(\d{1,5})(?:\s+|$)`)

func parseListeningPorts(output string) []int {
	var agentPorts []int
	var allPorts []int
	seenAgent := make(map[int]bool)
	seenAll := make(map[int]bool)

	lines := strings.Split(output, "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Proto") {
			continue
		}

		isAgent := strings.Contains(strings.ToLower(line), "honeyforge")

		matches := portRegex.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			p, err := strconv.Atoi(m[1])
			if err != nil || p <= 0 || p > 65535 {
				continue
			}
			if isAgent && !seenAgent[p] {
				seenAgent[p] = true
				agentPorts = append(agentPorts, p)
			}
			if !seenAll[p] {
				seenAll[p] = true
				allPorts = append(allPorts, p)
			}
		}
	}

	var result []int
	if len(agentPorts) > 0 {
		result = agentPorts
	} else {
		result = allPorts
	}
	sort.Ints(result)
	return result
}

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

func (d *SSHDeployer) runCommandWithOutput(client *ssh.Client, target TargetConfig, cmd string) (string, string, int, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", "", -1, fmt.Errorf("failed to create session: %w", err)
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

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(finalCmd)
	exitCode := 0
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitStatus()
		} else {
			return stdout.String(), stderr.String(), -1, err
		}
	}
	return stdout.String(), stderr.String(), exitCode, nil
}
