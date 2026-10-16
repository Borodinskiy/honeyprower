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

	"honeyprower/internal/pydeps"
)

var _ Deployer = (*SSHDeployer)(nil)

// goodDir keeps the last agent and config that passed verifyCmd, so a failed update can be
// rolled back. It is written only after a successful check: copying whatever runs before an
// update could save an agent that is crash-looping (it is briefly "active" between restarts).
const goodDir = "/var/lib/honeyforge/last-good"

// pluginsRoot — где на хосте лежат проекты своих ловушек (каталог на версию).
const pluginsRoot = "/opt/honeyforge/plugins"

// pluginDataDir — сюда программы плагинов могут писать (агент работает как nobody).
const pluginDataDir = "/var/lib/honeyforge/plugin-data"

// removeCmd tolerates an absent service (already removed), but not a failed rm (no rights).
const removeCmd = "systemctl disable --now honeyforge-agent.service >/dev/null 2>&1; " +
	"rm -f /etc/systemd/system/honeyforge-agent.service /usr/local/bin/honeyforge-agent && " +
	"rm -rf /etc/honeyforge /var/lib/honeyforge /opt/honeyforge && systemctl daemon-reload"

// ErrPluginRequirements: на хосте нет программ, без которых плагин не запустится.
var ErrPluginRequirements = errors.New("plugin requirements not met on host")

// ErrPluginPackages: не удалось поставить системные пакеты плагина (нет доступа к репозиториям и т.п.).
var ErrPluginPackages = errors.New("failed to install plugin packages on host")

// pydepsDir — каталог Python-зависимостей внутри каталога плагина; агент добавляет его в PYTHONPATH.
const pydepsDir = ".hf-pydeps"

// safeArg — имена команд и каталогов, которые подставляются в shell без кавычек.
// pyModule — имя модуля Python, как его проверяет internal/plugin.
var pyModule = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]{0,255}$`)

var safeArg = regexp.MustCompile(`^[A-Za-z0-9._+/-]+$`)

// saveGoodCmd remembers the agent that has just been verified (replacing the old copy atomically).
const saveGoodCmd = "rm -rf " + goodDir + ".tmp && mkdir -p " + goodDir + ".tmp && " +
	"cp -p /usr/local/bin/honeyforge-agent /etc/honeyforge/config.json " + goodDir + ".tmp/ && " +
	"rm -rf " + goodDir + " && mv " + goodDir + ".tmp " + goodDir

// rollbackCmd brings back the last good agent and prints "restored". Without one, or if it does
// not start either, it stops the service so it does not crash-loop and prints "stopped" or
// "restore-failed". The binary is replaced by rename: copying over a file that is being
// executed fails with "Text file busy".
const rollbackCmd = "systemctl stop honeyforge-agent.service; r=stopped; if [ -f " + goodDir + "/honeyforge-agent ]; then " +
	"cp -p " + goodDir + "/honeyforge-agent /usr/local/bin/honeyforge-agent.new && " +
	"mv -f /usr/local/bin/honeyforge-agent.new /usr/local/bin/honeyforge-agent && " +
	"cp -p " + goodDir + "/config.json /etc/honeyforge/config.json && " +
	"{ if command -v restorecon >/dev/null 2>&1; then restorecon -F /usr/local/bin/honeyforge-agent /etc/honeyforge/config.json; fi; } && " +
	"systemctl start honeyforge-agent.service && sleep 2 && systemctl is-active --quiet honeyforge-agent.service && { echo restored; exit 0; }; " +
	"r=restore-failed; fi; systemctl disable --now honeyforge-agent.service >/dev/null 2>&1; echo $r"

// activateCmd resets SELinux labels first: files moved from /tmp keep user_tmp_t and systemd refuses to exec them (203/EXEC).
const activateCmd = "if command -v restorecon >/dev/null 2>&1; then restorecon -F /usr/local/bin/honeyforge-agent /etc/honeyforge/config.json /etc/systemd/system/honeyforge-agent.service; fi; " +
	"systemctl daemon-reload && systemctl enable honeyforge-agent.service && systemctl restart honeyforge-agent.service"

// verifyCmd waits for the agent to settle. If it is not active, prints to stderr what the agent
// itself wrote in its last start (e.g. which port is busy) or, when the agent never got to run
// (bad user, SELinux), the unit's journal tail.
const verifyCmd = "sleep 3; systemctl is-active --quiet honeyforge-agent.service && exit 0; " +
	"id=$(systemctl show -p InvocationID --value honeyforge-agent.service); " +
	"out=$(if [ -n \"$id\" ]; then journalctl -o cat --no-pager _SYSTEMD_INVOCATION_ID=$id; fi); " +
	"[ -n \"$out\" ] || out=$(journalctl -u honeyforge-agent.service -n 15 --no-pager -o cat); " +
	"printf '%s\\n' \"$out\" >&2; exit 1"

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

	client, closeConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer closeConn()

	// Pre-flight verification (if enabled)
	if d.CheckPreflight || target.CheckPreflight {
		if err := d.runPreflight(ctx, client, target); err != nil {
			return fmt.Errorf("pre-flight check failed: %w", err)
		}
	}

	// 3. Deliver files and move them to destination locations
	// Step 3.0: projects of custom traps — before the agent, which needs them to start.
	if err := d.installPlugins(ctx, client, target, payload.Plugins); err != nil {
		return err
	}

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
	if err := d.runCommand(client, target, activateCmd); err != nil {
		return d.rollback(client, target, fmt.Errorf("failed to activate honeyforge-agent service: %w", err))
	}

	// 5. Make sure the agent stays up: a crash on start is otherwise invisible.
	if err := ctx.Err(); err != nil {
		return err
	}
	_, journal, code, err := d.runCommandWithOutput(client, target, verifyCmd)
	if err != nil {
		return fmt.Errorf("failed to check honeyforge-agent service: %w", err)
	}
	if code != 0 {
		return d.rollback(client, target, fmt.Errorf("agent failed to start:\n%s", strings.TrimSpace(journal)))
	}
	// Best effort: without the copy a later failed update can only stop the service.
	_ = d.runCommand(client, target, saveGoodCmd)
	// Old plugin versions go only now: until the new agent started, rollback could need them.
	_ = d.runCommand(client, target, prunePluginsCmd(payload.Plugins))

	// Post-install health check (if enabled)
	if d.CheckHealth || target.CheckHealth {
		if err := d.checkActiveState(ctx, client, target, 3*time.Second); err != nil {
			return fmt.Errorf("post-install health check failed: %w", err)
		}
	}

	return nil
}

// rollback returns the host to the last good agent after a failed update and adds the outcome
// to cause. If the agent ended up stopped, the error wraps ErrAgentStopped.
func (d *SSHDeployer) rollback(client *ssh.Client, target TargetConfig, cause error) error {
	out, stderr, code, err := d.runCommandWithOutput(client, target, rollbackCmd)
	out = strings.TrimSpace(out)
	switch {
	case err == nil && code == 0 && out == "restored":
		return fmt.Errorf("%w\nprevious version restored", cause)
	case err == nil && code == 0 && out == "stopped":
		return fmt.Errorf("%w\n%w: no previous working version to restore", cause, ErrAgentStopped)
	case err == nil && code == 0 && out == "restore-failed":
		return fmt.Errorf("%w\n%w: previous version did not start either", cause, ErrAgentStopped)
	default:
		if err == nil {
			err = fmt.Errorf("exit status %d", code)
		}
		return fmt.Errorf("%w\nrollback failed: %v %s", cause, err, strings.TrimSpace(stderr))
	}
}

// Status checks service status using systemctl and bound ports using ss/netstat.
func (d *SSHDeployer) Status(ctx context.Context, target TargetConfig) (*ServiceStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, closeConn, err := d.connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer closeConn()

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
	status.ListeningAll = parseAllListeningPorts(portsOut)

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
	client, closeConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer closeConn()

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
	client, closeConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer closeConn()

	cmd := "systemctl stop honeyforge-agent.service"
	if err := d.runCommand(client, target, cmd); err != nil {
		return fmt.Errorf("failed to stop honeyforge-agent service: %w", err)
	}
	return nil
}

// Undeploy stops the agent service on the remote server and removes everything Deploy installed.
func (d *SSHDeployer) Undeploy(ctx context.Context, target TargetConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, closeConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer closeConn()

	if err := d.runCommand(client, target, removeCmd); err != nil {
		return fmt.Errorf("failed to remove honeyforge-agent: %w", err)
	}
	return nil
}

// Uninstall cleanly stops, disables, and removes honeyforge-agent artifacts from the remote system.
func (d *SSHDeployer) Uninstall(ctx context.Context, target TargetConfig) error {
	return d.Undeploy(ctx, target)
}

// PreflightCheck verifies write permissions and disk space on /tmp and /usr/local/bin.
func (d *SSHDeployer) PreflightCheck(ctx context.Context, target TargetConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, closeConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer closeConn()

	return d.runPreflight(ctx, client, target)
}

// HealthCheck verifies that honeyforge-agent service is in active state within 3 seconds.
func (d *SSHDeployer) HealthCheck(ctx context.Context, target TargetConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, closeConn, err := d.connect(ctx, target)
	if err != nil {
		return err
	}
	defer closeConn()

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

// connect validates the target and opens an SSH client with retry resilience; closeConn releases it.
func (d *SSHDeployer) connect(ctx context.Context, target TargetConfig) (*ssh.Client, func(), error) {
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
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = client.Close()
				_ = netConn.Close()
			case <-done:
			}
		}()
		closeConn := func() {
			close(done)
			_ = client.Close()
			_ = netConn.Close()
		}
		return client, closeConn, nil
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

// parseAllListeningPorts — все порты из вывода ss/netstat, чей бы процесс их ни держал.
func parseAllListeningPorts(output string) []int {
	seen := map[int]bool{}
	var out []int
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Proto") {
			continue
		}
		for _, m := range portRegex.FindAllStringSubmatch(line, -1) {
			p, err := strconv.Atoi(m[1])
			if err == nil && p > 0 && p <= 65535 && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out
}

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

// installPlugins проверяет, что на хосте есть нужные плагинам программы, и
// раскладывает их проекты. Версия, которая уже стоит, заново не загружается.
func (d *SSHDeployer) installPlugins(ctx context.Context, client *ssh.Client, target TargetConfig, plugins []PluginFiles) error {
	if len(plugins) == 0 {
		return nil
	}
	var requires []string
	packages := map[string][]string{}
	seen := map[string]bool{}
	for _, p := range plugins {
		if !safeArg.MatchString(p.Dir) || !strings.HasPrefix(p.Dir, pluginsRoot+"/") || strings.Contains(p.Dir, "..") {
			return fmt.Errorf("plugin %s: invalid install dir %q", p.Name, p.Dir)
		}
		for _, r := range p.Requires {
			if !safeArg.MatchString(r) || strings.Contains(r, "/") {
				return fmt.Errorf("plugin %s: invalid requirement %q", p.Name, r)
			}
			if !seen[r] {
				seen[r] = true
				requires = append(requires, r)
			}
		}
		for _, m := range p.PythonModules {
			if !pyModule.MatchString(m) {
				return fmt.Errorf("plugin %s: invalid python module %q", p.Name, m)
			}
		}
		for mgr, pkgs := range p.Packages {
			if _, ok := pkgInstall[mgr]; !ok {
				return fmt.Errorf("plugin %s: invalid package manager %q", p.Name, mgr)
			}
			for _, name := range pkgs {
				if !pkgName.MatchString(name) {
					return fmt.Errorf("plugin %s: invalid package %q", p.Name, name)
				}
				if !seen[mgr+":"+name] {
					seen[mgr+":"+name] = true
					packages[mgr] = append(packages[mgr], name)
				}
			}
		}
	}

	// 1. Системные пакеты — из репозиториев хоста, только недостающие.
	if len(packages) > 0 {
		if err := d.installPackages(client, target, packages); err != nil {
			return err
		}
	}

	// 2. Программы, без которых плагины не запустятся.
	if len(requires) > 0 {
		cmd := "missing=''; for c in " + strings.Join(requires, " ") + "; do command -v \"$c\" >/dev/null 2>&1 || missing=\"$missing $c\"; done; "
		if err := d.checkMissing(client, target, cmd, "plugin requirements"); err != nil {
			return err
		}
	}

	// 3. Файлы плагинов и их Python-зависимости, собранные центром под платформу хоста.
	var platform *pydeps.Platform
	for _, p := range plugins {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, _, code, err := d.runCommandWithOutput(client, target, "test -f "+p.Dir+"/.hf-complete")
		if err != nil {
			return fmt.Errorf("plugin %s: %w", p.Name, err)
		}
		if code == 0 {
			continue // эта версия уже на хосте
		}
		base := strings.TrimPrefix(p.Dir, pluginsRoot+"/")
		tmp := "/tmp/hf_plugin_" + base + ".tgz"
		if err := d.uploadFile(client, tmp, p.Archive); err != nil {
			return fmt.Errorf("failed to upload plugin %s: %w", p.Name, err)
		}
		deps := ""
		if p.PyDeps != nil {
			if platform == nil {
				out, stderr, code, err := d.runCommandWithOutput(client, target, pydeps.ProbeCmd)
				if err != nil || code != 0 {
					return fmt.Errorf("plugin %s: failed to detect python platform on host: %v %s", p.Name, err, tail(stderr, 2))
				}
				pl, err := pydeps.ParseProbe(lastLine(out))
				if err != nil {
					return fmt.Errorf("plugin %s: %w", p.Name, err)
				}
				platform = &pl
			}
			archive, err := p.PyDeps(ctx, *platform)
			if err != nil {
				return fmt.Errorf("plugin %s: failed to prepare python dependencies for %s: %w", p.Name, platform, err)
			}
			deps = "/tmp/hf_pydeps_" + base + ".tgz"
			if err := d.uploadFile(client, deps, archive); err != nil {
				return fmt.Errorf("failed to upload python dependencies of plugin %s: %w", p.Name, err)
			}
		}
		// Распаковка во временный каталог и переименование: недоделанная установка
		// не выглядит готовой (.hf-complete появляется последним).
		install := "mkdir -p " + pluginsRoot + " && rm -rf " + p.Dir + ".tmp && mkdir -p " + p.Dir + ".tmp && " +
			"tar -xzf " + tmp + " -C " + p.Dir + ".tmp --no-same-owner && "
		if deps != "" {
			install += "mkdir -p " + p.Dir + ".tmp/" + pydepsDir + " && tar -xzf " + deps + " -C " + p.Dir + ".tmp/" + pydepsDir +
				" --no-same-owner && rm -f " + deps + " && "
		}
		install += "chmod -R u+rwX,go+rX,go-w " + p.Dir + ".tmp && touch " + p.Dir + ".tmp/.hf-complete && " +
			"rm -rf " + p.Dir + " && mv " + p.Dir + ".tmp " + p.Dir + " && rm -f " + tmp + "; " +
			"r=$?; if command -v restorecon >/dev/null 2>&1; then restorecon -RF " + p.Dir + " >/dev/null 2>&1; fi; exit $r"
		if err := d.runCommand(client, target, install); err != nil {
			return fmt.Errorf("failed to install plugin %s: %w", p.Name, err)
		}
	}

	// 4. Модули Python — так, как их увидит плагин: со своими зависимостями и без
	// пользовательских site-packages того, кто подключился (плагин работает от nobody).
	modCheck := ""
	for _, p := range plugins {
		for _, m := range p.PythonModules {
			modCheck += "PYTHONPATH=" + p.Dir + "/" + pydepsDir + " HOME=/nonexistent python3 -s -c \"import " + m +
				"\" >/dev/null 2>&1 || missing=\"$missing python3:" + m + "\"; "
		}
	}
	if modCheck != "" {
		if err := d.checkMissing(client, target, "missing=''; "+modCheck, "python modules"); err != nil {
			return err
		}
	}

	// Агент работает как nobody: каталог, куда его программы могут писать.
	dataCmd := "mkdir -p " + pluginDataDir + " && chown nobody " + pluginDataDir + " && chmod 0750 " + pluginDataDir
	if err := d.runCommand(client, target, dataCmd); err != nil {
		return fmt.Errorf("failed to prepare plugin data dir: %w", err)
	}
	return nil
}

// checkMissing выполняет проверку, которая собирает недостающее в $missing.
// Список — в stdout с меткой: в stderr sudo пишет своё (например, «лекцию» при первом запуске).
func (d *SSHDeployer) checkMissing(client *ssh.Client, target TargetConfig, cmd, what string) error {
	cmd += "if [ -n \"$missing\" ]; then echo \"hf-missing:$missing\"; exit 1; fi"
	stdout, stderr, code, err := d.runCommandWithOutput(client, target, cmd)
	if err != nil {
		return fmt.Errorf("failed to check %s: %w", what, err)
	}
	if code != 0 {
		for _, line := range strings.Split(stdout, "\n") {
			if missing, ok := strings.CutPrefix(strings.TrimSpace(line), "hf-missing:"); ok {
				return fmt.Errorf("%w: %s", ErrPluginRequirements, strings.TrimSpace(missing))
			}
		}
		return fmt.Errorf("failed to check %s: %s", what, tail(stderr, 3))
	}
	return nil
}

// Как проверить и поставить пакеты каждым менеджером. apt сначала пробует без
// update — не трогаем индексы, если пакеты и так известны.
var pkgInstall = map[string]struct{ check, install string }{
	"apt": {`dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'ok installed'`,
		`export DEBIAN_FRONTEND=noninteractive; apt-get install -y -q --no-install-recommends $todo || { apt-get update -q && apt-get install -y -q --no-install-recommends $todo; }`},
	"dnf":    {`rpm -q "$p" >/dev/null 2>&1`, `dnf install -y -q $todo`},
	"yum":    {`rpm -q "$p" >/dev/null 2>&1`, `yum install -y -q $todo`},
	"apk":    {`apk info -e "$p" >/dev/null 2>&1`, `apk add --no-cache -q $todo`},
	"zypper": {`rpm -q "$p" >/dev/null 2>&1`, `zypper -n -q install $todo`},
}

// Команда менеджера пакетов → его имя в манифесте.
var pkgManagers = [][2]string{{"apt-get", "apt"}, {"dnf", "dnf"}, {"yum", "yum"}, {"apk", "apk"}, {"zypper", "zypper"}}

var pkgName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_:-]{0,127}$`)

// installPackages ставит системные пакеты плагинов менеджером хоста. Нет
// менеджера или пакетов для него — ничего не делаем: чего не хватает, скажет
// проверка requires.
func (d *SSHDeployer) installPackages(client *ssh.Client, target TargetConfig, packages map[string][]string) error {
	detect := ""
	for _, m := range pkgManagers {
		detect += "command -v " + m[0] + " >/dev/null 2>&1 && { echo hf-pm:" + m[1] + "; exit 0; }; "
	}
	out, _, _, err := d.runCommandWithOutput(client, target, detect+"echo hf-pm:none")
	if err != nil {
		return fmt.Errorf("failed to detect package manager: %w", err)
	}
	mgr := ""
	for _, line := range strings.Split(out, "\n") {
		if m, ok := strings.CutPrefix(strings.TrimSpace(line), "hf-pm:"); ok {
			mgr = m
		}
	}
	pkgs := packages[mgr]
	if len(pkgs) == 0 {
		return nil
	}
	spec := pkgInstall[mgr]
	cmd := "todo=''; for p in " + strings.Join(pkgs, " ") + "; do " + spec.check + " || todo=\"$todo $p\"; done; " +
		"[ -z \"$todo\" ] && exit 0; echo \"hf-installing:$todo\"; " + spec.install
	stdout, stderr, code, err := d.runCommandWithOutput(client, target, cmd)
	if err != nil {
		return fmt.Errorf("%w (%s): %v", ErrPluginPackages, mgr, err)
	}
	if code != 0 {
		todo := ""
		for _, line := range strings.Split(stdout, "\n") {
			if t, ok := strings.CutPrefix(strings.TrimSpace(line), "hf-installing:"); ok {
				todo = strings.TrimSpace(t)
			}
		}
		return fmt.Errorf("%w (%s: %s): %s", ErrPluginPackages, mgr, todo, tail(stderr, 3))
	}
	return nil
}

// tail — последние n непустых строк одной строкой: для сообщений об ошибках.
func tail(s string, n int) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func lastLine(s string) string { return tail(s, 1) }

// prunePluginsCmd удаляет с хоста версии плагинов, которые не нужны текущему конфигу.
func prunePluginsCmd(plugins []PluginFiles) string {
	if len(plugins) == 0 {
		return "rm -rf " + pluginsRoot
	}
	keep := make([]string, 0, len(plugins))
	for _, p := range plugins {
		keep = append(keep, strings.TrimPrefix(p.Dir, pluginsRoot+"/"))
	}
	return "cd " + pluginsRoot + " 2>/dev/null || exit 0; for d in *; do case \"$d\" in " +
		strings.Join(keep, "|") + ") ;; *) rm -rf \"./$d\" ;; esac; done"
}
