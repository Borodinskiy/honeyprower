package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"honeyprower/internal/auth"
	"honeyprower/internal/deploy"
	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

type mockDeployer struct {
	deployFunc    func(ctx context.Context, target deploy.TargetConfig, payload deploy.Payload) error
	statusFunc    func(ctx context.Context, target deploy.TargetConfig) (*deploy.ServiceStatus, error)
	restartFunc   func(ctx context.Context, target deploy.TargetConfig) error
	stopFunc      func(ctx context.Context, target deploy.TargetConfig) error
	uninstallFunc func(ctx context.Context, target deploy.TargetConfig) error
	undeployFunc  func(ctx context.Context, target deploy.TargetConfig) error

	lastTarget  deploy.TargetConfig
	lastPayload deploy.Payload
	lastAction  string
	calls       int
}

func (m *mockDeployer) Deploy(ctx context.Context, target deploy.TargetConfig, payload deploy.Payload) error {
	m.calls++
	m.lastAction = "deploy"
	m.lastTarget = target
	m.lastPayload = payload
	if m.deployFunc != nil {
		return m.deployFunc(ctx, target, payload)
	}
	return nil
}

func (m *mockDeployer) Status(ctx context.Context, target deploy.TargetConfig) (*deploy.ServiceStatus, error) {
	m.calls++
	m.lastAction = "status"
	m.lastTarget = target
	if m.statusFunc != nil {
		return m.statusFunc(ctx, target)
	}
	return &deploy.ServiceStatus{
		Active:    true,
		SubState:  "active",
		Loaded:    true,
		Listening: []int{2222},
	}, nil
}

func (m *mockDeployer) Restart(ctx context.Context, target deploy.TargetConfig) error {
	m.calls++
	m.lastAction = "restart"
	m.lastTarget = target
	if m.restartFunc != nil {
		return m.restartFunc(ctx, target)
	}
	return nil
}

func (m *mockDeployer) Stop(ctx context.Context, target deploy.TargetConfig) error {
	m.calls++
	m.lastAction = "stop"
	m.lastTarget = target
	if m.stopFunc != nil {
		return m.stopFunc(ctx, target)
	}
	return nil
}

func (m *mockDeployer) Uninstall(ctx context.Context, target deploy.TargetConfig) error {
	m.calls++
	m.lastAction = "uninstall"
	m.lastTarget = target
	if m.uninstallFunc != nil {
		return m.uninstallFunc(ctx, target)
	}
	return nil
}

func (m *mockDeployer) Undeploy(ctx context.Context, target deploy.TargetConfig) error {
	m.calls++
	m.lastAction = "undeploy"
	m.lastTarget = target
	if m.undeployFunc != nil {
		return m.undeployFunc(ctx, target)
	}
	return nil
}
func setupDeployTest(t *testing.T) (*Handlers, *storage.Memory, *mockDeployer, *models.Trap) {
	t.Helper()
	mem := storage.NewInMemory()
	authMgr := auth.NewManager()
	h := New(mem, authMgr)
	mock := &mockDeployer{}
	h.Deployer = mock

	trap, err := mem.CreateTrap(context.Background(), models.TrapCreate{
		Name:    "Test Trap",
		Class:   "banner",
		Bind:    "0.0.0.0",
		Port:    2222,
		Params:  json.RawMessage(`{"banner":"Welcome\r\n"}`),
		Enabled: true,
	}, "test-token-xyz")
	if err != nil {
		t.Fatalf("failed to create trap: %v", err)
	}

	return h, mem, mock, trap
}

func TestDeployTrap_Success(t *testing.T) {
	h, _, mock, trap := setupDeployTest(t)

	tmpDir := t.TempDir()
	svcPath := filepath.Join(tmpDir, "honeyforge-agent.service")
	svcContent := []byte("[Unit]\nDescription=HoneyForge Agent\n")
	if err := os.WriteFile(svcPath, svcContent, 0644); err != nil {
		t.Fatalf("failed to write service file: %v", err)
	}

	binPath := filepath.Join(tmpDir, "honeyforge-agent")
	binContent := []byte("#!/bin/sh\n")
	if err := os.WriteFile(binPath, binContent, 0755); err != nil {
		t.Fatalf("failed to write binary file: %v", err)
	}

	t.Setenv("HF_AGENT_SERVICE", svcPath)
	t.Setenv("HF_AGENT_BIN", binPath)

	body := []byte(`{
		"host": "192.168.1.50",
		"port": 2222,
		"username": "deployuser",
		"password": "secretpassword",
		"useSudo": true
	}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Status string `json:"status"`
		TrapID int64  `json:"trapId"`
		Host   string `json:"host"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}
	if resp.Status != "deployed" {
		t.Errorf("expected status 'deployed', got %q", resp.Status)
	}
	if resp.TrapID != trap.ID {
		t.Errorf("expected trapId %d, got %d", trap.ID, resp.TrapID)
	}
	if resp.Host != "192.168.1.50" {
		t.Errorf("expected host '192.168.1.50', got %q", resp.Host)
	}

	if mock.calls != 1 {
		t.Fatalf("expected 1 call to deployer, got %d", mock.calls)
	}
	if mock.lastTarget.Host != "192.168.1.50" {
		t.Errorf("expected target host '192.168.1.50', got %q", mock.lastTarget.Host)
	}
	if mock.lastTarget.Username != "deployuser" {
		t.Errorf("expected target username 'deployuser', got %q", mock.lastTarget.Username)
	}
	if mock.lastTarget.Password != "secretpassword" {
		t.Errorf("expected target password 'secretpassword', got %q", mock.lastTarget.Password)
	}
	if mock.lastTarget.Port != 2222 {
		t.Errorf("expected target port 2222, got %d", mock.lastTarget.Port)
	}
	if !mock.lastTarget.UseSudo {
		t.Errorf("expected target useSudo true, got false")
	}

	if mock.lastPayload.BinaryPath != binPath {
		t.Errorf("expected binary path %q, got %q", binPath, mock.lastPayload.BinaryPath)
	}
	if !bytes.Equal(mock.lastPayload.ServiceContent, svcContent) {
		t.Errorf("expected service content %q, got %q", string(svcContent), string(mock.lastPayload.ServiceContent))
	}
	if !strings.Contains(string(mock.lastPayload.ConfigJSON), trap.Token) {
		t.Errorf("expected config JSON to contain trap token %q: %s", trap.Token, string(mock.lastPayload.ConfigJSON))
	}

	var agentCfg struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(mock.lastPayload.ConfigJSON, &agentCfg); err != nil {
		t.Fatalf("failed to decode config JSON: %v", err)
	}
	if agentCfg.Token != trap.Token {
		t.Errorf("expected agent config token %q, got %q", trap.Token, agentCfg.Token)
	}
}

func TestDeployTrap_NotFound(t *testing.T) {
	h, _, _, _ := setupDeployTest(t)

	body := []byte(`{"host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/traps/999/deploy", bytes.NewReader(body))
	req.SetPathValue("id", "999")
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeployTrap_Validation(t *testing.T) {
	h, _, _, trap := setupDeployTest(t)

	cases := []struct {
		name string
		body string
	}{
		{
			name: "empty host",
			body: `{"host":"","username":"deployuser","password":"secretpassword"}`,
		},
		{
			name: "whitespace host",
			body: `{"host":"   ","username":"deployuser","password":"secretpassword"}`,
		},
		{
			name: "empty username",
			body: `{"host":"192.168.1.50","username":"","password":"secretpassword"}`,
		},
		{
			name: "whitespace username",
			body: `{"host":"192.168.1.50","username":"   ","password":"secretpassword"}`,
		},
		{
			name: "no credentials",
			body: `{"host":"192.168.1.50","username":"deployuser"}`,
		},
		{
			name: "empty password and private key",
			body: `{"host":"192.168.1.50","username":"deployuser","password":"","privateKey":""}`,
		},
		{
			name: "invalid json",
			body: `not-valid-json`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader([]byte(tc.body)))
			req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
			w := httptest.NewRecorder()

			h.HandleDeployTrap(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400 for case %q, got %d: %s", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestDeployTrap_DeployerError(t *testing.T) {
	h, _, mock, trap := setupDeployTest(t)

	tmpDir := t.TempDir()
	svcPath := filepath.Join(tmpDir, "honeyforge-agent.service")
	if err := os.WriteFile(svcPath, []byte("[Unit]\n"), 0644); err != nil {
		t.Fatalf("failed to write service file: %v", err)
	}

	binPath := filepath.Join(tmpDir, "honeyforge-agent")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("failed to write binary file: %v", err)
	}

	t.Setenv("HF_AGENT_SERVICE", svcPath)
	t.Setenv("HF_AGENT_BIN", binPath)

	mock.deployFunc = func(ctx context.Context, target deploy.TargetConfig, payload deploy.Payload) error {
		return errors.New("ssh: connect to host 192.168.1.50 port 22: Connection refused")
	}

	body := []byte(`{"host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), "Connection refused") {
		t.Errorf("expected response to contain 'Connection refused', got %s", w.Body.String())
	}
}

func TestDeployTrap_InvalidID(t *testing.T) {
	h, _, _, _ := setupDeployTest(t)

	body := []byte(`{"host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/traps/abc/deploy", bytes.NewReader(body))
	req.SetPathValue("id", "abc")
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeployTrap_DeployerUnavailable(t *testing.T) {
	h, _, _, trap := setupDeployTest(t)
	h.Deployer = nil

	body := []byte(`{"host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "deployer service unavailable") {
		t.Errorf("expected 'deployer service unavailable', got %s", w.Body.String())
	}
}

func TestDeployTrap_MissingServiceFile(t *testing.T) {
	h, _, _, trap := setupDeployTest(t)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "honeyforge-agent")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("failed to write binary file: %v", err)
	}

	t.Setenv("HF_AGENT_SERVICE", filepath.Join(tmpDir, "nonexistent.service"))
	t.Setenv("HF_AGENT_BIN", binPath)

	body := []byte(`{"host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "failed to read systemd service file") {
		t.Errorf("expected 'failed to read systemd service file', got %s", w.Body.String())
	}
}

func TestDeployTrap_MissingBinary(t *testing.T) {
	h, _, _, trap := setupDeployTest(t)

	tmpDir := t.TempDir()
	svcPath := filepath.Join(tmpDir, "honeyforge-agent.service")
	if err := os.WriteFile(svcPath, []byte("[Unit]\n"), 0644); err != nil {
		t.Fatalf("failed to write service file: %v", err)
	}

	t.Setenv("HF_AGENT_SERVICE", svcPath)
	t.Setenv("HF_AGENT_BIN", filepath.Join(tmpDir, "nonexistent-agent"))

	body := []byte(`{"host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "agent binary not found; please build the agent first") {
		t.Errorf("expected 'agent binary not found; please build the agent first', got %s", w.Body.String())
	}
}

func TestDeployTrap_DefaultPortAndPrivateKey(t *testing.T) {
	h, _, mock, trap := setupDeployTest(t)

	tmpDir := t.TempDir()
	svcPath := filepath.Join(tmpDir, "honeyforge-agent.service")
	if err := os.WriteFile(svcPath, []byte("[Unit]\n"), 0644); err != nil {
		t.Fatalf("failed to write service file: %v", err)
	}

	binPath := filepath.Join(tmpDir, "honeyforge-agent")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("failed to write binary file: %v", err)
	}

	t.Setenv("HF_AGENT_SERVICE", svcPath)
	t.Setenv("HF_AGENT_BIN", binPath)

	body := []byte(`{
		"host": "192.168.1.50",
		"username": "deployuser",
		"privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----"
	}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	if mock.lastTarget.Port != 22 {
		t.Errorf("expected default port 22, got %d", mock.lastTarget.Port)
	}
	if !strings.Contains(mock.lastTarget.PrivateKey, "OPENSSH PRIVATE KEY") {
		t.Errorf("expected private key to be set, got %q", mock.lastTarget.PrivateKey)
	}
}

func TestDeployTrap_Lifecycle_Status(t *testing.T) {
	h, _, mock, trap := setupDeployTest(t)

	mock.statusFunc = func(ctx context.Context, target deploy.TargetConfig) (*deploy.ServiceStatus, error) {
		return &deploy.ServiceStatus{
			Active:    true,
			SubState:  "running",
			Loaded:    true,
			Listening: []int{2222, 8080},
			Uptime:    "2 hours",
			RawOutput: "systemctl is-active: running",
		}, nil
	}

	// 1. Dispatch via query parameter ?action=status
	body := []byte(`{"host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy?action=status", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.calls != 1 || mock.lastAction != "status" {
		t.Fatalf("expected 1 call with action 'status', got %d calls, lastAction=%s", mock.calls, mock.lastAction)
	}

	var resp struct {
		Active         bool     `json:"active"`
		SubState       string   `json:"subState"`
		Loaded         bool     `json:"loaded"`
		ListeningPorts []int    `json:"listeningPorts"`
		Uptime         string   `json:"uptime"`
		Status         string   `json:"status"`
		TrapID         int64    `json:"trapId"`
		Host           string   `json:"host"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Active || !resp.Loaded || resp.SubState != "running" {
		t.Errorf("unexpected status response: %+v", resp)
	}
	if len(resp.ListeningPorts) != 2 || resp.ListeningPorts[0] != 2222 || resp.ListeningPorts[1] != 8080 {
		t.Errorf("unexpected listening ports: %v", resp.ListeningPorts)
	}
	if resp.TrapID != trap.ID || resp.Host != "192.168.1.50" {
		t.Errorf("unexpected trapId/host: %d, %s", resp.TrapID, resp.Host)
	}

	// 2. Dispatch via body field {"action": "status"}
	bodyAction := []byte(`{"action":"status","host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req2 := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(bodyAction))
	req2.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w2 := httptest.NewRecorder()

	h.HandleDeployTrap(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w2.Code, w2.Body.String())
	}
	if mock.calls != 2 || mock.lastAction != "status" {
		t.Fatalf("expected 2 calls with action 'status', got %d calls, lastAction=%s", mock.calls, mock.lastAction)
	}
}

func TestDeployTrap_Lifecycle_Restart(t *testing.T) {
	h, _, mock, trap := setupDeployTest(t)

	// Query parameter dispatch
	body := []byte(`{"host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy?action=restart", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.calls != 1 || mock.lastAction != "restart" {
		t.Fatalf("expected 1 call with action 'restart', got %d, lastAction=%s", mock.calls, mock.lastAction)
	}

	var resp struct {
		Status string `json:"status"`
		TrapID int64  `json:"trapId"`
		Host   string `json:"host"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Status != "restarted" || resp.TrapID != trap.ID || resp.Host != "192.168.1.50" {
		t.Errorf("unexpected response: %+v", resp)
	}

	// Body action dispatch
	body2 := []byte(`{"action":"restart","host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req2 := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body2))
	req2.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w2 := httptest.NewRecorder()

	h.HandleDeployTrap(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w2.Code, w2.Body.String())
	}
	if mock.calls != 2 || mock.lastAction != "restart" {
		t.Fatalf("expected 2 calls with action 'restart', got %d", mock.calls)
	}
}

func TestDeployTrap_Lifecycle_Stop(t *testing.T) {
	h, _, mock, trap := setupDeployTest(t)

	body := []byte(`{"action":"stop","host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.calls != 1 || mock.lastAction != "stop" {
		t.Fatalf("expected 1 call with action 'stop', got %d, lastAction=%s", mock.calls, mock.lastAction)
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Status != "stopped" {
		t.Errorf("expected status 'stopped', got %q", resp.Status)
	}
}

func TestDeployTrap_Lifecycle_Uninstall(t *testing.T) {
	h, _, mock, trap := setupDeployTest(t)

	body := []byte(`{"action":"uninstall","host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.calls != 1 || mock.lastAction != "uninstall" {
		t.Fatalf("expected 1 call with action 'uninstall', got %d, lastAction=%s", mock.calls, mock.lastAction)
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Status != "uninstalled" {
		t.Errorf("expected status 'uninstalled', got %q", resp.Status)
	}
}

func TestDeployTrap_Lifecycle_Errors(t *testing.T) {
	h, _, mock, trap := setupDeployTest(t)

	actions := []struct {
		action    string
		setupMock func()
		errSubstr string
	}{
		{
			action: "status",
			setupMock: func() {
				mock.statusFunc = func(ctx context.Context, target deploy.TargetConfig) (*deploy.ServiceStatus, error) {
					return nil, errors.New("ssh connection failed")
				}
			},
			errSubstr: "ssh connection failed",
		},
		{
			action: "restart",
			setupMock: func() {
				mock.restartFunc = func(ctx context.Context, target deploy.TargetConfig) error {
					return errors.New("failed to restart service")
				}
			},
			errSubstr: "failed to restart service",
		},
		{
			action: "stop",
			setupMock: func() {
				mock.stopFunc = func(ctx context.Context, target deploy.TargetConfig) error {
					return errors.New("failed to stop service")
				}
			},
			errSubstr: "failed to stop service",
		},
		{
			action: "uninstall",
			setupMock: func() {
				mock.uninstallFunc = func(ctx context.Context, target deploy.TargetConfig) error {
					return errors.New("failed to uninstall service")
				}
			},
			errSubstr: "failed to uninstall service",
		},
	}

	for _, tc := range actions {
		t.Run(tc.action, func(t *testing.T) {
			tc.setupMock()
			body := []byte(fmt.Sprintf(`{"action":%q,"host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`, tc.action))
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body))
			req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
			w := httptest.NewRecorder()

			h.HandleDeployTrap(w, req)

			if w.Code != http.StatusInternalServerError {
				t.Fatalf("expected status 500 for action %q, got %d: %s", tc.action, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.errSubstr) {
				t.Errorf("expected response to contain %q, got: %s", tc.errSubstr, w.Body.String())
			}
		})
	}
}

func TestDeployTrap_Lifecycle_UnsupportedAction(t *testing.T) {
	h, _, _, trap := setupDeployTest(t)

	body := []byte(`{"action":"invalid_action","host":"192.168.1.50","username":"deployuser","password":"secretpassword"}`)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/traps/%d/deploy", trap.ID), bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(trap.ID, 10))
	w := httptest.NewRecorder()

	h.HandleDeployTrap(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for unsupported action, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unsupported action") {
		t.Errorf("expected error message to mention unsupported action, got: %s", w.Body.String())
	}
}

func undeployRequest(t *testing.T, id string, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/traps/"+id+"/undeploy", strings.NewReader(body))
	req.SetPathValue("id", id)
	return req
}

func TestUndeployTrap_Success(t *testing.T) {
	h, _, mock, trap := setupDeployTest(t)
	id := strconv.FormatInt(trap.ID, 10)

	w := httptest.NewRecorder()
	h.HandleUndeployTrap(w, undeployRequest(t, id, `{"host":"10.0.0.5","username":"admin","password":"pw","useSudo":true}`))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.calls != 1 || mock.lastTarget.Host != "10.0.0.5" || mock.lastTarget.Port != 22 || !mock.lastTarget.UseSudo {
		t.Errorf("unexpected target passed to deployer: %+v (calls %d)", mock.lastTarget, mock.calls)
	}
	if !strings.Contains(w.Body.String(), `"status":"removed"`) {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestUndeployTrap_Errors(t *testing.T) {
	h, _, mock, trap := setupDeployTest(t)
	id := strconv.FormatInt(trap.ID, 10)

	cases := []struct {
		name, id, body string
		code           int
		want           string
	}{
		{"unknown trap", "9999", `{"host":"h","username":"u","password":"p"}`, http.StatusNotFound, "trap not found"},
		{"no host", id, `{"username":"u","password":"p"}`, http.StatusBadRequest, "host is required"},
		{"no credentials", id, `{"host":"h","username":"u"}`, http.StatusBadRequest, "password or privateKey is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.HandleUndeployTrap(w, undeployRequest(t, c.id, c.body))
			if w.Code != c.code || !strings.Contains(w.Body.String(), c.want) {
				t.Errorf("got %d %s, want %d %q", w.Code, w.Body.String(), c.code, c.want)
			}
		})
	}
	if mock.calls != 0 {
		t.Errorf("deployer must not be called on invalid input, got %d calls", mock.calls)
	}

	mock.undeployFunc = func(ctx context.Context, target deploy.TargetConfig) error {
		return errors.New("failed to remove honeyforge-agent: Permission denied")
	}
	w := httptest.NewRecorder()
	h.HandleUndeployTrap(w, undeployRequest(t, id, `{"host":"h","username":"u","password":"p"}`))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "Permission denied") {
		t.Errorf("got %d %s, want 500 with deployer error", w.Code, w.Body.String())
	}
}
