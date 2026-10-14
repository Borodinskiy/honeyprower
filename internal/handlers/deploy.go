package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"honeyprower/internal/deploy"
	"honeyprower/internal/httpx"
	"honeyprower/internal/storage"
)

type deployResponse struct {
	Status string `json:"status"`
	TrapID int64  `json:"trapId"`
	Host   string `json:"host"`
}

// HandleDeployTrap handles POST /api/traps/{id}/deploy.
func (h *Handlers) HandleDeployTrap(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}

	trap, err := h.Store.GetTrap(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "trap not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap")
		return
	}

	var target deploy.TargetConfig
	if !httpx.DecodeJSON(w, r, &target) {
		return
	}

	if strings.TrimSpace(target.Host) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "host is required")
		return
	}
	if strings.TrimSpace(target.Username) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username is required")
		return
	}
	if target.Password == "" && target.PrivateKey == "" {
		httpx.WriteError(w, http.StatusBadRequest, "password or privateKey is required")
		return
	}
	if target.Port <= 0 {
		target.Port = 22
	}

	if h.Deployer == nil {
		httpx.WriteError(w, http.StatusInternalServerError, "deployer service unavailable")
		return
	}

	cfg := h.buildConfig(r, trap)
	cfgBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to marshal agent config")
		return
	}

	svcPath := os.Getenv("HF_AGENT_SERVICE")
	if svcPath == "" {
		svcPath = "agent/honeyforge-agent.service"
	}
	svcBytes, err := os.ReadFile(svcPath)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to read systemd service file")
		return
	}

	binPath := os.Getenv("HF_AGENT_BIN")
	if binPath == "" {
		binPath = "agent/target/release/honeyforge-agent"
	}
	if _, err := os.Stat(binPath); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "agent binary not found; please build the agent first")
		return
	}

	payload := deploy.Payload{
		BinaryPath:     binPath,
		ServiceContent: svcBytes,
		ConfigJSON:     cfgBytes,
	}

	if err := h.Deployer.Deploy(r.Context(), target, payload); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	httpx.WriteJSON(w, http.StatusOK, deployResponse{
		Status: "deployed",
		TrapID: id,
		Host:   target.Host,
	})
}
