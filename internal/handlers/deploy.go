package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
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

type statusResponse struct {
	*deploy.ServiceStatus
	Status string `json:"status,omitempty"`
	TrapID int64  `json:"trapId,omitempty"`
	Host   string `json:"host,omitempty"`
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

	// Action resolution priority:
	// 1. URL query param (?action=...)
	// 2. URL path value (if matched)
	// 3. Request body target.Action
	// 4. Default: "deploy"
	action := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("action")))
	if action == "" {
		action = strings.ToLower(strings.TrimSpace(r.PathValue("action")))
	}
	if action == "" {
		action = strings.ToLower(strings.TrimSpace(target.Action))
	}
	if action == "" {
		action = "deploy"
	}

	switch action {
	case "status":
		status, err := h.Deployer.Status(r.Context(), target)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if status == nil {
			status = &deploy.ServiceStatus{}
		}
		httpx.WriteJSON(w, http.StatusOK, statusResponse{
			ServiceStatus: status,
			Status:        status.SubState,
			TrapID:        id,
			Host:          target.Host,
		})

	case "restart":
		if err := h.Deployer.Restart(r.Context(), target); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httpx.WriteJSON(w, http.StatusOK, deployResponse{
			Status: "restarted",
			TrapID: id,
			Host:   target.Host,
		})

	case "stop":
		if err := h.Deployer.Stop(r.Context(), target); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httpx.WriteJSON(w, http.StatusOK, deployResponse{
			Status: "stopped",
			TrapID: id,
			Host:   target.Host,
		})

	case "uninstall":
		if err := h.Deployer.Uninstall(r.Context(), target); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httpx.WriteJSON(w, http.StatusOK, deployResponse{
			Status: "uninstalled",
			TrapID: id,
			Host:   target.Host,
		})

	case "deploy":
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

	default:
		httpx.WriteError(w, http.StatusBadRequest, fmt.Sprintf("unsupported action %q", action))
	}
}
