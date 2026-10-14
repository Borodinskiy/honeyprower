package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"honeyprower/internal/deploy"
	"honeyprower/internal/httpx"
	"honeyprower/internal/storage"
)

// deployTimeout покрывает загрузку бинарника агента на медленный канал и проверку запуска службы.
const deployTimeout = 3 * time.Minute

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

	target, ok := h.decodeTarget(w, r)
	if !ok {
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
		// Агент на другой машине не достучится до центра по localhost: подставляем адрес центра,
		// видимый из сети цели. Если цель — сама машина центра, localhost подходит как есть.
		if isLoopbackHost(hostOf(cfg.CenterURL)) && !isLocalHost(target.Host) {
			u, _ := url.Parse(cfg.CenterURL)
			ip, err := outboundIP(target.Host, target.Port)
			if err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "center url is loopback; set PUBLIC_URL")
				return
			}
			if port := u.Port(); port != "" {
				u.Host = net.JoinHostPort(ip, port)
			} else {
				u.Host = ip
			}
			cfg.CenterURL = u.String()
		}
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

		// Общий WriteTimeout сервера (15 с) оборвал бы ответ посреди деплоя.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(deployTimeout + 10*time.Second))
		ctx, cancel := context.WithTimeout(r.Context(), deployTimeout)
		defer cancel()

		if err := h.Deployer.Deploy(ctx, target, payload); err != nil {
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

// HandleUndeployTrap handles POST /api/traps/{id}/undeploy: stops the agent on the
// target over SSH and removes its files. The channel to the agent is one-way, so
// the center can't stop it any other way.
func (h *Handlers) HandleUndeployTrap(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := h.Store.GetTrap(r.Context(), id); errors.Is(err, storage.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "trap not found")
		return
	} else if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load trap")
		return
	}

	target, ok := h.decodeTarget(w, r)
	if !ok {
		return
	}

	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(deployTimeout + 10*time.Second))
	ctx, cancel := context.WithTimeout(r.Context(), deployTimeout)
	defer cancel()

	if err := h.Deployer.Undeploy(ctx, target); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	httpx.WriteJSON(w, http.StatusOK, deployResponse{
		Status: "removed",
		TrapID: id,
		Host:   target.Host,
	})
}

// decodeTarget reads and checks SSH connection settings; on failure the error is already written.
func (h *Handlers) decodeTarget(w http.ResponseWriter, r *http.Request) (deploy.TargetConfig, bool) {
	var target deploy.TargetConfig
	if !httpx.DecodeJSON(w, r, &target) {
		return target, false
	}

	if strings.TrimSpace(target.Host) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "host is required")
		return target, false
	}
	if strings.TrimSpace(target.Username) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username is required")
		return target, false
	}
	if target.Password == "" && target.PrivateKey == "" {
		httpx.WriteError(w, http.StatusBadRequest, "password or privateKey is required")
		return target, false
	}
	if target.Port <= 0 {
		target.Port = 22
	}

	if h.Deployer == nil {
		httpx.WriteError(w, http.StatusInternalServerError, "deployer service unavailable")
		return target, false
	}
	return target, true
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isLocalHost сообщает, указывает ли host на эту же машину (loopback или адрес её интерфейса).
func isLocalHost(host string) bool {
	if isLoopbackHost(host) {
		return true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, ip := range ips {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// outboundIP возвращает локальный адрес, с которого эта машина ходит к host (UDP-«соединение» пакетов не шлёт).
func outboundIP(host string, port int) (string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}
