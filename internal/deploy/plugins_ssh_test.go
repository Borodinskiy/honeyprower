package deploy

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func pluginTarget(server *mockSSHServer) TargetConfig {
	return TargetConfig{Host: "127.0.0.1", Port: server.port, Username: "root", Password: "pw"}
}

func pluginPayload(t *testing.T, plugins ...PluginFiles) Payload {
	return Payload{
		BinaryPath:     createTestBinary(t, []byte("agent")),
		ConfigJSON:     []byte(`{}`),
		ServiceContent: []byte("[Unit]\n"),
		Plugins:        plugins,
	}
}

func deployCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func indexOf(cmds []string, sub string) int {
	for i, c := range cmds {
		if strings.Contains(c, sub) {
			return i
		}
	}
	return -1
}

func TestDeploy_InstallsPluginBeforeAgentAndPrunesAfter(t *testing.T) {
	server := newMockSSHServer(t)
	server.allowedUsers["root"] = "pw"
	server.cmdExitCodes["test -f /opt/honeyforge/plugins/"] = 1 // версии ещё нет на хосте

	archive := []byte("tar.gz bytes")
	p := PluginFiles{Name: "my-ftp", Dir: "/opt/honeyforge/plugins/my-ftp-0123456789ab", Archive: archive, Requires: []string{"python3", "sh"}}
	if err := NewSSHDeployer().Deploy(deployCtx(t), pluginTarget(server), pluginPayload(t, p)); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	cmds := server.commands
	req := indexOf(cmds, "for c in python3 sh; do command -v")
	upload := indexOf(cmds, "cat > /tmp/hf_plugin_my-ftp-0123456789ab.tgz")
	install := indexOf(cmds, "tar -xzf /tmp/hf_plugin_my-ftp-0123456789ab.tgz -C /opt/honeyforge/plugins/my-ftp-0123456789ab.tmp --no-same-owner")
	data := indexOf(cmds, "chown nobody /var/lib/honeyforge/plugin-data")
	agent := indexOf(cmds, "cat > /tmp/hf_agent_bin")
	save := indexOf(cmds, "last-good.tmp")
	prune := indexOf(cmds, `case "$d" in my-ftp-0123456789ab) ;;`)
	if req < 0 || upload < 0 || install < 0 || data < 0 || agent < 0 || prune < 0 {
		t.Fatalf("не все шаги выполнены: %q", cmds)
	}
	if !(req < upload && upload < install && install < data && data < agent) {
		t.Fatalf("требования → загрузка → распаковка → каталог данных → агент; порядок: %q", cmds)
	}
	if prune < save {
		t.Fatal("старые версии удаляются только после того, как новый агент запустился")
	}
	if !bytes.Equal(server.files["/tmp/hf_plugin_my-ftp-0123456789ab.tgz"], archive) {
		t.Fatal("архив плагина доставлен не тот")
	}
	if !strings.Contains(cmds[install], "touch /opt/honeyforge/plugins/my-ftp-0123456789ab.tmp/.hf-complete && rm -rf /opt/honeyforge/plugins/my-ftp-0123456789ab && mv") {
		t.Fatalf("метка готовности ставится до переименования: %q", cmds[install])
	}
}

func TestDeploy_SkipsPluginVersionAlreadyOnHost(t *testing.T) {
	server := newMockSSHServer(t)
	server.allowedUsers["root"] = "pw"
	// test -f по умолчанию успешен — версия уже распакована
	p := PluginFiles{Name: "x", Dir: "/opt/honeyforge/plugins/x-aaaaaaaaaaaa", Archive: []byte("a")}
	if err := NewSSHDeployer().Deploy(deployCtx(t), pluginTarget(server), pluginPayload(t, p)); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if indexOf(server.commands, "hf_plugin_") >= 0 {
		t.Fatalf("уже установленную версию не надо загружать заново: %q", server.commands)
	}
	if indexOf(server.commands, "do command -v") >= 0 {
		t.Fatal("без requires проверять нечего")
	}
}

func TestDeploy_MissingRequirementsStopBeforeTouchingAgent(t *testing.T) {
	server := newMockSSHServer(t)
	server.allowedUsers["root"] = "pw"
	server.failCommands["do command -v"] = "python3 node\n"
	p := PluginFiles{Name: "x", Dir: "/opt/honeyforge/plugins/x-aaaaaaaaaaaa", Archive: []byte("a"), Requires: []string{"python3", "node"}}
	err := NewSSHDeployer().Deploy(deployCtx(t), pluginTarget(server), pluginPayload(t, p))
	if !errors.Is(err, ErrPluginRequirements) || !strings.Contains(err.Error(), "python3 node") {
		t.Fatalf("err = %v", err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if indexOf(server.commands, "hf_agent_bin") >= 0 || indexOf(server.commands, "hf_plugin_") >= 0 {
		t.Fatalf("при нехватке программ на хосте ничего ставить нельзя: %q", server.commands)
	}
}

func TestDeploy_RejectsUnsafePluginValues(t *testing.T) {
	cases := []PluginFiles{
		{Name: "x", Dir: "/etc/x"},
		{Name: "x", Dir: "/opt/honeyforge/plugins/../../etc"},
		{Name: "x", Dir: "/opt/honeyforge/plugins/x; rm -rf /"},
		{Name: "x", Dir: "/opt/honeyforge/plugins/x", Requires: []string{"python3;reboot"}},
		{Name: "x", Dir: "/opt/honeyforge/plugins/x", Requires: []string{"/usr/bin/python3"}},
	}
	for _, p := range cases {
		server := newMockSSHServer(t)
		server.allowedUsers["root"] = "pw"
		err := NewSSHDeployer().Deploy(deployCtx(t), pluginTarget(server), pluginPayload(t, p))
		if err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("%+v: err = %v", p, err)
		}
		server.mu.Lock()
		if len(server.commands) != 0 {
			t.Errorf("%+v: команды не должны выполняться: %q", p, server.commands)
		}
		server.mu.Unlock()
	}
}

func TestPrunePluginsCmd(t *testing.T) {
	if got := prunePluginsCmd(nil); got != "rm -rf /opt/honeyforge/plugins" {
		t.Fatalf("без плагинов каталог убирается целиком: %q", got)
	}
	got := prunePluginsCmd([]PluginFiles{
		{Dir: "/opt/honeyforge/plugins/a-111111111111"},
		{Dir: "/opt/honeyforge/plugins/b-222222222222"},
	})
	if !strings.Contains(got, "a-111111111111|b-222222222222) ;;") {
		t.Fatalf("prune = %q", got)
	}
}

func TestUndeploy_RemovesPlugins(t *testing.T) {
	if !strings.Contains(removeCmd, "/opt/honeyforge") {
		t.Fatal("снятие агента должно убирать и проекты своих ловушек")
	}
}

func TestParseAllListeningPortsIncludesOtherProcesses(t *testing.T) {
	out := "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
		"LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"honeyforge-agent\",pid=1,fd=3))\n" +
		"LISTEN 0 128 0.0.0.0:2121 0.0.0.0:* users:((\"python3\",pid=2,fd=3))\n" +
		"LISTEN 0 128 [::]:22 [::]:* users:((\"sshd\",pid=3,fd=4))\n"
	if got := parseListeningPorts(out); len(got) != 1 || got[0] != 2222 {
		t.Fatalf("agent ports = %v", got)
	}
	if got := parseAllListeningPorts(out); len(got) != 3 || got[0] != 22 || got[1] != 2121 || got[2] != 2222 {
		t.Fatalf("all ports = %v", got)
	}
}
