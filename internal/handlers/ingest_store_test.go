package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"honeyprower/internal/models"
)

func ingestReq(t *testing.T, h *Handlers, token, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(body))
	req.Header.Set("X-HF-Token", token)
	w := httptest.NewRecorder()
	h.Ingest(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("ingest: %d %s", w.Code, w.Body.String())
	}
}

func eventsOfType(t *testing.T, h *Handlers, typ string) []models.Event {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/events?type="+typ, nil)
	w := httptest.NewRecorder()
	h.ListFilterEvents(w, req)
	var out []models.Event
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHoneyCredentialLoginRaisesToken(t *testing.T) {
	h, _, mem := setupTestHandlers()
	w := createTrapReq(t, h, `{"name":"Приманки","class":"honeytoken","port":8088,"enabled":true,"params":{"tokens":[
		{"kind":"url","label":"share/a.html","token":""},
		{"kind":"credentials","label":"git/infra/.env","username":"svc_backup","password":""},
		{"kind":"credentials","label":"wiki","username":"","password":"Wiki-2026!"}]}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var ht models.Trap
	json.Unmarshal(w.Body.Bytes(), &ht)
	var p struct {
		Tokens []map[string]string `json:"tokens"`
	}
	json.Unmarshal(ht.Params, &p)
	if p.Tokens[0]["token"] == "" {
		t.Fatal("ссылке нужен сгенерированный ID")
	}
	pass := p.Tokens[1]["password"]
	if len(pass) < 10 {
		t.Fatalf("учётке нужен сгенерированный пароль, got %q", pass)
	}
	if p.Tokens[2]["password"] != "Wiki-2026!" {
		t.Fatal("заданный пароль не должен меняться")
	}

	mem.CreateTrap(nil, models.TrapCreate{Name: "FTP", Class: "dialog", Port: 2121, Enabled: true}, "tok-ftp")
	auth := func(user, pw string) string {
		return `{"event_type":"auth","src_ip":"203.0.113.7","src_port":4242,"session":"s1","username":"` + user + `","password":"` + pw + `","ts":1700000000}`
	}
	ingestReq(t, h, "tok-ftp", auth("svc_backup", "wrong"))
	ingestReq(t, h, "tok-ftp", auth("root", pass)) // логин не тот
	if got := eventsOfType(t, h, "token"); len(got) != 0 {
		t.Fatalf("без совпадения учётки события token нет, got %d", len(got))
	}

	ingestReq(t, h, "tok-ftp", auth("svc_backup", pass))
	ingestReq(t, h, "tok-ftp", auth("anyone", "Wiki-2026!")) // без логина — подходит любой
	got := eventsOfType(t, h, "token")
	if len(got) != 2 {
		t.Fatalf("ждали 2 события token, got %d", len(got))
	}
	labels := map[string]bool{}
	for _, e := range got {
		if e.Source != "203.0.113.7" || e.Session != "s1" || e.TrapName != "FTP" {
			t.Fatalf("событие token должно быть в ловушке входа с адресом атакующего: %+v", e)
		}
		var d map[string]any
		json.Unmarshal(e.Data, &d)
		if d["kind"] != "credentials" || d["honeytoken_trap"] != "Приманки" {
			t.Fatalf("data = %v", d)
		}
		labels[d["label"].(string)] = true
	}
	if !labels["git/infra/.env"] || !labels["wiki"] {
		t.Fatalf("labels = %v", labels)
	}
}

func TestHoneyCredentialsFollowTrapChanges(t *testing.T) {
	h, _, mem := setupTestHandlers()
	mem.CreateTrap(nil, models.TrapCreate{Name: "SSH", Class: "banner", Port: 22, Enabled: true}, "tok-ssh")
	login := `{"event_type":"auth","username":"u","password":"Bait-Pass-1","ts":1}`
	ingestReq(t, h, "tok-ssh", login) // кэш учёток заполнен — приманки ещё нет

	w := createTrapReq(t, h, `{"name":"HT","class":"honeytoken","port":8088,"enabled":true,"params":{"tokens":[{"kind":"credentials","label":"l","password":"Bait-Pass-1"}]}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	ingestReq(t, h, "tok-ssh", login)
	if n := len(eventsOfType(t, h, "token")); n != 1 {
		t.Fatalf("новая приманка должна работать сразу, token events = %d", n)
	}
}

func TestSanitizeEventForPostgres(t *testing.T) {
	user := "ro\x00ot"
	ev := sanitizeEvent(models.IngestEvent{
		EventType: strings.Repeat("x", 80),
		Session:   strings.Repeat("я", 100),
		SrcIP:     "1.2.3.4\x00",
		Username:  &user,
		Data:      json.RawMessage(`{"text":"\u0000\u0001abc","k\u0000":["\u0000"],"n":1}`),
	})
	if len([]rune(ev.EventType)) != 50 || len([]rune(ev.Session)) != 64 {
		t.Fatalf("длины не обрезаны: %d %d", len(ev.EventType), len([]rune(ev.Session)))
	}
	for _, s := range []string{ev.SrcIP, *ev.Username, string(ev.Data)} {
		if strings.Contains(s, "\x00") || strings.Contains(s, `\u0000`) {
			t.Fatalf("остался NUL: %q", s)
		}
	}
	var d map[string]any
	if err := json.Unmarshal(ev.Data, &d); err != nil || d["n"].(float64) != 1 {
		t.Fatalf("data испорчена: %s", ev.Data)
	}
	clean := json.RawMessage(`{"a":"b"}`)
	if got := sanitizeEvent(models.IngestEvent{EventType: "data", Data: clean}); !bytes.Equal(got.Data, clean) {
		t.Fatal("чистые данные не трогаем")
	}
}
