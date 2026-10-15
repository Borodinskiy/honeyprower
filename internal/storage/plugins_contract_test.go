package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"honeyprower/internal/models"
)

// testPluginsContract: плагины одинаково хранятся в памяти и в Postgres.
func testPluginsContract(t *testing.T, s Storage) {
	ctx := context.Background()
	if list, err := s.ListPlugins(ctx); err != nil || len(list) != 0 {
		t.Fatalf("empty list = %v, %v", list, err)
	}
	if _, err := s.GetPlugin(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPlugin missing: %v", err)
	}
	if _, err := s.GetPluginArchive(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPluginArchive missing: %v", err)
	}
	if err := s.DeletePlugin(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeletePlugin missing: %v", err)
	}

	// бинарный архив с нулевыми байтами должен храниться без искажений
	archive := []byte{0x1f, 0x8b, 0, 1, 2, 0xff, 0}
	manifest := json.RawMessage(`{"name":"b-plugin","title":"Б","command":["./run"],"params":[{"key":"z","title":"Z","type":"string"},{"key":"a","title":"A","type":"int"}]}`)
	p, err := s.SavePlugin(ctx, models.Plugin{Name: "b-plugin", Manifest: manifest, SHA256: "sha-1"}, archive)
	if err != nil {
		t.Fatalf("SavePlugin: %v", err)
	}
	if p.Size != int64(len(archive)) || p.UploadedAt.IsZero() || p.SHA256 != "sha-1" {
		t.Fatalf("saved = %+v", p)
	}
	if _, err := s.SavePlugin(ctx, models.Plugin{Name: "a-plugin", Manifest: json.RawMessage(`{"name":"a-plugin"}`), SHA256: "sha-a"}, []byte("a")); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetPlugin(ctx, "b-plugin")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Params []struct{ Key string } `json:"params"`
	}
	if err := json.Unmarshal(got.Manifest, &m); err != nil || len(m.Params) != 2 || m.Params[0].Key != "z" {
		t.Fatalf("порядок полей формы должен сохраняться: %s", got.Manifest)
	}
	if a, _ := s.GetPluginArchive(ctx, "b-plugin"); !bytes.Equal(a, archive) {
		t.Fatalf("archive = %v", a)
	}
	list, _ := s.ListPlugins(ctx)
	if len(list) != 2 || list[0].Name != "a-plugin" || list[1].Name != "b-plugin" {
		t.Fatalf("list = %+v", list)
	}

	// повторная загрузка заменяет
	newArchive := []byte("v2")
	if _, err := s.SavePlugin(ctx, models.Plugin{Name: "b-plugin", Manifest: manifest, SHA256: "sha-2"}, newArchive); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetPlugin(ctx, "b-plugin")
	if got.SHA256 != "sha-2" || got.Size != 2 {
		t.Fatalf("replace: %+v", got)
	}
	if a, _ := s.GetPluginArchive(ctx, "b-plugin"); !bytes.Equal(a, newArchive) {
		t.Fatal("архив не заменён")
	}
	if list, _ := s.ListPlugins(ctx); len(list) != 2 {
		t.Fatal("замена не должна добавлять запись")
	}

	if err := s.DeletePlugin(ctx, "b-plugin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPlugin(ctx, "b-plugin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("удалён")
	}
}

func TestMemoryPluginsContract(t *testing.T) {
	testPluginsContract(t, NewInMemory())
}

func TestPostgresPluginsContract(t *testing.T) {
	p, _ := newTestPostgres(t)
	testPluginsContract(t, p)
}
