package handlers

import (
	"context"
	"log"
	"path"
	"sort"

	"honeyprower/internal/catalog"
	"honeyprower/internal/models"
	"honeyprower/internal/plugin"
)

// pluginDirRemote — где лежат плагины на хосте после деплоя по SSH.
const pluginDirRemote = "/opt/honeyforge/plugins"

// classSet — классы ловушек, известные центру: встроенные и загруженные плагины.
type classSet struct {
	builtin []catalog.Class
	byID    map[string]catalog.Class
	plugins map[string]*loadedPlugin // по id класса ("plugin:<name>")
}

type loadedPlugin struct {
	rec      models.Plugin
	manifest *plugin.Manifest
}

// loadClasses собирает классы. Плагин с испорченным манифестом пропускается:
// из-за него не должна ломаться работа с остальными ловушками.
func (h *Handlers) loadClasses(ctx context.Context) (*classSet, error) {
	recs, err := h.Store.ListPlugins(ctx)
	if err != nil {
		return nil, err
	}
	cs := &classSet{builtin: catalog.Classes(), byID: map[string]catalog.Class{}, plugins: map[string]*loadedPlugin{}}
	for _, c := range cs.builtin {
		cs.byID[c.ID] = c
	}
	for _, rec := range recs {
		m, err := plugin.ParseManifest(rec.Manifest)
		if err != nil {
			log.Printf("plugin %s: stored manifest is invalid: %v", rec.Name, err)
			continue
		}
		c := m.Class(rec.SHA256)
		cs.byID[c.ID] = c
		cs.plugins[c.ID] = &loadedPlugin{rec: rec, manifest: m}
	}
	return cs, nil
}

func (cs *classSet) class(id string) (catalog.Class, bool) {
	c, ok := cs.byID[id]
	return c, ok
}

func (cs *classSet) plugin(classID string) *loadedPlugin {
	return cs.plugins[classID]
}

// list — для формы: сначала встроенные в их порядке, затем плагины по имени.
func (cs *classSet) list() []catalog.Class {
	out := append([]catalog.Class(nil), cs.builtin...)
	var custom []catalog.Class
	for id := range cs.plugins {
		custom = append(custom, cs.byID[id])
	}
	sort.Slice(custom, func(i, j int) bool { return custom[i].ID < custom[j].ID })
	return append(out, custom...)
}

// pluginSHA — версия плагина ловушки (пусто для встроенных классов): входит в
// отпечаток развёрнутого, чтобы новая загрузка плагина помечала хосты к обновлению.
func (cs *classSet) pluginSHA(classID string) string {
	if p := cs.plugins[classID]; p != nil {
		return p.rec.SHA256
	}
	return ""
}

// pluginDir — каталог плагина у агента: на хосте после деплоя — абсолютный,
// для ручного запуска — рядом с конфигом.
func pluginDir(p *loadedPlugin, remote bool) string {
	dir := plugin.DirName(p.rec.Name, p.rec.SHA256)
	if remote {
		return path.Join(pluginDirRemote, dir)
	}
	return path.Join("plugins", dir)
}
