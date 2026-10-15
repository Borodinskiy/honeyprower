package plugin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

const goodManifest = `{"name":"my-ftp","title":"Мой FTP","mode":"service","command":["./run.sh"],"default_port":2121,
"requires":["python3"],"params":[{"key":"banner","title":"Баннер","type":"string","default":"220 hi"},
{"key":"level","title":"Уровень","type":"enum","default":"a","options":[{"value":"a","label":"A"},{"value":"b","label":"B"}]},
{"key":"rules","title":"Правила","type":"list","item":[{"key":"match","title":"Если","type":"string","regex":true}]}]}`

type file struct {
	name string
	body string
	mode int64
	kind byte // 0 — обычный файл
	link string
}

func makeTarGz(t *testing.T, files ...file) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		h := &tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.body)), Typeflag: tar.TypeReg, Linkname: f.link}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if f.kind != 0 {
			h.Typeflag = f.kind
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte(f.body))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func makeZip(t *testing.T, files ...file) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate}
		mode := fs.FileMode(f.mode)
		if mode == 0 {
			mode = 0o644
		}
		if f.kind == tar.TypeSymlink {
			mode |= fs.ModeSymlink
			f.body = f.link
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(f.body))
	}
	_ = zw.Close()
	return buf.Bytes()
}

// unpack возвращает имя → (права, тип, содержимое) из готового архива.
func unpack(t *testing.T, archive []byte) map[string]*tar.Header {
	t.Helper()
	out := map[string]*tar.Header{}
	err := Files(archive, func(h *tar.Header, r io.Reader) error {
		out[h.Name] = h
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLoadZipAndTarGiveSameArchive(t *testing.T) {
	files := []file{
		{name: ManifestFile, body: goodManifest},
		{name: "run.sh", body: "#!/bin/sh\nexec python3 server.py\n"}, // без бита исполнения
		{name: "lib/util.py", body: "x = 1\n"},
		{name: "bin/tool", body: "ELF", mode: 0o755},
	}
	fromZip, err := Load(makeZip(t, files...))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	fromTar, err := Load(makeTarGz(t, files...))
	if err != nil {
		t.Fatalf("tar.gz: %v", err)
	}
	if fromZip.SHA256 != fromTar.SHA256 || !bytes.Equal(fromZip.Archive, fromTar.Archive) {
		t.Fatal("одинаковое содержимое должно давать одинаковый архив и хэш")
	}
	again, _ := Load(makeZip(t, files...))
	if again.SHA256 != fromZip.SHA256 {
		t.Fatal("повторная загрузка того же проекта должна давать тот же хэш")
	}
	if fromZip.Files != 4 || fromZip.Manifest.Name != "my-ftp" {
		t.Fatalf("bundle = %+v", fromZip)
	}

	got := unpack(t, fromZip.Archive)
	if got["run.sh"].Mode != 0o755 {
		t.Errorf("файл команды должен стать исполняемым, mode %o", got["run.sh"].Mode)
	}
	if got["bin/tool"].Mode != 0o755 || got["lib/util.py"].Mode != 0o644 {
		t.Errorf("права: tool %o, util.py %o", got["bin/tool"].Mode, got["lib/util.py"].Mode)
	}
	if got["lib/"] == nil || got["lib/"].Mode != 0o755 || got["bin/"] == nil {
		t.Error("каталоги должны быть явными, 0755")
	}
	for name, h := range got {
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" {
			t.Errorf("%s: владелец должен быть пустым (root на хосте)", name)
		}
	}
}

func TestLoadStripsTopFolderAndJunk(t *testing.T) {
	b, err := Load(makeZip(t,
		file{name: "my-ftp/", kind: tar.TypeDir},
		file{name: "my-ftp/" + ManifestFile, body: goodManifest},
		file{name: "my-ftp/run.sh", body: "#!/bin/sh\n"},
		file{name: "__MACOSX/my-ftp/._run.sh", body: "junk"},
		file{name: "my-ftp/.DS_Store", body: "junk"},
	))
	if err != nil {
		t.Fatal(err)
	}
	got := unpack(t, b.Archive)
	if got[ManifestFile] == nil || got["run.sh"] == nil {
		t.Fatalf("папка верхнего уровня должна сниматься: %v", keys(got))
	}
	for name := range got {
		if strings.Contains(name, "MACOSX") || strings.Contains(name, "DS_Store") {
			t.Errorf("мусор macOS попал в архив: %s", name)
		}
	}
}

func keys(m map[string]*tar.Header) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestLoadRejectsDangerousArchives(t *testing.T) {
	m := file{name: ManifestFile, body: goodManifest}
	run := file{name: "run.sh", body: "#!/bin/sh\n"}
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"не архив", []byte("hello world"), "нужен архив"},
		{"пусто", nil, "пустой"},
		{"нет манифеста", makeZip(t, run), "нет " + ManifestFile},
		{"обход каталога zip", makeZip(t, m, run, file{name: "../../etc/cron.d/x", body: "x"}), "выходит за пределы"},
		{"обход каталога tar", makeTarGz(t, m, run, file{name: "a/../../x", body: "x"}), "выходит за пределы"},
		{"абсолютный путь", makeTarGz(t, m, run, file{name: "/etc/passwd", body: "x"}), "абсолютный"},
		{"путь windows", makeZip(t, m, run, file{name: "C:\\x", body: "x"}), "абсолютный"},
		{"ссылка наружу", makeTarGz(t, m, run, file{name: "evil", kind: tar.TypeSymlink, link: "../../etc/shadow"}), "выходит за пределы"},
		{"абсолютная ссылка", makeTarGz(t, m, run, file{name: "evil", kind: tar.TypeSymlink, link: "/etc/shadow"}), "относительные"},
		{"ссылка в zip наружу", makeZip(t, m, run, file{name: "evil", kind: tar.TypeSymlink, link: "../x"}), "выходит за пределы"},
		{"жёсткая ссылка", makeTarGz(t, m, run, file{name: "hard", kind: tar.TypeLink, link: "run.sh"}), "только файлы"},
		{"устройство", makeTarGz(t, m, run, file{name: "dev", kind: tar.TypeChar}), "только файлы"},
		{"дубликат", makeTarGz(t, m, run, file{name: "run.sh", body: "again"}), "дважды"},
		{"файл и каталог", makeTarGz(t, m, run, file{name: "x", body: "1"}, file{name: "x/y", body: "2"}), "одновременно"},
		{"команда не найдена", makeZip(t, m), "нет файла run.sh"},
		{"команда — каталог", makeTarGz(t, m, file{name: "run.sh/", kind: tar.TypeDir}), "не обычный файл"},
		{"битый манифест", makeZip(t, file{name: ManifestFile, body: "{"}, run), ManifestFile},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(c.data)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestLoadLimits(t *testing.T) {
	m := file{name: ManifestFile, body: goodManifest}
	run := file{name: "run.sh", body: "#!/bin/sh\n"}

	// zip-бомба: маленький архив, огромная распаковка
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []file{m, run} {
		w, _ := zw.Create(f.name)
		_, _ = w.Write([]byte(f.body))
	}
	w, _ := zw.Create("bomb.bin")
	zeros := make([]byte, 1<<20)
	for i := 0; i < MaxFileBytes>>20+1; i++ {
		_, _ = w.Write(zeros)
	}
	_ = zw.Close()
	if buf.Len() > MaxArchiveBytes {
		t.Fatalf("тестовая бомба слишком большая: %d", buf.Len())
	}
	if _, err := Load(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "больше") {
		t.Fatalf("бомба: %v", err)
	}

	// много файлов
	files := []file{m, run}
	for i := 0; i < MaxEntries; i++ {
		files = append(files, file{name: "f/" + strings.Repeat("x", 3) + string(rune('a'+i%26)) + "/" + itoa(i), body: ""})
	}
	if _, err := Load(makeTarGz(t, files...)); err == nil || !strings.Contains(err.Error(), "файлов") {
		t.Fatalf("много файлов: %v", err)
	}

	// слишком большой загружаемый файл
	if _, err := Load(make([]byte, MaxArchiveBytes+1)); err == nil || !strings.Contains(err.Error(), "МБ") {
		t.Fatalf("большой архив: %v", err)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestManifestValidation(t *testing.T) {
	base := func() map[string]any {
		var m map[string]any
		_ = json.Unmarshal([]byte(goodManifest), &m)
		m["command"] = []any{"python3", "server.py"}
		return m
	}
	cases := []struct {
		name   string
		change func(m map[string]any)
		want   string
	}{
		{"ок", func(m map[string]any) {}, ""},
		{"имя с заглавными", func(m map[string]any) { m["name"] = "MyFTP" }, "name"},
		{"имя с пробелом", func(m map[string]any) { m["name"] = "my ftp" }, "name"},
		{"имя-путь", func(m map[string]any) { m["name"] = "../x" }, "name"},
		{"неизвестное поле", func(m map[string]any) { m["comand"] = []any{"x"} }, "unknown field"},
		{"режим", func(m map[string]any) { m["mode"] = "daemon" }, "mode"},
		{"stdio по udp", func(m map[string]any) { m["mode"] = "stdio"; m["transport"] = "udp" }, "stdio"},
		{"без команды", func(m map[string]any) { m["command"] = []any{} }, "command"},
		{"команда наружу", func(m map[string]any) { m["command"] = []any{"../../bin/sh"} }, "за пределы"},
		{"порт", func(m map[string]any) { m["default_port"] = 70000 }, "default_port"},
		{"requires с shell", func(m map[string]any) { m["requires"] = []any{"python3; rm -rf /"} }, "requires"},
		{"модуль с shell", func(m map[string]any) { m["python_modules"] = []any{"os; reboot"} }, "python_modules"},
		{"модуль-путь", func(m map[string]any) { m["python_modules"] = []any{"../x"} }, "python_modules"},
		{"pip с shell", func(m map[string]any) { m["pip"] = []any{"paramiko; rm -rf /"} }, "pip"},
		{"pip с опцией", func(m map[string]any) { m["pip"] = []any{"--index-url=http://evil/"} }, "pip"},
		{"pip с URL", func(m map[string]any) { m["pip"] = []any{"x @ https://evil/x.whl"} }, "pip"},
		{"pip ок", func(m map[string]any) { m["pip"] = []any{"paramiko>=3.4,<4", "requests[socks]", "pyyaml==6.0.1"} }, ""},
		{"менеджер пакетов", func(m map[string]any) { m["packages"] = map[string]any{"brew": []any{"x"}} }, "packages"},
		{"пакет с shell", func(m map[string]any) { m["packages"] = map[string]any{"apt": []any{"nmap;reboot"}} }, "packages.apt"},
		{"пакеты ок", func(m map[string]any) {
			m["packages"] = map[string]any{"apt": []any{"python3", "libc6:amd64"}, "dnf": []any{"python3"}, "apk": []any{"python3"}}
		}, ""},
		{"ключ параметра", func(m map[string]any) {
			m["params"] = []any{map[string]any{"key": "a-b", "title": "x", "type": "string"}}
		}, "key"},
		{"тип параметра", func(m map[string]any) { m["params"] = []any{map[string]any{"key": "a", "title": "x", "type": "file"}} }, "type"},
		{"повтор ключа", func(m map[string]any) {
			f := map[string]any{"key": "a", "title": "x", "type": "string"}
			m["params"] = []any{f, f}
		}, "повторяется"},
		{"enum без вариантов", func(m map[string]any) { m["params"] = []any{map[string]any{"key": "a", "title": "x", "type": "enum"}} }, "options"},
		{"default не того типа", func(m map[string]any) {
			m["params"] = []any{map[string]any{"key": "a", "title": "x", "type": "int", "default": "abc"}}
		}, "default"},
		{"список в списке", func(m map[string]any) {
			inner := map[string]any{"key": "b", "title": "y", "type": "list", "item": []any{map[string]any{"key": "c", "title": "z", "type": "string"}}}
			m["params"] = []any{map[string]any{"key": "a", "title": "x", "type": "list", "item": []any{inner}}}
		}, "списки внутри списков"},
		{"default_params не по схеме", func(m map[string]any) { m["default_params"] = map[string]any{"level": "zzz"} }, "default_params"},
		{"showIf на неизвестное поле", func(m map[string]any) {
			m["params"] = []any{map[string]any{"key": "a", "title": "x", "type": "string", "showIf": map[string]any{"key": "nope", "in": []any{"1"}}}}
		}, "showIf"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := base()
			c.change(m)
			raw, _ := json.Marshal(m)
			_, err := ParseManifest(raw)
			if c.want == "" {
				if err != nil {
					t.Fatalf("неожиданная ошибка: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestManifestDefaultsAndClass(t *testing.T) {
	m, err := ParseManifest([]byte(`{"name":"sh","mode":"stdio","command":["./shell.sh"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Title != "sh" || m.Transport != "tcp" {
		t.Fatalf("значения по умолчанию: %+v", m)
	}
	// stdio: агент сам читает idle_timeout и max_clients — они появляются в форме
	keys := map[string]bool{}
	for _, f := range m.Params {
		keys[f.Key] = f.Advanced
	}
	if !keys["idle_timeout"] || !keys["max_clients"] {
		t.Fatalf("stdio должен получить idle_timeout и max_clients: %+v", m.Params)
	}
	c := m.Class("abc")
	if c.ID != "plugin:sh" || c.Level != "Custom" || c.Origin != "plugin" || c.Mode != "stdio" || c.SHA256 != "abc" {
		t.Fatalf("class = %+v", c)
	}
	var defaults map[string]any
	_ = json.Unmarshal(c.DefaultParams, &defaults)
	if defaults["max_clients"] != 50.0 {
		t.Fatalf("defaultParams = %v", defaults)
	}

	svc, err := ParseManifest([]byte(goodManifest))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range svc.Params {
		if f.Key == "max_clients" {
			t.Fatal("service-плагину лишние поля не нужны")
		}
	}
	if n, ok := NameFromClass("plugin:my-ftp"); !ok || n != "my-ftp" {
		t.Fatal("NameFromClass")
	}
	if _, ok := NameFromClass("ssh"); ok {
		t.Fatal("встроенный класс — не плагин")
	}
	if DirName("my-ftp", "0123456789abcdef") != "my-ftp-0123456789ab" {
		t.Fatal("DirName")
	}
}

func TestTemplatesAreValidPlugins(t *testing.T) {
	for _, kind := range TemplateKinds {
		t.Run(kind, func(t *testing.T) {
			name, zipData, err := Template(kind)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Load(zipData)
			if err != nil {
				t.Fatalf("шаблон должен загружаться как есть: %v", err)
			}
			if b.Manifest.Name != name || b.Manifest.Mode != kind {
				t.Fatalf("manifest = %+v", b.Manifest)
			}
		})
	}
	if _, _, err := Template("nope"); err == nil {
		t.Fatal("неизвестный шаблон")
	}
}

func TestManifestPythonModulesRequirePython(t *testing.T) {
	m, err := ParseManifest([]byte(`{"name":"ssh","command":["python3","s.py"],"python_modules":["paramiko","cryptography.hazmat"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.Requires, "python3") || len(m.PythonModules) != 2 {
		t.Fatalf("requires = %v, modules = %v", m.Requires, m.PythonModules)
	}
	m, _ = ParseManifest([]byte(`{"name":"ssh","command":["python3","s.py"],"pip":["paramiko>=3.4"]}`))
	if !slices.Contains(m.Requires, "python3") {
		t.Fatalf("pip тоже требует python3: %v", m.Requires)
	}
	m, _ = ParseManifest([]byte(`{"name":"ssh","command":["python3","s.py"],"requires":["python3"],"python_modules":["paramiko"]}`))
	if len(m.Requires) != 1 {
		t.Fatalf("python3 не дублируется: %v", m.Requires)
	}
}
