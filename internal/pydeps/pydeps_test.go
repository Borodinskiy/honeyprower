package pydeps

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseProbe(t *testing.T) {
	p, err := ParseProbe("3 11 x86_64 glibc 2.36\n")
	if err != nil || p != (Platform{3, 11, "x86_64", "glibc", "2.36"}) {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = ParseProbe("3 12 aarch64 musl 0")
	if err != nil || p.LibcVersion != "1.2" {
		t.Fatalf("musl без версии: %+v %v", p, err)
	}
	for _, bad := range []string{"", "2 7 x86_64 glibc 2.17", "3 11 x86_64 unknown 0", "3 11 x86_64; glibc 2.3", "Traceback..."} {
		if _, err := ParseProbe(bad); err == nil {
			t.Errorf("%q: нужна ошибка", bad)
		}
	}
}

func TestTags(t *testing.T) {
	g := Platform{3, 11, "x86_64", "glibc", "2.36"}.Tags()
	for _, want := range []string{"manylinux_2_36_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64", "manylinux1_x86_64"} {
		if !slices.Contains(g, want) {
			t.Errorf("glibc 2.36: нет %s", want)
		}
	}
	if slices.Contains(g, "manylinux_2_37_x86_64") {
		t.Error("колёса под более новую glibc не подойдут")
	}
	old := Platform{3, 9, "aarch64", "glibc", "2.12"}.Tags()
	if slices.Contains(old, "manylinux2014_aarch64") || !slices.Contains(old, "manylinux2010_aarch64") {
		t.Errorf("glibc 2.12: %v", old)
	}
	m := Platform{3, 12, "x86_64", "musl", "1.2"}.Tags()
	if !slices.Equal(m, []string{"musllinux_1_2_x86_64", "musllinux_1_1_x86_64"}) {
		t.Errorf("musl: %v", m)
	}
}

// wheel собирает zip-колесо из файлов.
func wheel(t *testing.T, dir, name string, files map[string]string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for n, body := range files {
		w, _ := zw.Create(n)
		w.Write([]byte(body))
	}
	zw.Close()
	f.Close()
}

func untar(t *testing.T, data []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			out[h.Name] = string(b)
		}
	}
}

// fakePip «скачивает» колёса в --dest и запоминает аргументы.
func fakePip(t *testing.T, calls *[][]string, wheels map[string]map[string]string) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		*calls = append(*calls, append([]string{name}, args...))
		dest := args[slices.Index(args, "--dest")+1]
		os.MkdirAll(dest, 0o755)
		for n, files := range wheels {
			wheel(t, dest, n, files)
		}
		return nil, nil
	}
}

func TestBuildUnpacksWheelsAndCaches(t *testing.T) {
	var calls [][]string
	b := &Builder{CacheDir: t.TempDir(), Python: "py", Run: fakePip(t, &calls, map[string]map[string]string{
		"demo-1.0-py3-none-any.whl": {
			"demo/__init__.py":                "x = 1\n",
			"demo-1.0.dist-info/METADATA":     "Name: demo\n",
			"demo-1.0.data/purelib/extra.py":  "y = 2\n",
			"demo-1.0.data/scripts/demo":      "#!/bin/sh\n",
			"demo-1.0.data/platlib/_speed.so": "ELF",
		},
		"dep-2.0-cp311-cp311-manylinux_2_17_x86_64.whl": {"dep/core.py": "z = 3\n"},
	})}
	p := Platform{3, 11, "x86_64", "glibc", "2.36"}
	data, err := b.Build(context.Background(), []string{"demo", "dep>=2"}, p)
	if err != nil {
		t.Fatal(err)
	}
	files := untar(t, data)
	for _, want := range []string{"demo/__init__.py", "demo-1.0.dist-info/METADATA", "extra.py", "_speed.so", "dep/core.py"} {
		if _, ok := files[want]; !ok {
			t.Errorf("нет %s в %v", want, files)
		}
	}
	if _, ok := files["demo"]; ok {
		t.Error("scripts из .data не нужны")
	}

	args := strings.Join(calls[0], " ")
	for _, want := range []string{"py -m pip download", "--only-binary=:all:", "--python-version 3.11", "--implementation cp",
		"--platform manylinux_2_36_x86_64", "-- demo dep>=2"} {
		if !strings.Contains(args, want) {
			t.Errorf("pip без %q: %s", want, args)
		}
	}

	again, err := b.Build(context.Background(), []string{"dep>=2", "demo"}, p)
	if err != nil || !bytes.Equal(again, data) || len(calls) != 1 {
		t.Fatalf("та же платформа и те же зависимости — из кэша: calls=%d err=%v", len(calls), err)
	}
	if _, err := b.Build(context.Background(), []string{"demo"}, Platform{3, 12, "x86_64", "glibc", "2.36"}); err != nil || len(calls) != 2 {
		t.Fatal("другая версия Python — новая загрузка")
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	mk := func() []byte {
		var calls [][]string
		b := &Builder{Run: fakePip(t, &calls, map[string]map[string]string{"a-1-py3-none-any.whl": {"a/x.py": "1", "a/y.py": "2"}})}
		data, err := b.Build(context.Background(), []string{"a"}, Platform{3, 11, "x86_64", "glibc", "2.36"})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if !bytes.Equal(mk(), mk()) {
		t.Fatal("одинаковые колёса — одинаковый архив")
	}
}

func TestBuildErrors(t *testing.T) {
	b := &Builder{Run: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Looking in indexes...\nERROR: No matching distribution found for nosuchpkg\n"), errors.New("exit status 1")
	}}
	_, err := b.Build(context.Background(), []string{"nosuchpkg"}, Platform{3, 11, "x86_64", "glibc", "2.36"})
	if err == nil || !strings.Contains(err.Error(), "No matching distribution found for nosuchpkg") {
		t.Fatalf("ошибка pip должна дойти до оператора: %v", err)
	}

	var calls [][]string
	b = &Builder{Run: fakePip(t, &calls, map[string]map[string]string{"evil-1-py3-none-any.whl": {"../../etc/x": "pwn"}})}
	if _, err := b.Build(context.Background(), []string{"evil"}, Platform{3, 11, "x86_64", "glibc", "2.36"}); err == nil {
		t.Fatal("путь из колеса наружу — ошибка")
	}
	if _, err := (&Builder{}).Build(context.Background(), []string{"x"}, Platform{3, 11, "x86_64", "glibc", "3.0"}); err == nil {
		t.Fatal("неизвестная libc — ошибка")
	}
}
