// Package pydeps собирает Python-зависимости своих ловушек под платформу хоста.
//
// Центр скачивает колёса (wheels) из PyPI через pip под версию Python,
// архитектуру и libc конкретного сервера, распаковывает их в каталог и
// отдаёт его tar.gz-архивом. На хосте архив просто распаковывается в каталог
// ловушки и попадает в PYTHONPATH — серверу не нужны ни pip, ни доступ в
// интернет, а общий Python сервера не меняется. Сборка под одну платформу
// кэшируется и переиспользуется для всех таких серверов.
package pydeps

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProbeCmd печатает платформу хоста одной строкой: "3 12 x86_64 glibc 2.39".
// Выполняется на хосте по SSH; musl определяется по загрузчику, т.к.
// platform.libc_ver() на musl пуст.
const ProbeCmd = `python3 -c 'import sys,platform,glob; l=platform.libc_ver(); m=glob.glob("/lib/ld-musl-*"); ` +
	`print(sys.version_info[0], sys.version_info[1], platform.machine(), ` +
	`"musl" if m and not l[0] else (l[0] or "unknown"), l[1] or "0")'`

// Platform — то, от чего зависит выбор колёс.
type Platform struct {
	PyMajor, PyMinor int
	Machine          string // x86_64, aarch64
	Libc             string // glibc | musl
	LibcVersion      string // 2.39 (glibc) | 1.2 (musl)
}

func (p Platform) String() string {
	return fmt.Sprintf("cp%d%d-%s-%s%s", p.PyMajor, p.PyMinor, p.Machine, p.Libc, p.LibcVersion)
}

// ParseProbe разбирает вывод ProbeCmd.
func ParseProbe(out string) (Platform, error) {
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) != 5 {
		return Platform{}, fmt.Errorf("unexpected platform probe output %q", strings.TrimSpace(out))
	}
	major, err1 := strconv.Atoi(f[0])
	minor, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || major != 3 {
		return Platform{}, fmt.Errorf("unsupported python %s.%s", f[0], f[1])
	}
	p := Platform{PyMajor: major, PyMinor: minor, Machine: f[2], Libc: f[3], LibcVersion: f[4]}
	if p.Libc == "musl" && p.LibcVersion == "0" {
		p.LibcVersion = "1.2" // musl 1.2 — все актуальные Alpine
	}
	if p.Libc != "glibc" && p.Libc != "musl" {
		return Platform{}, fmt.Errorf("unsupported libc %q", p.Libc)
	}
	if !machineRe.MatchString(p.Machine) {
		return Platform{}, fmt.Errorf("unsupported machine %q", p.Machine)
	}
	return p, nil
}

var machineRe = regexp.MustCompile(`^(x86_64|aarch64|i686|armv7l|ppc64le|s390x)$`)

// Tags — платформенные теги колёс, которые подходят хосту, от новых к старым.
// Колёса без платформы (py3-none-any) pip берёт и так.
func (p Platform) Tags() []string {
	maj, min := 0, 0
	if parts := strings.SplitN(p.LibcVersion, ".", 2); len(parts) == 2 {
		maj, _ = strconv.Atoi(parts[0])
		min, _ = strconv.Atoi(parts[1])
	}
	var tags []string
	switch p.Libc {
	case "glibc":
		if maj != 2 {
			return nil
		}
		for v := min; v >= 5; v-- {
			tags = append(tags, fmt.Sprintf("manylinux_2_%d_%s", v, p.Machine))
		}
		// Старые имена тех же тегов: manylinux2014 = 2.17, 2010 = 2.12, 1 = 2.5.
		for _, legacy := range []struct {
			name string
			min  int
		}{{"manylinux2014", 17}, {"manylinux2010", 12}, {"manylinux1", 5}} {
			if min >= legacy.min {
				tags = append(tags, legacy.name+"_"+p.Machine)
			}
		}
	case "musl":
		for v := min; v >= 1; v-- {
			tags = append(tags, fmt.Sprintf("musllinux_%d_%d_%s", maj, v, p.Machine))
		}
	}
	return tags
}

// Builder скачивает и кэширует зависимости.
type Builder struct {
	// Python — интерпретатор центра с pip (по умолчанию python3).
	Python string
	// CacheDir — где хранить готовые архивы; пусто — без кэша.
	CacheDir string
	// Run запускает pip; подменяется в тестах.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// MaxArchive — больше этого архив зависимостей не везём на хосты.
const MaxArchive = 200 << 20

// Build возвращает tar.gz с распакованными колёсами reqs под платформу p.
func (b *Builder) Build(ctx context.Context, reqs []string, p Platform) ([]byte, error) {
	if len(reqs) == 0 {
		return nil, errors.New("no requirements")
	}
	tags := p.Tags()
	if len(tags) == 0 {
		return nil, fmt.Errorf("no wheel tags for %s", p)
	}
	key := cacheKey(reqs, p)
	lock := b.lock(key)
	lock.Lock()
	defer lock.Unlock()

	cached := ""
	if b.CacheDir != "" {
		cached = filepath.Join(b.CacheDir, key+".tar.gz")
		if data, err := os.ReadFile(cached); err == nil {
			return data, nil
		}
	}

	work, err := os.MkdirTemp("", "hf-pydeps-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	wheels := filepath.Join(work, "wheels")

	args := []string{"-m", "pip", "download", "--disable-pip-version-check", "--no-input", "--quiet",
		"--only-binary=:all:", "--dest", wheels,
		"--implementation", "cp", "--python-version", fmt.Sprintf("%d.%d", p.PyMajor, p.PyMinor)}
	for _, t := range tags {
		args = append(args, "--platform", t)
	}
	args = append(args, "--")
	args = append(args, reqs...)
	run := b.Run
	if run == nil {
		run = runCmd
	}
	python := b.Python
	if python == "" {
		python = "python3"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if out, err := run(ctx, python, args...); err != nil {
		return nil, fmt.Errorf("pip download for %s failed: %w: %s", p, err, lastLines(string(out), 6))
	}

	data, err := packWheels(wheels)
	if err != nil {
		return nil, err
	}
	if cached != "" {
		if err := os.MkdirAll(b.CacheDir, 0o750); err == nil {
			tmp := cached + ".tmp"
			if os.WriteFile(tmp, data, 0o640) == nil {
				_ = os.Rename(tmp, cached)
			}
		}
	}
	return data, nil
}

func (b *Builder) lock(key string) *sync.Mutex {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.locks == nil {
		b.locks = map[string]*sync.Mutex{}
	}
	if b.locks[key] == nil {
		b.locks[key] = &sync.Mutex{}
	}
	return b.locks[key]
}

func cacheKey(reqs []string, p Platform) string {
	sorted := append([]string(nil), reqs...)
	sort.Strings(sorted)
	raw, _ := json.Marshal(struct {
		R []string
		P Platform
		V int
	}{sorted, p, 1})
	sum := sha256.Sum256(raw)
	return p.String() + "-" + hex.EncodeToString(sum[:8])
}

func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "PIP_NO_INPUT=1", "PIP_DISABLE_PIP_VERSION_CHECK=1")
	return cmd.CombinedOutput()
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// packWheels распаковывает колёса (это zip) в один каталог, как pip install
// --target, и упаковывает его в детерминированный tar.gz.
func packWheels(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("pip downloaded nothing: %w", err)
	}
	files := map[string][]byte{}
	var total int64
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".whl") {
			continue // sdist сюда не попадает из-за --only-binary
		}
		zr, err := zip.OpenReader(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		for _, f := range zr.File {
			name := path.Clean(f.Name)
			if f.FileInfo().IsDir() {
				continue
			}
			if strings.HasPrefix(name, "../") || name == ".." || path.IsAbs(name) {
				zr.Close()
				return nil, fmt.Errorf("%s: unsafe path %q", e.Name(), f.Name)
			}
			// *.data/purelib|platlib — содержимое кладётся в корень, scripts и прочее не нужны.
			if i := strings.Index(name, ".data/"); i > 0 && !strings.Contains(name[:i], "/") {
				rest := name[i+len(".data/"):]
				sub, tail, _ := strings.Cut(rest, "/")
				if (sub != "purelib" && sub != "platlib") || tail == "" {
					continue
				}
				name = tail
			}
			total += int64(f.UncompressedSize64)
			if total > MaxArchive {
				zr.Close()
				return nil, fmt.Errorf("python dependencies are larger than %d MB", MaxArchive>>20)
			}
			rc, err := f.Open()
			if err != nil {
				zr.Close()
				return nil, err
			}
			data, err := io.ReadAll(io.LimitReader(rc, MaxArchive))
			rc.Close()
			if err != nil {
				zr.Close()
				return nil, err
			}
			files[name] = data
		}
		zr.Close()
	}
	if len(files) == 0 {
		return nil, errors.New("pip downloaded no wheels")
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	tw := tar.NewWriter(gz)
	dirs := map[string]bool{}
	for _, n := range names {
		for d := path.Dir(n); d != "." && !dirs[d]; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	dirList := make([]string, 0, len(dirs))
	for d := range dirs {
		dirList = append(dirList, d)
	}
	sort.Strings(dirList)
	epoch := time.Unix(1577836800, 0)
	for _, d := range dirList {
		if err := tw.WriteHeader(&tar.Header{Name: d + "/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: epoch}); err != nil {
			return nil, err
		}
	}
	for _, n := range names {
		mode := int64(0o644)
		if strings.HasSuffix(n, ".so") || strings.Contains(n, ".so.") {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(files[n])), ModTime: epoch}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(files[n]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
