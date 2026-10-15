package plugin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// Ограничения архива: проект едет на каждый хост по SSH и лежит в базе.
const (
	MaxArchiveBytes  = 32 << 20  // загружаемый файл
	MaxUnpackedBytes = 128 << 20 // всё содержимое после распаковки
	MaxFileBytes     = 64 << 20  // один файл
	MaxEntries       = 5000
	maxManifestBytes = 256 << 10
	maxPathLen       = 255
	maxDepth         = 32
)

// fixedTime — у всех файлов одна дата: одинаковый проект даёт одинаковый архив и хэш,
// и повторная загрузка того же не требует передеплоя.
var fixedTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// Bundle — проверенный плагин: манифест и пересобранный архив (tar.gz), который
// уедет на хосты, с его SHA-256.
type Bundle struct {
	Manifest *Manifest
	Archive  []byte
	SHA256   string
	Files    int
	Unpacked int64
}

type entry struct {
	name   string
	mode   fs.FileMode // только биты прав; тип — в kind
	kind   byte        // tar.TypeReg | tar.TypeDir | tar.TypeSymlink
	link   string
	data   []byte
	hasExe bool
}

// Load разбирает загруженный архив (zip, tar.gz или tar), проверяет его и
// манифест и собирает из него чистый tar.gz.
func Load(data []byte) (*Bundle, error) {
	if len(data) == 0 {
		return nil, errors.New("пустой файл")
	}
	if len(data) > MaxArchiveBytes {
		return nil, fmt.Errorf("архив больше %d МБ", MaxArchiveBytes>>20)
	}
	var (
		entries []entry
		err     error
	)
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")) || bytes.HasPrefix(data, []byte("PK\x05\x06")):
		entries, err = readZip(data)
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		var gz *gzip.Reader
		gz, err = gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			entries, err = readTar(gz)
		}
	case len(data) > 262 && string(data[257:262]) == "ustar":
		entries, err = readTar(bytes.NewReader(data))
	default:
		return nil, errors.New("нужен архив .zip или .tar.gz")
	}
	if err != nil {
		return nil, err
	}
	entries = stripTopDir(entries)

	var manifestData []byte
	for _, e := range entries {
		if e.name == ManifestFile && e.kind == tar.TypeReg {
			manifestData = e.data
		}
	}
	if manifestData == nil {
		return nil, fmt.Errorf("в корне архива нет %s", ManifestFile)
	}
	if len(manifestData) > maxManifestBytes {
		return nil, fmt.Errorf("%s слишком большой", ManifestFile)
	}
	m, err := ParseManifest(manifestData)
	if err != nil {
		return nil, err
	}
	if err := checkLinks(entries); err != nil {
		return nil, err
	}
	if file, _ := m.CommandFile(); file != "" {
		found := false
		for i := range entries {
			if entries[i].name == file {
				if entries[i].kind != tar.TypeReg {
					return nil, fmt.Errorf("command: %s — не обычный файл", file)
				}
				entries[i].hasExe = true // запускаемый файл должен быть исполняемым на хосте
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("command: в архиве нет файла %s", file)
		}
	}

	archive, unpacked, err := writeTarGz(entries)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(archive)
	files := 0
	for _, e := range entries {
		if e.kind != tar.TypeDir {
			files++
		}
	}
	return &Bundle{Manifest: m, Archive: archive, SHA256: hex.EncodeToString(sum[:]), Files: files, Unpacked: unpacked}, nil
}

// cleanName приводит путь из архива к виду "a/b/c" или возвращает ошибку,
// если он абсолютный, выходит наружу или странный. Пустая строка — пропустить.
func cleanName(raw string) (string, error) {
	n := strings.ReplaceAll(raw, "\\", "/")
	if strings.ContainsRune(n, 0) {
		return "", fmt.Errorf("недопустимое имя файла %q", raw)
	}
	if strings.HasPrefix(n, "/") || (len(n) > 1 && n[1] == ':') {
		return "", fmt.Errorf("абсолютный путь в архиве: %q", raw)
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return "", fmt.Errorf("путь выходит за пределы архива: %q", raw)
		}
	}
	n = path.Clean(n)
	if n == "." || n == "" {
		return "", nil
	}
	if len(n) > maxPathLen || strings.Count(n, "/") >= maxDepth {
		return "", fmt.Errorf("слишком длинный путь: %q", raw)
	}
	// Мусор архиваторов macOS.
	if n == "__MACOSX" || strings.HasPrefix(n, "__MACOSX/") || path.Base(n) == ".DS_Store" {
		return "", nil
	}
	return n, nil
}

type collector struct {
	entries []entry
	seen    map[string]bool
	total   int64
}

func (c *collector) add(e entry) error {
	if len(c.entries) >= MaxEntries {
		return fmt.Errorf("в архиве больше %d файлов", MaxEntries)
	}
	if c.seen[e.name] {
		if e.kind == tar.TypeDir {
			return nil
		}
		return fmt.Errorf("файл %s встречается в архиве дважды", e.name)
	}
	c.seen[e.name] = true
	c.entries = append(c.entries, e)
	return nil
}

// readLimited читает файл архива, следя за общим лимитом распаковки (защита от zip-бомб).
func (c *collector) readLimited(name string, r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s: %v", name, err)
	}
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("файл %s больше %d МБ", name, MaxFileBytes>>20)
	}
	c.total += int64(len(data))
	if c.total > MaxUnpackedBytes {
		return nil, fmt.Errorf("после распаковки больше %d МБ", MaxUnpackedBytes>>20)
	}
	return data, nil
}

func readZip(data []byte) ([]entry, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("битый zip: %v", err)
	}
	c := &collector{seen: map[string]bool{}}
	for _, f := range zr.File {
		name, err := cleanName(f.Name)
		if err != nil {
			return nil, err
		}
		if name == "" {
			continue
		}
		mode := f.Mode()
		switch {
		case mode.IsDir():
			err = c.add(entry{name: name, kind: tar.TypeDir})
		case mode&fs.ModeSymlink != 0:
			rc, oerr := f.Open()
			if oerr != nil {
				return nil, fmt.Errorf("битый zip: %v", oerr)
			}
			target, rerr := c.readLimited(name, io.LimitReader(rc, 4096))
			rc.Close()
			if rerr != nil {
				return nil, rerr
			}
			err = c.add(entry{name: name, kind: tar.TypeSymlink, link: string(target)})
		case mode.IsRegular():
			if f.UncompressedSize64 > MaxFileBytes {
				return nil, fmt.Errorf("файл %s больше %d МБ", name, MaxFileBytes>>20)
			}
			rc, oerr := f.Open()
			if oerr != nil {
				return nil, fmt.Errorf("битый zip: %v", oerr)
			}
			body, rerr := c.readLimited(name, rc)
			rc.Close()
			if rerr != nil {
				return nil, rerr
			}
			err = c.add(entry{name: name, kind: tar.TypeReg, data: body, hasExe: mode&0o111 != 0})
		default:
			return nil, fmt.Errorf("%s: в архиве допустимы только файлы, каталоги и ссылки", name)
		}
		if err != nil {
			return nil, err
		}
	}
	return c.entries, nil
}

func readTar(r io.Reader) ([]entry, error) {
	tr := tar.NewReader(r)
	c := &collector{seen: map[string]bool{}}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("битый архив: %v", err)
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name, err := cleanName(h.Name)
		if err != nil {
			return nil, err
		}
		if name == "" {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			err = c.add(entry{name: name, kind: tar.TypeDir})
		case tar.TypeSymlink:
			err = c.add(entry{name: name, kind: tar.TypeSymlink, link: h.Linkname})
		case tar.TypeReg, tar.TypeRegA:
			if h.Size > MaxFileBytes {
				return nil, fmt.Errorf("файл %s больше %d МБ", name, MaxFileBytes>>20)
			}
			body, rerr := c.readLimited(name, tr)
			if rerr != nil {
				return nil, rerr
			}
			err = c.add(entry{name: name, kind: tar.TypeReg, data: body, hasExe: h.Mode&0o111 != 0})
		default:
			return nil, fmt.Errorf("%s: в архиве допустимы только файлы, каталоги и ссылки", name)
		}
		if err != nil {
			return nil, err
		}
	}
	return c.entries, nil
}

// stripTopDir: архив папки ("my-trap/honeyforge-plugin.json") раскладывается от её корня.
func stripTopDir(entries []entry) []entry {
	for _, e := range entries {
		if e.name == ManifestFile {
			return entries
		}
	}
	top := ""
	for _, e := range entries {
		first, _, _ := strings.Cut(e.name, "/")
		if top == "" {
			top = first
		} else if first != top {
			return entries
		}
	}
	if top == "" {
		return entries
	}
	out := make([]entry, 0, len(entries))
	for _, e := range entries {
		rest := strings.TrimPrefix(e.name, top+"/")
		if rest == e.name { // сам каталог верхнего уровня
			continue
		}
		e.name = rest
		out = append(out, e)
	}
	return out
}

// checkLinks: ссылки только относительные и только внутрь проекта (venv, node_modules/.bin).
func checkLinks(entries []entry) error {
	for _, e := range entries {
		if e.kind != tar.TypeSymlink {
			continue
		}
		if e.link == "" || strings.HasPrefix(e.link, "/") || strings.ContainsRune(e.link, 0) {
			return fmt.Errorf("ссылка %s → %q: допустимы только относительные ссылки внутри проекта", e.name, e.link)
		}
		target := path.Clean(path.Join(path.Dir(e.name), e.link))
		if target == ".." || strings.HasPrefix(target, "../") {
			return fmt.Errorf("ссылка %s → %q выходит за пределы проекта", e.name, e.link)
		}
	}
	return nil
}

func writeTarGz(entries []entry) ([]byte, int64, error) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	// Явные каталоги для всех родителей: права 0755 не зависят от umask хоста.
	dirs := map[string]bool{}
	for _, e := range entries {
		if e.kind == tar.TypeDir {
			dirs[e.name] = true
		}
		for d := path.Dir(e.name); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	for _, e := range entries {
		if e.kind != tar.TypeDir && dirs[e.name] {
			return nil, 0, fmt.Errorf("%s — одновременно файл и каталог", e.name)
		}
	}
	all := make([]entry, 0, len(entries)+len(dirs))
	for d := range dirs {
		all = append(all, entry{name: d, kind: tar.TypeDir})
	}
	for _, e := range entries {
		if e.kind != tar.TypeDir {
			all = append(all, e)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })

	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	tw := tar.NewWriter(gz)
	var total int64
	for _, e := range all {
		h := &tar.Header{Name: e.name, ModTime: fixedTime, Typeflag: e.kind, Format: tar.FormatPAX}
		switch e.kind {
		case tar.TypeDir:
			h.Name += "/"
			h.Mode = 0o755
		case tar.TypeSymlink:
			h.Mode = 0o777
			h.Linkname = e.link
		default:
			h.Mode = 0o644
			if e.hasExe {
				h.Mode = 0o755
			}
			h.Size = int64(len(e.data))
			total += h.Size
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, 0, err
		}
		if e.kind == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
				return nil, 0, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	if err := gz.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), total, nil
}

// Files перечисляет файлы готового архива (для zip-пакета ловушки без хоста).
func Files(archive []byte, fn func(h *tar.Header, r io.Reader) error) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(h, tr); err != nil {
			return err
		}
	}
}

// DirName — каталог плагина на хосте: имя и начало хэша (новая версия — новый каталог,
// старый остаётся до успешного запуска, на него можно откатиться).
func DirName(name, sha string) string {
	if len(sha) > 12 {
		sha = sha[:12]
	}
	return name + "-" + sha
}
