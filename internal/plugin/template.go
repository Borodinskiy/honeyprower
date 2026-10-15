package plugin

import (
	"archive/zip"
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// Шаблоны своих ловушек: скачиваются со страницы «Свои ловушки» как стартовый проект.
//
//go:embed templates
var templateFS embed.FS

// TemplateKinds — доступные шаблоны (по режиму работы).
var TemplateKinds = []string{"service", "stdio"}

// Template собирает zip шаблона: папка с именем плагина, внутри — манифест и код.
func Template(kind string) (name string, data []byte, err error) {
	root := path.Join("templates", kind)
	manifest, err := templateFS.ReadFile(path.Join(root, ManifestFile))
	if err != nil {
		return "", nil, fmt.Errorf("нет шаблона %q", kind)
	}
	m, err := ParseManifest(manifest)
	if err != nil {
		return "", nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err = fs.WalkDir(templateFS, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := templateFS.ReadFile(p)
		if err != nil {
			return err
		}
		h := &zip.FileHeader{Name: m.Name + "/" + strings.TrimPrefix(p, root+"/"), Method: zip.Deflate, Modified: fixedTime}
		mode := fs.FileMode(0o644)
		if strings.HasSuffix(p, ".sh") {
			mode = 0o755
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = w.Write(body)
		return err
	})
	if err != nil {
		return "", nil, err
	}
	if err := zw.Close(); err != nil {
		return "", nil, err
	}
	return m.Name, buf.Bytes(), nil
}
