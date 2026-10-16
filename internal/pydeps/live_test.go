package pydeps

import (
	"context"
	"os"
	"testing"
)

// Реальная загрузка из PyPI: HF_PYDEPS_LIVE=1 go test ./internal/pydeps -run Live
func TestLiveDownload(t *testing.T) {
	if os.Getenv("HF_PYDEPS_LIVE") == "" {
		t.Skip("HF_PYDEPS_LIVE не задан")
	}
	b := &Builder{}
	for _, p := range []Platform{{3, 11, "x86_64", "glibc", "2.36"}, {3, 9, "aarch64", "glibc", "2.31"}, {3, 12, "x86_64", "musl", "1.2"}} {
		data, err := b.Build(context.Background(), []string{"paramiko>=3.4"}, p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		t.Logf("%s: %d bytes", p, len(data))
		if out := os.Getenv("HF_PYDEPS_OUT"); out != "" {
			os.WriteFile(out+"/"+p.String()+".tar.gz", data, 0o644)
		}
	}
}
