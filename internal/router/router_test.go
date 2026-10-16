package router

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Развёртывание с установкой зависимостей идёт дольше WriteTimeout сервера:
// ответ всё равно должен дойти до оператора.
func TestSlowOutlivesWriteTimeout(t *testing.T) {
	work := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("deployed"))
	}
	for _, c := range []struct {
		h    http.Handler
		want bool
	}{{slow(work), true}, {http.HandlerFunc(work), false}} {
		srv := httptest.NewUnstartedServer(c.h)
		srv.Config.WriteTimeout = 100 * time.Millisecond
		srv.Start()
		resp, err := http.Get(srv.URL)
		got := false
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			got = string(body) == "deployed"
		}
		srv.Close()
		if got != c.want {
			t.Fatalf("ответ дошёл = %v, ждали %v (err %v)", got, c.want, err)
		}
	}
}
