package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"honeyprower/internal/auth"
	"honeyprower/internal/config"
	"honeyprower/internal/handlers"
	"honeyprower/internal/middleware"
	"honeyprower/internal/router"
	"honeyprower/internal/storage"
)

func main() {
	cfg := config.Load()

	// ---------- Database ----------
	var store storage.Storage
	var closeStore func() error
	pgStore, err := storage.NewPostgres(context.Background(), cfg.DBDSN)
	if err != nil {
		log.Printf("failed to initialize postgres storage (%v), falling back to in-memory store", err)
		memStore := storage.NewInMemory()
		storage.Seed(memStore)
		store = memStore
	} else {
		store = pgStore
		closeStore = pgStore.Close
	}

	authMgr := auth.NewManager()
	h := handlers.New(store, authMgr)
	h.AllowRegistration = cfg.AllowRegistration
	h.PublicURL = cfg.PublicURL
	if !cfg.AllowRegistration {
		log.Println("self-registration is disabled (ALLOW_REGISTRATION=false)")
	}

	// ---------- API server ----------
	apiSrv := &http.Server{
		Addr:         cfg.APIAddr,
		Handler:      router.NewAPI(h, authMgr),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// ---------- Web server ----------
	apiURL, _ := url.Parse("http://" + cfg.APIAddr)
	proxy := httputil.NewSingleHostReverseProxy(apiURL)

	webMux := NewWebMux(cfg, authMgr, proxy)

	webSrv := &http.Server{
		Addr:         cfg.WebAddr,
		Handler:      webMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// ---------- run ----------
	// Отслеживание цепочки ошибок в проверках ниже
	errCh := make(chan error, 2)

	// Ошибки запуска серверов попадают в errCh.
	// http.ErrServerClosed значит, что сервер был выключен вручную, по сути не ошибка запуска, поэтому скип
	go func() {
		log.Printf("web server  → http://%s   (static dir: %s)", cfg.WebAddr, cfg.StaticDir)
		if err := webSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		log.Printf("api server  → http://%s", cfg.APIAddr)
		if err := apiSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// ---------- graceful shutdown ----------
	stop := make(chan os.Signal, 1)
	// Отслеживание сигнала остановки сервера в виде Ctrl+C
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	exitCode := 0
	select {
	case err := <-errCh:
		// не log.Fatalf: иначе не отработают defer'ы и соединение с БД не закроется
		log.Printf("server error: %v", err)
		exitCode = 1
	case sig := <-stop:
		log.Printf("signal %s — shutting down", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_ = webSrv.Shutdown(ctx)
	_ = apiSrv.Shutdown(ctx)
	cancel()
	if closeStore != nil {
		_ = closeStore()
	}
	log.Println("'Bye")
	os.Exit(exitCode)
}

// NewWebMux configures the web server router with authentication checks and route protection.
func NewWebMux(cfg *config.Config, authMgr *auth.Manager, proxy http.Handler) *http.ServeMux {
	webMux := http.NewServeMux()
	if proxy != nil {
		webMux.Handle("/api/", proxy)
		webMux.Handle("/cdn-cgi/rum", proxy)
		webMux.Handle("/v1/rgstr", proxy)
		webMux.Handle("/api/v2/metrics", proxy)
	}

	isAuthorized := func(r *http.Request) bool {
		c, err := r.Cookie(middleware.SessionCookie)
		if err != nil || c.Value == "" {
			return false
		}
		_, ok := authMgr.UserID(strings.TrimSpace(c.Value))
		return ok
	}

	handleIndex := func(w http.ResponseWriter, r *http.Request) {
		if isAuthorized(r) {
			http.Redirect(w, r, "/dashboard.html", http.StatusFound)
		} else {
			http.Redirect(w, r, "/login.html", http.StatusFound)
		}
	}

	webMux.HandleFunc("/{$}", handleIndex)
	webMux.HandleFunc("/index.html", handleIndex)

	webMux.HandleFunc("/dashboard.html", func(w http.ResponseWriter, r *http.Request) {
		if isAuthorized(r) {
			http.ServeFile(w, r, filepath.Join(cfg.StaticDir, "dashboard.html"))
		} else {
			http.Redirect(w, r, "/login.html", http.StatusFound)
		}
	})

	webMux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		if isAuthorized(r) {
			http.Redirect(w, r, "/dashboard.html", http.StatusFound)
		} else {
			http.ServeFile(w, r, filepath.Join(cfg.StaticDir, "login.html"))
		}
	})

	webMux.Handle("/", http.FileServer(http.Dir(cfg.StaticDir)))

	return webMux
}
