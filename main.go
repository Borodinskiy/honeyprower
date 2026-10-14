package main

// Начало начал

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
	"honeyprower/internal/deploy"
	"honeyprower/internal/handlers"
	"honeyprower/internal/middleware"
	"honeyprower/internal/router"
	"honeyprower/internal/storage"
)

func main() {
	honeycfg := config.Load()

	// ---------- Database ----------
	var dbStorage storage.Storage
	// Сюда попадает функция для закрытия базы данных
	var closeStore func() error
	pgDatabase, err := storage.NewPostgres(context.Background(), honeycfg.DBDSN)
	if err != nil {
		log.Printf("failed to initialize postgres storage (%v)", err)
		if !honeycfg.FallbackInMemory {
			log.Fatal("Ending operation")
			os.Exit(1)
		}
		// В случае ошибки открытия postgres все данные хранятся в оперативной памяти
		log.Printf("falling back to in-memory store")
		memDatabase := storage.NewInMemory()
		// Заполнение тестовыми данными
		storage.Seed(memDatabase)
		dbStorage = memDatabase
	} else {
		dbStorage = pgDatabase
		closeStore = pgDatabase.Close
	}

	authMgr := auth.NewManager()
	handlers := handlers.New(dbStorage, authMgr)
	handlers.Deployer = deploy.NewSSHDeployer()
	handlers.AllowRegistration = honeycfg.AllowRegistration
	handlers.PublicURL = honeycfg.PublicURL
	if !honeycfg.AllowRegistration {
		log.Println("WARN: self-registration is disabled in configuration")
	}

	// ---------- API server ----------
	apiSrv := &http.Server{
		Addr:         honeycfg.APIAddr,
		Handler:      router.NewAPI(handlers, authMgr),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// ---------- Web server ----------
	apiURL, _ := url.Parse("http://" + honeycfg.APIAddr)
	proxy := httputil.NewSingleHostReverseProxy(apiURL)

	webMux := NewWebMux(honeycfg, authMgr, proxy)

	webSrv := &http.Server{
		Addr:         honeycfg.WebAddr,
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
		log.Printf("web server  → http://%s   (static dir: %s)", honeycfg.WebAddr, honeycfg.StaticDir)
		if err := webSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		log.Printf("api server  → http://%s", honeycfg.APIAddr)
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
		// Деплой по SSH идёт дольше WriteTimeout веб-сервера — продлеваем срок только для него.
		webMux.Handle("POST /api/traps/{id}/deploy", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(4 * time.Minute))
			proxy.ServeHTTP(w, r)
		}))
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
