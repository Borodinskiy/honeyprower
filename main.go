package main

// Начало начал

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
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
	"honeyprower/internal/demo"
	"honeyprower/internal/deploy"
	"honeyprower/internal/handlers"
	"honeyprower/internal/middleware"
	"honeyprower/internal/router"
	"honeyprower/internal/secret"
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
	if err := setAgentTransport(handlers, honeycfg); err != nil {
		log.Fatal(err)
	}
	box, err := loadSecretBox(honeycfg)
	if err != nil {
		log.Fatalf("secret key: %v", err)
	}
	handlers.Secrets = box
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

	// ---------- demo traffic ----------
	// С DEMO_DATA центр сам генерирует атаки для показа; без него убирает оставшиеся демо-события.
	demoCtx, stopDemo := context.WithCancel(context.Background())
	defer stopDemo()
	if honeycfg.DemoData {
		log.Println("WARN: DEMO_DATA is on — generating fake attack events")
		go demo.Run(demoCtx, dbStorage)
	} else {
		go demo.Clear(demoCtx, dbStorage)
	}

	// ---------- run ----------
	// Отслеживание цепочки ошибок в проверках ниже
	errCh := make(chan error, 3)

	// UDP-приёмник транспорта udp_burst: конверты без ответа и без соединений.
	var udpConn net.PacketConn
	if honeycfg.UDPAddr != "" {
		udpConn, err = net.ListenPacket("udp", honeycfg.UDPAddr)
		if err != nil {
			log.Fatalf("UDP_INGEST_ADDR: %v", err)
		}
		log.Printf("udp ingest  → %s", udpConn.LocalAddr())
		go func() {
			if err := handlers.ServeStealthUDP(context.Background(), udpConn); err != nil {
				errCh <- err
			}
		}()
	}

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

	stopDemo()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_ = webSrv.Shutdown(ctx)
	_ = apiSrv.Shutdown(ctx)
	if udpConn != nil {
		_ = udpConn.Close()
	}
	cancel()
	if closeStore != nil {
		_ = closeStore()
	}
	log.Println("'Bye")
	os.Exit(exitCode)
}

// setAgentTransport выбирает, как агенты шлют события. udp_burst без
// UDP-приёмника центра терял бы все события, поэтому это ошибка запуска.
func setAgentTransport(h *handlers.Handlers, cfg *config.Config) error {
	switch cfg.AgentTransport {
	case "http_nolinger":
	case "udp_burst":
		if cfg.UDPAddr == "" {
			return errors.New("AGENT_TRANSPORT=udp_burst requires UDP_INGEST_ADDR")
		}
		h.CenterUDP = cfg.PublicUDP
		if h.CenterUDP == "" {
			_, port, err := net.SplitHostPort(cfg.UDPAddr)
			if err != nil {
				return fmt.Errorf("UDP_INGEST_ADDR: %w", err)
			}
			h.CenterUDP = ":" + port // хост подставится из адреса центра
		}
	default:
		return fmt.Errorf("AGENT_TRANSPORT=%q: expected http_nolinger or udp_burst", cfg.AgentTransport)
	}
	h.AgentTransport = cfg.AgentTransport
	return nil
}

// loadSecretBox берёт ключ шифрования SSH-доступа к хостам: HF_SECRET_KEY или
// файл ключа (создаётся при первом запуске). Без постоянного ключа сохранённые
// пароли не пережили бы перезапуск, поэтому ошибка здесь фатальна.
func loadSecretBox(cfg *config.Config) (*secret.Box, error) {
	if cfg.SecretKey != "" {
		key, err := secret.ParseKey(cfg.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("HF_SECRET_KEY: %w", err)
		}
		return secret.New(key)
	}
	key, err := secret.LoadOrCreateKeyFile(cfg.SecretKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%w (set HF_SECRET_KEY or HF_SECRET_KEY_FILE to a writable path)", err)
	}
	log.Printf("host credentials key: %s", cfg.SecretKeyFile)
	return secret.New(key)
}

// NewWebMux configures the web server router with authentication checks and route protection.
func NewWebMux(cfg *config.Config, authMgr *auth.Manager, proxy http.Handler) *http.ServeMux {
	webMux := http.NewServeMux()
	if proxy != nil {
		webMux.Handle("/api/", proxy)
		// Деплой и снятие по SSH идут дольше WriteTimeout веб-сервера — продлеваем срок только для них.
		slowSSH := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(4 * time.Minute))
			proxy.ServeHTTP(w, r)
		})
		webMux.Handle("POST /api/traps/{id}/deploy", slowSSH)
		webMux.Handle("POST /api/traps/{id}/undeploy", slowSSH)
		webMux.Handle("POST /api/hosts/{id}/deploy", slowSSH)
		webMux.Handle("POST /api/hosts/{id}/undeploy", slowSSH)
		webMux.Handle("GET /api/hosts/{id}/status", slowSSH)
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
