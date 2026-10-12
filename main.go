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
	"syscall"
	"time"

	"honeyprower/internal/auth"
	"honeyprower/internal/config"
	"honeyprower/internal/handlers"
	"honeyprower/internal/router"
	"honeyprower/internal/storage"
)

func main() {
	cfg := config.Load()

	// ---------- Database ----------
	store, err := storage.NewPostgres(context.Background(), cfg.DBDSN)
	if err != nil {
		log.Fatalf("failed to initialize postgres storage: %v", err)
	}
	defer store.Close()

	authMgr := auth.NewManager()
	h := handlers.New(store, authMgr)

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

	webMux := http.NewServeMux()
	webMux.Handle("/api/", proxy)
	webMux.Handle("/", http.FileServer(http.Dir(cfg.StaticDir)))

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

	// Ебанина, которая умом проверяет ошибки и записывает их в errCh
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

	select {
	case err := <-errCh:
		log.Fatalf("server error: %v", err)
	case sig := <-stop:
		log.Printf("signal %s — shutting down", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = webSrv.Shutdown(ctx)
	_ = apiSrv.Shutdown(ctx)
	log.Println("'Bye")
}
