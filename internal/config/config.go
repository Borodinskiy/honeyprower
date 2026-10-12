package config

import (
	"fmt"
	"os"
)

// Конфигурация сервера
type Config struct {
	WebAddr   string // адрес хостинга веб сервиса, например localhost:8080
	APIAddr   string // адрес хостинка сервиса API вызовов (ну типо JSON API)
	StaticDir string // путь до директории, в которой находятся файлы фронтэнда
	DBDSN     string // DSN подключение к базе данных PostgreSQL
}

// TODO: чтение конфигурационных файлов помимо переменных окружения
func Load() *Config {
	return &Config{
		WebAddr:   getenv("WEB_ADDR", ":8080"),
		APIAddr:   getenv("API_ADDR", ":8081"),
		StaticDir: getenv("STATIC_DIR", "./Web"),
		DBDSN:     getDBDSN(),
	}
}

func getDBDSN() string {
	if dsn := os.Getenv("DB_DSN"); dsn != "" {
		return dsn
	}
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		return dsn
	}

	host := getenv("DB_HOST", "localhost")
	port := getenv("DB_PORT", "5432")
	user := getenv("DB_USER", "postgres")
	pass := getenv("DB_PASSWORD", "postgres")
	name := getenv("DB_NAME", "honeyforge")
	ssl := getenv("DB_SSLMODE", "disable")

	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, pass, host, port, name, ssl)
}

// Возвращает значение переменной окружения k, иначе - значение по умолчанию из аргумента def
func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
