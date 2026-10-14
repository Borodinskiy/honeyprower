package config

// Содержит структуру для хранения параметров конфигурации сервера
// Переменные окружения имеют приоритет

import (
	"net"
	"net/url"
	"os"
	"strconv"
)

// Конфигурация сервера
type Config struct {
	WebAddr   string // адрес хостинга веб сервиса, например localhost:8080
	APIAddr   string // адрес хостинка сервиса API вызовов (ну типо JSON API)
	StaticDir string // путь до директории, в которой находятся файлы фронтэнда
	DBDSN     string // DSN подключение к базе данных PostgreSQL

	AllowRegistration bool   // разрешена ли самостоятельная регистрация операторов
	FallbackInMemory  bool   // использовать ли базу данных в ОЗУ при ошибке подключения к настоящей бд
	PublicURL         string // внешний адрес центра для агентов (в config.json); пусто — из запроса

	// Ключ шифрования SSH-доступа к хостам: HF_SECRET_KEY (64 hex, base64 32 байт
	// или фраза от 16 символов), иначе файл SecretKeyFile, создаваемый при первом запуске.
	SecretKey     string
	SecretKeyFile string
}

// TODO: чтение конфигурационных файлов помимо переменных окружения
func Load() *Config {
	return &Config{
		WebAddr: getenv("WEB_ADDR", ":8080"),
		// API доступен снаружи только через прокси веб-сервера, поэтому по умолчанию слушает localhost
		APIAddr:   getenv("API_ADDR", "127.0.0.1:8081"),
		StaticDir: getenv("STATIC_DIR", "./Web"),
		DBDSN:     getDBDSN(),

		AllowRegistration: getbool("ALLOW_REGISTRATION", true),
		FallbackInMemory:  getbool("FALLBACK_INMEMORY", false),
		PublicURL:         os.Getenv("PUBLIC_URL"),

		SecretKey:     os.Getenv("HF_SECRET_KEY"),
		SecretKeyFile: getenv("HF_SECRET_KEY_FILE", "data/secret.key"),
	}
}

// Формирует DBSSN строку для подключения к базе данных
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

	// url.URL экранирует спецсимволы в логине/пароле (например, '@' или '/')
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, pass),
		Host:     net.JoinHostPort(host, port),
		Path:     "/" + name,
		RawQuery: url.Values{"sslmode": {ssl}}.Encode(),
	}
	return u.String()
}

// Возвращает значение переменной окружения k, иначе - значение по умолчанию из аргумента def
func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Возвращает булево значение переменной окружения k (true/false, 1/0 и т.п.), иначе def
func getbool(k string, def bool) bool {
	v, err := strconv.ParseBool(os.Getenv(k))
	if err != nil {
		return def
	}
	return v
}
