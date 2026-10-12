package config

import "os"

// Конфигурация сервера
type Config struct {
	WebAddr   string // адрес хостинга веб сервиса, например localhost:8080
	APIAddr   string // адрес хостинка сервиса API вызовов (ну типо JSON API)
	StaticDir string // путь до директории, в которой находятся файлы фронтэнда
}

// TODO: чтение конфигурационных файлов помимо переменных окружения
func Load() *Config {
	return &Config{
		WebAddr:   getenv("WEB_ADDR", ":8080"),
		APIAddr:   getenv("API_ADDR", ":8081"),
		StaticDir: getenv("STATIC_DIR", "./Web"),
	}
}

// Возвращает значение переменной окружения k, иначе - значение по умолчанию из аргумента def
func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
