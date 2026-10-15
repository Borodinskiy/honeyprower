package handlers

// Обработчики HTTP запросов. Разбросаны по различным файлам этого модуля, но всецело представляют одну структуру Handlers и являются методами данного класса
// func (h *Handlers) function() - обозначение метода класса Handlers
//       ^ - переменная h для доступа к переменным класса.

import (
	"crypto/rand"
	"sync"

	"honeyprower/internal/auth"
	"honeyprower/internal/deploy"
	"honeyprower/internal/secret"
	"honeyprower/internal/storage"
)

type Handlers struct {
	Store storage.Storage
	Auth  *auth.Manager
	// AllowRegistration разрешает самостоятельную регистрацию через /api/auth/register.
	AllowRegistration bool
	// PublicURL — внешний адрес центра для агентов (в config.json). Пусто — берётся из запроса.
	PublicURL string
	// AgentTransport — как агенты шлют события: http_nolinger (по умолчанию) или udp_burst.
	AgentTransport string
	// CenterUDP — адрес UDP-приёмника центра для udp_burst, как его видят агенты
	// ("host:port"; пустой host — хост из адреса центра).
	CenterUDP string
	Deployer  deploy.Deployer
	// Secrets шифрует SSH-пароли и ключи хостов в базе.
	Secrets *secret.Box

	// hostOps не даёт запустить два деплоя/снятия одного хоста одновременно.
	hostOps sync.Map // host id -> *sync.Mutex
	// honeyCreds — учётки-приманки ловушек honeytoken для сверки входов.
	honeyCreds credCache
}

// Создаёт структуру обработчиков, передавая ей доступ к базе данных и менеджеру авторизации
// Ключ шифрования по умолчанию случайный: сохранённые секреты переживут только
// этот процесс. main подставляет постоянный ключ из конфигурации.
func New(dbStorage storage.Storage, authMgr *auth.Manager) *Handlers {
	return &Handlers{
		Store:             dbStorage,
		Auth:              authMgr,
		AllowRegistration: true,
		Deployer:          deploy.NewSSHDeployer(),
		Secrets:           ephemeralBox(),
	}
}

func ephemeralBox() *secret.Box {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	b, err := secret.New(key)
	if err != nil {
		panic(err)
	}
	return b
}
