package handlers

// Обработчики HTTP запросов. Разбросаны по различным файлам этого модуля, но всецело представляют одну структуру Handlers и являются методами данного класса
// func (h *Handlers) function() - обозначение метода класса Handlers
//       ^ - переменная h для доступа к переменным класса.

import (
	"honeyprower/internal/auth"
	"honeyprower/internal/deploy"
	"honeyprower/internal/storage"
)

type Handlers struct {
	Store storage.Storage
	Auth  *auth.Manager
	// AllowRegistration разрешает самостоятельную регистрацию через /api/auth/register.
	AllowRegistration bool
	// PublicURL — внешний адрес центра для агентов (в config.json). Пусто — берётся из запроса.
	PublicURL string
	Deployer  deploy.Deployer
}

// Создаёт структуру обработчиков, передавая ей доступ к базе данных и менеджеру авторизации
func New(dbStorage storage.Storage, authMgr *auth.Manager) *Handlers {
	return &Handlers{
		Store:             dbStorage,
		Auth:              authMgr,
		AllowRegistration: true,
		Deployer:          deploy.NewSSHDeployer(),
	}
}
