// ============================================================
// 🎯 АРХИТЕКТУРА ПОДКЛЮЧЕНИЯ К БЭКЕНДУ
// ------------------------------------------------------------
//   1. CONFIG.USE_MOCK_DATA = false → идём в реальный API.
//   2. _request возвращает ТЕЛО КАК ЕСТЬ. Обёртки типа { data }
//      распаковывай в конкретном методе.
//   3. Ошибки нормализуются в ApiError.
//   4. Контракт API см. в README.md.
//   5. Сессия живёт в HttpOnly-cookie session_token, которую ставит
//      сервер. Токен в localStorage НЕ храним: оттуда его может
//      украсть любой XSS, а cookie из JS недоступна.
//
// ⚠️ В mock-режиме методы api ОБЯЗАНЫ мутировать MOCK_DATA,
//    иначе refreshAll() вернёт старые данные и UI не обновится.
// ============================================================
const CONFIG = {
    USE_MOCK_DATA: false,
    API_BASE_URL: '/api',
    LEGACY_TOKEN_KEY: 'auth_token', // старые версии хранили токен здесь — подчищаем
    LANG_KEY: 'app_lang',
    DASH_RANGE_KEY: 'dash_range',
    THEME_KEY: 'app_theme',
    REQUEST_TIMEOUT: 10000,
    SSH_TIMEOUT: 240000, // деплой, снятие и статус хоста идут по SSH и бывают долгими
    POLL_INTERVAL: 10000 // автообновление дашборда, мс
};

// МОКОВЫЕ ДАННЫЕ

const MOCK_DATA = {
    user: { id: 1, username: 'admin' },
    hosts: [],
    traps: [
        { id: 1, name: 'SSH Honeypot', type: 'SSH', target: '192.168.1.10:22', warnings: 142, active: true,  totalEvents: 1420, lastEventAt: '2 мин назад' },
        { id: 2, name: 'Web Trap',     type: 'Web', target: 'http://10.0.0.5/',  warnings: 87,  active: true,  totalEvents: 870,  lastEventAt: '15 мин назад' },
        { id: 3, name: 'FTP Trap',     type: 'FTP', target: '192.168.1.12:21', warnings: 0,   active: false, totalEvents: 0,    lastEventAt: '—' }
    ],
    stats: { activeTraps: 3, warnings24h: 229, activeTasks: 1 },
    // Моковые события по id ловушки
    events: {
        1: [
            { id: 101, type: 'connection', source: '10.0.0.42',    time: '2024-01-15 12:34:56', detail: 'SSH-2.0-OpenSSH_8.2' },
            { id: 102, type: 'auth',       source: '192.168.1.50', time: '2024-01-15 11:20:11', detail: 'user=root pass=admin' },
            { id: 103, type: 'scan',       source: '203.0.113.5',  time: '2024-01-15 09:15:33', detail: 'nmap -sV' }
        ],
        2: [
            { id: 201, type: 'connection', source: '198.51.100.7', time: '2024-01-15 14:22:01', detail: 'GET /admin.php' }
        ],
        3: []
    }
};


// КЛАСС ОШИБКИ API

class ApiError extends Error {
    constructor(message, status = 0, data = null) {
        super(message);
        this.name = 'ApiError';
        this.status = status;
        this.data = data;
    }
}

//  API-СЛОЙ

const api = {
    async _request(endpoint, { method = 'GET', body = null, auth = true, timeout = CONFIG.REQUEST_TIMEOUT } = {}) {
        const url = `${CONFIG.API_BASE_URL}${endpoint}`;

        const headers = { 'Content-Type': 'application/json' };

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);

        try {
            const res = await fetch(url, {
                method,
                headers,
                credentials: 'same-origin',
                body: body ? JSON.stringify(body) : null,
                signal: controller.signal
            });

            if (res.status === 401 && auth) {
                this._handleAuthError();
                throw new ApiError('Session expired', 401);
            }

            const data = res.status === 204 ? null : await res.json().catch(() => null);

            if (!res.ok) {
                const msg = data?.error || data?.message || `HTTP ${res.status}`;
                throw new ApiError(msg, res.status, data);
            }

            return data;

        } catch (err) {
            if (err.name === 'AbortError') throw new ApiError('Request timeout');
            if (err instanceof ApiError) throw err;
            throw new ApiError(err.message || 'Network error');
        } finally {
            clearTimeout(timer);
        }
    },

    _handleAuthError() {
        state.user = null;

        applyUserMenu();
        document.querySelectorAll('.modal-overlay').forEach(m => m.style.display = 'none');
        if (window.location.pathname.endsWith('dashboard.html') || window.location.pathname === '/' || window.location.pathname === '/index.html') {
            window.location.href = '/login.html';
        }
    },


    //  ЛОВУШКИ

    async getTraps() {
        if (CONFIG.USE_MOCK_DATA) return MOCK_DATA.traps.map(t => ({ ...t }));
        return this._request('/traps');
    },

    async getStats() {
        if (CONFIG.USE_MOCK_DATA) return this._recalcStats();
        return this._request('/stats');
    },

    // Агрегаты для графиков: range = '1h' | '24h' | '7d'.
    async getDashboard(range) {
        if (CONFIG.USE_MOCK_DATA) return null;
        const tz = -new Date().getTimezoneOffset(); // вёдра графика ровные по местному времени
        return this._request(`/stats/dashboard?range=${encodeURIComponent(range)}&tz=${tz}`);
    },

    async createTrap(trap) {
        if (CONFIG.USE_MOCK_DATA) {
            const created = {
                ...trap,
                id: Date.now(),
                warnings: 0,
                totalEvents: 0,
                lastEventAt: '—'
            };
            MOCK_DATA.traps.push(created);
            MOCK_DATA.events[created.id] = MOCK_DATA.events[created.id] || [];
            return { ...created };
        }
        return this._request('/traps', { method: 'POST', body: trap });
    },

    async updateTrap(id, patch) {
        if (CONFIG.USE_MOCK_DATA) {
            const trap = MOCK_DATA.traps.find(t => t.id === Number(id));
            if (!trap) return null;
            Object.assign(trap, patch);
            return { ...trap };
        }
        return this._request(`/traps/${id}`, { method: 'PATCH', body: patch });
    },

    async deleteTrap(id) {
        if (CONFIG.USE_MOCK_DATA) {
            const idx = MOCK_DATA.traps.findIndex(t => t.id === Number(id));
            if (idx !== -1) MOCK_DATA.traps.splice(idx, 1);
            delete MOCK_DATA.events[Number(id)];
            return { ok: true };
        }
        return this._request(`/traps/${id}`, { method: 'DELETE' });
    },

    //  ХОСТЫ

    async getHosts() {
        if (CONFIG.USE_MOCK_DATA) return MOCK_DATA.hosts.map(h => ({ ...h }));
        return this._request('/hosts');
    },

    async createHost(host) {
        if (CONFIG.USE_MOCK_DATA) {
            const created = {
                id: Date.now(), name: host.name, address: host.address, sshPort: host.sshPort,
                username: host.username, authType: host.authType, useSudo: host.useSudo,
                hasPassword: !!host.password, hasPrivateKey: !!host.privateKey, hasSudoPassword: !!host.sudoPassword,
                trapCount: 0, enabledTraps: 0, onlineTraps: 0, pendingChanges: false
            };
            MOCK_DATA.hosts.push(created);
            return { ...created };
        }
        return this._request('/hosts', { method: 'POST', body: host });
    },

    async updateHost(id, patch) {
        if (CONFIG.USE_MOCK_DATA) {
            const host = MOCK_DATA.hosts.find(h => h.id === Number(id));
            if (host) Object.assign(host, patch);
            return host ? { ...host } : null;
        }
        return this._request(`/hosts/${id}`, { method: 'PATCH', body: patch });
    },

    async deleteHost(id, { force = false } = {}) {
        if (CONFIG.USE_MOCK_DATA) {
            MOCK_DATA.hosts = MOCK_DATA.hosts.filter(h => h.id !== Number(id));
            MOCK_DATA.traps.forEach(trap => { if (trap.hostId === Number(id)) trap.hostId = null; });
            return null;
        }
        return this._request(`/hosts/${id}${force ? '?force=true' : ''}`, { method: 'DELETE' });
    },

    async deployHost(id) {
        if (CONFIG.USE_MOCK_DATA) {
            await new Promise(r => setTimeout(r, 1200));
            const host = MOCK_DATA.hosts.find(h => h.id === Number(id));
            if (host) { host.deployedAt = new Date().toISOString(); host.pendingChanges = false; }
            return { status: 'deployed', hostId: Number(id), host: host && host.address, traps: host ? host.enabledTraps : 0 };
        }
        return this._request(`/hosts/${id}/deploy`, { method: 'POST', timeout: CONFIG.SSH_TIMEOUT });
    },

    async undeployHost(id) {
        if (CONFIG.USE_MOCK_DATA) {
            await new Promise(r => setTimeout(r, 800));
            const host = MOCK_DATA.hosts.find(h => h.id === Number(id));
            if (host) { delete host.deployedAt; host.pendingChanges = false; }
            return { status: 'removed', hostId: Number(id), host: host && host.address };
        }
        return this._request(`/hosts/${id}/undeploy`, { method: 'POST', timeout: CONFIG.SSH_TIMEOUT });
    },

    async getHostStatus(id) {
        if (CONFIG.USE_MOCK_DATA) {
            return { active: true, subState: 'active', expectedPorts: [], missingPorts: [] };
        }
        return this._request(`/hosts/${id}/status`, { timeout: CONFIG.SSH_TIMEOUT });
    },

    async getTrapEvents(id, type = '') {
        if (CONFIG.USE_MOCK_DATA) return MOCK_DATA.events[Number(id)] || [];
        const q = type ? `?type=${encodeURIComponent(type)}` : '';
        return this._request(`/traps/${id}/events${q}`);
    },

    async getClasses() {
        if (CONFIG.USE_MOCK_DATA) return [];
        return this._request('/classes');
    },

    async getPresets() {
        if (CONFIG.USE_MOCK_DATA) return [];
        return this._request('/presets');
    },

    _recalcStats() {
        const traps = MOCK_DATA.traps;
        const active = traps.filter(t => t.active).length;
        const warnings24h = traps.reduce((sum, t) => sum + (t.warnings || 0), 0);

        MOCK_DATA.stats.activeTraps = active;
        MOCK_DATA.stats.warnings24h = warnings24h;

        return { ...MOCK_DATA.stats };
    },


    // АВТОРИЗАЦИЯ

    async login(credentials) {
        if (CONFIG.USE_MOCK_DATA) return { token: 'mock-token', user: MOCK_DATA.user };
        return this._request('/auth/login', { method: 'POST', body: credentials, auth: false });
    },

    async register(data) {
        if (CONFIG.USE_MOCK_DATA) {
            return { token: 'mock-token', user: { id: Date.now(), username: data.username } };
        }
        return this._request('/auth/register', { method: 'POST', body: data, auth: false });
    },

    async me() {
        if (CONFIG.USE_MOCK_DATA) return { ...MOCK_DATA.user };
        try {
            return await this._request('/auth/me');
        } catch (err) {
            if (err.status === 401) return null;
            throw err;
        }
    },

    async logout() {
        if (CONFIG.USE_MOCK_DATA) {
            state.user = null;
            return { ok: true };
        }
        try {
            await this._request('/auth/logout', { method: 'POST', auth: true });
        } catch (err) {
            console.error('[logout]', err);
        } finally {
            state.user = null;
        }
    }
};


// 1. СОСТОЯНИЕ

const state = {
    currentLang: 'ru',
    currentTab: 'stats',
    traps: [],
    classes: [],
    presets: [],
    stats: null,
    dashboard: null,
    dashRange: '24h',      // окно графиков на «Статистике»: '1h' | '24h' | '7d'
    user: null,
    loading: false,
    selectedTrapId: null,
    editingTrapId: null,
    hosts: [],
    hostSearch: '',
    currentHostId: null,   // null — список хостов; число — открытый хост; 'none' — ловушки без хоста
    editingHostId: null,
    hostOps: {},           // id хоста → выполняемая операция ('deploy' | 'undeploy' | 'status')
    hostOpResult: null,    // { hostId, kind: 'loading'|'success'|'error', text } — строка состояния под шапкой хоста
    eventTypeFilter: ''
};

const TAB_LABELS = { traps: 'Хосты', stats: 'Статистика', events: 'События' };
const RANGE_LABELS = { '1h': 'за 1 ч', '24h': 'за 24 ч', '7d': 'за 7 дней' };

// Типы событий (русские подписи). Набор закрыт на стороне агента/центра.
const EVENT_TYPE_LABELS = {
    connect: 'Подключение',
    disconnect: 'Отключение',
    data: 'Данные',
    auth: 'Попытка входа',
    command: 'Команда',
    request: 'HTTP-запрос',
    handshake: 'Рукопожатие',
    scan: 'Сканирование',
    token: 'Honeytoken',
    error: 'Ошибка'
};

// Статусы ловушки.
const STATUS_LABELS = { online: '● На связи', offline: '● Нет связи', never: '● Ждёт агента', disabled: '● Выключена' };
const STATUS_COLORS = { online: '#10b981', offline: '#f59e0b', never: '#6b7280', disabled: '#6b7280' };

// 2. СЛОВАРЬ ПЕРЕВОДОВ (каюсь грешен, переводил не сам, могут быть ошибки)

const I18N_DICT = {
    "Панель управления": "Control Panel",
    "Ловушки": "Traps",
    "Статистика": "Statistics",
    "События": "Events",
    "Главная": "Home",

    "+ Создать ловушку": "+ Create Trap",
    "Редактировать": "Edit",
    "Удалить": "Delete",
    "Поиск ловушек по названию или IP...": "Search traps by name or IP...",

    "● Активна": "● Active",
    "● Неактивна": "● Inactive",

    "Предупреждений": "Warnings",
    "Всего событий": "Total events",
    "Последнее": "Last",

    "Ловушек на связи": "Traps online",
    "Дополнительные параметры": "Advanced parameters",
    "Ещё": "More",
    "Добавить": "Add",
    "Редактировать как JSON": "Edit as JSON",
    "Вернуться к форме": "Back to form",
    "Ошибка в параметрах": "Invalid parameters",
    "Параметры ловушки": "Trap parameters",
    "● На связи": "● Online",
    "● Нет связи": "● Offline",
    "● Ждёт агента": "● Waiting for agent",
    "● Выключена": "● Disabled",
    "Адрес": "Address",
    "Событий": "Events",
    "Включённых ловушек": "Enabled traps",
    "Предупреждения (за 24ч)": "Warnings (24h)",
    "Параметры должны быть корректным JSON.": "Params must be valid JSON.",
    "Параметры должны быть JSON-объектом.": "Params must be a JSON object.",

    "Ловушка:": "Trap:",
    "— Выберите ловушку —": "— Select a trap —",
    "Выберите ловушку": "Select a trap",
    "Подключение": "Connection",
    "Попытка входа": "Auth attempt",
    "Сканирование": "Scan",
    "Нет событий": "No events",

    "Войти": "Login",
    "Регистрация": "Register",
    "Выйти": "Logout",

    "Вход в систему": "Sign In",
    "Логин": "Username",
    "Введите логин": "Enter username",
    "Пароль": "Password",
    "Введите пароль": "Enter password",
    "Нет аккаунта?": "No account?",
    "Зарегистрироваться": "Sign Up",
    "Уже есть аккаунт?": "Already have an account?",
    "Придумайте логин": "Create username",
    "Введите email": "Enter email",
    "Придумайте пароль": "Create password",

    "Создание новой ловушки": "Create New Trap",
    "Редактирование ловушки": "Edit Trap",
    "Название ловушки": "Trap Name",
    "Например: SSH Honeypot": "E.g.: SSH Honeypot",
    "Тип ловушки": "Trap Type",
    "IP-адрес или URL": "IP Address or URL",
    "192.168.1.10:22 или http://10.0.0.5/": "192.168.1.10:22 or http://10.0.0.5/",
    "Активна": "Active",
    "Сохранить": "Save",

    "Переключить тему": "Toggle theme",
    "Загрузка...": "Loading...",
    "Данных пока нет.": "No data yet.",
    "Атаки": "Attacks",
    "Прочие события": "Other events",
    "включено": "enabled",
    "Разных IP-адресов": "Unique IP addresses",
    "Событий": "Events",
    "за 1 ч": "last hour",
    "за 24 ч": "last 24 h",
    "за 7 дней": "last 7 days",
    "1 ч": "1 h",
    "24 ч": "24 h",
    "7 дн": "7 d",
    "Активность": "Activity",
    "Атаки — попытки входа, сканирования и срабатывания honeytoken.": "Attacks are login attempts, scans and honeytoken hits.",
    "Показать таблицей": "Show as table",
    "Самые активные IP": "Most active IPs",
    "Атаки и прочие события с одного адреса.": "Attacks and other events from one address.",
    "Нажмите на ловушку, чтобы открыть её события.": "Click a trap to open its events.",
    "Типы событий": "Event types",
    "Частые логины": "Top usernames",
    "Частые пароли": "Top passwords",
    "Попыток входа": "Login attempts",
    "Ловушек задето": "Traps hit",
    "Последнее событие": "Last event",
    "Время": "Time",
    "Всего": "Total",
    "За этот период данных нет.": "No data for this period.",
    "За этот период событий нет.": "No events in this period.",
    "Выше": "Up",
    "Ниже": "Down",
    "Пока пусто.": "Empty for now.",
    "У этого класса нет параметров.": "This class has no parameters.",
    "Ловушки не найдены.": "No traps found.",
    "Ошибка загрузки данных.": "Failed to load data.",
    "Не удалось создать ловушку.": "Failed to create trap.",
    "Не удалось обновить ловушку.": "Failed to update trap.",
    "Не удалось удалить ловушку.": "Failed to delete trap.",
    "Не удалось загрузить события.": "Failed to load events.",
    "Неверный логин или пароль.": "Invalid username or password.",
    "Не удалось зарегистрироваться.": "Registration failed.",
    "Сессия истекла. Войдите заново.": "Session expired. Please log in again.",
    "Некорректный IP-адрес или URL.": "Invalid IP address or URL.",
    "Удалить ловушку «{name}» вместе со всеми её событиями?": "Delete trap \"{name}\" with all its events?",

    "Этот логин уже занят.": "This username is already taken.",
    "Регистрация отключена администратором.": "Registration is disabled by the administrator.",
    "Пароль должен быть не короче 6 символов.": "Password must be at least 6 characters.",
    "Пароль слишком длинный.": "Password is too long.",
    "Логин слишком длинный.": "Username is too long.",
    "Некорректный email.": "Invalid email.",
    "Заполните название, тип и адрес.": "Fill in name, type and target.",
    "Слишком длинное значение поля.": "Field value is too long.",

    "Хосты": "Hosts",
    "+ Добавить хост": "+ Add Host",
    "Хост — сервер, на котором один агент держит все свои ловушки. Откройте хост, чтобы добавить ловушки и развернуть агента.": "A host is a server where one agent runs all of its traps. Open a host to add traps and deploy the agent.",
    "Поиск хостов по названию или адресу...": "Search hosts by name or address...",
    "← Все хосты": "← All hosts",
    "Развернуть": "Deploy",
    "Применить изменения": "Apply changes",
    "Переразвернуть": "Redeploy",
    "Проверить статус": "Check status",
    "Снять с сервера": "Remove from server",
    "Скачать config.json": "Download config.json",
    "Изменить хост": "Edit host",
    "Удалить хост": "Delete host",
    "Ловушки хоста": "Host traps",
    "Ловушки без хоста": "Traps without a host",
    "Без хоста": "No host",
    "— Без хоста —": "— No host —",
    "Хост": "Host",
    "Агент хоста запускает все его включённые ловушки, поэтому их порты не должны совпадать.": "The host agent runs all enabled traps of the host, so their ports must not overlap.",
    "Хостов пока нет. Добавьте сервер, на котором будут работать ловушки.": "No hosts yet. Add a server to run traps on.",
    "Хосты не найдены.": "No hosts found.",
    "На этом хосте пока нет ловушек.": "This host has no traps yet.",
    "Эти ловушки не привязаны к хосту: центр не может развернуть их сам. Привяжите их к хосту через «Редактировать».": "These traps are not assigned to a host, so the center cannot deploy them. Assign them to a host via “Edit”.",
    "Ловушек": "Traps",
    "включено": "enabled",
    "● Не развёрнут": "● Not deployed",
    "● Развёрнут": "● Deployed",
    "● Есть неприменённые изменения": "● Changes not applied",
    "на связи": "online",
    "из": "of",
    "развёрнут": "deployed",
    "Новый хост": "New Host",
    "Изменение хоста": "Edit Host",
    "Доступ по SSH центр хранит зашифрованным и в браузер не возвращает. По нему он ставит, обновляет и снимает агента хоста.": "The center stores SSH access encrypted and never sends it back to the browser. It uses it to install, update and remove the host agent.",
    "Название": "Name",
    "Например: web-01 (DMZ)": "E.g.: web-01 (DMZ)",
    "Адрес сервера": "Server address",
    "Например: 192.168.1.50 или honeypot.internal": "E.g.: 192.168.1.50 or honeypot.internal",
    "SSH Порт": "SSH Port",
    "Имя пользователя SSH": "SSH Username",
    "Способ аутентификации": "Authentication Method",
    "Пароль SSH": "SSH Password",
    "Приватный SSH-ключ": "Private SSH Key",
    "Приватный ключ SSH (OpenSSH / PEM, без пароля)": "Private SSH key (OpenSSH / PEM, unencrypted)",
    "Введите пароль пользователя SSH": "Enter the SSH user's password",
    "Использовать sudo (если подключаетесь не под root)": "Use sudo (if not connecting as root)",
    "Пароль sudo (если отличается от пароля SSH)": "Sudo password (if different from SSH password)",
    "Оставьте пустым, если совпадает с паролем SSH": "Leave empty if it matches the SSH password",
    "Сохранён — оставьте пустым, чтобы не менять": "Saved — leave empty to keep it",
    "Отмена": "Cancel",
    "Развёртывание агента: загрузка, настройка systemd, запуск...": "Deploying the agent: upload, systemd setup, start...",
    "Остановка агента и удаление его файлов с сервера...": "Stopping the agent and removing its files from the server...",
    "Подключение к серверу и проверка агента...": "Connecting to the server and checking the agent...",
    "Агент развёрнут. Ловушек запущено: {n}.": "Agent deployed. Traps running: {n}.",
    "Агент снят с сервера: служба остановлена, файлы удалены.": "Agent removed: service stopped, files deleted.",
    "Агент работает (служба {state}).": "Agent is running (service {state}).",
    "Агент не работает (служба {state}).": "Agent is not running (service {state}).",
    "Не слушаются порты: {ports}.": "Ports not listening: {ports}.",
    "Все порты ловушек открыты.": "All trap ports are open.",
    "Ошибка развертывания": "Deployment error",
    "Ошибка снятия агента": "Agent removal error",
    "Ошибка проверки статуса": "Status check error",
    "Снять агента с хоста «{name}»? Все ловушки этого хоста перестанут работать.": "Remove the agent from host \"{name}\"? All traps of this host will stop.",
    "Удалить хост «{name}»? Его ловушки останутся в разделе «Без хоста».": "Delete host \"{name}\"? Its traps will move to \"No host\".",
    "На сервере всё ещё работает агент этого хоста. Удалить хост, не снимая агента? Управлять им из центра будет нельзя.": "The host agent is still running on the server. Delete the host without removing it? The center will no longer be able to manage it.",
    "Не удалось сохранить хост.": "Failed to save host.",
    "Не удалось удалить хост.": "Failed to delete host.",
    "Укажите название.": "Enter a name.",
    "Укажите адрес хоста.": "Enter the host address.",
    "Некорректный адрес: нужен IP или DNS-имя без схемы и порта.": "Invalid address: use an IP or DNS name without scheme or port.",
    "SSH-порт должен быть от 1 до 65535.": "SSH port must be 1..65535.",
    "Некорректное имя пользователя SSH.": "Invalid SSH username.",
    "Введите пароль SSH.": "Enter the SSH password.",
    "Вставьте приватный SSH-ключ.": "Paste a private SSH key.",
    "Не удалось разобрать приватный ключ.": "Could not parse the private key.",
    "Ключ защищён паролем — такие ключи не поддерживаются. Снимите пароль: ssh-keygen -p -f <файл ключа>.": "The key is passphrase-protected, which is not supported. Remove the passphrase: ssh-keygen -p -f <key file>.",
    "Слишком длинный пароль или ключ.": "Password or key is too long.",
    "Хост с таким адресом и SSH-портом уже есть.": "A host with this address and SSH port already exists.",
    "Хост не найден.": "Host not found.",
    "На хосте нет включённых ловушек — разворачивать нечего.": "The host has no enabled traps — nothing to deploy.",
    "С этим хостом уже выполняется операция. Дождитесь её окончания.": "Another operation on this host is in progress. Wait for it to finish.",
    "Сохранённый SSH-доступ не расшифровывается (сменился ключ центра). Введите пароль или ключ заново в «Изменить хост».": "Saved SSH access cannot be decrypted (the center key changed). Re-enter the password or key in “Edit host”.",
    "У хоста нет сохранённого SSH-доступа.": "The host has no saved SSH access.",
    "Агент на сервере ещё работает — сначала снимите его.": "The agent is still running on the server — remove it first.",
    "Ловушка привязана к хосту — разворачивайте хост целиком.": "The trap belongs to a host — deploy the whole host.",
    "Порт {port} на этом хосте уже занят ловушкой «{trap}».": "Port {port} on this host is already used by trap \"{trap}\".",
    "Ловушка создана": "Trap created",
    "Ловушка добавлена на хост «{host}». Она заработает после того, как вы примените изменения на сервере.": "The trap was added to host \"{host}\". It will start once you apply the changes on the server.",
    "Применить на сервере": "Apply on server",
    "Позже": "Later",
    "Ловушка не привязана к хосту. Запустите агента вручную или привяжите ловушку к хосту, чтобы центр сам разворачивал её по SSH.": "The trap is not assigned to a host. Run the agent manually or assign the trap to a host so the center deploys it over SSH.",
    "Готово": "Done",
    "Закрыть": "Close"
};

// Известные сообщения бэкенда → русские ключи словаря (см. internal/handlers)
const SERVER_ERROR_LABELS = {
    'invalid username or password': 'Неверный логин или пароль.',
    'username already taken': 'Этот логин уже занят.',
    'registration is disabled': 'Регистрация отключена администратором.',
    'password must be at least 6 characters': 'Пароль должен быть не короче 6 символов.',
    'password is too long': 'Пароль слишком длинный.',
    'username is too long': 'Логин слишком длинный.',
    'invalid email': 'Некорректный email.',
    'name, type and target are required': 'Заполните название, тип и адрес.',
    'name, type and target must not be empty': 'Заполните название, тип и адрес.',
    'name is too long': 'Слишком длинное значение поля.',
    'type is too long': 'Слишком длинное значение поля.',
    'target is too long': 'Слишком длинное значение поля.',
    'host is required': 'Укажите адрес хоста.',
    'username is required': 'Укажите имя пользователя SSH.',
    'password or privateKey is required': 'Введите пароль SSH.',
    'name is required': 'Укажите название.',
    'address is required': 'Укажите адрес хоста.',
    'invalid address': 'Некорректный адрес: нужен IP или DNS-имя без схемы и порта.',
    'ssh port must be 1..65535': 'SSH-порт должен быть от 1 до 65535.',
    'invalid username': 'Некорректное имя пользователя SSH.',
    'password is required': 'Введите пароль SSH.',
    'private key is required': 'Вставьте приватный SSH-ключ.',
    'invalid private key': 'Не удалось разобрать приватный ключ.',
    'encrypted private keys are not supported': 'Ключ защищён паролем — такие ключи не поддерживаются. Снимите пароль: ssh-keygen -p -f <файл ключа>.',
    'secret is too long': 'Слишком длинный пароль или ключ.',
    'host with this address already exists': 'Хост с таким адресом и SSH-портом уже есть.',
    'host not found': 'Хост не найден.',
    'host has no enabled traps': 'На хосте нет включённых ловушек — разворачивать нечего.',
    'another operation on this host is in progress': 'С этим хостом уже выполняется операция. Дождитесь её окончания.',
    'stored credentials cannot be decrypted; re-enter them': 'Сохранённый SSH-доступ не расшифровывается (сменился ключ центра). Введите пароль или ключ заново в «Изменить хост».',
    'host has no saved credentials': 'У хоста нет сохранённого SSH-доступа.',
    'host is deployed; remove the agent first': 'Агент на сервере ещё работает — сначала снимите его.',
    'trap belongs to a host; deploy the host instead': 'Ловушка привязана к хосту — разворачивайте хост целиком.',
    'trap not found': 'Ловушка не найдена.',
    'deployer not configured': 'Служба деплоя недоступна на сервере.',
    'deployer service unavailable': 'Служба деплоя недоступна на сервере.',
    'systemd unit file not found': 'Unit-файл systemd не найден на сервере.',
    'failed to read systemd service file': 'Не удалось прочитать unit-файл службы systemd.',
    'agent binary not found; please build the agent first': 'Бинарный файл агента не найден на сервере.',
    'center url is loopback; set PUBLIC_URL': 'Центр открыт по localhost — агент на удалённом сервере не сможет до него достучаться. Задайте PUBLIC_URL (внешний адрес центра) и перезапустите центр.'
};

// Части составных ошибок деплоя (internal/deploy): между ними — вывод самого агента,
// поэтому переводим фразы, а не сообщение целиком.
const SERVER_ERROR_PHRASES = [
    ['agent failed to start:', 'Агент не запустился:'],
    ['previous version restored', 'На сервере восстановлена предыдущая рабочая версия — ловушки хоста продолжают работать.'],
    ['agent stopped: no previous working version to restore', 'Агент остановлен: предыдущей рабочей версии нет.'],
    ['agent stopped: previous version did not start either', 'Агент остановлен: предыдущая версия тоже не запустилась.'],
    ['rollback failed:', 'Откат не удался:']
];

const I18N_REVERSE = Object.fromEntries(
    Object.entries(I18N_DICT).map(([ru, en]) => [en, ru])
);


// 3. ПЕРЕВОД (в основном - на будующее)

function t(ruText) {
    const dict = state.currentLang === 'en' ? I18N_DICT : I18N_REVERSE;
    return dict[ruText] || ruText;
}

function translateStatic() {
    const dict = state.currentLang === 'en' ? I18N_DICT : I18N_REVERSE;

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
        acceptNode(node) {
            const tag = node.parentNode ? node.parentNode.nodeName : '';
            if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'TEXTAREA') return NodeFilter.FILTER_SKIP;
            return NodeFilter.FILTER_ACCEPT;
        }
    });

    const textNodes = [];
    while (walker.nextNode()) textNodes.push(walker.currentNode);

    for (const node of textNodes) {
        const trimmed = node.nodeValue.trim();
        if (!trimmed) continue;
        const translated = dict[trimmed];
        if (translated) node.nodeValue = node.nodeValue.replace(trimmed, translated);
    }

    document.querySelectorAll('[placeholder]').forEach(el => {
        el.placeholder = dict[el.placeholder] || el.placeholder;
    });

    document.querySelectorAll('[title]').forEach(el => {
        el.title = dict[el.title] || el.title;
    });

    const titleEl = document.querySelector('title');
    if (titleEl) {
        const currentTitle = titleEl.textContent.trim();
        if (dict[currentTitle]) titleEl.textContent = dict[currentTitle];
    }
}

function setLanguage(lang) {
    state.currentLang = lang;
    try { localStorage.setItem(CONFIG.LANG_KEY, lang); } catch (e) {}
    renderAll();
    translateStatic();
}

// 4. УТИЛИТЫ
//защита от XSS атак (ну,мало ли)
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// по идее должно извлекать данные из сообщений бэка, НО, возможно, будет требовать доработки (без бэка не проверить)
function getErrorMessage(err, fallbackRuKey) {
    const d = err?.data;
    if (d?.error === 'port conflict') {
        return t('Порт {port} на этом хосте уже занят ловушкой «{trap}».')
            .replace('{port}', d.port || '?').replace('{trap}', d.trap || '?');
    }
    const fromError = (typeof d?.error === 'object' && d.error !== null) ? d.error.message : d?.error;
    const serverMsg = fromError || d?.message;
    if (serverMsg && SERVER_ERROR_LABELS[serverMsg]) return t(SERVER_ERROR_LABELS[serverMsg]);
    if (serverMsg && state.currentLang === 'ru') {
        return SERVER_ERROR_PHRASES.reduce((msg, [en, ru]) => msg.split(en).join(ru), serverMsg);
    }
    return serverMsg || t(fallbackRuKey);
}



// 5. РЕНДЕР

// просто красиво пишет Главная/...
function updateBreadcrumb() {
    const crumb = document.getElementById('current-tab-crumb');
    if (crumb) crumb.textContent = t(TAB_LABELS[state.currentTab] || '');
}

//по сути заготовка на то, как будет выглядеть менюшка для залогиненного пользователя и не залогиненного
function applyUserMenu() {
    const isLoggedIn = !!state.user;

    document.querySelectorAll('[data-action="open-login"], [data-action="open-register"]').forEach(el => {
        el.style.display = isLoggedIn ? 'none' : '';
    });
    document.querySelectorAll('[data-action="logout"]').forEach(el => {
        el.style.display = isLoggedIn ? '' : 'none';
    });

    const nameEl = document.getElementById('current-user-name');
    if (nameEl) nameEl.textContent = isLoggedIn ? state.user.username : t('Войти');
}

// вот это для кнопок действий, пока не выбрана ловушка - кнопки не активны
function updateTrapActions() {
    const hasSelection = state.selectedTrapId !== null;

    const eventsBtn = document.getElementById('open-events-trap-btn');
    const editBtn = document.getElementById('open-edit-trap-btn');
    const deleteBtn = document.getElementById('delete-trap-btn');

    // Кнопки действий показываем только при выбранной ловушке — без выбора они лишь мешают.
    for (const btn of [eventsBtn, editBtn, deleteBtn]) {
        if (!btn) continue;
        btn.disabled = !hasSelection;
        btn.hidden = !hasSelection;
    }
}

// Адрес ловушки: bind:port или bind + список портов.
function trapAddress(trap) {
    if (trap.ports) return `${trap.bind || '0.0.0.0'} : ${trap.ports}`;
    return `${trap.bind || '0.0.0.0'}:${trap.port}`;
}

function classTitle(classId) {
    const c = state.classes.find(c => c.id === classId);
    return c ? c.title : classId;
}

function getLevelBadge(classId) {
    const c = (state.classes || []).find(c => c.id === classId);
    let level = c ? c.level : '';
    let badgeClass = 'badge-low';
    if (!level) {
        if (['dialog', 'http', 'honeytoken', 'medium_extra'].includes(classId)) {
            level = 'Medium';
        } else if (classId === 'high_interaction') {
            level = 'High';
        } else if (['iec104', 'scada'].includes(classId)) {
            level = 'ICS/SCADA';
        } else {
            level = 'Low';
        }
    }
    const text = level;
    if (level === 'Medium') {
        badgeClass = 'badge-med';
    } else if (level === 'High') {
        badgeClass = 'badge-high';
    } else if (level === 'ICS/SCADA' || level === 'ICS') {
        badgeClass = 'badge-ics';
    } else {
        badgeClass = 'badge-low';
    }
    return `<span class="badge ${badgeClass}">${escapeHtml(text)}</span>`;
}

// собирает структуру для карточки с ловушкой
function buildTrapCard(trap) {
    const status = trap.enabled ? (trap.status || 'never') : 'disabled';
    const statusClass = status === 'online' ? '' : 'inactive';
    const statusText = t(STATUS_LABELS[status] || status);
    const statusColor = STATUS_COLORS[status] || '#6b7280';
    const selectedClass = state.selectedTrapId === trap.id ? 'selected' : '';

    return `
        <div class="trap-item ${statusClass} ${selectedClass}" data-trap-id="${trap.id}">
            <div class="trap-title">
                <span class="trap-name" title="${escapeHtml(trap.name)}">${escapeHtml(trap.name)}</span>
                <span class="trap-status" style="color: ${statusColor};">${statusText}</span>
            </div>
            <div class="trap-info trap-class" style="display: flex; align-items: center; gap: 8px;">
                ${getLevelBadge(trap.class)}
                <span>${escapeHtml(classTitle(trap.class))}</span>
            </div>
            <div class="trap-info">${t('Адрес')}: ${escapeHtml(trapAddress(trap))}</div>
            <div class="trap-info"><span>${t('Предупреждений')}</span>: ${escapeHtml(trap.warnings ?? 0)} · <span>${t('Событий')}</span>: ${escapeHtml(trap.totalEvents ?? 0)}</div>
        </div>
    `;
}

// Ловушки открытого хоста ('none' — ловушки без хоста).
function trapsOfCurrentHost() {
    const id = state.currentHostId;
    if (id === null) return [];
    return state.traps.filter(trap => id === 'none' ? trap.hostId == null : trap.hostId === id);
}

function hostById(id) {
    return state.hosts.find(h => h.id === id) || null;
}

// Это вывод ловушек открытого хоста в #traps-list-container
function renderTraps() {
    const container = document.getElementById('traps-list-container');
    if (!container) return;

    if (state.loading) {
        container.innerHTML = `<p style="color: var(--text-muted);">${t('Загрузка...')}</p>`;
        return;
    }

    const traps = trapsOfCurrentHost();
    if (!traps.length) {
        container.innerHTML = `<p class="empty-hint">${t('На этом хосте пока нет ловушек.')}</p>`;
        return;
    }
    container.innerHTML = traps.map(buildTrapCard).join('');
}

// Состояние хоста: не развёрнут / развёрнут / есть неприменённые изменения.
function hostState(host) {
    if (!host.deployedAt) return { key: 'idle', label: t('● Не развёрнут'), color: '#6b7280' };
    if (host.pendingChanges) return { key: 'pending', label: t('● Есть неприменённые изменения'), color: '#f59e0b' };
    const allOnline = host.enabledTraps > 0 && host.onlineTraps >= host.enabledTraps;
    return { key: 'deployed', label: t('● Развёрнут'), color: allOnline ? '#10b981' : '#f59e0b' };
}

function hostAddress(host) {
    const port = host.sshPort && host.sshPort !== 22 ? `:${host.sshPort}` : '';
    return `${host.username}@${host.address}${port}`;
}

function buildHostCard(host) {
    const st = hostState(host);
    const cls = st.key === 'idle' ? 'inactive' : (st.key === 'pending' ? 'pending' : '');
    const online = host.deployedAt
        ? ` · ${t('на связи')} ${escapeHtml(host.onlineTraps)} ${t('из')} ${escapeHtml(host.enabledTraps)}`
        : '';
    return `
        <div class="trap-item host-item ${cls}" data-host-id="${host.id}">
            <div class="trap-title">
                <span class="trap-name" title="${escapeHtml(host.name)}">${escapeHtml(host.name)}</span>
                <span class="trap-status" style="color: ${st.color};">${escapeHtml(st.label)}</span>
            </div>
            <div class="trap-info">${escapeHtml(hostAddress(host))}</div>
            <div class="trap-info"><span>${t('Ловушек')}</span>: ${escapeHtml(host.trapCount ?? 0)} (${t('включено')} ${escapeHtml(host.enabledTraps ?? 0)})${online}</div>
        </div>
    `;
}

// Список хостов + карточка «Без хоста», если такие ловушки есть.
function renderHosts() {
    const container = document.getElementById('hosts-list-container');
    if (!container) return;

    if (state.loading) {
        container.innerHTML = `<p style="color: var(--text-muted);">${t('Загрузка...')}</p>`;
        return;
    }

    const query = state.hostSearch.toLowerCase().trim();
    const hosts = state.hosts.filter(h => !query
        || (h.name || '').toLowerCase().includes(query)
        || hostAddress(h).toLowerCase().includes(query));

    const loose = state.traps.filter(trap => trap.hostId == null);
    const looseCard = loose.length && !query ? `
        <div class="trap-item host-item inactive loose" data-host-id="none">
            <div class="trap-title"><span class="trap-name">${t('Без хоста')}</span></div>
            <div class="trap-info"><span>${t('Ловушек')}</span>: ${loose.length}</div>
        </div>` : '';

    if (!hosts.length && !looseCard) {
        container.innerHTML = `<p class="empty-hint">${t(state.hosts.length ? 'Хосты не найдены.' : 'Хостов пока нет. Добавьте сервер, на котором будут работать ловушки.')}</p>`;
        return;
    }
    container.innerHTML = hosts.map(buildHostCard).join('') + looseCard;
}

// Шапка открытого хоста: название, адрес, состояние, доступность кнопок.
function renderHostView() {
    const listView = document.getElementById('hosts-view');
    const hostView = document.getElementById('host-view');
    if (!listView || !hostView) return;

    const open = state.currentHostId !== null;
    listView.hidden = open;
    hostView.hidden = !open;
    if (!open) return;

    const loose = state.currentHostId === 'none';
    const host = loose ? null : hostById(state.currentHostId);
    const titleEl = document.getElementById('host-view-title');
    const metaEl = document.getElementById('host-view-meta');
    const trapsTitle = document.getElementById('host-traps-title');
    const actions = document.getElementById('host-actions');

    if (loose) {
        titleEl.textContent = t('Ловушки без хоста');
        metaEl.textContent = t('Эти ловушки не привязаны к хосту: центр не может развернуть их сам. Привяжите их к хосту через «Редактировать».');
        trapsTitle.textContent = t('Ловушки без хоста');
        actions.hidden = true;
    } else if (host) {
        const st = hostState(host);
        titleEl.textContent = host.name;
        const deployed = host.deployedAt
            ? ` · ${t('развёрнут')} ${escapeHtml(new Date(host.deployedAt).toLocaleString(state.currentLang === 'en' ? 'en-GB' : 'ru-RU'))}`
            : '';
        metaEl.innerHTML = `${escapeHtml(hostAddress(host))}${host.useSudo ? ' (sudo)' : ''} · `
            + `<span class="host-state" style="color: ${st.color};">${escapeHtml(st.label)}</span>${deployed}`;
        trapsTitle.textContent = t('Ловушки хоста');
        actions.hidden = false;

        const busy = !!state.hostOps[host.id];
        const deployBtn = document.getElementById('host-deploy-btn');
        deployBtn.textContent = t(!host.deployedAt ? 'Развернуть' : (host.pendingChanges ? 'Применить изменения' : 'Переразвернуть'));
        deployBtn.disabled = busy || host.enabledTraps === 0;
        deployBtn.title = host.enabledTraps === 0 ? t('На хосте нет включённых ловушек — разворачивать нечего.') : '';
        document.getElementById('host-status-btn').disabled = busy;
        document.getElementById('host-undeploy-btn').disabled = busy || !host.deployedAt;
        document.getElementById('host-config-btn').disabled = host.enabledTraps === 0;
        document.getElementById('host-edit-btn').disabled = busy;
        document.getElementById('host-delete-btn').disabled = busy;
    }

    renderHostOpStatus();
}

// Строка результата операции над хостом (деплой, снятие, статус).
function renderHostOpStatus() {
    const box = document.getElementById('host-op-status');
    if (!box) return;
    const r = state.hostOpResult;
    if (!r || r.hostId !== state.currentHostId) {
        box.hidden = true;
        return;
    }
    box.hidden = false;
    box.className = `deploy-status-box deploy-status-${r.kind}`;
    document.getElementById('host-op-spinner').style.display = r.kind === 'loading' ? 'block' : 'none';
    document.getElementById('host-op-text').textContent = r.text;
}

// Рисует KPI-карточки на вкладке "Статистика": ловушки на связи и итоги выбранного периода.
function renderStats() {
    const container = document.getElementById('stats-container');
    if (!container) return;

    if (state.loading) {
        container.innerHTML = `<p style="color: var(--text-muted);">${t('Загрузка...')}</p>`;
        return;
    }

    if (!state.stats) {
        container.innerHTML = `<p style="color: var(--text-muted);">${t('Данных пока нет.')}</p>`;
        return;
    }

    const s = state.stats;
    const d = state.dashboard;
    const period = t(RANGE_LABELS[state.dashRange]);
    container.innerHTML = `
        <div class="stat-card">
            <div class="stat-value" style="color: #10b981;">${escapeHtml(s.onlineTraps ?? 0)}</div>
            <div class="stat-label">${t('Ловушек на связи')} · ${t('включено')} ${escapeHtml(s.activeTraps ?? 0)}</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: var(--viz-attack);">${escapeHtml(d ? d.warnings : s.warnings24h ?? 0)}</div>
            <div class="stat-label">${d ? `${t('Атаки')} · ${period}` : t('Предупреждения (за 24ч)')}</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: var(--text-main);">${escapeHtml(d ? d.uniqueSources : '—')}</div>
            <div class="stat-label">${t('Разных IP-адресов')} · ${period}</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: var(--text-main);">${escapeHtml(d ? d.events : s.totalEvents ?? 0)}</div>
            <div class="stat-label">${d ? `${t('Событий')} · ${period}` : t('Всего событий')}</div>
        </div>
    `;
}

// --- Дашборд: графики на вкладке «Статистика» ---
// Одна пара цветов на всех графиках: атаки (auth/scan/token) и прочие события.

const ATTACK_TYPES = new Set(['auth', 'scan', 'token']);
let dashRenderedKey = null; // данные, язык и ширина последнего рендера: без изменений не перерисовываем
let chartTips = [];         // содержимое тултипов; элементы ссылаются на него через data-tip

function renderDashboard() {
    syncRangeSwitch();
    const act = document.getElementById('dash-activity');
    if (!act) return;

    const d = state.dashboard;
    const width = act.clientWidth; // 0, пока вкладка скрыта: график дорисуется при переключении
    const key = JSON.stringify([d, state.currentLang, width, state.loading && !d]);
    if (key === dashRenderedKey) return;
    dashRenderedKey = key;
    chartTips = [];
    hideChartTip();

    const ids = ['dash-activity', 'dash-sources', 'dash-traps', 'dash-types', 'dash-usernames', 'dash-passwords'];
    if (!d) {
        const msg = state.loading ? t('Загрузка...') : t('Данных пока нет.');
        ids.forEach(id => { document.getElementById(id).innerHTML = `<p class="chart-empty">${msg}</p>`; });
        document.getElementById('dash-activity-table').innerHTML = '';
        return;
    }

    act.innerHTML = width ? activityChartSvg(d, width) : '';
    document.getElementById('dash-activity-table').innerHTML = activityTable(d);

    document.getElementById('dash-sources').innerHTML = hbars(d.topSources.map(s => ({
        label: s.ip, mono: true, attack: s.warnings, other: s.events - s.warnings,
        tip: {
            title: s.ip,
            rows: [
                ...splitRows(s.warnings, s.events - s.warnings),
                { label: t('Ловушек задето'), value: s.traps },
                { label: t('Последнее событие'), value: formatClock(s.lastTs, true) }
            ]
        }
    })));

    document.getElementById('dash-traps').innerHTML = hbars(d.byTrap.map(tr => ({
        label: tr.name, attack: tr.warnings, other: tr.events - tr.warnings, trapId: tr.trapId,
        tip: { title: tr.name, rows: splitRows(tr.warnings, tr.events - tr.warnings) }
    })));

    document.getElementById('dash-types').innerHTML = hbars(d.byType.map(ty => {
        const label = t(EVENT_TYPE_LABELS[ty.key] || ty.key);
        const attack = ATTACK_TYPES.has(ty.key);
        return {
            label, attack: attack ? ty.count : 0, other: attack ? 0 : ty.count,
            tip: { title: label, rows: [{ key: attack ? 'attack' : 'other', label: attack ? t('Атаки') : t('Прочие события'), value: ty.count }] }
        };
    }));

    const credRows = list => list.map(c => ({
        label: c.key, mono: true, attack: c.count, other: 0,
        tip: { title: c.key, rows: [{ key: 'attack', label: t('Попыток входа'), value: c.count }] }
    }));
    document.getElementById('dash-usernames').innerHTML = hbars(credRows(d.topUsernames));
    document.getElementById('dash-passwords').innerHTML = hbars(credRows(d.topPasswords));
}

function splitRows(attack, other) {
    return [
        { key: 'attack', label: t('Атаки'), value: attack },
        { key: 'other', label: t('Прочие события'), value: other },
        { label: t('Всего'), value: attack + other }
    ];
}

function addTip(tip) {
    chartTips.push(tip);
    return chartTips.length - 1;
}

// Горизонтальные полосы: у каждой строки сегмент атак и сегмент прочих, общий масштаб — максимум строки.
function hbars(rows) {
    if (!rows.length) return `<p class="chart-empty">${t('За этот период данных нет.')}</p>`;
    const max = Math.max(1, ...rows.map(r => r.attack + r.other));
    return rows.map(r => {
        const parts = [['attack', r.attack], ['other', r.other]].filter(([, v]) => v > 0);
        const gap = parts.length > 1 ? ' - 1px' : '';
        const segs = parts.map(([cls, v]) =>
            `<div class="hbar-seg ${cls}" style="width: calc(${(v / max * 100).toFixed(2)}%${gap})"></div>`).join('');
        const click = r.trapId != null ? ` clickable" data-trap-id="${r.trapId}` : '';
        return `
            <div class="hbar${click}" tabindex="0" data-tip="${addTip(r.tip)}">
                <div class="hbar-label${r.mono ? ' mono' : ''}">${escapeHtml(r.label)}</div>
                <div class="hbar-track">${segs}</div>
                <div class="hbar-value">${escapeHtml(r.attack + r.other)}</div>
            </div>`;
    }).join('');
}

// Ровные деления оси: шаг 1/2/5·10ⁿ, около четырёх делений; пустой график — шкала 0–4.
function niceTicks(max) {
    max = Math.max(max, 4);
    const raw = Math.max(1, max / 4);
    const pow = Math.pow(10, Math.floor(Math.log10(raw)));
    const step = [1, 2, 5, 10].map(m => m * pow).find(v => v >= raw);
    const ticks = [];
    for (let v = 0; v < max + step; v += step) ticks.push(v);
    return ticks;
}

// Прямоугольник со скруглёнными верхними углами: столбец «стоит» на оси.
function roundedTopRect(x, y, w, h, r) {
    r = Math.min(r, w / 2, h);
    return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

function pad2(n) { return String(n).padStart(2, '0'); }

function formatClock(ts, withDate) {
    const dt = new Date(ts * 1000);
    const time = `${pad2(dt.getHours())}:${pad2(dt.getMinutes())}`;
    return withDate ? `${pad2(dt.getDate())}.${pad2(dt.getMonth() + 1)} ${time}` : time;
}

function bucketTitle(d, b) {
    const multiDay = d.until - d.since > 86400;
    return `${formatClock(b.ts, multiDay)} – ${formatClock(b.ts + d.bucketSeconds, multiDay)}`;
}

// Столбцы активности: атаки внизу, прочие сверху, между сегментами зазор 2px.
function activityChartSvg(d, width) {
    const H = 220, M = { top: 10, right: 6, bottom: 26, left: 38 };
    const plotW = width - M.left - M.right, plotH = H - M.top - M.bottom;
    const n = d.timeline.length;
    const ticks = niceTicks(Math.max(...d.timeline.map(b => b.events)));
    const yMax = ticks[ticks.length - 1];
    const slot = plotW / n;
    const barW = Math.max(2, slot - Math.max(2, Math.min(8, slot * 0.3)));
    const base = M.top + plotH;
    const h = v => v / yMax * plotH;

    const grid = ticks.map(v => {
        const y = base - h(v);
        return `<line class="${v === 0 ? 'baseline' : 'grid'}" x1="${M.left}" x2="${width - M.right}" y1="${y}" y2="${y}"/>`
            + `<text x="${M.left - 6}" y="${y + 4}" text-anchor="end">${v}</text>`;
    }).join('');

    const multiDay = d.until - d.since > 86400;
    const every = Math.max(1, Math.ceil((multiDay ? 84 : 44) / slot));
    let bars = '', labels = '', hits = '';
    d.timeline.forEach((b, i) => {
        const x = M.left + i * slot + (slot - barW) / 2;
        const ha = h(b.warnings), ho = h(b.events - b.warnings);
        if (ho > 0) {
            const top = ha > 0 ? Math.max(1, ho - 2) : ho;
            const y = base - ha - (ha > 0 ? 2 : 0) - top;
            bars += `<path class="seg-other" d="${roundedTopRect(x, y, barW, top, 4)}"/>`;
        }
        if (ha > 0) {
            bars += ho > 0
                ? `<rect class="seg-attack" x="${x}" y="${base - ha}" width="${barW}" height="${ha}"/>`
                : `<path class="seg-attack" d="${roundedTopRect(x, base - ha, barW, ha, 4)}"/>`;
        }
        if ((n - 1 - i) % every === 0) {
            labels += `<text x="${M.left + i * slot + slot / 2}" y="${H - 8}" text-anchor="middle">${formatClock(b.ts, multiDay)}</text>`;
        }
        const tip = addTip({ title: bucketTitle(d, b), rows: splitRows(b.warnings, b.events - b.warnings) });
        hits += `<rect class="col-hit" tabindex="0" data-tip="${tip}" x="${M.left + i * slot}" y="${M.top}" width="${slot}" height="${plotH}"/>`;
    });

    return `<svg viewBox="0 0 ${width} ${H}" width="${width}" height="${H}" role="img"
                aria-label="${escapeHtml(t('Активность'))}: ${d.events} · ${escapeHtml(t('Атаки'))}: ${d.warnings}">
        ${grid}${hits}${bars}${labels}${d.events ? '' : `<text class="chart-empty-label" x="${M.left + plotW / 2}"
            y="${M.top + plotH / 2}" text-anchor="middle">${escapeHtml(t('За этот период событий нет.'))}</text>`}</svg>`;
}

function activityTable(d) {
    const rows = d.timeline.map(b => `<tr><td>${bucketTitle(d, b)}</td><td>${b.warnings}</td>`
        + `<td>${b.events - b.warnings}</td><td>${b.events}</td></tr>`).join('');
    return `<div class="chart-table-scroll"><table>
        <thead><tr><th>${t('Время')}</th><th>${t('Атаки')}</th><th>${t('Прочие события')}</th><th>${t('Всего')}</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
}

function syncRangeSwitch() {
    document.querySelectorAll('#dash-range button').forEach(btn => {
        const on = btn.dataset.range === state.dashRange;
        btn.classList.toggle('active', on);
        btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
}

async function setDashRange(range) {
    if (!RANGE_LABELS[range] || range === state.dashRange) return;
    state.dashRange = range;
    try { localStorage.setItem(CONFIG.DASH_RANGE_KEY, range); } catch (e) {}
    syncRangeSwitch();
    await loadDashboard();
    renderStats();
    renderDashboard();
}

// Тултип строится через textContent: подписи (логины, пароли, имена) приходят от атакующих.
function showChartTip(el, x, y) {
    const tip = chartTips[Number(el.dataset.tip)];
    const box = document.getElementById('chart-tooltip');
    if (!tip || !box) return;
    box.replaceChildren();
    const title = document.createElement('div');
    title.className = 'tt-title';
    title.textContent = tip.title;
    box.appendChild(title);
    for (const r of tip.rows) {
        const row = document.createElement('div');
        row.className = 'tt-row';
        if (r.key) {
            const k = document.createElement('i');
            k.className = `tt-key ${r.key}`;
            row.appendChild(k);
        }
        const v = document.createElement('strong');
        v.textContent = r.value;
        row.append(v, document.createTextNode(' ' + r.label));
        box.appendChild(row);
    }
    box.hidden = false;
    const w = box.offsetWidth, h = box.offsetHeight;
    let left = x + 14, top = y + 14;
    if (left + w > window.innerWidth - 8) left = x - w - 14;
    if (top + h > window.innerHeight - 8) top = y - h - 14;
    box.style.left = `${Math.max(8, left)}px`;
    box.style.top = `${Math.max(8, top)}px`;
}

function hideChartTip() {
    const box = document.getElementById('chart-tooltip');
    if (box) box.hidden = true;
}

function initDashboard() {
    const stats = document.getElementById('stats');
    if (!stats) return;

    document.getElementById('dash-range').addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-range]');
        if (btn) setDashRange(btn.dataset.range);
    });

    stats.addEventListener('pointermove', (e) => {
        const el = e.target.closest('[data-tip]');
        if (el) showChartTip(el, e.clientX, e.clientY); else hideChartTip();
    });
    stats.addEventListener('pointerleave', hideChartTip);
    stats.addEventListener('focusin', (e) => {
        const el = e.target.closest('[data-tip]');
        if (!el) return;
        const r = el.getBoundingClientRect();
        showChartTip(el, r.left + r.width / 2, r.top);
    });
    stats.addEventListener('focusout', hideChartTip);

    // Строка ловушки открывает её события.
    const openTrap = (e) => {
        const row = e.target.closest('.hbar[data-trap-id]');
        if (!row) return;
        if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        state.selectedTrapId = Number(row.dataset.trapId);
        hideChartTip();
        switchTab('events', document.querySelector('.nav-link[data-tab="events"]'));
    };
    stats.addEventListener('click', openTrap);
    stats.addEventListener('keydown', openTrap);

    let resizeTimer = null;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => { if (state.currentTab === 'stats') renderDashboard(); }, 150);
    });
}

// Заполняет селект ловушек на вкладке "События".
// Сохраняет текущий выбор, если он есть в state.traps.
function renderEventsSelect() {
    const select = document.getElementById('events-trap-select');
    if (!select) return;

    const prevValue = select.value;

    // Ловушки сгруппированы по хостам, как на вкладке «Хосты».
    const option = trap => `<option value="${trap.id}">${escapeHtml(trap.name)}</option>`;
    const groups = state.hosts
        .map(h => ({ label: h.name, traps: state.traps.filter(trap => trap.hostId === h.id) }))
        .concat([{ label: t('Без хоста'), traps: state.traps.filter(trap => trap.hostId == null) }])
        .filter(g => g.traps.length);
    const optionsHtml = `<option value="">${t('— Выберите ловушку —')}</option>`
        + groups.map(g => `<optgroup label="${escapeHtml(g.label)}">${g.traps.map(option).join('')}</optgroup>`).join('');
    // не пересобираем список без изменений: иначе автообновление закрывает открытый select
    if (select.dataset.optionsHtml !== optionsHtml) {
        select.innerHTML = optionsHtml;
        select.dataset.optionsHtml = optionsHtml;
    }

    if (state.selectedTrapId !== null
        && state.traps.some(t => t.id === state.selectedTrapId)) {
        select.value = String(state.selectedTrapId);
    } else if (prevValue && state.traps.some(t => String(t.id) === prevValue)) {
        select.value = prevValue;
    } else {
        select.value = '';
    }
}

//вызов всех рэндеров
function trapHostName(trap) {
    const host = trap.hostId != null ? hostById(trap.hostId) : null;
    return host ? host.name : t('Без хоста');
}

function renderAll() {
    updateBreadcrumb();
    renderHosts();
    renderHostView();
    renderTraps();
    renderStats();
    renderDashboard();
    applyUserMenu();
    updateTrapActions();

    // Если пользователь сейчас на вкладке "События" — обновляет селект
    if (state.currentTab === 'events') {
        renderEventsSelect();
    }
}


// 6. ЗАГРУЗКА ДАННЫХ

//проверка существует ли выбранная ловушка
async function loadTraps() {
    try {
        const [traps, hosts] = await Promise.all([api.getTraps(), api.getHosts()]);
        state.traps = traps || [];
        state.hosts = hosts || [];
        // Открытый хост удалили (например, в другой вкладке) — возвращаемся к списку.
        if (typeof state.currentHostId === 'number' && !hostById(state.currentHostId)) {
            setCurrentHost(null);
        }
        if (state.selectedTrapId !== null
            && !state.traps.some(t => t.id === state.selectedTrapId)) {
            state.selectedTrapId = null;
        }
    } catch (err) {
        console.error('[loadTraps]', err);
    }
}

// это мне добавил фикс гптешник, с его слов:
// "Идёт в api.getStats(), кладёт результат в state.stats. При ошибке — null."
async function loadStats() {
    try {
        state.stats = await api.getStats() || null;
    } catch (err) {
        console.error('[loadStats]', err);
    }
}

async function loadDashboard() {
    try {
        state.dashboard = await api.getDashboard(state.dashRange) || null;
    } catch (err) {
        console.error('[loadDashboard]', err);
    }
}

// Каталог классов и шаблонов нужен для формы создания и названий классов на карточках.
async function loadCatalog() {
    try {
        const [classes, presets] = await Promise.all([api.getClasses(), api.getPresets()]);
        state.classes = classes || [];
        state.presets = presets || [];
    } catch (err) {
        console.error('[loadCatalog]', err);
    }
}

// по идее тоже должно работать с бэком
// полностью обновляет все данные с бэка и перерисовывает их в UI
async function refreshAll() {
    state.loading = true;
    renderHosts();
    renderTraps();
    renderStats();

    await Promise.all([loadTraps(), loadStats(), loadDashboard()]);

    state.loading = false;
    renderAll();
}

// Тихое фоновое обновление: без «Загрузка...», чтобы интерфейс не мигал.
// Пропускается, пока вкладка браузера скрыта или идёт полная перезагрузка.
async function pollRefresh() {
    if (document.hidden || state.loading) return;

    await Promise.all([loadTraps(), loadStats(), loadDashboard()]);
    if (state.loading) return;
    renderAll();

    if (state.currentTab === 'events') {
        const select = document.getElementById('events-trap-select');
        const trapId = select && select.value ? Number(select.value) : null;
        if (trapId) await loadAndRenderEvents(trapId, { silent: true });
    }
}

function startPolling() {
    if (!CONFIG.POLL_INTERVAL) return;
    setInterval(pollRefresh, CONFIG.POLL_INTERVAL);
    // вернулись на вкладку — сразу подтягиваем свежие данные
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) pollRefresh();
    });
}


// 7. МОДАЛЬНЫЕ ОКНА (тут уже на удаление, скорее всего, чисто для показа того, как выглядит)

function showAuthError(message) {
    const errorEl = document.getElementById('auth-error');
    if (errorEl) {
        if (message) {
            errorEl.textContent = message;
            errorEl.style.display = 'block';
        } else {
            errorEl.textContent = '';
            errorEl.style.display = 'none';
        }
    } else if (message) {
        alert(message);
    }
}

function openModal(modalId) {
    const el = document.getElementById(modalId);
    if (el) el.style.display = 'flex';
}
function closeModal(modalId) {
    const el = document.getElementById(modalId);
    if (el) el.style.display = 'none';
}
function switchAuthForm(type) {
    showAuthError('');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    if (loginForm) loginForm.classList.toggle('active', type === 'login');
    if (registerForm) registerForm.classList.toggle('active', type === 'register');
}

// ---------- Форма параметров ловушки: строится по схеме класса (/api/classes) ----------

const paramForm = {
    classId: '',
    params: {},             // редактируемый объект; ключи вне схемы сохраняются как есть
    jsonMode: false,
    expanded: new WeakSet(),  // строки списков с раскрытыми редкими полями (по объекту — переживает перестановку)
    advOpen: new Set()        // раскрытые блоки «Дополнительно» (по пути)
};

function currentClass() {
    return state.classes.find(c => c.id === paramForm.classId);
}

function deepClone(v) {
    return v === undefined ? undefined : JSON.parse(JSON.stringify(v));
}

function parseParams(value) {
    if (!value) return {};
    if (typeof value === 'string') {
        try { return JSON.parse(value); } catch (e) { return {}; }
    }
    return deepClone(value);
}

// Значения по умолчанию из схемы: форма показывает и отправляет ровно то, с чем запустится агент.
function fillDefaults(fields, obj) {
    for (const f of fields || []) {
        if (f.type === 'list') {
            if (!Array.isArray(obj[f.key])) obj[f.key] = [];
            obj[f.key].forEach(item => { if (item && typeof item === 'object') fillDefaults(f.item, item); });
        } else if (obj[f.key] === undefined && f.default !== undefined) {
            obj[f.key] = deepClone(f.default);
        }
    }
    return obj;
}

// Управляющие символы показываем как \r \n \t — агент сам раскрывает эти последовательности.
function toEditable(v) {
    if (v === undefined || v === null) return '';
    return String(v).replace(/\r/g, '\\r').replace(/\n/g, '\\n').replace(/\t/g, '\\t');
}

function isVisible(f, obj) {
    if (!f.showIf) return true;
    const cur = obj[f.showIf.key];
    return f.showIf.in.includes(cur === undefined || cur === null ? '' : String(cur));
}

// Мини-конструктор DOM: атрибуты on* становятся обработчиками, остальное — свойствами.
function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (v === undefined || v === null || v === false) continue;
        if (k === 'class') node.className = v;
        else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
        else if (k in node) node[k] = v;
        else node.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children) {
        if (c !== null && c !== undefined && c !== false) node.append(c);
    }
    return node;
}

function renderParamsForm() {
    const root = document.getElementById('params-form');
    if (!root) return;
    root.replaceChildren();
    const cls = currentClass();
    if (!cls) return;
    if (!(cls.fields || []).length) {
        root.append(el('p', { class: 'field-help' }, t('У этого класса нет параметров.')));
        return;
    }
    root.append(...renderFieldGroup(cls.fields || [], paramForm.params, '', 'Дополнительные параметры'));
}

// Поля в две колонки; длинный текст, списки и флажки — на всю ширину. Редкие поля — в раскрывающемся блоке.
function renderFieldGroup(fields, obj, path, advLabel) {
    const out = [];
    const basic = fields.filter(f => !f.advanced && isVisible(f, obj));
    const adv = fields.filter(f => f.advanced && isVisible(f, obj));
    if (basic.length) out.push(el('div', { class: 'form-grid' }, ...basic.map(f => renderField(f, obj, path))));
    if (adv.length) {
        const key = path + '#adv';
        out.push(el('details', {
            class: 'params-advanced',
            open: paramForm.advOpen.has(key),
            ontoggle: (e) => { e.target.open ? paramForm.advOpen.add(key) : paramForm.advOpen.delete(key); }
        },
            el('summary', {}, `${t(advLabel)} (${adv.length})`),
            el('div', { class: 'form-grid' }, ...adv.map(f => renderField(f, obj, path)))));
    }
    return out;
}

function fieldId(path, f) {
    return 'pf-' + (path + f.key).replace(/[^a-zA-Z0-9_-]/g, '-');
}

// Поле ввода без подписи: общее для формы и ячеек таблицы списка.
function fieldInput(f, obj, id) {
    const value = obj[f.key];
    if (f.type === 'bool') {
        return el('input', { type: 'checkbox', id, checked: !!value, onchange: (e) => { obj[f.key] = e.target.checked; } });
    }
    if (f.type === 'enum') {
        return el('select', {
            id, class: 'form-select',
            onchange: (e) => { obj[f.key] = e.target.value; renderParamsForm(); } // могут появиться/скрыться зависимые поля
        }, ...f.options.map(o => el('option', { value: o.value, selected: String(value ?? '') === o.value }, o.label)));
    }
    if (f.type === 'int' || f.type === 'number') {
        return el('input', {
            id, type: 'number', value: value ?? '', min: f.min, max: f.max,
            step: f.type === 'int' ? '1' : 'any',
            placeholder: f.default !== undefined ? String(f.default) : '',
            oninput: (e) => {
                const v = e.target.value;
                if (v === '') delete obj[f.key]; else obj[f.key] = Number(v);
            }
        });
    }
    const attrs = {
        id, value: toEditable(value), placeholder: f.placeholder || '',
        class: (f.type === 'text' || f.regex || f.hex) ? 'mono' : '',
        oninput: (e) => { obj[f.key] = e.target.value; }
    };
    const input = f.type === 'text' ? el('textarea', { ...attrs, rows: 3 }) : el('input', { ...attrs, type: 'text' });
    input.spellcheck = false;
    return input;
}

function renderField(f, obj, path) {
    if (f.type === 'list') return renderList(f, obj, path);

    const id = fieldId(path, f);
    const help = f.help ? el('p', { class: 'field-help' }, f.help) : null;
    if (f.type === 'bool') {
        return el('div', { class: 'form-group span-all' },
            el('div', { class: 'checkbox-group' }, fieldInput(f, obj, id), el('label', { htmlFor: id }, f.title)), help);
    }
    return el('div', { class: 'form-group' + (f.type === 'text' ? ' span-all' : '') },
        el('label', { htmlFor: id }, f.title), fieldInput(f, obj, id), help);
}

// Список (правила, маршруты, токены) — таблица: строка на элемент, короткие поля — колонки.
// Длинный текст и редкие поля открываются под строкой кнопкой «Ещё».
function renderList(f, obj, path) {
    const items = Array.isArray(obj[f.key]) ? obj[f.key] : (obj[f.key] = []);
    const itemFields = f.item || [];
    const cols = itemFields.filter(x => !x.advanced && x.type !== 'text' && x.type !== 'list');
    const extra = itemFields.filter(x => !cols.includes(x));
    const itemTitle = f.itemTitle || 'Элемент';
    const colCount = cols.length + 2;

    const head = el('tr', {},
        el('th', { class: 'col-num' }, '#'),
        ...cols.map(c => el('th', { class: `col-${c.type}`, title: c.help || '' }, c.column || c.title)),
        el('th', { class: 'col-actions' }));

    const body = el('tbody');
    items.forEach((item, i) => {
        const itemPath = `${path}${f.key}[${i}].`;
        const move = (j) => () => { [items[i], items[j]] = [items[j], items[i]]; renderParamsForm(); };
        const open = paramForm.expanded.has(item);
        const extraVisible = extra.filter(x => isVisible(x, item));

        const actions = el('td', { class: 'col-actions' });
        if (extraVisible.length) {
            actions.append(el('button', {
                type: 'button', class: 'table-btn' + (open ? ' active' : ''),
                title: extraVisible.map(x => x.title).join(', '),
                onclick: () => { open ? paramForm.expanded.delete(item) : paramForm.expanded.add(item); renderParamsForm(); }
            }, `${t('Ещё')} ${open ? '▴' : '▾'}`));
        }
        actions.append(
            el('button', { type: 'button', class: 'table-btn', title: t('Выше'), disabled: i === 0, onclick: move(i - 1) }, '↑'),
            el('button', { type: 'button', class: 'table-btn', title: t('Ниже'), disabled: i === items.length - 1, onclick: move(i + 1) }, '↓'),
            el('button', { type: 'button', class: 'table-btn danger', title: t('Удалить'), onclick: () => { items.splice(i, 1); renderParamsForm(); } }, '✕'));

        body.append(el('tr', { class: open ? 'is-open' : '' },
            el('td', { class: 'col-num' }, String(i + 1)),
            ...cols.map(c => {
                if (!isVisible(c, item)) return el('td', { class: `col-${c.type}` });
                const input = fieldInput(c, item, fieldId(itemPath, c));
                input.setAttribute('aria-label', `${itemTitle} ${i + 1}: ${c.title}`);
                return el('td', { class: `col-${c.type}` }, input);
            }),
            actions));

        if (open && extraVisible.length) {
            body.append(el('tr', { class: 'row-extra' },
                el('td', { colSpan: colCount },
                    el('div', { class: 'form-grid' }, ...extraVisible.map(x => renderField(x, item, itemPath))))));
        }
    });
    if (!items.length) {
        body.append(el('tr', {}, el('td', { class: 'table-empty', colSpan: colCount }, t('Пока пусто.'))));
    }

    const colHelp = cols.filter(c => c.help);
    return el('div', { class: 'form-group span-all param-list' },
        el('div', { class: 'param-list-head' },
            el('span', { class: 'param-list-title' }, `${f.title} (${items.length})`),
            el('button', {
                type: 'button', class: 'btn btn-secondary btn-small',
                onclick: () => { items.push(fillDefaults(f.item, {})); renderParamsForm(); }
            }, `+ ${t('Добавить')}`)),
        f.help ? el('p', { class: 'field-help' }, f.help) : null,
        el('div', { class: 'table-scroll' }, el('table', { class: 'param-table' }, el('thead', {}, head), body)),
        colHelp.length ? el('dl', { class: 'col-help' },
            ...colHelp.flatMap(c => [el('dt', {}, c.column || c.title), el('dd', {}, c.help)])) : null);
}

function showTrapFormError(message) {
    const box = document.getElementById('trap-form-error');
    if (!box) return;
    box.textContent = message || '';
    box.hidden = !message;
}

// «invalid params: rules[0].match: …» → «Правила ответа › Правило 1 › Если клиент прислал (regex) — …»
function humanizeParamError(message) {
    const m = /^invalid params: ([^:]+): (.*)$/.exec(message || '');
    if (!m) return message;
    let fields = (currentClass() || {}).fields || [];
    const parts = [];
    for (const seg of m[1].split('.')) {
        const mm = /^([^[]+)(?:\[(\d+)\])?$/.exec(seg);
        const f = mm ? fields.find(x => x.key === mm[1]) : null;
        parts.push(f ? f.title : seg);
        if (mm && mm[2] !== undefined) parts.push(`${(f && f.itemTitle) || 'элемент'} ${Number(mm[2]) + 1}`);
        fields = (f && f.item) || [];
    }
    return `${t('Ошибка в параметрах')}: ${parts.join(' › ')} — ${m[2]}`;
}

// Переключение «форма ⇄ JSON». Из JSON обратно — только если он корректный.
function setParamsMode(json) {
    const ta = document.getElementById('trap-params');
    if (json) {
        ta.value = JSON.stringify(paramForm.params, null, 2);
    } else if (paramForm.jsonMode) {
        let parsed;
        try {
            parsed = JSON.parse(ta.value || '{}');
        } catch (e) {
            showTrapFormError(t('Параметры должны быть корректным JSON.'));
            return false;
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            showTrapFormError(t('Параметры должны быть JSON-объектом.'));
            return false;
        }
        paramForm.params = fillDefaults((currentClass() || {}).fields, parsed);
    }
    paramForm.jsonMode = json;
    ta.hidden = !json;
    document.getElementById('params-form').hidden = json;
    document.getElementById('params-mode-btn').textContent = json ? t('Вернуться к форме') : t('Редактировать как JSON');
    showTrapFormError('');
    if (!json) renderParamsForm();
    return true;
}

// Сбросить в режим формы без разбора JSON (смена класса или шаблона).
function resetParamsView() {
    paramForm.jsonMode = true;
    document.getElementById('trap-params').value = JSON.stringify(paramForm.params);
    setParamsMode(false);
}

// Описание класса под селектами: уровень уже виден в названии варианта.
function setClassHelp(classId) {
    const help = document.getElementById('trap-class-help');
    const c = state.classes.find(cls => cls.id === classId);
    if (help) help.textContent = c ? c.description : '';
}

// Заполняет селект классов. Класс нельзя менять у существующей ловушки.
function populateClassSelect(selectedClass) {
    const sel = document.getElementById('trap-class');
    if (!sel) return;
    sel.innerHTML = state.classes.map(c =>
        `<option value="${c.id}">[${escapeHtml(c.level || 'Low')}] ${escapeHtml(c.title)}</option>`).join('');
    if (selectedClass) sel.value = selectedClass;
}

// Шаблоны, подходящие выбранному классу.
function populatePresetSelect(classId) {
    const sel = document.getElementById('trap-preset');
    if (!sel) return;
    const matching = state.presets.filter(p => p.class === classId);
    const others = state.presets.filter(p => p.class !== classId);

    let html = `<option value="">— Без шаблона —</option>`;
    if (matching.length > 0) {
        html += `<optgroup label="Шаблоны для этого класса">` +
            matching.map(p => {
                const c = state.classes.find(cls => cls.id === p.class);
                const lvl = (c && c.level) || p.level || '';
                const tag = lvl ? `[${lvl}] ` : '';
                return `<option value="${escapeHtml(p.presetId)}">${tag}${escapeHtml(p.name)}</option>`;
            }).join('') + `</optgroup>`;
    }
    if (others.length > 0) {
        html += `<optgroup label="Шаблоны других классов">` +
            others.map(p => {
                const c = state.classes.find(cls => cls.id === p.class);
                const lvl = (c && c.level) || p.level || '';
                const tag = lvl ? `[${lvl}] ` : '';
                return `<option value="${escapeHtml(p.presetId)}">${tag}${escapeHtml(p.name)} (${escapeHtml((c && c.title) || p.class)})</option>`;
            }).join('') + `</optgroup>`;
    }
    sel.innerHTML = html;
    sel.value = '';
}

// Класс многопортовый? (port_listener). Переключает поля порт/порты.
function classIsMultiPort(classId) {
    const c = state.classes.find(c => c.id === classId);
    return !!(c && c.multiPort);
}

function togglePortFields(classId) {
    const multi = classIsMultiPort(classId);
    document.getElementById('trap-port-group').style.display = multi ? 'none' : '';
    document.getElementById('trap-ports-group').style.display = multi ? '' : 'none';
}

function applyClassDefaults(classId) {
    paramForm.classId = classId;
    const c = currentClass();
    setClassHelp(classId);
    togglePortFields(classId);
    if (c && c.defaultPort) document.getElementById('trap-port').value = c.defaultPort;
    if (c && c.defaultPorts) document.getElementById('trap-ports').value = c.defaultPorts;

    paramForm.params = fillDefaults(c ? c.fields : [], parseParams(c && c.defaultParams));
    paramForm.advOpen.clear();
    populatePresetSelect(classId);
    resetParamsView();
}

function applyPreset(presetId) {
    const p = state.presets.find(p => p.presetId === presetId);
    if (!p) return;
    if (p.class && p.class !== paramForm.classId) {
        const classSel = document.getElementById('trap-class');
        if (classSel && !classSel.disabled) {
            classSel.value = p.class;
            paramForm.classId = p.class;
            setClassHelp(p.class);
            togglePortFields(p.class);
            populatePresetSelect(p.class);
            document.getElementById('trap-preset').value = presetId;
        }
    }
    if (p.port) document.getElementById('trap-port').value = p.port;
    if (p.ports) document.getElementById('trap-ports').value = p.ports;
    paramForm.params = fillDefaults((currentClass() || {}).fields, parseParams(p.params));
    const nameInput = document.getElementById('trap-name');
    if (!nameInput.value.trim() || state.presets.some(pr => pr.name === nameInput.value.trim())) {
        nameInput.value = p.name;
    }
    resetParamsView();
}

// Заполняет выбор хоста в форме ловушки.
function populateHostSelect(selected) {
    const sel = document.getElementById('trap-host');
    if (!sel) return;
    sel.innerHTML = `<option value="">${t('— Без хоста —')}</option>`
        + state.hosts.map(h => `<option value="${h.id}">${escapeHtml(h.name)} (${escapeHtml(h.address)})</option>`).join('');
    sel.value = selected != null && hostById(selected) ? String(selected) : '';
}

function selectedHostId() {
    const v = document.getElementById('trap-host').value;
    return v ? Number(v) : null;
}

function openTrapModal(mode, trapId = null) {
    const titleEl = document.getElementById('trap-modal-title');
    const formEl = document.getElementById('create-trap-form');
    const classSel = document.getElementById('trap-class');
    const presetGroup = document.getElementById('trap-preset-group');
    showTrapFormError('');

    if (mode === 'edit' && trapId !== null) {
        const trap = state.traps.find(t => t.id === trapId);
        if (!trap) return;

        state.editingTrapId = trapId;
        if (titleEl) titleEl.textContent = t('Редактирование ловушки');

        populateClassSelect(trap.class);
        classSel.disabled = true;            // класс менять нельзя — проще пересоздать
        if (presetGroup) presetGroup.style.display = 'none';

        paramForm.classId = trap.class;
        const c = currentClass();
        setClassHelp(trap.class);
        togglePortFields(trap.class);

        populateHostSelect(trap.hostId);
        document.getElementById('trap-name').value  = trap.name || '';
        document.getElementById('trap-bind').value  = trap.bind || '0.0.0.0';
        document.getElementById('trap-port').value  = trap.port || '';
        document.getElementById('trap-ports').value = trap.ports || '';
        document.getElementById('trap-active').checked = !!trap.enabled;

        paramForm.params = fillDefaults(c ? c.fields : [], parseParams(trap.params));
        paramForm.advOpen.clear();
        resetParamsView();
    } else {
        state.editingTrapId = null;
        if (titleEl) titleEl.textContent = t('Создание новой ловушки');
        formEl.reset();
        classSel.disabled = false;
        if (presetGroup) presetGroup.style.display = '';
        populateClassSelect();
        applyClassDefaults(classSel.value);
        populateHostSelect(typeof state.currentHostId === 'number' ? state.currentHostId : null);
        document.getElementById('trap-bind').value = '0.0.0.0';
        document.getElementById('trap-active').checked = true;
    }

    openModal('create-trap-modal');
}

// Окно «ловушка создана»: для ловушки на хосте — предложить применить изменения,
// для ловушки без хоста — ручной запуск агента с конфигом.
function showCreatedModal(trap) {
    state.lastCreatedTrap = trap;
    const host = trap.hostId != null ? hostById(trap.hostId) : null;
    document.getElementById('created-hosted').hidden = !host;
    document.getElementById('created-loose').hidden = !!host;
    if (host) {
        document.getElementById('created-hosted-text').textContent =
            t('Ловушка добавлена на хост «{host}». Она заработает после того, как вы примените изменения на сервере.')
                .replace('{host}', host.name);
    } else {
        document.getElementById('created-token').value = trap.token || '';
        document.getElementById('download-config-btn').href = `${CONFIG.API_BASE_URL}/traps/${trap.id}/config`;
        document.getElementById('download-bundle-btn').href = `${CONFIG.API_BASE_URL}/traps/${trap.id}/bundle`;
    }
    openModal('trap-created-modal');
}

// ---------- Хосты: навигация ----------

// Открыть хост (число), ловушки без хоста ('none') или список (null). Адрес
// страницы (#host-3) запоминает выбор, чтобы обновление страницы его не сбрасывало.
function setCurrentHost(id) {
    state.currentHostId = id;
    state.selectedTrapId = null;
    const hash = id === null ? '' : `#host-${id}`;
    if (window.location.hash !== hash) {
        history.replaceState(null, '', hash || window.location.pathname + window.location.search);
    }
}

function hostFromHash() {
    const m = /^#host-(\d+|none)$/.exec(window.location.hash);
    if (!m) return null;
    return m[1] === 'none' ? 'none' : Number(m[1]);
}

function openHost(id) {
    setCurrentHost(id);
    renderAll();
    window.scrollTo(0, 0);
}

// ---------- Хосты: окно создания / изменения ----------

function showHostFormError(message) {
    const el = document.getElementById('host-form-error');
    if (!el) return;
    el.textContent = message || '';
    el.hidden = !message;
}

function setHostAuthType(type) {
    const isKey = type === 'key';
    document.getElementById(isKey ? 'host-auth-key-radio' : 'host-auth-password-radio').checked = true;
    document.getElementById('host-password-group').style.display = isKey ? 'none' : '';
    document.getElementById('host-key-group').style.display = isKey ? '' : 'none';
}

function openHostModal(hostId = null) {
    const host = hostId !== null ? hostById(hostId) : null;
    state.editingHostId = host ? host.id : null;
    document.getElementById('host-form').reset();
    showHostFormError('');

    document.getElementById('host-modal-title').textContent = t(host ? 'Изменение хоста' : 'Новый хост');
    document.getElementById('host-name').value = host ? host.name : '';
    document.getElementById('host-address').value = host ? host.address : '';
    document.getElementById('host-port').value = String(host ? host.sshPort : 22);
    document.getElementById('host-username').value = host ? host.username : 'root';
    setHostAuthType(host ? host.authType : 'password');
    document.getElementById('host-use-sudo').checked = !!(host && host.useSudo);
    document.getElementById('host-sudo-password-group').style.display = host && host.useSudo ? '' : 'none';

    // Сохранённые секреты в браузер не приходят: поле пустое, подсказка говорит, что он есть.
    const savedHint = t('Сохранён — оставьте пустым, чтобы не менять');
    document.getElementById('host-password').placeholder = host && host.hasPassword ? savedHint : t('Введите пароль пользователя SSH');
    document.getElementById('host-key').placeholder = host && host.hasPrivateKey
        ? savedHint
        : '-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----';
    document.getElementById('host-sudo-password').placeholder = host && host.hasSudoPassword ? savedHint : t('Оставьте пустым, если совпадает с паролем SSH');

    openModal('host-modal');
    document.getElementById('host-name').focus();
}

async function handleSubmitHost(event) {
    event.preventDefault();
    showHostFormError('');
    const editing = state.editingHostId !== null;
    const host = editing ? hostById(state.editingHostId) : null;
    const authType = document.querySelector('input[name="host-auth-type"]:checked')?.value || 'password';
    const password = document.getElementById('host-password').value;
    const privateKey = document.getElementById('host-key').value.trim();

    const body = {
        name: document.getElementById('host-name').value.trim(),
        address: document.getElementById('host-address').value.trim(),
        sshPort: parseInt(document.getElementById('host-port').value, 10) || 22,
        username: document.getElementById('host-username').value.trim(),
        authType,
        useSudo: document.getElementById('host-use-sudo').checked
    };
    // Пустой секрет не отправляем: при изменении хоста это значит «оставить сохранённый».
    if (authType === 'password' && password) body.password = password;
    if (authType === 'key' && privateKey) body.privateKey = privateKey;
    const sudoPassword = document.getElementById('host-sudo-password').value;
    if (body.useSudo && sudoPassword) body.sudoPassword = sudoPassword;

    // Без секрета для выбранного способа входа сервер всё равно откажет — скажем сразу.
    if (authType === 'password' && !password && !(host && host.hasPassword)) {
        showHostFormError(t('Введите пароль SSH.'));
        return;
    }
    if (authType === 'key' && !privateKey && !(host && host.hasPrivateKey)) {
        showHostFormError(t('Вставьте приватный SSH-ключ.'));
        return;
    }

    const submitBtn = document.getElementById('host-submit-btn');
    submitBtn.disabled = true;
    try {
        const saved = editing ? await api.updateHost(state.editingHostId, body) : await api.createHost(body);
        closeModal('host-modal');
        document.getElementById('host-form').reset();
        await refreshAll();
        if (!editing && saved && saved.id) openHost(saved.id);
    } catch (err) {
        console.error('[handleSubmitHost]', err);
        showHostFormError(getErrorMessage(err, 'Не удалось сохранить хост.'));
    } finally {
        submitBtn.disabled = false;
    }
}

// ---------- Хосты: операции по SSH ----------

// Выполняет операцию над хостом, показывая ход и итог в строке под шапкой хоста.
async function runHostOp(hostId, kind, loadingText, run, describe, errKey) {
    if (state.hostOps[hostId]) return;
    state.hostOps[hostId] = kind;
    state.hostOpResult = { hostId, kind: 'loading', text: t(loadingText) };
    renderHostView();
    try {
        const res = await run();
        state.hostOpResult = { hostId, ...describe(res) };
    } catch (err) {
        console.error(`[host ${kind}]`, err);
        state.hostOpResult = { hostId, kind: 'error', text: `${t(errKey)}: ${getErrorMessage(err, errKey)}` };
    } finally {
        delete state.hostOps[hostId];
    }
    await refreshAll();
}

function deployHost(hostId) {
    return runHostOp(hostId, 'deploy', 'Развёртывание агента: загрузка, настройка systemd, запуск...',
        () => api.deployHost(hostId),
        res => ({ kind: 'success', text: t('Агент развёрнут. Ловушек запущено: {n}.').replace('{n}', res && res.traps != null ? res.traps : '?') }),
        'Ошибка развертывания');
}

function undeployHost(hostId) {
    const host = hostById(hostId);
    if (!host) return;
    if (!confirm(t('Снять агента с хоста «{name}»? Все ловушки этого хоста перестанут работать.').replace('{name}', host.name))) return;
    return runHostOp(hostId, 'undeploy', 'Остановка агента и удаление его файлов с сервера...',
        () => api.undeployHost(hostId),
        () => ({ kind: 'success', text: t('Агент снят с сервера: служба остановлена, файлы удалены.') }),
        'Ошибка снятия агента');
}

function checkHostStatus(hostId) {
    return runHostOp(hostId, 'status', 'Подключение к серверу и проверка агента...',
        () => api.getHostStatus(hostId),
        st => {
            const svc = (st && st.subState) || '?';
            if (!st || !st.active) {
                return { kind: 'error', text: t('Агент не работает (служба {state}).').replace('{state}', svc) };
            }
            const missing = st.missingPorts || [];
            const ports = missing.length
                ? t('Не слушаются порты: {ports}.').replace('{ports}', missing.join(', '))
                : t('Все порты ловушек открыты.');
            return {
                kind: missing.length ? 'error' : 'success',
                text: `${t('Агент работает (служба {state}).').replace('{state}', svc)} ${ports}`
            };
        },
        'Ошибка проверки статуса');
}

async function handleDeleteHost(hostId) {
    const host = hostById(hostId);
    if (!host) return;
    if (!confirm(t('Удалить хост «{name}»? Его ловушки останутся в разделе «Без хоста».').replace('{name}', host.name))) return;
    try {
        try {
            await api.deleteHost(hostId);
        } catch (err) {
            // Агент ещё стоит на сервере: удалять хост без снятия — только по явному согласию.
            if (err.status !== 409 || err.data?.error !== 'host is deployed; remove the agent first') throw err;
            if (!confirm(t('На сервере всё ещё работает агент этого хоста. Удалить хост, не снимая агента? Управлять им из центра будет нельзя.'))) return;
            await api.deleteHost(hostId, { force: true });
        }
        if (state.hostOpResult && state.hostOpResult.hostId === hostId) state.hostOpResult = null;
        setCurrentHost(null);
        await refreshAll();
    } catch (err) {
        console.error('[handleDeleteHost]', err);
        alert(getErrorMessage(err, 'Не удалось удалить хост.'));
    }
}

// 8. ПЕРЕКЛЮЧЕНИЕ ВКЛАДОК

async function switchTab(tabId, clickedLink) {
    state.currentTab = tabId;

    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    clickedLink.classList.add('active');

    document.querySelectorAll('.tab-content').forEach(s => s.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');

    updateBreadcrumb();
    hideChartTip();

    // скрытая вкладка имеет нулевую ширину — график активности рисуем, когда она видна
    if (tabId === 'stats') renderDashboard();

    // Специфика вкладки "События"
    if (tabId === 'events') {
        renderEventsSelect();
        const select = document.getElementById('events-trap-select');
        const currentId = select && select.value ? Number(select.value) : null;

        if (currentId) {
            await loadAndRenderEvents(currentId);
        } else {
            const listEl = document.getElementById('events-list');
            if (listEl) listEl.innerHTML = `<p class="no-events">${t('Выберите ловушку')}</p>`;
        }
    }
}

// Загружает и рендерит события для конкретной ловушки
// silent — фоновое обновление: без плейсхолдера загрузки и без затирания списка при ошибке.
async function loadAndRenderEvents(trapId, { silent = false } = {}) {
    const listEl = document.getElementById('events-list');
    if (!listEl) return;

    if (!trapId) {
        listEl.innerHTML = `<p class="no-events">${t('Выберите ловушку')}</p>`;
        return;
    }

    if (!silent) listEl.innerHTML = `<p class="no-events">${t('Загрузка...')}</p>`;

    // пока шёл запрос, пользователь мог выбрать другую ловушку — тогда ответ устарел
    const isStillSelected = () => {
        const select = document.getElementById('events-trap-select');
        return !select || select.value === String(trapId);
    };

    try {
        const events = await api.getTrapEvents(trapId, state.eventTypeFilter) || [];
        if (isStillSelected()) renderEvents(events);
    } catch (err) {
        console.error('[loadAndRenderEvents]', err);
        if (!silent && isStillSelected()) {
            listEl.innerHTML = `<p class="no-events">${t('Не удалось загрузить события.')}</p>`;
        }
    }
}

// 9. ОБРАБОТЧИКИ ФОРМ И ДЕЙСТВИЙ

async function handleSubmitTrap(event) {
    event.preventDefault();
    showTrapFormError('');

    const classId = document.getElementById('trap-class').value;
    const multi = classIsMultiPort(classId);

    // В режиме JSON берём текст, иначе — объект, который правит форма.
    if (paramForm.jsonMode && !setParamsMode(false)) return;
    const params = paramForm.params;

    const payload = {
        hostId:  selectedHostId(),
        name:    document.getElementById('trap-name').value.trim(),
        class:   classId,
        bind:    document.getElementById('trap-bind').value.trim() || '0.0.0.0',
        port:    multi ? 0 : Number(document.getElementById('trap-port').value || 0),
        ports:   multi ? document.getElementById('trap-ports').value.trim() : '',
        params,
        enabled: document.getElementById('trap-active').checked
    };

    try {
        if (state.editingTrapId !== null) {
            // класс не меняем; отправляем изменяемые поля
            const patch = { hostId: payload.hostId, name: payload.name, bind: payload.bind, params, enabled: payload.enabled };
            if (multi) patch.ports = payload.ports; else patch.port = payload.port;
            await api.updateTrap(state.editingTrapId, patch);
            closeModal('create-trap-modal');
            state.editingTrapId = null;
            await refreshAll();
        } else {
            const created = await api.createTrap(payload);
            closeModal('create-trap-modal');
            document.getElementById('create-trap-form').reset();
            await refreshAll();
            if (created && created.id) showCreatedModal(created);
        }
    } catch (err) {
        console.error('[handleSubmitTrap]', err);
        const fallback = state.editingTrapId !== null
            ? 'Не удалось обновить ловушку.'
            : 'Не удалось создать ловушку.';
        showTrapFormError(humanizeParamError(getErrorMessage(err, fallback)));
    }
}

//удаление выбранной ловушки..надеюсь только ловушк
async function handleDeleteTrap() {
    if (state.selectedTrapId === null) return;

    const trap = state.traps.find(tr => tr.id === state.selectedTrapId);
    const question = t('Удалить ловушку «{name}» вместе со всеми её событиями?')
        .replace('{name}', trap ? trap.name : state.selectedTrapId);
    if (!confirm(question)) return;

    try {
        await api.deleteTrap(state.selectedTrapId);
        state.selectedTrapId = null;
        await refreshAll();
    } catch (err) {
        console.error('[handleDeleteTrap]', err);
        alert(getErrorMessage(err, 'Не удалось удалить ловушку.'));
    }
}

// Кнопка "события" над ловушками переключает на "События"
async function handleShowEvents() {
    if (state.selectedTrapId === null) return;

    const eventsLink = document.querySelector('.nav-link[data-tab="events"]');
    if (!eventsLink) return;

    // switchTab сам подтянет selectedTrapId и загрузит события
    await switchTab('events', eventsLink);
}

// Человекочитаемая строка-деталь события из его полей data/username/password.
function eventDetail(ev) {
    const d = ev.data || {};
    switch (ev.type) {
        case 'auth':
            return `логин: ${ev.username ?? '∅'} · пароль: ${ev.password ?? '∅'}`;
        case 'command':
            return d.line ? `команда: ${d.line}` : '';
        case 'request':
            return [d.method, d.path].filter(Boolean).join(' ') + (d.user_agent ? ` · UA: ${d.user_agent}` : '');
        case 'scan':
            return `порты: ${(d.ports || []).join(', ')}`;
        case 'token':
            return `сработал токен ${d.label || d.token || ''}`;
        case 'handshake':
            return d.telnet_options ? `telnet: ${d.telnet_options.join(', ')}` : JSON.stringify(d);
        case 'disconnect':
            return `длительность: ${d.duration ?? '?'}с · принято байт: ${d.bytes_in ?? 0}`;
        case 'data':
            return d.text || d.hex || '';
        default:
            return d.text || '';
    }
}

// вот это рисует список событий
function renderEvents(events) {
    const listEl = document.getElementById('events-list');
    if (!listEl) return;

    if (!events.length) {
        listEl.innerHTML = `<p class="no-events">${t('Нет событий')}</p>`;
        return;
    }

    listEl.innerHTML = events.map(ev => {
        const typeLabel = t(EVENT_TYPE_LABELS[ev.type] || ev.type);
        const src = ev.source ? `${ev.source}${ev.srcPort ? ':' + ev.srcPort : ''}` : '';
        const proto = ev.proto && ev.proto !== 'tcp' ? ` [${escapeHtml(ev.proto)}]` : '';
        const warn = ['auth', 'scan', 'token'].includes(ev.type) ? ' event-warn' : '';
        return `
            <div class="event-item${warn}">
                <div class="event-head">
                    <span class="event-type">${escapeHtml(typeLabel)}${proto}</span>
                    <span class="event-time">${escapeHtml(ev.time || '')}</span>
                </div>
                <div class="event-source">${escapeHtml(src)}${ev.dstPort ? ' → :' + escapeHtml(ev.dstPort) : ''}</div>
                <div class="event-detail">${escapeHtml(eventDetail(ev))}</div>
            </div>
        `;
    }).join('');
}

// снова работа с бэком: обирает данные, отправляет на бэк, сохраняет токен, обновляет UI.
async function handleLogin(event) {
    event.preventDefault();
    showAuthError('');
    const form = event.target;
    const credentials = {
        username: form.username.value.trim(),
        password: form.password.value
    };

    try {
        const result = await api.login(credentials);
        if (result && result.user) {
            state.user = result.user;
        }
        applyUserMenu();
        closeModal('auth-modal');
        form.reset();
        window.location.href = '/dashboard.html';
    } catch (err) {
        console.error('[handleLogin]', err);
        const errMsg = getErrorMessage(err, 'Неверный логин или пароль.');
        showAuthError(errMsg);
    }
}

// дополнение к предыдущему
async function handleRegister(event) {
    event.preventDefault();
    showAuthError('');
    const form = event.target;
    const data = {
        username: form.username.value.trim(),
        email:    form.email.value.trim(),
        password: form.password.value
    };

    try {
        const result = await api.register(data);
        if (result && result.user) {
            state.user = result.user;
        }
        applyUserMenu();
        closeModal('auth-modal');
        form.reset();
        window.location.href = '/dashboard.html';
    } catch (err) {
        console.error('[handleRegister]', err);
        const errMsg = getErrorMessage(err, 'Не удалось зарегистрироваться.');
        showAuthError(errMsg);
    }
}

// Выход из системы
async function handleLogout() {
    try {
        await api.logout();
    } catch (err) {
        console.error('[handleLogout]', err);
    }
    state.user = null;
    window.location.href = '/login.html';
}

// должно восстанавливать сессию пользователя при загрузке страницы
async function restoreSession() {
    try {
        const user = await api.me();
        if (user) {
            state.user = user;
            applyUserMenu();
            return user;
        }
    } catch (err) {
        console.error('[restoreSession]', err);
    }
    return null;
}


// 10. ИНИЦИАЛИЗАЦИЯ

document.addEventListener('DOMContentLoaded', async () => {

    // Восстановление темы и языка ДО первого рендера
    try {
        localStorage.removeItem(CONFIG.LEGACY_TOKEN_KEY);

        const savedTheme = localStorage.getItem(CONFIG.THEME_KEY);
        const themeToggle = document.getElementById('theme-toggle');
        if (savedTheme === 'light') {
            document.body.classList.remove('dark-theme');
            if (themeToggle) themeToggle.checked = false;
        } else if (savedTheme === 'dark') {
            document.body.classList.add('dark-theme');
            if (themeToggle) themeToggle.checked = true;
        }

        const savedLang = localStorage.getItem(CONFIG.LANG_KEY);
        if (savedLang === 'en' || savedLang === 'ru') {
            state.currentLang = savedLang;
            const el = document.getElementById('lang-switch');
            if (el) el.value = savedLang;
        }
        const savedRange = localStorage.getItem(CONFIG.DASH_RANGE_KEY);
        if (RANGE_LABELS[savedRange]) state.dashRange = savedRange;
    } catch (e) { /* localStorage может быть выключен */ }

    initDashboard();

    // --- Вкладки ---
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab(link.getAttribute('data-tab'), link);
        });
    });

    // --- Тема ---
    const themeToggleEl = document.getElementById('theme-toggle');
    if (themeToggleEl) {
        themeToggleEl.addEventListener('change', (e) => {
            const isDark = e.target.checked;
            document.body.classList.toggle('dark-theme', isDark);
            try { localStorage.setItem(CONFIG.THEME_KEY, isDark ? 'dark' : 'light'); } catch (err) {}
        });
    }

    // --- Язык ---
    const langSwitchEl = document.getElementById('lang-switch');
    if (langSwitchEl) {
        langSwitchEl.addEventListener('change', (e) => {
            setLanguage(e.target.value);
        });
    }

    // --- Выбор ловушки кликом ---
    const trapsListEl = document.getElementById('traps-list-container');
    if (trapsListEl) {
        trapsListEl.addEventListener('click', (e) => {
            const trapEl = e.target.closest('.trap-item');
            if (!trapEl) return;

            const trapId = Number(trapEl.dataset.trapId);
            state.selectedTrapId = state.selectedTrapId === trapId ? null : trapId;

            renderTraps();
            updateTrapActions();
        });
    }

    // --- Селект ловушек на вкладке «События» ---
    const eventsSelectEl = document.getElementById('events-trap-select');
    if (eventsSelectEl) {
        eventsSelectEl.addEventListener('change', async (e) => {
            const trapId = e.target.value ? Number(e.target.value) : null;
            state.selectedTrapId = trapId;

            // Обновляем состояние кнопок и подсветку на вкладке «Ловушки»
            renderTraps();
            updateTrapActions();

            if (trapId) {
                await loadAndRenderEvents(trapId);
            } else {
                const listEl = document.getElementById('events-list');
                if (listEl) listEl.innerHTML = `<p class="no-events">${t('Выберите ловушку')}</p>`;
            }
        });
    }

    // --- Фильтр типа на вкладке «События» ---
    const eventsTypeEl = document.getElementById('events-type-select');
    if (eventsTypeEl) {
        eventsTypeEl.addEventListener('change', async (e) => {
            state.eventTypeFilter = e.target.value;
            const sel = document.getElementById('events-trap-select');
            const trapId = sel && sel.value ? Number(sel.value) : null;
            if (trapId) await loadAndRenderEvents(trapId);
        });
    }

    // --- Форма параметров: переключатель «форма ⇄ JSON» ---
    const paramsModeBtn = document.getElementById('params-mode-btn');
    if (paramsModeBtn) {
        paramsModeBtn.addEventListener('click', () => setParamsMode(!paramForm.jsonMode));
    }

    // --- Форма создания: класс и шаблон ---
    const classSelEl = document.getElementById('trap-class');
    if (classSelEl) {
        classSelEl.addEventListener('change', (e) => applyClassDefaults(e.target.value));
    }
    const presetSelEl = document.getElementById('trap-preset');
    if (presetSelEl) {
        presetSelEl.addEventListener('change', (e) => applyPreset(e.target.value));
    }

    // --- Кнопки действий над ловушкой ---
    const createBtn = document.getElementById('open-create-trap-btn');
    if (createBtn) {
        createBtn.addEventListener('click', () => {
            openTrapModal('create');
        });
    }

    const editBtn = document.getElementById('open-edit-trap-btn');
    if (editBtn) {
        editBtn.addEventListener('click', () => {
            if (state.selectedTrapId === null) return;
            openTrapModal('edit', state.selectedTrapId);
        });
    }

    const deleteBtn = document.getElementById('delete-trap-btn');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', () => {
            if (state.selectedTrapId === null) return;
            handleDeleteTrap();
        });
    }

    const eventsBtn = document.getElementById('open-events-trap-btn');
    if (eventsBtn) {
        eventsBtn.addEventListener('click', () => {
            if (state.selectedTrapId === null) return;
            handleShowEvents();
        });
    }

    const createdApplyBtn = document.getElementById('created-apply-btn');
    if (createdApplyBtn) {
        createdApplyBtn.addEventListener('click', () => {
            const trap = state.lastCreatedTrap;
            closeModal('trap-created-modal');
            if (trap && trap.hostId != null) {
                openHost(trap.hostId);
                deployHost(trap.hostId);
            }
        });
    }

    // --- Хосты: список и навигация ---
    const hostsListEl = document.getElementById('hosts-list-container');
    if (hostsListEl) {
        hostsListEl.addEventListener('click', (e) => {
            const card = e.target.closest('.host-item');
            if (!card) return;
            const id = card.dataset.hostId;
            openHost(id === 'none' ? 'none' : Number(id));
        });
    }

    const hostsSearchEl = document.getElementById('hosts-search');
    if (hostsSearchEl) {
        hostsSearchEl.addEventListener('input', (e) => {
            state.hostSearch = e.target.value;
            renderHosts();
        });
    }

    const backToHostsEl = document.getElementById('back-to-hosts');
    if (backToHostsEl) {
        backToHostsEl.addEventListener('click', (e) => {
            e.preventDefault();
            openHost(null);
        });
    }

    // Кнопки «назад/вперёд» браузера и ручная правка адреса.
    window.addEventListener('hashchange', () => {
        const id = hostFromHash();
        if (id !== state.currentHostId) openHost(id);
    });

    // --- Хосты: кнопки ---
    const onCurrentHost = (fn) => () => {
        if (typeof state.currentHostId === 'number') fn(state.currentHostId);
    };
    const hostButtons = {
        'open-create-host-btn': () => openHostModal(),
        'host-edit-btn': onCurrentHost(openHostModal),
        'host-deploy-btn': onCurrentHost(deployHost),
        'host-undeploy-btn': onCurrentHost(undeployHost),
        'host-status-btn': onCurrentHost(checkHostStatus),
        'host-delete-btn': onCurrentHost(handleDeleteHost),
        // Скачивание по ссылке: файл отдаётся с Content-Disposition: attachment.
        'host-config-btn': onCurrentHost(id => { window.location.href = `${CONFIG.API_BASE_URL}/hosts/${id}/config`; })
    };
    for (const [id, handler] of Object.entries(hostButtons)) {
        const btn = document.getElementById(id);
        if (btn) btn.addEventListener('click', handler);
    }

    // --- Окно хоста: способ входа и sudo ---
    document.querySelectorAll('input[name="host-auth-type"]').forEach(radio => {
        radio.addEventListener('change', (e) => setHostAuthType(e.target.value));
    });
    const hostSudoEl = document.getElementById('host-use-sudo');
    if (hostSudoEl) {
        hostSudoEl.addEventListener('change', (e) => {
            document.getElementById('host-sudo-password-group').style.display = e.target.checked ? '' : 'none';
        });
    }
    const hostFormEl = document.getElementById('host-form');
    if (hostFormEl) hostFormEl.addEventListener('submit', handleSubmitHost);

    // --- Меню пользователя ---
    const userMenuBtn = document.getElementById('user-menu-btn');
    const userDropdown = document.getElementById('user-dropdown');

    if (userMenuBtn && userDropdown) {
        userMenuBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            userDropdown.classList.toggle('show');
        });

        document.addEventListener('click', (e) => {
            if (!userDropdown.contains(e.target) && e.target !== userMenuBtn) {
                userDropdown.classList.remove('show');
            }
        });
    }

    // --- Пункты меню ---
    document.querySelectorAll('[data-action]').forEach(item => {
        item.addEventListener('click', async (e) => {
            e.preventDefault();
            const action = item.getAttribute('data-action');
            if (action === 'open-login') {
                openModal('auth-modal');
                switchAuthForm('login');
            } else if (action === 'open-register') {
                openModal('auth-modal');
                switchAuthForm('register');
            } else if (action === 'logout') {
                await handleLogout();
            }
            if (userDropdown) userDropdown.classList.remove('show');
        });
    });

    // --- Переключение форм авторизации ---
    document.querySelectorAll('[data-switch-form]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            switchAuthForm(link.getAttribute('data-switch-form'));
        });
    });

    // --- Закрытие модалок ---
    document.querySelectorAll('[data-close-modal]').forEach(btn => {
        btn.addEventListener('click', () => closeModal(btn.getAttribute('data-close-modal')));
    });

    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) closeModal(overlay.id);
        });
    });

    // --- Формы ---
    const createTrapFormEl = document.getElementById('create-trap-form');
    if (createTrapFormEl) createTrapFormEl.addEventListener('submit', handleSubmitTrap);

    const loginFormEl = document.getElementById('login-form-el');
    if (loginFormEl) loginFormEl.addEventListener('submit', handleLogin);

    const registerFormEl = document.getElementById('register-form-el');
    if (registerFormEl) registerFormEl.addEventListener('submit', handleRegister);

    // --- Первичный перевод, восстановление сессии, загрузка данных ---
    translateStatic();

    const isDashboard = !!document.getElementById('traps-list-container');
    const isLogin = !!document.getElementById('login-form-el') && !isDashboard;

    if (isDashboard) {
        state.currentHostId = hostFromHash();
        await restoreSession();
        await loadCatalog();
        await refreshAll();
        startPolling();
    } else if (isLogin) {
        const user = await restoreSession();
        if (user) {
            window.location.href = '/dashboard.html';
        }
    } else {
        const user = await restoreSession();
        if (document.getElementById('traps-list-container')) {
            await refreshAll();
        }
    }
});