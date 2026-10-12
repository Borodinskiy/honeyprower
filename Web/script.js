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
    THEME_KEY: 'app_theme',
    REQUEST_TIMEOUT: 10000,
    POLL_INTERVAL: 10000 // автообновление дашборда, мс
};

// МОКОВЫЕ ДАННЫЕ

const MOCK_DATA = {
    user: { id: 1, username: 'admin' },
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
    async _request(endpoint, { method = 'GET', body = null, auth = true } = {}) {
        const url = `${CONFIG.API_BASE_URL}${endpoint}`;

        const headers = { 'Content-Type': 'application/json' };

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

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
                throw new ApiError(data?.message || `HTTP ${res.status}`, res.status, data);
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
    currentTab: 'traps',
    traps: [],
    classes: [],
    presets: [],
    stats: null,
    user: null,
    searchQuery: '',
    loading: false,
    selectedTrapId: null,
    editingTrapId: null,
    eventTypeFilter: ''
};

const TAB_LABELS = { traps: 'Ловушки', stats: 'Статистика', events: 'События' };

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
    "Детализация по активным ловушкам": "Details for active traps",
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
    "Слишком длинное значение поля.": "Field value is too long."
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
    'target is too long': 'Слишком длинное значение поля.'
};

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
    const fromError = (typeof d?.error === 'object' && d.error !== null) ? d.error.message : d?.error;
    const serverMsg = fromError || d?.message;
    if (serverMsg && SERVER_ERROR_LABELS[serverMsg]) return t(SERVER_ERROR_LABELS[serverMsg]);
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
            <div class="trap-info trap-class">${escapeHtml(classTitle(trap.class))}</div>
            <div class="trap-info">${t('Адрес')}: ${escapeHtml(trapAddress(trap))}</div>
            <div class="trap-info"><span>${t('Предупреждений')}</span>: ${escapeHtml(trap.warnings ?? 0)} · <span>${t('Событий')}</span>: ${escapeHtml(trap.totalEvents ?? 0)}</div>
        </div>
    `;
}

// Это вывод всех ловушек в #traps-list-container
function renderTraps() {
    const container = document.getElementById('traps-list-container');
    if (!container) return;

    if (state.loading) {
        container.innerHTML = `<p style="color: var(--text-muted);">${t('Загрузка...')}</p>`;
        return;
    }

    const query = state.searchQuery.toLowerCase().trim();
    const filtered = state.traps.filter(trap => {
        if (!query) return true;
        return (trap.name || '').toLowerCase().includes(query)
            || (trap.class || '').toLowerCase().includes(query)
            || classTitle(trap.class).toLowerCase().includes(query)
            || trapAddress(trap).toLowerCase().includes(query);
    });

    container.innerHTML = filtered.length
        ? filtered.map(buildTrapCard).join('')
        : `<p style="color: var(--text-muted);">${t('Ловушки не найдены.')}</p>`;
}

// Рисует три KPI-карточки на вкладке "Статистика": активные ловушки, предупреждения за 24ч, активные задачи.
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
    container.innerHTML = `
        <div class="stat-card">
            <div class="stat-value" style="color: #10b981;">${escapeHtml(s.onlineTraps ?? 0)}</div>
            <div class="stat-label">${t('Ловушек на связи')}</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${escapeHtml(s.activeTraps ?? 0)}</div>
            <div class="stat-label">${t('Включённых ловушек')}</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: #f59e0b;">${escapeHtml(s.warnings24h ?? 0)}</div>
            <div class="stat-label">${t('Предупреждения (за 24ч)')}</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${escapeHtml(s.totalEvents ?? 0)}</div>
            <div class="stat-label">${t('Всего событий')}</div>
        </div>
    `;
}

//Рисует детализацию по активным ловушкам на вкладке "Статистика"
function renderTrapDetails() {
    const container = document.getElementById('traps-detail-container');
    if (!container) return;

    const active = state.traps.filter(trap => trap.enabled);
    if (active.length === 0) {
        container.innerHTML = `<p style="color: var(--text-muted);">${t('Данных пока нет.')}</p>`;
        return;
    }

    container.innerHTML = active.map(trap => `
        <div class="trap-item" data-trap-id="${trap.id}">
            <div class="trap-title">${escapeHtml(trap.name)}</div>
            <div class="trap-info"><span>${t('Всего событий')}</span>: ${escapeHtml(trap.totalEvents ?? 0)}</div>
            <div class="trap-info"><span>${t('Последнее')}</span>: ${escapeHtml(trap.lastEventAt ?? '—')}</div>
        </div>
    `).join('');
}

// Заполняет селект ловушек на вкладке "События".
// Сохраняет текущий выбор, если он есть в state.traps.
function renderEventsSelect() {
    const select = document.getElementById('events-trap-select');
    if (!select) return;

    const prevValue = select.value;

    const optionsHtml = `<option value="">${t('— Выберите ловушку —')}</option>`
        + state.traps.map(trap =>
            `<option value="${trap.id}">${escapeHtml(trap.name)}</option>`
        ).join('');
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
function renderAll() {
    updateBreadcrumb();
    renderTraps();
    renderStats();
    renderTrapDetails();
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
        state.traps = await api.getTraps() || [];
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
    renderTraps();
    renderStats();

    await Promise.all([loadTraps(), loadStats()]);

    state.loading = false;
    renderAll();
}

// Тихое фоновое обновление: без «Загрузка...», чтобы интерфейс не мигал.
// Пропускается, пока вкладка браузера скрыта или идёт полная перезагрузка.
async function pollRefresh() {
    if (document.hidden || state.loading) return;

    await Promise.all([loadTraps(), loadStats()]);
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
    collapsed: new WeakSet(), // свёрнутые элементы списков (по объекту — переживает перестановку)
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
    root.append(...renderFieldGroup(cls.fields || [], paramForm.params, '', 'Дополнительные параметры'));
}

// Обычные поля + раскрывающийся блок с редкими.
function renderFieldGroup(fields, obj, path, advLabel) {
    const out = [];
    const basic = fields.filter(f => !f.advanced && isVisible(f, obj));
    const adv = fields.filter(f => f.advanced && isVisible(f, obj));
    basic.forEach(f => out.push(renderField(f, obj, path)));
    if (adv.length) {
        const key = path + '#adv';
        const details = el('details', {
            class: 'params-advanced',
            open: paramForm.advOpen.has(key),
            ontoggle: (e) => { e.target.open ? paramForm.advOpen.add(key) : paramForm.advOpen.delete(key); }
        }, el('summary', {}, `${t(advLabel)} (${adv.length})`));
        adv.forEach(f => details.append(renderField(f, obj, path)));
        out.push(details);
    }
    return out;
}

function renderField(f, obj, path) {
    if (f.type === 'list') return renderList(f, obj, path);

    const id = 'pf-' + (path + f.key).replace(/[^a-zA-Z0-9_-]/g, '-');
    const help = f.help ? el('p', { class: 'field-help' }, f.help) : null;
    const value = obj[f.key];

    if (f.type === 'bool') {
        const cb = el('input', {
            type: 'checkbox', id, checked: !!value,
            onchange: (e) => { obj[f.key] = e.target.checked; }
        });
        return el('div', { class: 'form-group' },
            el('div', { class: 'checkbox-group' }, cb, el('label', { htmlFor: id }, f.title)), help);
    }

    let input;
    if (f.type === 'enum') {
        input = el('select', {
            id, class: 'form-select',
            onchange: (e) => { obj[f.key] = e.target.value; renderParamsForm(); } // могут появиться/скрыться зависимые поля
        }, ...f.options.map(o => el('option', { value: o.value, selected: String(value ?? '') === o.value }, o.label)));
    } else if (f.type === 'int' || f.type === 'number') {
        input = el('input', {
            id, type: 'number', value: value ?? '', min: f.min, max: f.max,
            step: f.type === 'int' ? '1' : 'any',
            placeholder: f.default !== undefined ? String(f.default) : '',
            oninput: (e) => {
                const v = e.target.value;
                if (v === '') delete obj[f.key]; else obj[f.key] = Number(v);
            }
        });
    } else {
        const attrs = {
            id, value: toEditable(value), placeholder: f.placeholder || '',
            class: [f.type === 'text' ? 'param-text' : '', (f.regex || f.hex) ? 'mono' : ''].join(' ').trim(),
            oninput: (e) => { obj[f.key] = e.target.value; }
        };
        input = f.type === 'text' ? el('textarea', { ...attrs, rows: 3 }) : el('input', { ...attrs, type: 'text' });
        input.spellcheck = false;
    }
    return el('div', { class: 'form-group' }, el('label', { htmlFor: id }, f.title), input, help);
}

function listItemSummary(f, item) {
    const s = (f.summary || []).map(k => toEditable(item[k])).filter(Boolean).join('  →  ');
    return s.length > 70 ? s.slice(0, 69) + '…' : s;
}

function renderList(f, obj, path) {
    const items = Array.isArray(obj[f.key]) ? obj[f.key] : (obj[f.key] = []);
    const itemTitle = f.itemTitle || 'Элемент';
    const box = el('div', { class: 'form-group param-list' },
        el('div', { class: 'param-list-title' }, `${f.title} (${items.length})`),
        f.help ? el('p', { class: 'field-help' }, f.help) : null);

    items.forEach((item, i) => {
        const summaryText = el('span', { class: 'list-item-summary' });
        const updateSummary = () => { summaryText.textContent = listItemSummary(f, item); };
        updateSummary();

        const stop = (fn) => (e) => { e.preventDefault(); e.stopPropagation(); fn(); renderParamsForm(); };
        const swap = (j) => () => { [items[i], items[j]] = [items[j], items[i]]; };

        const details = el('details', {
            class: 'list-item',
            open: !paramForm.collapsed.has(item),
            ontoggle: (e) => { e.target.open ? paramForm.collapsed.delete(item) : paramForm.collapsed.add(item); }
        },
            el('summary', {},
                el('span', { class: 'list-item-num' }, `${itemTitle} ${i + 1}`),
                summaryText,
                el('span', { class: 'list-item-actions' },
                    el('button', { type: 'button', class: 'icon-btn', title: 'Выше', disabled: i === 0, onclick: stop(swap(i - 1)) }, '↑'),
                    el('button', { type: 'button', class: 'icon-btn', title: 'Ниже', disabled: i === items.length - 1, onclick: stop(swap(i + 1)) }, '↓'),
                    el('button', { type: 'button', class: 'icon-btn danger', title: 'Удалить', onclick: stop(() => items.splice(i, 1)) }, '✕'))),
            el('div', { class: 'list-item-body', oninput: updateSummary, onchange: updateSummary },
                ...renderFieldGroup(f.item || [], item, `${path}${f.key}[${i}].`, 'Ещё')));
        box.append(details);
    });

    box.append(el('button', {
        type: 'button', class: 'btn btn-secondary btn-small',
        onclick: () => { items.push(fillDefaults(f.item, {})); renderParamsForm(); }
    }, `+ ${t('Добавить')}: ${itemTitle.toLowerCase()}`));
    return box;
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

// Заполняет селект классов. Класс нельзя менять у существующей ловушки.
function populateClassSelect(selectedClass) {
    const sel = document.getElementById('trap-class');
    if (!sel) return;
    sel.innerHTML = state.classes.map(c =>
        `<option value="${c.id}">${escapeHtml(c.title)}</option>`).join('');
    if (selectedClass) sel.value = selectedClass;
}

// Шаблоны, подходящие выбранному классу.
function populatePresetSelect(classId) {
    const sel = document.getElementById('trap-preset');
    if (!sel) return;
    const list = state.presets.filter(p => p.class === classId);
    sel.innerHTML = `<option value="">— Без шаблона —</option>` +
        list.map(p => `<option value="${escapeHtml(p.presetId)}">${escapeHtml(p.name)}</option>`).join('');
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
    const help = document.getElementById('trap-class-help');
    if (help) help.textContent = c ? c.description : '';

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
    if (p.port) document.getElementById('trap-port').value = p.port;
    if (p.ports) document.getElementById('trap-ports').value = p.ports;
    paramForm.params = fillDefaults((currentClass() || {}).fields, parseParams(p.params));
    if (!document.getElementById('trap-name').value.trim()) {
        document.getElementById('trap-name').value = p.name;
    }
    resetParamsView();
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
        const help = document.getElementById('trap-class-help');
        if (help) help.textContent = c ? c.description : '';
        togglePortFields(trap.class);

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
        document.getElementById('trap-bind').value = '0.0.0.0';
        document.getElementById('trap-active').checked = true;
    }

    openModal('create-trap-modal');
}

// Показывает окно с инструкцией запуска агента и ссылками на конфиг/бандл.
function showCreatedModal(trap) {
    document.getElementById('created-token').value = trap.token || '';
    document.getElementById('download-config-btn').href = `${CONFIG.API_BASE_URL}/traps/${trap.id}/config`;
    document.getElementById('download-bundle-btn').href = `${CONFIG.API_BASE_URL}/traps/${trap.id}/bundle`;
    openModal('trap-created-modal');
}


// 8. ПЕРЕКЛЮЧЕНИЕ ВКЛАДОК

async function switchTab(tabId, clickedLink) {
    state.currentTab = tabId;

    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    clickedLink.classList.add('active');

    document.querySelectorAll('.tab-content').forEach(s => s.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');

    updateBreadcrumb();

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
            const patch = { name: payload.name, bind: payload.bind, params, enabled: payload.enabled };
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
    } catch (e) { /* localStorage может быть выключен */ }

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

    // --- Поиск ---
    const trapsSearchEl = document.getElementById('traps-search');
    if (trapsSearchEl) {
        trapsSearchEl.addEventListener('input', (e) => {
            state.searchQuery = e.target.value;
            renderTraps();
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