// ============================================================
// 🎯 АРХИТЕКТУРА ПОДКЛЮЧЕНИЯ К БЭКЕНДУ
// ------------------------------------------------------------
//   1. CONFIG.USE_MOCK_DATA = false → идём в реальный API.
//   2. _request возвращает ТЕЛО КАК ЕСТЬ. Обёртки типа { data }
//      распаковывай в конкретном методе.
//   3. Ошибки нормализуются в ApiError.
//   4. Контракт API см. в API.md.
//
// ⚠️ В mock-режиме методы api ОБЯЗАНЫ мутировать MOCK_DATA,
//    иначе refreshAll() вернёт старые данные и UI не обновится.
// ============================================================
const CONFIG = {
    USE_MOCK_DATA: false,
    API_BASE_URL: '/api',
    AUTH_TOKEN_KEY: 'auth_token',
    LANG_KEY: 'app_lang',
    THEME_KEY: 'app_theme',
    REQUEST_TIMEOUT: 10000,
    // POLL_INTERVAL: 30000
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
        if (auth) Object.assign(headers, this._authHeaders());

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
        localStorage.removeItem(CONFIG.AUTH_TOKEN_KEY);
        state.user = null;

        applyUserMenu();
        document.querySelectorAll('.modal-overlay').forEach(m => m.style.display = 'none');
        if (window.location.pathname.endsWith('dashboard.html') || window.location.pathname === '/' || window.location.pathname === '/index.html') {
            window.location.href = '/login.html';
        }
    },

    _authHeaders() {
        const token = localStorage.getItem(CONFIG.AUTH_TOKEN_KEY);
        return token ? { 'Authorization': `Bearer ${token}` } : {};
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
        const created = await this._request('/traps', { method: 'POST', body: trap });
        return { warnings: 0, totalEvents: 0, lastEventAt: '—', active: true, ...created };
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

    async getTrapEvents(id) {
        if (CONFIG.USE_MOCK_DATA) return MOCK_DATA.events[Number(id)] || [];
        return this._request(`/traps/${id}/events`);
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
        if (CONFIG.USE_MOCK_DATA) {
            const token = localStorage.getItem(CONFIG.AUTH_TOKEN_KEY);
            return token ? { ...MOCK_DATA.user } : null;
        }
        try {
            return await this._request('/auth/me');
        } catch (err) {
            if (err.status === 401) return null;
            throw err;
        }
    },

    async logout() {
        if (CONFIG.USE_MOCK_DATA) {
            localStorage.removeItem(CONFIG.AUTH_TOKEN_KEY);
            state.user = null;
            return { ok: true };
        }
        try {
            await this._request('/auth/logout', { method: 'POST', auth: true });
        } catch (err) {
            console.error('[logout]', err);
        } finally {
            localStorage.removeItem(CONFIG.AUTH_TOKEN_KEY);
            state.user = null;
        }
    }
};


// 1. СОСТОЯНИЕ

const state = {
    currentLang: 'ru',
    currentTab: 'traps',
    traps: [],
    stats: null,
    user: null,
    searchQuery: '',
    loading: false,
    selectedTrapId: null,
    editingTrapId: null
};

const TAB_LABELS = { traps: 'Ловушки', stats: 'Статистика', events: 'События' };

// Типы событий  (русские подписи)
const EVENT_TYPE_LABELS = {
    connection: 'Подключение',
    auth: 'Попытка входа',
    scan: 'Сканирование'
};

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

    "Активные ловушки": "Active Traps",
    "Предупреждения (за 24ч)": "Warnings (24h)",
    "Активные задачи": "Active Tasks",
    "Детализация по активным ловушкам": "Details for active traps",

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
    "Некорректный IP-адрес или URL.": "Invalid IP address or URL."
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
    return serverMsg || t(fallbackRuKey);
}

// проверка на вшивость ввода IP,URL или хоста
function isValidTarget(value) {
    if (!value || !value.trim()) return false;
    const v = value.trim();

    if (/^https?:\/\/[^\s]+$/i.test(v)) return true;

    const hostRe = /^([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9\-]*[a-z0-9])?$/i;
    const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
    const portRe = /^:\d{1,5}$/;

    let host = v, port = '';
    const colonIdx = v.lastIndexOf(':');
    if (colonIdx > -1) {
        host = v.slice(0, colonIdx);
        port = v.slice(colonIdx);
        if (!portRe.test(port)) return false;
    }

    if (ipv4Re.test(host)) {
        return host.split('.').every(n => +n >= 0 && +n <= 255);
    }
    return hostRe.test(host);
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

    if (eventsBtn) eventsBtn.disabled = !hasSelection;
    if (editBtn) editBtn.disabled = !hasSelection;
    if (deleteBtn) deleteBtn.disabled = !hasSelection;
}

// собирает структуру для карточки с ловушкой
function buildTrapCard(trap) {
    const statusClass = trap.active ? '' : 'inactive';
    const statusColor = trap.active ? '#10b981' : '#6b7280';
    const statusText = trap.active ? t('● Активна') : t('● Неактивна');
    const targetLabel = (trap.target || '').includes('http') ? 'URL' : 'IP';
    const selectedClass = state.selectedTrapId === trap.id ? 'selected' : '';

    return `
        <div class="trap-item ${statusClass} ${selectedClass}" data-trap-id="${trap.id}">
            <div class="trap-title">
                <span>${escapeHtml(trap.name)} (${escapeHtml(trap.type)})</span>
                <span style="color: ${statusColor}; font-size: 12px;">${statusText}</span>
            </div>
            <div class="trap-info">${targetLabel}: ${escapeHtml(trap.target)}</div>
            <div class="trap-info"><span>${t('Предупреждений')}</span>: ${escapeHtml(trap.warnings ?? 0)}</div>
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
            || (trap.target || '').toLowerCase().includes(query)
            || (trap.type || '').toLowerCase().includes(query);
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
            <div class="stat-value">${escapeHtml(s.activeTraps ?? 0)}</div>
            <div class="stat-label">${t('Активные ловушки')}</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: #f59e0b;">${escapeHtml(s.warnings24h ?? 0)}</div>
            <div class="stat-label">${t('Предупреждения (за 24ч)')}</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${escapeHtml(s.activeTasks ?? 0)}</div>
            <div class="stat-label">${t('Активные задачи')}</div>
        </div>
    `;
}

//Рисует детализацию по активным ловушкам на вкладке "Статистика"
function renderTrapDetails() {
    const container = document.getElementById('traps-detail-container');
    if (!container) return;

    const active = state.traps.filter(trap => trap.active);
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

    select.innerHTML = `<option value="">${t('— Выберите ловушку —')}</option>`
        + state.traps.map(trap =>
            `<option value="${trap.id}">${escapeHtml(trap.name)}</option>`
        ).join('');

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
        state.traps = [];
    }
}

// это мне добавил фикс гптешник, с его слов:
// "Идёт в api.getStats(), кладёт результат в state.stats. При ошибке — null."
async function loadStats() {
    try {
        state.stats = await api.getStats() || null;
    } catch (err) {
        console.error('[loadStats]', err);
        state.stats = null;
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

function openTrapModal(mode, trapId = null) {
    const titleEl = document.getElementById('trap-modal-title');
    const form = document.getElementById('create-trap-form');

    if (mode === 'edit' && trapId !== null) {
        const trap = state.traps.find(t => t.id === trapId);
        if (!trap) return;

        state.editingTrapId = trapId;
        if (titleEl) titleEl.textContent = t('Редактирование ловушки');

        document.getElementById('trap-name').value   = trap.name || '';
        document.getElementById('trap-type').value   = trap.type || 'SSH';
        document.getElementById('trap-target').value = trap.target || '';
        document.getElementById('trap-active').checked = !!trap.active;
    } else {
        state.editingTrapId = null;
        if (titleEl) titleEl.textContent = t('Создание новой ловушки');
        form.reset();
        document.getElementById('trap-active').checked = true;
    }

    openModal('create-trap-modal');
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
async function loadAndRenderEvents(trapId) {
    const listEl = document.getElementById('events-list');
    if (!listEl) return;

    if (!trapId) {
        listEl.innerHTML = `<p class="no-events">${t('Выберите ловушку')}</p>`;
        return;
    }

    listEl.innerHTML = `<p class="no-events">${t('Загрузка...')}</p>`;

    try {
        const events = await api.getTrapEvents(trapId) || [];
        renderEvents(events);
    } catch (err) {
        console.error('[loadAndRenderEvents]', err);
        listEl.innerHTML = `<p class="no-events">${t('Не удалось загрузить события.')}</p>`;
    }
}

// 9. ОБРАБОТЧИКИ ФОРМ И ДЕЙСТВИЙ

async function handleSubmitTrap(event) {
    event.preventDefault();

    const target = document.getElementById('trap-target').value.trim();
    if (!isValidTarget(target)) {
        alert(t('Некорректный IP-адрес или URL.'));
        return;
    }

    const payload = {
        name:   document.getElementById('trap-name').value.trim(),
        type:   document.getElementById('trap-type').value,
        target: target,
        active: document.getElementById('trap-active').checked
    };

    try {
        if (state.editingTrapId !== null) {
            await api.updateTrap(state.editingTrapId, payload);
        } else {
            await api.createTrap(payload);
        }
        closeModal('create-trap-modal');
        document.getElementById('create-trap-form').reset();
        state.editingTrapId = null;
        await refreshAll();
    } catch (err) {
        console.error('[handleSubmitTrap]', err);
        const fallback = state.editingTrapId !== null
            ? 'Не удалось обновить ловушку.'
            : 'Не удалось создать ловушку.';
        alert(getErrorMessage(err, fallback));
    }
}

//удаление выбранной ловушки..надеюсь только ловушк
async function handleDeleteTrap() {
    if (state.selectedTrapId === null) return;

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
        return `
            <div class="event-item">
                <div class="event-head">
                    <span class="event-type">${escapeHtml(typeLabel)}</span>
                    <span class="event-time">${escapeHtml(ev.time || '')}</span>
                </div>
                <div class="event-source">${escapeHtml(ev.source || '')}</div>
                <div class="event-detail">${escapeHtml(ev.detail || '')}</div>
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
        if (result && result.token) {
            localStorage.setItem(CONFIG.AUTH_TOKEN_KEY, result.token);
        }
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
        if (result && result.token) {
            localStorage.setItem(CONFIG.AUTH_TOKEN_KEY, result.token);
        }
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
    localStorage.removeItem(CONFIG.AUTH_TOKEN_KEY);
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
        await refreshAll();
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