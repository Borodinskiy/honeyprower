# Task 2: Authentication Isolation and UI (Cookies, login.html, dashboard.html)

/boost

## Objective
Isolate authentication, implement server-side session control using Cookies, create `login.html`, move dashboard interface to `dashboard.html`, and ensure immediate data loading on login without manual F5 refresh.

## Context
Working directory: `/home/tinger/honeyforge`
- Auth manager: `internal/auth/auth.go`
- Auth handlers: `internal/handlers/auth.go`
- Middleware: `internal/middleware/middleware.go`
- Router: `internal/router/router.go`
- Web server & main: `main.go`
- Frontend: `Web/index.html`, `Web/script.js`, `Web/style.css`

## Requirements
1. **Cookie-based Session Authentication**:
   - In `internal/middleware/middleware.go`:
     - Update `Auth` middleware: verify `Authorization: Bearer <token>` header first. If absent, check `session_token` Cookie.
   - In `internal/handlers/auth.go`:
     - In `Login` and `Register`: upon successful authentication, set `session_token` cookie:
       ```go
       http.SetCookie(w, &http.Cookie{
           Name:     "session_token",
           Value:    token,
           Path:     "/",
           HttpOnly: true,
           SameSite: http.SameSiteLaxMode,
           MaxAge:   7 * 24 * 3600,
       })
       ```
     - Add `Logout` handler: clears `session_token` cookie (`MaxAge: -1`, `Path: "/"`), revokes token in `auth.Manager` if token found, and returns 200 or 204.
   - In `internal/router/router.go`:
     - Register `POST /api/auth/logout` handler.

2. **Server-Side Web Route Protection (`main.go`)**:
   - In `webMux` (Web server):
     - For requests to `/` and `/index.html`: check `session_token` cookie against `authMgr.UserID(...)`. If authorized -> HTTP 302 Redirect to `/dashboard.html`. If unauthorized -> HTTP 302 Redirect to `/login.html`.
     - For requests to `/dashboard.html`: check `session_token` cookie against `authMgr.UserID(...)`. If authorized -> serve `dashboard.html`. If unauthorized -> HTTP 302 Redirect to `/login.html`.
     - For requests to `/login.html`: check `session_token` cookie against `authMgr.UserID(...)`. If authorized -> HTTP 302 Redirect to `/dashboard.html`. If unauthorized -> serve `login.html`.
     - Static assets (`style.css`, `script.js`, etc.) served via `http.FileServer(http.Dir(cfg.StaticDir))` as usual.

3. **Frontend Pages (`Web/`)**:
   - Create `Web/login.html`:
     - Dedicated, responsive page in dark-theme (`style.css`).
     - Contains both Login and Register forms with a tab/switch (like the modal previously had).
     - Fields for login: username, password, submit button.
     - Fields for register: username, email, password, submit button.
     - Proper error display on failed login/register.
     - On successful login/register: redirect via `window.location.href = '/dashboard.html'`.
   - Create `Web/dashboard.html`:
     - Move the full dashboard interface from `index.html` to `dashboard.html`.
     - Remove the unnecessary login modal markup from `dashboard.html`.
     - In user menu, show active username, and provide "Выйти" (Logout) action which calls `/api/auth/logout`, clears tokens, and redirects to `/login.html`.
   - Update `Web/script.js`:
     - Adapt `script.js` to work on both `login.html` and `dashboard.html` (or ensure no errors if elements are absent).
     - On `dashboard.html`: upon `DOMContentLoaded`, immediately restore session and call `refreshAll()` so traps and statistics are loaded instantly without needing an F5 reload!
     - On `login.html`: wire form submit handlers to `api.login` and `api.register`, then redirect to `/dashboard.html`.
   - Update or replace `Web/index.html` with a redirect or clean entrypoint.

## Verification
- Code must compile with `go build -v .`.
- `go test -v ./...` must succeed.
- `Web/login.html` and `Web/dashboard.html` must exist.
