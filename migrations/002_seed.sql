-- Оператор по умолчанию: admin / admin (bcrypt-хэш пароля "admin").
INSERT INTO users (username, email, password_hash)
VALUES ('admin', 'admin@example.com', '$2a$10$wL978Q.q5X5rxRR9cjuUy.AJrhsTzZkBDt4Hi4u0NJVHdDBgpgQFu')
ON CONFLICT (username) DO NOTHING;

-- Две демо-ловушки с фиксированными токенами: под них есть готовые конфиги
-- агентов (deploy/agent-configs) и сервисы в docker-compose. В бою создавайте
-- ловушки на сайте — тогда токен будет случайным.
INSERT INTO traps (name, class, bind, port, params, token, enabled)
VALUES (
    'SSH баннер (демо, low)', 'banner', '0.0.0.0', 2222,
    '{"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n","close_after_input":true}'::jsonb,
    'demo-ssh-banner-token', TRUE
),
(
    'FTP vsftpd (демо, medium)', 'dialog', '0.0.0.0', 2121,
    '{"greeting":"220 (vsFTPd 3.0.5)\r\n","decoder":"line","default_response":"530 Please login with USER and PASS.\r\n","rules":[{"match":"^USER\\s+(.*)$","response":"331 Please specify the password.\r\n","capture":"username"},{"match":"^PASS\\s?(.*)$","response":"530 Login incorrect.\r\n","capture":"password"},{"match":"^SYST","response":"215 UNIX Type: L8\r\n"},{"match":"^QUIT","response":"221 Goodbye.\r\n","close":true}]}'::jsonb,
    'demo-ftp-token', TRUE
)
ON CONFLICT (token) DO NOTHING;
