INSERT INTO users (username, email, password_hash)
VALUES ('admin', 'admin@example.com', '$2a$10$wL978Q.q5X5rxRR9cjuUy.AJrhsTzZkBDt4Hi4u0NJVHdDBgpgQFu')
ON CONFLICT (username) DO NOTHING;

INSERT INTO traps (name, type, target, active, warnings, total_events, last_event_at)
VALUES 
('SSH Honeypot', 'SSH', '192.168.1.10:22', TRUE, 142, 1420, NOW() - INTERVAL '2 minutes'),
('Web Trap', 'Web', 'http://10.0.0.5/', TRUE, 87, 870, NOW() - INTERVAL '15 minutes'),
('FTP Trap', 'FTP', '192.168.1.12:21', FALSE, 0, 0, NULL);

INSERT INTO events (trap_id, type, source, time, detail)
VALUES
((SELECT id FROM traps WHERE name = 'SSH Honeypot' ORDER BY id LIMIT 1), 'connection', '10.0.0.42', '2024-01-15 12:34:56', 'SSH-2.0-OpenSSH_8.2'),
((SELECT id FROM traps WHERE name = 'SSH Honeypot' ORDER BY id LIMIT 1), 'auth', '192.168.1.50', '2024-01-15 11:20:11', 'user=root pass=admin'),
((SELECT id FROM traps WHERE name = 'SSH Honeypot' ORDER BY id LIMIT 1), 'scan', '203.0.113.5', '2024-01-15 09:15:33', 'nmap -sV'),
((SELECT id FROM traps WHERE name = 'Web Trap' ORDER BY id LIMIT 1), 'connection', '198.51.100.7', '2024-01-15 14:22:01', 'GET /admin.php');
