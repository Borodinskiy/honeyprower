"""Пример своей ловушки HoneyForge в режиме service.

Агент запускает программу и передаёт ей через окружение:
  HF_BIND, HF_PORT  — где слушать;
  HF_PARAMS         — параметры ловушки из центра (JSON);
  HF_DATA_DIR       — каталог, куда можно писать.

Событие — одна строка JSON с полем "type" в stdout (или stderr). Всё остальное,
что программа печатает, попадает в журнал агента. Типы событий: connect,
disconnect, data, auth, command, request, handshake, scan, token, error.
"""

import json
import os
import socket
import sys
import threading

PARAMS = json.loads(os.environ.get("HF_PARAMS") or "{}")
HOSTNAME = PARAMS.get("hostname", "RT-AC68U")
MAX_ATTEMPTS = int(PARAMS.get("max_attempts", 3))
MOTD = PARAMS.get("motd", "")
_lock = threading.Lock()


def event(kind, **fields):
    """Отправить событие в центр: агент прочитает эту строку из stdout."""
    with _lock:
        print(json.dumps({"type": kind, **fields}, ensure_ascii=False), flush=True)


def ask(conn, prompt):
    conn.sendall(prompt.encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(256)
        if not chunk:
            raise ConnectionError
        data += chunk
        if len(data) > 1024:
            break
    return data.decode(errors="replace").strip()


def serve(conn, addr):
    ip, port = addr[0], addr[1]
    conn.settimeout(60)
    try:
        conn.sendall(f"\r\n{HOSTNAME} login: ".encode())
        user = ask(conn, "")
        for attempt in range(MAX_ATTEMPTS):
            password = ask(conn, "Password: ")
            event("auth", src_ip=ip, src_port=port, username=user, password=password,
                  data={"attempt": attempt + 1})
            if MOTD:
                conn.sendall(MOTD.encode() + b"\r\n# ")
                command = ask(conn, "")
                event("command", src_ip=ip, src_port=port, data={"line": command})
                break
            conn.sendall(b"\r\nLogin incorrect\r\n")
            if attempt + 1 < MAX_ATTEMPTS:
                user = ask(conn, f"{HOSTNAME} login: ")
    except (ConnectionError, OSError):
        pass
    finally:
        conn.close()


def main():
    family = socket.AF_INET6 if ":" in os.environ.get("HF_BIND", "") else socket.AF_INET
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((os.environ.get("HF_BIND", "0.0.0.0"), int(os.environ["HF_PORT"])))
    srv.listen(64)
    print(f"router-login слушает порт {os.environ['HF_PORT']}", file=sys.stderr)
    while True:
        conn, addr = srv.accept()
        event("connect", src_ip=addr[0], src_port=addr[1])
        threading.Thread(target=serve, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
