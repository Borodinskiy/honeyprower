#!/usr/bin/env python3
"""SSH-приманка в стиле Cowrie для HoneyForge.

Настоящий SSH-сервер (Paramiko) с эмуляцией оболочки Linux: своя файловая
система на сессию, цепочки команд (; && || |), перенаправления (> >>),
перехват загрузок wget/curl и записанных файлов с SHA-256. События — строки
JSON в stdout, их забирает агент HoneyForge.
"""

import hashlib
import ipaddress
import json
import os
import posixpath
import re
import socket
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone

try:
    import paramiko
except ImportError:
    print("CRITICAL: нет модуля paramiko — центр привозит его сам (pip в манифесте); при ручном запуске: pip install paramiko", file=sys.stderr)
    sys.exit(1)

BIND = os.environ.get("HF_BIND", "0.0.0.0")
PORT = int(os.environ.get("HF_PORT", "2222"))
DATA_DIR = os.environ.get("HF_DATA_DIR", "")

try:
    PARAMS = json.loads(os.environ.get("HF_PARAMS", "{}")) or {}
except ValueError:
    PARAMS = {}

HOSTNAME = PARAMS.get("hostname", "srv-prod-db01")
BANNER = PARAMS.get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
AUTH_MODE = PARAMS.get("auth_mode", "accept_all")
ALLOWED = {l.strip() for l in PARAMS.get("allowed_creds", "root:root").splitlines() if ":" in l}
MOTD = re.sub(r"\r?\n", "\r\n", PARAMS.get("motd", ""))
DOWNLOAD = bool(PARAMS.get("download_payloads", False))
MAX_DOWNLOAD = int(PARAMS.get("max_download_kb", 5120)) * 1024

KERNEL = "5.15.0-105-generic"
UNAME_A = f"Linux {HOSTNAME} {KERNEL} #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
MAX_FILE = 1 << 20  # больше в виртуальную ФС не пишем

_out_lock = threading.Lock()


def emit(event_type, peer, **fields):
    """Событие для агента: одна строка JSON в stdout."""
    ev = {"type": event_type, "src_ip": peer[0], "src_port": peer[1]}
    ev.update({k: v for k, v in fields.items() if v is not None})
    line = json.dumps(ev, ensure_ascii=False)
    with _out_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ----------------------------- ключи хоста -----------------------------

def host_keys():
    """RSA, ECDSA и Ed25519, как у OpenSSH; хранятся в HF_DATA_DIR между запусками."""
    keys = []
    for name, load, make in (
        ("ssh_host_ed25519_key", paramiko.Ed25519Key.from_private_key_file, _new_ed25519),
        ("ssh_host_ecdsa_key", paramiko.ECDSAKey.from_private_key_file, lambda p: _save(paramiko.ECDSAKey.generate(bits=256), p)),
        ("ssh_host_rsa_key", paramiko.RSAKey.from_private_key_file, lambda p: _save(paramiko.RSAKey.generate(3072), p)),
    ):
        path = os.path.join(DATA_DIR or ".", name)
        try:
            keys.append(load(path) if os.path.exists(path) else make(path))
        except Exception as e:  # ключ не критичен — хватит остальных
            log(f"ключ {name}: {e}")
    return keys


def _save(key, path):
    try:
        key.write_private_key_file(path)
    except OSError as e:
        log(f"не удалось сохранить {path}: {e}")
    return key


def _new_ed25519(path):
    # Paramiko не умеет создавать Ed25519 — создаём через cryptography (его зависимость).
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    try:
        with open(path, "wb") as f:
            f.write(pem)
        os.chmod(path, 0o600)
        return paramiko.Ed25519Key.from_private_key_file(path)
    except OSError:
        import io
        return paramiko.Ed25519Key(file_obj=io.StringIO(pem.decode()))


# ------------------------- виртуальная ФС -------------------------

def _file(content, mode=0o644, owner="root"):
    return {"type": "file", "data": content.encode() if isinstance(content, str) else content,
            "mode": mode, "owner": owner, "mtime": time.time() - 86400 * 30}


def _dir(mode=0o755, owner="root"):
    return {"type": "dir", "mode": mode, "owner": owner, "mtime": time.time() - 86400 * 30}


def base_fs(user):
    home = "/root" if user == "root" else f"/home/{user}"
    fs = {p: _dir() for p in (
        "/", "/bin", "/boot", "/dev", "/etc", "/etc/ssh", "/home", "/lib", "/opt", "/proc", "/root",
        "/run", "/sbin", "/srv", "/tmp", "/usr", "/usr/bin", "/usr/local", "/usr/local/bin",
        "/usr/sbin", "/var", "/var/log", "/var/tmp", "/var/www", "/root/.ssh")}
    fs["/tmp"]["mode"] = 0o1777
    fs["/root"]["mode"] = 0o700
    if user != "root":
        fs[home] = _dir(owner=user)
    passwd = ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
              "bin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
              "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
              "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
              "postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n")
    if user != "root":
        passwd += f"{user}:x:1000:1000:{user},,,:{home}:/bin/bash\n"
    files = {
        "/etc/passwd": passwd,
        "/etc/hostname": HOSTNAME + "\n",
        "/etc/hosts": f"127.0.0.1 localhost\n127.0.1.1 {HOSTNAME}\n::1 ip6-localhost ip6-loopback\n",
        "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n\n",
        "/etc/os-release": ('PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
                            'VERSION="22.04.4 LTS (Jammy Jellyfish)"\nVERSION_CODENAME=jammy\nID=ubuntu\n'
                            'ID_LIKE=debian\nHOME_URL="https://www.ubuntu.com/"\n'),
        "/etc/resolv.conf": "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n",
        "/etc/crontab": "SHELL=/bin/sh\n17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n",
        "/proc/version": f"Linux version {KERNEL} (buildd@lcy02-amd64-001) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #115-Ubuntu SMP\n",
        "/proc/cpuinfo": "".join(
            f"processor\t: {i}\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz\n"
            f"cpu MHz\t\t: 2999.998\ncache size\t: 36608 KB\ncpu cores\t: 4\n\n" for i in range(4)),
        "/proc/meminfo": "MemTotal:        8131576 kB\nMemFree:         1123412 kB\nMemAvailable:    5021380 kB\n",
        "/var/log/auth.log": "",
        "/root/.bashrc": "# ~/.bashrc\n[ -z \"$PS1\" ] && return\nHISTCONTROL=ignoredups\n",
        "/root/.profile": "if [ -f ~/.bashrc ]; then . ~/.bashrc; fi\n",
        "/root/.ssh/authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl deploy@ci\n",
    }
    for path, content in files.items():
        fs[path] = _file(content)
    fs["/etc/shadow"] = _file("root:$6$Zq1...:19700:0:99999:7:::\n", mode=0o640)
    for b in ("bash", "sh", "ls", "cat", "echo", "ps", "uname", "wget", "curl", "chmod", "rm", "mkdir", "cp", "mv"):
        fs["/bin/" + b] = _file(b"\x7fELF", mode=0o755)
    if user != "root":
        fs[f"{home}/.bashrc"] = _file("# ~/.bashrc\n", owner=user)
        fs[f"{home}/.bash_history"] = _file("sudo systemctl restart postgresql\nls -la\n", owner=user)
    return fs


# --------------------------- разбор команд ---------------------------

OPERATORS = (";", "&&", "||", "|", ">>", ">", "<", "&")
NOEXPAND = "\x01"  # «$» из одинарных кавычек


def tokenize(line):
    """Слова и операторы оболочки. Кавычки и экранирование — как в sh, без подстановок."""
    tokens, word, quoted, i = [], [], False, 0
    while i < len(line):
        c = line[i]
        if c in " \t":
            if word or quoted:
                tokens.append(("w", "".join(word)))
                word, quoted = [], False
            i += 1
            continue
        if c == "\\" and i + 1 < len(line):
            word.append(line[i + 1])
            i += 2
            continue
        if c == "'":
            end = line.find("'", i + 1)
            end = len(line) if end < 0 else end
            word.append(line[i + 1:end].replace("$", NOEXPAND))  # в '' переменные не раскрываются
            quoted, i = True, end + 1
            continue
        if c == '"':
            i += 1
            while i < len(line) and line[i] != '"':
                if line[i] == "\\" and i + 1 < len(line) and line[i + 1] in '"\\$`':
                    i += 1
                word.append(line[i])
                i += 1
            quoted, i = True, i + 1
            continue
        if c == "#" and not word and not quoted:
            break
        op = next((o for o in OPERATORS if line.startswith(o, i)), None)
        if op:
            if word or quoted:
                tokens.append(("w", "".join(word)))
                word, quoted = [], False
            tokens.append(("op", op))
            i += len(op)
            continue
        word.append(c)
        i += 1
    if word or quoted:
        tokens.append(("w", "".join(word)))
    return tokens


def parse(line):
    """Список (связка, конвейер); конвейер — список команд {argv, out, append, inp}."""
    chain, pipeline, cmd, link = [], [], None, None

    def new_cmd():
        return {"argv": [], "out": None, "append": False, "inp": None}

    cmd = new_cmd()
    tokens = tokenize(line)
    i = 0
    while i < len(tokens):
        kind, val = tokens[i]
        if kind == "w":
            cmd["argv"].append(val)
        elif val in (">", ">>", "<"):
            target = tokens[i + 1][1] if i + 1 < len(tokens) and tokens[i + 1][0] == "w" else None
            i += 1
            if val == "<":
                cmd["inp"] = target
            else:
                cmd["out"], cmd["append"] = target, val == ">>"
        elif val == "|":
            pipeline.append(cmd)
            cmd = new_cmd()
        else:  # ; && || &
            pipeline.append(cmd)
            chain.append((link, pipeline))
            pipeline, cmd = [], new_cmd()
            link = val if val in ("&&", "||") else ";"
        i += 1
    pipeline.append(cmd)
    chain.append((link, pipeline))
    return [(l, [c for c in p if c["argv"] or c["out"]]) for l, p in chain if any(c["argv"] for c in p)]


# ------------------------------ загрузки ------------------------------

def public_address(host):
    """Адрес хоста, если все его адреса публичные: ловушка не должна ходить во внутреннюю сеть."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return None
    addrs = {info[4][0] for info in infos}
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if not ip.is_global or ip.is_multicast:
            return None
    return sorted(addrs)[0] if addrs else None


def fetch(url, max_bytes=None, timeout=10):
    """Скачивает файл атакующего (до 3 переадресаций). Возвращает (bytes, ошибка)."""
    import http.client
    max_bytes = max_bytes or MAX_DOWNLOAD
    for _ in range(4):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            return None, "unsupported url"
        if public_address(u.hostname) is None:
            return None, "non-public address"
        conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(u.hostname, u.port, timeout=timeout)
        try:
            path = (u.path or "/") + (("?" + u.query) if u.query else "")
            conn.request("GET", path, headers={"User-Agent": "Wget/1.21.2", "Host": u.netloc})
            resp = conn.getresponse()
            if resp.status in (301, 302, 303, 307, 308) and resp.getheader("Location"):
                url = urllib.parse.urljoin(url, resp.getheader("Location"))
                continue
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                return data[:max_bytes], "truncated"
            return data, None
        except (OSError, http.client.HTTPException) as e:
            return None, str(e)[:200]
        finally:
            conn.close()
    return None, "too many redirects"


# ------------------------------ оболочка ------------------------------

class Shell:
    def __init__(self, user, peer, session_bytes=None):
        self.user = user
        self.peer = peer
        self.home = "/root" if user == "root" else f"/home/{user}"
        self.cwd = self.home
        self.fs = base_fs(user)
        self.env = {"HOME": self.home, "USER": user, "SHELL": "/bin/bash", "LANG": "C.UTF-8",
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM": "xterm-256color"}
        self.history = []
        self.status = 0
        self.exit = False
        self.interactive = True

    # --- пути и файлы ---
    def path(self, p):
        if p == "~" or p.startswith("~/"):
            p = self.home + p[1:]
        return posixpath.normpath(posixpath.join(self.cwd, p)) if p else self.cwd

    def short_cwd(self):
        if self.cwd == self.home:
            return "~"
        if self.cwd.startswith(self.home + "/"):
            return "~" + self.cwd[len(self.home):]
        return self.cwd

    def can_read(self, node):
        return self.user == "root" or node["owner"] == self.user or node["mode"] & 0o004

    def write_file(self, path, data, append=False, source=None, report=True):
        full = self.path(path)
        parent = posixpath.dirname(full)
        if parent not in self.fs or self.fs[parent]["type"] != "dir":
            return f"bash: {path}: No such file or directory\n"
        if self.fs.get(full, {}).get("type") == "dir":
            return f"bash: {path}: Is a directory\n"
        old = self.fs[full]["data"] if append and full in self.fs else b""
        content = (old + data)[:MAX_FILE]
        self.fs[full] = _file(content, owner=self.user)
        self.fs[full]["mtime"] = time.time()
        if data and report:
            self.report_file(full, content, source)
        return ""

    def report_file(self, path, content, source, url=None, downloaded=None, error=None):
        data = {"command": source, "path": path, "url": url, "downloaded": downloaded, "error": error}
        if content:
            data.update(payload_sha256=hashlib.sha256(content).hexdigest(), payload_size=len(content),
                        payload_sample=content[:256].decode("utf-8", "replace"))
        emit("payload", self.peer, username=self.user, data={k: v for k, v in data.items() if v is not None})

    # --- выполнение ---
    def run_line(self, line):
        """Выполняет строку; возвращает вывод (str)."""
        out = []
        for link, pipeline in parse(line):
            if (link == "&&" and self.status != 0) or (link == "||" and self.status == 0):
                continue
            out.append(self.run_pipeline(pipeline, line))
            if self.exit:
                break
        return "".join(out)

    def run_pipeline(self, pipeline, line):
        data = ""
        for idx, cmd in enumerate(pipeline):
            stdin = data if idx else None
            if cmd["inp"]:
                node = self.fs.get(self.path(self.expand(cmd["inp"])))
                if not node or node["type"] != "file":
                    self.status = 1
                    return f"bash: {cmd['inp']}: No such file or directory\n"
                stdin = node["data"].decode("utf-8", "replace")
            data = self.run(cmd["argv"], stdin, line)
            if cmd["out"]:
                err = self.write_file(self.expand(cmd["out"]), data.encode(), cmd["append"], source=line)
                data = err
        return data

    def run(self, argv, stdin, line):
        if not argv:
            return ""
        argv = [self.expand(x) for x in argv]
        name, args = argv[0], argv[1:]
        if "=" in name and not name.startswith("="):  # VAR=value
            k, _, v = name.partition("=")
            self.env[k] = v
            return self.run(args, stdin, line) if args else ""
        fn = getattr(self, "c_" + name.replace("-", "_").replace(".", "_"), None)
        if name in ("[", "test"):
            fn = self.c_true
        if fn is None and "/" in name:
            node = self.fs.get(self.path(name))
            if node and node["type"] == "file":
                if not node["mode"] & 0o111:
                    self.status = 126
                    return f"-bash: {name}: Permission denied\n"
                if node["data"].startswith(b"\x7fELF"):
                    return ""  # «запустилась» и молча завершилась
                return self.c_bash([name], stdin, line)
            fn = getattr(self, "c_" + posixpath.basename(name), None) if name.startswith("/") else None
            if fn is None:
                self.status = 127
                return f"-bash: {name}: No such file or directory\n"
        if fn is None:
            self.status = 127
            prefix = "-bash" if self.interactive else "bash: line 1"
            return f"{prefix}: {name}: command not found\n"
        self.status = 0
        try:
            return fn(args, stdin, line) or ""
        except Exception as e:  # эмулятор не должен падать на странном вводе
            log(f"команда {name}: {e}")
            self.status = 1
            return ""

    # --- команды ---
    def c_true(self, a, i, l): return ""
    def c_false(self, a, i, l): self.status = 1
    c_sleep = c_true
    c_clear = lambda self, a, i, l: "\033[H\033[2J"
    def c_whoami(self, a, i, l): return self.user + "\n"
    def c_hostname(self, a, i, l): return HOSTNAME + "\n"
    def c_pwd(self, a, i, l): return self.cwd + "\n"
    def c_nproc(self, a, i, l): return "4\n"
    def c_arch(self, a, i, l): return "x86_64\n"

    def c_id(self, a, i, l):
        if self.user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user}),4(adm),27(sudo)\n"

    def c_uname(self, a, i, l):
        flags = "".join(x[1:] for x in a if x.startswith("-"))
        if "a" in flags:
            return UNAME_A + "\n"
        parts = {"s": "Linux", "n": HOSTNAME, "r": KERNEL, "m": "x86_64", "o": "GNU/Linux",
                 "v": "#115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024", "p": "x86_64", "i": "x86_64"}
        return " ".join(parts[f] for f in flags if f in parts) + "\n" if flags else "Linux\n"

    def c_date(self, a, i, l):
        return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y") + "\n"

    def c_uptime(self, a, i, l):
        return datetime.now(timezone.utc).strftime(" %H:%M:%S") + " up 42 days,  3:18,  1 user,  load average: 0.12, 0.08, 0.05\n"

    def c_w(self, a, i, l):
        return (self.c_uptime(a, i, l) + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                f"{self.user:<8} pts/0    {self.peer[0]:<16} 21:50    0.00s  0.02s  0.00s -bash\n")
    c_who = lambda self, a, i, l: f"{self.user:<8} pts/0        2026-01-01 21:50 ({self.peer[0]})\n"

    def c_echo(self, a, i, l):
        newline, escapes = True, False
        while a and re.fullmatch(r"-[neE]+", a[0]):
            newline = newline and "n" not in a[0]
            escapes = "e" in a[0] or (escapes and "E" not in a[0])
            a = a[1:]
        text = " ".join(a)
        if escapes:
            text = text.encode("utf-8", "replace").decode("unicode_escape", "replace")
        return text + ("\n" if newline else "")

    def c_printf(self, a, i, l):
        if not a:
            return ""
        fmt = a[0].encode().decode("unicode_escape", "replace")
        try:
            return fmt.replace("%s", "{}").format(*a[1:]) if "%s" in fmt else fmt
        except (IndexError, ValueError):
            return fmt

    def expand(self, word):
        word = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda m: self.env.get(m.group(1), ""), word)
        return word.replace(NOEXPAND, "$")

    def c_env(self, a, i, l): return "".join(f"{k}={v}\n" for k, v in sorted(self.env.items()))
    c_printenv = c_env

    def c_export(self, a, i, l):
        for x in a:
            if "=" in x:
                k, _, v = x.partition("=")
                self.env[k] = v

    def c_cd(self, a, i, l):
        target = self.path(a[0]) if a else self.home
        node = self.fs.get(target)
        if not node:
            self.status = 1
            return f"-bash: cd: {a[0]}: No such file or directory\n"
        if node["type"] != "dir":
            self.status = 1
            return f"-bash: cd: {a[0]}: Not a directory\n"
        if not self.can_read(node):
            self.status = 1
            return f"-bash: cd: {a[0]}: Permission denied\n"
        self.cwd = target

    def children(self, d):
        prefix = d.rstrip("/") + "/"
        return sorted(p[len(prefix):] for p in self.fs if p.startswith(prefix) and p != d and "/" not in p[len(prefix):])

    def c_ls(self, a, i, l):
        flags = "".join(x[1:] for x in a if x.startswith("-"))
        targets = [x for x in a if not x.startswith("-")] or ["."]
        out = []
        for t in targets:
            full = self.path(t)
            node = self.fs.get(full)
            if not node:
                self.status = 2
                out.append(f"ls: cannot access '{t}': No such file or directory\n")
                continue
            names = self.children(full) if node["type"] == "dir" else [t]
            if "a" not in flags:
                names = [n for n in names if not n.startswith(".")]
            elif node["type"] == "dir":
                names = [".", ".."] + names
            if "l" in flags:
                if node["type"] == "dir":
                    out.append(f"total {4 * len(names)}\n")
                for n in names:
                    p = full if node["type"] != "dir" else posixpath.normpath(posixpath.join(full, n))
                    out.append(self.long_line(self.fs.get(p, _dir()), n))
            elif names:
                out.append("  ".join(names) + "\n")
        return "".join(out)

    def long_line(self, node, name):
        kind = "d" if node["type"] == "dir" else "-"
        m = node["mode"]
        perms = "".join(c if m & (1 << (8 - k)) else "-" for k, c in enumerate("rwxrwxrwx"))
        if m & 0o1000:
            perms = perms[:-1] + "t"
        size = len(node["data"]) if node["type"] == "file" else 4096
        when = datetime.fromtimestamp(node["mtime"]).strftime("%b %d %H:%M")
        return f"{kind}{perms} 1 {node['owner']:<5} {node['owner']:<5} {size:>6} {when} {name}\n"
    c_ll = lambda self, a, i, l: self.c_ls(["-la"] + a, i, l)

    def read(self, name):
        full = self.path(name)
        node = self.fs.get(full)
        if not node:
            return None, f"{name}: No such file or directory"
        if node["type"] == "dir":
            return None, f"{name}: Is a directory"
        if not self.can_read(node):
            return None, f"{name}: Permission denied"
        return node["data"].decode("utf-8", "replace"), None

    def c_cat(self, a, i, l):
        files = [x for x in a if not x.startswith("-")]
        if not files:
            return i or ""
        out = []
        for f in files:
            text, err = self.read(f)
            if err:
                self.status = 1
                out.append(f"cat: {err}\n")
            else:
                out.append(text)
        return "".join(out)

    def _lines_cmd(self, a, i, take):
        n, by_bytes, files = 10, False, []
        it = iter(a)
        for x in it:
            if x in ("-n", "-c"):
                by_bytes = x == "-c"
                n = int(next(it, "10").lstrip("+-") or 10)
            elif x.startswith(("-n", "-c")) and x[2:].isdigit():
                by_bytes, n = x[1] == "c", int(x[2:])
            elif x.startswith("-") and x[1:].isdigit():
                n = int(x[1:])
            else:
                files.append(x)
        text = i or ""
        if files:
            text, err = self.read(files[0])
            if err:
                self.status = 1
                return f"{err}\n"
        if by_bytes:
            return "".join(take(list(text), n))
        return "".join(take(text.splitlines(True), n))

    def c_head(self, a, i, l): return self._lines_cmd(a, i, lambda ls, n: ls[:n])
    def c_tail(self, a, i, l): return self._lines_cmd(a, i, lambda ls, n: ls[-n:] if n else [])

    def c_grep(self, a, i, l):
        args = [x for x in a if not x.startswith("-")]
        if not args:
            return "Usage: grep [OPTION]... PATTERNS [FILE]...\n"
        pat, files = args[0], args[1:]
        text = i or ""
        if files:
            text, err = self.read(files[0])
            if err:
                self.status = 2
                return f"grep: {err}\n"
        insensitive = "-i" in a
        found = [ln for ln in text.splitlines(True) if (pat.lower() in ln.lower() if insensitive else pat in ln)]
        self.status = 0 if found else 1
        return "".join(found)

    def c_wc(self, a, i, l):
        text = i or ""
        files = [x for x in a if not x.startswith("-")]
        if files:
            text, err = self.read(files[0])
            if err:
                return f"wc: {err}\n"
        if "-l" in a:
            return f"{text.count(chr(10))}\n"
        return f"{text.count(chr(10)):>7} {len(text.split()):>7} {len(text.encode()):>7}\n"

    def c_mkdir(self, a, i, l):
        parents = "-p" in a
        for d in (x for x in a if not x.startswith("-")):
            full = self.path(d)
            if full in self.fs:
                if not parents:
                    self.status = 1
                    return f"mkdir: cannot create directory '{d}': File exists\n"
                continue
            parent = posixpath.dirname(full)
            if parent not in self.fs and not parents:
                self.status = 1
                return f"mkdir: cannot create directory '{d}': No such file or directory\n"
            chain = []
            p = full
            while p not in self.fs:
                chain.append(p)
                p = posixpath.dirname(p)
            for p in reversed(chain):
                self.fs[p] = _dir(owner=self.user)

    def c_touch(self, a, i, l):
        for f in (x for x in a if not x.startswith("-")):
            full = self.path(f)
            if full in self.fs:
                self.fs[full]["mtime"] = time.time()
            else:
                err = self.write_file(f, b"")
                if err:
                    return "touch: cannot touch '" + f + "': No such file or directory\n"

    def c_rm(self, a, i, l):
        recursive = any(x.startswith("-") and ("r" in x or "R" in x) for x in a)
        for f in (x for x in a if not x.startswith("-")):
            full = self.path(f)
            node = self.fs.get(full)
            if not node:
                if not any("f" in x for x in a if x.startswith("-")):
                    self.status = 1
                    return f"rm: cannot remove '{f}': No such file or directory\n"
                continue
            if node["type"] == "dir" and not recursive:
                self.status = 1
                return f"rm: cannot remove '{f}': Is a directory\n"
            if full == "/":
                return "rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe\n"
            for p in [p for p in self.fs if p == full or p.startswith(full + "/")]:
                del self.fs[p]
    c_rmdir = c_rm

    def c_cp(self, a, i, l):
        args = [x for x in a if not x.startswith("-")]
        if len(args) < 2:
            return "cp: missing destination file operand\n"
        text, err = self.read(args[0])
        if err:
            self.status = 1
            return f"cp: cannot stat {err}\n"
        dst = args[1]
        if self.fs.get(self.path(dst), {}).get("type") == "dir":
            dst = posixpath.join(dst, posixpath.basename(args[0]))
        return self.write_file(dst, self.fs[self.path(args[0])]["data"], source=l)

    def c_mv(self, a, i, l):
        args = [x for x in a if not x.startswith("-")]
        if len(args) < 2:
            return "mv: missing destination file operand\n"
        src, dst = self.path(args[0]), self.path(args[1])
        if src not in self.fs:
            self.status = 1
            return f"mv: cannot stat '{args[0]}': No such file or directory\n"
        if self.fs.get(dst, {}).get("type") == "dir":
            dst = posixpath.join(dst, posixpath.basename(src))
        for p in [p for p in self.fs if p == src or p.startswith(src + "/")]:
            self.fs[dst + p[len(src):]] = self.fs.pop(p)

    def c_chmod(self, a, i, l):
        args = [x for x in a if not x.startswith("-") or re.fullmatch(r"-[rwx]+", x)]
        if len(args) < 2:
            return "chmod: missing operand\n"
        mode, files = args[0], args[1:]
        for f in files:
            node = self.fs.get(self.path(f))
            if not node:
                self.status = 1
                return f"chmod: cannot access '{f}': No such file or directory\n"
            if re.fullmatch(r"[0-7]{3,4}", mode):
                node["mode"] = int(mode, 8)
            elif "+x" in mode:
                node["mode"] |= 0o111
    c_chown = c_true
    c_chattr = c_true

    def c_ps(self, a, i, l):
        return ("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root           1  0.0  0.1 168392 11200 ?        Ss   Apr15   0:15 /sbin/init\n"
                "root           2  0.0  0.0      0     0 ?        S    Apr15   0:00 [kthreadd]\n"
                "root         540  0.0  0.1  72456  6320 ?        S<s  Apr15   0:02 /lib/systemd/systemd-journald\n"
                "root         890  0.0  0.1  15816  5400 ?        Ss   Apr15   0:01 sshd: /usr/sbin/sshd -D [listener]\n"
                "root        1020  0.0  0.0  14520  2100 ?        Ss   Apr15   0:00 /usr/sbin/cron -f -P\n"
                "postgres    1187  0.0  1.2 218112 98720 ?        Ss   Apr15   1:12 /usr/lib/postgresql/14/bin/postgres\n"
                f"{self.user:<8}    4210  0.0  0.0  16420  4800 pts/0    Ss   21:50   0:00 -bash\n"
                f"{self.user:<8}    4235  0.0  0.0  18900  3200 pts/0    R+   21:55   0:00 ps {' '.join(a)}\n")
    c_top = c_ps

    def c_free(self, a, i, l):
        return ("               total        used        free      shared  buff/cache   available\n"
                "Mem:         8131576     2810196     1123412       12544     4197968     5021380\n"
                "Swap:        2097148           0     2097148\n")

    def c_df(self, a, i, l):
        return ("Filesystem     1K-blocks     Used Available Use% Mounted on\n"
                "/dev/sda1       81120924 23512704  53491836  31% /\n"
                "tmpfs            4065788        0   4065788   0% /dev/shm\n")

    def c_ifconfig(self, a, i, l):
        return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 192.168.1.150  netmask 255.255.255.0  broadcast 192.168.1.255\n"
                "        ether 52:54:00:3a:91:7c  txqueuelen 1000  (Ethernet)\n\n"
                "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n")

    def c_ip(self, a, i, l):
        return ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
                "    inet 192.168.1.150/24 brd 192.168.1.255 scope global eth0\n")

    def c_which(self, a, i, l):
        out = []
        for x in a:
            if hasattr(self, "c_" + x):
                out.append(f"/usr/bin/{x}\n")
            else:
                self.status = 1
        return "".join(out)
    c_command = lambda self, a, i, l: self.c_which([x for x in a if not x.startswith("-")], i, l)

    def c_history(self, a, i, l):
        return "".join(f" {n:4d}  {h}\n" for n, h in enumerate(self.history[-50:], 1))

    def c_crontab(self, a, i, l):
        if "-l" in a:
            self.status = 1
            return f"no crontab for {self.user}\n"
        if i:  # crontab - <<< ...
            self.report_file("crontab:" + self.user, i.encode(), l)

    def c_sudo(self, a, i, l):
        args = [x for x in a if not x.startswith("-")]
        if "-l" in a or not args:
            return (f"Matching Defaults entries for {self.user} on {HOSTNAME}:\n    env_reset, mail_badpass\n\n"
                    f"User {self.user} may run the following commands on {HOSTNAME}:\n    (ALL : ALL) ALL\n")
        return self.run(args, i, l)
    c_nohup = lambda self, a, i, l: self.run(a, i, l)

    def c_su(self, a, i, l):
        return ""

    def c_exit(self, a, i, l):
        self.exit = True
    c_logout = c_exit

    def c_kill(self, a, i, l): return ""
    c_pkill = c_killall = c_kill
    c_systemctl = c_service = c_kill

    def c_bash(self, a, i, l):
        if "-c" in a:
            idx = a.index("-c")
            return self.run_line(a[idx + 1]) if idx + 1 < len(a) else ""
        script = None
        files = [x for x in a if not x.startswith("-")]
        if files:
            script, err = self.read(files[0])
            if err:
                self.status = 127
                return f"bash: {err}\n"
        elif i:
            script = i
        out = []
        for line in (script or "").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                self.history.append(line)
                emit("command", self.peer, username=self.user, data={"line": line, "mode": "script"})
                out.append(self.run_line(line))
        return "".join(out)
    c_sh = c_dash = c_busybox_sh = c_bash

    def c_base64(self, a, i, l):
        import base64
        files = [x for x in a if not x.startswith("-")]
        text = i or ""
        if files:
            text, err = self.read(files[0])
            if err:
                return f"base64: {err}\n"
        if "-d" in a or "--decode" in a:
            try:
                return base64.b64decode("".join(text.split()) + "==").decode("utf-8", "replace")
            except ValueError:
                self.status = 1
                return "base64: invalid input\n"
        return base64.b64encode(text.encode()).decode() + "\n"

    def download(self, url, out_path, line):
        """Загрузка wget/curl. Событие payload пишется всегда; файл в виртуальной ФС и
        копия в HF_DATA_DIR — только если файл действительно скачан. Иначе
        атакующий видит обрыв по таймауту, как за файрволом. Возвращает текст или None."""
        data, err = fetch(url) if DOWNLOAD else (None, "downloads disabled")
        full = self.path(out_path) if out_path and out_path != "-" else None
        if data is not None and full:
            self.write_file(out_path, data, report=False)
        self.report_file(full, data or b"", line, url=url, downloaded=data is not None, error=err)
        if data and DATA_DIR:
            d = os.path.join(DATA_DIR, "downloads")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, hashlib.sha256(data).hexdigest()), "wb") as f:
                f.write(data)
        return None if data is None else data.decode("utf-8", "replace")

    def c_wget(self, a, i, l):
        urls = [x for x in a if re.match(r"^(https?|ftp)://", x)] or [x for x in a if not x.startswith("-")]
        out = None
        if "-O" in a and a.index("-O") + 1 < len(a):
            out = a[a.index("-O") + 1]
        if not urls:
            return "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n"
        url = urls[0] if "://" in urls[0] else "http://" + urls[0]
        u = urllib.parse.urlsplit(url)
        host, port = u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
        name = out or posixpath.basename(u.path) or "index.html"
        text = self.download(url, name, l)
        quiet = "-q" in a or "-qO-" in a
        head = f"--{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S}--  {url}\nConnecting to {host}:{port}... "
        if text is None:
            self.status = 4
            return "" if quiet else head + "failed: Connection timed out.\nRetrying.\n\n"
        if out == "-":
            return text
        if quiet:
            return ""
        size = len(text.encode())
        return (head + "connected.\nHTTP request sent, awaiting response... 200 OK\n"
                f"Length: {size} [application/octet-stream]\nSaving to: '{name}'\n\n"
                f"{name}              100%[===================>]  {size}  --.-KB/s    in 0.01s\n\n")

    def c_curl(self, a, i, l):
        urls = [x for x in a if re.match(r"^https?://", x)] or [x for x in a if not x.startswith("-")]
        if not urls:
            return "curl: try 'curl --help' or 'curl --manual' for more information\n"
        out = None
        for flag in ("-o", "--output"):
            if flag in a and a.index(flag) + 1 < len(a):
                out = a[a.index(flag) + 1]
        if "-O" in a or "--remote-name" in a:
            out = posixpath.basename(urllib.parse.urlsplit(urls[0]).path) or "index.html"
        url = urls[0] if "://" in urls[0] else "http://" + urls[0]
        text = self.download(url, out or "-", l)
        if text is None:
            self.status = 28
            u = urllib.parse.urlsplit(url)
            port = u.port or (443 if u.scheme == "https" else 80)
            return f"curl: (28) Failed to connect to {u.hostname} port {port} after 10001 ms: Timeout was reached\n"
        return "" if out else text
    c_fetch = c_curl

    def c_python3(self, a, i, l):
        files = [x for x in a if not x.startswith("-")]
        if "-c" in a or not files:
            return ""
        self.status = 2
        return f"python3: can't open file '{self.path(files[0])}': [Errno 2] No such file or directory\n"
    c_python = c_perl = c_python3


# ------------------------------ SSH ------------------------------

class Server(paramiko.ServerInterface):
    def __init__(self, peer):
        self.peer = peer
        self.user = None
        self.attempts = 0
        self.requests = {}  # chanid -> ("shell" | "exec", command)
        self.ready = {}     # chanid -> Event
        self.lock = threading.Lock()

    def _ready(self, chanid):
        with self.lock:
            return self.ready.setdefault(chanid, threading.Event())

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        emit("auth", self.peer, username=username, data={
            "auth_type": "publickey", "status": "failed",
            "key_type": key.get_name(), "fingerprint": key.fingerprint})
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        self.attempts += 1
        ok = AUTH_MODE == "accept_all" or (AUTH_MODE == "require_list" and f"{username}:{password}" in ALLOWED)
        emit("auth", self.peer, username=username, password=password, data={
            "auth_type": "password", "status": "success" if ok else "failed", "attempt": self.attempts})
        if ok:
            self.user = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_window_change_request(self, *a):
        return True

    def check_channel_env_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        self.requests[channel.get_id()] = ("shell", None)
        self._ready(channel.get_id()).set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.requests[channel.get_id()] = ("exec", command.decode("utf-8", "replace"))
        self._ready(channel.get_id()).set()
        return True

    def check_channel_subsystem_request(self, channel, name):
        emit("command", self.peer, username=self.user, data={"line": f"subsystem {name}", "mode": "subsystem"})
        return False


def serve_channel(server, chan, shell):
    if not server._ready(chan.get_id()).wait(30):
        chan.close()
        return
    kind, command = server.requests.get(chan.get_id(), ("shell", None))
    try:
        if kind == "exec":
            shell.history.append(command)
            emit("command", server.peer, username=shell.user, data={"line": command, "mode": "exec"})
            shell.interactive = False
            try:
                out = shell.run_line(command)
            finally:
                shell.interactive = True
            chan.sendall(out.encode())
            chan.send_exit_status(shell.status)
        else:
            interactive(server, chan, shell)
    except (OSError, EOFError, paramiko.SSHException):
        pass
    finally:
        chan.close()


def interactive(server, chan, shell):
    def prompt():
        mark = "#" if shell.user == "root" else "$"
        chan.send(f"{shell.user}@{HOSTNAME}:{shell.short_cwd()}{mark} ".encode())

    chan.settimeout(600)
    if MOTD:
        chan.send((MOTD if MOTD.endswith("\r\n") else MOTD + "\r\n").encode())
    chan.send(f"Last login: {datetime.now(timezone.utc):%a %b %d %H:%M:%S %Y} from 10.0.2.15\r\n".encode())
    prompt()
    buf = bytearray()
    while not shell.exit:
        data = chan.recv(1024)
        if not data:
            break
        i = 0
        while i < len(data):
            b = data[i]
            i += 1
            if b in (13, 10):
                if b == 10 and i > 1 and data[i - 2] == 13:
                    continue
                chan.send(b"\r\n")
                line = buf.decode("utf-8", "replace").strip()
                buf.clear()
                if line:
                    shell.history.append(line)
                    emit("command", server.peer, username=shell.user, data={"line": line, "mode": "interactive"})
                    out = shell.run_line(line)
                    if out:
                        chan.send(out.replace("\r\n", "\n").replace("\n", "\r\n").encode())
                if shell.exit:
                    chan.send(b"logout\r\n")
                    break
                prompt()
            elif b in (127, 8):
                if buf:
                    buf.pop()
                    chan.send(b"\b \b")
            elif b == 3:  # Ctrl-C
                buf.clear()
                chan.send(b"^C\r\n")
                prompt()
            elif b == 4:  # Ctrl-D
                if not buf:
                    chan.send(b"logout\r\n")
                    shell.exit = True
                    break
            elif b == 27:  # стрелки и прочие escape-последовательности — пропускаем
                while i < len(data) and not (64 <= data[i] <= 126 and data[i] != 91):
                    i += 1
                i += 1
            elif b == 9:
                continue
            elif b >= 32:
                buf.append(b)
                chan.send(bytes([b]))
    chan.send_exit_status(0)


def handle_client(sock, peer, keys):
    peer = (peer[0], peer[1])
    emit("connect", peer)
    started = time.time()
    server = Server(peer)
    transport = None
    shell = None
    commands = 0
    try:
        transport = paramiko.Transport(sock)
        transport.local_version = BANNER
        for k in keys:
            transport.add_server_key(k)
        transport.start_server(server=server)
        threads, last = [], time.time()
        # Канал за каналом, пока клиент не уйдёт: exec и shell в одном соединении — норма.
        while transport.is_active():
            chan = transport.accept(1)
            if chan is None:
                if any(t.is_alive() for t in threads):
                    last = time.time()
                elif time.time() - last > (120 if server.user is None else 600):
                    break
                continue
            if shell is None:
                shell = Shell(server.user or "root", peer)
            t = threading.Thread(target=serve_channel, args=(server, chan, shell), daemon=True)
            t.start()
            threads.append(t)
    except (paramiko.SSHException, EOFError, OSError) as e:
        log(f"{peer[0]}:{peer[1]}: {e}")
    finally:
        if shell:
            commands = len(shell.history)
        emit("disconnect", peer, username=server.user, data={
            "duration": round(time.time() - started, 2), "commands": commands})
        if transport:
            transport.close()
        sock.close()


def main():
    keys = host_keys()
    if not keys:
        log("CRITICAL: нет ни одного ключа хоста")
        sys.exit(1)
    srv = socket.socket(socket.AF_INET6 if ":" in BIND else socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((BIND, PORT))
    except OSError as e:
        log(f"CRITICAL: не удалось занять {BIND}:{PORT}: {e}")
        sys.exit(1)
    srv.listen(128)
    log(f"Cowrie-style SSH на {BIND}:{PORT}, баннер {BANNER}, ключи: {', '.join(k.get_name() for k in keys)}")
    while True:
        sock, peer = srv.accept()
        threading.Thread(target=handle_client, args=(sock, peer, keys), daemon=True).start()


if __name__ == "__main__":
    main()
