#!/bin/sh
# Пример своей ловушки HoneyForge в режиме stdio.
#
# Порт слушает агент. На каждое подключение он запускает этот скрипт:
#   stdin  — что прислал клиент,
#   stdout — что клиент увидит,
#   stderr — события (строка JSON с полем "type") и журнал.
# Адрес клиента и сессию агент подставит в события сам; они есть и в
# окружении: HF_SRC_IP, HF_SRC_PORT, HF_SESSION. Параметры — в HF_PARAMS.

prompt=$(printf '%s' "$HF_PARAMS" | sed -n 's/.*"prompt" *: *"\([^"]*\)".*/\1/p')
[ -n "$prompt" ] || prompt='root@db01:~# '

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

printf 'Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\n\n'
while printf '%s' "$prompt" && IFS= read -r line; do
    printf '{"type":"command","data":{"line":"%s"}}\n' "$(json_escape "$line")" >&2
    case "$line" in
        exit|logout) break ;;
        whoami) echo root ;;
        id) echo 'uid=0(root) gid=0(root) groups=0(root)' ;;
        uname*) echo 'Linux db01 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux' ;;
        '') ;;
        *) echo "-sh: ${line%% *}: command not found" ;;
    esac
done
