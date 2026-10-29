#!/usr/bin/env bash
# =============================================================================
#  smartdns-setup.sh — Smart DNS (DNS-unlock) для обхода гео-блокировок
#
#  Как это работает:
#    • dnsmasq  — для доменов из списка (Claude, ChatGPT, Gemini, Xbox, PlayStation)
#                 отвечает IP ЭТОГО сервера; всё остальное форвардит на публичные
#                 DNS (1.1.1.1 / 8.8.8.8) => остальной трафик идёт НАПРЯМУЮ.
#    • nginx    — SNI-прокси на :443 и HTTP-прокси на :80. Пропускает только домены
#                 из списка, всё прочее отбрасывает (это не открытый прокси).
#    • DoT      — <ваш домен>:853 с сертификатом Let's Encrypt
#                 (Android: Настройки → Частный DNS → ваш домен).
#
#  Требования: Debian/Ubuntu + systemd, root, свободные порты 53, 80, 443, 853.
#  Сервер должен стоять в стране, где эти сервисы доступны (например, США/ЕС).
#
#  Использование:  sudo bash smartdns-setup.sh [опции]   (см. --help)
#
#  Диагностика:
#    • /var/log/smartdns-setup.log — лог установки (ПОЛНАЯ трассировка команд)
#    • smartdns-ctl diag           — отчёт о состоянии (сохраняется в файл)
#    • smartdns-ctl logs [-f]      — журналы сервисов;  smartdns-ctl debug on — подробные логи
# =============================================================================
set -Eeuo pipefail
export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
umask 022

LOG_FILE=${SMARTDNS_LOG:-/var/log/smartdns-setup.log}
VERBOSE=${SMARTDNS_VERBOSE:-0}
MAIN_PID=$$
STEP_NO=0
STEP_TOTAL=7
CUR_STEP="запуск"
C_R=''; C_G=''; C_Y=''; C_C=''; C_D=''; C_0=''

# ═════════════════ общие функции (копируются в /usr/local/lib/smartdns) ═════
# Всё, что между этой строкой и «конец общих функций», доступно и smartdns-ctl.

init_ui() {
  if [[ -t 2 ]]; then
    C_R=$'\e[1;31m'; C_G=$'\e[1;32m'; C_Y=$'\e[1;33m'; C_C=$'\e[1;36m'; C_D=$'\e[2m'; C_0=$'\e[0m'
  else
    C_R=''; C_G=''; C_Y=''; C_C=''; C_D=''; C_0=''
  fi
}

_logf() { # уровень сообщение  — запись ТОЛЬКО в файл лога
  [[ -n ${LOG_FILE:-} ]] || return 0
  printf '%s [%-5s] %s\n' "$(date '+%F %T')" "$1" "$2" >>"$LOG_FILE" 2>/dev/null || true
}
log()  { printf '%s[+]%s %s\n' "$C_G" "$C_0" "$*"; _logf INFO "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_Y" "$C_0" "$*" >&2; _logf WARN "$*"; }
err()  { printf '%s[x]%s %s\n' "$C_R" "$C_0" "$*" >&2; _logf ERROR "$*"; }
note() { printf '      %s\n' "$*" >&2; _logf INFO "      $*"; }
dbg()  {
  _logf DEBUG "$*"
  if (( ${VERBOSE:-0} )); then printf '%s[·] %s%s\n' "$C_D" "$*" "$C_0" >&2; fi
  return 0
}
die()  { err "$*"; exit 1; }

step() {
  STEP_NO=$((STEP_NO + 1)); CUR_STEP="$*"
  printf '\n%s[%d/%d]%s %s\n' "$C_C" "$STEP_NO" "${STEP_TOTAL:-0}" "$C_0" "$*"
  _logf STEP "[$STEP_NO/${STEP_TOTAL:-0}] $*"
}

# Обработчик ERR: где именно упало, какая команда, какой стек функций.
on_err() { # код строка команда
  local rc=$1 line=$2 cmd=$3 stack="" i
  for ((i = 1; i < ${#FUNCNAME[@]}; i++)); do stack+="${FUNCNAME[i]} <- "; done
  stack=${stack% <- }
  _logf ERROR "rc=$rc строка=$line стек=[${stack:-main}] команда=[$cmd]"
  if [[ ${BASHPID:-$$} != "${MAIN_PID:-$$}" ]]; then return 0; fi   # из подоболочки — только в лог
  err "Непредвиденная ошибка: команда вернула код $rc"
  note "строка  : $line"
  note "функция : ${stack:-main}"
  note "команда : $cmd"
  return 0
}

# run "описание" команда арг…  — вывод команды уходит в лог; при ошибке на экран
# выводится хвост вывода. Код возврата = код команды. Последний вывод — в $RUN_LAST.
RUN_LAST=""
run() {
  local desc=$1 out rc=0; shift
  out=$(mktemp /tmp/smartdns.XXXXXX) || return 1
  dbg "RUN [$desc]: $*"
  if "$@" </dev/null >"$out" 2>&1; then rc=0; else rc=$?; fi
  { printf -- '----- %s: %s (код %s) -----\n' "$desc" "$*" "$rc"; cat "$out"; printf -- '-----\n'; } >>"${LOG_FILE:-/dev/null}" 2>/dev/null || true
  RUN_LAST=$(tail -n 80 "$out" 2>/dev/null || true)
  if (( rc != 0 )); then
    err "Не удалось: $desc (код $rc)"
    note "команда: $*"
    tail -n "${RUN_TAIL:-15}" "$out" 2>/dev/null | sed 's/^/      | /' >&2 || true
  fi
  rm -f "$out"
  return "$rc"
}

lock_holders() { # кто сейчас держит apt/dpkg
  ps -eo pid=,etime=,comm= 2>/dev/null \
    | awk '$3 ~ /^(apt|apt-get|dpkg|unattended-up|packagekitd|aptd)/ { print "pid " $1 " (" $3 ", работает " $2 ")" }' || true
}

# apt_run "описание" <аргументы apt-get>  — ждёт блокировку dpkg, повторяет при сбое
apt_run() {
  local desc=$1 n tries=3 h l; shift
  for ((n = 1; n <= tries; n++)); do
    if run "$desc (попытка $n/$tries)" apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 \
         -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"; then
      return 0
    fi
    h=$(lock_holders)
    if [[ -n $h ]]; then
      warn "apt/dpkg занят другим процессом (часто unattended-upgrades на свежем VPS):"
      while IFS= read -r l; do note "$l"; done <<<"$h"
    fi
    if (( n < tries )); then warn "Повторю через $((n * 5)) с…"; sleep $((n * 5)); fi
  done
  return 1
}

ipv4_ok() { # корректный IPv4 (каждый октет 0–255)
  local ip=$1 o
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.
  for o in $ip; do (( 10#$o <= 255 )) || return 1; done
  return 0
}

cidr_ok() { # IPv4 или IPv4/маска
  local ip=${1%%/*} mask=""
  if [[ $1 == */* ]]; then mask=${1#*/}; fi
  ipv4_ok "$ip" || return 1
  if [[ -n $mask ]]; then
    [[ $mask =~ ^[0-9]{1,2}$ ]] || return 1
    (( 10#$mask <= 32 )) || return 1
  fi
  return 0
}

ip_is_private() {
  [[ $1 =~ ^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]
}

domain_ok() {
  local re='^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$'
  [[ $1 =~ $re ]]
}

norm_domain() { # печатает нормализованный домен; код 1 — домен некорректен
  local d=${1,,}
  d=${d//[[:space:]]/}; d=${d#*://}; d=${d%%/*}; d=${d%%:*}; d=${d#\*.}; d=${d#.}; d=${d%.}
  domain_ok "$d" || return 1
  printf '%s' "$d"
}

# port_listeners proto port → строки «адрес:порт процесс» (нужен root для имени процесса)
port_listeners() {
  local flag=-ltnp
  if [[ $1 == udp ]]; then flag=-lunp; fi
  ss "$flag" 2>/dev/null | awk -v suf=":$2" '
    NR > 1 {
      a = $4
      if (length(a) >= length(suf) && substr(a, length(a) - length(suf) + 1) == suf) {
        p = ($NF ~ /^users:/) ? $NF : "-"
        print a, p
      }
    }' || true
}

# port_conflicts proto port [наши_адреса…] — кто мешает нам занять порт.
# Без адресов любой слушатель считается конфликтом.
port_conflicts() {
  local proto=$1 port=$2 line addr m hit; shift 2
  local -a mine=("$@")
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    addr=${line%% *}
    hit=0
    if (( ${#mine[@]} == 0 )); then
      hit=1
    else
      case $addr in
        "0.0.0.0:$port"|"*:$port"|"[::]:$port") hit=1 ;;
      esac
      for m in "${mine[@]}"; do
        if [[ $addr == "$m:$port" ]]; then hit=1; fi
      done
    fi
    if (( hit )); then printf '%s\n' "$line"; fi
  done < <(port_listeners "$proto" "$port")
  return 0
}

listening() { # proto адрес порт — слушает ли кто-то именно этот адрес:порт
  port_listeners "$1" "$3" \
    | awk -v w="$2:$3" -v w2="*:$3" '$1 == w || (w ~ /^0\.0\.0\.0:/ && $1 == w2) { f = 1 } END { exit !f }'
}

wait_listen() { # proto адрес порт [секунд]
  local i max=$(( ${4:-10} * 4 ))
  for ((i = 0; i < max; i++)); do
    if listening "$1" "$2" "$3"; then return 0; fi
    sleep 0.25
  done
  return 1
}

svc_tail() { # unit [строк] — состояние сервиса + хвост журнала (и в лог тоже)
  local u=$1 n=${2:-25}
  warn "Состояние $u: $(systemctl is-active "$u" 2>/dev/null || true)"
  if command -v journalctl >/dev/null 2>&1; then
    { journalctl -u "$u" -n "$n" --no-pager -o cat 2>&1 || true; } \
      | tee -a "${LOG_FILE:-/dev/null}" | sed 's/^/      | /' >&2 || true
  fi
}

dns_a() { # имя [dns-сервер] → A-записи, по одной в строке
  local h=$1 srv=${2:-}
  if command -v dig >/dev/null 2>&1; then
    if [[ -n $srv ]]; then
      dig +short +time=3 +tries=1 "@$srv" A "$h" 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' || true
    else
      dig +short +time=3 +tries=1 A "$h" 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' || true
    fi
  elif [[ -z $srv ]]; then
    getent ahostsv4 "$h" 2>/dev/null | awk '{ print $1 }' | sort -u || true
  fi
  return 0
}

nginx_feature() { # есть ли в `nginx -V` указанный флаг сборки
  local v
  v=$("$NGINX_BIN" -V 2>&1 || true)
  [[ $v == *"$1"* ]]
}

# Печатает строку load_module (пусто, если stream вшит в nginx). Код 1 — stream недоступен.
nginx_stream_load() {
  local v m re='--with-stream([[:space:]]|$)'
  v=$("$NGINX_BIN" -V 2>&1 || true)
  if [[ $v == *"--with-stream=dynamic"* ]]; then
    for m in /usr/lib/nginx/modules /usr/lib64/nginx/modules /usr/share/nginx/modules /etc/nginx/modules; do
      if [[ -f $m/ngx_stream_module.so ]]; then printf 'load_module %s/ngx_stream_module.so;' "$m"; return 0; fi
    done
    return 1
  fi
  [[ $v =~ $re ]]
}
# ═════════════════ конец общих функций ═══════════════════════════════════════

COMMON_FUNCS=(init_ui _logf log warn err note dbg die step on_err run lock_holders apt_run
              ipv4_ok cidr_ok ip_is_private domain_ok norm_domain port_listeners port_conflicts
              listening wait_listen svc_tail dns_a nginx_feature nginx_stream_load)

CONF_DIR=/etc/smartdns
STATE_DIR=/var/lib/smartdns
LIB_DIR=/usr/local/lib/smartdns
LIB_FILE=$LIB_DIR/common.sh
CTL=/usr/local/bin/smartdns-ctl
UPSTREAM_DNS=${SMARTDNS_UPSTREAM:-"1.1.1.1 8.8.8.8"}

DOMAIN=${SMARTDNS_DOMAIN:-}
PUBLIC_IP=${SMARTDNS_IP:-}
EMAIL=${SMARTDNS_EMAIL:-}
ALLOW=${SMARTDNS_ALLOW:-}
NO_DOT=0
ASSUME_YES=0
MODE=install
INTERACTIVE=0

init_ui

usage() {
  cat <<'EOF'
Использование: sudo bash smartdns-setup.sh [опции]

  -d, --domain DOMAIN   домен/поддомен DNS-сервера (по умолчанию dns.meowcat.me);
                        используется для DoT и сертификата Let's Encrypt
  -i, --ip IP           публичный IPv4 сервера (по умолчанию определяется сам)
  -e, --email EMAIL     e-mail для Let's Encrypt (необязательно)
  -a, --allow "IP ..."  клиентские IP/CIDR через пробел, которым разрешён доступ
                        (по умолчанию — всем; ОТКРЫТЫЙ резолвер рискованно!)
      --no-dot          не выпускать сертификат и не включать DoT (853)
  -v, --verbose         показывать отладочные сообщения в консоли
      --log FILE        файл лога (по умолчанию /var/log/smartdns-setup.log)
  -y, --yes             не задавать вопросов
      uninstall         удалить Smart DNS
  -h, --help            эта справка

Те же значения можно передать переменными: SMARTDNS_DOMAIN, SMARTDNS_IP,
SMARTDNS_EMAIL, SMARTDNS_ALLOW, SMARTDNS_UPSTREAM, SMARTDNS_VERBOSE=1.
После установки управление — командой: smartdns-ctl help
Если что-то не работает:  smartdns-ctl diag   и   tail -n 100 /var/log/smartdns-setup.log
EOF
}

while (($#)); do
  case $1 in
    -d|--domain) DOMAIN=${2:?нужно значение для $1}; shift 2 ;;
    -i|--ip)     PUBLIC_IP=${2:?нужно значение для $1}; shift 2 ;;
    -e|--email)  EMAIL=${2:?нужно значение для $1}; shift 2 ;;
    -a|--allow)  ALLOW=${2:?нужно значение для $1}; shift 2 ;;
    --log)       LOG_FILE=${2:?нужно значение для $1}; shift 2 ;;
    --no-dot)    NO_DOT=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    -y|--yes)    ASSUME_YES=1; shift ;;
    uninstall|--uninstall) MODE=uninstall; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) die "Неизвестный параметр: $1 (см. --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Запустите от root: sudo bash $0"

if [[ $MODE == uninstall ]]; then
  [[ -x $CTL ]] || die "smartdns-ctl не найден — похоже, Smart DNS не установлен."
  exec "$CTL" uninstall
fi

# ─────────────────────────── лог, трассировка, обработчики ───────────────────
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
if ! { : >>"$LOG_FILE"; } 2>/dev/null; then
  LOG_FILE=/tmp/smartdns-setup.log
  : >>"$LOG_FILE"
fi
chmod 600 "$LOG_FILE" 2>/dev/null || true
printf '\n===== smartdns-setup: запуск %s, pid %s, аргументы: domain=%s ip=%s no_dot=%s allow=%s =====\n' \
  "$(date '+%F %T')" "$$" "${DOMAIN:-<спросим>}" "${PUBLIC_IP:-<авто>}" "$NO_DOT" "${ALLOW:-<пусто>}" >>"$LOG_FILE"

# xtrace пишется ТОЛЬКО в файл лога — консоль остаётся чистой, но по логу видна каждая команда
if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 1) )); then
  exec {XTRACE_FD}>>"$LOG_FILE"
  BASH_XTRACEFD=$XTRACE_FD
  PS4='+${LINENO}:${FUNCNAME[0]:-main}: '
  set -x
else
  die "Нужен bash 4.1+ (сейчас $BASH_VERSION)."
fi

on_exit() {
  local rc=$?
  trap - EXIT
  if (( rc != 0 )); then
    echo >&2
    err "Установка прервана (код выхода $rc) на шаге «${CUR_STEP}»."
    note "Полный лог с трассировкой команд: $LOG_FILE"
    note "Последние строки: tail -n 80 $LOG_FILE"
    if [[ -x $CTL ]]; then note "Состояние сервисов и тесты: smartdns-ctl diag"; fi
    note "Повторный запуск безопасен (скрипт идемпотентен)."
  fi
  return 0
}
trap 'on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
trap on_exit EXIT
trap 'err "Прервано пользователем (Ctrl+C)"; exit 130' INT
trap 'err "Получен сигнал TERM"; exit 143' TERM

# ─────────────────────────── вспомогательное для установщика ─────────────────
ask() { # "вопрос" "значение по умолчанию"
  local q=$1 def=${2-} ans=""
  if (( INTERACTIVE )); then
    printf '%s%s: ' "$q" "${def:+ [$def]}" >&2
    read -r ans </dev/tty || ans=""
  fi
  ans=${ans//$'\r'/}
  ans=${ans#"${ans%%[![:space:]]*}"}; ans=${ans%"${ans##*[![:space:]]}"}
  dbg "ask «$q» → «${ans:-$def}»"
  printf '%s' "${ans:-$def}"
}

ask_until() { # ПЕРЕМЕННАЯ "вопрос" "умолчание" нормализатор "текст ошибки" ["начальное значение"]
  local __var=$1 q=$2 def=$3 fn=$4 msg=$5 raw=${6-} val n
  for ((n = 1; n <= 3; n++)); do
    if [[ -z $raw ]]; then raw=$(ask "$q" "$def"); fi
    if val=$("$fn" "$raw"); then printf -v "$__var" '%s' "$val"; return 0; fi
    warn "$msg: «$raw»"
    if (( ! INTERACTIVE )); then return 1; fi
    raw=""
  done
  return 1
}

norm_ip() { # печатает IPv4 без пробелов; код 1 — некорректный
  local v=${1//[[:space:]]/}
  ipv4_ok "$v" || return 1
  printf '%s' "$v"
}

os_name() {
  if [[ -r /etc/os-release ]]; then ( . /etc/os-release; printf '%s' "${PRETTY_NAME:-linux}" ); else printf 'linux'; fi
}

detect_public_ip() {
  local u ip
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com https://ipv4.icanhazip.com; do
    dbg "Запрашиваю внешний IP: $u"
    ip=$(curl -4 -fsS --max-time 5 "$u" 2>>"$LOG_FILE" | tr -d '[:space:]') || ip=""
    if ipv4_ok "$ip"; then dbg "  → $ip"; printf '%s' "$ip"; return 0; fi
    dbg "  → нет корректного ответа («$ip»)"
  done
  return 1
}

check_net() {
  local code
  code=$(curl -4 -sS -o /dev/null -w '%{http_code}' --max-time 8 https://acme-v02.api.letsencrypt.org/directory 2>>"$LOG_FILE") || code=000
  if [[ $code == 200 ]]; then
    log "Исходящий HTTPS работает (Let's Encrypt API доступен)."
  else
    warn "Let's Encrypt API недоступен (HTTP $code): выпуск сертификата для DoT может не удаться."
    note "Проверьте исходящий доступ и DNS самого сервера (cat /etc/resolv.conf)."
  fi
}

port_hint() { # порт
  case $1 in
    53)     note "Освободите порт 53: dnsmasq/bind9/unbound/pdns либо слушатель на 0.0.0.0:53."
            note "systemd-resolved на 127.0.0.53 НЕ мешает (мы слушаем 127.0.0.1 и $LOCAL_IP)." ;;
    80|443) note "Остановите веб-сервер: systemctl disable --now apache2 nginx caddy (или xray/x-ui на :$1)." ;;
    853)    note "Порт 853 занят (другой DoT/Stubby/AdGuard?). Освободите его или запустите с --no-dot." ;;
  esac
}

# ═════════════════ ШАГ 1. Проверка системы ═══════════════════════════════════
step "Проверка системы"
log "Лог установки: $LOG_FILE (в нём — трассировка каждой команды)"
log "Система: $(os_name) | ядро $(uname -r) | $(uname -m) | bash $BASH_VERSION"
dbg "виртуализация: $(systemd-detect-virt 2>/dev/null || true) | пользователь: $(id -un) | PATH=$PATH"

command -v apt-get   >/dev/null || die "Поддерживаются только Debian/Ubuntu (нужен apt)."
command -v systemctl >/dev/null || die "Нужен systemd."
[[ -d /run/systemd/system ]] || die "systemd не запущен как PID 1 (контейнер/WSL/chroot?): сервисы создать нельзя."

free_mb=$(df -Pm /var 2>/dev/null | awk 'NR==2 { print $4 }' || true)
if [[ ${free_mb:-} =~ ^[0-9]+$ ]] && (( free_mb < 300 )); then
  warn "Мало места на /var: ${free_mb} МБ (нужно ~300 МБ для пакетов)."
fi

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1
log "Обновляю индекс пакетов и ставлю базовые утилиты (curl, iproute2) — до минуты…"
apt_run "apt-get update" update -qq \
  || warn "apt-get update завершился с ошибкой — продолжаю с имеющимся кэшем (подробности в логе)."
apt_run "базовые пакеты" install -y -qq --no-install-recommends curl ca-certificates iproute2 \
  || die "Не удалось поставить curl/iproute2: проверьте сеть, DNS сервера и репозитории (см. вывод выше и $LOG_FILE)."
command -v ss >/dev/null || die "Нет утилиты ss (пакет iproute2) — установка не удалась."
check_net

# ═════════════════ ШАГ 2. Параметры ══════════════════════════════════════════
step "Параметры установки"
if (( ! ASSUME_YES )) && (: </dev/tty) 2>/dev/null; then INTERACTIVE=1; fi
if (( ! INTERACTIVE )); then
  warn "Интерактивный ввод недоступен (--yes или нет /dev/tty): вопросов не будет, беру параметры/значения по умолчанию."
fi
dbg "интерактивный режим: $INTERACTIVE"

ask_until DOMAIN "Домен/поддомен для DNS-сервера" "dns.meowcat.me" norm_domain \
  "Некорректный домен (нужен вид dns.example.com)" "$DOMAIN" \
  || die "Домен не задан/некорректен. Укажите: --domain dns.example.com"
log "Домен: $DOMAIN"

if [[ -z $PUBLIC_IP ]]; then
  log "Определяю публичный IPv4 сервера (до 5 с на каждый источник)…"
  detected=$(detect_public_ip || true)
  if [[ -n $detected ]]; then log "Внешний IP определён: $detected"; else warn "Автоопределение IP не удалось (нет исходящего HTTPS?)."; fi
  PUBLIC_IP=$(ask "Публичный IPv4 этого сервера" "$detected")
fi
PUBLIC_IP=$(norm_ip "$PUBLIC_IP") || die "Некорректный/не определён публичный IPv4: «${PUBLIC_IP}». Укажите: --ip 203.0.113.10"

LOCAL_IP=$(ip -4 route get 1.1.1.1 2>>"$LOG_FILE" | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }' || true)
if ! ipv4_ok "${LOCAL_IP:-}"; then
  dbg "ip route get не дал src — пробую первый глобальный адрес интерфейса"
  LOCAL_IP=$(ip -4 -o addr show scope global 2>>"$LOG_FILE" | awk 'NR == 1 { split($4, a, "/"); print a[1] }' || true)
fi
ipv4_ok "${LOCAL_IP:-}" || die "Не удалось определить локальный IPv4 интерфейса (нет IPv4-маршрута по умолчанию?). См. вывод: ip -4 addr; ip -4 route"

if ip_is_private "$PUBLIC_IP"; then
  warn "Публичный IP $PUBLIC_IP — частный адрес: клиенты из интернета до него не достучатся."
fi
if [[ $PUBLIC_IP != "$LOCAL_IP" ]]; then
  log "Сервер за NAT/с плавающим IP: внешний $PUBLIC_IP, на интерфейсе $LOCAL_IP (это нормально для облаков)."
fi

if (( ! NO_DOT )) && [[ -z $EMAIL ]]; then EMAIL=$(ask "E-mail для Let's Encrypt (можно пусто)" ""); fi
if [[ -n $EMAIL && ! $EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
  warn "E-mail «$EMAIL» выглядит некорректно — игнорирую (сертификат будет без e-mail)."
  EMAIL=""
fi
[[ -n $ALLOW ]] || ALLOW=$(ask "Разрешённые IP клиентов через пробел (пусто = всем)" "")
for ip in $ALLOW; do cidr_ok "$ip" || die "Некорректный IP/CIDR в --allow: $ip"; done

log "Итоговые параметры:"
note "домен          : $DOMAIN"
note "публичный IP   : $PUBLIC_IP   (локальный: $LOCAL_IP)"
note "e-mail         : ${EMAIL:-—}"
note "белый список   : ${ALLOW:-нет — резолвер ОТКРЫТ ВСЕМ}"
note "DoT (853)      : $(if (( NO_DOT )); then echo выкл; else echo вкл; fi)"
note "upstream DNS   : $UPSTREAM_DNS"
if (( INTERACTIVE )); then
  ans=$(ask "Продолжить установку? (Y/n)" "Y")
  if [[ $ans =~ ^[nNнН] ]]; then die "Отменено пользователем."; fi
fi

# ═════════════════ ШАГ 3. Проверка портов ════════════════════════════════════
step "Проверка свободных портов"
systemctl stop smartdns-proxy smartdns-dns 2>/dev/null || true   # повторный запуск скрипта

conflicts=0
for spec in udp:53 tcp:53 tcp:80 tcp:443 tcp:853; do
  proto=${spec%%:*}; port=${spec##*:}
  if (( NO_DOT )) && [[ $port == 853 ]]; then continue; fi
  if [[ $port == 53 ]]; then
    holders=$(port_conflicts "$proto" "$port" 127.0.0.1 "$LOCAL_IP")
  else
    holders=$(port_conflicts "$proto" "$port")
  fi
  if [[ -n $holders ]]; then
    conflicts=$((conflicts + 1))
    err "Порт $port/$proto занят:"
    while IFS= read -r l; do note "$l"; done <<<"$holders"
    port_hint "$port"
  else
    dbg "порт $port/$proto свободен"
  fi
done
if (( conflicts > 0 )); then
  die "Занято портов: $conflicts. Освободите их (подсказки выше) и запустите скрипт снова."
fi
log "Порты 53, 80, 443$(if (( ! NO_DOT )); then echo ', 853'; fi) свободны."

# ═════════════════ ШАГ 4. Пакеты ═════════════════════════════════════════════
step "Установка пакетов (dnsmasq, nginx + stream, certbot)"
log "Ставлю пакеты — это может занять 1–2 минуты…"
apt_run "установка dnsmasq/nginx/certbot" install -y -qq --no-install-recommends \
    dnsmasq-base nginx libnginx-mod-stream certbot \
  || die "Не удалось поставить dnsmasq-base/nginx/libnginx-mod-stream/certbot (вывод apt выше и в $LOG_FILE)."
apt_run "dnsutils (dig)" install -y -qq dnsutils \
  || apt_run "bind9-dnsutils (dig)" install -y -qq bind9-dnsutils \
  || warn "dig не установлен — часть самопроверок будет пропущена."
# системный nginx.service нам не нужен — работаем отдельным инстансом
systemctl disable --now nginx >/dev/null 2>&1 || warn "Не удалось отключить системный nginx.service (проверьте: systemctl status nginx)."

NGINX_BIN=$(command -v nginx || echo /usr/sbin/nginx)
DNSMASQ_BIN=$(command -v dnsmasq || echo /usr/sbin/dnsmasq)
[[ -x $NGINX_BIN && -x $DNSMASQ_BIN ]] || die "Не найдены бинарники nginx/dnsmasq (nginx=$NGINX_BIN, dnsmasq=$DNSMASQ_BIN)."
dbg "nginx: $("$NGINX_BIN" -v 2>&1 || true) | dnsmasq: $("$DNSMASQ_BIN" --version 2>&1 | sed -n 1p || true)"

nginx_stream_load >/dev/null \
  || die "У nginx нет модуля stream (нужен пакет libnginx-mod-stream). Проверьте: nginx -V 2>&1 | tr ' ' '\\n' | grep stream"
nginx_feature "--with-stream_ssl_preread_module" \
  || die "У nginx нет ssl_preread (--with-stream_ssl_preread_module) — SNI-прокси невозможен. Поставьте nginx из репозитория Debian/Ubuntu."
if (( ! NO_DOT )) && ! nginx_feature "--with-stream_ssl_module"; then
  warn "nginx собран без stream_ssl_module — DoT (853) невозможен, отключаю его."
  NO_DOT=1
fi
log "nginx: stream и ssl_preread доступны."

# ═════════════════ ШАГ 5. Конфигурация и сервисы ═════════════════════════════
step "Конфигурация и запуск сервисов"
log "Пишу конфигурацию в $CONF_DIR …"
mkdir -p "$CONF_DIR" "$STATE_DIR/acme" "$LIB_DIR"
chmod 755 "$STATE_DIR" "$STATE_DIR/acme"

{
  printf 'DOMAIN=%q\n'       "$DOMAIN"
  printf 'PUBLIC_IP=%q\n'    "$PUBLIC_IP"
  printf 'LOCAL_IP=%q\n'     "$LOCAL_IP"
  printf 'UPSTREAM_DNS=%q\n' "$UPSTREAM_DNS"
  printf 'EMAIL=%q\n'        "$EMAIL"
  printf 'ENABLE_DOT=%q\n'   "$(( NO_DOT ? 0 : 1 ))"
  printf 'DEBUG_LOG=%q\n'    "0"
  printf 'NGINX_BIN=%q\n'    "$NGINX_BIN"
  printf 'DNSMASQ_BIN=%q\n'  "$DNSMASQ_BIN"
} > "$CONF_DIR/smartdns.conf"
chmod 644 "$CONF_DIR/smartdns.conf"

if [[ ! -f $CONF_DIR/domains.list ]]; then
cat > "$CONF_DIR/domains.list" <<'EOF'
# Домены, которые идут через этот сервер. Один на строку.
# Записанный домен покрывает и все его поддомены (claude.ai => *.claude.ai).
# Всё, чего здесь нет, резолвится как обычно и ходит напрямую.
# После правки:  smartdns-ctl reload   (или:  smartdns-ctl add example.com)

# --- Claude / Anthropic
claude.ai
claude.com
anthropic.com
claudeusercontent.com

# --- ChatGPT / OpenAI
chatgpt.com
openai.com
oaistatic.com
oaiusercontent.com
sora.com

# --- Gemini / Google AI (только нужные хосты, а не весь google.com)
gemini.google.com
bard.google.com
aistudio.google.com
ai.google.dev
makersuite.google.com
notebooklm.google.com
labs.google
generativelanguage.googleapis.com
alkalimakersuite-pa.clients6.google.com
proactivebackend-pa.googleapis.com
robinfrontend-pa.googleapis.com

# --- Xbox
xboxlive.com
xbox.com
xboxservices.com
gamepass.com

# --- PlayStation
playstation.com
playstation.net
sonyentertainmentnetwork.com

# --- Примеры, если понадобятся (раскомментируйте):
# perplexity.ai
# grok.com
# x.ai
# copilot.microsoft.com
EOF
fi

if [[ ! -f $CONF_DIR/bypass.list ]]; then
cat > "$CONF_DIR/bypass.list" <<'EOF'
# Исключения: эти (под)домены идут НАПРЯМУЮ, даже если родитель есть в domains.list.
# Нужны, чтобы тяжёлые загрузки игр не гонялись через ваш сервер.
dlassets.xboxlive.com
dlassets-ssl.xboxlive.com
assets1.xboxlive.com
assets2.xboxlive.com
xvcf1.xboxlive.com
xvcf2.xboxlive.com
dl.playstation.net
EOF
fi

if [[ -n $ALLOW ]]; then
  { echo "# IP/CIDR клиентов, которым разрешён доступ. Пусто = доступ у всех."
    for ip in $ALLOW; do echo "$ip"; done; } > "$CONF_DIR/allowed_ips.list"
else
  [[ -f $CONF_DIR/allowed_ips.list ]] || echo "# IP/CIDR клиентов, которым разрешён доступ. Пусто = доступ у всех." > "$CONF_DIR/allowed_ips.list"
fi

# ---- общие функции для smartdns-ctl (из этого же скрипта — один источник правды)
{
  echo "# Сгенерировано smartdns-setup.sh — общие функции для smartdns-ctl. Не править."
  declare -f "${COMMON_FUNCS[@]}"
} > "$LIB_FILE"
chmod 644 "$LIB_FILE"
bash -n "$LIB_FILE" || die "Сгенерированная библиотека $LIB_FILE содержит синтаксическую ошибку (баг скрипта)."

# ----------------------------------------------------- smartdns-ctl ----------
cat > "$CTL" <<'CTL_EOF'
#!/usr/bin/env bash
# smartdns-ctl — управление Smart DNS (dnsmasq + nginx)
set -Eeuo pipefail
export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1

CONF_DIR=${SMARTDNS_CONF_DIR:-/etc/smartdns}
STATE_DIR=${SMARTDNS_STATE_DIR:-/var/lib/smartdns}
LIB_FILE=${SMARTDNS_LIB:-/usr/local/lib/smartdns/common.sh}
LOG_FILE=${SMARTDNS_CTL_LOG:-/var/log/smartdns-ctl.log}
SETUP_LOG=/var/log/smartdns-setup.log
VERBOSE=${SMARTDNS_VERBOSE:-0}
MAIN_PID=$$
STEP_NO=0; STEP_TOTAL=0
C_R=''; C_G=''; C_Y=''; C_C=''; C_D=''; C_0=''

if [[ ! -r $LIB_FILE ]]; then
  echo "smartdns-ctl: не найден $LIB_FILE — переустановите: sudo bash smartdns-setup.sh" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$LIB_FILE"
init_ui

[[ $EUID -eq 0 ]] || die "Запустите от root (sudo smartdns-ctl …)"
[[ -r $CONF_DIR/smartdns.conf ]] || die "Нет $CONF_DIR/smartdns.conf — Smart DNS не установлен?"
# shellcheck disable=SC1090
source "$CONF_DIR/smartdns.conf"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
{ : >>"$LOG_FILE"; } 2>/dev/null || LOG_FILE=/dev/null

if [[ ${SMARTDNS_TRACE:-0} == 1 && $LOG_FILE != /dev/null ]]; then   # SMARTDNS_TRACE=1 smartdns-ctl reload
  exec {XFD}>>"$LOG_FILE"
  BASH_XTRACEFD=$XFD
  PS4='+${LINENO}:${FUNCNAME[0]:-main}: '
  set -x
fi
trap 'on_err "$?" "$LINENO" "$BASH_COMMAND"' ERR
trap 'err "Прервано"; exit 130' INT
_logf INFO "=== smartdns-ctl $* (pid $$) ==="

DOMAINS_FILE=$CONF_DIR/domains.list
BYPASS_FILE=$CONF_DIR/bypass.list
ALLOW_FILE=$CONF_DIR/allowed_ips.list
BACKUP_DIR=$STATE_DIR/backup
CONF_FILES=(dnsmasq.conf nginx.conf nginx-hosts.map nginx-allow.conf)

# Перед правкой списков делаем снимок: если новая конфигурация не применилась —
# списки откатываются, иначе «плохой» домен ломал бы каждый следующий reload.
LISTS_SNAP=""
snapshot_lists() {
  LISTS_SNAP=$(mktemp -d /tmp/smartdns-lists.XXXXXX)
  cp -af "$DOMAINS_FILE" "$BYPASS_FILE" "$ALLOW_FILE" "$LISTS_SNAP/"
}
on_exit_ctl() {
  local rc=$?
  trap - EXIT
  if [[ -n $LISTS_SNAP && -d $LISTS_SNAP ]]; then
    if (( rc != 0 )); then
      cp -af "$LISTS_SNAP"/. "$CONF_DIR/"
      warn "Конфигурация не применилась — изменения в списках доменов/IP отменены."
    fi
    rm -rf "$LISTS_SNAP"
  fi
  return 0
}
trap on_exit_ctl EXIT

usage() {
  cat <<EOF
smartdns-ctl — управление Smart DNS

  add [-b] домен…     добавить домен в список (с -b — в исключения «напрямую»)
  del домен…          убрать домен из обоих списков
  list                показать списки и разрешённые IP
  allow IP/CIDR…      разрешить клиентам доступ (включает белый список)
  unallow IP/CIDR…    убрать IP из белого списка (пустой список = доступ всем)
  reload              пересобрать конфиги и перезапустить сервисы (с откатом при ошибке)
  cert                выпустить/обновить сертификат для DoT ($DOMAIN)
  status              состояние сервисов и портов
  test [домен]        быстрые проверки: DNS, SNI-прокси, DoT, «не открытый прокси»
  diag                полный отчёт (сохраняется в /var/log/smartdns-diag.txt)
  logs [dns|proxy|setup|stream] [-f]   журналы сервисов / лога установки
  debug on|off        подробные логи: DNS-запросы dnsmasq и подключения nginx
  uninstall           удалить Smart DNS

Файлы: $DOMAINS_FILE, $BYPASS_FILE, $ALLOW_FILE (после правки — reload)
Лог команд: $LOG_FILE   (SMARTDNS_TRACE=1 smartdns-ctl … — с трассировкой)
EOF
}

read_list() { # файл -> значения без комментариев и пробелов
  [[ -f $1 ]] || return 0
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$1" | awk 'NF && !seen[$0]++'
}

list_remove() { # файл значение
  local esc=${2//./\\.}
  sed -i -E "\|^[[:space:]]*${esc}[[:space:]]*(#.*)?\$|d" "$1"
}

set_conf() { # КЛЮЧ значение — изменить/добавить строку в smartdns.conf
  local k=$1 v v_q
  v=$2; v_q=$(printf '%q' "$v")
  if grep -q "^$k=" "$CONF_DIR/smartdns.conf"; then
    sed -i "s|^$k=.*|$k=$v_q|" "$CONF_DIR/smartdns.conf"
  else
    printf '%s=%s\n' "$k" "$v_q" >> "$CONF_DIR/smartdns.conf"
  fi
}

apply_fw() { # белый список клиентов для порта 53 (80/443/853 фильтрует nginx)
  local -a ips; mapfile -t ips < <(read_list "$ALLOW_FILE")
  if (( ${#ips[@]} )); then
    if ! command -v nft >/dev/null 2>&1; then
      log "Ставлю nftables (нужен для белого списка клиентов)…"
      apt_run "установка nftables" install -y -qq nftables || { warn "nftables не установлен."; return 1; }
    fi
    local set; set=$(printf '%s, ' "${ips[@]}"); set=${set%, }
    cat > "$CONF_DIR/nft.rules" <<EOF
add table inet smartdns
delete table inet smartdns
table inet smartdns {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "lo" accept
    ip saddr != { $set } udp dport 53 drop
    ip saddr != { $set } tcp dport 53 drop
  }
}
EOF
    systemctl enable smartdns-fw >/dev/null 2>&1 || true
    if ! run "применение nft-правил (белый список порта 53)" systemctl restart smartdns-fw; then
      svc_tail smartdns-fw 15
      return 1
    fi
    dbg "nft: белый список $set"
  else
    systemctl disable --now smartdns-fw >/dev/null 2>&1 || true
    rm -f "$CONF_DIR/nft.rules"
  fi
  return 0
}

fill_tpl() { # шаблон каталог_конфигов группа
  sed -e "s|__NOGROUP__|$3|g" \
      -e "s|__RESOLVERS__|$UPSTREAM_DNS|g" \
      -e "s|__DOMAIN__|$DOMAIN|g" \
      -e "s|__CONF__|$2|g" \
      -e "s|__ACME__|$STATE_DIR/acme|g" "$1"
}

start_services() { # перезапуск сервисов + проверка, что порты реально слушаются
  local ok=1 dot=0 p restarted=0
  local -a ports=(443 80)
  if grep -q 'listen 853' "$CONF_DIR/nginx.conf" 2>/dev/null; then dot=1; ports+=(853); fi

  apply_fw || warn "Белый список для порта 53 применить не удалось (см. выше) — продолжаю."
  systemctl enable smartdns-dns smartdns-proxy >/dev/null 2>&1 || true

  # Type=simple: «systemctl restart» успешен, даже если процесс упал через секунду —
  # поэтому дополнительно ждём, пока порт реально начнёт слушаться.
  if ! run "запуск smartdns-dns (dnsmasq)" systemctl restart smartdns-dns; then ok=0; fi
  if (( ok )); then
    if wait_listen udp 127.0.0.1 53 15 && wait_listen tcp 127.0.0.1 53 5; then
      dbg "dnsmasq слушает 127.0.0.1:53 (udp+tcp)"
    else
      err "dnsmasq запущен, но не слушает 127.0.0.1:53."
      svc_tail smartdns-dns 30
      ok=0
    fi
  fi

  if (( ok )); then
    if systemctl is-active --quiet smartdns-proxy; then
      run "перечитывание конфига nginx" systemctl reload smartdns-proxy || ok=0
    else
      run "запуск smartdns-proxy (nginx)" systemctl start smartdns-proxy || ok=0
    fi
  fi
  if (( ok )); then
    for p in "${ports[@]}"; do
      if wait_listen tcp 0.0.0.0 "$p" 8; then dbg "nginx слушает :$p"; continue; fi
      if (( ! restarted )); then
        warn "nginx не слушает :$p — пробую полный перезапуск…"
        restarted=1
        if ! run "перезапуск smartdns-proxy" systemctl restart smartdns-proxy; then ok=0; break; fi
        if wait_listen tcp 0.0.0.0 "$p" 10; then continue; fi
      fi
      err "nginx не слушает TCP-порт $p."
      port_listeners tcp "$p" | sed 's/^/      на порту сейчас: /' >&2 || true
      svc_tail smartdns-proxy 30
      ok=0; break
    done
  fi
  if (( ok )); then return 0; fi
  return 1
}

render() {
  local d u nogroup dot=0 stage load f had_old=0
  local -a DOMS BYP IPS
  mapfile -t DOMS < <(read_list "$DOMAINS_FILE")
  mapfile -t BYP  < <(read_list "$BYPASS_FILE")
  mapfile -t IPS  < <(read_list "$ALLOW_FILE")
  if (( ${#DOMS[@]} == 0 )); then die "domains.list пуст — нечего разблокировать."; fi
  dbg "render: доменов=${#DOMS[@]}, исключений=${#BYP[@]}, разрешённых IP=${#IPS[@]}, DEBUG_LOG=${DEBUG_LOG:-0}"

  load=$(nginx_stream_load) || die "У nginx нет модуля stream (поставьте libnginx-mod-stream; проверка: $NGINX_BIN -V)."
  nogroup=$(getent group nogroup >/dev/null && echo nogroup || echo nobody)
  mkdir -p "$STATE_DIR/acme"; chmod 755 "$STATE_DIR" "$STATE_DIR/acme"
  if [[ ${DEBUG_LOG:-0} == 1 ]]; then
    mkdir -p /var/log/smartdns
    printf '%s\n' '/var/log/smartdns/*.log {' '  weekly' '  rotate 4' '  compress' '  missingok' '  notifempty' '  copytruncate' '}' \
      > /etc/logrotate.d/smartdns
  fi

  rm -rf "$CONF_DIR"/.stage.*
  stage=$(mktemp -d "$CONF_DIR/.stage.XXXXXX")
  dbg "stage: $stage"

  # ---- dnsmasq
  {
    cat <<EOF
# Сгенерировано smartdns-ctl. Правьте domains.list / bypass.list и делайте: smartdns-ctl reload
user=nobody
group=$nogroup
port=53
listen-address=127.0.0.1
listen-address=$LOCAL_IP
bind-interfaces
no-resolv
no-hosts
no-poll
domain-needed
bogus-priv
cache-size=10000
local-ttl=300
dns-forward-max=1000
edns-packet-max=1232
pid-file=/run/smartdns-dns.pid
EOF
    if [[ ${DEBUG_LOG:-0} == 1 ]]; then
      echo "# --- отладка: каждый запрос и ответ — в журнал (journalctl -u smartdns-dns -f)"
      echo "log-queries"
      echo "log-facility=-"
    fi
    for u in $UPSTREAM_DNS; do echo "server=$u"; done
    echo "# --- исключения: резолвим у публичных DNS => трафик напрямую"
    for d in "${BYP[@]}"; do for u in $UPSTREAM_DNS; do echo "server=/$d/$u"; done; done
    echo "# --- список: отвечаем IP этого сервера (все поддомены тоже)"
    for d in "${DOMS[@]}"; do echo "address=/$d/$PUBLIC_IP"; done
  } > "$stage/dnsmasq.conf"

  # ---- карты и ACL для nginx
  {
    for d in "${DOMS[@]}"; do echo ".$d 1;"; done
    for d in "${BYP[@]}";  do echo ".$d 0;"; done
  } > "$stage/nginx-hosts.map"

  {
    if (( ${#IPS[@]} )); then
      echo "allow 127.0.0.1;"
      for u in "${IPS[@]}"; do echo "allow $u;"; done
      echo "deny all;"
    fi
  } > "$stage/nginx-allow.conf"

  if [[ ${ENABLE_DOT:-0} == 1 && -s /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]]; then dot=1; fi

  # ---- nginx (шаблон; __CONF__ подставляется отдельно для теста и для боевого файла)
  {
    echo "# Сгенерировано smartdns-ctl — не править руками"
    echo "user nobody __NOGROUP__;"
    echo "worker_processes auto;"
    echo "worker_rlimit_nofile 65535;"
    echo "pid /run/smartdns-proxy.pid;"
    if [[ ${DEBUG_LOG:-0} == 1 ]]; then echo "error_log stderr info;"; else echo "error_log stderr warn;"; fi
    if [[ -n $load ]]; then echo "$load"; fi
    cat <<'EOF'

events { worker_connections 8192; }

stream {
    map_hash_bucket_size 128;
    map_hash_max_size 2048;
    resolver __RESOLVERS__ valid=300s ipv6=off;
    resolver_timeout 5s;

    map $ssl_preread_server_name $sp_sni_ok {
        hostnames;
        default 0;
        include __CONF__/nginx-hosts.map;
    }
    # домен не из списка => «чёрная дыра» (порт 9 закрыт), никакого открытого прокси
    map $sp_sni_ok $sp_upstream {
        1       $ssl_preread_server_name:443;
        default 127.0.0.1:9;
    }
EOF
    if [[ ${DEBUG_LOG:-0} == 1 ]]; then
      cat <<'EOF'

    log_format sp '$time_iso8601 client=$remote_addr sni="$ssl_preread_server_name" allowed=$sp_sni_ok upstream=$upstream_addr status=$status sent=$bytes_sent recv=$bytes_received t=$session_time';
    access_log /var/log/smartdns/stream.log sp;
EOF
    fi
    cat <<'EOF'

    # HTTPS: читаем SNI и пробрасываем TCP на настоящий сервер
    server {
        listen 443;
        ssl_preread on;
        proxy_connect_timeout 10s;
        proxy_pass $sp_upstream;
        include __CONF__/nginx-allow.conf;
    }
EOF
    if (( dot )); then
      cat <<'EOF'

    # DNS-over-TLS (Android «Частный DNS»): TLS на :853 -> локальный dnsmasq
    server {
        listen 853 ssl;
        ssl_certificate     /etc/letsencrypt/live/__DOMAIN__/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/__DOMAIN__/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:SMARTDNS_DOT:2m;
        ssl_session_timeout 10m;
        proxy_pass 127.0.0.1:53;
        include __CONF__/nginx-allow.conf;
    }
EOF
    fi
    cat <<'EOF'
}

http {
    map_hash_bucket_size 128;
    map_hash_max_size 2048;
EOF
    if [[ ${DEBUG_LOG:-0} == 1 ]]; then echo "    access_log /var/log/smartdns/http.log;"; else echo "    access_log off;"; fi
    cat <<'EOF'
    server_tokens off;
    client_max_body_size 0;
    resolver __RESOLVERS__ valid=300s ipv6=off;
    resolver_timeout 5s;

    map $http_upgrade $connection_upgrade { default upgrade; '' close; }
    map $host $sp_host_ok {
        hostnames;
        default 0;
        include __CONF__/nginx-hosts.map;
    }

    # собственный домен: только ACME-проверка Let's Encrypt
    server {
        listen 80;
        server_name __DOMAIN__;
        location /.well-known/acme-challenge/ { root __ACME__; }
        location / { return 404; }
    }

    # HTTP: проксируем только домены из списка
    server {
        listen 80 default_server;
        server_name _;
        include __CONF__/nginx-allow.conf;
        if ($sp_host_ok = 0) { return 444; }
        location / {
            proxy_pass http://$host;
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_buffering off;
            proxy_read_timeout 300s;
        }
    }
}
EOF
  } > "$stage/nginx.conf.tpl"
  fill_tpl "$stage/nginx.conf.tpl" "$stage" "$nogroup"     > "$stage/nginx.test.conf"
  fill_tpl "$stage/nginx.conf.tpl" "$CONF_DIR" "$nogroup"  > "$stage/nginx.conf"

  # ---- проверка конфигов ДО замены боевых (ошибка здесь ничего не ломает)
  if ! run "проверка конфига dnsmasq" "$DNSMASQ_BIN" --test --conf-file="$stage/dnsmasq.conf"; then
    cp -f "$stage/dnsmasq.conf" /tmp/smartdns-dnsmasq.conf.failed 2>/dev/null || true
    rm -rf "$stage"
    die "Ошибка в конфиге dnsmasq (копия для разбора: /tmp/smartdns-dnsmasq.conf.failed). Работающие сервисы не тронуты."
  fi
  if ! RUN_TAIL=25 run "проверка конфига nginx" "$NGINX_BIN" -t -c "$stage/nginx.test.conf"; then
    cp -f "$stage/nginx.test.conf" /tmp/smartdns-nginx.conf.failed 2>/dev/null || true
    rm -rf "$stage"
    die "Ошибка в конфиге nginx (копия для разбора: /tmp/smartdns-nginx.conf.failed). Работающие сервисы не тронуты."
  fi

  # ---- бэкап текущего рабочего состояния и замена
  if [[ -f $CONF_DIR/dnsmasq.conf && -f $CONF_DIR/nginx.conf ]]; then
    had_old=1
    mkdir -p "$BACKUP_DIR"
    for f in "${CONF_FILES[@]}"; do
      if [[ -f $CONF_DIR/$f ]]; then cp -af "$CONF_DIR/$f" "$BACKUP_DIR/$f"; fi
    done
    dbg "бэкап предыдущей конфигурации: $BACKUP_DIR"
  fi
  for f in "${CONF_FILES[@]}"; do mv -f "$stage/$f" "$CONF_DIR/$f"; done
  rm -rf "$stage"

  if ! start_services; then
    err "Новая конфигурация не заработала."
    if (( had_old )); then
      warn "Откатываюсь к предыдущей рабочей конфигурации…"
      for f in "${CONF_FILES[@]}"; do
        if [[ -f $BACKUP_DIR/$f ]]; then cp -af "$BACKUP_DIR/$f" "$CONF_DIR/$f"; fi
      done
      if start_services; then
        warn "Откат выполнен: сервисы работают на ПРЕДЫДУЩЕЙ конфигурации."
      else
        err "Откат тоже не удался — смотрите: smartdns-ctl diag"
      fi
    fi
    die "Не удалось применить конфигурацию. Диагностика: smartdns-ctl diag | журналы: smartdns-ctl logs"
  fi
  log "Применено: в списке ${#DOMS[@]}, исключений ${#BYP[@]}, разрешённых IP ${#IPS[@]}$(if (( dot )); then echo ', DoT включён'; fi)$(if [[ ${DEBUG_LOG:-0} == 1 ]]; then echo ', DEBUG-лог ВКЛ'; fi)"
}

cmd_add() {
  local file=$DOMAINS_FILE other=$BYPASS_FILE raw d
  if [[ ${1:-} == -b ]]; then file=$BYPASS_FILE; other=$DOMAINS_FILE; shift; fi
  (($#)) || die "Укажите домен(ы): smartdns-ctl add [-b] example.com"
  snapshot_lists
  for raw in "$@"; do
    d=$(norm_domain "$raw") || { warn "Пропускаю некорректный домен: $raw"; continue; }
    list_remove "$other" "$d"
    if ! grep -qxF "$d" <(read_list "$file"); then echo "$d" >> "$file"; fi
    log "добавлен: $d"
  done
  render
}

cmd_del() {
  local raw d
  (($#)) || die "Укажите домен(ы): smartdns-ctl del example.com"
  snapshot_lists
  for raw in "$@"; do
    d=$(norm_domain "$raw") || { warn "Пропускаю некорректный домен: $raw"; continue; }
    list_remove "$DOMAINS_FILE" "$d"; list_remove "$BYPASS_FILE" "$d"
    log "удалён: $d"
  done
  render
}

cmd_allow() {
  local ip
  (($#)) || die "Укажите IP/CIDR: smartdns-ctl allow 203.0.113.7"
  snapshot_lists
  for ip in "$@"; do
    cidr_ok "$ip" || { warn "Некорректный IP: $ip"; continue; }
    if ! grep -qxF "$ip" <(read_list "$ALLOW_FILE"); then echo "$ip" >> "$ALLOW_FILE"; fi
    log "разрешён: $ip"
  done
  render
}

cmd_unallow() {
  local ip
  (($#)) || die "Укажите IP/CIDR."
  snapshot_lists
  for ip in "$@"; do list_remove "$ALLOW_FILE" "$ip"; log "убран: $ip"; done
  render
}

cmd_list() {
  echo "== Через сервер (domains.list) ==";   read_list "$DOMAINS_FILE" | sed 's/^/  /'
  echo "== Напрямую (bypass.list) ==";        read_list "$BYPASS_FILE"  | sed 's/^/  /'
  echo "== Разрешённые клиенты (пусто = все) =="; read_list "$ALLOW_FILE" | sed 's/^/  /'
  return 0
}

cert_hints() { # разбор типичных причин отказа Let's Encrypt по выводу certbot
  local o=${RUN_LAST,,}
  if [[ $o == *"timeout during connect"* || $o == *"connection timed out"* ]]; then
    note "Let's Encrypt не достучался до $DOMAIN:80 снаружи → откройте TCP 80 в облачном файрволе / ufw / security group."
  fi
  if [[ $o == *"nxdomain"* || $o == *"no valid a records"* || $o == *"dns problem"* ]]; then
    note "У $DOMAIN нет A-записи (или она ещё не разошлась по DNS). Создайте A → $PUBLIC_IP."
  fi
  if [[ $o == *"connection refused"* ]]; then
    note "На $DOMAIN:80 никто не слушает снаружи (файрвол провайдера?) — проверьте: smartdns-ctl status"
  fi
  if [[ $o == *"unauthorized"* || $o == *"invalid response"* || $o == *"404"* ]]; then
    note "По адресу $DOMAIN отвечает не наш nginx: Cloudflare-прокси (оранжевое облако) или другой сервер. Нужен режим «DNS only»."
  fi
  if [[ $o == *"too many"* || $o == *"rate limit"* ]]; then
    note "Сработал лимит Let's Encrypt — подождите (обычно час) и повторите: smartdns-ctl cert"
  fi
  note "Полный лог certbot: /var/log/letsencrypt/letsencrypt.log"
}

cmd_cert() {
  [[ ${ENABLE_DOT:-0} == 1 ]] || die "DoT отключён при установке (--no-dot)."
  systemctl is-active --quiet smartdns-proxy || die "smartdns-proxy не запущен (нужен :80 для проверки ACME). Смотрите: smartdns-ctl logs proxy"

  local tok="selftest-$RANDOM$RANDOM" dir="$STATE_DIR/acme/.well-known/acme-challenge" got
  local -a em=(--register-unsafely-without-email)
  log "Проверяю локально, что nginx отдаёт ACME-каталог для $DOMAIN…"
  mkdir -p "$dir"; chmod 755 "$STATE_DIR/acme/.well-known" "$dir"
  printf 'ok' > "$dir/$tok"; chmod 644 "$dir/$tok"
  got=$(curl -fsS --max-time 8 -H "Host: $DOMAIN" "http://127.0.0.1/.well-known/acme-challenge/$tok" 2>>"$LOG_FILE" || true)
  rm -f "$dir/$tok"
  if [[ $got != ok ]]; then
    svc_tail smartdns-proxy 15
    die "nginx не отдаёт файл из $dir (получено: «${got:-пусто}»). Проверьте права и конфиг: smartdns-ctl diag"
  fi

  if [[ -n ${EMAIL:-} ]]; then em=(-m "$EMAIL"); fi
  log "Запрашиваю сертификат Let's Encrypt для $DOMAIN (проверка по HTTP :80)…"
  if ! RUN_TAIL=25 run "выпуск сертификата Let's Encrypt для $DOMAIN" \
        certbot certonly --webroot -w "$STATE_DIR/acme" -d "$DOMAIN" \
        --non-interactive --agree-tos "${em[@]}" \
        --deploy-hook "systemctl reload smartdns-proxy"; then
    cert_hints
    die "Сертификат не выпущен. Исправьте причину и выполните: smartdns-ctl cert"
  fi
  [[ -s /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]] || die "certbot отчитался об успехе, но файла сертификата нет: /etc/letsencrypt/live/$DOMAIN/"
  log "Сертификат получен. Включаю DoT…"
  render
}

# ---- тесты --------------------------------------------------------------------
PASS=0; FAIL=0
t_ok()   { printf '  %s✔%s %s\n' "$C_G" "$C_0" "$*"; PASS=$((PASS + 1)); _logf INFO "TEST OK: $*"; }
t_fail() { printf '  %s✘%s %s\n' "$C_R" "$C_0" "$*"; FAIL=$((FAIL + 1)); _logf ERROR "TEST FAIL: $*"; }
t_hint() { printf '      %s\n' "$*"; }

cmd_test() {
  local d=${1:-claude.ai} a b c code pem=/etc/letsencrypt/live/$DOMAIN/fullchain.pem
  PASS=0; FAIL=0
  echo "Проверки для $d (ожидаемый IP сервера: $PUBLIC_IP):"
  if ! command -v dig >/dev/null 2>&1; then
    t_fail "нет утилиты dig"; t_hint "поставьте: apt-get install dnsutils"
  else
    a=$(dns_a "$d" 127.0.0.1 | sed -n 1p)
    if [[ $a == "$PUBLIC_IP" ]]; then t_ok "DNS (127.0.0.1): $d → $a (через сервер)"
    else t_fail "DNS (127.0.0.1): $d → ${a:-нет ответа}, ожидался $PUBLIC_IP"; t_hint "dnsmasq не запущен или домена нет в списке: smartdns-ctl list; smartdns-ctl logs dns"; fi

    c=$(dns_a "$d" "$LOCAL_IP" | sed -n 1p)
    if [[ $c == "$PUBLIC_IP" ]]; then t_ok "DNS ($LOCAL_IP): тот же ответ на внешнем адресе интерфейса"
    else t_fail "DNS ($LOCAL_IP): ${c:-нет ответа}"; t_hint "dnsmasq не слушает $LOCAL_IP:53 — возможно, сменился IP сервера? Выполните: smartdns-ctl reload"; fi

    b=$(dns_a example.com 127.0.0.1 | sed -n 1p)
    if [[ -n $b && $b != "$PUBLIC_IP" ]]; then t_ok "DNS: example.com → $b (напрямую, форвардинг работает)"
    else t_fail "DNS: example.com → ${b:-нет ответа} — форвардинг не работает"; t_hint "проверьте исходящий UDP/TCP 53 к: $UPSTREAM_DNS (файрвол провайдера?)"; fi
  fi

  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 12 --resolve "$d:443:127.0.0.1" "https://$d/" 2>>"$LOG_FILE" || true)
  if [[ -n $code && $code != 000 ]]; then t_ok "SNI-прокси: https://$d через сервер → HTTP $code"
  else t_fail "SNI-прокси: https://$d через сервер → нет ответа"; t_hint "проверьте исходящий 443 с сервера и: smartdns-ctl logs proxy"; fi

  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 --resolve "example.com:443:127.0.0.1" "https://example.com/" 2>>"$LOG_FILE" || true)
  if [[ -z $code || $code == 000 ]]; then t_ok "Защита: домен не из списка (example.com) через прокси НЕ проходит"
  else t_fail "Защита: example.com прошёл через прокси (HTTP $code) — это открытый прокси!"; t_hint "проверьте $CONF_DIR/nginx-hosts.map"; fi

  if [[ ${ENABLE_DOT:-0} == 1 ]]; then
    if [[ ! -s $pem ]]; then t_fail "DoT: сертификата нет — выполните smartdns-ctl cert"
    elif ! command -v openssl >/dev/null 2>&1; then t_hint "openssl не найден — проверку DoT пропускаю"
    else
      if echo | timeout 8 openssl s_client -connect 127.0.0.1:853 -servername "$DOMAIN" >/dev/null 2>&1; then
        t_ok "DoT: TLS-рукопожатие на :853 успешно ($DOMAIN)"
      else
        t_fail "DoT: TLS на 127.0.0.1:853 не отвечает"; t_hint "smartdns-ctl status; smartdns-ctl logs proxy"
      fi
    fi
  fi
  echo "Итого: ✔ $PASS, ✘ $FAIL"
  if (( FAIL == 0 )); then return 0; fi
  return 1
}

cmd_status() {
  local s st en pem=/etc/letsencrypt/live/$DOMAIN/fullchain.pem p exp=""
  for s in smartdns-dns smartdns-proxy smartdns-fw; do
    st=$(systemctl is-active "$s" 2>/dev/null || true)
    en=$(systemctl is-enabled "$s" 2>/dev/null || true)
    printf '  %-16s %-10s (автозапуск: %s)\n' "$s" "$st" "$en"
  done
  if [[ -s $pem ]] && command -v openssl >/dev/null 2>&1; then
    exp=$(openssl x509 -enddate -noout -in "$pem" 2>/dev/null | cut -d= -f2 || true)
  fi
  echo "  IP: $PUBLIC_IP (интерфейс $LOCAL_IP)   домен: $DOMAIN   DEBUG-лог: ${DEBUG_LOG:-0}"
  echo "  сертификат DoT: $([[ -s $pem ]] && echo "есть, действует до ${exp:-?}" || echo нет)"
  echo "  Слушает:"
  for p in "udp 127.0.0.1 53" "tcp 127.0.0.1 53" "tcp 0.0.0.0 80" "tcp 0.0.0.0 443" "tcp 0.0.0.0 853"; do
    # shellcheck disable=SC2086
    if listening $p; then printf '    %s✔%s %s\n' "$C_G" "$C_0" "$p"; else printf '    %s✘%s %s\n' "$C_R" "$C_0" "$p"; fi
  done
  return 0
}

_diag() {
  set +e; trap - ERR
  C_R=''; C_G=''; C_Y=''; C_C=''; C_D=''; C_0=''
  local s a1 a2 a3
  echo "=== smartdns diag: $(date '+%F %T') ==="
  echo "--- система"
  uname -a; ( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-?}" )
  echo "bash $BASH_VERSION | виртуализация: $(systemd-detect-virt 2>/dev/null)"
  echo "--- smartdns.conf"
  cat "$CONF_DIR/smartdns.conf"
  echo "--- версии"
  "$NGINX_BIN" -v 2>&1; "$DNSMASQ_BIN" --version 2>&1 | sed -n 1p
  echo "--- сервисы"
  for s in smartdns-dns smartdns-proxy smartdns-fw; do
    printf '%-16s active=%s enabled=%s\n' "$s" "$(systemctl is-active "$s" 2>&1)" "$(systemctl is-enabled "$s" 2>&1)"
  done
  echo "--- слушающие порты 53/80/443/853"
  ss -lntup 2>&1 | awk 'NR == 1 || $5 ~ /:(53|80|443|853)$/'
  echo "--- проверка конфигов"
  "$NGINX_BIN" -t -c "$CONF_DIR/nginx.conf" 2>&1
  "$DNSMASQ_BIN" --test --conf-file="$CONF_DIR/dnsmasq.conf" 2>&1
  echo "--- A-запись $DOMAIN (ожидается $PUBLIC_IP)"
  a1=$(dns_a "$DOMAIN" | tr '\n' ' '); a2=$(dns_a "$DOMAIN" 1.1.1.1 | tr '\n' ' '); a3=$(dns_a "$DOMAIN" 8.8.8.8 | tr '\n' ' ')
  echo "системный резолвер: ${a1:-нет} | 1.1.1.1: ${a2:-нет} | 8.8.8.8: ${a3:-нет}"
  echo "--- тесты"
  cmd_test
  echo "--- сертификат"
  ls -l "/etc/letsencrypt/live/$DOMAIN/" 2>&1
  [[ -s /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]] && openssl x509 -noout -subject -enddate -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" 2>&1
  echo "--- файрвол"
  if command -v ufw >/dev/null 2>&1; then ufw status 2>&1 | sed -n 1,20p; fi
  nft list table inet smartdns 2>&1 | sed -n 1,20p
  echo "--- журнал dnsmasq (40 строк)"; journalctl -u smartdns-dns -n 40 --no-pager -o short-iso 2>&1
  echo "--- журнал nginx (40 строк)";   journalctl -u smartdns-proxy -n 40 --no-pager -o short-iso 2>&1
  echo "--- хвост лога smartdns-ctl";   tail -n 30 "$LOG_FILE" 2>&1
  echo "--- хвост лога установки (без трассировки)"; grep -v '^+' "$SETUP_LOG" 2>/dev/null | tail -n 40
  echo "=== конец отчёта ==="
}

cmd_diag() {
  local rep=/var/log/smartdns-diag.txt
  { _diag; } 2>&1 | tee "$rep" || true
  log "Отчёт сохранён: $rep — приложите его, если нужна помощь."
}

cmd_logs() {
  local target=${1:-all} follow=0 a
  for a in "$@"; do if [[ $a == -f ]]; then follow=1; fi; done
  if [[ $target == -f ]]; then target=all; fi
  local -a units
  case $target in
    dns)    units=(-u smartdns-dns) ;;
    proxy)  units=(-u smartdns-proxy) ;;
    setup)  tail -n 200 "$SETUP_LOG"; return 0 ;;
    stream) [[ -f /var/log/smartdns/stream.log ]] || die "Нет /var/log/smartdns/stream.log — включите: smartdns-ctl debug on"
            if (( follow )); then tail -n 50 -f /var/log/smartdns/stream.log; else tail -n 200 /var/log/smartdns/stream.log; fi
            return 0 ;;
    *)      units=(-u smartdns-dns -u smartdns-proxy -u smartdns-fw) ;;
  esac
  if (( follow )); then journalctl "${units[@]}" -n 50 -f --no-pager -o short-iso
  else journalctl "${units[@]}" -n 100 --no-pager -o short-iso; fi
}

cmd_debug() {
  case ${1:-status} in
    on)  set_conf DEBUG_LOG 1; DEBUG_LOG=1; render
         log "Подробные логи ВКЛЮЧЕНЫ: DNS-запросы — smartdns-ctl logs dns -f ; подключения — smartdns-ctl logs stream -f"
         warn "В логах видны домены, которые открывают клиенты. После отладки: smartdns-ctl debug off" ;;
    off) set_conf DEBUG_LOG 0; DEBUG_LOG=0; render; log "Подробные логи выключены." ;;
    *)   echo "  DEBUG-лог: ${DEBUG_LOG:-0}   (smartdns-ctl debug on|off)" ;;
  esac
}

cmd_uninstall() {
  local a=y
  if [[ -t 0 ]]; then read -r -p "Удалить Smart DNS (конфиги и сервисы)? [y/N] " a || a=n; fi
  [[ $a =~ ^[yYдД] ]] || die "Отменено."
  systemctl disable --now smartdns-proxy smartdns-dns smartdns-fw >/dev/null 2>&1 || true
  nft delete table inet smartdns >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/smartdns-dns.service /etc/systemd/system/smartdns-proxy.service /etc/systemd/system/smartdns-fw.service
  systemctl daemon-reload
  rm -rf "$CONF_DIR" "$STATE_DIR" /usr/local/lib/smartdns /var/log/smartdns /etc/logrotate.d/smartdns /usr/local/bin/smartdns-ctl
  log "Удалено. Пакеты (nginx, dnsmasq-base, certbot), сертификат Let's Encrypt и логи в /var/log/smartdns-*.log не тронуты."
}

rc=0
case "${1:-help}" in
  add)               shift; cmd_add "$@" ;;
  del|rm)            shift; cmd_del "$@" ;;
  list|ls)           cmd_list ;;
  allow)             shift; cmd_allow "$@" ;;
  unallow|disallow)  shift; cmd_unallow "$@" ;;
  reload|apply)      render ;;
  cert)              cmd_cert ;;
  status)            cmd_status ;;
  test)              shift; cmd_test "$@" || rc=$? ;;
  diag)              cmd_diag ;;
  logs)              shift; cmd_logs "$@" ;;
  debug)             shift; cmd_debug "$@" ;;
  uninstall)         cmd_uninstall ;;
  help|-h|--help)    usage ;;
  *)                 usage; rc=1 ;;
esac
exit "$rc"
CTL_EOF
chmod 755 "$CTL"
bash -n "$CTL" || die "Сгенерированный $CTL содержит синтаксическую ошибку (баг скрипта)."

# ---------------------------------------------------------- systemd ----------
log "Создаю systemd-юниты…"
cat > /etc/systemd/system/smartdns-dns.service <<EOF
[Unit]
Description=SmartDNS: dnsmasq (DNS-unlock)
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=$DNSMASQ_BIN --test --conf-file=$CONF_DIR/dnsmasq.conf
ExecStart=$DNSMASQ_BIN --keep-in-foreground --conf-file=$CONF_DIR/dnsmasq.conf
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/smartdns-proxy.service <<EOF
[Unit]
Description=SmartDNS: SNI/HTTP-прокси (nginx)
After=network-online.target smartdns-dns.service
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=$NGINX_BIN -t -c $CONF_DIR/nginx.conf
ExecStart=$NGINX_BIN -c $CONF_DIR/nginx.conf -g "daemon off;"
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/smartdns-fw.service <<EOF
[Unit]
Description=SmartDNS: белый список клиентов для порта 53 (nftables)
After=network-pre.target nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/env nft -f $CONF_DIR/nft.rules
ExecStop=-/usr/bin/env nft delete table inet smartdns

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

# ----------------------------------------------------------- firewall --------
ufw_state=""
if command -v ufw >/dev/null 2>&1; then ufw_state=$(ufw status 2>/dev/null || true); fi
if [[ $ufw_state == "Status: active"* ]]; then
  log "ufw активен — открываю 53, 80, 443$(if (( ! NO_DOT )); then echo ', 853'; fi)…"
  ufw allow 53 >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
  if (( ! NO_DOT )); then ufw allow 853/tcp >/dev/null; fi
fi

log "Собираю конфиги и запускаю сервисы…"
"$CTL" reload || die "Не удалось запустить сервисы (причина — в выводе выше; журналы: smartdns-ctl logs; лог: /var/log/smartdns-ctl.log)."

# ═════════════════ ШАГ 6. Сертификат DoT ═════════════════════════════════════
step "Сертификат Let's Encrypt для DoT"
if (( NO_DOT )); then
  log "DoT отключён — шаг пропущен."
else
  a_sys=$(dns_a "$DOMAIN" | tr '\n' ' ')
  a_cf=$(dns_a "$DOMAIN" 1.1.1.1 | tr '\n' ' ')
  a_g=$(dns_a "$DOMAIN" 8.8.8.8 | tr '\n' ' ')
  log "A-запись $DOMAIN: системный DNS=[${a_sys:-нет}] 1.1.1.1=[${a_cf:-нет}] 8.8.8.8=[${a_g:-нет}], IP сервера=$PUBLIC_IP"
  if [[ " $a_cf $a_g $a_sys " == *" $PUBLIC_IP "* ]]; then
    log "Запрашиваю сертификат для $DOMAIN…"
    "$CTL" cert || warn "Сертификат не выпущен (причина выше). После исправления выполните: smartdns-ctl cert"
  else
    warn "A-запись $DOMAIN не указывает на $PUBLIC_IP — сертификат не запрашиваю (чтобы не упереться в лимиты Let's Encrypt)."
    note "Создайте A-запись  $DOMAIN → $PUBLIC_IP  (для Cloudflare — режим «DNS only», серое облако)."
    note "Когда запись появится (проверка: dig +short $DOMAIN @1.1.1.1), выполните: smartdns-ctl cert"
  fi
fi

# ═════════════════ ШАГ 7. Самопроверка ═══════════════════════════════════════
step "Самопроверка"
sleep 1
"$CTL" test || warn "Часть проверок не прошла — подсказки выше. Полный отчёт: smartdns-ctl diag"

CUR_STEP="готово"
set +x
have_cert=нет
if [[ -s /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]]; then have_cert=есть; fi

cat <<EOF

════════════════════════════════════════════════════════════════
 Smart DNS установлен
════════════════════════════════════════════════════════════════
 DNS-сервер : $PUBLIC_IP  (порт 53, udp+tcp)
 DoT        : $DOMAIN:853  (сертификат: $have_cert)

 Как пользоваться
   • Консоль / ПК / роутер / телефон: в настройках сети вручную задайте
     DNS = $PUBLIC_IP  (вторичный DNS не указывайте или ставьте тот же).
   • Android: Настройки → Сеть → Частный DNS → $DOMAIN
   • Домены из списка идут через сервер, всё остальное — напрямую.
   • Отключите «Безопасный DNS/DoH» в браузере, иначе он обойдёт ваш DNS.

 Управление
   smartdns-ctl add claude.ai | add -b dl.example.com | del | list
   smartdns-ctl allow <ваш IP> | unallow | reload | status | cert | uninstall

 Если что-то не работает
   smartdns-ctl test         быстрые проверки с подсказками
   smartdns-ctl diag         полный отчёт (/var/log/smartdns-diag.txt)
   smartdns-ctl logs -f      журналы сервисов;  smartdns-ctl debug on — подробные логи
   Лог установки: $LOG_FILE

 В файрволе провайдера (облачная панель) откройте: 53/udp, 53/tcp, 80/tcp, 443/tcp$(if (( ! NO_DOT )); then echo ', 853/tcp'; fi).
EOF
if [[ -z $ALLOW ]] && ! grep -qvE '^\s*(#|$)' "$CONF_DIR/allowed_ips.list"; then
  warn "Доступ открыт ВСЕМ: это открытый DNS-резолвер (его используют для DDoS-амплификации)."
  warn "Рекомендую ограничить клиентов:  smartdns-ctl allow <ваш IP>"
fi
