#!/usr/bin/env bash
#
# smartdns.sh — превращает Debian-сервер в Smart DNS (DNS + SNI-прокси).
#
# Как это работает:
#   * dnsmasq отвечает на DNS-запросы: для доменов из списка (Claude, ChatGPT, Gemini,
#     Xbox, PlayStation и т.д.) возвращает IP ЭТОГО сервера, остальное резолвит как обычно.
#   * nginx (stream + ssl_preread) принимает HTTPS/HTTP на 443/80 и прозрачно пробрасывает
#     соединение на настоящий сайт по SNI/Host. Сервис видит IP сервера, а не ваш.
#   * nftables пускает на порты 53/80/443 только IP из белого списка — иначе сервер
#     станет открытым DNS-резолвером и прокси, которым воспользуются для DDoS.
#
# Запуск (от root, sudo не нужен):
#   bash smartdns.sh                       — установка (спросит ваш внешний IP)
#   bash smartdns.sh 203.0.113.5 [IP...]   — установка без вопросов
# После установки доступна команда `smartdns`:
#   smartdns allow <IP|CIDR>   добавить клиента      smartdns remove <IP|CIDR>   убрать
#   smartdns list              список клиентов       smartdns apply              применить правки domains.txt
#   smartdns status            состояние служб       smartdns uninstall          удалить
#
set -Eeuo pipefail
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"

CONF_DIR=/etc/smartdns
DOMAINS_FILE=$CONF_DIR/domains.txt
ALLOWED_FILE=$CONF_DIR/allowed.txt
ENV_FILE=$CONF_DIR/server.env
SELF_BIN=/usr/local/bin/smartdns
UNIT_DIR=/etc/systemd/system
NGX_MODULE=/usr/lib/nginx/modules/ngx_stream_module.so

if [[ -t 1 ]]; then
  C_G=$'\e[32m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_B=$'\e[1m'; C_0=$'\e[0m'
else
  C_G=''; C_Y=''; C_R=''; C_B=''; C_0=''
fi
info() { printf '%s\n' "${C_B}==>${C_0} $*"; }
ok()   { printf '%s\n' "${C_G}  ✔${C_0} $*"; }
warn() { printf '%s\n' "${C_Y}  !${C_0} $*" >&2; }
die()  { printf '%s\n' "${C_R}Ошибка:${C_0} $*" >&2; exit 1; }
trap 'die "сбой на строке $LINENO (команда: $BASH_COMMAND)"' ERR

CLIENTS=()
PUBLIC_IP=""; LOCAL_IP=""; IFACE=""

# ───────────────────────── вспомогательные функции ─────────────────────────

need_root() {
  [[ $EUID -eq 0 ]] || die "Нужен root (sudo не используется). Войдите как root или выполните: su -"
}

is_ipv4() {
  local ip=$1 o
  [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  local IFS=.
  for o in $ip; do (( 10#$o <= 255 )) || return 1; done
  return 0
}

is_client() { # IPv4 или IPv4/маска
  local v=$1 ip=${1%%/*} mask=""
  [[ $v == */* ]] && mask=${v#*/}
  is_ipv4 "$ip" || return 1
  [[ -z $mask || ( $mask =~ ^[0-9]+$ && 10#$mask -le 32 ) ]]
}

read_allowed() { grep -E '^[0-9]' "$ALLOWED_FILE" 2>/dev/null | sort -u || true; }

read_domains() { # нормализованный список: "domain" или "-domain" (исключение)
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$DOMAINS_FILE" \
    | tr 'A-Z' 'a-z' \
    | grep -E '^-?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' || true
}

check_system() {
  [[ -r /etc/os-release ]] && . /etc/os-release || true
  [[ ${ID:-} == debian || ${ID_LIKE:-} == *debian* ]] || die "Скрипт рассчитан на Debian и производные."
  [[ -d /run/systemd/system ]] || die "Нужен systemd."
}

check_ports() {
  local port svc busy
  for port in 53 80 443; do
    svc=smartdns-proxy
    [[ $port == 53 ]] && svc=smartdns-dns
    systemctl is-active -q "$svc" 2>/dev/null && continue   # это наши службы (повторный запуск)
    busy=$(ss -H -lntup "sport = :$port" 2>/dev/null \
           | awk '$5 !~ /^127\.0\.0\.5[34][%:]/ {print "     " $1, $5, $7}' || true)
    [[ -z $busy ]] || die $'Порт '"$port"$' уже занят:\n'"$busy"$'\nОстановите эту службу и запустите скрипт снова.'
  done
}

ask_clients() {
  local def="" ans
  if [[ -n ${SSH_CLIENT:-} ]]; then
    def=${SSH_CLIENT%% *}
    is_ipv4 "$def" || def=""
  fi
  cat >&2 <<'EOF'

Smart DNS должен отвечать только вам — иначе сервер станет открытым DNS-резолвером и прокси.
Укажите внешний IPv4 (или подсеть CIDR) той сети, откуда будете подключаться: домашний интернет,
мобильный оператор и т.п. Узнать: откройте https://ifconfig.me с нужного устройства.
Несколько адресов — через пробел. Позже добавить ещё: smartdns allow <IP>
EOF
  { : </dev/tty; } 2>/dev/null || die "Нет терминала для ввода. Передайте IP аргументами: bash smartdns.sh 203.0.113.5"
  read -r -p "IP-адреса${def:+ [по умолчанию $def — ваш SSH-адрес]}: " ans </dev/tty
  ans=${ans:-$def}
  [[ -n $ans ]] || die "IP не указан."
  read -r -a CLIENTS <<< "$ans"
}

detect_net() {
  local u
  LOCAL_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)
  IFACE=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)
  [[ -n $LOCAL_IP && -n $IFACE ]] || die "Не удалось определить сетевой интерфейс и IPv4 сервера."

  PUBLIC_IP=""
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    PUBLIC_IP=$(curl -4 -fsS --max-time 6 "$u" 2>/dev/null | tr -d '[:space:]' || true)
    is_ipv4 "$PUBLIC_IP" && break
    PUBLIC_IP=""
  done
  if [[ -z $PUBLIC_IP && -r $ENV_FILE ]]; then
    PUBLIC_IP=$(. "$ENV_FILE" 2>/dev/null; echo "${PUBLIC_IP:-}")
  fi
  if [[ -z $PUBLIC_IP ]]; then
    PUBLIC_IP=$LOCAL_IP
    warn "Не удалось узнать внешний IP, использую $LOCAL_IP"
  fi
  mkdir -p "$CONF_DIR"
  printf 'PUBLIC_IP=%s\nLOCAL_IP=%s\nIFACE=%s\n' "$PUBLIC_IP" "$LOCAL_IP" "$IFACE" > "$ENV_FILE"
}

# ───────────────────────── установка пакетов и файлы ─────────────────────────

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  local had_nginx=0
  dpkg -s nginx >/dev/null 2>&1 && had_nginx=1
  info "Установка пакетов (nginx, dnsmasq, nftables)…"
  apt-get update -qq || warn "apt-get update завершился с ошибкой — продолжаю"
  apt-get install -y -qq --no-install-recommends \
    ca-certificates curl iproute2 nftables dnsmasq-base nginx libnginx-mod-stream >/dev/null
  apt-get install -y -qq --no-install-recommends bind9-dnsutils >/dev/null 2>&1 \
    || apt-get install -y -qq --no-install-recommends dnsutils >/dev/null 2>&1 \
    || warn "dig не установлен — проверка DNS будет пропущена"
  # Штатный nginx нам не нужен: работаем своим экземпляром со своим конфигом.
  if (( had_nginx == 0 )); then systemctl disable --now nginx >/dev/null 2>&1 || true; fi
  ok "Пакеты установлены"
}

write_default_domains() {
  [[ -f $DOMAINS_FILE ]] && return 0
  cat > "$DOMAINS_FILE" <<'EOF'
# Smart DNS: домены, трафик к которым идёт через этот сервер.
# Один домен на строку; example.com покрывает и все его поддомены.
# Строка с минусом (-host.example.com) — исключение: хост резолвится как обычно, напрямую
# (нужно для тяжёлых загрузок игр, чтобы не гнать их через сервер).
# После правки выполните: smartdns apply

# --- Claude / Anthropic ---
claude.ai
claude.com
anthropic.com
claudeusercontent.com

# --- ChatGPT / OpenAI / Sora ---
chatgpt.com
openai.com
oaistatic.com
oaiusercontent.com
sora.com
challenges.cloudflare.com

# --- Google Gemini / AI Studio / NotebookLM ---
gemini.google.com
bard.google.com
aistudio.google.com
makersuite.google.com
ai.google.dev
generativelanguage.googleapis.com
alkalimakersuite-pa.clients6.google.com
notebooklm.google.com
notebooklm.google
labs.google
deepmind.google

# --- Другие ИИ-сервисы ---
perplexity.ai
grok.com
x.ai
meta.ai
copilot.microsoft.com
midjourney.com

# --- Xbox ---
xbox.com
xboxlive.com
xboxservices.com
gamepass.com
mp.microsoft.com
login.live.com
# загрузки игр идут напрямую, мимо сервера
-assets1.xboxlive.com
-assets2.xboxlive.com
-dlassets.xboxlive.com
-dlassets2.xboxlive.com
-d1.xboxlive.com
-d2.xboxlive.com
-xvcf1.xboxlive.com
-xvcf2.xboxlive.com
-delivery.mp.microsoft.com

# --- PlayStation ---
playstation.com
playstation.net
sonyentertainmentnetwork.com
account.sony.com
# загрузки и обновления идут напрямую
-dl.playstation.net
-update.playstation.net
EOF
}

write_units() {
  local nft_bin ngx_bin dns_bin
  nft_bin=$(command -v nft) || die "nft не найден"
  ngx_bin=$(command -v nginx) || die "nginx не найден"
  dns_bin=$(command -v dnsmasq) || die "dnsmasq не найден"

  cat > "$UNIT_DIR/smartdns-firewall.service" <<EOF
[Unit]
Description=Smart DNS: доступ только для разрешённых IP (nftables)
After=local-fs.target
Before=smartdns-dns.service smartdns-proxy.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$nft_bin -f $CONF_DIR/firewall.nft
ExecReload=$nft_bin -f $CONF_DIR/firewall.nft
ExecStop=-$nft_bin delete table inet smartdns

[Install]
WantedBy=multi-user.target
EOF

  cat > "$UNIT_DIR/smartdns-dns.service" <<EOF
[Unit]
Description=Smart DNS: DNS-сервер (dnsmasq)
After=network-online.target smartdns-firewall.service
Wants=network-online.target
Requires=smartdns-firewall.service

[Service]
ExecStartPre=$dns_bin --test -C $CONF_DIR/dnsmasq.conf
ExecStart=$dns_bin -k -C $CONF_DIR/dnsmasq.conf
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  cat > "$UNIT_DIR/smartdns-proxy.service" <<EOF
[Unit]
Description=Smart DNS: SNI/HTTP-прокси (nginx)
After=network-online.target smartdns-firewall.service
Wants=network-online.target
Requires=smartdns-firewall.service

[Service]
ExecStartPre=$ngx_bin -t -c $CONF_DIR/nginx.conf
ExecStart=$ngx_bin -c $CONF_DIR/nginx.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
}

install_self() {
  local src=${BASH_SOURCE[0]:-$0}
  if [[ -f $src && $(readlink -f "$src") != "$SELF_BIN" ]]; then
    install -m 0755 "$src" "$SELF_BIN"
  fi
}

# ───────────────────────── генерация конфигов ─────────────────────────

gen_domain_files() { # карты для nginx
  local d re
  : > "$CONF_DIR/nginx-sni.map"
  : > "$CONF_DIR/nginx-http.map"
  while read -r d; do
    [[ $d == -* ]] && continue
    re=${d//./\\.}
    printf '"~*(^|\\.)%s$" $ssl_preread_server_name:443;\n' "$re" >> "$CONF_DIR/nginx-sni.map"
    printf '"~*(^|\\.)%s$" 1;\n' "$re" >> "$CONF_DIR/nginx-http.map"
  done < <(read_domains)
}

gen_dnsmasq_conf() {
  local d
  {
    cat <<EOF
# Сгенерировано smartdns — не редактируйте (правьте domains.txt и выполните: smartdns apply)
port=53
interface=$IFACE
bind-dynamic
no-resolv
no-hosts
domain-needed
bogus-priv
cache-size=4096
pid-file=/run/smartdns-dns.pid
server=1.1.1.1
server=8.8.8.8
EOF
    while read -r d; do
      if [[ $d == -* ]]; then
        echo "server=/${d#-}/#"
      else
        echo "address=/$d/$PUBLIC_IP"
      fi
    done < <(read_domains)
  } > "$CONF_DIR/dnsmasq.conf"
}

gen_nginx_conf() {
  local c
  {
    echo 'allow 127.0.0.1;'
    for c in $(read_allowed); do printf 'allow %s;\n' "$c"; done
    echo 'deny all;'
  } > "$CONF_DIR/nginx-allow.conf"

  {
    [[ -f $NGX_MODULE ]] && echo "load_module $NGX_MODULE;"
    cat <<'EOF'
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/smartdns-nginx.pid;
daemon off;
error_log /var/log/smartdns-nginx.log warn;

events {
    worker_connections 8192;
}

# HTTPS: проброс TCP-соединения на оригинальный сайт по SNI (TLS не расшифровывается)
stream {
    resolver 1.1.1.1 8.8.8.8 valid=300s ipv6=off;
    resolver_timeout 5s;

    map $ssl_preread_server_name $sni_upstream {
        include /etc/smartdns/nginx-sni.map;
        default 127.0.0.1:9;
    }

    server {
        listen 443;
        include /etc/smartdns/nginx-allow.conf;
        ssl_preread on;
        proxy_pass $sni_upstream;
        proxy_connect_timeout 8s;
        proxy_timeout 1h;
    }
}

# HTTP: проброс по заголовку Host
http {
    access_log off;
    server_tokens off;
    client_max_body_size 0;
    resolver 1.1.1.1 8.8.8.8 valid=300s ipv6=off;
    resolver_timeout 5s;

    map $host $host_allowed {
        include /etc/smartdns/nginx-http.map;
        default 0;
    }

    server {
        listen 80 default_server;
        server_name _;
        include /etc/smartdns/nginx-allow.conf;

        if ($host_allowed = 0) { return 444; }

        location / {
            proxy_pass http://$host;
            proxy_set_header Host $host;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
        }
    }
}
EOF
  } > "$CONF_DIR/nginx.conf"
}

gen_firewall() {
  local elems
  elems=$(read_allowed | paste -sd, -)
  [[ -n $elems ]] || die "Список разрешённых IP пуст."
  cat > "$CONF_DIR/firewall.nft" <<EOF
table inet smartdns
delete table inet smartdns
table inet smartdns {
    set allowed4 {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { $elems }
    }
    chain input {
        type filter hook input priority -10; policy accept;
        iifname "lo" return
        ip saddr @allowed4 return
        tcp dport { 53, 80, 443 } drop
        udp dport 53 drop
    }
}
EOF
}

ufw_active() { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; }

ufw_sync() {
  ufw_active || return 0
  local c
  for c in $(read_allowed); do
    ufw allow from "$c" to any port 53 >/dev/null 2>&1 || true
    ufw allow proto tcp from "$c" to any port 80,443 >/dev/null 2>&1 || true
  done
}

ufw_forget() {
  ufw_active || return 0
  ufw --force delete allow from "$1" to any port 53 >/dev/null 2>&1 || true
  ufw --force delete allow proto tcp from "$1" to any port 80,443 >/dev/null 2>&1 || true
}

# ───────────────────────── применение и проверка ─────────────────────────

apply() {
  local out
  [[ -n $(read_allowed) ]] || die "Список разрешённых IP пуст — добавьте: smartdns allow <IP>"
  detect_net
  gen_domain_files
  gen_dnsmasq_conf
  gen_nginx_conf
  gen_firewall

  out=$(dnsmasq --test -C "$CONF_DIR/dnsmasq.conf" 2>&1) || die "dnsmasq.conf: $out"
  out=$(nginx -t -c "$CONF_DIR/nginx.conf" 2>&1) || die "nginx.conf: $out"
  out=$(nft -c -f "$CONF_DIR/firewall.nft" 2>&1) \
    || die "nftables: $out
Без файрвола запуск запрещён (сервер станет открытым DNS-резолвером). Возможно, контейнер/ядро без поддержки nftables."

  ufw_sync
  systemctl daemon-reload
  systemctl enable smartdns-firewall smartdns-dns smartdns-proxy >/dev/null 2>&1
  systemctl reload-or-restart smartdns-firewall || die "Не удалось применить правила файрвола"
  if ! systemctl restart smartdns-dns smartdns-proxy; then
    journalctl -u smartdns-dns -u smartdns-proxy -n 25 --no-pager >&2 || true
    die "Службы не запустились (см. лог выше)"
  fi
}

selftest() {
  local got code
  info "Проверка работы"
  sleep 1
  if command -v dig >/dev/null 2>&1; then
    got=$(dig +short +time=3 +tries=2 @127.0.0.1 claude.ai A 2>/dev/null | head -n1 || true)
    if [[ $got == "$PUBLIC_IP" ]]; then
      ok "DNS подменяет claude.ai → $PUBLIC_IP"
    else
      warn "DNS вернул '${got:-пусто}' вместо $PUBLIC_IP"
    fi
    got=$(dig +short +time=3 +tries=2 @127.0.0.1 example.com A 2>/dev/null | head -n1 || true)
    if [[ -n $got ]]; then
      ok "Обычные домены резолвятся как обычно (example.com → $got)"
    else
      warn "Внешний DNS не отвечает — проверьте исходящие запросы к 1.1.1.1 / 8.8.8.8 (порт 53)"
    fi
  else
    warn "dig не найден — DNS-проверка пропущена"
  fi
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
         --resolve claude.ai:443:127.0.0.1 https://claude.ai/ 2>/dev/null || true)
  case ${code:-000} in
    000) warn "Прокси не смог достучаться до claude.ai (нет исходящего 443 или TLS-ошибка). Лог: /var/log/smartdns-nginx.log" ;;
    403|429|503) ok "Прокси работает (claude.ai ответил HTTP $code — для curl с IP дата-центра это ожидаемо, проверьте из браузера)" ;;
    *) ok "Прокси работает (claude.ai ответил HTTP $code)" ;;
  esac
}

print_summary() {
  local line c
  line=$(printf '=%.0s' {1..64})
  cat <<EOF

$line
  ${C_B}Smart DNS готов.${C_0}  Подключайтесь по адресу (DNS-сервер):

            ${C_G}${C_B}$PUBLIC_IP${C_0}

$line

Впишите этот IP как основной И дополнительный DNS:
  • Xbox:         Настройки → Общие → Параметры сети → Дополнительные параметры → Настройки DNS → Вручную
  • PlayStation:  Настройки → Сеть → Настроить подключение к интернету → Wi-Fi/LAN → Особые → DNS: вручную
  • ПК/телефон:   свойства Wi-Fi/сетевого адаптера → DNS. В браузере отключите «Безопасный DNS» (DoH),
                  на устройстве лучше отключить IPv6.

Разрешённые клиенты (остальным доступ закрыт):
$(read_allowed | sed 's/^/  • /')

Не забудьте открыть в панели хостера/файрволе: 53 (TCP+UDP), 80 и 443 (TCP).
Домены:     $DOMAINS_FILE   (после правки: smartdns apply)
Управление: smartdns allow <IP> | remove <IP> | list | apply | status | uninstall
EOF
}

# ───────────────────────── команды ─────────────────────────

cmd_install() {
  CLIENTS=("$@")
  check_system
  check_ports
  mkdir -p "$CONF_DIR"
  touch "$ALLOWED_FILE"
  if (( ${#CLIENTS[@]} == 0 )) && [[ -z $(read_allowed) ]]; then ask_clients; fi
  local c
  for c in "${CLIENTS[@]}"; do
    is_client "$c" || die "Некорректный IPv4/CIDR: $c"
    echo "$c" >> "$ALLOWED_FILE"
  done
  sort -u "$ALLOWED_FILE" -o "$ALLOWED_FILE"

  install_packages
  write_default_domains
  write_units
  install_self
  info "Настройка и запуск служб…"
  apply
  ok "Службы запущены"
  selftest
  print_summary
}

cmd_allow() {
  [[ $# -gt 0 ]] || die "Использование: smartdns allow <IP|CIDR> ..."
  local c
  for c in "$@"; do
    is_client "$c" || die "Некорректный IPv4/CIDR: $c"
    echo "$c" >> "$ALLOWED_FILE"
  done
  sort -u "$ALLOWED_FILE" -o "$ALLOWED_FILE"
  apply
  ok "Разрешено: $*"
}

cmd_remove() {
  [[ $# -gt 0 ]] || die "Использование: smartdns remove <IP|CIDR> ..."
  local c tmp
  tmp=$(mktemp)
  cp "$ALLOWED_FILE" "$tmp"
  for c in "$@"; do
    grep -vxF "$c" "$tmp" > "$tmp.new" || true
    mv "$tmp.new" "$tmp"
  done
  if ! grep -qE '^[0-9]' "$tmp"; then rm -f "$tmp"; die "Нельзя удалить последний разрешённый IP."; fi
  for c in "$@"; do ufw_forget "$c"; done
  mv "$tmp" "$ALLOWED_FILE"
  apply
  ok "Удалено: $*"
}

cmd_list() { read_allowed; }

cmd_status() {
  local s
  for s in smartdns-firewall smartdns-dns smartdns-proxy; do
    printf '%-20s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"
  done
  if [[ -r $ENV_FILE ]]; then . "$ENV_FILE"; echo "DNS-сервер для клиентов: ${PUBLIC_IP:-?}"; fi
  echo "Разрешённые клиенты:"
  read_allowed | sed 's/^/  /'
}

cmd_uninstall() {
  local c
  for c in $(read_allowed); do ufw_forget "$c"; done
  systemctl disable --now smartdns-proxy smartdns-dns smartdns-firewall >/dev/null 2>&1 || true
  rm -f "$UNIT_DIR"/smartdns-{firewall,dns,proxy}.service
  systemctl daemon-reload
  rm -rf "$CONF_DIR" /var/log/smartdns-nginx.log
  [[ -f $SELF_BIN ]] && rm -f "$SELF_BIN"
  ok "Smart DNS удалён. Пакеты оставлены (удалить: apt purge nginx libnginx-mod-stream dnsmasq-base)."
}

usage() {
  cat <<'EOF'
Использование (от root):
  smartdns.sh [install] [IP|CIDR ...]   установить Smart DNS (без аргументов спросит IP клиентов)
  smartdns allow <IP|CIDR> ...          разрешить клиентов
  smartdns remove <IP|CIDR> ...         убрать клиентов
  smartdns list                         показать клиентов
  smartdns apply                        применить правки /etc/smartdns/domains.txt
  smartdns status                       состояние служб
  smartdns uninstall                    удалить
EOF
}

main() {
  local cmd=${1:-install}
  (( $# )) && shift
  case $cmd in
    -h|--help|help) usage ;;
    install)        need_root; cmd_install "$@" ;;
    allow)          need_root; cmd_allow "$@" ;;
    remove|deny)    need_root; cmd_remove "$@" ;;
    list)           need_root; cmd_list ;;
    apply)          need_root; apply; ok "Конфигурация применена" ;;
    status)         need_root; cmd_status ;;
    uninstall)      need_root; cmd_uninstall ;;
    *)
      if is_client "$cmd"; then need_root; cmd_install "$cmd" "$@"; else usage; exit 1; fi ;;
  esac
}

main "$@"
