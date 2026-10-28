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
# =============================================================================
set -Eeuo pipefail
trap 'printf "\e[1;31m[x]\e[0m Сбой на строке %s\n" "$LINENO" >&2' ERR

log()  { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }

CONF_DIR=/etc/smartdns
STATE_DIR=/var/lib/smartdns
CTL=/usr/local/bin/smartdns-ctl
UPSTREAM_DNS=${SMARTDNS_UPSTREAM:-"1.1.1.1 8.8.8.8"}

DOMAIN=${SMARTDNS_DOMAIN:-}
PUBLIC_IP=${SMARTDNS_IP:-}
EMAIL=${SMARTDNS_EMAIL:-}
ALLOW=${SMARTDNS_ALLOW:-}
NO_DOT=0
ASSUME_YES=0
MODE=install

DOMAIN_RE='^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$'
IPV4_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
CIDR_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'

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
  -y, --yes             не задавать вопросов
      uninstall         удалить Smart DNS
  -h, --help            эта справка

Те же значения можно передать переменными: SMARTDNS_DOMAIN, SMARTDNS_IP,
SMARTDNS_EMAIL, SMARTDNS_ALLOW, SMARTDNS_UPSTREAM.
После установки управление — командой: smartdns-ctl help
EOF
}

while (($#)); do
  case $1 in
    -d|--domain) DOMAIN=${2:?нужно значение для $1}; shift 2 ;;
    -i|--ip)     PUBLIC_IP=${2:?нужно значение для $1}; shift 2 ;;
    -e|--email)  EMAIL=${2:?нужно значение для $1}; shift 2 ;;
    -a|--allow)  ALLOW=${2:?нужно значение для $1}; shift 2 ;;
    --no-dot)    NO_DOT=1; shift ;;
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

command -v apt-get   >/dev/null || die "Поддерживаются только Debian/Ubuntu (нужен apt)."
command -v systemctl >/dev/null || die "Нужен systemd."

# ---------------------------------------------------------------- вопросы ----
INTERACTIVE=0
if (( ! ASSUME_YES )) && (: </dev/tty) 2>/dev/null; then INTERACTIVE=1; fi

ask() { # ask "вопрос" "значение по умолчанию"
  local q=$1 def=${2-} ans=""
  if (( INTERACTIVE )); then
    printf '%s%s: ' "$q" "${def:+ [$def]}" >&2
    read -r ans </dev/tty || ans=""
  fi
  printf '%s' "${ans:-$def}"
}

export DEBIAN_FRONTEND=noninteractive
log "Ставлю базовые пакеты…"
apt-get update -qq
apt-get install -y -qq --no-install-recommends curl ca-certificates iproute2 >/dev/null

detect_public_ip() {
  local u ip
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    ip=$(curl -4 -fsS --max-time 6 "$u" 2>/dev/null | tr -d '[:space:]') || true
    if [[ $ip =~ $IPV4_RE ]]; then echo "$ip"; return 0; fi
  done
  return 1
}

[[ -n $DOMAIN ]] || DOMAIN=$(ask "Домен/поддомен для DNS-сервера" "dns.meowcat.me")
DOMAIN=${DOMAIN,,}; DOMAIN=${DOMAIN%.}
[[ $DOMAIN =~ $DOMAIN_RE ]] || die "Некорректный домен: '$DOMAIN'"

if [[ -z $PUBLIC_IP ]]; then
  PUBLIC_IP=$(ask "Публичный IPv4 этого сервера" "$(detect_public_ip || true)")
fi
[[ $PUBLIC_IP =~ $IPV4_RE ]] || die "Не удалось определить публичный IPv4. Укажите --ip."

LOCAL_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)
[[ $LOCAL_IP =~ $IPV4_RE ]] || die "Не удалось определить локальный IPv4 интерфейса."

if (( ! NO_DOT )); then
  [[ -n $EMAIL ]] || EMAIL=$(ask "E-mail для Let's Encrypt (можно пусто)" "")
fi
[[ -n $ALLOW ]] || ALLOW=$(ask "Разрешённые IP клиентов через пробел (пусто = всем)" "")
for ip in $ALLOW; do [[ $ip =~ $CIDR_RE ]] || die "Некорректный IP/CIDR в --allow: $ip"; done

# ------------------------------------------------------ проверка портов ------
systemctl stop smartdns-proxy smartdns-dns 2>/dev/null || true   # повторный запуск скрипта

tcp_busy() { ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ":$1\$"; }
dns_busy() {
  { ss -H -ltn; ss -H -lun; } 2>/dev/null | awk '{print $4}' \
    | grep -Eq "^(0\.0\.0\.0|\*|127\.0\.0\.1|\[::\]|${LOCAL_IP//./[.]}):53\$"
}
dns_busy && die "Порт 53 занят (часто systemd-resolved с DNSStubListener=yes на 0.0.0.0, bind9, dnsmasq). Освободите его и запустите снова."
for p in 80 443 853; do
  tcp_busy "$p" && die "TCP-порт $p занят другим сервисом (nginx/apache/xray…). Освободите его и запустите снова."
done

# --------------------------------------------------------------- пакеты ------
log "Ставлю dnsmasq, nginx (stream), certbot…"
apt-get install -y -qq --no-install-recommends dnsmasq-base nginx libnginx-mod-stream certbot >/dev/null
apt-get install -y -qq dnsutils >/dev/null 2>&1 || apt-get install -y -qq bind9-dnsutils >/dev/null 2>&1 || true
# системный nginx.service нам не нужен — работаем отдельным инстансом
systemctl disable --now nginx >/dev/null 2>&1 || true

NGINX_BIN=$(command -v nginx || echo /usr/sbin/nginx)
DNSMASQ_BIN=$(command -v dnsmasq || echo /usr/sbin/dnsmasq)
[[ -x $NGINX_BIN && -x $DNSMASQ_BIN ]] || die "Не найдены бинарники nginx/dnsmasq."

# ------------------------------------------------------------- конфиги -------
log "Пишу конфигурацию в $CONF_DIR …"
mkdir -p "$CONF_DIR" "$STATE_DIR/acme"
chmod 755 "$STATE_DIR" "$STATE_DIR/acme"

{
  printf 'DOMAIN=%q\n'       "$DOMAIN"
  printf 'PUBLIC_IP=%q\n'    "$PUBLIC_IP"
  printf 'LOCAL_IP=%q\n'     "$LOCAL_IP"
  printf 'UPSTREAM_DNS=%q\n' "$UPSTREAM_DNS"
  printf 'EMAIL=%q\n'        "$EMAIL"
  printf 'ENABLE_DOT=%q\n'   "$(( NO_DOT ? 0 : 1 ))"
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

# ----------------------------------------------------- smartdns-ctl ----------
cat > "$CTL" <<'CTL_EOF'
#!/usr/bin/env bash
# smartdns-ctl — управление Smart DNS (dnsmasq + nginx)
set -Eeuo pipefail

CONF_DIR=${SMARTDNS_CONF_DIR:-/etc/smartdns}
STATE_DIR=${SMARTDNS_STATE_DIR:-/var/lib/smartdns}
# shellcheck disable=SC1091
source "$CONF_DIR/smartdns.conf"
DOMAINS_FILE=$CONF_DIR/domains.list
BYPASS_FILE=$CONF_DIR/bypass.list
ALLOW_FILE=$CONF_DIR/allowed_ips.list

DOMAIN_RE='^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$'
CIDR_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'

ok()   { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "Запустите от root (sudo smartdns-ctl …)"

usage() {
  cat <<EOF
smartdns-ctl — управление Smart DNS

  add [-b] домен…     добавить домен в список (с -b — в исключения «напрямую»)
  del домен…          убрать домен из обоих списков
  list                показать списки и разрешённые IP
  allow IP/CIDR…      разрешить клиентам доступ (включает белый список)
  unallow IP/CIDR…    убрать IP из белого списка (пустой список = доступ всем)
  reload              пересобрать конфиги и перезапустить сервисы
  cert                выпустить/обновить сертификат для DoT ($DOMAIN)
  status              состояние сервисов и портов
  uninstall           удалить Smart DNS

Файлы: $DOMAINS_FILE, $BYPASS_FILE, $ALLOW_FILE (после правки — reload)
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

norm_domain() {
  local d=${1,,}
  d=${d#*://}; d=${d%%/*}; d=${d#\*.}; d=${d#.}; d=${d%.}
  [[ $d =~ $DOMAIN_RE ]] || return 1
  printf '%s' "$d"
}

apply_fw() { # белый список клиентов для порта 53 (80/443/853 фильтрует nginx)
  local -a ips; mapfile -t ips < <(read_list "$ALLOW_FILE")
  if (( ${#ips[@]} )); then
    command -v nft >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null; }
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
    systemctl restart smartdns-fw || warn "не удалось применить nft-правила (журнал: journalctl -u smartdns-fw)"
  else
    systemctl disable --now smartdns-fw >/dev/null 2>&1 || true
    rm -f "$CONF_DIR/nft.rules"
  fi
}

render() {
  local d u nogroup dot=0
  local -a DOMS BYP IPS
  mapfile -t DOMS < <(read_list "$DOMAINS_FILE")
  mapfile -t BYP  < <(read_list "$BYPASS_FILE")
  mapfile -t IPS  < <(read_list "$ALLOW_FILE")
  (( ${#DOMS[@]} )) || die "domains.list пуст — нечего разблокировать."
  nogroup=$(getent group nogroup >/dev/null && echo nogroup || echo nobody)
  mkdir -p "$STATE_DIR/acme"; chmod 755 "$STATE_DIR" "$STATE_DIR/acme"

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
    for u in $UPSTREAM_DNS; do echo "server=$u"; done
    echo "# --- исключения: резолвим у публичных DNS => трафик напрямую"
    for d in "${BYP[@]}"; do for u in $UPSTREAM_DNS; do echo "server=/$d/$u"; done; done
    echo "# --- список: отвечаем IP этого сервера (все поддомены тоже)"
    for d in "${DOMS[@]}"; do echo "address=/$d/$PUBLIC_IP"; done
  } > "$CONF_DIR/dnsmasq.conf.new"
  "$DNSMASQ_BIN" --test --conf-file="$CONF_DIR/dnsmasq.conf.new" || die "Ошибка в конфиге dnsmasq."

  # ---- карты и ACL для nginx
  {
    for d in "${DOMS[@]}"; do echo ".$d 1;"; done
    for d in "${BYP[@]}";  do echo ".$d 0;"; done
  } > "$CONF_DIR/nginx-hosts.map"

  {
    if (( ${#IPS[@]} )); then
      echo "allow 127.0.0.1;"
      for u in "${IPS[@]}"; do echo "allow $u;"; done
      echo "deny all;"
    fi
  } > "$CONF_DIR/nginx-allow.conf"

  if [[ ${ENABLE_DOT:-0} == 1 && -s /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]]; then dot=1; fi

  # ---- nginx
  {
    cat <<'EOF'
# Сгенерировано smartdns-ctl — не править руками
user nobody __NOGROUP__;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/smartdns-proxy.pid;
error_log stderr warn;
include /etc/nginx/modules-enabled/*stream*.conf;

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
    access_log off;
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
  } | sed -e "s|__NOGROUP__|$nogroup|g" \
          -e "s|__RESOLVERS__|$UPSTREAM_DNS|g" \
          -e "s|__DOMAIN__|$DOMAIN|g" \
          -e "s|__CONF__|$CONF_DIR|g" \
          -e "s|__ACME__|$STATE_DIR/acme|g" > "$CONF_DIR/nginx.conf.new"
  "$NGINX_BIN" -t -c "$CONF_DIR/nginx.conf.new" || die "Ошибка в конфиге nginx."

  mv -f "$CONF_DIR/dnsmasq.conf.new" "$CONF_DIR/dnsmasq.conf"
  mv -f "$CONF_DIR/nginx.conf.new"   "$CONF_DIR/nginx.conf"

  apply_fw
  systemctl enable smartdns-dns smartdns-proxy >/dev/null 2>&1 || true
  systemctl restart smartdns-dns \
    || die "smartdns-dns не запустился: journalctl -u smartdns-dns -n 30"
  if systemctl is-active --quiet smartdns-proxy; then
    systemctl reload smartdns-proxy || die "nginx не перечитал конфиг: journalctl -u smartdns-proxy -n 30"
  else
    systemctl start smartdns-proxy  || die "smartdns-proxy не запустился: journalctl -u smartdns-proxy -n 30"
  fi
  ok "Применено: в списке ${#DOMS[@]}, исключений ${#BYP[@]}, разрешённых IP ${#IPS[@]}$( ((dot)) && echo ', DoT включён' )"
}

cmd_add() {
  local file=$DOMAINS_FILE other=$BYPASS_FILE raw d
  if [[ ${1:-} == -b ]]; then file=$BYPASS_FILE; other=$DOMAINS_FILE; shift; fi
  (($#)) || die "Укажите домен(ы): smartdns-ctl add [-b] example.com"
  for raw in "$@"; do
    d=$(norm_domain "$raw") || { warn "Пропускаю некорректный домен: $raw"; continue; }
    list_remove "$other" "$d"
    if ! grep -qxF "$d" <(read_list "$file"); then echo "$d" >> "$file"; fi
    ok "добавлен: $d"
  done
  render
}

cmd_del() {
  local raw d
  (($#)) || die "Укажите домен(ы): smartdns-ctl del example.com"
  for raw in "$@"; do
    d=$(norm_domain "$raw") || { warn "Пропускаю некорректный домен: $raw"; continue; }
    list_remove "$DOMAINS_FILE" "$d"; list_remove "$BYPASS_FILE" "$d"
    ok "удалён: $d"
  done
  render
}

cmd_allow() {
  local ip
  (($#)) || die "Укажите IP/CIDR: smartdns-ctl allow 203.0.113.7"
  for ip in "$@"; do
    [[ $ip =~ $CIDR_RE ]] || { warn "Некорректный IP: $ip"; continue; }
    if ! grep -qxF "$ip" <(read_list "$ALLOW_FILE"); then echo "$ip" >> "$ALLOW_FILE"; fi
    ok "разрешён: $ip"
  done
  render
}

cmd_unallow() {
  local ip
  (($#)) || die "Укажите IP/CIDR."
  for ip in "$@"; do list_remove "$ALLOW_FILE" "$ip"; ok "убран: $ip"; done
  render
}

cmd_list() {
  echo "== Через сервер (domains.list) ==";   read_list "$DOMAINS_FILE" | sed 's/^/  /'
  echo "== Напрямую (bypass.list) ==";        read_list "$BYPASS_FILE"  | sed 's/^/  /'
  echo "== Разрешённые клиенты (пусто = все) =="; read_list "$ALLOW_FILE" | sed 's/^/  /'
  return 0
}

cmd_cert() {
  [[ ${ENABLE_DOT:-0} == 1 ]] || die "DoT отключён при установке (--no-dot)."
  systemctl is-active --quiet smartdns-proxy || die "smartdns-proxy не запущен (нужен :80 для проверки ACME)."
  local -a em=(--register-unsafely-without-email)
  if [[ -n ${EMAIL:-} ]]; then em=(-m "$EMAIL"); fi
  certbot certonly --webroot -w "$STATE_DIR/acme" -d "$DOMAIN" \
    --non-interactive --agree-tos "${em[@]}" \
    --deploy-hook "systemctl reload smartdns-proxy"
  render
}

cmd_status() {
  local s
  for s in smartdns-dns smartdns-proxy smartdns-fw; do
    printf '  %-16s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"
  done
  echo "  IP: $PUBLIC_IP   домен: $DOMAIN   сертификат DoT: $([[ -s /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]] && echo есть || echo нет)"
  echo "  Слушает:"
  ss -H -lntu 2>/dev/null | awk '$5 ~ /:(53|80|443|853)$/ {print "    " $1, $5}' | sort -u
  return 0
}

cmd_uninstall() {
  local a=y
  if [[ -t 0 ]]; then read -r -p "Удалить Smart DNS (конфиги и сервисы)? [y/N] " a || a=n; fi
  [[ $a =~ ^[yYдД] ]] || die "Отменено."
  systemctl disable --now smartdns-proxy smartdns-dns smartdns-fw >/dev/null 2>&1 || true
  nft delete table inet smartdns >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/smartdns-dns.service /etc/systemd/system/smartdns-proxy.service /etc/systemd/system/smartdns-fw.service
  systemctl daemon-reload
  rm -rf "$CONF_DIR" "$STATE_DIR" /usr/local/bin/smartdns-ctl
  ok "Удалено. Пакеты (nginx, dnsmasq-base, certbot) и сертификат Let's Encrypt не тронуты."
}

case "${1:-help}" in
  add)               shift; cmd_add "$@" ;;
  del|rm)            shift; cmd_del "$@" ;;
  list|ls)           cmd_list ;;
  allow)             shift; cmd_allow "$@" ;;
  unallow|disallow)  shift; cmd_unallow "$@" ;;
  reload|apply)      render ;;
  cert)              cmd_cert ;;
  status)            cmd_status ;;
  uninstall)         cmd_uninstall ;;
  *)                 usage ;;
esac
CTL_EOF
chmod 755 "$CTL"

# ---------------------------------------------------------- systemd ----------
log "Создаю systemd-юниты…"
cat > /etc/systemd/system/smartdns-dns.service <<EOF
[Unit]
Description=SmartDNS: dnsmasq (DNS-unlock)
After=network-online.target
Wants=network-online.target

[Service]
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
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  log "ufw активен — открываю 53, 80, 443, 853…"
  ufw allow 53 >/dev/null; ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null; ufw allow 853/tcp >/dev/null
fi

# ------------------------------------------------------------- запуск --------
log "Собираю конфиги и запускаю сервисы…"
"$CTL" reload
sleep 1

if (( ! NO_DOT )); then
  resolved=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}' || true)
  if [[ $resolved == "$PUBLIC_IP" ]]; then
    log "Выпускаю сертификат Let's Encrypt для $DOMAIN…"
    "$CTL" cert || warn "Сертификат не выпущен. Исправьте причину и выполните: smartdns-ctl cert"
  else
    warn "A-запись $DOMAIN → '${resolved:-нет}', а IP сервера $PUBLIC_IP."
    warn "Создайте A-запись (без проксирования Cloudflare), затем выполните: smartdns-ctl cert"
  fi
fi

# ------------------------------------------------------------ самопроверка ---
if command -v dig >/dev/null 2>&1; then
  a=$(dig +short +time=2 +tries=1 @127.0.0.1 claude.ai A 2>/dev/null | head -n1 || true)
  b=$(dig +short +time=3 +tries=1 @127.0.0.1 example.com A 2>/dev/null | head -n1 || true)
  if [[ $a == "$PUBLIC_IP" ]]; then log "DNS: claude.ai → $a  (через сервер) ✔"
  else warn "DNS: claude.ai → '${a:-нет ответа}', ожидался $PUBLIC_IP"; fi
  if [[ -n $b && $b != "$PUBLIC_IP" ]]; then log "DNS: example.com → $b  (напрямую) ✔"
  else warn "DNS: example.com → '${b:-нет ответа}' — проверьте исходящий доступ к $UPSTREAM_DNS"; fi
fi
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
        --resolve claude.ai:443:127.0.0.1 https://claude.ai/ 2>/dev/null || true)
log "SNI-прокси: https://claude.ai через сервер → HTTP ${code:-000} (000 = не работает)"

# ------------------------------------------------------------------ итог -----
cat <<EOF

════════════════════════════════════════════════════════════════
 Smart DNS установлен
════════════════════════════════════════════════════════════════
 DNS-сервер : $PUBLIC_IP  (порт 53, udp+tcp)
 DoT        : $DOMAIN:853  $([[ -s /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]] && echo "(сертификат есть)" || echo "(пока нет сертификата — см. выше)")

 Как пользоваться
   • Консоль / ПК / роутер / телефон: в настройках сети вручную задайте
     DNS = $PUBLIC_IP  (вторичный DNS не указывайте или ставьте тот же).
   • Android: Настройки → Сеть → Частный DNS → $DOMAIN
   • Домены из списка идут через сервер, всё остальное — напрямую.
   • Отключите «Безопасный DNS/DoH» в браузере, иначе он обойдёт ваш DNS.

 Управление
   smartdns-ctl add claude.ai | add -b dl.example.com | del | list
   smartdns-ctl allow <ваш IP> | unallow | reload | status | cert | uninstall
   Списки: $CONF_DIR/domains.list, bypass.list, allowed_ips.list

 В файрволе провайдера (облачная панель) откройте: 53/udp, 53/tcp, 80/tcp, 443/tcp, 853/tcp.
EOF
if [[ -z $ALLOW ]] && ! grep -qvE '^\s*(#|$)' "$CONF_DIR/allowed_ips.list"; then
  warn "Доступ открыт ВСЕМ: это открытый DNS-резолвер (его используют для DDoS-амплификации)."
  warn "Рекомендую ограничить клиентов:  smartdns-ctl allow <ваш IP>"
fi
