#!/usr/bin/env bash
# =====================================================================
#  VLESS-стек за собственным сайтом (Debian / Ubuntu)
#
#  РЕЖИМ 1 — warp: всё на одном сервере, выход через Cloudflare WARP
#
#    443/tcp -> Xray (VLESS + Reality + Vision, "self-steal": dest = свой nginx)
#                 |-- клиенты Reality  -> VPN
#                 '-- всё остальное (браузеры, сканеры, прочие транспорты)
#                       -> nginx 127.0.0.1:8443 с настоящим сертификатом LE
#                            |-- /            -> ваш сайт
#                            |-- /<xhttp>     -> Xray VLESS + XHTTP
#                            |-- /<grpc>      -> Xray VLESS + gRPC
#                            |-- /<ws>        -> Xray VLESS + WebSocket
#                            '-- /<hu>        -> Xray VLESS + HTTPUpgrade
#    Весь исходящий трафик Xray -> WireGuard (WARP). Прямого выхода нет (fail-closed).
#
#  РЕЖИМ 2 — chain: входной сервер + от 1 до 3 выходных релеев
#
#    клиент --VLESS(SNI=ваш домен)--> ВХОД (сайт на этом домене + Xray,
#                 для посторонних это обычный HTTPS-сайт, всё как в режиме 1)
#                 -> HAProxy 127.0.0.1:10443 (выбор релея по нагрузке)
#                 -> WireGuard-туннель (10.200.0.0/24)
#                 -> ВЫХОДНОЙ РЕЛЕЙ (SOCKS5 только внутри туннеля) -> интернет
#
#    * Домен и сайт нужны ТОЛЬКО входному серверу: клиент подключается по
#      VLESS с SNI вашего домена, входной сервер поднимает на этом домене
#      сайт — снаружи это выглядит как обычное посещение сайта.
#    * Релеи указываются по IP, БЕЗ доменов и БЕЗ сайтов: маскировка им не
#      нужна — провайдер релея видит лишь зашифрованный WireGuard-туннель.
#    * Между серверами трафик идёт НЕ по VLESS, а по WireGuard (UDP, ядерный
#      модуль) — быстро и с минимальными накладными расходами; внутри
#      туннеля — лёгкий SOCKS5 без шифрования (шифрует сам WireGuard).
#    * Выходные релеи скрипт ставит САМ по SSH (чистый Debian/Ubuntu с root-доступом).
#    * На выходе нет WARP: трафик уходит в интернет напрямую, с IP релея.
#    * На каждом релее крутится крошечный агент: он измеряет CPU / load / сеть / RAM
#      и отдаёт входному серверу "вес" в процентах (доступен только внутри
#      туннеля). HAProxy раздаёт новые соединения пропорционально свободным
#      ресурсам (balance leastconn + динамические веса), упавший релей
#      исключается автоматически.
#    * Прямого выхода с входного сервера нет (fail-closed).
#
#  Запуск (скрипт должен лежать файлом — он сам копирует себя на выходные релеи):
#
#    bash install.sh                                   # интерактивное меню
#    DOMAIN=вход.example.com bash install.sh           # режим warp
#    DOMAIN=вход.example.com MODE=chain \
#      EXITS="203.0.113.10 203.0.113.11:2222 ubuntu@203.0.113.12" \
#      bash install.sh                                 # режим chain
#
#  Переменные (необязательные):
#    EMAIL=…           e-mail для Let's Encrypt (входной сервер)
#    FORCE=1           не проверять DNS
#    NO_UFW=1          не трогать фаервол
#    EXIT_SSH_PASS=…   пароль SSH выходных релеев (иначе спросит при копировании ключа)
#    ENTRY_IP=…        IP входного сервера, как его видят релеи (по умолчанию — внешний IP)
#    AGENT_PORT=9777   порт агента нагрузки на релеях (слушает только внутри туннеля)
#    NET_CAP_MBIT=1000 полоса канала релея, Мбит/с (для расчёта загрузки сети)
#    WG_PORT=51820     UDP-порт WireGuard (открыт только между серверами цепочки)
#
#  MODE=exit — служебный режим, его запускает входной сервер на релеях.
# =====================================================================
set -Eeuo pipefail

MODE="${MODE:-}"
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"            # необязательно, для уведомлений Let's Encrypt
FORCE="${FORCE:-}"            # FORCE=1 — пропустить проверку DNS
NO_UFW="${NO_UFW:-}"          # NO_UFW=1 — не трогать фаервол
EXITS="${EXITS:-}"            # chain: список выходных релеев (1–3), по IP
EXIT_SSH_PASS="${EXIT_SSH_PASS:-}"
ENTRY_IP="${ENTRY_IP:-}"
AGENT_PORT="${AGENT_PORT:-9777}"
NET_CAP_MBIT="${NET_CAP_MBIT:-1000}"
WG_PORT="${WG_PORT:-51820}"
PARAMS_FILE="${PARAMS_FILE:-}"

XCONF=/usr/local/etc/xray/config.json
ENVF=/root/.vpn-secrets.env          # секреты входного сервера (warp / chain)
EXIT_ENVF=/root/.vpn-exit.env        # параметры выходного релея
WEBROOT=/var/www/hlebcraft
WARPDIR=/etc/warp
HA_CFG=/etc/haproxy/haproxy.cfg
HA_PORT=10443
HA_SOCK=/run/haproxy-vpn.sock
EXITS_MAP=/etc/vpn-exits.map
CHAIN_KEY=/root/.ssh/vpn_chain_ed25519
CHAIN_KNOWN=/root/.ssh/known_hosts_vpnchain
WG_DIR=/etc/wireguard
WG_IF=wg0
WG_NET=10.200.0                      # подсеть туннеля: вход = .1, релеи = .11, .12, .13
WG_ENTRY_IP=$WG_NET.1
EXIT_SOCKS_PORT=1080                 # SOCKS5 на релее (только внутри туннеля)
SELF="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || true)"

SNIFF='"sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}'
RE_DOMAIN='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z0-9-]+$'

EX_USER=(); EX_HOST=(); EX_PORT=(); EX_IP=(); EX_PUB=(); EX_WGIP=()
SSH_O=(-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$CHAIN_KNOWN" -o ConnectTimeout=15)

log(){ printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die(){ printf '\n\033[1;31m[ОШИБКА]\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "Сбой на строке $LINENO"' ERR

is_tty(){ [[ -t 0 ]]; }
valid_domain(){ [[ "$1" =~ $RE_DOMAIN && ! "$1" =~ ^[0-9.]+$ ]]; }

# значение из прежнего ENVF, не засоряя окружение
saved(){
  [[ -f "$ENVF" ]] || return 0
  ( set +eu; trap - ERR; . "$ENVF" >/dev/null 2>&1 || true; eval "printf '%s' \"\${$1:-}\"" )
}
save_kv(){
  local k="$1" v="$2"
  touch "$ENVF"; chmod 600 "$ENVF"
  sed -i "/^$k=/d" "$ENVF"
  printf '%s=%q\n' "$k" "$v" >> "$ENVF"
}

# ================================================================ проверки
preflight(){
  [[ $EUID -eq 0 ]] || die "Запускайте от root"
  [[ -r /etc/os-release ]] || die "Не найден /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) : ;;
    *)
      if [[ "${ID_LIKE:-}" == *debian* || "${ID_LIKE:-}" == *ubuntu* ]]; then
        warn "Система ${PRETTY_NAME:-?} — производная от Debian/Ubuntu, продолжаю на свой страх и риск"
      else
        die "Скрипт рассчитан на Debian и Ubuntu"
      fi ;;
  esac
  local major="${VERSION_ID:-}"; major="${major%%.*}"
  if [[ "$major" =~ ^[0-9]+$ ]]; then
    if [[ "${ID:-}" == debian && $major -lt 10 ]]; then die "Нужен Debian 10 или новее"; fi
    if [[ "${ID:-}" == ubuntu && $major -lt 20 ]]; then die "Нужна Ubuntu 20.04 или новее"; fi
  fi
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1
}

select_mode(){
  case "${MODE,,}" in
    warp|1)  MODE=warp;  return 0 ;;
    chain|2) MODE=chain; return 0 ;;
    exit)    MODE=exit;  return 0 ;;
    "")      : ;;
    *) die "Неизвестный MODE=\"$MODE\". Допустимо: warp, chain" ;;
  esac
  if is_tty; then
    local def ans
    def=$(saved SAVED_MODE)
    if [[ "$def" == chain ]]; then def=2; else def=1; fi
    cat <<'EOF'

Выберите режим работы:
  1) WARP    — один сервер: сайт + VLESS, выход в интернет через Cloudflare WARP
  2) Цепочка — этот сервер входной (сайт + VLESS), трафик уходит на 1–3
               выходных релея через быстрый WireGuard-туннель; на релеях скрипт
               всё ставит сам по SSH, сайтов на них нет, а релей для каждого
               соединения выбирается автоматически по загруженности
EOF
    read -r -p "Режим [$def]: " ans || true
    ans="${ans:-$def}"
    case "$ans" in
      1) MODE=warp ;;
      2) MODE=chain ;;
      *) die "Нужно ввести 1 или 2" ;;
    esac
  else
    MODE=warp
    warn "MODE не задан, а запуск неинтерактивный — использую warp"
  fi
}

ensure_domain(){
  if [[ -z "$DOMAIN" || "$DOMAIN" == "ВАШСАЙТ" ]]; then
    DOMAIN=""
    if is_tty; then
      read -r -p "Домен ${1:-этого сервера} (A-запись должна указывать на этот сервер): " DOMAIN || true
    fi
  fi
  DOMAIN="${DOMAIN,,}"
  valid_domain "$DOMAIN" || die "Укажите корректный DOMAIN (пример: DOMAIN=example.com bash install.sh). IP-адрес не подходит — нужен домен."
}

# ================================================================ пакеты
install_packages(){
  log "Установка пакетов"
  local pk
  case "$MODE" in
    warp)  pk=(curl ca-certificates openssl nginx certbot ufw iproute2 unzip qrencode) ;;
    chain)
      pk=(curl ca-certificates openssl nginx certbot ufw iproute2 unzip qrencode haproxy socat openssh-client wireguard)
      if [[ -n "$EXIT_SSH_PASS" ]]; then pk+=(sshpass); fi ;;
    exit)  # на релее нет сайта: nginx и certbot не нужны — только туннель и SOCKS5
      pk=(curl ca-certificates ufw iproute2 unzip wireguard) ;;
  esac
  apt-get -o DPkg::Lock::Timeout=300 update -y
  apt-get -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confold install -y "${pk[@]}" >/dev/null
}

check_dns(){
  log "Проверка DNS для $DOMAIN"
  SERVER_IP=$(curl -4fsS --max-time 10 https://api.ipify.org || curl -4fsS --max-time 10 https://ifconfig.me || true)
  DNS_IP=$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}' || true)
  echo "IP сервера: ${SERVER_IP:-?}   A-запись $DOMAIN: ${DNS_IP:-нет}"
  if [[ -z "$FORCE" && "$SERVER_IP" != "$DNS_IP" ]]; then
    die "A-запись $DOMAIN должна указывать на $SERVER_IP (без проксирования Cloudflare / оранжевого облака). Исправьте DNS, подождите пару минут и запустите снова."
  fi
}

install_xray(){
  log "Установка Xray-core"
  local n
  for n in 1 2 3; do
    curl -fsSL -o /tmp/xray-install.sh https://github.com/XTLS/Xray-install/raw/main/install-release.sh && break
    echo "Повтор загрузки установщика Xray ($n/3)…"; sleep 3
  done
  [[ -s /tmp/xray-install.sh ]] || die "Не удалось скачать установщик Xray"
  bash /tmp/xray-install.sh install
  command -v xray >/dev/null || die "Xray не установился"
}

# ================================================================ секреты
gen_x25519(){   # -> GK_PRIV, GK_PUB
  local keys
  keys=$(xray x25519)
  GK_PRIV=$(echo "$keys" | awk -F': *' 'tolower($1) ~ /private/ {print $2}' | tr -d ' \r')
  GK_PUB=$(echo "$keys"  | awk -F': *' 'tolower($1) ~ /public|password/ {print $2}' | tr -d ' \r')
  [[ -n "$GK_PRIV" && -n "$GK_PUB" ]] || die "Не удалось получить ключи Reality: $keys"
}

# секреты входного сервера (переиспользуются при повторном запуске)
load_secrets(){
  if [[ -f "$ENVF" ]]; then
    log "Найдены прежние ключи, использую их"
    # shellcheck disable=SC1090
    source "$ENVF"
  else
    log "Генерация ключей"
    UUID=$(cat /proc/sys/kernel/random/uuid)
    gen_x25519
    R_PRIV=$GK_PRIV; R_PUB=$GK_PUB
    SID=$(openssl rand -hex 8)
    P_XHTTP=$(openssl rand -hex 6)
    P_GRPC=$(openssl rand -hex 6)
    P_WS=$(openssl rand -hex 6)
    P_HU=$(openssl rand -hex 6)
    umask 077
    cat > "$ENVF" <<EOF
UUID=$UUID
R_PRIV=$R_PRIV
R_PUB=$R_PUB
SID=$SID
P_XHTTP=$P_XHTTP
P_GRPC=$P_GRPC
P_WS=$P_WS
P_HU=$P_HU
EOF
    umask 022
  fi

  # ключи WireGuard-туннеля вход -> выход (входной сервер)
  if [[ "$MODE" == chain && -z "${WG_PRIV:-}" ]]; then
    log "Генерация ключей WireGuard-туннеля"
    WG_PRIV=$(wg genkey)
    WG_PUB=$(wg pubkey <<<"$WG_PRIV")
    save_kv WG_PRIV "$WG_PRIV"; save_kv WG_PUB "$WG_PUB"
  fi
}

# ================================================================ сайт-прикрытие + сертификат
# (только входной сервер: на релеях сайтов и доменов нет и не создаётся)
setup_site(){
  log "Сайт и сертификат"
  mkdir -p "$WEBROOT" /var/www/letsencrypt
  if [[ ! -f "$WEBROOT/index.html" ]]; then
cat > "$WEBROOT/index.html" <<'HTML'
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HlebCraft — ремесленная пекарня</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🍞</text></svg>">
<style>
  :root{--bg:#fbf5ea;--ink:#3b2a1a;--accent:#b5651d;--card:#fff}
  *{box-sizing:border-box}
  body{margin:0;font-family:Georgia,'Times New Roman',serif;background:var(--bg);color:var(--ink);line-height:1.6}
  header{padding:72px 24px 48px;text-align:center}
  h1{font-size:clamp(2.2rem,6vw,3.6rem);margin:0 0 8px;letter-spacing:.02em}
  header p{margin:0;font-size:1.15rem;opacity:.8}
  main{max-width:960px;margin:0 auto;padding:0 24px 64px;display:grid;gap:20px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
  .card{background:var(--card);border-radius:14px;padding:24px;box-shadow:0 2px 10px rgba(59,42,26,.08)}
  .card h2{margin-top:0;color:var(--accent);font-size:1.3rem}
  footer{text-align:center;padding:32px;font-size:.9rem;opacity:.6}
</style>
</head>
<body>
<header>
  <h1>🍞 HlebCraft</h1>
  <p>Хлеб на закваске. Каждый день. Руками.</p>
</header>
<main>
  <section class="card"><h2>Ржаной на закваске</h2><p>Плотный мякиш, хрустящая корка, 24 часа ферментации.</p></section>
  <section class="card"><h2>Пшеничный бездрожжевой</h2><p>Лёгкий, ароматный, с лёгкой кислинкой и открытым мякишем.</p></section>
  <section class="card"><h2>Булочки и выпечка</h2><p>Сезонные начинки, сливочное масло и настоящая ваниль.</p></section>
</main>
<footer>© HlebCraft. Работаем ежедневно с 7:00 до 20:00.</footer>
</body>
</html>
HTML
  fi

  rm -f /etc/nginx/sites-enabled/default
  cat > /etc/nginx/conf.d/00-http.conf <<EOF
server {
    listen 80 default_server;
    server_name $DOMAIN;
    access_log off;
    server_tokens off;
    location /.well-known/acme-challenge/ { root /var/www/letsencrypt; }
    location / { return 301 https://$DOMAIN\$request_uri; }
}
EOF
  rm -f /etc/nginx/conf.d/hlebcraft.conf
  nginx -t
  systemctl enable nginx >/dev/null 2>&1
  systemctl restart nginx

  if [[ ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
    local CB_MAIL
    if [[ -n "$EMAIL" ]]; then CB_MAIL=(-m "$EMAIL"); else CB_MAIL=(--register-unsafely-without-email); fi
    certbot certonly --webroot -w /var/www/letsencrypt -d "$DOMAIN" \
      --non-interactive --agree-tos "${CB_MAIL[@]}"
  fi
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  printf '#!/bin/sh\nsystemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
}

# внутренний TLS-сервер за Reality (только входной сервер: у релеев сайта нет)
write_nginx_tls(){
  local with_vless="${1:-0}" ngx_ver listen
  ngx_ver=$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9][0-9.]*\).*|\1|p')
  # nginx >= 1.25.1: "listen ... http2" устарел, нужна директива "http2 on;"
  if [[ -n "$ngx_ver" && "$(printf '%s\n%s\n' 1.25.1 "$ngx_ver" | sort -V | head -n1)" == "1.25.1" ]]; then
    listen=$'listen 127.0.0.1:8443 ssl default_server;\n    http2 on;'
  else
    listen='listen 127.0.0.1:8443 ssl http2 default_server;'
  fi
  {
    cat <<EOF
server {
    $listen
    server_name $DOMAIN;
    access_log off;
    server_tokens off;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options nosniff always;

    root $WEBROOT;
    index index.html;

    location / { try_files \$uri \$uri/ =404; }
EOF
    if [[ "$with_vless" == 1 ]]; then
      cat <<EOF

    # VLESS + XHTTP
    location /$P_XHTTP {
        client_max_body_size 0;
        client_body_timeout 1h;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header Host \$host;
        grpc_pass grpc://127.0.0.1:10001;
    }

    # VLESS + gRPC
    location /$P_GRPC {
        client_max_body_size 0;
        client_body_timeout 1h;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header Host \$host;
        grpc_pass grpc://127.0.0.1:10002;
    }

    # VLESS + WebSocket
    location /$P_WS {
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
    }

    # VLESS + HTTPUpgrade
    location /$P_HU {
        proxy_pass http://127.0.0.1:10004;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
    }
EOF
    fi
    echo "}"
  } > /etc/nginx/conf.d/hlebcraft.conf
  nginx -t
  systemctl reload nginx
}

# ================================================================ WARP (режим warp)
setup_warp(){
  log "Регистрация Cloudflare WARP"
  local WA i TPID TRACE WGCF_URL
  case "$(dpkg --print-architecture)" in
    amd64) WA=amd64 ;;
    arm64) WA=arm64 ;;
    armhf) WA=armv7 ;;
    *) die "Неподдерживаемая архитектура" ;;
  esac
  if ! command -v wgcf >/dev/null; then
    WGCF_URL=$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest \
                | grep -oE "https://[^\"]+_linux_${WA}" | head -1 || true)
    [[ -n "$WGCF_URL" ]] || WGCF_URL="https://github.com/ViRb3/wgcf/releases/download/v2.2.22/wgcf_2.2.22_linux_${WA}"
    curl -fsSL -o /usr/local/bin/wgcf "$WGCF_URL"
    chmod +x /usr/local/bin/wgcf
  fi
  mkdir -p "$WARPDIR"
  cd "$WARPDIR"
  if [[ ! -f wgcf-account.toml ]]; then
    for i in 1 2 3 4 5 6; do
      wgcf register --accept-tos && break
      echo "Повтор регистрации WARP ($i/6)…"; sleep 8
    done
  fi
  [[ -f wgcf-account.toml ]] || die "Не удалось зарегистрировать WARP (Cloudflare мог ограничить запросы — повторите через несколько минут)"
  wgcf generate
  [[ -f wgcf-profile.conf ]] || die "Не создан профиль WARP"

  WG_PRIV=$(awk -F' *= *' '/^PrivateKey/{print $2}' wgcf-profile.conf | tr -d ' \r')
  WG_PUB=$(awk -F' *= *' '/^PublicKey/{print $2}' wgcf-profile.conf | tr -d ' \r')
  ADDR_JSON=$(grep -E '^Address' wgcf-profile.conf | sed 's/^Address *= *//' | tr ',' '\n' \
              | tr -d ' \r' | sed '/^$/d' | sed 's/.*/"&"/' | paste -sd, -)
  [[ -n "$WG_PRIV" && -n "$WG_PUB" && -n "$ADDR_JSON" ]] || die "Не удалось разобрать профиль WARP"
  cd /

  WARP_OUT=$(cat <<EOF
{
  "tag": "warp",
  "protocol": "wireguard",
  "settings": {
    "secretKey": "$WG_PRIV",
    "address": [$ADDR_JSON],
    "peers": [{
      "publicKey": "$WG_PUB",
      "allowedIPs": ["0.0.0.0/0", "::/0"],
      "endpoint": "162.159.192.1:2408"
    }],
    "mtu": 1280
  }
}
EOF
)

  log "Проверка выхода через WARP"
  cat > /tmp/xray-warp-test.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": false}}],
  "outbounds": [$WARP_OUT]
}
EOF
  xray run -config /tmp/xray-warp-test.json >/tmp/xray-warp-test.log 2>&1 &
  TPID=$!
  sleep 3
  TRACE=""
  for i in 1 2 3; do
    TRACE=$(curl -fsS --max-time 20 --socks5-hostname 127.0.0.1:10808 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
    grep -qE '^warp=(on|plus)' <<<"$TRACE" && break
    sleep 3
  done
  kill "$TPID" 2>/dev/null || true
  wait "$TPID" 2>/dev/null || true
  rm -f /tmp/xray-warp-test.json
  if ! grep -qE '^warp=(on|plus)' <<<"$TRACE"; then
    echo "--- лог Xray ---"; tail -n 20 /tmp/xray-warp-test.log || true
    die "Трафик не проходит через WARP. Возможно, хостер блокирует UDP/2408. Проверьте и запустите скрипт снова."
  fi
  echo "WARP работает. Внешний IP для сайтов: $(awk -F= '/^ip=/{print $2}' <<<"$TRACE")"
  rm -f /tmp/xray-warp-test.log
}

# ================================================================ конфиги Xray
# входные точки для клиентов (общие для warp и chain) — VLESS + сайт на домене входа
emit_client_inbounds(){
  cat <<EOF
    {
      "tag": "reality",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "$UUID", "flow": "xtls-rprx-vision", "email": "reality"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "127.0.0.1:8443",
          "xver": 0,
          "serverNames": ["$DOMAIN"],
          "privateKey": "$R_PRIV",
          "shortIds": ["$SID"]
        }
      },
      $SNIFF
    },
    {
      "tag": "xhttp",
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID", "email": "xhttp"}], "decryption": "none"},
      "streamSettings": {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": {"path": "/$P_XHTTP", "mode": "auto"}
      },
      $SNIFF
    },
    {
      "tag": "grpc",
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID", "email": "grpc"}], "decryption": "none"},
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {"serviceName": "$P_GRPC"}
      },
      $SNIFF
    },
    {
      "tag": "ws",
      "listen": "127.0.0.1",
      "port": 10003,
      "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID", "email": "ws"}], "decryption": "none"},
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {"path": "/$P_WS"}
      },
      $SNIFF
    },
    {
      "tag": "httpupgrade",
      "listen": "127.0.0.1",
      "port": 10004,
      "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID", "email": "httpupgrade"}], "decryption": "none"},
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "httpupgradeSettings": {"path": "/$P_HU"}
      },
      $SNIFF
    }
EOF
}

write_xray_warp(){
  log "Конфигурация Xray"
  cat > "$XCONF" <<EOF
{
  "log": {"loglevel": "warning", "access": "none"},
  "dns": {
    "servers": ["https+local://1.1.1.1/dns-query", "https+local://1.0.0.1/dns-query"],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
$(emit_client_inbounds)
  ],
  "outbounds": [
    $WARP_OUT,
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
      {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
      {"type": "field", "network": "tcp,udp", "outboundTag": "warp"}
    ]
  }
}
EOF
}

# Исходящее подключение к выходным релеям (через локальный HAProxy).
# Между серверами — НЕ VLESS, а лёгкий SOCKS5 внутри WireGuard-туннеля:
# HAProxy пробрасывает TCP на релей 10.200.0.x:1080, шифрует всё сам WireGuard.
chain_outbound_json(){
  cat <<EOF
{
  "tag": "chain",
  "protocol": "socks",
  "settings": {
    "servers": [{"address": "127.0.0.1", "port": $HA_PORT}]
  }
}
EOF
}

# Домены клиентов на входе не резолвятся (AsIs): разрешает имена уже выходной релей.
write_xray_chain(){
  log "Конфигурация Xray (цепочка)"
  cat > "$XCONF" <<EOF
{
  "log": {"loglevel": "warning", "access": "none"},
  "inbounds": [
$(emit_client_inbounds)
  ],
  "outbounds": [
    $(chain_outbound_json),
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
      {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
      {"type": "field", "network": "tcp,udp", "outboundTag": "chain"}
    ]
  }
}
EOF
}

# Выходной релей: ни сайта, ни домена, ни VLESS наружу.
# Единственный вход — SOCKS5 на адресе туннеля (доступен только входному серверу).
write_xray_exit(){
  log "Конфигурация Xray (выходной релей, SOCKS5 внутри туннеля)"
  cat > "$XCONF" <<EOF
{
  "log": {"loglevel": "warning", "access": "none"},
  "dns": {
    "servers": ["https+local://1.1.1.1/dns-query", "https+local://1.0.0.1/dns-query", "localhost"],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
    {
      "tag": "chain-in",
      "listen": "$WG_RELAY_IP",
      "port": $EXIT_SOCKS_PORT,
      "protocol": "socks",
      "settings": {"auth": "noauth", "udp": true},
      $SNIFF
    }
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
      {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
      {"type": "field", "network": "tcp,udp", "outboundTag": "direct"}
    ]
  }
}
EOF
}

finish_xray(){
  local XUSER CHECK_PORT="${1:-443}"
  XUSER=$(systemctl show -p User --value xray 2>/dev/null || true)
  XUSER=${XUSER:-nobody}
  chown "root:$(id -gn "$XUSER" 2>/dev/null || echo nogroup)" "$XCONF"
  chmod 640 "$XCONF"

  xray run -test -config "$XCONF" >/dev/null || die "Конфиг Xray не прошёл проверку"
  systemctl enable xray >/dev/null 2>&1
  systemctl restart xray
  sleep 2
  systemctl is-active --quiet xray || { journalctl -u xray -n 30 --no-pager; die "Xray не запустился"; }
  ss -tln | grep -q ":$CHECK_PORT " || die "Порт $CHECK_PORT не слушается"
}

# ================================================================ WireGuard-туннель вход <-> релеи
# Входной сервер: wg0 = 10.200.0.1, пиры — релеи (публичные ключи получены по SSH).
setup_wg_entry(){
  log "WireGuard-туннель до выходных релеев ($WG_IF, порт $WG_PORT/udp)"
  modprobe wireguard 2>/dev/null || true
  mkdir -p "$WG_DIR"; chmod 700 "$WG_DIR"
  local i
  {
    echo "[Interface]"
    echo "Address = $WG_ENTRY_IP/24"
    echo "ListenPort = $WG_PORT"
    echo "PrivateKey = $WG_PRIV"
    for i in "${!EX_HOST[@]}"; do
      echo ""
      echo "[Peer]  # exit$((i+1)) ${EX_HOST[$i]}"
      echo "PublicKey = ${EX_PUB[$i]}"
      echo "AllowedIPs = ${EX_WGIP[$i]}/32"
    done
  } > "$WG_DIR/$WG_IF.conf"
  chmod 600 "$WG_DIR/$WG_IF.conf"
  systemctl enable "wg-quick@$WG_IF" >/dev/null 2>&1
  systemctl restart "wg-quick@$WG_IF"
  sleep 2

  # ждём рукопожатия: пингуем каждый релей через туннель
  for i in "${!EX_HOST[@]}"; do
    local ok=0 t
    for t in 1 2 3 4 5 6 7 8; do
      if ping -4 -c1 -W2 "${EX_WGIP[$i]}" >/dev/null 2>&1; then ok=1; break; fi
      sleep 3
    done
    (( ok == 1 )) || die "Туннель до релея ${EX_HOST[$i]} (${EX_WGIP[$i]}) не поднялся. Проверьте, что хостер пропускает UDP/$WG_PORT."
    echo "Туннель до ${EX_HOST[$i]} (${EX_WGIP[$i]}) — ок"
  done
}

# Выходной релей: свой ключ, пир — входной сервер (endpoint = его публичный IP).
setup_wg_exit(){
  log "WireGuard-туннель до входного сервера ($WG_IF, порт $WG_PORT/udp)"
  modprobe wireguard 2>/dev/null || true
  mkdir -p "$WG_DIR"; chmod 700 "$WG_DIR"
  local priv
  if [[ -f "$WG_DIR/relay.key" ]]; then
    priv=$(cat "$WG_DIR/relay.key")
  else
    priv=$(wg genkey)
    printf '%s\n' "$priv" > "$WG_DIR/relay.key"
  fi
  chmod 600 "$WG_DIR/relay.key"
  wg pubkey <<<"$priv" > "$WG_DIR/relay.pub"   # входной сервер заберёт её по SSH
  cat > "$WG_DIR/$WG_IF.conf" <<EOF
[Interface]
Address = $WG_RELAY_IP/32
PrivateKey = $priv

[Peer]
# входной сервер
PublicKey = $WG_ENTRY_PUB
AllowedIPs = $WG_ENTRY_IP/32
Endpoint = $ENTRY_IP:$WG_PORT
PersistentKeepalive = 25
EOF
  chmod 600 "$WG_DIR/$WG_IF.conf"
  systemctl enable "wg-quick@$WG_IF" >/dev/null 2>&1
  systemctl restart "wg-quick@$WG_IF"
}

# ================================================================ система
setup_bbr(){
  cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null 2>&1 || true
}

# $1 — роль: warp | chain | exit
setup_ufw(){
  if [[ -n "$NO_UFW" ]]; then return 0; fi
  local role="${1:-warp}" ports p i
  # порты sshd: из конфига и из реально слушающих сокетов (Ubuntu 22.10+ — socket activation)
  ports=$({ sshd -T 2>/dev/null | awk '/^port /{print $2}'
            ss -tlnpH 2>/dev/null | awk '/"sshd"/{n=split($4,a,":"); print a[n]}'; } | sort -un || true)
  ports=${ports:-22}
  case "$role" in
    warp)  log "Фаервол (ufw): открыты SSH, 80, 443" ;;
    chain) log "Фаервол (ufw): открыты SSH, 80, 443; WireGuard $WG_PORT/udp — только для релеев" ;;
    exit)  log "Фаервол (ufw): открыт SSH; WireGuard $WG_PORT/udp — только для $ENTRY_IP; остальное закрыто" ;;
  esac
  for p in $ports; do ufw allow "$p"/tcp >/dev/null; done
  case "$role" in
    warp|chain)
      ufw allow 80/tcp >/dev/null
      ufw allow 443/tcp >/dev/null
      if [[ "$role" == chain ]]; then
        for i in "${EX_IP[@]}"; do
          ufw allow from "$i" to any port "$WG_PORT" proto udp >/dev/null
        done
      fi ;;
    exit)
      # ни 80, ни 443 на релее не нужны: сайта нет, SOCKS5 слушает только туннель
      ufw allow from "$ENTRY_IP" to any port "$WG_PORT" proto udp >/dev/null
      # служебный трафик внутри туннеля (SOCKS5 + агент нагрузки) — только с адресов туннеля
      ufw allow from "$WG_NET.0/24" >/dev/null ;;
  esac
  ufw --force enable >/dev/null
}

# ================================================================ сетевые проверки
tcp_ok(){ timeout 5 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$1" "$2" 2>/dev/null; }
agent_read(){
  timeout 7 bash -c 'exec 3<>"/dev/tcp/$1/$2"; IFS= read -r -t 5 l <&3; printf "%s" "$l"' _ "$1" "$2" 2>/dev/null || true
}

# ================================================================ выходной релей: агент нагрузки
setup_agent(){
  log "Агент нагрузки (порт $AGENT_PORT, доступен только внутри туннеля)"
  [[ "$NET_CAP_MBIT" =~ ^[0-9]+$ ]] || NET_CAP_MBIT=1000

  cat > /usr/local/sbin/vpn-load-agent <<'AGENT'
#!/usr/bin/env bash
# Агент нагрузки для HAProxy (agent-check).
# Печатает вес сервера в процентах: 100% — свободен, 1% — загружен полностью.
# Загрузка = максимум из: CPU, load average на ядро, сеть (к полосе канала), RAM (если >85%).
set -u
CONF=/etc/vpn-load-agent.conf
NET_CAP_MBIT=1000
if [[ -r "$CONF" ]]; then . "$CONF"; fi

IFACE=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')

snap(){   # "total idle rx tx uptime"
  local _ u n s i w q sq st rx tx up
  read -r _ u n s i w q sq st _ < /proc/stat
  read -r rx tx < <(sed 's/:/ /' /proc/net/dev | awk -v f="$IFACE" '$1==f{print $2,$10}')
  read -r up _ < /proc/uptime
  echo "$((u+n+s+i+w+q+sq+st)) $((i+w)) ${rx:-0} ${tx:-0} $up"
}

read -r t1 i1 rx1 tx1 up1 < <(snap)
sleep 0.5
read -r t2 i2 rx2 tx2 up2 < <(snap)
cores=$(nproc 2>/dev/null || echo 1)
read -r load1 _ < /proc/loadavg
read -r memt mema < <(awk '/^MemTotal/{t=$2} /^MemAvailable/{a=$2} END{print t+0, a+0}' /proc/meminfo)

awk -v t1="$t1" -v i1="$i1" -v t2="$t2" -v i2="$i2" \
    -v rx1="$rx1" -v tx1="$tx1" -v rx2="$rx2" -v tx2="$tx2" \
    -v u1="$up1" -v u2="$up2" -v cores="$cores" -v load="$load1" \
    -v cap="$NET_CAP_MBIT" -v memt="$memt" -v mema="$mema" 'BEGIN{
  dt = t2 - t1
  cpu = (dt > 0) ? (dt - (i2 - i1)) * 100 / dt : 0
  ld  = (cores > 0) ? load / cores * 100 : 0
  el  = u2 - u1; if (el <= 0) el = 0.5
  r = (rx2 - rx1) * 8 / el / 1e6
  t = (tx2 - tx1) * 8 / el / 1e6
  m = (r > t) ? r : t
  net = (cap > 0) ? m * 100 / cap : 0
  mem = (memt > 0 && mema > 0) ? (memt - mema) * 100 / memt : 0
  if (mem < 85) mem = 0
  s = cpu
  if (ld  > s) s = ld
  if (net > s) s = net
  if (mem > s) s = mem
  if (s > 100) s = 100
  if (s < 0)   s = 0
  w = 100 - s
  if (w < 1) w = 1
  printf "%d%%\n", w
}'
AGENT
  chmod 755 /usr/local/sbin/vpn-load-agent
  printf 'NET_CAP_MBIT=%s\n' "$NET_CAP_MBIT" > /etc/vpn-load-agent.conf

  cat > /etc/systemd/system/vpn-load-agent.socket <<EOF
[Unit]
Description=VPN load agent (socket)

[Socket]
ListenStream=$AGENT_PORT
Accept=yes
MaxConnections=16

[Install]
WantedBy=sockets.target
EOF
  cat > /etc/systemd/system/vpn-load-agent@.service <<'EOF'
[Unit]
Description=VPN load agent

[Service]
ExecStart=/usr/local/sbin/vpn-load-agent
StandardInput=socket
StandardOutput=socket
StandardError=journal
User=nobody
RuntimeMaxSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
EOF
  systemctl daemon-reload
  systemctl enable vpn-load-agent.socket >/dev/null 2>&1
  systemctl restart vpn-load-agent.socket

  local r
  r=$(agent_read 127.0.0.1 "$AGENT_PORT")
  [[ "$r" =~ ^[0-9]+%$ ]] || die "Агент нагрузки не отвечает на порту $AGENT_PORT"
  echo "Агент нагрузки работает, текущий вес: $r"
}

# ================================================================ входной сервер: цепочка
collect_exits(){
  local raw="$EXITS" prev n a hint s user port host ip j
  if [[ -z "$raw" ]]; then
    prev=$(saved SAVED_EXITS)
    if is_tty; then
      echo
      echo "Выходные релеи: от 1 до 3 серверов (чистый Debian/Ubuntu, доступ по SSH)."
      echo "Указывайте релеи по IP: домены им не нужны — сайты на них не создаются,"
      echo "трафик между серверами идёт по WireGuard-туннелю (маскировка не требуется)."
      echo "Формат: ip  |  ip:ssh-порт  |  пользователь@ip[:порт]   (по умолчанию root, порт 22)"
      if [[ -n "$prev" ]]; then echo "Сохранено с прошлого раза: $prev   (Enter на первом вопросе — оставить)"; fi
      for n in 1 2 3; do
        hint=""
        if (( n > 1 )); then hint=" (Enter — закончить)"; fi
        read -r -p "Релей №$n$hint: " a || true
        if [[ -z "$a" ]]; then break; fi
        raw+="$a "
      done
      if [[ -z "$raw" ]]; then raw="$prev"; fi
    else
      raw="$prev"
    fi
  fi

  raw="${raw//,/ }"
  local -a specs=()
  read -r -a specs <<<"$raw" || true
  (( ${#specs[@]} >= 1 )) || die "Не указаны выходные релеи (пример: EXITS=\"203.0.113.10 203.0.113.11\")"
  (( ${#specs[@]} <= 3 )) || die "Выходных релеев может быть от 1 до 3 (указано ${#specs[@]})"

  EX_USER=(); EX_HOST=(); EX_PORT=(); EX_IP=(); EX_PUB=(); EX_WGIP=()
  for s in "${specs[@]}"; do
    user=root; port=22
    if [[ "$s" == *@* ]]; then user="${s%%@*}"; s="${s#*@}"; fi
    if [[ "$s" == *:* ]]; then port="${s##*:}"; s="${s%%:*}"; fi
    host="${s,,}"
    # релей — по IP; домен тоже примем (просто резолвим в IP), но сайт ему не нужен
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      ip="$host"
    else
      valid_domain "$host" || die "Некорректный адрес релея: «$host». Укажите IP релея (домены не нужны — сайтов на релеях нет)."
      ip=$(getent ahostsv4 "$host" | awk 'NR==1{print $1}' || true)
      [[ -n "$ip" ]] || die "У $host нет A-записи. Проще указать IP релея — домен ему не нужен."
    fi
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || die "Некорректный SSH-порт у $host: $port"
    [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "Некорректное имя пользователя у $host: $user"
    [[ "$host" != "$DOMAIN" ]] || die "Выходной релей не может совпадать с входным сервером ($DOMAIN)"
    for j in "${EX_HOST[@]}"; do
      [[ "$j" != "$host" ]] || die "Релей $host указан дважды"
    done
    EX_USER+=("$user"); EX_HOST+=("$host"); EX_PORT+=("$port"); EX_IP+=("$ip")
    EX_WGIP+=("$WG_NET.$((10 + ${#EX_WGIP[@]} + 1))")   # 10.200.0.11, .12, .13
  done
  # нормализованная запись для сохранения: [user@]адрес[:порт]
  EXITS=""
  for j in "${!EX_HOST[@]}"; do
    s="${EX_HOST[$j]}"
    if [[ "${EX_USER[$j]}" != root ]]; then s="${EX_USER[$j]}@$s"; fi
    if [[ "${EX_PORT[$j]}" != 22 ]]; then s="$s:${EX_PORT[$j]}"; fi
    EXITS+="$s "
  done
  EXITS="${EXITS% }"
}

init_ssh(){
  mkdir -p /root/.ssh; chmod 700 /root/.ssh
  if [[ ! -f "$CHAIN_KEY" ]]; then
    ssh-keygen -q -t ed25519 -N '' -C "vpn-chain@$(hostname)" -f "$CHAIN_KEY"
  fi
}
xssh(){
  local i="$1"; shift
  ssh -i "$CHAIN_KEY" -o IdentitiesOnly=yes "${SSH_O[@]}" -o BatchMode=yes \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=10 \
      -p "${EX_PORT[$i]}" "${EX_USER[$i]}@${EX_HOST[$i]}" "$@"
}
xscp(){
  local i="$1" src="$2" dst="$3"
  scp -q -i "$CHAIN_KEY" -o IdentitiesOnly=yes "${SSH_O[@]}" -o BatchMode=yes \
      -P "${EX_PORT[$i]}" "$src" "${EX_USER[$i]}@${EX_HOST[$i]}:$dst"
}

ensure_ssh_access(){
  local i="$1" h ok=0
  h="${EX_HOST[$i]}"
  if ! xssh "$i" true 2>/dev/null; then
    log "Нужен SSH-доступ к $h: копирую ключ (потребуется пароль ${EX_USER[$i]}@$h)"
    if [[ -n "$EXIT_SSH_PASS" ]]; then
      SSHPASS="$EXIT_SSH_PASS" sshpass -e ssh-copy-id -i "$CHAIN_KEY.pub" -p "${EX_PORT[$i]}" \
        "${SSH_O[@]}" "${EX_USER[$i]}@$h" && ok=1
    elif is_tty; then
      ssh-copy-id -i "$CHAIN_KEY.pub" -p "${EX_PORT[$i]}" "${SSH_O[@]}" "${EX_USER[$i]}@$h" && ok=1
    else
      die "Нет SSH-доступа к $h. Добавьте на релей этот публичный ключ (authorized_keys) и запустите снова:
$(cat "$CHAIN_KEY.pub")
Либо передайте пароль: EXIT_SSH_PASS=... (нужен sshpass)."
    fi
    if (( ok == 0 )) || ! xssh "$i" true 2>/dev/null; then
      die "Не удалось получить SSH-доступ к $h. Если сервер переустанавливали, удалите старый отпечаток:
ssh-keygen -f $CHAIN_KNOWN -R $h"
    fi
  fi
  if [[ "${EX_USER[$i]}" != root ]]; then
    xssh "$i" "sudo -n true" 2>/dev/null || die "У ${EX_USER[$i]}@$h нет sudo без пароля — используйте root или настройте NOPASSWD."
  fi
  echo "SSH-доступ к $h есть"
}

# параметры, которые входной сервер передаёт релею (файл с правами 600, не командная строка)
make_params(){
  local v
  for v in NO_UFW AGENT_PORT NET_CAP_MBIT WG_PORT WG_PUB WG_RELAY_IP ENTRY_IP; do
    printf '%s=%q\n' "$v" "${!v}"
  done
}

deploy_exit(){
  local i="$1" h tmp pre="" rc=0 pub
  h="${EX_HOST[$i]}"
  if [[ "${EX_USER[$i]}" != root ]]; then pre="sudo -n"; fi
  # публичный ключ входного сервера и адрес релея в туннеле — в параметры релея
  WG_RELAY_IP="${EX_WGIP[$i]}"
  log "Установка выходного релея $h (${EX_IP[$i]}) — это займёт пару минут"
  tmp=$(mktemp); chmod 600 "$tmp"
  make_params > "$tmp"
  xscp "$i" "$SELF" ".vpn-install.sh"
  xscp "$i" "$tmp" ".vpn-exit-params.env"
  rm -f "$tmp"
  xssh "$i" "chmod 600 .vpn-exit-params.env"
  xssh "$i" "$pre env MODE=exit PARAMS_FILE=\"\$HOME/.vpn-exit-params.env\" bash \"\$HOME/.vpn-install.sh\"" 2>&1 \
    | sed -u "s/^/[$h] /" || rc=$?
  # забираем публичный WireGuard-ключ релея (нужен для пира на входном сервере)
  pub=$(xssh "$i" 'cat /etc/wireguard/relay.pub' 2>/dev/null || true)
  xssh "$i" 'rm -f "$HOME/.vpn-exit-params.env" "$HOME/.vpn-install.sh"' || true
  (( rc == 0 )) || die "Не удалось настроить выходной релей $h (причина — в выводе выше). Исправьте её и запустите скрипт снова: он идемпотентен."
  [[ "$pub" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "Не удалось получить WireGuard-ключ релея $h"
  EX_PUB[$i]="$pub"
}

verify_exits(){
  local i ip ok r t
  log "Проверка выходных релеев (внутри туннеля)"
  for i in "${!EX_HOST[@]}"; do
    ip="${EX_WGIP[$i]}"; ok=0
    for t in 1 2 3 4 5; do
      if tcp_ok "$ip" "$EXIT_SOCKS_PORT"; then ok=1; break; fi
      sleep 3
    done
    (( ok == 1 )) || die "${EX_HOST[$i]}: SOCKS5 ($ip:$EXIT_SOCKS_PORT) недоступен из туннеля"
    r=$(agent_read "$ip" "$AGENT_PORT")
    [[ "$r" =~ ^[0-9]+%$ ]] || die "${EX_HOST[$i]}: агент нагрузки ($ip:$AGENT_PORT) не отвечает из туннеля. Проверьте, что на релее разрешён трафик из $WG_NET.0/24 и что хостер не режет UDP/$WG_PORT."
    echo "${EX_HOST[$i]}  (${EX_IP[$i]}, туннель $ip):  SOCKS5 — ок,  свободно ресурсов: $r"
  done
}

write_haproxy(){
  log "HAProxy: выбор релея по нагрузке (бэкенды — адреса внутри туннеля)"
  if [[ -f "$HA_CFG" ]] && ! grep -q '^# vpn-installer' "$HA_CFG" && [[ ! -f "$HA_CFG.orig" ]]; then
    cp "$HA_CFG" "$HA_CFG.orig"
  fi
  local i
  {
    cat <<EOF
# vpn-installer: файл создан install.sh, ручные правки будут перезаписаны
global
    maxconn 20000
    user haproxy
    group haproxy
    stats socket $HA_SOCK mode 660 level admin

defaults
    mode tcp
    option dontlognull
    option redispatch
    retries 2
    timeout connect 5s
    timeout client 2h
    timeout server 2h
    timeout tunnel 2h
    timeout check 3s

# Новые соединения идут на релей с наименьшим числом соединений относительно
# его веса; вес каждые 5 с обновляет агент релея (свободные CPU/сеть/RAM).
# Бэкенды — адреса релеев внутри WireGuard-туннеля (SOCKS5, порт $EXIT_SOCKS_PORT).
listen vpn_exits
    bind 127.0.0.1:$HA_PORT
    balance leastconn
    default-server inter 10s fastinter 3s downinter 5s rise 2 fall 3
EOF
    for i in "${!EX_HOST[@]}"; do
      echo "    server exit$((i+1)) ${EX_WGIP[$i]}:$EXIT_SOCKS_PORT check agent-check agent-port $AGENT_PORT agent-inter 5s weight 100"
    done
  } > "$HA_CFG"
  : > "$EXITS_MAP"
  for i in "${!EX_HOST[@]}"; do echo "exit$((i+1)),${EX_HOST[$i]}" >> "$EXITS_MAP"; done

  haproxy -c -f "$HA_CFG" >/dev/null || { haproxy -c -f "$HA_CFG" || true; die "Конфиг HAProxy не прошёл проверку"; }
  systemctl enable haproxy >/dev/null 2>&1
  systemctl restart haproxy
  sleep 2
  systemctl is-active --quiet haproxy || { journalctl -u haproxy -n 30 --no-pager; die "HAProxy не запустился"; }

  cat > /usr/local/bin/vpn-status <<'EOF'
#!/usr/bin/env bash
# Состояние выходных релеев: статус, вес (по нагрузке), текущие и всего соединений.
SOCK=/run/haproxy-vpn.sock
MAP=/etc/vpn-exits.map
[[ -S "$SOCK" ]] || { echo "HAProxy не запущен"; exit 1; }
printf '%-7s %-30s %-14s %-7s %-7s %s\n' RELAY ADDRESS STATUS WEIGHT CONNS TOTAL
echo "show stat" | socat stdio "unix-connect:$SOCK" \
  | awk -F, 'NR==FNR{d[$1]=$2; next}
             $1=="vpn_exits" && $2!="FRONTEND" && $2!="BACKEND" {
               printf "%-7s %-30s %-14s %-7s %-7s %s\n", $2, d[$2], $18, $19, $5, $8 }' "$MAP" -
EOF
  chmod 755 /usr/local/bin/vpn-status
}

test_chain(){
  log "Проверка цепочки вход → туннель → релей → интернет"
  local tpid ip="" i
  cat > /tmp/xray-chain-test.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": false}}],
  "outbounds": [$(chain_outbound_json)]
}
EOF
  xray run -config /tmp/xray-chain-test.json >/tmp/xray-chain-test.log 2>&1 &
  tpid=$!
  sleep 3
  for i in 1 2 3 4; do
    ip=$(curl -4fsS --max-time 20 --socks5-hostname 127.0.0.1:10808 https://api.ipify.org 2>/dev/null || true)
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then break; fi
    ip=""; sleep 3
  done
  kill "$tpid" 2>/dev/null || true
  wait "$tpid" 2>/dev/null || true
  rm -f /tmp/xray-chain-test.json
  if [[ -z "$ip" ]]; then
    echo "--- лог Xray ---"; tail -n 20 /tmp/xray-chain-test.log || true
    echo "--- HAProxy ---"; /usr/local/bin/vpn-status || true
    die "Трафик не проходит через выходные релеи. Проверьте вывод выше."
  fi
  rm -f /tmp/xray-chain-test.log
  local j found=0
  for j in "${EX_IP[@]}"; do if [[ "$j" == "$ip" ]]; then found=1; fi; done
  if (( found == 1 )); then
    echo "Цепочка работает: выход в интернет через релей с IP $ip"
  else
    echo "Цепочка работает. Внешний IP для сайтов: $ip (отличается от IP релея — у хостера, видимо, отдельный исходящий адрес)"
  fi
}

disable_chain_leftovers(){
  if [[ -f "$HA_CFG" ]] && grep -q '^# vpn-installer' "$HA_CFG"; then
    log "Отключаю HAProxy от прежнего режима chain"
    systemctl disable --now haproxy >/dev/null 2>&1 || true
    rm -f /usr/local/bin/vpn-status "$EXITS_MAP"
  fi
  if [[ -f "$WG_DIR/$WG_IF.conf" ]]; then
    log "Отключаю WireGuard-туннель от прежнего режима chain"
    systemctl disable --now "wg-quick@$WG_IF" >/dev/null 2>&1 || true
    rm -f "$WG_DIR/$WG_IF.conf"
  fi
}

# ================================================================ итог для входного сервера
print_links(){
  local L_REALITY L_XHTTP L_GRPC L_WS L_HU
  L_REALITY="vless://$UUID@$DOMAIN:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$DOMAIN&fp=chrome&pbk=$R_PUB&sid=$SID&type=tcp&headerType=none#hlebcraft-reality"
  L_XHTTP="vless://$UUID@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&alpn=h2&type=xhttp&host=$DOMAIN&path=%2F$P_XHTTP&mode=auto#hlebcraft-xhttp"
  L_GRPC="vless://$UUID@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&alpn=h2&type=grpc&serviceName=$P_GRPC&mode=gun#hlebcraft-grpc"
  L_WS="vless://$UUID@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&alpn=http%2F1.1&type=ws&host=$DOMAIN&path=%2F$P_WS#hlebcraft-ws"
  L_HU="vless://$UUID@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&alpn=http%2F1.1&type=httpupgrade&host=$DOMAIN&path=%2F$P_HU#hlebcraft-httpupgrade"

  umask 077
  cat > /root/vless-links.txt <<EOF
# Основной (рекомендуется): VLESS + Reality + Vision
$L_REALITY

# Запасные (обычный TLS на вашем домене, за nginx)
$L_XHTTP
$L_GRPC
$L_WS
$L_HU
EOF
  umask 022

  printf '\n\033[1;32m================ ГОТОВО ================\033[0m\n'
  echo "Режим:  $MODE"
  echo "Сайт:   https://$DOMAIN"
  if [[ "$MODE" == chain ]]; then
    echo "Выходные релеи (по WireGuard-туннелю $WG_NET.0/24):"
    local i
    for i in "${!EX_HOST[@]}"; do echo "  exit$((i+1))  ${EX_HOST[$i]}  (${EX_IP[$i]}  ->  ${EX_WGIP[$i]})"; done
    echo "Нагрузка и состояние релеев:  vpn-status"
  fi
  echo "Ссылки сохранены: /root/vless-links.txt"
  echo
  cat /root/vless-links.txt
  echo
  echo "QR для основной ссылки (Reality):"
  qrencode -t ansiutf8 "$L_REALITY" || true
  echo
  echo "Свой сайт кладите в $WEBROOT (index.html уже есть как заглушка)."
}

# ================================================================ сценарии
run_warp(){
  ensure_domain "этого сервера"
  log "Режим: WARP (один сервер)"
  disable_chain_leftovers
  install_packages
  check_dns
  install_xray
  load_secrets
  setup_site
  write_nginx_tls 1
  setup_warp
  write_xray_warp
  finish_xray 443
  setup_bbr
  setup_ufw warp
  save_kv SAVED_MODE warp
  print_links
}

run_chain(){
  ensure_domain "ВХОДНОГО сервера"
  collect_exits
  [[ -f "$SELF" && -r "$SELF" ]] || die "Запускайте скрипт из файла (bash install.sh), а не через pipe: он копирует себя на выходные релеи."
  log "Режим: цепочка. Вход: $DOMAIN  →  релеи: ${EX_HOST[*]} (WireGuard-туннель)"
  install_packages
  check_dns
  ENTRY_IP="${ENTRY_IP:-$SERVER_IP}"
  [[ "$ENTRY_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Не удалось определить внешний IP входного сервера — задайте ENTRY_IP=…"
  install_xray
  load_secrets

  init_ssh
  local i
  for i in "${!EX_HOST[@]}"; do ensure_ssh_access "$i"; done
  for i in "${!EX_HOST[@]}"; do deploy_exit "$i"; done
  setup_wg_entry          # туннель до релеев (публичные ключи уже получены по SSH)
  verify_exits

  setup_site              # сайт и домен — ТОЛЬКО на входном сервере
  write_nginx_tls 1
  write_haproxy
  test_chain
  write_xray_chain
  finish_xray 443
  setup_bbr
  setup_ufw chain
  save_kv SAVED_MODE chain
  save_kv SAVED_EXITS "$EXITS"
  print_links
}

run_exit(){
  [[ -n "$PARAMS_FILE" && -f "$PARAMS_FILE" ]] || die "Режим exit запускается только входным сервером (нет PARAMS_FILE)"
  # shellcheck disable=SC1090
  . "$PARAMS_FILE"
  rm -f "$PARAMS_FILE"
  local v
  for v in WG_PUB WG_RELAY_IP ENTRY_IP WG_PORT; do
    [[ -n "${!v:-}" ]] || die "В параметрах выходного релея нет $v"
  done
  [[ "$WG_RELAY_IP" =~ ^10\.200\.0\.[0-9]+$ ]] || die "Некорректный WG_RELAY_IP: $WG_RELAY_IP"
  WG_ENTRY_PUB="$WG_PUB"   # публичный ключ входного сервера (пира)
  umask 077
  for v in WG_ENTRY_PUB WG_RELAY_IP WG_PORT ENTRY_IP AGENT_PORT NET_CAP_MBIT; do
    printf '%s=%q\n' "$v" "${!v}"
  done > "$EXIT_ENVF"
  umask 022

  log "Режим: ВЫХОДНОЙ релей (без сайта и домена), вход: $ENTRY_IP"
  install_packages
  install_xray
  setup_wg_exit
  write_xray_exit
  finish_xray "$EXIT_SOCKS_PORT"
  setup_agent
  setup_bbr
  setup_ufw exit
  printf '\n\033[1;32m=== Выходной релей готов ===\033[0m\n'
}

main(){
  preflight
  if [[ -n "$PARAMS_FILE" ]]; then MODE=exit; fi
  select_mode
  case "$MODE" in
    warp)  run_warp ;;
    chain) run_chain ;;
    exit)  run_exit ;;
  esac
}

# VPN_INSTALL_NO_MAIN=1 — только подгрузить функции (для тестов)
if [[ -z "${VPN_INSTALL_NO_MAIN:-}" ]]; then main "$@"; fi
