#!/usr/bin/env bash
# =====================================================================
#  VLESS-стек за собственным сайтом (Debian / Ubuntu)
#
#  ------------------------------ НАСТРОЙКИ ------------------------------
#
#  SNI для Reality: это поле sni= в основной ссылке и serverNames на сервере.
#    Пусто (рекомендуется) = подставится DOMAIN — тот самый домен, по которому
#    вы подключаетесь к серверу и который уже стоит адресом в профиле клиента.
#    Скорее всего нужен именно он: в режиме "self-steal" Reality берёт за образец
#    собственный nginx, а у него сертификат выдан на DOMAIN, так что снаружи SNI
#    совпадает с настоящим сертификатом сайта.
#    Свой SNI имеет смысл задавать, только если вы точно понимаете зачем: сертификат
#    nginx всё равно выдан на DOMAIN, и при проверке с чужим SNI он не совпадёт.
#    Пример:  SNI="example.com"
SNI="${SNI:-}"
#
#  UDP-порт WireGuard на выходных релеях (режим chain). На релее он открыт
#  только для IP входного сервера.
WG_PORT="${WG_PORT:-51820}"
#
#  Внутренняя сеть туннелей (два первых октета), режим chain. Релей №k:
#  вход = WG_NET.k.1, релей = WG_NET.k.2. Менять нужно, только если 10.77.x.x
#  уже занято у вашего хостера.
WG_NET="${WG_NET:-10.77}"
#
#  MTU туннелей WireGuard (режим chain). 1380 проходит через любые хостинги
#  (часть из них режет или не пропускает фрагменты UDP, и тогда "тяжёлые" сайты
#  зависают наполовину). Поднимайте до 1420 только если уверены в канале.
WG_MTU="${WG_MTU:-1380}"
#
#  ----------------------------------------------------------------------
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
#    клиент -> ВХОД (сайт-заглушка + Xray, всё как в режиме 1)
#                 |  Xray выбирает релей для каждого соединения (случайно среди
#                 |  живых; упавший исключается пробой каждые 15 с)
#                 |-- WireGuard (ядро Linux, ничего поверх) --> РЕЛЕЙ 1 -> интернет
#                 |-- WireGuard                             --> РЕЛЕЙ 2 -> интернет
#                 '-- WireGuard                             --> РЕЛЕЙ 3 -> интернет
#
#    * Домен и сайт нужны ТОЛЬКО входному серверу (клиент заходит на него по VLESS
#      с SNI этого домена, снаружи это выглядит как обычный HTTPS-сайт).
#    * Релеи указываются ТОЛЬКО по IP: домены им не нужны, сайты на них не создаются,
#      сертификаты не выпускаются. Скрипт настраивает их САМ по SSH по этому IP
#      (чистый Debian/Ubuntu с root-доступом).
#    * Канал вход -> релей — это обычный WireGuard в ядре Linux: никаких SOCKS,
#      Shadowsocks, VLESS, TLS, HAProxy и прочих надстроек. Пакеты идут ядро -> ядро
#      (ChaCha20-Poly1305, один UDP-порт), без пользовательского режима, а
#      PersistentKeepalive держит туннель "тёплым", чтобы первый пакет после простоя
#      не ждал рукопожатия. Порт релея открыт ТОЛЬКО для IP входного сервера.
#    * На входе у каждого релея свой интерфейс wgx1..wgx3 со своим адресом; Xray
#      привязывает исходящие соединения к адресу нужного туннеля (sendThrough), а
#      policy routing (ip rule from <адрес>) отправляет их в этот туннель.
#    * Релей = только ядро: wg + NAT (MASQUERADE) + ip_forward. Ни Xray, ни агентов,
#      ни открытых портов, кроме UDP WireGuard для входного сервера.
#      Весь трафик (TCP, UDP, QUIC, звонки, игры) идёт одним и тем же путём.
#    * DNS-имена клиентов резолвит входной сервер, но запросы идут через туннель
#      (сам вход прямого DNS наружу не делает). Запросы идут по TCP (каждый — новым
#      соединением, т.е. с новым выбором живого релея) к нескольким резолверам.
#    * На выходе нет WARP: трафик уходит в интернет напрямую, с IP релея.
#    * Прямого выхода с входного сервера нет (fail-closed).
#
#  Запуск (скрипт должен лежать файлом — он сам копирует себя на выходные релеи):
#
#    # 1) скачать ИМЕННО «сырой» файл (raw), а не страницу сайта, и проверить первую строку:
#    curl -fsSL -o install.sh <ПРЯМАЯ_ССЫЛКА_НА_ФАЙЛ>
#    head -n1 install.sh        # ждём: #!/usr/bin/env bash
#                               # увидели <!DOCTYPE html> — ссылка ведёт на веб-страницу, не на файл
#    # (для GitHub это raw.githubusercontent.com/..., а не github.com/.../blob/...)
#
#    # 2) запустить (домен — только латиницей/цифрами; для кириллических доменов нужен punycode xn--…)
#    bash install.sh                                   # интерактивное меню
#    DOMAIN=entry.example.com bash install.sh          # режим warp
#    DOMAIN=entry.example.com MODE=chain \
#      EXITS="203.0.113.10 203.0.113.11:2222 ubuntu@203.0.113.12" \
#      bash install.sh                                 # режим chain
#
#    Режим warp можно запустить и одной командой через pipe (переменные — перед bash, не перед curl):
#      curl -fsSL <ПРЯМАЯ_ССЫЛКА> | DOMAIN=entry.example.com bash
#    Режим chain и интерактивное меню через pipe не работают — только из файла.
#
#  Переменные (необязательные; SNI, WG_PORT, WG_NET и WG_MTU — см. НАСТРОЙКИ выше):
#    EMAIL=…           e-mail для Let's Encrypt (входной сервер)
#    FORCE=1           не проверять DNS
#    NO_UFW=1          не трогать фаервол
#    EXIT_SSH_PASS=…   пароль SSH выходных релеев (иначе спросит при копировании ключа)
#    ENTRY_IP=…        IP входного сервера, как его видят релеи (по умолчанию — внешний IP)
#
#  Нужно ядро с WireGuard (Linux 5.6+, либо Ubuntu 20.04+ / Debian 11+ на KVM/VDS;
#  в контейнерах OpenVZ/LXC WireGuard обычно недоступен).
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
PARAMS_FILE="${PARAMS_FILE:-}"

XCONF=/usr/local/etc/xray/config.json
ENVF=/root/.vpn-secrets.env          # секреты входного сервера (warp / chain)
EXIT_ENVF=/root/.vpn-exit.env        # параметры выходного релея
EXIT_PUB=/root/.vpn-exit.pub         # публичный ключ WireGuard релея (его забирает вход)
WEBROOT=/var/www/hlebcraft
WARPDIR=/etc/warp
WG_DIR=/etc/wireguard
HA_CFG=/etc/haproxy/haproxy.cfg      # только для уборки HAProxy от прежней версии
EXITS_MAP=/etc/vpn-exits.map
CHAIN_KEY=/root/.ssh/vpn_chain_ed25519
CHAIN_KNOWN=/root/.ssh/known_hosts_vpnchain
SELF="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || true)"

SNIFF='"sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}'
RE_DOMAIN='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z0-9-]+$'
RE_X25519='^[A-Za-z0-9_-]{43}$'      # ключ x25519 в base64url без "="
SERVER_NAMES=""                      # заполняет resolve_sni

EX_USER=(); EX_HOST=(); EX_PORT=(); EX_IP=(); EX_PUB=()
SSH_O=(-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$CHAIN_KNOWN" -o ConnectTimeout=15)

log(){ printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die(){ printf '\n\033[1;31m[ОШИБКА]\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "Сбой на строке $LINENO"' ERR

is_tty(){ [[ -t 0 ]]; }
valid_domain(){ [[ "$1" =~ $RE_DOMAIN && ! "$1" =~ ^[0-9.]+$ ]]; }

# имя интерфейса, адреса и таблица маршрутизации для релея с индексом $1 (0..2)
wg_if(){ printf 'wgx%d' $(( $1 + 1 )); }
wg_entry_ip(){ printf '%s.%d.1' "$WG_NET" $(( $1 + 1 )); }
wg_exit_ip(){ printf '%s.%d.2' "$WG_NET" $(( $1 + 1 )); }
wg_table(){ printf '%d' $(( 101 + $1 )); }

# значение переменной из env-файла, не засоряя окружение
env_get(){
  local f="$1" k="$2"
  [[ -f "$f" ]] || return 0
  ( set +eu; trap - ERR; . "$f" >/dev/null 2>&1 || true; eval "printf '%s' \"\${$k:-}\"" )
}
saved(){ env_get "$ENVF" "$1"; }
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

# настройки WireGuard (режимы chain и exit)
check_wg_settings(){
  local a b
  if ! [[ "$WG_PORT" =~ ^[0-9]{1,5}$ ]] || (( 10#$WG_PORT < 1 || 10#$WG_PORT > 65535 )); then
    die "Некорректный WG_PORT=\"$WG_PORT\" (нужен порт 1–65535)"
  fi
  if ! [[ "$WG_MTU" =~ ^[0-9]{3,4}$ ]] || (( 10#$WG_MTU < 1280 || 10#$WG_MTU > 1500 )); then
    die "Некорректный WG_MTU=\"$WG_MTU\" (нужно число 1280–1500)"
  fi
  [[ "$WG_NET" =~ ^([0-9]{1,3})\.([0-9]{1,3})$ ]] || die "Некорректный WG_NET=\"$WG_NET\" (ожидается вид 10.77)"
  a=$((10#${BASH_REMATCH[1]})); b=$((10#${BASH_REMATCH[2]}))
  (( a <= 255 && b <= 255 )) || die "Некорректный WG_NET=\"$WG_NET\""
}

# WireGuard должен быть в ядре (в OpenVZ/LXC и на очень старых ядрах его нет)
check_wireguard(){
  command -v wg >/dev/null || die "Не установлен wireguard-tools"
  if ! ip link add vpnwgtest type wireguard 2>/dev/null; then
    modprobe wireguard 2>/dev/null || true
    ip link add vpnwgtest type wireguard 2>/dev/null \
      || die "Ядро этого сервера не поддерживает WireGuard (контейнер OpenVZ/LXC или ядро старше 5.6; на Debian 10 нужен backports). Возьмите KVM/VDS с Debian 11+ / Ubuntu 20.04+."
  fi
  ip link del vpnwgtest 2>/dev/null || true
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
               выходных релея (по IP, без доменов и сайтов); на них скрипт всё
               ставит сам по SSH, между серверами — обычный WireGuard в ядре
               (ничего поверх), релей для каждого соединения выбирает Xray
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
  DOMAIN="${DOMAIN//[[:space:]]/}"; DOMAIN="${DOMAIN,,}"
  valid_domain "$DOMAIN" || die "Укажите корректный DOMAIN (пример: DOMAIN=example.com bash install.sh). IP-адрес не подходит — нужен домен."
}

# SNI для Reality: по умолчанию тот же домен, по которому клиент подключается
resolve_sni(){
  SNI="${SNI//[[:space:]]/}"; SNI="${SNI,,}"
  if [[ -z "$SNI" ]]; then SNI="$DOMAIN"; fi
  valid_domain "$SNI" || die "Некорректный SNI=\"$SNI\" (нужно доменное имя, например example.com; пусто — взять DOMAIN)"
  if [[ "$SNI" == "$DOMAIN" ]]; then
    SERVER_NAMES="\"$DOMAIN\""
  else
    SERVER_NAMES="\"$SNI\", \"$DOMAIN\""
    warn "SNI ($SNI) отличается от DOMAIN ($DOMAIN). Сертификат nginx выдан на DOMAIN, поэтому при проверке сервера с SNI=$SNI он не совпадёт. Убедитесь, что вам это нужно."
  fi
}

# ================================================================ пакеты
install_packages(){
  log "Установка пакетов"
  local pk
  case "$MODE" in
    warp)  pk=(curl ca-certificates openssl nginx certbot ufw iproute2 unzip qrencode) ;;
    chain)
      pk=(curl ca-certificates openssl nginx certbot ufw iproute2 unzip qrencode openssh-client iputils-ping)
      if [[ -n "$EXIT_SSH_PASS" ]]; then pk+=(sshpass); fi ;;
    exit)  # на релее нет ни сайта, ни Xray: только ядро + wg + NAT
      pk=(ca-certificates ufw iproute2 procps) ;;
  esac
  apt-get -o DPkg::Lock::Timeout=300 update -y
  apt-get -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confold install -y "${pk[@]}" >/dev/null
  # WireGuard — без рекомендованных пакетов (resolvconf и прочее серверу не нужны)
  case "$MODE" in
    chain) apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends wireguard-tools >/dev/null ;;
    exit)  apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends wireguard-tools iptables >/dev/null ;;
  esac
}

check_dns(){
  log "Проверка DNS для $DOMAIN"
  local dns_all
  SERVER_IP=$(curl -4fsS --max-time 10 https://api.ipify.org || curl -4fsS --max-time 10 https://ifconfig.me || true)
  # все A-записи домена (а не только первая): при нескольких записях порядок не гарантирован
  dns_all=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u || true)
  DNS_IP=$(tr '\n' ' ' <<<"$dns_all"); DNS_IP="${DNS_IP% }"
  echo "IP сервера: ${SERVER_IP:-?}   A-запись $DOMAIN: ${DNS_IP:-нет}"
  if [[ -z "$FORCE" ]]; then
    [[ -n "$dns_all" ]] \
      || die "У домена $DOMAIN нет A-записи. Создайте её на IP этого сервера (без проксирования Cloudflare), подождите пару минут и запустите снова."
    [[ -n "$SERVER_IP" ]] \
      || die "Не удалось определить внешний IP сервера (api.ipify.org и ifconfig.me недоступны). Проверьте сеть либо запустите с FORCE=1, если уверены в A-записи."
    grep -qxF "$SERVER_IP" <<<"$dns_all" \
      || die "A-запись $DOMAIN ($DNS_IP) должна указывать на $SERVER_IP (без проксирования Cloudflare / оранжевого облака). Исправьте DNS, подождите пару минут и запустите снова."
    if [[ "$dns_all" == *$'\n'* ]]; then
      warn "У $DOMAIN несколько A-записей ($DNS_IP). Let's Encrypt может зайти на любую из них — оставьте только IP этого сервера."
    fi
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
# Публичный ключ x25519 по приватному (в stdout). Понимает и старый вывод xray
# ("Public key: …"), и новый ("Password: …" / "Password (PublicKey): …").
x25519_pub(){
  local out
  out=$(xray x25519 -i "$1" 2>/dev/null) || return 1
  awk -F': *' 'tolower($1) ~ /public|password/ { gsub(/[ \r]/, "", $2); print $2; exit }' <<<"$out"
}

gen_x25519(){   # -> GK_PRIV, GK_PUB
  local keys
  keys=$(xray x25519)
  GK_PRIV=$(awk -F': *' 'tolower($1) ~ /private/ { gsub(/[ \r]/, "", $2); print $2; exit }' <<<"$keys")
  [[ "$GK_PRIV" =~ $RE_X25519 ]] || die "Не удалось получить приватный ключ Reality: $keys"
  # публичный ключ считаем отдельно из приватного, а не выуживаем из вывода генерации
  GK_PUB=$(x25519_pub "$GK_PRIV" || true)
  [[ "$GK_PUB" =~ $RE_X25519 ]] || die "Не удалось вычислить публичный ключ Reality"
}

# Пара ключей Reality должна быть согласованной. Если публичный ключ в ссылке не
# соответствует приватному на сервере, Xray считает клиента "чужим" и отдаёт ему
# обычный сайт: Reality-клиент не подключается, а запасные транспорты (обычный TLS
# через nginx) при этом работают. Поэтому при каждом запуске публичный ключ
# пересчитывается из приватного, а не берётся из сохранённого файла.
check_reality_keys(){
  local pub
  if ! [[ "${R_PRIV:-}" =~ $RE_X25519 ]]; then
    warn "Приватный ключ Reality в $ENVF отсутствует или повреждён — создаю новую пару (прежние ссылки Reality перестанут работать)"
    gen_x25519
    R_PRIV=$GK_PRIV; R_PUB=$GK_PUB
    save_kv R_PRIV "$R_PRIV"
    save_kv R_PUB "$R_PUB"
  else
    pub=$(x25519_pub "$R_PRIV" || true)
    [[ "$pub" =~ $RE_X25519 ]] || die "Не удалось вычислить публичный ключ Reality (xray x25519 -i)"
    if [[ "${R_PUB:-}" != "$pub" ]]; then
      warn "Сохранённый публичный ключ Reality не соответствовал приватному — исправлено. Возьмите ссылки заново (ниже и в /root/vless-links.txt)."
      R_PUB="$pub"
      save_kv R_PUB "$R_PUB"
    fi
  fi
  if ! [[ "${SID:-}" =~ ^([0-9a-f]{2}){1,8}$ ]]; then
    warn "shortId Reality отсутствует или некорректен — создаю новый"
    SID=$(openssl rand -hex 8)
    save_kv SID "$SID"
  fi
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
  check_reality_keys

  # ключи WireGuard входного сервера (один ключ на все туннели к релеям)
  if [[ "$MODE" == chain ]]; then
    # ключи прежнего канала Shadowsocks-2022 больше не нужны
    if [[ -f "$ENVF" ]]; then sed -i '/^X_SS_KEY=/d;/^SS_METHOD=/d' "$ENVF"; fi
    if [[ -z "${ENT_WG_PRIV:-}" || -z "${ENT_WG_PUB:-}" ]]; then
      log "Генерация ключей WireGuard входного сервера"
      ENT_WG_PRIV=$(wg genkey)
      ENT_WG_PUB=$(printf '%s' "$ENT_WG_PRIV" | wg pubkey)
      save_kv ENT_WG_PRIV "$ENT_WG_PRIV"
      save_kv ENT_WG_PUB "$ENT_WG_PUB"
    fi
  fi
}

# ================================================================ сайт-прикрытие + сертификат
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
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx

  # Let's Encrypt проверяет домен по HTTP (порт 80). Если ufw на сервере уже включён
  # (часть образов VPS) и 80 в нём закрыт, certbot упадёт — открываем заранее.
  if [[ -z "$NO_UFW" ]] && command -v ufw >/dev/null 2>&1 \
     && [[ "$(ufw status 2>/dev/null || true)" == *"Status: active"* ]]; then
    ufw allow 80/tcp >/dev/null
  fi

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
    # Только классические кривые. Reality берёт этот сервер за образец (dest), и ему
    # нужен обмен ключами X25519. Свежий OpenSSL 3.5+ (новые Debian/Ubuntu) по умолчанию
    # договаривается о гибриде X25519MLKEM768 с клиентами в профиле Chrome, и образец
    # перестаёт совпадать с тем, что Reality отдаёт клиенту сам.
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
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
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
        client_max_body_size 0;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
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

  # значение — всё после ПЕРВОГО "=": ключи base64 сами заканчиваются на "=", делить по "=" нельзя
  WG_PRIV=$(awk '/^PrivateKey/{sub(/^[^=]*=[ \t]*/, ""); print; exit}' wgcf-profile.conf | tr -d ' \r')
  WG_PUB=$(awk '/^PublicKey/{sub(/^[^=]*=[ \t]*/, ""); print; exit}' wgcf-profile.conf | tr -d ' \r')
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
# входные точки для клиентов (общие для warp и chain)
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
          "serverNames": [$SERVER_NAMES],
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
    "tag": "dns-module",
    "queryStrategy": "UseIPv4",
    "enableParallelQuery": true,
    "disableFallback": false,
    "servers": ["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"]
  },
  "inbounds": [
$(emit_client_inbounds)
  ],
  "outbounds": [
    $WARP_OUT,
    {"tag": "dns-out", "protocol": "dns", "settings": {"rules": [{"qType": "65", "action": "drop"}, {"action": "hijack"}]}},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "port": "53", "outboundTag": "dns-out"},
      {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
      {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
      {"type": "field", "network": "tcp,udp", "outboundTag": "warp"}
    ]
  }
}
EOF
}

# Цепочка. На каждый релей — свой outbound exit-k (freedom), привязанный к адресу
# туннеля wgxK (sendThrough); policy routing (ip rule from <адрес>) уводит его пакеты
# прямо в WireGuard-интерфейс. Прямого выхода нет: других outbound'ов, кроме block, нет.
#
# DNS. Клиентские DNS-запросы (на любой адрес, порт 53) перехватываются первым
# правилом routing и уходят в outbound dns-out (protocol "dns", action hijack), т.е.
# во встроенный DNS Xray. Значит за имена отвечает РОВНО ОДНА инстанция — встроенный
# DNS ВХОДНОГО сервера; релеи DNS не резолвят вовсе (они только ядро + NAT).
# Встроенный DNS ходит наверх по DoH (порт 443) через тот же WireGuard-туннель:
#   * утечек нет — запросы не уходят напрямую с IP входа, только через релей;
#   * хостер релея почти никогда не режет 443 (в отличие от UDP/53) — поэтому "DNS не
#     найден" для новых имён и работа только из кеша больше не возникают;
#   * enableParallelQuery гоняет несколько DoH-резолверов одновременно — ответ берётся
#     от самого быстрого/живого, зависаний на одном резолвере нет.
# Routing — IPIfNonMatch: домены, ведущие на частные адреса, блокируются.
# Для 2–3 релеев — балансировщик: случайный выбор среди живых (burstObservatory
# пробует каждый релей каждые 15 с, упавший исключается), при одном релее — прямое правило.
write_xray_chain(){
  log "Конфигурация Xray (цепочка)"
  local n=${#EX_IP[@]} i outs="" blocked target obs="" bal=""
  for i in "${!EX_IP[@]}"; do
    outs+="    {\"tag\": \"exit-$((i+1))\", \"protocol\": \"freedom\", \"sendThrough\": \"$(wg_entry_ip "$i")\", \"settings\": {\"domainStrategy\": \"UseIPv4\"}},"$'\n'
  done
  # закрываем доступ клиентов к самим серверам цепочки (вход и релеи)
  blocked=$(printf ', "%s"' "$ENTRY_IP" "${EX_IP[@]}")
  if (( n > 1 )); then
    target='"balancerTag": "exits"'
    obs=$(cat <<EOF
  "burstObservatory": {
    "subjectSelector": ["exit-"],
    "pingConfig": {
      "destination": "https://1.1.1.1/cdn-cgi/trace",
      "connectivity": "",
      "interval": "15s",
      "sampling": 3,
      "timeout": "5s"
    }
  },
EOF
)
    bal=$(cat <<EOF
,
    "balancers": [
      {
        "tag": "exits",
        "selector": ["exit-"],
        "strategy": {"type": "leastLoad", "settings": {"expected": $n, "maxRTT": "2s", "tolerance": 0.2}},
        "fallbackTag": "exit-1"
      }
    ]
EOF
)
  else
    target='"outboundTag": "exit-1"'
  fi
  cat > "$XCONF" <<EOF
{
  "log": {"loglevel": "warning", "access": "none"},
  "dns": {
    "tag": "dns-module",
    "queryStrategy": "UseIPv4",
    "enableParallelQuery": true,
    "disableFallback": false,
    "servers": [
      "https://1.1.1.1/dns-query",
      "https://1.0.0.1/dns-query",
      "https://9.9.9.9/dns-query",
      "https://8.8.8.8/dns-query"
    ]
  },
$obs
  "inbounds": [
$(emit_client_inbounds)
  ],
  "outbounds": [
$outs    {"tag": "dns-out", "protocol": "dns", "settings": {"rules": [{"qType": "65", "action": "drop"}, {"action": "hijack"}]}},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "port": "53", "outboundTag": "dns-out"},
      {"type": "field", "ip": ["geoip:private"$blocked], "outboundTag": "block"},
      {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
      {"type": "field", "network": "tcp,udp", $target}
    ]$bal
  }
}
EOF
}

finish_xray(){
  local XUSER
  XUSER=$(systemctl show -p User --value xray 2>/dev/null || true)
  XUSER=${XUSER:-nobody}
  chown "root:$(id -gn "$XUSER" 2>/dev/null || echo nogroup)" "$XCONF"
  chmod 640 "$XCONF"

  local test_out
  test_out=$(xray run -test -config "$XCONF" 2>&1) \
    || { printf '%s\n' "$test_out"; die "Конфиг Xray не прошёл проверку (причина — в выводе выше)"; }
  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray
  sleep 2
  systemctl is-active --quiet xray || { journalctl -u xray -n 30 --no-pager; die "Xray не запустился"; }
  # без "ss | grep -q": при pipefail ранний выход grep может дать SIGPIPE и ложную ошибку
  [[ "$(ss -tln)" == *":443 "* ]] || die "Порт 443 не слушается"
}

# Сквозная проверка Reality + Vision: локальный клиент Xray подключается к своему же
# серверу (127.0.0.1:443) с теми же параметрами, что и в ссылке, и выходит в интернет
# (в режиме chain — через релей). Если здесь не проходит, не пройдёт и у клиента.
# Не фатальна: ссылки всё равно выводятся, но с диагностикой.
verify_reality(){
  log "Проверка Reality + Vision (то же, что делает клиент по ссылке)"
  local cfg=/tmp/xray-reality-test.json logf=/tmp/xray-reality-test.log pid trace="" i
  cat > "$cfg" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": 10809, "protocol": "socks", "settings": {"udp": false}}],
  "outbounds": [{
    "protocol": "vless",
    "settings": {"vnext": [{
      "address": "127.0.0.1",
      "port": 443,
      "users": [{"id": "$UUID", "encryption": "none", "flow": "xtls-rprx-vision"}]
    }]},
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "serverName": "$SNI",
        "fingerprint": "chrome",
        "publicKey": "$R_PUB",
        "shortId": "$SID",
        "spiderX": "/"
      }
    }
  }]
}
EOF
  xray run -config "$cfg" >"$logf" 2>&1 &
  pid=$!
  sleep 2
  for i in 1 2 3; do
    trace=$(curl -fsS --max-time 25 --socks5-hostname 127.0.0.1:10809 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
    if grep -q '^ip=' <<<"$trace"; then break; fi
    sleep 3
  done
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f "$cfg"
  if grep -q '^ip=' <<<"$trace"; then
    echo "Reality + Vision работает. Выходной IP: $(awk -F= '/^ip=/{print $2}' <<<"$trace")"
    rm -f "$logf"
    return 0
  fi
  warn "Reality + Vision НЕ прошёл проверку на самом сервере — клиент по ссылке тоже не подключится."
  echo "--- лог тестового клиента ---"; tail -n 15 "$logf" 2>/dev/null || true
  echo "--- лог сервера Xray ---"; journalctl -u xray -n 15 --no-pager 2>/dev/null || true
  rm -f "$logf"
  return 1
}

# ================================================================ система
setup_bbr(){
  cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null 2>&1 || true
}

# $1 — IP входного сервера (только на выходном релее: ему открывается порт WireGuard)
setup_ufw(){
  if [[ -n "$NO_UFW" ]]; then return 0; fi
  local ports p
  # порты sshd: из конфига и из реально слушающих сокетов (Ubuntu 22.10+ — socket activation)
  ports=$({ sshd -T 2>/dev/null | awk '/^port /{print $2}'
            ss -tlnpH 2>/dev/null | awk '/"sshd"/{n=split($4,a,":"); print a[n]}'; } | sort -un || true)
  ports=${ports:-22}
  if [[ -n "${1:-}" ]]; then
    log "Фаервол (ufw): открыт SSH; WireGuard (UDP $WG_PORT) — только для ${1}"
  else
    log "Фаервол (ufw): открыты SSH, 80, 443"
  fi
  for p in $ports; do ufw allow "$p"/tcp >/dev/null; done
  if [[ -n "${1:-}" ]]; then
    # релей: сайта нет, виден только WireGuard и только входному серверу
    ufw delete allow 443/tcp >/dev/null 2>&1 || true   # убрать открытый всем 443 от прежней версии
    ufw allow from "$1" to any port "$WG_PORT" proto udp >/dev/null
  else
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
  fi
  ufw --force enable >/dev/null
}

# ================================================================ уборка после прежних версий
# вход: прежний HAProxy (выбор релея по нагрузке) больше не нужен
drop_haproxy_legacy(){
  if [[ -f "$HA_CFG" ]] && grep -q '^# vpn-installer' "$HA_CFG"; then
    log "Отключаю прежний HAProxy (в цепочке он больше не используется)"
    systemctl disable --now haproxy >/dev/null 2>&1 || true
    mv -f "$HA_CFG" "$HA_CFG.vpn-old"
    if [[ -f "$HA_CFG.orig" ]]; then cp "$HA_CFG.orig" "$HA_CFG"; fi
    rm -f /usr/local/bin/vpn-status "$EXITS_MAP"
  fi
}

# вход: убрать туннели wgx* (перед настройкой заново и при переходе на warp)
drop_wg_chain() {
  local f ifn
  shopt -s nullglob
  for f in "$WG_DIR"/wgx*.conf; do
    ifn=$(basename "$f" .conf)
    systemctl disable --now "wg-quick@$ifn" >/dev/null 2>&1 || true
    rm -f "$f"
  done
  shopt -u nullglob
  rm -f /usr/local/bin/vpn-status "$EXITS_MAP"
}

# релей: убрать Xray / Shadowsocks и агент нагрузки от прежней версии
legacy_exit_cleanup(){
  local old_port old_entry
  old_port=$(env_get "$EXIT_ENVF" AGENT_PORT)
  old_entry=$(env_get "$EXIT_ENVF" ENTRY_IP)
  if [[ -f "$XCONF" ]] && grep -q '"chain-in"' "$XCONF" 2>/dev/null; then
    log "Убираю прежний транспорт (Xray / Shadowsocks): теперь только WireGuard"
    systemctl disable --now xray >/dev/null 2>&1 || true
    mv -f "$XCONF" "$XCONF.vpn-old"
  fi
  if [[ -f /etc/systemd/system/vpn-load-agent.socket ]]; then
    systemctl disable --now vpn-load-agent.socket >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/vpn-load-agent.socket /etc/systemd/system/vpn-load-agent@.service \
          /usr/local/sbin/vpn-load-agent /etc/vpn-load-agent.conf
    systemctl daemon-reload
  fi
  if [[ -n "$old_entry" ]] && command -v ufw >/dev/null; then
    ufw delete allow from "$old_entry" to any port 443 >/dev/null 2>&1 || true
    if [[ -n "$old_port" ]]; then
      ufw delete allow from "$old_entry" to any port "$old_port" proto tcp >/dev/null 2>&1 || true
    fi
  fi
}

# ================================================================ выходной релей: WireGuard + NAT
setup_wg_exit(){
  local ifn=wgin priv pub
  log "WireGuard на релее: $TUN_EXIT_IP, UDP $WG_PORT, MTU $WG_MTU (ядро Linux, ничего поверх)"
  mkdir -p "$WG_DIR"; chmod 700 "$WG_DIR"
  umask 077
  if [[ ! -s "$WG_DIR/$ifn.key" ]]; then wg genkey > "$WG_DIR/$ifn.key"; fi
  priv=$(<"$WG_DIR/$ifn.key")
  pub=$(wg pubkey < "$WG_DIR/$ifn.key")
  printf '%s\n' "$pub" > "$EXIT_PUB"
  # TCPMSS: подгоняет размер сегментов под MTU туннеля, чтобы "тяжёлые" ответы сайтов не
  # терялись на фрагментации (без этого часть страниц зависает на полпути). Ошибка
  # правил MSS не должна ронять туннель, поэтому "|| true".
  cat > "$WG_DIR/$ifn.conf" <<EOF
# vpn-installer: файл создан install.sh
[Interface]
PrivateKey = $priv
Address = $TUN_EXIT_IP/32
ListenPort = $WG_PORT
MTU = $WG_MTU
PostUp = sysctl -q -w net.ipv4.ip_forward=1
PostUp = iptables -t nat -C POSTROUTING -s $TUN_ENTRY_IP/32 ! -o %i -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s $TUN_ENTRY_IP/32 ! -o %i -j MASQUERADE
PostUp = iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i %i -j ACCEPT
PostUp = iptables -C FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t mangle -C FORWARD -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true
PostUp = iptables -t mangle -C FORWARD -i %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -i %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true
PostDown = iptables -t nat -D POSTROUTING -s $TUN_ENTRY_IP/32 ! -o %i -j MASQUERADE 2>/dev/null || true
PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
PostDown = iptables -t mangle -D FORWARD -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
PostDown = iptables -t mangle -D FORWARD -i %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

[Peer]
PublicKey = $ENT_WG_PUB
AllowedIPs = $TUN_ENTRY_IP/32
EOF
  umask 022
  printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/98-vpn-forward.conf
  sysctl -q -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  systemctl enable "wg-quick@$ifn" >/dev/null 2>&1 || true
  systemctl restart "wg-quick@$ifn" || { journalctl -u "wg-quick@$ifn" -n 20 --no-pager || true; die "Не поднялся WireGuard на релее"; }
  wg show "$ifn" >/dev/null || die "Интерфейс $ifn не создан"
  echo "WireGuard на релее поднят"
}

# ================================================================ входной сервер: цепочка
collect_exits(){
  local raw="$EXITS" prev n a hint s user port host ip j o
  if [[ -z "$raw" ]]; then
    prev=$(saved SAVED_EXITS)
    if is_tty; then
      echo
      echo "Выходные релеи: от 1 до 3 серверов (чистый Debian/Ubuntu, доступ по SSH)."
      echo "Релеи — ТОЛЬКО по IP: домены им не нужны, сайты на них не создаются."
      echo "Скрипт сам подключится к каждому по SSH и всё настроит."
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

  EX_USER=(); EX_HOST=(); EX_PORT=(); EX_IP=(); EX_PUB=()
  for s in "${specs[@]}"; do
    user=root; port=22
    if [[ "$s" == *@* ]]; then user="${s%%@*}"; s="${s#*@}"; fi
    if [[ "$s" == *:* ]]; then port="${s##*:}"; s="${s%%:*}"; fi
    host="${s,,}"
    # релей — ТОЛЬКО по IP: домен, сайт и сертификат есть лишь у входного сервера
    [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
      || die "Релей «$host» нужно указывать по IP-адресу: домены релеям не нужны, сайты на них не создаются."
    for o in ${host//./ }; do
      if (( 10#$o > 255 )); then die "Некорректный IP релея: $host"; fi
    done
    ip="$host"
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || die "Некорректный SSH-порт у $host: $port"
    [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "Некорректное имя пользователя у $host: $user"
    for j in "${EX_HOST[@]}"; do
      [[ "$j" != "$host" ]] || die "Релей $host указан дважды"
    done
    EX_USER+=("$user"); EX_HOST+=("$host"); EX_PORT+=("$port"); EX_IP+=("$ip")
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

# параметры, которые входной сервер передаёт релею (файл с правами 600, не командная строка);
# приватный ключ релея никуда не передаётся: релей создаёт его у себя и отдаёт только публичный
make_params(){
  local i="$1" v
  for v in WG_PORT WG_MTU ENT_WG_PUB ENTRY_IP; do
    printf '%s=%q\n' "$v" "${!v}"
  done
  printf 'TUN_ENTRY_IP=%q\n' "$(wg_entry_ip "$i")"
  printf 'TUN_EXIT_IP=%q\n' "$(wg_exit_ip "$i")"
}

deploy_exit(){
  local i="$1" h tmp pre="" rc=0 pub
  h="${EX_HOST[$i]}"
  if [[ "${EX_USER[$i]}" != root ]]; then pre="sudo -n"; fi
  log "Установка выходного релея $h (${EX_IP[$i]}) — это займёт минуту"
  tmp=$(mktemp); chmod 600 "$tmp"
  make_params "$i" > "$tmp"
  xscp "$i" "$SELF" ".vpn-install.sh"
  xscp "$i" "$tmp" ".vpn-exit-params.env"
  rm -f "$tmp"
  xssh "$i" "chmod 600 .vpn-exit-params.env"
  xssh "$i" "$pre env MODE=exit PARAMS_FILE=\"\$HOME/.vpn-exit-params.env\" bash \"\$HOME/.vpn-install.sh\"" 2>&1 \
    | sed -u "s/^/[$h] /" || rc=$?
  xssh "$i" 'rm -f "$HOME/.vpn-exit-params.env" "$HOME/.vpn-install.sh"' || true
  (( rc == 0 )) || die "Не удалось настроить выходной релей $h (причина — в выводе выше). Исправьте её и запустите скрипт снова: он идемпотентен."
  pub=$(xssh "$i" "$pre cat $EXIT_PUB" 2>/dev/null | tr -d '[:space:]' || true)
  [[ "$pub" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "Не удалось получить публичный ключ WireGuard релея $h"
  EX_PUB[i]="$pub"
}

# входные туннели: по интерфейсу wgxK на релей (ядро, Table = off — маршрутами управляем сами)
setup_wg_entry(){
  log "WireGuard: туннели вход → релеи (ядро Linux, ничего поверх), MTU $WG_MTU"
  local i ifn eip rip tbl prio
  mkdir -p "$WG_DIR"; chmod 700 "$WG_DIR"
  drop_wg_chain
  : > "$EXITS_MAP"
  for i in "${!EX_IP[@]}"; do
    ifn=$(wg_if "$i"); eip=$(wg_entry_ip "$i"); rip=$(wg_exit_ip "$i")
    tbl=$(wg_table "$i"); prio=$((1001 + i))
    umask 077
    cat > "$WG_DIR/$ifn.conf" <<EOF
# vpn-installer: файл создан install.sh
[Interface]
PrivateKey = $ENT_WG_PRIV
Address = $eip/32
MTU = $WG_MTU
Table = off
# всё, что исходит с адреса этого туннеля, уходит в него (и больше никуда)
PostUp = ip -4 route replace default dev %i table $tbl
PostUp = ip -4 rule del from $eip/32 lookup $tbl 2>/dev/null || true; ip -4 rule add from $eip/32 lookup $tbl priority $prio
PostDown = ip -4 rule del from $eip/32 lookup $tbl 2>/dev/null || true; ip -4 route flush table $tbl 2>/dev/null || true

[Peer]
PublicKey = ${EX_PUB[$i]}
Endpoint = ${EX_IP[$i]}:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    umask 022
    echo "$ifn,${EX_HOST[$i]},$eip,$rip" >> "$EXITS_MAP"
    systemctl enable "wg-quick@$ifn" >/dev/null 2>&1 || true
    systemctl restart "wg-quick@$ifn" || { journalctl -u "wg-quick@$ifn" -n 20 --no-pager || true; die "Не поднялся туннель $ifn"; }
  done
  write_vpn_status
}

write_vpn_status(){
  cat > /usr/local/bin/vpn-status <<'EOF'
#!/usr/bin/env bash
# Состояние туннелей вход -> релеи (WireGuard): рукопожатие, трафик, задержка до релея.
MAP=/etc/vpn-exits.map
[[ -r "$MAP" ]] || { echo "Нет $MAP: это не входной сервер цепочки"; exit 1; }
now=$(date +%s)
printf '%-6s %-17s %-12s %-9s %-9s %s\n' IFACE RELAY HANDSHAKE RX TX RTT
while IFS=, read -r ifn host eip rip; do
  [[ -n "$ifn" ]] || continue
  hs=$(wg show "$ifn" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
  if [[ "${hs:-0}" -gt 0 ]]; then age="$((now - hs)) c назад"; else age="нет"; fi
  read -r rx tx < <(wg show "$ifn" transfer 2>/dev/null | awk 'NR==1{print $2, $3}')
  rtt=$(ping -c3 -W2 -I "$eip" "$rip" 2>/dev/null | awk -F/ '/^(rtt|round-trip)/{print $5" ms"}')
  printf '%-6s %-17s %-12s %-9s %-9s %s\n' "$ifn" "$host" "$age" \
    "$(numfmt --to=iec "${rx:-0}" 2>/dev/null || echo "${rx:-0}")" \
    "$(numfmt --to=iec "${tx:-0}" 2>/dev/null || echo "${tx:-0}")" "${rtt:-недоступен}"
done < "$MAP"
EOF
  chmod 755 /usr/local/bin/vpn-status
}

# проверка без Xray: curl с адреса туннеля должен выйти в интернет с IP релея
verify_tunnels(){
  log "Проверка туннелей вход → релей → интернет"
  local i ifn eip ip t
  for i in "${!EX_IP[@]}"; do
    ifn=$(wg_if "$i"); eip=$(wg_entry_ip "$i"); ip=""
    for t in 1 2 3 4 5; do
      ip=$(curl -4fsS --max-time 8 --interface "$eip" https://api.ipify.org 2>/dev/null || true)
      if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then break; fi
      ip=""; sleep 2
    done
    if [[ -z "$ip" ]]; then
      echo "--- wg show $ifn ---"; wg show "$ifn" || true
      die "${EX_HOST[$i]}: трафик не проходит через WireGuard-туннель $ifn. Проверьте, что UDP $WG_PORT доходит до релея (хостер/фаервол/DPI), что релей видит входной сервер как $ENTRY_IP (иначе задайте ENTRY_IP=…) и нет ли пересечения сети $WG_NET.x.x с сетью хостера (WG_NET=…)."
    fi
    echo "${EX_HOST[$i]}: туннель $ifn работает, выход в интернет с IP $ip"
  done
}

# ================================================================ итог для входного сервера
print_links(){
  local L_REALITY L_XHTTP L_GRPC L_WS L_HU
  L_REALITY="vless://$UUID@$DOMAIN:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$R_PUB&sid=$SID&type=tcp&headerType=none#hlebcraft-reality"
  L_XHTTP="vless://$UUID@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&alpn=http%2F1.1&type=xhttp&host=$DOMAIN&path=%2F$P_XHTTP&mode=auto#hlebcraft-xhttp"
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
  echo "SNI (Reality):  $SNI"
  if [[ "$MODE" == chain ]]; then
    echo "Выходные релеи (WireGuard):"
    local i
    for i in "${!EX_HOST[@]}"; do echo "  $(wg_if "$i")  ${EX_HOST[$i]}  (${EX_IP[$i]})"; done
    echo "Состояние туннелей:  vpn-status"
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
  resolve_sni
  log "Режим: WARP (один сервер)"
  drop_haproxy_legacy
  drop_wg_chain
  install_packages
  check_dns
  install_xray
  load_secrets
  setup_site
  write_nginx_tls 1
  setup_warp
  write_xray_warp
  finish_xray
  verify_reality || true
  setup_bbr
  setup_ufw
  save_kv SAVED_MODE warp
  print_links
}

run_chain(){
  [[ -f "$SELF" && -r "$SELF" ]] || die "Режим chain нужно запускать из файла (bash install.sh), а не через pipe: скрипт копирует себя на выходные релеи. Скачайте файл: curl -fsSL -o install.sh <ссылка>"
  ensure_domain "ВХОДНОГО сервера"
  resolve_sni
  check_wg_settings
  collect_exits
  log "Режим: цепочка. Вход: $DOMAIN  →  релеи: ${EX_HOST[*]}  (WireGuard)"
  install_packages
  check_wireguard
  check_dns
  ENTRY_IP="${ENTRY_IP:-$SERVER_IP}"
  [[ "$ENTRY_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Не удалось определить внешний IP входного сервера — задайте ENTRY_IP=…"
  local i
  for i in "${EX_IP[@]}"; do
    [[ "$i" != "$ENTRY_IP" ]] || die "Выходной релей $i совпадает с входным сервером"
  done
  install_xray
  load_secrets      # заодно ключи WireGuard входного сервера

  init_ssh
  for i in "${!EX_HOST[@]}"; do ensure_ssh_access "$i"; done
  for i in "${!EX_HOST[@]}"; do deploy_exit "$i"; done

  setup_site
  write_nginx_tls 1
  drop_haproxy_legacy
  setup_wg_entry
  verify_tunnels
  write_xray_chain
  finish_xray
  verify_reality || true
  setup_bbr
  setup_ufw
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
  for v in ENT_WG_PUB ENTRY_IP TUN_ENTRY_IP TUN_EXIT_IP WG_PORT; do
    [[ -n "${!v:-}" ]] || die "В параметрах выходного релея нет $v"
  done
  check_wg_settings
  legacy_exit_cleanup       # до перезаписи EXIT_ENVF: оттуда берутся старые порты
  umask 077
  for v in ENT_WG_PUB ENTRY_IP TUN_ENTRY_IP TUN_EXIT_IP WG_PORT WG_MTU; do
    printf '%s=%q\n' "$v" "${!v}"
  done > "$EXIT_ENVF"
  umask 022

  log "Режим: ВЫХОДНОЙ релей (без сайта и домена), вход: $ENTRY_IP, канал: WireGuard"
  install_packages
  check_wireguard
  setup_ufw "$ENTRY_IP"
  setup_wg_exit
  setup_bbr
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
