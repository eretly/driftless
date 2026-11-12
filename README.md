# Driftless (v1.5.5)

> 🌐 **Choose Language / Выберите язык:** [🇺🇸 English (Full Documentation)](#english-documentation) · [🇷🇺 Русский (Полная инструкция)](#ru)

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![Transport](https://img.shields.io/badge/Transport-QUIC_%2B_TLS_1.3_%2B_TCP--Mux-10b981?style=flat-square)](#english-documentation)
[![NAT Traversal](https://img.shields.io/badge/Router-UPnP_%2B_NAT--PMP_%2B_PCP_v2-3b82f6?style=flat-square)](#english-documentation)
[![License](https://img.shields.io/badge/License-MIT-a855f7?style=flat-square)](LICENSE)

---

<a id="english-documentation"></a>

## 🇺🇸 English Documentation

### What Driftless Does
When your ISP gives you a **dynamic public IP** (or places you behind **CGNAT**), **Driftless** makes your home services work as if you had a permanent static IP:
- Opens **both TCP and UDP** ports automatically (`-udp=true` by default).
- Works **with zero VPS** (`driftless standalone`) or **through your own VPS** (`driftless server` + `driftless client`).
- Supports **multiple Home PCs (`-id pc1`, `-id pc2`, `-id pc3`)** on a single VPS and **automatic failover to a 2nd backup VPS (`-vps2`)**.
- Never interferes with your services' own login/password (SSH, Windows RDP, Jellyfin, websites, game servers use their native authentication).

---

### 1. Run Without a VPS (`standalone` + `-duck`)

If your router has a dynamic public IP, run a single command on your PC. You do **not** need to paste tokens or configure your router manually:

**Windows (PowerShell):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,3389,22 -duck
```

**Linux / macOS:**
```bash
./driftless standalone -ports 8096,3389,22 -duck
```

**What happens automatically:**
1. **UPnP / NAT-PMP / PCP** opens TCP and UDP ports `8096`, `3389`, and `22` on your home router.
2. **UDP STUN (`1s`)** detects your external IP in 5 ms and tracks any ISP IP rotation in real time.
3. **`-duck`** automatically binds an HTTPS domain (uses your saved DuckDNS config if present, or generates an automatic `<IP>.sslip.io` domain + TLS certificate on the fly).

**What you see in the console:**
```text
[standalone] ==========================================================
[standalone] Published Endpoints (Domain: 198-51-100-42.sslip.io | Public IP: 198.51.100.42):
[standalone]   Port :8096  -> :8096  : https://198-51-100-42.sslip.io:8096  (TCP/UDP: 198-51-100-42.sslip.io:8096)
[standalone]   Remote Desktop (RDP)  : 198-51-100-42.sslip.io:3389 (uses your Windows account credentials)
[standalone]   SSH Service           : 198-51-100-42.sslip.io:22 (uses your system SSH server & OS credentials)
[standalone] ==========================================================
```

**How to connect from anywhere (phone / laptop):**
- **Browser / Jellyfin / Web App:** open `https://198-51-100-42.sslip.io:8096`
- **SSH (Termius / WebSSH / terminal):** Host `198-51-100-42.sslip.io`, Port `22`, your OS username & password/key.
- **Windows Remote Desktop (RDP):** Computer `198-51-100-42.sslip.io:3389`, your Windows username & password.

---

### 2. Bind Your Own Custom Domain (`-domain` & `-vhosts`)

#### Option A: One-Flag Custom Domain (`-domain`)
Point your domain's `A` record to your PC (or VPS) IP and pass `-domain`:
```bash
# Bind mysite.com with automatic HTTPS/TLS on your mapped ports
./driftless standalone -ports 8096,25565 -domain mysite.com

# Or route a domain directly to a local port on :80 / :443
./driftless standalone -domain media.mysite.com:8096 -https :443
```

#### Option B: Multiple Domains on Port 80 & 443 (`-vhosts`)
```bash
./driftless standalone -vhosts site.mysite.com:3000,media.mysite.com:8096 -vhost-addr :80 -https :443
```

#### Option C: Auto-Update Your Cloudflare / No-IP Domain on IP Change
```bash
# Cloudflare DNS API v4 (TTL=60s)
./driftless standalone -ports 8096 -ddns-provider cloudflare -ddns-zone YOUR_ZONE_ID -ddns-domain home.mysite.com -ddns-token YOUR_CF_TOKEN

# No-IP
./driftless standalone -ports 8096 -ddns-provider noip -ddns-domain mypc.ddns.net -ddns-user USER -ddns-token PASS
```

---

### 3. Run With a VPS + Second Backup VPS + Multiple Home PCs

Use this mode if your ISP uses **CGNAT (`100.64.0.0/10`)** or if you want a permanent VPS entry point.

#### Basic Setup (1 VPS + 1 Home PC)
1. **On your VPS:**
   ```bash
   ./driftless server -ports 8080:80,8096,25565
   ```
   The VPS prints a ready-to-copy `./driftless client ...` command with an auto-generated token and TLS fingerprint.
2. **On your Home PC:**
   ```bash
   ./driftless client -quic YOUR_VPS_IP:4242 -token YOUR_TOKEN
   ```

#### Adding a Second Backup VPS (`-vps2` Automatic Failover)
If you have a second VPS, run `driftless server` on both VPS servers with the same `-token`, and add `-vps2` on your Home PC:
```bash
./driftless client -quic VPS_1_IP:4242 -vps2 VPS_2_IP:4242 -token YOUR_SHARED_TOKEN
```
*(Or list both via comma: `-quic VPS_1_IP:4242,VPS_2_IP:4242`). If VPS #1 goes offline, the Home PC automatically switches to VPS #2.*

#### Connecting Multiple Home PCs (`pc1`, `pc2`, `pc3`) to One VPS
1. **On your VPS:**
   ```bash
   ./driftless server -quic 0.0.0.0:4242 -vhost-addr :80 -https :443
   ```
2. **On Home PC 1 (`pc1` - Media Server + SSH):**
   ```bash
   ./driftless client -id pc1 -quic YOUR_VPS_IP:4242 -token YOUR_TOKEN -vhosts media.mysite.com:8096 -ports 2221:22
   ```
3. **On Home PC 2 (`pc2` - Website + SSH):**
   ```bash
   ./driftless client -id pc2 -quic YOUR_VPS_IP:4242 -token YOUR_TOKEN -vhosts site.mysite.com:3000 -ports 2222:22
   ```
4. **On Home PC 3 (`pc3` - Game Server TCP+UDP):**
   ```bash
   ./driftless client -id pc3 -quic YOUR_VPS_IP:4242 -token YOUR_TOKEN -vhosts game.mysite.com:8080 -ports 25565:25565
   ```
Disconnecting or rebooting `pc1` never interrupts `pc2` or `pc3`.

---

### 4. Network & CGNAT Diagnostics (`./driftless check`)

Test your external IP via STUN, check for ISP CGNAT (`100.64.0.0/10`), verify router UPnP/NAT-PMP/PCP rules, and check port reachability:
```bash
./driftless check -ports 8096,25565,22 -duck
```

**When Standalone Mode Cannot Work Without a VPS:**
- Your ISP places your router behind **CGNAT (`100.64.0.0/10`)** or Double NAT.
- UPnP / NAT-PMP / PCP is disabled on your router and ports are not forwarded manually.
- Your ISP blocks inbound ports (`80`, `443`, `22`) or your OS firewall blocks `driftless`.

---

### 5. Complete CLI Flags Reference (All Flags)

#### Subcommands
| Subcommand | Description |
| :--- | :--- |
| `driftless standalone` | Run directly on Home PC without a VPS (STUN + Auto-UPnP + Auto-Domain/DDNS + TCP/UDP/TLS) |
| `driftless server` | Run Gateway on a VPS (accepts one or multiple Home PC Agents) |
| `driftless client` | Run Agent on a Home PC (connects to VPS Gateway, supports `-id` and `-vps2`) |
| `driftless check` | Run external IP, CGNAT, UPnP, and port reachability diagnostics |
| `driftless show-token` | Print the saved Gateway token and ready-to-copy client connection command |
| `driftless version` | Print `driftless v1.5.5` version string |

#### All CLI Flags
| Flag | Default | Description |
| :--- | :--- | :--- |
| `-mode` | `"agent"` | Operating mode: `server` (`gateway`), `client` (`agent`), or `standalone` (`direct`, `p2p`) |
| `-ports` | `"8080:80,8096:8096"` | Port mappings: `PORT`, `PUBLIC:LOCAL`, `PUBLIC:NODE_ID:LOCAL`, or `127.0.0.1:PUBLIC:LOCAL` (supports `/tcp`, `/udp`, `/both`, `/http`, `/https`) |
| `-udp` | `true` | Forward both TCP and UDP by default on all mapped ports |
| `-duck` | `""` | Automatic zero-config domain & DuckDNS sync in standalone/server mode (just pass `-duck`) |
| `-domain` | `""` | Bind your own custom domain with Auto-TLS (`-domain mysite.com` or `-domain media.mysite.com:8096`) |
| `-vhosts` | `""` | Virtual Host domain routing (`domain:PORT` or `domain:NODE_ID:PORT`, e.g. `media.mysite.com:pc1:8096`) |
| `-vhost-addr` | `""` (`:80` if vhosts) | HTTP/HTTPS VHost router listen address (e.g. `:80`) |
| `-https` | `""` | Dedicated HTTPS VHost router listen address (e.g. `:443` or `:8443`) |
| `-tls` | `false` | Enable automatic HTTPS/TLS termination on mapped TCP ports |
| `-tls-cert` | `""` | Path to custom TLS certificate PEM file (auto-discovers Let's Encrypt / SNI if omitted) |
| `-tls-key` | `""` | Path to custom TLS private key PEM file |
| `-quic` | `"0.0.0.0:4242"` | Gateway tunnel address on VPS, or comma-separated failover list on PC (`VPS1:4242,VPS2:4242`) |
| `-gateway` | `""` | Alias for `-quic` |
| `-vps2` | `""` | Second backup VPS Gateway address for automatic failover (e.g. `BACKUP_VPS_IP:4242`) |
| `-id` / `-node` | `""` (`default`) | Unique computer/node ID when connecting multiple Home PCs to one VPS (`pc1`, `pc2`, `pc3`) |
| `-transport` | `"auto"` | Tunnel transport protocol: `auto` (QUIC with automatic TCP-Mux fallback), `quic`, or `tcp` |
| `-token` | `""` (auto on VPS) | Shared secret tunnel password or comma-separated token rotation list (`new_tok,old_tok`) |
| `-token-file` | `""` | Path to file containing shared secret tunnel password |
| `-fingerprint` | `""` (auto-TOFU) | Gateway TLS certificate SHA-256 fingerprint for strict pinning |
| `-direct` | `":8888"` | Direct LAN/Wi-Fi HTTP redirector port to bypass VPS on home network (`""` to disable) |
| `-same-lan` | `true` | Redirect clients sharing the same WAN IP directly to the Agent's LAN IP |
| `-host` | `"127.0.0.1"` | Local target host IP on Home PC (`agent` / `standalone`) |
| `-lan-ip` | `""` (auto) | Override auto-detected local LAN IP address |
| `-allow-ports` | `""` (all) | Security whitelist of allowed local target ports on Home PC (e.g. `"80,8096,25565"`) |
| `-upnp` | `true` | Automatically open TCP+UDP ports on home router via UPnP IGDv1/v2, NAT-PMP, and PCP v2 |
| `-stun` | `"stun.cloudflare.com:3478"` | RFC 5389 UDP STUN server (or comma-separated list) for 5 ms external IP change detection |
| `-stun-interval` | `1s` | How often to check external IP via UDP STUN in standalone mode |
| `-ddns-provider` | `""` | Built-in Dynamic DNS provider: `duckdns`, `cloudflare`, or `noip` |
| `-ddns-domain` | `""` | Domain name to update when external IP changes |
| `-ddns-token` | `""` | API token or password for Dynamic DNS provider |
| `-ddns-user` | `""` | Username for No-IP / DynDNS provider |
| `-ddns-zone` | `""` | Cloudflare Zone ID (when `-ddns-provider=cloudflare`) |
| `-ddns-url` | `""` | Custom DDNS webhook URL (replaces `{ip}` and `{domain}` automatically) |
| `-max-buf` | `16777216` (16 MiB) | Max per-session sliding ring buffer in RAM for zero-drop reconnects |
| `-max-mem` | `268435456` (256 MiB) | Max global buffered bytes across all active sessions |
| `-session-ttl` | `90s` | How long to hold frozen TCP/UDP sessions in RAM during a WAN IP outage |
| `-quic-idle-timeout` | `8s` | QUIC / TCP-Mux idle timeout before triggering reconnect |
| `-quic-keepalive` | `2s` | QUIC / TCP-Mux heartbeat keepalive interval |
| `-cert-dir` | `""` (`.driftless-certs`) | Directory to persist generated TLS certificates, CA, and tokens |
| `-client-ca` | `""` | CA PEM file on VPS to enforce mutual TLS (mTLS) client certificates from Agents |
| `-client-cert` | `""` | Client mTLS certificate PEM file on Home PC Agent |
| `-client-key` | `""` | Client mTLS private key PEM file on Home PC Agent |
| `-proxy-protocol` | `false` | Prepend HAProxy PROXY protocol v1 header so local servers see real visitor IPs |
| `-metrics` | `""` | Observability HTTP listen address for `/metrics` (Prometheus) and `/status` (JSON) |

---

<a id="ru"></a>

## 🇷🇺 Русская документация (Полная инструкция)

### Зачем нужен Driftless
Когда провайдер выдаёт **динамический IP** (который меняется при перезагрузке роутера) или прячет вас за **CGNAT**, **Driftless** даёт удобство постоянного статического IP:
- По умолчанию открывает **сразу и TCP, и UDP** для каждого порта (`-udp=true`).
- Работает **вообще без ВПС** (`driftless standalone`) или **через ваш дешёвый ВПС** (`driftless server` + `driftless client`).
- Позволяет подключить **несколько домашних ПК (`-id pc1`, `-id pc2`, `-id pc3`) к одному ВПС**, а также указать **второй резервный ВПС (`-vps2`)** на случай падения основного.
- Не ломает и не подменяет авторизацию ваших программ: SSH, Windows RDP, сайты, Jellyfin и игровые серверы используют свои родные логины и пароли.

---

### 1. Запуск БЕЗ ВПС одной командой (`standalone` + `-duck`)

Если дома «белый» (пусть и динамический) IP, просто запустите программу с флагом `-duck`. Никакие токены вводить в команду не нужно:

**Windows (PowerShell):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,3389,22 -duck
```

**Linux / macOS:**
```bash
./driftless standalone -ports 8096,3389,22 -duck
```

**Что программа сделает сама за 1 секунду:**
1. **UPnP / NAT-PMP / PCP** автоматически откроет порты `8096`, `3389` и `22` (TCP и UDP) на вашем роутере.
2. **UDP STUN (`1s`)** за 5 мс узнает ваш внешний IP и будет каждую секунду следить за его сменой.
3. **`-duck`** автоматически выдаст готовый HTTPS-домен (если в папке уже есть конфиг DuckDNS - подхватит его автоматически; если нет - мгновенно создаст домен `<ВАШ_IP>.sslip.io` и выпустит TLS-сертификат).

**Что вы увидите в консоли:**
```text
[standalone] ==========================================================
[standalone] Published Endpoints (Domain: 198-51-100-42.sslip.io | Public IP: 198.51.100.42):
[standalone]   Port :8096  -> :8096  : https://198-51-100-42.sslip.io:8096  (TCP/UDP: 198-51-100-42.sslip.io:8096)
[standalone]   Remote Desktop (RDP)  : 198-51-100-42.sslip.io:3389 (uses your Windows account credentials)
[standalone]   SSH Service           : 198-51-100-42.sslip.io:22 (uses your system SSH server & OS credentials)
[standalone] ==========================================================
```

**Как теперь подключаться с телефона или ноутбука:**
- **Браузер / Jellyfin / Сайт:** просто откройте `https://198-51-100-42.sslip.io:8096`
- **SSH (WebSSH / Termius на iPhone или Android):** Хост `198-51-100-42.sslip.io`, Порт `22`, ваш обычный логин и пароль от Windows/Linux.
- **Удалённый рабочий стол (Microsoft Remote Desktop):** Компьютер `198-51-100-42.sslip.io:3389`, ваша учётная запись Windows.

---

### 2. Как легко подвязать свой домен (`-domain` и `-vhosts`)

#### Вариант А: Одним флагом `-domain`
Направьте `A`-запись вашего домена на IP компьютера (или ВПС) и укажите `-domain`:
```bash
# Привязать свой домен mysite.com (автоматически включит HTTPS/TLS)
./driftless standalone -ports 8096,25565 -domain mysite.com

# Или сразу привязать домен к конкретному локальному порту на :80 и :443
./driftless standalone -domain media.mysite.com:8096 -https :443
```

#### Вариант Б: Несколько своих доменов на портах 80 и 443 (`-vhosts`)
```bash
./driftless standalone -vhosts site.mysite.com:3000,media.mysite.com:8096 -vhost-addr :80 -https :443
```

#### Вариант В: Автообновление своего домена в Cloudflare или No-IP при смене IP
```bash
# Cloudflare (автоматически меняет A-запись при смене IP провайдером, TTL=60s)
./driftless standalone -ports 8096 -ddns-provider cloudflare -ddns-zone ID_ЗОНЫ -ddns-domain home.mysite.com -ddns-token ТОКЕН_CLOUDFLARE

# No-IP
./driftless standalone -ports 8096 -ddns-provider noip -ddns-domain mypc.ddns.net -ddns-user ЛОГИН -ddns-token ПАРОЛЬ
```

---

### 3. Запуск через ВПС + Второй резервный ВПС (`-vps2`) + Несколько ПК

Используйте этот режим, если у провайдера «серый» IP (**CGNAT `100.64.0.0/10`**) или вы хотите раздавать сервисы через постоянный IP своего ВПС.

#### Обычное подключение (1 ВПС + 1 домашний ПК)
1. **На ВПС:**
   ```bash
   ./driftless server -ports 8080:80,8096,25565
   ```
   ВПС сам сгенерирует пароль и напечатает в консоли готовую строчку для запуска на домашнем ПК.
2. **На домашнем ПК:**
   ```bash
   ./driftless client -quic IP_ВАШЕГО_ВПС:4242 -token ПАРОЛЬ_ИЗ_КОНСОЛИ_ВПС
   ```

#### Как подключить второй резервный ВПС (`-vps2`)
Если у вас есть второй запасной ВПС, запустите на нём `driftless server` с тем же `-token`, а на домашнем ПК добавьте флаг `-vps2`:
```bash
./driftless client -quic IP_ВПС_1:4242 -vps2 IP_ВПС_2:4242 -token ВАШ_ОБЩИЙ_ТОКЕН
```
*(Либо через запятую: `-quic IP_ВПС_1:4242,IP_ВПС_2:4242`). Если первый ВПС упадёт или станет недоступен, агент за долю секунды переключит туннель на второй ВПС.*

#### Как подключить несколько домашних компьютеров (`pc1`, `pc2`, `pc3`) к одному ВПС
1. **На ВПС (один общий сервер):**
   ```bash
   ./driftless server -quic 0.0.0.0:4242 -vhost-addr :80 -https :443
   ```
2. **На Компьютере 1 (`pc1` - медиасервер + SSH):**
   ```bash
   ./driftless client -id pc1 -quic IP_ВПС:4242 -token ВАШ_ТОКЕН -vhosts media.mysite.com:8096 -ports 2221:22
   ```
3. **На Компьютере 2 (`pc2` - веб-сайт + SSH):**
   ```bash
   ./driftless client -id pc2 -quic IP_ВПС:4242 -token ВАШ_ТОКЕН -vhosts site.mysite.com:3000 -ports 2222:22
   ```
4. **На Компьютере 3 (`pc3` - игровой сервер TCP+UDP):**
   ```bash
   ./driftless client -id pc3 -quic IP_ВПС:4242 -token ВАШ_ТОКЕН -vhosts game.mysite.com:8080 -ports 25565:25565
   ```
Отключение или перезагрузка `pc1` никак не влияет на работу `pc2` и `pc3`.

---

### 4. Проверка доступности и CGNAT (`./driftless check`)

Чтобы за секунду проверить свой внешний IP, узнать, нет ли у провайдера CGNAT, и проверить открыты ли порты снаружи:
```bash
./driftless check -ports 8096,25565,22 -duck
```

**Когда режим без ВПС (`standalone`) не сработает:**
- Провайдер выдаёт «серый» IP за **CGNAT (`100.64.0.0/10`)** или двойным NAT (в этом случае нужен ВПС).
- На роутере выключен UPnP / NAT-PMP / PCP и порты не открыты вручную в настройках роутера.
- Провайдер или брандмауэр Windows/Linux блокирует входящие соединения.

---

### 5. Полный справочник всех флагов CLI

#### Команды запуска
| Команда | Описание |
| :--- | :--- |
| `driftless standalone` | Работа на домашнем ПК без ВПС (STUN + Авто-UPnP + Авто-домен `-duck` + TCP/UDP/TLS) |
| `driftless server` | Запуск шлюза (Gateway) на ВПС (принимает один или несколько домашних ПК) |
| `driftless client` | Запуск агента на домашнем ПК (подключается к ВПС, поддерживает `-id` и `-vps2`) |
| `driftless check` | Диагностика внешнего IP по STUN, проверка CGNAT, тест UPnP и проверка доступности портов |
| `driftless show-token` | Показать сохранённый токен ВПС и готовую команду подключения для домашнего ПК |
| `driftless version` | Вывести версию `driftless v1.5.5` |

#### Все флаги (полная таблица)
| Флаг | По умолчанию | Описание |
| :--- | :--- | :--- |
| `-mode` | `"agent"` | Режим работы: `server` (`gateway`), `client` (`agent`) или `standalone` (`direct`, `p2p`) |
| `-ports` | `"8080:80,8096:8096"` | Порты: можно коротко `8096,25565`, `PUBLIC:LOCAL`, `PUBLIC:NODE_ID:LOCAL` или `127.0.0.1:PUBLIC:LOCAL` (суффиксы `/tcp`, `/udp`, `/both`, `/http`, `/https`) |
| `-udp` | `true` | Включено по умолчанию: пробрасывает сразу и TCP, и UDP на всех портах |
| `-duck` | `""` | Автоматический домен и обновление IP без возни с токенами (просто укажите `-duck`) |
| `-domain` | `""` | Привязать свой собственный домен с Auto-TLS (`-domain mysite.com` или `-domain media.mysite.com:8096`) |
| `-vhosts` | `""` | Маршрутизация доменов (`домен:ПОРТ` или `домен:ID_ПК:ПОРТ`, например `media.mysite.com:pc1:8096`) |
| `-vhost-addr` | `""` (`:80` при vhosts) | Порт приёма HTTP/HTTPS для доменного роутера (например, `:80`) |
| `-https` | `""` | Выделенный порт HTTPS для доменного роутера (например, `:443` или `:8443`) |
| `-tls` | `false` | Включить автоматическую расшифровку HTTPS/TLS на обычных TCP-портах из `-ports` |
| `-tls-cert` | `""` | Путь к своему `.pem` сертификату (если не указать - авто Let's Encrypt / SNI) |
| `-tls-key` | `""` | Путь к своему закрытому ключу `.pem` |
| `-quic` | `"0.0.0.0:4242"` | Адрес туннеля (на ВПС `0.0.0.0:4242`, на ПК `IP_ВПС:4242` или список через запятую `ВПС1:4242,ВПС2:4242`) |
| `-gateway` | `""` | Синоним флага `-quic` |
| `-vps2` | `""` | Адрес второго резервного ВПС для автоматического переключения (`IP_ВТОРОГО_ВПС:4242`) |
| `-id` / `-node` | `""` (`default`) | Имя домашнего ПК при подключении нескольких компьютеров к одному ВПС (`pc1`, `pc2`, `pc3`) |
| `-transport` | `"auto"` | Протокол туннеля: `auto` (QUIC с автопереключением на TCP-Mux), `quic` или `tcp` |
| `-token` | `""` (авто на ВПС) | Общий секретный пароль между ВПС и ПК (или список ротации через запятую `новый,старый`) |
| `-token-file` | `""` | Путь к файлу с секретным паролем туннеля |
| `-fingerprint` | `""` (авто-TOFU) | SHA-256 отпечаток сертификата ВПС для жёсткой привязки (Pinning) |
| `-direct` | `":8888"` | Порт прямого редиректа в домашней локальной сети/Wi-Fi в обход ВПС (`""` чтобы отключить) |
| `-same-lan` | `true` | Автоматически перенаправлять клиентов из одной домашней сети напрямую на локальный IP ПК |
| `-host` | `"127.0.0.1"` | Локальный IP целевых сервисов на домашнем ПК |
| `-lan-ip` | `""` (авто) | Вручную задать локальный LAN IP домашнего ПК |
| `-allow-ports` | `""` (все) | Белый список разрешённых локальных портов на домашнем ПК (например, `"80,8096,25565"`) |
| `-upnp` | `true` | Автоматический проброс TCP и UDP портов на роутере через UPnP IGDv1/v2, NAT-PMP и PCP v2 |
| `-stun` | `"stun.cloudflare.com:3478"` | STUN-сервер (или список через запятую) для 5 мс проверки смены внешнего IP по UDP |
| `-stun-interval` | `1s` | Частота проверки внешнего IP через STUN (по умолчанию каждую секунду) |
| `-ddns-provider` | `""` | Провайдер динамического DNS: `duckdns`, `cloudflare` (TTL=60s) или `noip` |
| `-ddns-domain` | `""` | Домен для автообновления при смене IP |
| `-ddns-token` | `""` | API-токен или пароль для DDNS-провайдера |
| `-ddns-user` | `""` | Логин для No-IP / DynDNS |
| `-ddns-zone` | `""` | Zone ID для Cloudflare (при `-ddns-provider=cloudflare`) |
| `-ddns-url` | `""` | Свой Webhook URL для обновления DNS (автоматически подставляет `{ip}` и `{domain}`) |
| `-max-buf` | `16777216` (16 МБ) | Размер скользящего кольцевого буфера в RAM на одну сессию |
| `-max-mem` | `268435456` (256 МБ) | Общий лимит памяти RAM для всех буферов сессий |
| `-session-ttl` | `90s` | Время удержания «замороженных» TCP/UDP соединений в RAM во время смены IP |
| `-quic-idle-timeout` | `8s` | Таймаут простоя туннеля до переподключения |
| `-quic-keepalive` | `2s` | Интервал проверки активности туннеля (Keepalive) |
| `-cert-dir` | `""` (`.driftless-certs`) | Папка для хранения сертификатов, ключей и токена |
| `-client-ca` | `""` | Файл корневого сертификата CA на ВПС для включения двустороннего mTLS |
| `-client-cert` | `""` | Клиентский сертификат mTLS на домашнем ПК |
| `-client-key` | `""` | Закрытый ключ клиентского сертификата mTLS на домашнем ПК |
| `-proxy-protocol` | `false` | Передавать заголовок HAProxy PROXY protocol v1, чтобы локальный сервер видел реальный IP гостя |
| `-metrics` | `""` | Адрес локального сервера метрик `/metrics` (Prometheus) и `/status` (JSON) |
