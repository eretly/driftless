# driftless

[English](#english) | [Русский](#ru)

---

<a id="english"></a>

## English

**Open ports on your Home PC or Linux server (websites, Minecraft/CS2/Rust servers, Jellyfin, SSH, RDP) and keep them running 24/7 without disconnects when your dynamic IP changes.**

### Which mode do I need?
1. **No VPS (`standalone` mode):** Your ISP gives you a dynamic public ("white") IP. You run `driftless` **only on your PC or Linux box**. It opens ports on your router automatically (UPnP / NAT-PMP / PCP v2), tracks IP changes every second via STUN, updates your domain, and restores router rules automatically even if your router reboots.
2. **With a cheap VPS (`server` + `client` mode):** Your ISP puts you behind CGNAT ("gray" IP), so incoming connections to your router are blocked by the provider. Run `server` on a VPS and `client` on your Home PC. When your home IP changes, active TCP streams (downloads, websites, SSH, RDP) freeze in a 16 MB RAM ring buffer and resume from the exact byte offset with zero drops.

Download one binary from [Releases](https://github.com/ERETLY/driftless/releases):
- **Windows:** `driftless-windows-amd64.exe`
- **Linux:** `driftless-linux-amd64` (or `arm64`)
- **macOS:** `driftless-darwin-arm64`

---

### Quick Start 1: Without a VPS (only on your PC / Linux with a dynamic IP)

Suppose you have a website on port `3000` (want it on public port `80`), a game/media server on `8096`, and SSH on `22`.

**Step 1. Run one command on your PC:**

Windows:
```powershell
.\driftless-windows-amd64.exe standalone -ports 80:3000,8096,22 -duck
```

Linux:
```bash
./driftless standalone -ports 80:3000,8096,22 -duck
```

**How `-duck` works automatically:**
- **With your own free DuckDNS domain:** Run `-duck mypc:YOUR_TOKEN` **once**. `driftless` saves it in `.driftless-ddns.json`. On every future launch, just write `-duck` and it automatically loads `mypc.duckdns.org`.
- **Without any account at all:** Just write `-duck`. If no saved token is found, `driftless` automatically assigns an `<IP>.sslip.io` domain and updates it whenever your IP changes.

**Step 2. Copy the ready-to-use addresses printed in your terminal:**
```text
[standalone] driftless v1.5.4 Zero-VPS mode active (LAN=192.168.1.50, Public IP=203.0.113.45)
[standalone] DDNS updated -> 203.0.113.45 (mypc.duckdns.org)
[standalone] router UPnP/NAT-PMP auto-forwarded 6 port rules to 192.168.1.50
[standalone] ==========================================================
[standalone] Ready-to-use connections (Domain: mypc.duckdns.org | IP: 203.0.113.45):
[standalone]   Website (HTTPS)   : https://mypc.duckdns.org:80 (or http://mypc.duckdns.org:80)
[standalone]   Port :8096  -> :8096  : https://mypc.duckdns.org:8096  (TCP/UDP: mypc.duckdns.org:8096)
[standalone]   SSH Terminal      : ssh user@mypc.duckdns.org
[standalone] ==========================================================
```
*(Forgot your addresses or running in the background? Run `./driftless show-token` anytime to print them again).*

---

### Quick Start 2: Through a VPS (works on any internet, including CGNAT / "gray" IP)

**Step 1. Run on your VPS:**
```bash
wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
chmod +x driftless
./driftless server -ports 80:3000,8096,25565
```
The VPS generates a secret token and prints the exact command for your Home PC right on screen (run `./driftless show-token` to view it again anytime).

**Step 2. Run that printed command on your Home PC:**
```powershell
.\driftless-windows-amd64.exe client -quic YOUR_VPS_IP:4242 -token PASSWORD -fingerprint CERT_HASH
```
Done. Your Home PC services are now live at `http://YOUR_VPS_IP`, `YOUR_VPS_IP:8096`, and `YOUR_VPS_IP:25565`.

---

### How to connect from an iPhone, Android, or another laptop

`driftless` runs **only on your PC** (or VPS + PC). You do not install anything on your phone. Just open your normal app and enter your domain (`mypc.duckdns.org`) or IP:

| What you want to access on your PC | Port in `-ports` | App on iPhone / Android / Laptop | What to enter in the app |
| :--- | :--- | :--- | :--- |
| **Your Website / Web App** | `80:3000` or `443:3000` | Safari / Chrome | `http://mypc.duckdns.org` or `https://mypc.duckdns.org` |
| **SSH / SFTP Terminal & Files** | `22` | **WebSSH** / Termius / Blink | Host: `mypc.duckdns.org`, Port: `22`, your normal PC username & password (or SSH key) |
| **Windows Remote Desktop (RDP)** | `3389` | **Windows App** (Microsoft Remote Desktop) | PC Name: `mypc.duckdns.org:3389`, your Windows login & password |
| **AnyDesk (direct lag-free TCP)** | `7070` | **AnyDesk** | In address bar instead of 9-digit ID: `mypc.duckdns.org:7070` |
| **Jellyfin / Plex Media Server** | `8096` | **Jellyfin** / Swiftfin / Infuse | `http://mypc.duckdns.org:8096` |
| **Game Server (Minecraft / CS2 / Rust)** | `25565` / `27015` | Game client | `mypc.duckdns.org:25565` |

*Note on SSH Private Keys in WebSSH:* `driftless` itself does not require any special key on your phone. In WebSSH, simply enter your normal Windows/Linux account password, or use your standard SSH key (`id_ed25519` / `id_rsa`) if you configured key login on your PC.

#### Optional: Stealth Port Protection (`-knock`)
If you do not want ports like `22` (SSH) or `3389` (RDP) visible to internet scanners, add `-knock`:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,3389,22 -duck -knock
```
- All mapped TCP and UDP ports stay completely closed to everyone except authorized IPs.
- `driftless` prints a secret `https://` Magic Knock link in your terminal (view anytime via `./driftless show-token`).
- Open that link once on your phone to unlock your phone's IP for **1 hour** (`-knock-ttl 1h`).
- Supports unlocking a single port only (`?port=22`), downloading a ready `.rdp` file (`/connect.rdp`), or revoking your IP immediately (`/revoke` or `/revoke?all=1`).

---

### Designed to Run 24/7 for Months ("Turn On and Forget")

- **Survives ISP IP changes without dropping streams:** Active TCP streams are buffered in a 16 MB ring buffer and resume from the exact byte offset; UDP sessions preserve port mappings and buffer brief link blips (with a 2-second freshness window so stale packets are never replayed).
- **Survives local server restarts:** Restarting your website (`:3000`), game server (`:25565`), or UDP service while `driftless` is running never breaks listeners or active UDP sessions.
- **Survives home router reboots:** In `standalone` mode, if your router reboots and wipes its UPnP/PCP table (or finishes booting after your PC), `driftless` automatically detects the recovery and re-registers all port forwards.
- **Smart Ephemeral Port Bridging:** Even if a local program (`3389`, `8096`, `25565`) is already bound to `0.0.0.0` on the same PC, `standalone` mode automatically bridges router ports without `address already in use` errors.
- **Single-Port Auto-Routing:** If you expose multiple ports (e.g. `-ports 8096,22,3389`), connecting with an SSH client or RDP client to port `8096` automatically routes SSH (`SSH-2.0-`) to `:22` and RDP (`0x03 0x00`) to `:3389`.

---

### All CLI Flags Reference

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Ports to open: `8096,25565`, `80:3000`, or `127.0.0.1:8080:3000`. Supports `/tcp`, `/udp`, `/https`. |
| `-duck` | `""` | Automatic domain & TLS certificate: pass `-duck mypc:TOKEN` once (saved to `.driftless-ddns.json`), then just `-duck`. |
| `-udp` | `true` | Forward UDP alongside TCP on all ports (`-udp=false` for TCP only). |
| `-quic` | `"0.0.0.0:4242"` | Tunnel address on VPS or comma-separated failover list on Home PC (`vps1:4242,vps2:4242`). |
| `-transport` | `"auto"` | Tunnel transport: `"auto"` (QUIC with automatic TCP-Mux fallback), `"quic"`, or `"tcp"`. |
| `-token` | auto | Shared password or comma-separated rotation list (`"new_tok,old_tok"`). |
| `-fingerprint` | `""` | VPS SHA-256 certificate fingerprint (auto-filled in the generated client command). |
| `-knock` | `false` | Enable HTTPS Magic Knock stealth gatekeeper (per-port `?port=22`, 1h TTL, `/revoke`). |
| `-knock-token` | auto | Custom secret for `-knock` URL (auto-generated and saved in `.driftless-certs/knock.secret` if omitted). |
| `-knock-ttl` | `1h` | How long an IP stays unlocked after opening the Magic Knock URL (default `1h`). |
| `-tls` | `false` | Enable automatic HTTPS/TLS termination on mapped TCP ports. |
| `-vhosts` | `""` | Route domains and URL paths to local ports: `"site.com:3000,site.com/api:4000,*.site.com:5000"`. |
| `-vhost-addr` / `-https` | `":80"` / `""` | HTTP and HTTPS listen addresses for `-vhosts`. |
| `-tls-cert` / `-tls-key` | `""` | Custom `.pem` TLS certificate and private key files. |
| `-direct` | `":8888"` | Direct home Wi-Fi/LAN HTTP redirector bypassing the VPS (`""` to disable). |
| `-host` | `"127.0.0.1"` | Local target IP on your Home PC. |
| `-allow-ports` | `""` | Whitelist allowed local target ports on your Home PC (e.g. `"80,3000,8096,25565"`). |
| `-allow-ips` | `""` | IP/CIDR ACL whitelist for public listeners (e.g. `"192.168.1.0/24,203.0.113.5"`). |
| `-client-ca` / `-client-cert` / `-client-key` | `""` | Optional mutual TLS (mTLS) client certificate verification between VPS and Home PC. |
| `-proxy-protocol` | `false` | Prepend HAProxy PROXY protocol v1 header so local backends see the real client IP. |
| `-metrics` | `""` | Observability listen address for `/metrics` (Prometheus) and `/status` (JSON), e.g. `"127.0.0.1:9090"`. |
| `-upnp` | `true` | Automatically open ports on home router via UPnP IGD / NAT-PMP / PCP v2 (`standalone` mode). |
| `-stun` | `"stun.cloudflare.com:3478"` | STUN server(s) for external IP change detection (`standalone` mode). |
| `-stun-interval` | `1s` | How often to check external IP via STUN (`standalone` mode). |
| `-ddns-provider` | `""` | Additional DDNS providers: `"duckdns"`, `"cloudflare"`, or `"noip"`. |
| `-ddns-domain` / `-ddns-token` | `""` | Domain and API token when using `-ddns-provider`. |
| `-ddns-user` / `-ddns-zone` / `-ddns-url` | `""` | Username (No-IP), Zone ID (Cloudflare), or custom webhook URL (`{ip}`). |
| `-max-buf` / `-max-mem` | `16 MB` / `256 MB` | Per-session ring buffer size and global memory cap across all sessions. |
| `-session-ttl` | `90s` | How long to hold frozen TCP sessions while home internet reconnects. |

---

<a id="ru"></a>

## Русский

[Read in English ↑](#english)

**Открой порты на домашнем ПК или Linux-сервере (свой сайт, игровой сервер Minecraft/CS2/Rust, Jellyfin, SSH, удаленный рабочий стол RDP) один раз на месяц 24/7 - без обрывов связи при смене динамического IP.**

### Какой режим выбрать?
1. **Вообще без ВПС (`standalone`):** Если провайдер дает динамический белый IP. Ты запускаешь один файл **только на своем ПК или Linux**. Программа сама открывает порты на роутере (UPnP / NAT-PMP / PCP v2), каждую секунду следит за внешним IP через STUN, обновляет домен и сама восстанавливает проброс портов даже после перезагрузки роутера.
2. **Через дешевый ВПС (`server` + `client`):** Если у провайдера серый IP (CGNAT) и входящие подключения из интернета заблокированы. Запускаешь `server` на ВПС и `client` дома на ПК. При смене домашнего IP все активные TCP-соединения (загрузки, стримы, сайты, SSH) удерживаются в буфере памяти 16 МБ и продолжают работу с точного байта без разрыва.

Скачай один готовый файл под свою ОС из [Releases](https://github.com/ERETLY/driftless/releases):
- **Windows:** `driftless-windows-amd64.exe`
- **Linux:** `driftless-linux-amd64` (или `arm64`)
- **macOS:** `driftless-darwin-arm64`

---

### Способ 1. Без ВПС - только на своем ПК или Linux (если IP динамический)

Допустим, у тебя на ПК запущен сайт на порту `3000` (хочешь открыть его на `80` порту), медиасервер на `8096` и SSH на `22`.

**Шаг 1. Запусти одну команду на своем ПК:**

На Windows:
```powershell
.\driftless-windows-amd64.exe standalone -ports 80:3000,8096,22 -duck
```

На Linux:
```bash
./driftless standalone -ports 80:3000,8096,22 -duck
```

**Как работает флаг `-duck` (ничего настраивать вручную не нужно):**
- **Если есть бесплатный домен на DuckDNS:** Один раз запусти с токеном: `-duck mypc:ТВОЙ_ТОКЕН`. Программа сама сохранит его в файл `.driftless-ddns.json`. При всех следующих запусках пиши просто `-duck` - она сама подхватит твой домен `mypc.duckdns.org`.
- **Если токена вообще нет:** Пиши просто `-duck`. Если сохраненного токена нет, программа автоматически выдаст тебе рабочий домен `<ТВОЙ_IP>.sslip.io` + TLS-сертификат и будет обновлять его при каждой смене IP.

**Шаг 2. Программа сразу выведет в консоль готовые ссылки и команды для входа:**
```text
[standalone] driftless v1.5.4 Zero-VPS mode active (LAN=192.168.1.50, Public IP=203.0.113.45)
[standalone] DDNS updated -> 203.0.113.45 (mypc.duckdns.org)
[standalone] router UPnP/NAT-PMP auto-forwarded 6 port rules to 192.168.1.50
[standalone] ==========================================================
[standalone] Ready-to-use connections (Domain: mypc.duckdns.org | IP: 203.0.113.45):
[standalone]   Website (HTTPS)   : https://mypc.duckdns.org:80 (or http://mypc.duckdns.org:80)
[standalone]   Port :8096  -> :8096  : https://mypc.duckdns.org:8096  (TCP/UDP: mypc.duckdns.org:8096)
[standalone]   SSH Terminal      : ssh user@mypc.duckdns.org
[standalone] ==========================================================
```
*(Если закрыл окно или запустил в фоне - в любой момент выполни `./driftless show-token`, и программа снова покажет все твои ссылки и адреса).*

---

### Способ 2. Через ВПС (работает везде, даже если дома серый IP / CGNAT)

**Шаг 1. Запусти на ВПС:**
```bash
wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
chmod +x driftless
./driftless server -ports 80:3000,8096,25565
```
Сервер сам сгенерирует пароль и выведет на экран готовую строчку для запуска на домашнем ПК (посмотреть ее снова можно командой `./driftless show-token`).

**Шаг 2. Скопируй эту команду и запусти на домашнем ПК:**
```powershell
.\driftless-windows-amd64.exe client -quic IP_ВПС:4242 -token ПАРОЛЬ -fingerprint ОТПЕЧАТОК
```
Готово. Твой сайт, медиасервер или игровой сервер доступны по адресу `http://IP_ВПС`, `IP_ВПС:8096` и `IP_ВПС:25565`.

---

### Как зайти на свой ПК с телефона (iPhone / Android) или другого ноутбука

Программа `driftless` стоит **только на твоем ПК** (или ВПС + ПК). На телефон ничего скачивать не нужно - просто открываешь нужное приложение и вводишь свой адрес (`mypc.duckdns.org` или IP из консоли):

| Что открываем на ПК | Какой порт указать в `-ports` | Приложение на телефоне / ПК | Что вводить для входа |
| :--- | :--- | :--- | :--- |
| **Свой сайт / веб-панель** | `80:3000` или `443:3000` | Safari / Chrome | `http://mypc.duckdns.org` или `https://mypc.duckdns.org` |
| **Терминал SSH и файлы SFTP** | `22` | **WebSSH** / Termius | Host: `mypc.duckdns.org`, Port: `22`, обычный логин и пароль от твоего ПК |
| **Рабочий стол Windows (RDP)** | `3389` | **Windows App** (Microsoft Remote Desktop) | Имя ПК: `mypc.duckdns.org:3389`, логин и пароль Windows |
| **AnyDesk напрямую без лагов** | `7070` | **AnyDesk** | В адресной строке вместо цифр ID: `mypc.duckdns.org:7070` |
| **Фильмы и медиа (Jellyfin / Plex)** | `8096` | **Jellyfin** / Swiftfin / Infuse | `http://mypc.duckdns.org:8096` |
| **Игровой сервер (Minecraft / CS2 / Rust)** | `25565` / `27015` | Клиент игры | `mypc.duckdns.org:25565` |

*Нужен ли приватный ключ в WebSSH?* Для самой `driftless` никакой ключ не нужен - вводишь обычный пароль от своей учетной записи Windows/Linux (или свой стандартный SSH-ключ `id_ed25519`, если сам настроил вход по ключу).

#### По желанию: Секретная защита портов от ботов (`-knock`)
Если не хочешь, чтобы порты `22` (SSH) или `3389` (RDP) были видны сканерам в интернете, добавь флаг `-knock`:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,3389,22 -duck -knock
```
- Все порты полностью закрыты для чужих IP.
- В консоли появится секретная `https://` ссылка (посмотреть снова: `./driftless show-token`).
- Открываешь эту ссылку один раз на телефоне - твой мобильный IP разблокируется на **1 час** (`-knock-ttl 1h`), и ты спокойно заходишь через WebSSH или RDP.
- Можно открыть только один порт (`?port=22`), скачать готовый `.rdp` ярлык (`/connect.rdp`) или мгновенно закрыть доступ обратно (`/revoke` или `/revoke?all=1`).

---

### Работа 24/7 («Врубил и забыл на месяц»)

- **Не рвет соединения при смене IP провайдером:** Активные TCP-потоки (загрузки, стримы, SSH, RDP) ждут переподключения в кольцевом буфере 16 МБ и продолжаются с точного байта. Свежие UDP-пакеты буферизуются в окне до 2 секунд (старые пакеты автоматически отбрасываются).
- **Не падает при перезапуске твоих серверов:** Ты можешь сколько угодно перезапускать свой сайт (`:3000`), игровой сервер (`:25565`) или UDP-сервер на ПК - `driftless` продолжает работать без перезапуска.
- **Переживает перезагрузку домашнего роутера:** Если роутер перезагрузился и сбросил таблицу портов UPnP/PCP (или включился позже компьютера), `driftless` сам определит это и заново откроет все порты.
- **Не конфликтует с уже занятыми портами:** Если порт (`3389`, `8096`, `25565`) уже занят самой программой на `0.0.0.0`, режим `standalone` автоматически включает локальный мост без ошибки `address already in use`.
- **Авто-распознавание SSH и RDP на любом порту:** Если открыто несколько портов (например `-ports 8096,22,3389`), можно подключиться клиентом SSH или RDP прямо на порт `8096` - программа по первым байтам сама перенаправит SSH на `:22`, а RDP на `:3389`.

---

### Полный справочник флагов

| Флаг | По умолчанию | Описание |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Порты: `8096,25565`, `80:3000` или локально `127.0.0.1:8080:3000`. Поддерживает `/tcp`, `/udp`, `/https`. |
| `-duck` | `""` | Авто-домен и сертификат: один раз укажи `-duck домен:токен` (сохранится сам), дальше пиши просто `-duck`. |
| `-udp` | `true` | Открывать UDP вместе с TCP на всех портах (`-udp=false` оставит только TCP). |
| `-quic` | `"0.0.0.0:4242"` | Адрес туннеля на ВПС или список ВПС через запятую на ПК (`vps1:4242,vps2:4242`). |
| `-transport` | `"auto"` | Транспорт туннеля: `"auto"` (QUIC с авто-переходом на TCP-Mux), `"quic"` или `"tcp"`. |
| `-token` | создается сам | Общий пароль (или список через запятую для ротации без разрыва `"новый,старый"`). |
| `-fingerprint` | `""` | SHA-256 отпечаток сертификата ВПС (сам подставляется в готовую команду). |
| `-knock` | `false` | Включить HTTPS защиту портов по секретной ссылке (TTL 1 час, `?port=22`, отзыв `/revoke`). |
| `-knock-token` | создается сам | Свой секрет для ссылки `-knock` (если не указать, сохраняется в `.driftless-certs/knock.secret`). |
| `-knock-ttl` | `1h` | На сколько времени открывать доступ для IP после перехода по ссылке `-knock` (по умолчанию `1h`). |
| `-tls` | `false` | Включить HTTPS/TLS сразу на всех открытых TCP-портах. |
| `-vhosts` | `""` | Маршрутизация доменов и путей по портам: `"site.ru:3000,site.ru/api:4000,*.site.ru:5000"`. |
| `-vhost-addr` / `-https` | `":80"` / `""` | Порты HTTP и HTTPS для доменного режима `-vhosts`. |
| `-tls-cert` / `-tls-key` | `""` | Путь к своим файлам сертификата и ключа `.pem`. |
| `-direct` | `":8888"` | Прямое подключение дома по Wi-Fi/LAN в обход ВПС (`""` - выключить). |
| `-host` | `"127.0.0.1"` | Локальный IP-адрес назначения на домашнем ПК. |
| `-allow-ports` | `""` | Белый список разрешенных локальных портов на ПК (например, `"80,3000,8096,25565"`). |
| `-allow-ips` | `""` | Разрешить входящие подключения только с указанных IP или подсетей CIDR (`"192.168.1.0/24,203.0.113.5"`). |
| `-client-ca` / `-client-cert` / `-client-key` | `""` | Опциональная проверка клиентских сертификатов mTLS между ВПС и домашним ПК. |
| `-proxy-protocol` | `false` | Передавать реальный IP клиента локальному серверу через заголовок HAProxy PROXY protocol v1. |
| `-metrics` | `""` | Адрес сервера метрик `/metrics` (Prometheus) и `/status` (JSON), например `"127.0.0.1:9090"`. |
| `-upnp` | `true` | Авто-открытие портов на домашнем роутере через UPnP / NAT-PMP / PCP v2 (`standalone`). |
| `-stun` | `"stun.cloudflare.com:3478"` | STUN-сервер (или список через запятую) для проверки внешнего IP (`standalone`). |
| `-stun-interval` | `1s` | Частота проверки внешнего IP по STUN (`standalone`). |
| `-ddns-provider` | `""` | Другие DDNS-провайдеры: `"duckdns"`, `"cloudflare"` или `"noip"`. |
| `-ddns-domain` / `-ddns-token` | `""` | Домен и токен при использовании `-ddns-provider`. |
| `-ddns-user` / `-ddns-zone` / `-ddns-url` | `""` | Логин (No-IP), Zone ID (Cloudflare) или свой вебхук (`{ip}`). |
| `-max-buf` / `-max-mem` | `16 МБ` / `256 МБ` | Лимит буфера памяти на одно соединение и общий лимит на всю программу. |
| `-session-ttl` | `90s` | Сколько секунд удерживать активные соединения при переподключении интернета дома. |

## License

[MIT](LICENSE)
