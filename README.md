# driftless

[English](#english) | [Русский](#ru)

---

<a id="english"></a>

## English

**Open ports on your Home PC or Linux server (24/7 websites, Minecraft/CS2/Rust servers, Jellyfin, SSH, AnyDesk, RDP) and keep them running for months without disconnects when your dynamic IP changes.**

### Which mode do I need?
1. **No VPS (`standalone` mode):** Your ISP gives you a dynamic public ("white") IP. You run `driftless` **only on your PC or Linux box**. It opens ports on your router automatically (UPnP / NAT-PMP / PCP v2), tracks IP changes every second via STUN, updates your domain, and restores router rules automatically even if your router reboots.
2. **With a cheap VPS (`server` + `client` mode):** Your ISP puts you behind CGNAT ("gray" IP), so incoming connections to your router are blocked by the provider. Run `server` on a VPS and `client` on your Home PC. When your home IP changes, active TCP streams (downloads, websites, SSH, RDP) freeze in a 16 MB RAM ring buffer and resume from the exact byte offset with zero drops.

Download one binary from [Releases](https://github.com/ERETLY/driftless/releases):
- **Windows:** `driftless-windows-amd64.exe`
- **Linux:** `driftless-linux-amd64` (or `arm64`)
- **macOS:** `driftless-darwin-arm64`

---

### Quick Start 1: Without a VPS (only on your PC / Linux with a dynamic IP)

Suppose you want to run a website 24/7 on port `3000` (exposed on public port `80`), connect from your phone via **WebSSH** (`22`) with your own username and password (`-user admin -pass mypass123`), or connect via **AnyDesk** (`7070`) and **RDP** (`3389`).

**Step 1. Run one command on your PC:**

Windows:
```powershell
.\driftless-windows-amd64.exe standalone -ports 80:3000,22,7070,3389 -user admin -pass mypass123 -duck
```

Linux:
```bash
./driftless standalone -ports 80:3000,22,7070,3389 -user admin -pass mypass123 -duck
```

**How `-duck` works automatically:**
- **With your own free DuckDNS domain:** Run `-duck mypc:YOUR_TOKEN` **once**. `driftless` saves it in `.driftless-ddns.json`. On every future launch (even after stopping the program or rebooting your PC), just write `-duck` and it automatically loads `mypc.duckdns.org`.
- **Without any account at all:** Just write `-duck`. If no saved token is found, `driftless` automatically assigns an `<IP>.sslip.io` domain and updates it whenever your IP changes.

**Step 2. Copy the ready-to-use login details printed in your terminal:**
```text
[standalone] driftless v1.5.4 Zero-VPS mode active (LAN=192.168.1.50, Public IP=203.0.113.45)
[standalone] DDNS updated -> 203.0.113.45 (mypc.duckdns.org)
[standalone] router UPnP/NAT-PMP auto-forwarded 8 port rules to 192.168.1.50
[standalone] ==========================================================
[standalone] Ready-to-use connections (Domain: mypc.duckdns.org | IP: 203.0.113.45):
[standalone]   Website (24/7 HTTPS): https://mypc.duckdns.org:80 (or http://mypc.duckdns.org:80)
[standalone]   SSH (WebSSH/Phone)  : Host: mypc.duckdns.org | Port: 22 | User: admin  (CLI: ssh admin@mypc.duckdns.org)
[standalone]   AnyDesk Direct TCP  : mypc.duckdns.org:7070 (enter in AnyDesk app + your AnyDesk password)
[standalone]   Remote Desktop      : mypc.duckdns.org:3389 (Windows App / Microsoft Remote Desktop / mstsc)
[standalone] Connect from Phone (WebSSH / Termius):
  Host: mypc.duckdns.org   Port: 22   User: admin   Password: mypass123
[standalone] ==========================================================
```
*(Closed the window or running in the background? Run `./driftless show-token` anytime to print all addresses and saved login credentials again).*

---

### How to Log In from Android / iPhone (WebSSH, AnyDesk, RDP, Browser)

`driftless` runs **only on your PC** (or VPS + PC). You do not install `driftless` on your phone. Open the standard app on your phone and enter what is shown in your console:

#### 1. WebSSH / Termius / JuiceSSH (Run scripts & terminal on your PC from iPhone/Android)
`driftless` includes a **built-in SSHv2 server** when `-user` and `-pass` are set (or when port `22` is in `-ports` and no system `sshd` is running). You do **not** need to install Windows OpenSSH Server or generate private keys:
- **Host / IP:** `mypc.duckdns.org` (or the IP shown in console)
- **Port:** `22` *(or any other open port like `8096` - `driftless` auto-detects SSH on any port)*
- **User:** `admin` (what you passed in `-user`)
- **Password:** `mypass123` (what you passed in `-pass`)
- **Private Key:** Leave empty (not required). Once connected, you get a live PowerShell / CMD (Windows) or Bash (Linux) terminal to start/stop scripts and servers.

#### 2. AnyDesk from Android / iPhone (Direct TCP without cloud lag)
1. In AnyDesk on your PC, open **Settings -> Security -> Unlock Security Settings**, check **Enable unattended access**, and set your AnyDesk password.
2. Include port `7070` in `-ports` (e.g. `-ports 7070,22`).
3. Open the **AnyDesk** app on your Android or iPhone, and in the **Remote Address** field type:
   ```text
   mypc.duckdns.org:7070
   ```
4. Enter your AnyDesk password when prompted.

#### 3. Windows App / Microsoft Remote Desktop (Full Windows Desktop from Phone/Tablet)
1. Include port `3389` in `-ports`.
2. Open **Windows App** (or Microsoft Remote Desktop) on iPhone/Android -> tap **+** -> **Add PC**.
3. **PC Name:** `mypc.duckdns.org:3389`
4. **User Account:** Your Windows account username and password.

#### 4. Hosting a Website 24/7 for a Month (with optional password lock)
- Run your local web server (Node.js, Python, Nginx, Docker) on e.g. port `3000` and start `driftless` with `-ports 80:3000 -duck`.
- Your website is live 24/7 at `http://mypc.duckdns.org` and `https://mypc.duckdns.org:80`.
- Want to password-protect a private web dashboard? Add `-user admin -pass mypass123 -http-auth` and any browser visiting your port will prompt for that login and password.

---

### Quick Start 2: Through a VPS (works on any internet, including CGNAT / "gray" IP)

**Step 1. Run on your VPS:**
```bash
wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
chmod +x driftless
./driftless server -ports 80:3000,8096,22,7070
```
The VPS generates a secret token and prints the exact command for your Home PC right on screen (run `./driftless show-token` to view it again anytime).

**Step 2. Run that printed command on your Home PC:**
```powershell
.\driftless-windows-amd64.exe client -quic YOUR_VPS_IP:4242 -token PASSWORD -fingerprint CERT_HASH -user admin -pass mypass123
```
Done. Your Home PC website, SSH terminal, and AnyDesk are now live through `YOUR_VPS_IP`.

---

### Optional: Stealth Port Protection (`-knock`)
If you want all ports (`22`, `3389`, `7070`) completely invisible to internet scanners until you unlock them from your phone, add `-knock`:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,3389,22 -user admin -pass mypass123 -duck -knock
```
- All mapped TCP and UDP ports drop packets from unknown IPs.
- `driftless` prints a secret `https://` Magic Knock link in your terminal (view anytime via `./driftless show-token`).
- Open that link once in your phone's browser to unlock your phone's IP for **1 hour** (`-knock-ttl 1h`).
- Supports unlocking a single port only (`?port=22`), downloading a ready `.rdp` file (`/connect.rdp`), or revoking access immediately (`/revoke` or `/revoke?all=1`).

---

### Designed to Run 24/7 for Months ("Turn On and Forget")

- **Survives ISP IP changes without dropping streams:** Active TCP streams are buffered in a 16 MB ring buffer and resume from the exact byte offset; UDP sessions preserve port mappings and buffer brief link blips (with a 2-second freshness window so stale packets are never replayed).
- **Zero socket leaks over 30+ days:** Automatic idle socket deadlines clean up abandoned half-open scanner connections so file descriptors and RAM stay flat over months of uptime.
- **Survives local server restarts:** Restarting your website (`:3000`), game server (`:25565`), or UDP service while `driftless` is running never breaks listeners or active UDP sessions.
- **Survives home router reboots:** In `standalone` mode, if your router reboots and wipes its UPnP/PCP table (or finishes booting after your PC), `driftless` automatically detects the recovery and re-registers all port forwards within 60 seconds.
- **Full Stop/Restart Persistence:** Stopping `driftless` (or rebooting your PC) and starting it again with `-duck` automatically reloads your saved DuckDNS domain/token (`.driftless-ddns.json`), TLS certificates, SSH host key, and login credentials (`.driftless-certs/`).
- **Smart Ephemeral Port Bridging & Single-Port Auto-Routing:** Works even if a local service is already bound to `0.0.0.0`, and automatically routes SSH (`SSH-2.0-`) to `:22` and RDP (`0x03 0x00`) to `:3389` on any mapped TCP port.

---

### All CLI Flags Reference

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Ports to open: `8096,25565`, `80:3000`, or `127.0.0.1:8080:3000`. Supports `/tcp`, `/udp`, `/https`. |
| `-duck` | `""` | Automatic domain & TLS certificate: pass `-duck mypc:TOKEN` once (saved to `.driftless-ddns.json`), then just `-duck`. |
| `-user` / `-pass` | `""` | Username and password for built-in SSH server (WebSSH/Termius) and optional `-http-auth` (saved automatically). |
| `-auth` | `""` | Shorthand `"user:password"` for `-user` and `-pass`. |
| `-http-auth` | `false` | Require HTTP Basic Auth (`-user`/`-pass`) on forwarded HTTP/VHost web ports. |
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
| `-ddns-user` / `-ddns-zone` / `-ddns-url` | `""` | Username (No-IP), Zone ID (Cloudflare) or custom webhook URL (`{ip}`). |
| `-max-buf` / `-max-mem` | `16 MB` / `256 MB` | Per-session ring buffer size and global memory cap across all sessions. |
| `-session-ttl` | `90s` | How long to hold frozen TCP sessions while home internet reconnects. |

---

<a id="ru"></a>

## Русский

[Read in English ↑](#english)

**Открой порты на домашнем ПК или Linux-сервере (свой сайт 24/7, игровой сервер Minecraft/CS2/Rust, Jellyfin, SSH с телефона, AnyDesk, удаленный рабочий стол RDP) один раз на месяц - без обрывов связи при смене динамического IP.**

### Какой режим выбрать?
1. **Вообще без ВПС (`standalone`):** Если провайдер дает динамический белый IP. Ты запускаешь один файл **только на своем ПК или Linux**. Программа сама открывает порты на роутере (UPnP / NAT-PMP / PCP v2), каждую секунду следит за внешним IP через STUN, обновляет домен и сама восстанавливает проброс портов даже после перезагрузки роутера.
2. **Через дешевый ВПС (`server` + `client`):** Если у провайдера серый IP (CGNAT) и входящие подключения из интернета заблокированы. Запускаешь `server` на ВПС и `client` дома на ПК. При смене домашнего IP все активные TCP-соединения (загрузки, стримы, сайты, SSH) удерживаются в буфере памяти 16 МБ и продолжают работу с точного байта без разрыва.

Скачай один готовый файл под свою ОС из [Releases](https://github.com/ERETLY/driftless/releases):
- **Windows:** `driftless-windows-amd64.exe`
- **Linux:** `driftless-linux-amd64` (или `arm64`)
- **macOS:** `driftless-darwin-arm64`

---

### Способ 1. Без ВПС - только на своем ПК или Linux (если IP динамический)

Допустим, ты хочешь держать свой сайт 24/7 на порту `3000` (открыть его наружу на `80` порту), подключаться к ПК с телефона через **WebSSH** (`22`) по своему логину и паролю (`-user admin -pass mypass123`), а также заходить через **AnyDesk** (`7070`) или **RDP** (`3389`).

**Шаг 1. Запусти одну команду на своем ПК:**

На Windows:
```powershell
.\driftless-windows-amd64.exe standalone -ports 80:3000,22,7070,3389 -user admin -pass mypass123 -duck
```

На Linux:
```bash
./driftless standalone -ports 80:3000,22,7070,3389 -user admin -pass mypass123 -duck
```

**Как работает флаг `-duck` (ничего настраивать вручную не нужно):**
- **Если есть бесплатный домен на DuckDNS:** Один раз запусти с токеном: `-duck mypc:ТВОЙ_ТОКЕН`. Программа сама сохранит его в файл `.driftless-ddns.json`. При всех следующих запусках (даже после остановки программы или перезагрузки ПК) пиши просто `-duck` - она сама подхватит твой домен `mypc.duckdns.org`.
- **Если токена вообще нет:** Пиши просто `-duck`. Если сохраненного токена нет, программа автоматически создаст рабочий домен `<ТВОЙ_IP>.sslip.io` + TLS-сертификат и будет обновлять его при каждой смене IP.

**Шаг 2. Программа сразу выведет в консоль готовые данные для входа:**
```text
[standalone] driftless v1.5.4 Zero-VPS mode active (LAN=192.168.1.50, Public IP=203.0.113.45)
[standalone] DDNS updated -> 203.0.113.45 (mypc.duckdns.org)
[standalone] router UPnP/NAT-PMP auto-forwarded 8 port rules to 192.168.1.50
[standalone] ==========================================================
[standalone] Ready-to-use connections (Domain: mypc.duckdns.org | IP: 203.0.113.45):
[standalone]   Website (24/7 HTTPS): https://mypc.duckdns.org:80 (or http://mypc.duckdns.org:80)
[standalone]   SSH (WebSSH/Phone)  : Host: mypc.duckdns.org | Port: 22 | User: admin  (CLI: ssh admin@mypc.duckdns.org)
[standalone]   AnyDesk Direct TCP  : mypc.duckdns.org:7070 (enter in AnyDesk app + your AnyDesk password)
[standalone]   Remote Desktop      : mypc.duckdns.org:3389 (Windows App / Microsoft Remote Desktop / mstsc)
[standalone] Connect from Phone (WebSSH / Termius):
  Host: mypc.duckdns.org   Port: 22   User: admin   Password: mypass123
[standalone] ==========================================================
```
*(Если закрыл окно или перезапустил консоль - в любой момент выполни `./driftless show-token`, и программа снова покажет все твои ссылки, логин и пароль).*

---

### Как войти с телефона (Android / iPhone) через WebSSH, AnyDesk, RDP или браузер

Сама `driftless` стоит **только на твоем ПК** (или ВПС + ПК). На телефон ничего необычного ставить не нужно - открываешь привычное приложение и вводишь данные из консоли:

#### 1. Вход через WebSSH / Termius (управление ПК и запуск скриптов с iPhone / Android)
В `driftless` уже встроен собственный **SSH-сервер**, когда ты указываешь `-user` и `-pass` (или открываешь порт `22`). Тебе **не нужно** устанавливать OpenSSH в Windows или возиться с приватными ключами:
- Открываешь **WebSSH** (или Termius / JuiceSSH) на телефоне и нажимаешь **Add Connection**:
  - **Host / IP:** `mypc.duckdns.org` (или IP из консоли)
  - **Port:** `22` *(или любой другой открытый порт, например `8096` - `driftless` сама распознает SSH на любом порту)*
  - **User (Логин):** `admin` (то, что ты указал во флаге `-user`)
  - **Password (Пароль):** `mypass123` (то, что ты указал во флаге `-pass`)
  - **Private Key (Приватный ключ):** оставляешь пустым (не нужен).
- Нажимаешь **Connect** - и сразу попадаешь в командную строку своего ПК (PowerShell / CMD на Windows или Bash на Linux), где можешь запускать любые скрипты, ботов и серверы.

#### 2. Вход через AnyDesk с Android / iPhone (напрямую без лагов)
1. В AnyDesk на ПК открой **Настройки -> Безопасность -> Разблокировать настройки безопасности**, включи **Неконтролируемый доступ (Unattended Access)** и задай постоянный пароль.
2. Добавь порт `7070` в `-ports` (например: `-ports 7070,22 -duck`).
3. Открой приложение **AnyDesk** на Android или iPhone и в строке адреса (вместо 9 цифр ID) введи:
   ```text
   mypc.duckdns.org:7070
   ```
4. Введи свой пароль от AnyDesk - подключение пойдет напрямую к твоему ПК.

#### 3. Вход на рабочий стол Windows (Windows App / Microsoft Remote Desktop)
1. Добавь порт `3389` в `-ports`.
2. На телефоне открой **Windows App** (Microsoft Remote Desktop) -> нажми **+** -> **Add PC**.
3. **Имя ПК (PC Name):** `mypc.duckdns.org:3389`
4. **Учетная запись:** логин и пароль от твоей учетной записи Windows.

#### 4. Свой сайт 24/7 на месяц (и закрытие сайта паролем при желании)
- Запусти свой сайт (Node.js, Python, Nginx, Docker) например на порту `3000` и запусти `driftless` с `-ports 80:3000 -duck`.
- Сайт работает круглосуточно по адресу `http://mypc.duckdns.org` и `https://mypc.duckdns.org:80` и сам обновляет IP при любых переподключениях провайдера.
- Если хочешь закрыть сайт или веб-панель своим логином и паролем, добавь `-user admin -pass mypass123 -http-auth` - браузер при входе спросит этот логин и пароль.

---

### Способ 2. Через ВПС (работает везде, даже если дома серый IP / CGNAT)

**Шаг 1. Запусти на ВПС:**
```bash
wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
chmod +x driftless
./driftless server -ports 80:3000,8096,22,7070
```
Сервер сам сгенерирует пароль и выведет на экран готовую строчку для запуска на домашнем ПК (посмотреть ее снова можно командой `./driftless show-token`).

**Шаг 2. Скопируй эту команду и запусти на домашнем ПК:**
```powershell
.\driftless-windows-amd64.exe client -quic IP_ВПС:4242 -token ПАРОЛЬ -fingerprint ОТПЕЧАТОК -user admin -pass mypass123
```
Готово. Твой сайт, терминал WebSSH и AnyDesk доступны по адресу `IP_ВПС`.

---

### По желанию: Секретная защита портов от ботов (`-knock`)
Если не хочешь, чтобы порты `22` (SSH), `7070` (AnyDesk) или `3389` (RDP) были видны сканерам в интернете, добавь флаг `-knock`:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,3389,22 -user admin -pass mypass123 -duck -knock
```
- Все порты полностью закрыты для чужих IP.
- В консоли появится секретная `https://` ссылка (посмотреть снова: `./driftless show-token`).
- Открываешь эту ссылку один раз в браузере на телефоне - твой мобильный IP разблокируется на **1 час** (`-knock-ttl 1h`), и ты спокойно заходишь через WebSSH, AnyDesk или RDP.
- Можно открыть только один порт (`?port=22`), скачать готовый `.rdp` ярлык (`/connect.rdp`) или мгновенно закрыть доступ обратно (`/revoke` или `/revoke?all=1`).

---

### Работа 24/7 («Врубил и забыл на месяц»)

- **Не рвет соединения при смене IP провайдером:** Активные TCP-потоки (загрузки, стримы, SSH, RDP) ждут переподключения в кольцевом буфере 16 МБ и продолжаются с точного байта. Свежие UDP-пакеты буферизуются в окне до 2 секунд (старые пакеты автоматически отбрасываются).
- **Никаких утечек памяти и сокетов за 30+ дней:** Зависшие или брошенные сканерами соединения автоматически очищаются по таймауту неактивности, поэтому потребление памяти и файловых дескрипторов остается стабильным месяцами.
- **Все сохраняется при остановке и перезапуске:** Если ты остановил программу или перезагрузил ПК, при следующем запуске с `-duck` автоматически подхватываются сохраненный домен/токен DuckDNS (`.driftless-ddns.json`), TLS-сертификаты, ключ SSH-сервера и логин/пароль (`.driftless-certs/`).
- **Не падает при перезапуске твоих серверов:** Ты можешь сколько угодно перезапускать свой сайт (`:3000`), игровой сервер (`:25565`) или UDP-сервер на ПК - `driftless` продолжает работать без перезапуска.
- **Переживает перезагрузку домашнего роутера:** Если роутер перезагрузился и сбросил таблицу портов UPnP/PCP (или включился позже компьютера), `driftless` сам определит это и заново откроет все порты в течение 60 секунд.
- **Авто-распознавание SSH и RDP на любом порту:** Можно подключиться клиентом WebSSH или RDP к любому открытому TCP-порту (например `8096` или `80`) - программа по первым байтам сама перенаправит SSH на встроенный терминал (`:22`), а RDP на `:3389`.

---

### Полный справочник флагов

| Флаг | По умолчанию | Описание |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Порты: `8096,25565`, `80:3000` или локально `127.0.0.1:8080:3000`. Поддерживает `/tcp`, `/udp`, `/https`. |
| `-duck` | `""` | Авто-домен и сертификат: один раз укажи `-duck домен:токен` (сохранится сам), дальше пиши просто `-duck`. |
| `-user` / `-pass` | `""` | Логин и пароль для встроенного SSH-сервера (WebSSH/Termius) и `-http-auth` (сохраняются автоматически). |
| `-auth` | `""` | Короткая запись `"логин:пароль"` вместо `-user` и `-pass`. |
| `-http-auth` | `false` | Защитить открытые HTTP/VHost веб-порты паролем (`-user` и `-pass`). |
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
