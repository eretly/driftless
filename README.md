# driftless

> [🇺🇸 English](#english) | [🇷🇺 Русский](#ru)

---

<a id="english"></a>

## English

**Open ports to your Home PC and host game servers, websites, Jellyfin, or Ollama without disconnects when your home IP changes.**

### What problem does this solve?
Suppose you run a Minecraft/CS2 server, Jellyfin media server, local AI (Ollama), or a website on your Home PC:
1. Your ISP gives you a "gray" IP (CGNAT), so nobody from the internet can connect to your PC at all.
2. Or your ISP gives you a dynamic IP that changes every few hours or days. Every time your IP changes, standard tunnels (`frp`, `ngrok`, `Cloudflare Tunnel`) drop all active streams, downloads, and game connections.

`driftless` fixes both problems. When your home IP changes, it holds active connections in memory for a moment and switches them to your new IP seamlessly - video streams, file downloads, and games keep running without dropping.

---

### How to run (2 ways)

Download the file for your system from [Releases](https://github.com/ERETLY/driftless/releases) (any mode works on Windows, Linux, and macOS):
- For Linux (VPS or Home PC): `driftless-linux-amd64`
- For Windows (Home PC or Windows VPS): `driftless-windows-amd64.exe`
- For macOS: `driftless-darwin-arm64`

---

#### Way 1. With a cheap VPS (Works on ANY internet, including CGNAT / "gray" IP)

You rent the cheapest $2 VPS with a static IP (Linux or Windows), run one file on the VPS and the same file on your Home PC.

**1. Run on your VPS:**
Just list the ports you want to open separated by commas (both TCP and UDP open automatically).

If your VPS is on **Linux**:
```bash
wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
chmod +x driftless
./driftless server -ports 8096,25565
```

If your VPS is on **Windows**:
```powershell
.\driftless-windows-amd64.exe server -ports 8096,25565
```
*(You don't need to invent a password or look up your IP. The server will generate a password and print a ready-to-copy command for your Home PC right in the terminal.)*

**2. Copy that line and run it on your Home PC (Windows / Linux / macOS):**
```powershell
.\driftless-windows-amd64.exe client -quic YOUR_VPS_IP:4242 -token PASSWORD_FROM_TERMINAL
```
That's it. Anyone connecting to `YOUR_VPS_IP:8096` or `YOUR_VPS_IP:25565` lands on your Home PC.

---

#### Way 2. Without a VPS at all (Runs only on your Home PC)

If your ISP gives you a public ("white") dynamic IP - even if it changes every 10 minutes - you don't need to buy a VPS.

Run `driftless` in `standalone` mode only on your Home PC:
- It automatically opens the ports on your home Wi-Fi router via UPnP (you don't need to log into `192.168.1.1`).
- It checks your external IP every second.
- If you attach a free domain (like DuckDNS or Cloudflare), it updates your domain with the new IP the same second your ISP changes it.

**Run on your Home PC (opens ports on router and prints a ready-to-copy domain in console):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```
Right after launch, the console prints your ready-to-copy address (including an automatic `<your-ip>.sslip.io` domain that works without any registration).

**With a free DuckDNS domain (enter once, or auto-detected from `duck.sh` / `duckdns.txt`):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -duck mypc:YOUR_DUCKDNS_TOKEN
```
*(You can also pass the full form `-ddns-provider duckdns -ddns-domain mypc -ddns-token YOUR_DUCKDNS_TOKEN`. Once entered, `driftless` saves it locally in `.driftless-ddns.json` so on future runs you don't even have to type `-duck` again - it loads your domain automatically and prints `mypc.duckdns.org:8096` in the console ready to copy.)*

---

### Ready-to-copy commands for popular apps

| What you are hosting | Command to run |
| :--- | :--- |
| **Minecraft, CS2, Rust, Valheim, Palworld** (TCP + UDP open automatically) | `./driftless server -ports 25565,27015` |
| **Jellyfin / Plex** media server | `./driftless server -ports 8096` |
| **Website** (map VPS port 80 to local port 3000) | `./driftless server -ports 80:3000` |
| **Ollama / OpenWebUI** with built-in HTTPS encryption | `./driftless server -ports 443:11434/https,3000` |
| **Multiple domains** on one VPS (with automatic HTTP + HTTPS) | `./driftless server -vhosts site.com:3000,media.site.com:8096 -vhost-addr :80 -https :443` |

---

### Useful features built-in by default

- **UDP works out of the box:** Every port you list in `-ports` opens both TCP and UDP automatically. Game servers and voice chat work right away without extra flags.
- **Built-in HTTPS (TLS) without Nginx or Caddy:**
  - If you use domains (`-vhosts`), HTTPS works automatically on the same port as HTTP.
  - If you want HTTPS on a regular port, just add `/https` to the port (for example, `-ports 443:8096/https`) or add the `-tls` flag.
  - If you have Let's Encrypt certificates on your server, `driftless` finds them automatically. Otherwise, it generates a certificate on the fly.
- **Full local speed when you are at home (`-direct :8888`):** If you open your server from your phone or laptop while connected to your home Wi-Fi, traffic doesn't travel to the VPS and back. Instead, `driftless` connects you straight to your PC through your home router (`192.168.x.x`) at the maximum speed of your local network without losing speed to the VPS channel.

---

### Security and reliability (how it is protected under the hood)

- **Client authentication and password protection:** Your password (`-token`) is never sent in plain text over the network. The VPS sends a random 32-byte challenge (`crypto/rand`), and your Home PC proves it knows the password via `HMAC-SHA256` with constant-time verification (`hmac.Equal`).
- **Protection against strangers and brute-force:** Built-in rate limiting blocks any IP after 10 failed authentication attempts per minute (`5s` handshake timeout). Nobody can attach a rogue client to your VPS.
- **TLS 1.3 encryption and certificate pinning:** All traffic between the VPS and your Home PC runs over encrypted QUIC TLS 1.3 with Ed25519 keys. For maximum security, you can pass `-fingerprint SHA256_HASH` on the client to pin the exact VPS certificate and block any MITM interception.
- **Protection against opening unwanted local ports:** By default, the client only connects to `127.0.0.1` and you can lock down allowed local ports on your Home PC with `-allow-ports 80,8096,25565`. Even if someone got access to the VPS, they cannot touch SSH, RDP, SMB, or any other port on your PC.
- **Surviving 10 to 90 second internet drops:** When your ISP changes your IP or your router reconnects (up to `-session-ttl 90s`), active sockets are frozen in RAM and resume from the exact unacknowledged byte (`64-bit offset ACK`) without corrupting files or dropping streams.
- **Strict RAM limits under heavy load or flood:** Memory is strictly capped at `16 MB` per connection (`-max-buf`) and `256 MB` across the entire program (`-max-mem`). If memory is full during a flood of connections, the oldest stalled session is evicted automatically (FIFO) so the server never crashes with Out-Of-Memory (OOM).

---

### All Flags (for advanced setup)

Most flags are optional - the defaults work out of the box.

| Flag | Default | What it does |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Ports to open. Write `8096,25565` (if public and local ports match) or `8080:80`. Add `/tcp`, `/udp`, or `/https` if needed. |
| `-udp` | `true` | Opens both UDP and TCP on every port by default. Set `-udp=false` if you only want TCP. |
| `-quic` | `"0.0.0.0:4242"` | Tunnel port on VPS (`0.0.0.0:4242`) or VPS address on Home PC (`VPS_IP:4242`). |
| `-token` | auto | Password between VPS and Home PC. Generated automatically on VPS if not set. |
| `-token-file` | `""` | Read password from a text file. |
| `-fingerprint` | `""` | Optional SHA-256 certificate fingerprint of the VPS for strict TLS pinning. |
| `-tls` | `false` | Turn on built-in HTTPS encryption on all ports in `-ports`. |
| `-vhosts` | `""` | Connect domains to local ports: `"site.com:3000,media.site.com:8096"`. Supports HTTP and HTTPS out of the box. |
| `-vhost-addr` | `":80"` | Port for domain routing (`-vhosts`). |
| `-https` | `""` | Extra HTTPS port for domain routing (for example `":443"`). |
| `-tls-cert` / `-tls-key` | `""` | Path to your own `.pem` certificate and key files (optional). |
| `-direct` | `":8888"` | Port for direct connection over home Wi-Fi/LAN bypassing the VPS so you don't lose speed (`""` to turn off). |
| `-host` | `"127.0.0.1"` | Local IP on your Home PC. |
| `-allow-ports` | `""` | Restrict which local ports on your Home PC can be accessed (e.g. `"80,8096,25565"`). |
| `-upnp` | `true` | Automatically open ports on your home router via UPnP / NAT-PMP (in `standalone` mode). |
| `-stun` | `"stun.l.google.com:19302"` | STUN server used to check your external IP in 5ms (`standalone` mode). |
| `-stun-interval` | `1s` | How often to check if your IP changed (`standalone` mode). |
| `-duck` | `""` | Shorthand DuckDNS `"subdomain:token"` or update URL (saved automatically to `.driftless-ddns.json` for next runs). |
| `-ddns-provider` | `""` | Auto-update domain IP: `"duckdns"`, `"cloudflare"`, or `"noip"` (`standalone` mode). |
| `-ddns-domain` | `""` | Your domain name for DDNS. |
| `-ddns-token` | `""` | Token/password from DuckDNS, Cloudflare, or No-IP. |
| `-ddns-zone` | `""` | Cloudflare Zone ID (only for `-ddns-provider cloudflare`). |
| `-ddns-user` | `""` | Username (only for `-ddns-provider noip`). |
| `-ddns-url` | `""` | Custom URL for any other DDNS service (`{ip}` gets replaced with your new IP). |
| `-max-buf` | `16 MB` | RAM buffer size per connection to hold data during an IP change. |
| `-max-mem` | `256 MB` | Maximum total RAM used for all buffers. |
| `-session-ttl` | `90s` | How long to wait for your home internet to reconnect before closing a session. |

---

### How it compares to other tools

| Feature | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Streams/downloads survive IP change | Yes (16 MB RAM buffer) | No (connection drops) | No (connection drops) | Yes |
| Can work without a VPS (`standalone`) | Yes (Auto-UPnP + STUN + DDNS) | No | No | No |
| Built-in HTTPS (TLS) | Yes | Manual config files | Yes | No (needs Nginx/Caddy) |
| TCP + UDP open by default | Yes | Separate config blocks | Paid / limited UDP | Manual `iptables` |
| Direct home Wi-Fi/LAN connection bypassing VPS (no speed loss) | Yes (`-direct :8888`) | No | No | Split-DNS required |
| Works without root or virtual network cards | Yes (1 file) | Yes | Yes | No |

---

<a id="ru"></a>

## Русский

> [🇺🇸 Читать на английском ↑](#english)

**Простой способ открыть порты на домашнем ПК и раздавать игры, сайты, Jellyfin или нейронки (Ollama) без обрывов связи при смене IP.**

### Зачем это нужно простыми словами?
Допустим, ты запустил у себя дома на ПК сервер Minecraft/CS2, медиасервер Jellyfin/Plex, нейронку или свой сайт. Обычно ты упираешься в две проблемы:
1. Провайдер дает "серый" IP (CGNAT) - из интернета к твоему ПК вообще никто не может подключиться.
2. Или провайдер дает динамический IP, который меняется раз в сутки или при перезагрузке роутера. В обычных туннелях (`frp`, `ngrok`, `Cloudflare`) в момент смены IP все активные загрузки, стримы и игровые сессии сразу обрываются.

`driftless` решает обе проблемы. Когда провайдер меняет твой IP, программа придерживает данные в оперативной памяти на долю секунды и продолжает передачу уже с нового IP - фильм, скачивание файла или катка на сервере не вылетают.

---

### Как запустить (за 30 секунд)

Сначала скачай один готовый файл под свою систему из раздела [Releases](https://github.com/ERETLY/driftless/releases) (и сервер на ВПС, и клиент дома одинаково работают на Windows, Linux и macOS):
- Для Linux (на ВПС или домашний ПК): `driftless-linux-amd64`
- Для Windows (на домашний ПК или на Windows ВПС): `driftless-windows-amd64.exe`
- Для macOS: `driftless-darwin-arm64`

Дальше выбери один из двух вариантов запуска:

---

#### Вариант 1. Через дешевый ВПС (работает вообще у всех, даже если дома "серый" IP)

Берешь любой самый дешевый ВПС за 100-200 рублей в месяц (подойдет и обычный Linux ВПС, и Windows ВПС), запускаешь файл на ВПС и такой же файл у себя дома на ПК.

**Шаг 1. Запусти на ВПС:**
Просто напиши через запятую порты, которые нужно открыть (и TCP, и UDP для игр откроются сами).

Если у тебя ВПС на **Linux**:
```bash
wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
chmod +x driftless
./driftless server -ports 8096,25565
```

Если у тебя ВПС на **Windows**:
```powershell
.\driftless-windows-amd64.exe server -ports 8096,25565
```
Тебе не нужно придумывать пароль или искать свой IP. Программа на ВПС сама создаст пароль и напишет в консоли готовую строчку для твоего домашнего ПК.

**Шаг 2. Скопируй эту строчку из консоли ВПС и запусти дома на ПК (в PowerShell, cmd или терминале):**
```powershell
.\driftless-windows-amd64.exe client -quic IP_ТВОЕГО_ВПС:4242 -token ПАРОЛЬ_ИЗ_КОНСОЛИ
```
Всё, готово. Теперь любой, кто зайдет на `IP_ТВОЕГО_ВПС:8096` или `25565`, попадает прямо на твой домашний ПК.

---

#### Вариант 2. Вообще без покупки ВПС (только на домашнем ПК)

Если у тебя дома IP меняется хоть каждые 10 минут, но сам IP при этом "белый" (публичный динамический, не за CGNAT), то покупать ВПС вообще не надо.

Запускаешь `driftless` в режиме `standalone` только у себя на домашнем ПК:
- Программа сама пробьет нужные порты на твоем домашнем Wi-Fi роутере через UPnP (даже в настройки роутера `192.168.1.1` лазить не придется).
- Каждую секунду она проверяет твой текущий внешний IP.
- Если подключишь бесплатный домен (например, DuckDNS или Cloudflare), программа будет в ту же секунду сама менять IP на домене, когда провайдер его сменит.

**Запуск на домашнем ПК (пробить порты на роутере автоматом и получить готовый адрес в консоли):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```
Сразу после запуска программа один раз выведет в консоль готовые адреса для копирования (включая бесплатный авто-домен вида `<твой-ip>.sslip.io:8096`, который работает сразу без регистраций).

**С бесплатным доменом DuckDNS (достаточно ввести один раз, дальше подхватывается само):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -duck mypc:ТВОЙ_ТОКЕН_DUCKDNS
```
*(Полная запись `-ddns-provider duckdns -ddns-domain mypc -ddns-token ТВОЙ_ТОКЕН` тоже работает. Домен и токен автоматически сохраняются в локальный файл `.driftless-ddns.json` (а если у тебя на ПК уже лежит `duck.sh` или `duckdns.txt`, программа найдет их сама). При следующих запусках токен вообще можно не вводить: программа сама обновит DuckDNS и напишет в консоли готовый адрес `mypc.duckdns.org:8096` для копирования.)*

---

### Готовые команды под частые задачи

| Что хочешь раздать с ПК | Какую команду запустить |
| :--- | :--- |
| **Игровой сервер (Minecraft, CS2, Rust, Valheim)** - TCP и UDP уже включены | `./driftless server -ports 25565,27015` |
| **Медиасервер (Jellyfin / Plex)** | `./driftless server -ports 8096` |
| **Свой сайт** (открыть порт 80 на ВПС, а дома сайт крутится на порту 3000) | `./driftless server -ports 80:3000` |
| **Нейронка (Ollama / OpenWebUI)** сразу с защитой HTTPS | `./driftless server -ports 443:11434/https,3000` |
| **Несколько сайтов на разных доменах** (HTTP + HTTPS работают сами) | `./driftless server -vhosts site.ru:3000,media.site.ru:8096 -vhost-addr :80 -https :443` |

---

### Полезные фишки, которые уже работают из коробки

- **Не нужно париться с UDP для игр:** Любой порт в `-ports` по умолчанию открывает сразу и TCP, и UDP. Игры и голосовой чат работают без дописывания `/udp`.
- **Встроенный HTTPS (TLS) без возни с Nginx и Caddy:**
  - Если привязываешь домены через `-vhosts`, то HTTPS там уже включен по умолчанию (один и тот же порт понимает и `http://`, и `https://`).
  - Если нужен HTTPS на обычном порту, просто допиши `/https` к порту (например, `-ports 443:8096/https`) или добавь флаг `-tls`.
  - Если на сервере есть сертификаты Let's Encrypt, программа подхватит их сама. Если нет - сама создаст сертификат на лету.
- **Прямое подключение дома по Wi-Fi без потери скорости (`-direct :8888`):** Когда ты открываешь свой сервер с телефона или ноутбука, находясь дома в одной сети с ПК, трафик не гоняется туда-обратно через ВПС. Программа соединяет устройство напрямую с твоим ПК через домашний роутер (`192.168.x.x`) на полной скорости твоей домашней сети и Wi-Fi, чтобы ВПС не резал скорость.

---

### Безопасность и надежность (почему этому можно доверять)

- **Аутентификация клиента и защита пароля (токена):** Пароль (`-token`) никогда не передается по сети в открытом виде. Сервер присылает случайный 32-байтный вызов (`crypto/rand`), а домашний ПК подтверждает знание пароля криптографической подписью `HMAC-SHA256` со сравнением за константное время (`hmac.Equal`).
- **Защита от подключения посторонних клиентов и перебора пароля:** Встроенный ограничитель блокирует IP после 10 неудачных попыток входа в минуту (таймаут рукопожатия 5 секунд). Чужой клиент не сможет ни подобрать токен, ни перехватить туннель.
- **Проверка TLS-сертификатов:** Весь трафик между ВПС и домашним ПК шифруется по протоколу QUIC (TLS 1.3 на ключах Ed25519). Если нужна максимальная защита от перехвата трафика (MITM), на домашнем ПК можно указать точный SHA-256 отпечаток сертификата твоего ВПС через флаг `-fingerprint`.
- **Защита от открытия нежелательных портов на домашнем ПК:** По умолчанию клиент стучится только на локальный адрес `127.0.0.1`, а флагом `-allow-ports 80,8096,25565` на домашнем ПК можно жестко разрешить только нужные порты. Даже если кто-то получит доступ к ВПС, он физически не сможет обратиться к закрытым портам твоего ПК (SSH, RDP, SMB и т.д.).
- **Удержание связи при потере интернета на 10-90 секунд:** Если провайдер меняет IP или роутер переподключается (до `-session-ttl 90s`), активные соединения не закрываются, а ставятся на паузу в кольцевом буфере памяти. Как только интернет появляется, передача продолжается с того же самого байта (`64-bit offset ACK`) без битых файлов и обрыва стрима.
- **Жесткое ограничение памяти при наплыве соединений:** Память ограничена двумя лимитами: максимум `16 МБ` на одно соединение (`-max-buf`) и максимум `256 МБ` на всю программу (`-max-mem`). Если при большом количестве соединений или флуде буфер заполняется, программа автоматически вытесняет самую старую зависшую сессию (FIFO) и никогда не положит сервер от нехватки оперативки (OOM).

---

### Все флаги (если нужно настроить что-то свое)

Обычно трогать их не нужно - стандартные настройки уже выставлены нормально.

| Флаг | По умолчанию | Что делает |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Какие порты открыть. Если порт на входе и дома одинаковый, пиши просто одно число (`8096,25565`). Если разные - через двоеточие (`8080:80`). В конце порта можно дописать `/tcp`, `/udp` или `/https`. |
| `-udp` | `true` | Открывать UDP вместе с TCP на всех портах по умолчанию (`-udp=false` оставит только TCP). |
| `-quic` | `"0.0.0.0:4242"` | Порт связи на ВПС (`0.0.0.0:4242`), а на домашнем ПК туда пишется адрес ВПС (`IP_ВПС:4242`). |
| `-token` | создается сам | Общий пароль между ВПС и домашним ПК. На ВПС генерируется сам, если не указать. |
| `-token-file` | `""` | Прочитать пароль из текстового файла. |
| `-fingerprint` | `""` | SHA-256 отпечаток сертификата ВПС для строгой проверки подлинности сервера (pinning). |
| `-tls` | `false` | Включить встроенный HTTPS (TLS) сразу на всех открытых портах. |
| `-vhosts` | `""` | Раздавать разные сайты по доменам: `"site.ru:3000,media.site.ru:8096"`. Поддерживает HTTP и HTTPS из коробки. |
| `-vhost-addr` | `":80"` | Порт для доменного режима (`-vhosts`). |
| `-https` | `""` | Дополнительный порт под HTTPS для доменов (например, `":443"`). |
| `-tls-cert` / `-tls-key` | `""` | Путь к своим файлам сертификата `.pem` (если не указать, ищет Let's Encrypt или создает свой). |
| `-direct` | `":8888"` | Порт для прямого подключения по домашней локалке/Wi-Fi в обход ВПС без потери скорости (`""` чтобы выключить). |
| `-host` | `"127.0.0.1"` | Локальный адрес на домашнем ПК. |
| `-allow-ports` | `""` | Разрешить доступ только к указанным портам на домашнем ПК (например, `"80,8096,25565"`). |
| `-upnp` | `true` | Автоматически открывать порты на домашнем роутере через UPnP / NAT-PMP (в режиме `standalone`). |
| `-stun` | `"stun.l.google.com:19302"` | STUN-сервер для быстрой проверки внешнего IP за 5 мс (в режиме `standalone`). |
| `-stun-interval` | `1s` | Как часто проверять смену внешнего IP (в режиме `standalone`). |
| `-duck` | `""` | Короткая привязка DuckDNS `"домен:токен"` или ссылка обновления (сохраняется в `.driftless-ddns.json` для следующих запусков). |
| `-ddns-provider` | `""` | Автообновление IP на домене: `"duckdns"`, `"cloudflare"` или `"noip"` (в режиме `standalone`). |
| `-ddns-domain` | `""` | Твой домен для автообновления IP. |
| `-ddns-token` | `""` | Токен или пароль от DuckDNS, Cloudflare или No-IP. |
| `-ddns-zone` | `""` | Zone ID в Cloudflare (нужен только для `-ddns-provider cloudflare`). |
| `-ddns-user` | `""` | Логин (нужен только для `-ddns-provider noip`). |
| `-ddns-url` | `""` | Своя ссылка для любого другого DDNS-сервиса (`{ip}` заменится на новый внешний IP). |
| `-max-buf` | `16 МБ` | Размер буфера памяти на одно соединение (чтобы удерживать поток во время смены IP). |
| `-max-mem` | `256 МБ` | Общий лимит оперативной памяти под все соединения. |
| `-session-ttl` | `90s` | Сколько секунд ждать переподключения интернета дома, прежде чем закрыть соединение. |

---

### Чем отличается от других программ

| Что умеет | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Стримы и загрузки не рвутся при смене IP | Да (буфер 16 МБ в памяти) | Нет (обрыв соединения) | Нет (обрыв соединения) | Да |
| Может работать вообще без ВПС (`standalone`) | Да (Авто-UPnP + STUN + DDNS) | Нет | Нет | Нет |
| Встроенный HTTPS (TLS) | Да | Нужно писать конфиги | Да | Нет (нужен Nginx/Caddy) |
| TCP + UDP открываются по умолчанию | Да | Нужно прописывать отдельно | Платно / урезанный UDP | Ручная настройка `iptables` |
| Прямое подключение дома по Wi-Fi в обход ВПС (без потери скорости) | Да (`-direct :8888`) | Нет | Нет | Нужен свой Split-DNS |
| Работает без прав root и сетевых карт | Да (один файл) | Да | Да | Нет |

## License

[MIT](LICENSE)
