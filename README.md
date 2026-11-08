# driftless

> [🇺🇸 English](#english) | [🇷🇺 Русский](#ru)

---

<a id="english"></a>

## English

Self-hosted QUIC reverse tunnel and standalone router (TCP, UDP, HTTP/HTTPS VHosts, UPnP, STUN DDNS) for home servers on dynamic IPs or behind CGNAT.

When you host Jellyfin, Plex, Nextcloud, Ollama, Minecraft, CS2, or local web apps at home, standard tunnels (`frp`, `rathole`, `ngrok`, `Cloudflare Tunnel`) drop active connections whenever your home ISP changes your dynamic IP address.

`driftless` works in two modes:
1. **VPS + Home PC (`server` + `client`):** Works behind CGNAT ("gray" IP) and dynamic IPs. It keeps a 16 MB sliding ring buffer in RAM per session and frames traffic into `DATA`, `ACK`, and `FIN` packets over QUIC. Local sockets stay open during an IP change, and bytes are only removed from the buffer after the remote peer confirms writing them to the TCP socket.
2. **Standalone without VPS (`standalone`):** If your ISP gives you a public dynamic IP (not behind CGNAT), you can run `driftless` directly on your Home PC without a VPS. It opens ports on your router via UPnP / NAT-PMP, checks your external IP via STUN every second (5ms UDP check), and updates your domain (DuckDNS, Cloudflare DNS, No-IP, or custom webhook) when the IP changes.

---

### Quick Start: Mode 1 - With a VPS (`server` + `client`)

Use this mode if your ISP puts you behind CGNAT or you want to hide your home IP behind a cheap VPS. Both TCP and UDP are forwarded on all mapped ports by default.

#### Step 1. Download the binary
Download the file for your OS from [Releases](https://github.com/ERETLY/driftless/releases):
- On your **VPS** (Linux):
  ```bash
  wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
  chmod +x driftless
  ```
- On your **Home PC** (Windows/Linux/macOS): download `driftless-windows-amd64.exe` (or the Linux/macOS binary).

#### Step 2. Start on your VPS
Pass the ports you want to open (`8080:80` maps VPS port 8080 to local port 80; if the port is the same on both sides, you can just write `8096,25565`):
```bash
./driftless server -ports 8080:80,8096,25565
```
If you omit `-token`, the server generates a password automatically and prints the command to run on your Home PC.

#### Step 3. Run the printed command on your Home PC
```powershell
.\driftless-windows-amd64.exe client -quic YOUR_VPS_IP:4242 -token AUTO_GENERATED_PASSWORD
```

---

### Quick Start: Mode 2 - Without a VPS (`standalone`)

If you have a public dynamic IP at home (even if it changes every 10 minutes), you don't need a VPS:
- `driftless standalone` runs only on your Home PC.
- On startup, it maps the specified TCP and UDP ports on your home router using UPnP IGD and NAT-PMP (`-upnp=true` by default).
- Every second, it sends a 20-byte UDP packet to a STUN server (`stun.l.google.com:19302`) to check if your public IP changed.
- When the IP changes, it updates your DNS record via DuckDNS, Cloudflare DNS API (`TTL = 60s`), No-IP, or a custom webhook URL.

#### Example with DuckDNS:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -ddns-provider duckdns -ddns-domain myhomeserver -ddns-token YOUR_DUCKDNS_TOKEN
```

#### Example with Cloudflare DNS:
```powershell
.\driftless-windows-amd64.exe standalone -ports 80,443:8096/https -ddns-provider cloudflare -ddns-zone ZONE_ID -ddns-domain home.example.com -ddns-token CF_API_TOKEN
```

#### Example without DDNS (only UPnP port forwarding + local proxy):
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```

---

### Built-in TLS (HTTPS) and Default UDP

- **UDP enabled by default (`-udp=true`):** Since TCP and UDP ports use separate kernel namespaces, `-ports 8096,25565` opens both TCP and UDP on those ports. You don't need to append `/udp` for game servers or WebRTC. If you want only TCP or only UDP on a port, use `8080:80/tcp`, `25565:25565/udp`, or pass `-udp=false`.
- **Built-in TLS / HTTPS termination:**
  - On the HTTP VHost router (`-vhosts`), auto-TLS is enabled by default. It peeks at the first byte of incoming connections (`0x16` TLS ClientHello) so the same port can accept both `http://` and `https://`.
  - On standard port mappings (`-ports`), raw TCP is forwarded untouched by default so protocols like SSH, databases, or game traffic are not intercepted. To enable TLS termination on a mapped port, add `/https` to the port (`-ports 443:8096/https`) or pass the global `-tls` flag.
  - Certificates: if `/etc/letsencrypt/live/<domain>/fullchain.pem` exists on the machine, `driftless` loads it automatically. You can also pass `-tls-cert` and `-tls-key`, or let `driftless` generate an in-memory X.509 SAN certificate per SNI hostname automatically.

```bash
# Route multiple domains over HTTP (:80) and HTTPS (:443)
./driftless server -vhosts app.example.com:3000,media.example.com:8096 -vhost-addr :80 -https :443

# Enable TLS termination on a single port mapping
./driftless server -ports 8443:8096/https,25565
```

---

### Common Examples

| Task | Command |
| :--- | :--- |
| Media server (Jellyfin / Plex) via VPS | `./driftless server -ports 8096` |
| Game server (Minecraft / CS2 / Rust) TCP+UDP | `./driftless server -ports 25565,27015` |
| Local AI (Ollama / OpenWebUI) with HTTPS | `./driftless server -ports 443:11434/https,3000` |
| Home PC without VPS (UPnP + DuckDNS) | `./driftless standalone -ports 8096,25565 -ddns-provider duckdns -ddns-domain mypc -ddns-token TOKEN` |

---

### CLI Flags

```text
Usage:
  driftless server [flags]       # Run on VPS (gateway mode)
  driftless client [flags]       # Run on Home PC (connects to VPS)
  driftless standalone [flags]   # Run on Home PC without a VPS (UPnP + STUN + DDNS)
  driftless version              # Print version
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Port mappings: `PUBLIC:LOCAL` or `PORT` (e.g. `8096,25565`). Supports `/tcp`, `/udp`, `/https`. |
| `-udp` | `true` | Forward both UDP and TCP by default on unsuffixed ports (`-udp=false` for TCP only). |
| `-quic` | `"0.0.0.0:4242"` | QUIC address (`0.0.0.0:4242` on VPS, `VPS_IP:4242` on client). |
| `-token` | auto-generated | Shared password between VPS and Home PC. |
| `-token-file` | `""` | Path to file containing the shared password. |
| `-direct` | `":8888"` | Direct 1 Gbps LAN/WAN HTTP redirector port (`""` to disable). |
| `-same-lan` | `true` | Redirect clients sharing the same WAN IP directly to the agent LAN IP. |
| `-host` | `"127.0.0.1"` | Local target host on the Home PC. |
| `-allow-ports` | `""` | Optional comma-separated whitelist of local ports on the Home PC (e.g. `"80,8096,25565"`). |
| `-tls` | `false` | Enable built-in TLS/HTTPS termination on all mapped TCP ports. |
| `-vhosts` | `""` | Domain to local port mappings (`"app.example.com:3000,media.example.com:8096"`). |
| `-vhost-addr` | `":80"` | Listen address for the VHost router when `-vhosts` is set. |
| `-https` | `""` | Optional extra HTTPS listen address for the VHost router (e.g. `":443"`). |
| `-tls-cert` | `""` | Path to custom TLS certificate PEM file. |
| `-tls-key` | `""` | Path to custom TLS private key PEM file. |
| `-cert-dir` | `""` | Directory to save/load gateway QUIC certificate (`cert.pem` / `key.pem`). |
| `-fingerprint` | `""` | Gateway SHA-256 certificate fingerprint for client pinning. |
| `-upnp` | `true` | Automatically open ports on the router via UPnP IGD / NAT-PMP (`standalone` mode). |
| `-stun` | `"stun.l.google.com:19302"` | STUN server address for public IP checks (`standalone` mode). |
| `-stun-interval` | `1s` | How often to check public IP via STUN (`standalone` mode). |
| `-ddns-provider` | `""` | Dynamic DNS provider: `"duckdns"`, `"cloudflare"`, or `"noip"`. |
| `-ddns-domain` | `""` | Domain name to update on IP change. |
| `-ddns-token` | `""` | API token or password for the DDNS provider. |
| `-ddns-zone` | `""` | Cloudflare Zone ID (used with `-ddns-provider cloudflare`). |
| `-ddns-user` | `""` | Username (used with `-ddns-provider noip`). |
| `-ddns-url` | `""` | Custom DDNS webhook URL (`{ip}` is replaced with the new public IP). |
| `-max-buf` | `16777216` (16 MiB) | Max per-session ring buffer in RAM. |
| `-max-mem` | `268435456` (256 MiB) | Max total buffered RAM across all sessions. |
| `-session-ttl` | `90s` | How long to hold frozen sessions during an IP outage. |

---

### Comparison

| Feature | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare Tunnel | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Active streams survive ISP IP change | Yes (RAM Ring Buffer + ACK) | No (TCP socket resets) | No (Stream resets) | Yes (Kernel L3 roaming) |
| Standalone mode without a VPS | Yes (STUN + UPnP + DDNS) | No | No | No |
| Built-in TLS / HTTPS termination | Yes (SNI / Let's Encrypt / `-tls`) | Manual config files | Yes (Cloud proxy) | No (Needs Caddy/Nginx) |
| TCP + UDP enabled by default | Yes (`-udp=true`) | Separate config blocks | Paid / Limited UDP | Manual port routing |
| Requires root / virtual NIC / `iptables` | No (Single binary) | No | No | Yes (Root + TUN + NAT) |
| Direct 1 Gbps LAN redirect | Yes (`-direct :8888`) | No | No | Split-DNS required |

---

<a id="ru"></a>

## Русский

> [🇺🇸 Switch to English ↑](#english)

QUIC-туннель и автономный роутер (TCP, UDP, HTTP/HTTPS по доменам, авто-UPnP, STUN + DDNS) для домашних серверов с динамическим IP или за CGNAT.

Когда дома запущен сайт, медиасервер (Jellyfin, Plex), нейронка (Ollama, OpenWebUI) или игровой сервер (Minecraft, CS2, Rust, Valheim), обычные туннели (`frp`, `rathole`, `ngrok`, `Cloudflare Tunnel`) сбрасывают активные соединения в момент, когда провайдер меняет домашний динамический IP.

В `driftless` есть два режима работы:
1. **Через дешевый ВПС (`server` + `client`):** Работает при любом "сером" IP (CGNAT) и динамическом IP. Держит в оперативной памяти скользящий буфер (16 МБ на сессию) и подтверждает доставку данных пакетами `DATA`, `ACK` и `FIN` поверх QUIC. Во время смены IP локальные сокеты не закрываются, а данные удаляются из буфера только после того, как вторая сторона подтвердила запись в TCP-сокет.
2. **Без ВПС на одном домашнем ПК (`standalone`):** Если провайдер дома выдает публичный ("белый") динамический IP, который просто периодически меняется, покупать ВПС не нужно. Вы запускаете `driftless standalone` только у себя на ПК: программа сама открывает порты на домашнем роутере через UPnP / NAT-PMP, каждую секунду проверяет внешний IP через STUN (5 мс по UDP) и при смене IP сразу обновляет запись на бесплатном домене (DuckDNS, Cloudflare DNS, No-IP).

---

### Быстрый старт: Вариант 1 - С дешевым ВПС (если дома CGNAT / "серый" IP)

Настраивать роутер, WireGuard, `iptables` или вручную придумывать токены не нужно. TCP и UDP открываются одновременно по умолчанию.

#### Шаг 1. Скачайте готовый файл из раздела [Releases](https://github.com/ERETLY/driftless/releases)
- На **ВПС** (Linux):
  ```bash
  wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
  chmod +x driftless
  ```
- На **Домашний ПК** (Windows/Linux/macOS): скачайте `driftless-windows-amd64.exe` (или файл под свою систему).

#### Шаг 2. Запустите на ВПС
Укажите порты, которые нужно открыть (`8080:80` перекинет с порта 8080 ВПС на порт 80 домашнего ПК; если номера портов одинаковые, можно писать просто через запятую `8096,25565`):
```bash
./driftless server -ports 8080:80,8096,25565
```
Если не указывать флаг `-token`, сервер сам создаст случайный пароль, определит IP вашего ВПС и выведет в консоль готовую команду для домашнего ПК.

#### Шаг 3. Скопируйте строку из консоли ВПС и запустите дома на ПК
```powershell
.\driftless-windows-amd64.exe client -quic IP_ВАШЕГО_ВПС:4242 -token ПАРОЛЬ_ИЗ_КОНСОЛИ
```

---

### Быстрый старт: Вариант 2 - Вообще без ВПС и без Cloudflare (`standalone`)

Если у вас дома IP меняется хоть каждые 10 минут, но сам IP при этом публичный ("белый" динамический, не за CGNAT), то ВПС не нужен:
- Программа запускается только дома на ПК в режиме `standalone`.
- При запуске она сама пробрасывает нужные TCP и UDP порты на домашнем роутере через UPnP IGD и NAT-PMP (заходить в настройки роутера не нужно).
- Каждую секунду программа пингует STUN-сервер (`stun.l.google.com:19302`) коротким UDP-пакетом за 5 мс.
- Как только провайдер сменил IP, `driftless` сразу переписывает новый IP в DNS вашего домена через DuckDNS, Cloudflare DNS API (с `TTL = 60` сек), No-IP или любой свой Webhook URL.

#### Пример запуска с бесплатным доменом DuckDNS:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -ddns-provider duckdns -ddns-domain myhomeserver -ddns-token ВАШ_ТОКЕН_DUCKDNS
```

#### Пример запуска с доменом на Cloudflare (TTL = 60 сек):
```powershell
.\driftless-windows-amd64.exe standalone -ports 80,443:8096/https -ddns-provider cloudflare -ddns-zone ID_ЗОНЫ -ddns-domain home.example.com -ddns-token ТОКЕН_CLOUDFLARE
```

#### Пример запуска без домена (только авто-проброс портов на роутере по UPnP + локальный прокси):
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```

---

### Как работают UDP по умолчанию и встроенная терминация TLS (HTTPS)

- **UDP включен по умолчанию (`-udp=true`):** В системе порты TCP и UDP не мешают друг другу, поэтому `-ports 8096,25565` сразу открывает и TCP, и UDP на указанных портах. Дописывать `/udp` для игр или голосовых серверов больше не обязательно. Если нужен строго один протокол, можно указать `8080:80/tcp`, `25565:25565/udp` или отключить авто-UDP флагом `-udp=false`.
- **Встроенная терминация TLS / HTTPS (без Caddy и Nginx):**
  - На доменном роутере (`-vhosts`) авто-TLS включен по умолчанию. Программа проверяет первый байт соединения (`0x16` TLS ClientHello), поэтому один и тот же порт принимает одновременно и `http://`, и `https://`.
  - На обычных портах (`-ports`) по умолчанию передается чистый TCP без вмешательства, чтобы не ломать SSH, базы данных и игровые протоколы. Чтобы включить расшифровку HTTPS на обычном порту, добавьте `/https` к нужному порту (`-ports 443:8096/https`) или общий флаг `-tls`.
  - Сертификаты: если на сервере лежат сертификаты Let's Encrypt (`/etc/letsencrypt/live/<домен>/fullchain.pem`), они подхватываются автоматически. Также можно указать свои файлы через `-tls-cert` и `-tls-key`. Если сертификатов нет, встроенный генератор сам создаст в памяти валидный X.509 SNI-сертификат под запрошенный домен или IP.

```bash
# Раздача нескольких сайтов по доменам на портах :80 и :443
./driftless server -vhosts site.ru:3000,media.site.ru:8096 -vhost-addr :80 -https :443

# Включение HTTPS для конкретного порта через /https
./driftless server -ports 8443:8096/https,25565
```

---

### Примеры частых команд

| Задача | Команда |
| :--- | :--- |
| Медиасервер (Jellyfin / Plex) через ВПС | `./driftless server -ports 8096` |
| Игровой сервер (Minecraft / CS2 / Rust) TCP+UDP | `./driftless server -ports 25565,27015` |
| Локальная нейросеть (Ollama / OpenWebUI) с HTTPS | `./driftless server -ports 443:11434/https,3000` |
| Домашний ПК без ВПС (UPnP + DuckDNS) | `./driftless standalone -ports 8096,25565 -ddns-provider duckdns -ddns-domain mypc -ddns-token ТОКЕН` |

---

### Все флаги командной строки

```text
Запуск:
  driftless server [флаги]       # Запустить на ВПС (шлюз)
  driftless client [флаги]       # Запустить дома на ПК (клиент к ВПС)
  driftless standalone [флаги]   # Автономный режим дома на ПК без ВПС (UPnP + STUN + DDNS)
  driftless version              # Показать версию
```

| Флаг | По умолчанию | Описание |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Порты для открытия: `ВНЕШНИЙ:ЛОКАЛЬНЫЙ` или просто `ПОРТ` (`8096,25565`). Поддерживает `/tcp`, `/udp`, `/https`. |
| `-udp` | `true` | Пробрасывать UDP вместе с TCP по умолчанию на всех портах (`-udp=false` оставит только TCP). |
| `-quic` | `"0.0.0.0:4242"` | Адрес QUIC-туннеля (на ВПС по умолчанию, на клиенте `IP_ВПС:4242`). |
| `-token` | создается сам | Общий пароль между ВПС и домашним ПК. |
| `-token-file` | `""` | Путь к файлу с паролем. |
| `-direct` | `":8888"` | Порт прямого редиректа 1 Гбит/с внутри домашней локальной сети (`""` чтобы отключить). |
| `-same-lan` | `true` | Перенаправлять клиентов из домашней сети напрямую на локальный IP ПК (`192.168.x.x`). |
| `-host` | `"127.0.0.1"` | Локальный IP на домашнем ПК, куда отправлять трафик. |
| `-allow-ports` | `""` | Опциональный список разрешенных локальных портов на домашнем ПК (`"80,8096,25565"`). |
| `-tls` | `false` | Включить встроенную терминацию TLS (HTTPS) на всех TCP-портах из `-ports`. |
| `-vhosts` | `""` | Маршрутизация по доменам (`"app.example.com:3000,media.example.com:8096"`). |
| `-vhost-addr` | `":80"` | Адрес прослушивания доменного роутера при использовании `-vhosts`. |
| `-https` | `""` | Дополнительный порт для HTTPS доменного роутера (например, `":443"`). |
| `-tls-cert` | `""` | Путь к своему файлу сертификата `.pem`. |
| `-tls-key` | `""` | Путь к своему приватному ключу `.pem`. |
| `-cert-dir` | `""` | Папка для сохранения QUIC-сертификата шлюза (`cert.pem` / `key.pem`). |
| `-fingerprint` | `""` | SHA-256 отпечаток сертификата ВПС для строгой проверки на клиенте. |
| `-upnp` | `true` | Автоматически открывать порты на роутере через UPnP IGD и NAT-PMP (в режиме `standalone`). |
| `-stun` | `"stun.l.google.com:19302"` | STUN-сервер для проверки внешнего IP (в режиме `standalone`). |
| `-stun-interval` | `1s` | Интервал проверки внешнего IP через STUN (в режиме `standalone`). |
| `-ddns-provider` | `""` | Провайдер динамического DNS: `"duckdns"`, `"cloudflare"` или `"noip"`. |
| `-ddns-domain` | `""` | Домен, который нужно обновлять при смене IP. |
| `-ddns-token` | `""` | Токен или пароль от аккаунта DDNS. |
| `-ddns-zone` | `""` | Zone ID в Cloudflare (для `-ddns-provider cloudflare`). |
| `-ddns-user` | `""` | Логин пользователя (для `-ddns-provider noip`). |
| `-ddns-url` | `""` | Своя ссылка (Webhook) для обновления DDNS (`{ip}` заменяется на текущий внешний IP). |
| `-max-buf` | `16777216` (16 МБ) | Максимальный размер буфера в оперативной памяти на одно соединение. |
| `-max-mem` | `268435456` (256 МБ) | Общий лимит памяти под буферы всех сессий. |
| `-session-ttl` | `90s` | Время удержания замороженной сессии при обрыве связи. |

---

### Сравнение с аналогами

| Функция | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare Tunnel | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Активные загрузки не рвутся при смене IP | Да (16 МБ RAM буфер + ACK) | Нет (сброс TCP-сокета) | Нет (обрыв стрима) | Да (L3 роуминг ядра) |
| Автономная работа без ВПС (`standalone`) | Да (STUN + UPnP + DDNS) | Нет | Нет | Нет |
| Терминация TLS (HTTPS) | Да (SNI / Let's Encrypt / `-tls`) | Вручную через конфиги | Да (на стороне облака) | Нет (нужен Caddy/Nginx) |
| TCP + UDP включены по умолчанию | Да (`-udp=true`) | Отдельные секции конфига | Платно / ограничения UDP | Ручная настройка `iptables` |
| Работа без root и виртуальных сетевых карт | Да (один бинарник) | Да | Да | Нет (нужен root + TUN + NAT) |
| Прямой режим 1 Гбит/с по домашней локалке | Да (`-direct :8888`) | Нет | Нет | Нужен свой Split-DNS |

## License

[MIT](LICENSE)
