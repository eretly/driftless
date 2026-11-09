# driftless

> [🇺🇸 English](#english) | [🇷🇺 Русский](#ru)

---

<a id="english"></a>

## English

**Open ports to your Home PC and host game servers, websites, Jellyfin, or Ollama without disconnects when your home IP changes.**

### Why use this?
When you run a Minecraft/CS2 server, Jellyfin, Ollama, or a website on your Home PC, you usually hit two problems:
1. Your ISP gives you a "gray" IP (CGNAT), so nobody from the internet can connect to your PC.
2. Or your ISP gives you a dynamic IP that changes periodically. In standard tunnels (`frp`, `ngrok`, `Cloudflare`), every IP change drops all active streams, downloads, and game sessions.

`driftless` solves both. When your home IP changes, TCP streams and downloads are held in a 16 MB RAM ring buffer and resume from the exact byte offset without dropping, while UDP game/voice sessions keep their port mapping and buffer up to 1024 packets during the brief reconnect so your lobby does not disconnect.

---

### Quick Start (2 ways)

Download one file for your system from [Releases](https://github.com/ERETLY/driftless/releases):
- For Linux (VPS or Home PC): `driftless-linux-amd64`
- For Windows (VPS or Home PC): `driftless-windows-amd64.exe`
- For macOS (Home PC): `driftless-darwin-arm64`

---

#### Way 1. With a cheap VPS (works on any internet, including "gray" IP / CGNAT)

**Step 1. Run on your VPS (Linux or Windows):**
List the ports you want to open separated by commas (TCP and UDP open automatically).

Linux:
```bash
wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
chmod +x driftless
./driftless server -ports 8096,25565
```

Windows:
```powershell
.\driftless-windows-amd64.exe server -ports 8096,25565
```
The server generates a password and prints a ready-to-copy command for your Home PC in the console.

**Step 2. Copy that command and run it on your Home PC:**
```powershell
.\driftless-windows-amd64.exe client -quic YOUR_VPS_IP:4242 -token PASSWORD -fingerprint CERT_HASH
```
Done. Your Home PC is now reachable at `YOUR_VPS_IP:8096` and `YOUR_VPS_IP:25565`.

---

#### Way 2. Without a VPS (only on your Home PC, for dynamic public IP)

If your ISP gives you a public ("white") dynamic IP (not static), you don't need a VPS. `standalone` mode automatically opens ports on your home router via UPnP (including PPPoE/PPTP `WANPPPConnection` with permanent lease fallback) and checks for IP changes every second via STUN:

```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```

**Optional: add `-duck` so you have a permanent domain to connect from your phone outside home**
Normally, you cannot point a domain to a non-static IP because the IP keeps changing. With `-duck`, `driftless` updates your domain automatically the second your home IP changes (and retries automatically if the link is still coming up):
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -duck
```
*(If you have a free DuckDNS account, run `-duck mypc:YOUR_TOKEN` once - it saves your token in `.driftless-ddns.json`, so next time you just write `-duck` and always connect to `mypc.duckdns.org:8096` from anywhere.)*
- Prints your ready domain address in the console so you can copy it (and refreshes it automatically if your IP changes).
- If a certificate for the domain already exists on disk, it uses it without creating a new one; if not (or if it is expiring), it creates and saves it automatically.

---

### Examples for common tasks

| Task | Command |
| :--- | :--- |
| **Game server (Minecraft, CS2, Rust, Valheim)** - TCP + UDP included | `./driftless server -ports 25565,27015` |
| **Jellyfin / Plex** media server | `./driftless server -ports 8096` |
| **Website** (VPS port 80 -> Home PC port 3000) | `./driftless server -ports 80:3000` |
| **Ollama / OpenWebUI** with HTTPS | `./driftless server -ports 443:11434/https,3000` |
| **Multiple domains & URL paths** (with automatic Let's Encrypt HTTPS) | `./driftless server -vhosts site.com:3000,site.com/api:4000,media.site.com:8096 -vhost-addr :80 -https :443` |
| **Behind Caddy / Nginx** (bind tunnel ports only to local `127.0.0.1`) | `./driftless server -ports 127.0.0.1:8080:3000` |

---

### Built-in features

- **QUIC + automatic TCP-Mux fallback (`-transport auto`):** Uses multiplexed QUIC (`UDP :4242`) by default and automatically falls back to multiplexed TLS over TCP (`TCP :4242`) when UDP is blocked by corporate firewalls or strict NATs.
- **Multi-Gateway failover:** Pass multiple VPS addresses in `-quic vps1:4242,vps2:4242` for automatic failover.
- **TCP + UDP by default:** Every port in `-ports` opens both TCP and UDP automatically.
- **Built-in HTTPS and certificates:** Supports automatic Let's Encrypt certificates (on `:443` via TLS-ALPN-01, `:80` via HTTP-01, or via DuckDNS DNS-01), reuses existing certificates from disk without recreating them, renews them automatically on a background schedule (< 30 days left), and never silently replaces a failed public domain certificate with an untrusted self-signed one.
- **Full speed on home Wi-Fi (`-direct :8888`):** When you connect from your phone or laptop on the same home Wi-Fi, traffic goes straight through your home router (`192.168.x.x`) at full local network speed bypassing the VPS.
- **Security & Observability:** Supports zero-downtime token rotation (`-token new_pass,old_pass`), optional mTLS (`-client-ca`, `-client-cert`, `-client-key`), IP/CIDR ACL filtering (`-allow-ips`), local port whitelisting (`-allow-ports`), and Prometheus/JSON metrics (`-metrics 127.0.0.1:9090`).

---

### All Flags (optional)

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Ports to open: `8096,25565`, `8080:80`, or local `127.0.0.1:8080:80`. Supports `/tcp`, `/udp`, `/https`. |
| `-udp` | `true` | Open UDP alongside TCP on all ports (`-udp=false` for TCP only). |
| `-quic` | `"0.0.0.0:4242"` | Tunnel address on VPS or comma-separated VPS list on Home PC (`vps1:4242,vps2:4242`). |
| `-transport` | `"auto"` | Tunnel transport: `"auto"` (QUIC with automatic TCP-Mux fallback), `"quic"`, or `"tcp"`. |
| `-token` | auto | Shared password or comma-separated rotation list (`"new_tok,old_tok"`). |
| `-fingerprint` | `""` | VPS certificate fingerprint (included automatically in the server console command). |
| `-duck` | `""` | Optional domain + certificate flag (`-duck` or `-duck subdomain:token`). Off by default. |
| `-tls` | `false` | Enable HTTPS on all ports in `-ports`. |
| `-vhosts` | `""` | Route domains and paths to local ports: `"site.com:3000,site.com/api:4000,*.site.com:5000"`. |
| `-vhost-addr` / `-https` | `":80"` / `""` | HTTP and HTTPS ports for `-vhosts`. |
| `-tls-cert` / `-tls-key` | `""` | Custom `.pem` certificate and key files. |
| `-direct` | `":8888"` | Direct connection over home Wi-Fi/LAN bypassing the VPS (`""` to disable). |
| `-host` | `"127.0.0.1"` | Local target IP on your Home PC. |
| `-allow-ports` | `""` | Whitelist allowed local ports on your Home PC (e.g. `"80,8096,25565"`). |
| `-allow-ips` | `""` | Optional IP/CIDR ACL whitelist for public listeners (e.g. `"192.168.1.0/24,203.0.113.5"`). |
| `-client-ca` / `-client-cert` / `-client-key` | `""` | Optional mTLS client certificate verification between VPS and Home PC. |
| `-metrics` | `""` | Optional observability server address for `/metrics` (Prometheus) and `/status` (JSON). |
| `-upnp` | `true` | Auto-open ports on home router via UPnP / NAT-PMP (`standalone` mode). |
| `-stun` / `-stun-interval` | Google STUN / `1s` | External IP check server and interval (`standalone` mode). |
| `-ddns-provider` | `""` | Other DDNS providers: `"cloudflare"` or `"noip"`. |
| `-max-buf` / `-max-mem` | `16 MB` / `256 MB` | RAM buffer limits per connection and total. |
| `-session-ttl` | `90s` | How long to hold active connections while home internet reconnects. |

---

### Comparison

| Feature | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Streams/downloads survive IP change | Yes (16 MB RAM buffer) | No (drops) | No (drops) | Yes |
| QUIC + automatic TCP-Mux fallback | Yes (`-transport auto`) | Separate config | Yes | UDP only |
| Works without a VPS (`standalone`) | Yes (UPnP + STUN + DDNS) | No | No | No |
| Built-in HTTPS & certificates | Yes | Manual config | Yes | No (needs Nginx/Caddy) |
| TCP + UDP open by default | Yes | Separate blocks | Paid / limited UDP | Manual `iptables` |
| Direct home Wi-Fi connection bypassing VPS (no speed loss) | Yes (`-direct :8888`) | No | No | Split-DNS required |
| Works without root or virtual network cards | Yes (1 file) | Yes | Yes | No |

---

<a id="ru"></a>

## Русский

> [🇺🇸 Читать на английском ↑](#english)

**Простой способ открыть порты на домашнем ПК и раздавать игры, сайты, Jellyfin или нейронки (Ollama) без обрывов связи при смене IP.**

### Зачем это нужно?
Когда запускаешь дома на ПК сервер Minecraft/CS2, Jellyfin, нейронку или сайт, обычно мешают две вещи:
1. Провайдер дает "серый" IP (CGNAT) - из интернета к твоему ПК никто не может подключиться.
2. Или провайдер дает динамический IP, который периодически меняется. В обычных туннелях (`frp`, `ngrok`, `Cloudflare`) при смене IP все активные загрузки, стримы и игры сразу обрываются.

`driftless` решает обе проблемы. При смене IP TCP-соединения (стримы, загрузки, сайты, SSH) удерживаются в кольцевом буфере памяти (16 МБ) и продолжают передачу с точного байта без разрыва, а для UDP (игры, голос) сохраняется привязка порта и буферизуются пакеты (до 1024 датаграмм на поток) на время короткого переподключения, чтобы не выкидывало из лобби и сервера.

---

### Быстрый запуск (2 варианта)

Скачай один готовый файл под свою систему из [Releases](https://github.com/ERETLY/driftless/releases):
- Для Linux (на ВПС или домашний ПК): `driftless-linux-amd64`
- Для Windows (на ВПС или домашний ПК): `driftless-windows-amd64.exe`
- Для macOS (на домашний ПК): `driftless-darwin-arm64`

---

#### Вариант 1. Через дешевый ВПС (работает у всех, даже если дома "серый" IP)

**Шаг 1. Запусти на ВПС (Linux или Windows):**
Напиши через запятую порты, которые нужно открыть (TCP и UDP откроются сами).

Linux:
```bash
wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
chmod +x driftless
./driftless server -ports 8096,25565
```

Windows:
```powershell
.\driftless-windows-amd64.exe server -ports 8096,25565
```
Сервер сам создаст пароль и выведет в консоль готовую строчку для твоего домашнего ПК.

**Шаг 2. Скопируй эту строчку из консоли ВПС и запусти дома на ПК:**
```powershell
.\driftless-windows-amd64.exe client -quic IP_ВПС:4242 -token ПАРОЛЬ -fingerprint ОТПЕЧАТОК
```
Готово. Твой домашний ПК доступен по адресу `IP_ВПС:8096` и `IP_ВПС:25565`.

---

#### Вариант 2. Вообще без ВПС (если IP не статичный, но "белый")

Если провайдер дает динамический "белый" IP (включая PPTP/PPPoE), покупать ВПС не нужно. Режим `standalone` сам откроет порты на домашнем роутере через UPnP (`WANPPPConnection` и `WANIPConnection`) и каждую секунду следит за сменой IP по STUN:

```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```

**По желанию: добавь `-duck`, чтобы получить постоянный адрес и заходить с телефона вне дома**
Обычно на динамический (не статичный) IP нельзя направить домен, потому что адрес меняется. С флагом `-duck` программа в ту же секунду при смене IP сама обновляет адрес домена (с авто-повтором, если интернет только поднялся):
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -duck
```
*(Если есть бесплатный аккаунт на DuckDNS, один раз запусти `-duck mypc:ТВОЙ_ТОКЕН` - программа его запомнит, и дальше можно писать просто `-duck`, всегда подключаясь с телефона по постоянному адресу `mypc.duckdns.org:8096`.)*
- Выведет в консоль готовый адрес с доменом, чтобы его можно было скопировать (и сам обновит при смене IP).
- Если сертификат для домена уже есть на диске - просто использует его и заново не создает. Если сертификата еще нет (или он истекает) - сама создаст и сохранит.

---

### Примеры команд под частые задачи

| Задача | Команда |
| :--- | :--- |
| **Игровой сервер (Minecraft, CS2, Rust, Valheim)** - TCP и UDP сразу | `./driftless server -ports 25565,27015` |
| **Медиасервер (Jellyfin / Plex)** | `./driftless server -ports 8096` |
| **Свой сайт** (порт 80 на ВПС -> порт 3000 дома) | `./driftless server -ports 80:3000` |
| **Нейронка (Ollama / OpenWebUI)** с защитой HTTPS | `./driftless server -ports 443:11434/https,3000` |
| **Несколько сайтов и путей на разных доменах** (авто-HTTPS Let's Encrypt) | `./driftless server -vhosts site.ru:3000,site.ru/api:4000,media.site.ru:8096 -vhost-addr :80 -https :443` |
| **В связке с Caddy / Nginx** (открыть порты только внутри ВПС на `127.0.0.1`) | `./driftless server -ports 127.0.0.1:8080:3000` |

---

### Что еще встроено из коробки

- **Автовыбор транспорта QUIC / TCP-Mux (`-transport auto`):** По умолчанию работает по QUIC (`UDP :4242`), а если провайдер или корпоративный файрвол режет UDP, автоматически переключается на мультиплексирование потоков поверх одного TLS/TCP-соединения (`TCP :4242`).
- **Резервирование ВПС (Multi-Gateway):** В `-quic` можно указать несколько серверов через запятую (`-quic vps1:4242,vps2:4242`) для автоматического переключения при падении узла.
- **TCP и UDP открываются сразу:** Игры и голосовой чат работают без дописывания `/udp`.
- **Сертификаты и HTTPS:** Поддерживается авто-получение Let's Encrypt (через `:443` TLS-ALPN-01, `:80` HTTP-01 или DNS-01). Если сертификат уже лежит на диске, программа берет его без пересоздания, заранее продлевает по встроенному расписанию (когда остается меньше 30 дней) и не подменяет публичные домены самоподписанными сертификатами при ошибке выпуска.
- **Полная скорость дома по Wi-Fi (`-direct :8888`):** Когда заходишь на сервер с телефона или ноутбука из дома (в одной сети с ПК), трафик идет напрямую через домашний роутер (`192.168.x.x`) на полной скорости локальной сети в обход ВПС.
- **Безопасность и метрики:** Поддерживается бесшовная ротация паролей (`-token новый,старый`), взаимный mTLS (`-client-ca`, `-client-cert`, `-client-key`), фильтрация по IP/подсетям (`-allow-ips`), белый список портов (`-allow-ports`) и мониторинг Prometheus/JSON (`-metrics 127.0.0.1:9090`).

---

### Все флаги (необязательные)

| Флаг | По умолчанию | Что делает |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Порты: `8096,25565`, `8080:80` или локально `127.0.0.1:8080:80`. Можно дописать `/tcp`, `/udp`, `/https`. |
| `-udp` | `true` | Открывать UDP вместе с TCP (`-udp=false` оставит только TCP). |
| `-quic` | `"0.0.0.0:4242"` | Порт связи на ВПС или список адресов ВПС через запятую на ПК (`vps1:4242,vps2:4242`). |
| `-transport` | `"auto"` | Транспорт туннеля: `"auto"` (QUIC с авто-переходом на TCP-Mux), `"quic"` или `"tcp"`. |
| `-token` | создается сам | Общий пароль (или список паролей через запятую для ротации `"новый,старый"`). |
| `-fingerprint` | `""` | Отпечаток сертификата ВПС (сам подставляется в готовую команду в консоли ВПС). |
| `-duck` | `""` | Опция авто-домена и сертификата (`-duck` или `-duck домен:токен`). По умолчанию выключена. |
| `-tls` | `false` | Включить HTTPS сразу на всех открытых портах. |
| `-vhosts` | `""` | Раздавать сайты по доменам и путям: `"site.ru:3000,site.ru/api:4000,*.site.ru:5000"`. |
| `-vhost-addr` / `-https` | `":80"` / `""` | Порты HTTP и HTTPS для доменного режима (`-vhosts`). |
| `-tls-cert` / `-tls-key` | `""` | Путь к своим файлам сертификата `.pem`. |
| `-direct` | `":8888"` | Прямое подключение по домашней локалке/Wi-Fi в обход ВПС без потери скорости (`""` - выкл). |
| `-host` | `"127.0.0.1"` | Локальный адрес на домашнем ПК. |
| `-allow-ports` | `""` | Разрешить доступ только к указанным портам на домашнем ПК (например, `"80,8096,25565"`). |
| `-allow-ips` | `""` | Разрешить входящие подключения только с указанных IP или подсетей CIDR (`"192.168.1.0/24,203.0.113.5"`). |
| `-client-ca` / `-client-cert` / `-client-key` | `""` | Опциональная проверка клиентских сертификатов mTLS между ВПС и домашним ПК. |
| `-metrics` | `""` | Адрес HTTP-сервера метрик `/metrics` (Prometheus) и `/status` (JSON), например `"127.0.0.1:9090"`. |
| `-upnp` | `true` | Авто-открытие портов на домашнем роутере через UPnP / NAT-PMP (`standalone`). |
| `-stun` / `-stun-interval` | Google STUN / `1s` | STUN-сервер и частота проверки внешнего IP (`standalone`). |
| `-ddns-provider` | `""` | Другие DDNS-сервисы: `"cloudflare"` или `"noip"`. |
| `-max-buf` / `-max-mem` | `16 МБ` / `256 МБ` | Лимиты оперативной памяти на одно соединение и на всю программу. |
| `-session-ttl` | `90s` | Сколько секунд удерживать соединение при переподключении интернета дома. |

---

### Сравнение

| Что умеет | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Стримы и загрузки не рвутся при смене IP | Да (буфер 16 МБ в памяти) | Нет (обрыв) | Нет (обрыв) | Да |
| Автовыбор QUIC и fallback на TCP-Mux | Да (`-transport auto`) | Отдельные конфиги | Да | Только UDP |
| Может работать вообще без ВПС (`standalone`) | Да (UPnP + STUN + DDNS) | Нет | Нет | Нет |
| Встроенный HTTPS и сертификаты | Да | Нужны конфиги | Да | Нет (нужен Nginx/Caddy) |
| TCP + UDP открываются по умолчанию | Да | Отдельные блоки | Платно / урезанный UDP | Ручной `iptables` |
| Прямое подключение дома по Wi-Fi в обход ВПС (без потери скорости) | Да (`-direct :8888`) | Нет | Нет | Нужен Split-DNS |
| Работает без прав root и сетевых карт | Да (1 файл) | Да | Да | Нет |

## License

[MIT](LICENSE)

