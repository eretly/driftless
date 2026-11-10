# driftless

[English](#english) | [Русский](#ru)

---

<a id="english"></a>

## English

**Open ports to your Home PC behind CGNAT or a dynamic IP. Host game servers (Minecraft, CS2, Rust, Valheim), Jellyfin, Plex, Ollama, or websites without disconnects when your ISP changes your IP.**

### What problem does this solve?
When you run a game server, media server, local LLM, or website on your Home PC, you usually hit one of two walls:
1. Your ISP puts you behind CGNAT ("gray" IP), so nobody from the internet can connect to your ports.
2. Your ISP gives you a dynamic public IP that changes periodically. In standard reverse tunnels (`frp`, `rathole`, `ngrok`, `Cloudflare Tunnel`), every IP change drops all active TCP downloads, video streams, and UDP game lobbies.

`driftless` fixes both:
- When your home IP changes, active TCP connections are held in a 16 MB RAM ring buffer and resume from the exact byte offset without dropping.
- Active UDP game and voice sessions keep their port mapping and buffer up to 1024 datagrams while the link reconnects, so players do not get kicked from the server.

---

### Quick Start (2 ways)

Download one binary for your OS from [Releases](https://github.com/ERETLY/driftless/releases):
- Linux (VPS or Home PC): `driftless-linux-amd64` (or `arm64`)
- Windows (VPS or Home PC): `driftless-windows-amd64.exe`
- macOS (Home PC): `driftless-darwin-arm64` (or `amd64`)

---

#### Way 1. Through a cheap VPS (works on any internet, including CGNAT / "gray" IP)

**Step 1. Run on your VPS (Linux or Windows):**
List the ports you want to open separated by commas (both TCP and UDP open automatically).

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
The server generates a password and prints a ready-to-copy command for your Home PC right on your screen (to print it again later, run `./driftless show-token`).

**Step 2. Run that command on your Home PC:**
```powershell
.\driftless-windows-amd64.exe client -quic YOUR_VPS_IP:4242 -token PASSWORD -fingerprint CERT_HASH
```
Done. Your Home PC is now reachable at `YOUR_VPS_IP:8096` and `YOUR_VPS_IP:25565`.

---

#### Way 2. Without a VPS (only on your Home PC, if you have a dynamic public IP)

If your ISP gives you a public ("white") dynamic IP, you do not need a VPS. `standalone` mode opens ports on your home router via UPnP / NAT-PMP and checks for IP changes every second via STUN:

```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```

**Optional: add `-duck` for a permanent domain name**
With `-duck`, `driftless` updates your domain the second your home IP changes and handles HTTPS certificates automatically:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -duck
```
*(If you have a free DuckDNS account, run `-duck mypc:YOUR_TOKEN` once. It saves the token in `.driftless-ddns.json`, so next time you just run `-duck` and connect to `mypc.duckdns.org:8096` from anywhere.)*

---

### Common Tasks

| Task | Command |
| :--- | :--- |
| **Game server (Minecraft, CS2, Rust, Valheim, Palworld)** - TCP + UDP | `./driftless server -ports 25565,27015` |
| **Jellyfin / Plex / Home Assistant** | `./driftless server -ports 8096,8123` |
| **Website / API** (VPS port 80 -> Home PC port 3000) | `./driftless server -ports 80:3000` |
| **Ollama / OpenWebUI** with HTTPS | `./driftless server -ports 443:11434/https,3000` |
| **Multiple domains & URL paths** (with Let's Encrypt HTTPS) | `./driftless server -vhosts site.com:3000,site.com/api:4000,media.site.com:8096 -vhost-addr :80 -https :443` |
| **Behind Caddy / Nginx** (bind tunnel ports only to `127.0.0.1`) | `./driftless server -ports 127.0.0.1:8080:3000` |

---

### Built-in Features

- **QUIC + automatic TCP-Mux fallback (`-transport auto`):** Uses multiplexed QUIC (`UDP :4242`) by default and falls back to multiplexed TLS over TCP (`TCP :4242`) when UDP is blocked by firewalls or strict NATs.
- **Multi-Gateway failover:** Pass multiple VPS addresses in `-quic vps1:4242,vps2:4242` for automatic failover.
- **TCP + UDP by default:** Every port in `-ports` forwards both TCP and UDP automatically.
- **Built-in HTTPS and ACME certificates:** Obtains Let's Encrypt certificates (on `:443` via TLS-ALPN-01, `:80` via HTTP-01, or via DuckDNS DNS-01), reuses existing certificates from disk without recreating them, and renews them in the background (< 30 days left).
- **Direct LAN bypass on home Wi-Fi (`-direct :8888`):** When connecting from your phone or laptop on the same home Wi-Fi, traffic goes directly over your local network (`192.168.x.x`) at full LAN speed instead of hair-pinning through the VPS.
- **Security & Observability:** Mutual HMAC authentication with TLS Certificate Channel Binding, zero-downtime token rotation (`-token new_pass,old_pass`), optional mTLS (`-client-ca`, `-client-cert`, `-client-key`), IP/CIDR ACL filtering (`-allow-ips`), local port whitelisting (`-allow-ports`), HAProxy PROXY protocol v1 (`-proxy-protocol`), and Prometheus/JSON metrics (`-metrics 127.0.0.1:9090`).

---

### All Flags (optional)

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Ports to open: `8096,25565`, `8080:80`, or `127.0.0.1:8080:80`. Supports `/tcp`, `/udp`, `/https`. |
| `-udp` | `true` | Open UDP alongside TCP on all ports (`-udp=false` for TCP only). |
| `-quic` | `"0.0.0.0:4242"` | Tunnel address on VPS or comma-separated VPS list on Home PC (`vps1:4242,vps2:4242`). |
| `-transport` | `"auto"` | Tunnel transport: `"auto"` (QUIC with TCP-Mux fallback), `"quic"`, or `"tcp"`. |
| `-token` | auto | Shared password or comma-separated rotation list (`"new_tok,old_tok"`). |
| `-fingerprint` | `""` | VPS certificate fingerprint (included in the generated client command). |
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
| `-proxy-protocol` | `false` | Prepend HAProxy PROXY protocol v1 header with the real client IP to local TCP services. |
| `-metrics` | `""` | Optional observability server address for `/metrics` (Prometheus) and `/status` (JSON). |
| `-upnp` | `true` | Auto-open ports on home router via UPnP / NAT-PMP (`standalone` mode). |
| `-stun` | `"stun.cloudflare.com:3478"` | Custom STUN server or comma-separated list for external IP detection (`standalone` mode). |
| `-stun-interval` | `1s` | External IP check interval via STUN (`standalone` mode). |
| `-ddns-provider` | `""` | Other DDNS providers: `"cloudflare"` or `"noip"`. |
| `-max-buf` / `-max-mem` | `16 MB` / `256 MB` | RAM buffer limits per connection and total. |
| `-session-ttl` | `90s` | How long to hold active connections while home internet reconnects. |

---

### Comparison with Alternatives

| Feature | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare Tunnel | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Streams & downloads survive IP change | Yes (16 MB RAM buffer) | No (drops) | No (drops) | Yes |
| QUIC + automatic TCP-Mux fallback | Yes (`-transport auto`) | Separate config | Yes | UDP only |
| Works without a VPS (`standalone`) | Yes (UPnP + STUN + DDNS) | No | No | No |
| Built-in HTTPS & Let's Encrypt | Yes | Manual config | Yes | No (needs Nginx/Caddy) |
| TCP + UDP open by default | Yes | Separate blocks | Paid / limited UDP | Manual `iptables` |
| Direct home Wi-Fi bypass (full LAN speed) | Yes (`-direct :8888`) | No | No | Split-DNS required |
| Single file, no root or virtual NICs | Yes | Yes | Yes | No |

---

### FAQ & Troubleshooting

**How to open ports behind CGNAT ("gray" IP) for Minecraft, CS2, or Jellyfin?**
Run `./driftless server -ports 25565,8096` on any cheap VPS and run the printed `client` command on your Home PC. Your Home PC initiates an outbound QUIC/TCP connection to the VPS, bypassing CGNAT completely without needing router configuration or root permissions.

**Why do `frp`, `ngrok`, and `Cloudflare Tunnel` disconnect when my dynamic IP changes?**
Standard tunnels tie each public TCP stream directly to the underlying tunnel socket. When your ISP rotates your IP or PPPoE reconnects, the socket closes and every active download, video stream, or SSH session gets a `connection reset`. `driftless` decouples public sessions from the tunnel link using a 16 MB per-session ring buffer (`Session-Resume`) and replays unacknowledged bytes as soon as the agent reconnects from the new IP.

**Can I forward UDP game servers (CS2, Rust, Valheim, Minecraft Bedrock)?**
Yes. Unlike HTTP-only tunnels (`Cloudflare Tunnel`, free `ngrok`), `driftless` forwards both TCP and UDP on every port by default and preserves per-client UDP port mappings across brief reconnects.

---

<a id="ru"></a>

## Русский

[Читать на английском ↑](#english)

**Простой способ открыть порты на домашнем ПК через серый IP (CGNAT) или динамический IP. Раздавай игровые серверы (Minecraft, CS2, Rust, Valheim), Jellyfin, Plex, сайты или нейронки (Ollama) без обрывов связи при смене IP провайдером.**

### Какую проблему это решает?
Когда поднимаешь дома сервер Minecraft/CS2, Jellyfin, нейронку или сайт, обычно мешают две вещи:
1. Провайдер выдает серый IP (CGNAT), поэтому из интернета к твоему ПК никто не может подключиться.
2. Или провайдер дает динамический белый IP, который периодически меняется. В обычных туннелях (`frp`, `rathole`, `ngrok`, `Cloudflare Tunnel`) при смене IP или переподключении роутера все активные загрузки, стримы и игровые сессии сразу обрываются.

Как это решает `driftless`:
- При смене IP активные TCP-соединения (стримы, загрузки, сайты, SSH) удерживаются в кольцевом буфере памяти (16 МБ) и продолжают передачу с точного байта без разрыва.
- Для UDP (игры, голосовой чат) сохраняется привязка порта и буферизуются пакеты (до 1024 датаграмм на поток) на время короткого переподключения, чтобы игроков не выкидывало с сервера.

---

### Быстрый запуск (2 варианта)

Скачай один готовый файл под свою систему из [Releases](https://github.com/ERETLY/driftless/releases):
- Для Linux (на ВПС или домашний ПК): `driftless-linux-amd64` (или `arm64`)
- Для Windows (на ВПС или домашний ПК): `driftless-windows-amd64.exe`
- Для macOS (на домашний ПК): `driftless-darwin-arm64` (или `amd64`)

---

#### Вариант 1. Через дешевый ВПС (работает у всех, даже если дома серый IP / CGNAT)

**Шаг 1. Запусти на ВПС (Linux или Windows):**
Укажи через запятую порты, которые нужно открыть (TCP и UDP откроются сразу).

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
Сервер сам создаст пароль и сразу выведет на экран готовую команду подключения для домашнего ПК (если нужно посмотреть ее еще раз позже - `./driftless show-token`).

**Шаг 2. Скопируй эту команду и запусти дома на ПК:**
```powershell
.\driftless-windows-amd64.exe client -quic IP_ВПС:4242 -token ПАРОЛЬ -fingerprint ОТПЕЧАТОК
```
Готово. Твой домашний ПК доступен из интернета по адресу `IP_ВПС:8096` и `IP_ВПС:25565`.

---

#### Вариант 2. Вообще без ВПС (если у провайдера динамический белый IP)

Если провайдер дает динамический белый IP, покупать ВПС не нужно. Режим `standalone` сам откроет порты на домашнем роутере через UPnP / NAT-PMP и каждую секунду проверяет внешний IP по STUN:

```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```

**По желанию: добавь `-duck`, чтобы получить постоянный домен**
С флагом `-duck` программа в ту же секунду при смене IP сама обновляет адрес домена и выпускает сертификат:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -duck
```
*(Если есть бесплатный аккаунт на DuckDNS, один раз запусти `-duck mypc:ТВОЙ_ТОКЕН`. Программа сохранит его в `.driftless-ddns.json`, и дальше можно писать просто `-duck`, подключаясь с телефона по адресу `mypc.duckdns.org:8096`.)*

---

### Примеры команд под частые задачи

| Задача | Команда |
| :--- | :--- |
| **Игровой сервер (Minecraft, CS2, Rust, Valheim, Palworld)** - TCP и UDP | `./driftless server -ports 25565,27015` |
| **Медиасервер (Jellyfin / Plex / Home Assistant)** | `./driftless server -ports 8096,8123` |
| **Свой сайт / API** (порт 80 на ВПС -> порт 3000 дома) | `./driftless server -ports 80:3000` |
| **Нейронка (Ollama / OpenWebUI)** с HTTPS | `./driftless server -ports 443:11434/https,3000` |
| **Несколько сайтов и путей на разных доменах** (авто-HTTPS Let's Encrypt) | `./driftless server -vhosts site.ru:3000,site.ru/api:4000,media.site.ru:8096 -vhost-addr :80 -https :443` |
| **В связке с Caddy / Nginx** (открыть порты только внутри ВПС на `127.0.0.1`) | `./driftless server -ports 127.0.0.1:8080:3000` |

---

### Что еще встроено из коробки

- **Автовыбор транспорта QUIC / TCP-Mux (`-transport auto`):** По умолчанию работает по QUIC (`UDP :4242`), а если провайдер или корпоративный файрвол блокирует UDP, сам переключается на мультиплексирование потоков поверх одного TLS/TCP-соединения (`TCP :4242`).
- **Резервирование ВПС (Multi-Gateway):** В `-quic` можно указать несколько серверов через запятую (`-quic vps1:4242,vps2:4242`) для авто-переключения при падении узла.
- **TCP и UDP открываются сразу:** Игры и голосовой чат работают без ручного дописывания `/udp`.
- **Сертификаты и HTTPS:** Авто-получение Let's Encrypt (через `:443` TLS-ALPN-01, `:80` HTTP-01 или DNS-01). Если сертификат уже лежит на диске, программа берет его без пересоздания и заранее продлевает в фоне (когда остается меньше 30 дней).
- **Полная скорость дома по Wi-Fi (`-direct :8888`):** Когда заходишь на сервер с телефона или ноутбука из дома (в одной сети с ПК), трафик идет напрямую через домашний роутер (`192.168.x.x`) на скорости локальной сети в обход ВПС.
- **Безопасность и метрики:** Взаимная аутентификация с привязкой к TLS-сертификату (Channel Binding), бесшовная ротация паролей (`-token новый,старый`), взаимный mTLS (`-client-ca`, `-client-cert`, `-client-key`), фильтрация по IP/подсетям (`-allow-ips`), белый список портов (`-allow-ports`), передача реального IP через HAProxy PROXY protocol v1 (`-proxy-protocol`) и мониторинг Prometheus/JSON (`-metrics 127.0.0.1:9090`).

---

### Все флаги (необязательные)

| Флаг | По умолчанию | Что делает |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Порты: `8096,25565`, `8080:80` или локально `127.0.0.1:8080:80`. Можно дописать `/tcp`, `/udp`, `/https`. |
| `-udp` | `true` | Открывать UDP вместе с TCP (`-udp=false` оставит только TCP). |
| `-quic` | `"0.0.0.0:4242"` | Порт связи на ВПС или список адресов ВПС через запятую на ПК (`vps1:4242,vps2:4242`). |
| `-transport` | `"auto"` | Транспорт туннеля: `"auto"` (QUIC с авто-переходом на TCP-Mux), `"quic"` или `"tcp"`. |
| `-token` | создается сам | Общий пароль (или список паролей через запятую для ротации `"новый,старый"`). |
| `-fingerprint` | `""` | Отпечаток сертификата ВПС (сам подставляется в готовую команду). |
| `-duck` | `""` | Опция авто-домена и сертификата (`-duck` или `-duck домен:токен`). По умолчанию выключена. |
| `-tls` | `false` | Включить HTTPS сразу на всех открытых портах. |
| `-vhosts` | `""` | Раздавать сайты по доменам и путям: `"site.ru:3000,site.ru/api:4000,*.site.ru:5000"`. |
| `-vhost-addr` / `-https` | `":80"` / `""` | Порты HTTP и HTTPS для доменного режима (`-vhosts`). |
| `-tls-cert` / `-tls-key` | `""` | Путь к своим файлам сертификата `.pem`. |
| `-direct` | `":8888"` | Прямое подключение по домашней локалке/Wi-Fi в обход ВПС (`""` - выкл). |
| `-host` | `"127.0.0.1"` | Локальный адрес на домашнем ПК. |
| `-allow-ports` | `""` | Разрешить доступ только к указанным портам на домашнем ПК (например, `"80,8096,25565"`). |
| `-allow-ips` | `""` | Разрешить входящие подключения только с указанных IP или подсетей CIDR (`"192.168.1.0/24,203.0.113.5"`). |
| `-client-ca` / `-client-cert` / `-client-key` | `""` | Опциональная проверка клиентских сертификатов mTLS между ВПС и домашним ПК. |
| `-proxy-protocol` | `false` | Передавать реальный IP клиента локальному TCP-серверу через заголовок HAProxy PROXY protocol v1. |
| `-metrics` | `""` | Адрес HTTP-сервера метрик `/metrics` (Prometheus) и `/status` (JSON), например `"127.0.0.1:9090"`. |
| `-upnp` | `true` | Авто-открытие портов на домашнем роутере через UPnP / NAT-PMP (`standalone`). |
| `-stun` | `"stun.cloudflare.com:3478"` | Свой STUN-сервер или список через запятую для проверки внешнего IP (`standalone`). |
| `-stun-interval` | `1s` | Частота проверки внешнего IP по STUN (`standalone`). |
| `-ddns-provider` | `""` | Другие DDNS-сервисы: `"cloudflare"` or `"noip"`. |
| `-max-buf` / `-max-mem` | `16 МБ` / `256 МБ` | Лимиты оперативной памяти на одно соединение и на всю программу. |
| `-session-ttl` | `90s` | Сколько секунд удерживать соединение при переподключении интернета дома. |

---

### Сравнение с аналогами

| Что умеет | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare Tunnel | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Стримы и загрузки не рвутся при смене IP | Да (буфер 16 МБ в памяти) | Нет (обрыв) | Нет (обрыв) | Да |
| Автовыбор QUIC и fallback на TCP-Mux | Да (`-transport auto`) | Отдельные конфиги | Да | Только UDP |
| Может работать вообще без ВПС (`standalone`) | Да (UPnP + STUN + DDNS) | Нет | Нет | Нет |
| Встроенный HTTPS и сертификаты | Да | Нужны конфиги | Да | Нет (нужен Nginx/Caddy) |
| TCP + UDP открываются по умолчанию | Да | Отдельные блоки | Платно / урезанный UDP | Ручной `iptables` |
| Прямое подключение дома по Wi-Fi в обход ВПС | Да (`-direct :8888`) | Нет | Нет | Нужен Split-DNS |
| Работает без прав root и сетевых карт | Да (1 файл) | Да | Да | Нет |

---

### Частые вопросы (FAQ)

**Как открыть порты через серый IP (CGNAT) для сервера Minecraft, CS2 или Jellyfin?**
Запусти `./driftless server -ports 25565,8096` на любом дешевом ВПС, а на домашнем ПК выполни готовую команду `client`, которую выведет сервер. Домашний ПК сам пробьет исходящий туннель к ВПС, поэтому серый IP провайдера и закрытые порты на роутере не мешают подключению.

**Почему в `frp`, `ngrok` и `Cloudflare Tunnel` рвутся загрузки и стримы при смене динамического IP?**
Обычные туннели жестко привязывают каждое пользовательское соединение к текущему сокету туннеля. Когда провайдер меняет внешний IP или переподключает PPPoE, сокет закрывается и все активные загрузки, видеопотоки или SSH-сессии падают с ошибкой `connection reset`. В `driftless` соединения отделены от туннельного сокета через кольцевой буфер 16 МБ в оперативной памяти: как только клиент переподключается с нового IP, передача продолжается с точного байта без разрыва.

**Как открыть порты на домашнем ПК без покупки ВПС, если IP белый, но динамический?**
Используй режим `./driftless standalone -ports 25565,8096 -duck`. Программа сама пробросит TCP и UDP порты на домашнем роутере по UPnP / NAT-PMP, каждую секунду будет отслеживать смену внешнего IP через STUN и мгновенно обновлять привязанный домен DuckDNS.

## License

[MIT](LICENSE)
