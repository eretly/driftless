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

**Run on your Home PC (just open ports on router automatically):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```

**Or with a free DuckDNS domain (auto-updates IP when ISP changes it):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -ddns-provider duckdns -ddns-domain mypc -ddns-token YOUR_DUCKDNS_TOKEN
```

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

### All Flags (for advanced setup)

Most flags are optional - the defaults work out of the box.

| Flag | Default | What it does |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Ports to open. Write `8096,25565` (if public and local ports match) or `8080:80`. Add `/tcp`, `/udp`, or `/https` if needed. |
| `-udp` | `true` | Opens both UDP and TCP on every port by default. Set `-udp=false` if you only want TCP. |
| `-quic` | `"0.0.0.0:4242"` | Tunnel port on VPS (`0.0.0.0:4242`) or VPS address on Home PC (`VPS_IP:4242`). |
| `-token` | auto | Password between VPS and Home PC. Generated automatically on VPS if not set. |
| `-token-file` | `""` | Read password from a text file. |
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

**Запуск на домашнем ПК (просто пробить порты на роутере автоматом):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```

**Запуск на домашнем ПК + автообновление бесплатного домена DuckDNS при смене IP:**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -ddns-provider duckdns -ddns-domain mypc -ddns-token ТВОЙ_ТОКЕН_DUCKDNS
```

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

### Все флаги (если нужно настроить что-то свое)

Обычно трогать их не нужно - стандартные настройки уже выставлены нормально.

| Флаг | По умолчанию | Что делает |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Какие порты открыть. Если порт на входе и дома одинаковый, пиши просто одно число (`8096,25565`). Если разные - через двоеточие (`8080:80`). В конце порта можно дописать `/tcp`, `/udp` или `/https`. |
| `-udp` | `true` | Открывать UDP вместе с TCP на всех портах по умолчанию (`-udp=false` оставит только TCP). |
| `-quic` | `"0.0.0.0:4242"` | Порт связи на ВПС (`0.0.0.0:4242`), а на домашнем ПК туда пишется адрес ВПС (`IP_ВПС:4242`). |
| `-token` | создается сам | Общий пароль между ВПС и домашним ПК. На ВПС генерируется сам, если не указать. |
| `-token-file` | `""` | Прочитать пароль из текстового файла. |
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
