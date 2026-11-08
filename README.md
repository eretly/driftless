# driftless

> [🇺🇸 English](#english) | [🇷🇺 Русский](#ru)

---

<a id="english"></a>

## English

**Open ports to your Home PC and host game servers, websites, Jellyfin, or Ollama without disconnects when your home IP changes.**

### What problem does this solve?
Suppose you run a Minecraft/CS2 server, Jellyfin media server, local AI (Ollama), or a website on your Home PC:
1. Your ISP gives you a "gray" IP (CGNAT), so nobody from the internet can connect to your PC at all.
2. Or your ISP gives you a dynamic IP that changes every few hours or days. Every time your IP changes, normal tunnels (`frp`, `ngrok`, `Cloudflare Tunnel`) drop all active streams, downloads, and game connections.

`driftless` fixes both problems. When your home IP changes, it holds active connections in memory for a moment and switches them to your new IP seamlessly - video streams, file downloads, and games keep running without dropping.

---

### How to run (2 ways)

Download the file for your system from [Releases](https://github.com/ERETLY/driftless/releases) (all modes work on Windows, Linux, and macOS):
- For Linux (VPS or Home PC): `driftless-linux-amd64`
- For Windows (Home PC or Windows VPS): `driftless-windows-amd64.exe`
- For macOS: `driftless-darwin-arm64`

---

#### Way 1. With a cheap VPS (Works on ANY internet, including CGNAT / "gray" IP)

Rent any cheap $2 VPS (Linux or Windows), run one file on the VPS and the same file on your Home PC.

**1. Run on your VPS:**
List the ports you want to open separated by commas (both TCP and UDP open automatically).

On a **Linux** VPS:
```bash
wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
chmod +x driftless
./driftless server -ports 8096,25565
```

On a **Windows** VPS:
```powershell
.\driftless-windows-amd64.exe server -ports 8096,25565
```
*(You don't need to invent a password or look up your IP. The server generates a password and prints a ready-to-copy command for your Home PC right in the console.)*

**2. Copy that command from the VPS console and run it on your Home PC:**
```powershell
.\driftless-windows-amd64.exe client -quic YOUR_VPS_IP:4242 -token PASSWORD_FROM_CONSOLE -fingerprint CERT_HASH
```
Done. Anyone connecting to `YOUR_VPS_IP:8096` or `YOUR_VPS_IP:25565` lands on your Home PC.

---

#### Way 2. Without a VPS at all (Runs only on your Home PC)

If your ISP gives you a public ("white") dynamic IP - even if it changes every 10 minutes - you don't need a VPS.

Run `driftless` in `standalone` mode on your Home PC:
- It opens the ports on your home router automatically via UPnP (no need to log into `192.168.1.1`).
- It checks your external IP every second.

**Run on your Home PC (by default, just opens ports on your IP):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```

**Optional: automatic domain and HTTPS certificate with `-duck`**
By default, automatic domain and certificate creation are turned off. To turn them on, just add `-duck` at the end:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -duck
```
*(Or if you have your own DuckDNS account, pass `-duck mypc:YOUR_TOKEN` the first time - after that you can run it with just `-duck`.)*

What `-duck` does when enabled:
- Gives you a ready domain name (either your saved `mypc.duckdns.org` or an automatic domain if you didn't enter a token) and prints it once in the console ready to copy.
- Checks if an HTTPS certificate for that domain already exists on disk: if it already exists, it simply uses it without creating a new one; if not, it creates and saves the certificate automatically.

---

### Ready-to-copy commands for common tasks

| What you are hosting | Command to run |
| :--- | :--- |
| **Minecraft, CS2, Rust, Valheim, Palworld** (TCP + UDP open by default) | `./driftless server -ports 25565,27015` |
| **Jellyfin / Plex** media server | `./driftless server -ports 8096` |
| **Website** (VPS port 80 -> Home PC port 3000) | `./driftless server -ports 80:3000` |
| **Ollama / OpenWebUI** with HTTPS encryption | `./driftless server -ports 443:11434/https,3000` |
| **Multiple domains & URL paths** on one VPS (with automatic Let's Encrypt HTTPS) | `./driftless server -vhosts site.com:3000,site.com/api:4000,media.site.com:8096 -vhost-addr :80 -https :443` |
| **Together with Caddy / Nginx** (open ports only locally on `127.0.0.1`) | `./driftless server -ports 127.0.0.1:8080:3000` |

---

### Useful built-in features

- **UDP works out of the box:** Every port in `-ports` opens both TCP and UDP by default, so game servers and voice chat work right away.
- **Built-in HTTPS and certificates:**
  - If you pass `-duck domain:token` or `-vhosts`, `driftless` checks if a certificate for your domain already exists. If it does, it uses the existing certificate; if not, it creates/obtains one (including Let's Encrypt on public domains) and saves it to disk for next runs.
  - On regular ports, add `/https` (for example `-ports 443:8096/https`) or `-tls` to enable HTTPS.
- **Full local speed when you are at home (`-direct :8888`):** When you connect to your server from your phone or laptop on the same home Wi-Fi, traffic doesn't go to the VPS and back. It connects straight to your PC through your home router (`192.168.x.x`) at the full speed of your local network without losing speed to the VPS.
- **Built-in protection:** The ready command printed on the VPS already includes a random password and certificate fingerprint check (`-fingerprint`), memory buffers are capped (`16 MB` per stream, `256 MB` total), and `-allow-ports` lets you restrict which local ports your Home PC allows.

---

### All Flags (optional)

| Flag | Default | What it does |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Ports to open: `8096,25565`, `8080:80`, or local-only `127.0.0.1:8080:80`. Add `/tcp`, `/udp`, or `/https` if needed. |
| `-udp` | `true` | Opens both UDP and TCP on every port by default (`-udp=false` for TCP only). |
| `-quic` | `"0.0.0.0:4242"` | Tunnel port on VPS (`0.0.0.0:4242`) or VPS address on Home PC (`VPS_IP:4242`). |
| `-token` | auto | Password between VPS and Home PC (generated automatically on VPS if omitted). |
| `-fingerprint` | `""` | VPS certificate fingerprint (automatically included in the command printed by the server). |
| `-duck` | `""` | Optional DuckDNS `"subdomain:token"`. Disabled by default. When set, updates your domain IP and uses/creates the domain certificate. |
| `-tls` | `false` | Turn on HTTPS encryption on all ports in `-ports`. |
| `-vhosts` | `""` | Route domains and URL paths to local ports: `"site.com:3000,site.com/api:4000,*.site.com:5000"`. |
| `-vhost-addr` | `":80"` | HTTP/HTTPS port for domain routing (`-vhosts`). |
| `-https` | `""` | Additional HTTPS port for domain routing (e.g. `":443"`). |
| `-tls-cert` / `-tls-key` | `""` | Path to your own `.pem` certificate and key files (optional). |
| `-direct` | `":8888"` | Port for direct connection over home Wi-Fi/LAN bypassing the VPS (`""` to disable). |
| `-host` | `"127.0.0.1"` | Local address on your Home PC. |
| `-allow-ports` | `""` | Restrict which local ports on your Home PC can be accessed (e.g. `"80,8096,25565"`). |
| `-upnp` | `true` | Automatically open ports on your home router via UPnP / NAT-PMP (`standalone` mode). |
| `-stun` | `"stun.l.google.com:19302"` | STUN server used to check your external IP (`standalone` mode). |
| `-stun-interval` | `1s` | How often to check if your IP changed (`standalone` mode). |
| `-ddns-provider` | `""` | Other DDNS providers if not using `-duck`: `"cloudflare"` or `"noip"`. |
| `-ddns-domain` / `-ddns-token` | `""` | Domain and token for Cloudflare or No-IP. |
| `-max-buf` / `-max-mem` | `16 MB` / `256 MB` | RAM buffer limits per connection and for the whole program. |
| `-session-ttl` | `90s` | How long to hold active connections while waiting for home internet to reconnect. |

---

### Comparison with other tools

| Feature | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Streams/downloads survive IP change | Yes (16 MB RAM buffer) | No (connection drops) | No (connection drops) | Yes |
| Can work without a VPS (`standalone`) | Yes (Auto-UPnP + STUN + DDNS) | No | No | No |
| Built-in HTTPS & certificates | Yes | Manual config files | Yes | No (needs Nginx/Caddy) |
| TCP + UDP open by default | Yes | Separate config blocks | Paid / limited UDP | Manual `iptables` |
| Direct home Wi-Fi/LAN connection bypassing VPS (no speed loss) | Yes (`-direct :8888`) | No | No | Split-DNS required |
| Works without root or virtual network cards | Yes (1 file) | Yes | Yes | No |

---

<a id="ru"></a>

## Русский

> [🇺🇸 Читать на английском ↑](#english)

**Простой способ открыть порты на домашнем ПК и раздавать игры, сайты, Jellyfin или нейронки (Ollama) без обрывов связи при смене IP.**

### Зачем это нужно простыми словами?
Допустим, ты запустил у себя дома на ПК сервер Minecraft/CS2, медиасервер Jellyfin/Plex, нейронку или свой сайт. Обычно мешают две проблемы:
1. Провайдер дает "серый" IP (CGNAT) - из интернета к твоему ПК вообще никто не может подключиться.
2. Или провайдер дает динамический IP, который меняется раз в сутки или при перезагрузке роутера. В обычных туннелях (`frp`, `ngrok`, `Cloudflare`) в момент смены IP все активные загрузки, стримы и игровые сессии сразу обрываются.

`driftless` решает обе проблемы. Когда провайдер меняет твой IP, программа придерживает данные в оперативной памяти на долю секунды и продолжает передачу уже с нового IP - фильм, скачивание файла или игра на сервере не вылетают.

---

### Как запустить (за 30 секунд)

Скачай один готовый файл под свою систему из раздела [Releases](https://github.com/ERETLY/driftless/releases) (все режимы одинаково работают на Windows, Linux и macOS):
- Для Linux (на ВПС или домашний ПК): `driftless-linux-amd64`
- Для Windows (на домашний ПК или на Windows ВПС): `driftless-windows-amd64.exe`
- Для macOS: `driftless-darwin-arm64`

Дальше выбери один из двух вариантов запуска:

---

#### Вариант 1. Через дешевый ВПС (работает вообще у всех, даже если дома "серый" IP)

Берешь любой дешевый ВПС за 100-200 рублей в месяц (подойдет и Linux ВПС, и Windows ВПС), запускаешь файл на ВПС и такой же файл у себя дома на ПК.

**Шаг 1. Запусти на ВПС:**
Просто напиши через запятую порты, которые нужно открыть (и TCP, и UDP для игр откроются сами).

Если ВПС на **Linux**:
```bash
wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
chmod +x driftless
./driftless server -ports 8096,25565
```

Если ВПС на **Windows**:
```powershell
.\driftless-windows-amd64.exe server -ports 8096,25565
```
Придумывать пароль или искать свой IP не надо: программа на ВПС сама создаст пароль и выведет в консоль готовую строчку для твоего домашнего ПК.

**Шаг 2. Скопируй эту строчку из консоли ВПС и запусти дома на ПК:**
```powershell
.\driftless-windows-amd64.exe client -quic IP_ТВОЕГО_ВПС:4242 -token ПАРОЛЬ_ИЗ_КОНСОЛИ -fingerprint ОТПЕЧАТОК
```
Всё. Теперь любой, кто зайдет на `IP_ТВОЕГО_ВПС:8096` или `25565`, попадает прямо на твой домашний ПК.

---

#### Вариант 2. Вообще без ВПС (только на домашнем ПК)

Если у тебя дома "белый" (публичный) IP - даже если провайдер меняет его каждые 10 минут - покупать ВПС не нужно.

Запускаешь `driftless` в режиме `standalone` только у себя на ПК:
- Программа сама откроет нужные порты на твоем домашнем роутере через UPnP (в настройки роутера `192.168.1.1` лазить не придется).
- Каждую секунду она проверяет твой внешний IP.

**Обычный запуск по умолчанию (просто открывает порты по твоему IP):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565
```

**По желанию: авто-домен и сертификат одной опцией `-duck`**
По умолчанию никакие домены и сертификаты сами не создаются. Если нужен готовый домен и HTTPS-сертификат, просто допиши в конце `-duck`:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565 -duck
```
*(А если у тебя есть свой аккаунт на DuckDNS, можешь один раз написать `-duck mypc:ТВОЙ_ТОКЕН` - программа его запомнит, и дальше тоже можно запускать просто с `-duck`.)*

Что делает `-duck`:
- Сам подхватывает твой домен DuckDNS (или выдает готовый авто-домен, если токен вообще не вводился) и один раз выводит готовый адрес в консоль, чтобы ты мог его скопировать.
- Проверяет сертификат на диске: если сертификат уже есть - просто использует его и заново не создает. Если сертификата еще нет - один раз создаст его, сохранит и сразу подключит.

---

### Готовые команды под частые задачи

| Что хочешь раздать с ПК | Какую команду запустить |
| :--- | :--- |
| **Игровой сервер (Minecraft, CS2, Rust, Valheim)** - TCP и UDP уже включены | `./driftless server -ports 25565,27015` |
| **Медиасервер (Jellyfin / Plex)** | `./driftless server -ports 8096` |
| **Свой сайт** (открыть порт 80 на ВПС, а дома сайт на порту 3000) | `./driftless server -ports 80:3000` |
| **Нейронка (Ollama / OpenWebUI)** сразу с HTTPS | `./driftless server -ports 443:11434/https,3000` |
| **Несколько сайтов и путей на разных доменах** (HTTP + HTTPS работают сами) | `./driftless server -vhosts site.ru:3000,site.ru/api:4000,media.site.ru:8096 -vhost-addr :80 -https :443` |
| **В связке с Caddy / Nginx** (открыть порты только внутри ВПС на `127.0.0.1`) | `./driftless server -ports 127.0.0.1:8080:3000` |

---

### Полезные фишки из коробки

- **UDP для игр работает сразу:** Любой порт в `-ports` по умолчанию открывает сразу и TCP, и UDP. Игры и голосовой чат работают без дописывания `/udp`.
- **Сертификаты и HTTPS без лишней возни:**
  - Если ты указал `-duck домен:токен` или домены в `-vhosts`, программа сначала смотрит, есть ли уже сертификат для этого домена. Если есть - просто берет его и не пересоздает. Если нет - сама выпускает и сохраняет на диск для следующих запусков.
  - Если нужен HTTPS на обычном порту без домена, просто допиши `/https` (например, `-ports 443:8096/https`) или флаг `-tls`.
- **Прямое подключение дома по Wi-Fi без потери скорости (`-direct :8888`):** Когда ты заходишь на свой сервер с телефона или ноутбука из дома (в одной сети с ПК), трафик не гоняется туда-обратно через ВПС. Программа соединяет устройство напрямую с твоим ПК через домашний роутер (`192.168.x.x`) на максимальной скорости твоей домашней сети, чтобы ВПС не резал скорость.
- **Защита без ручной настройки:** В готовую команду, которую выводит ВПС, уже вшиты случайный пароль и проверка сертификата сервера (`-fingerprint`), память под буферы ограничена (`16 МБ` на соединение, `256 МБ` всего), а флагом `-allow-ports` дома можно разрешить доступ только к нужным портам.

---

### Все флаги (если нужно настроить под себя)

Обычно трогать их не нужно - стандартные настройки уже выставлены нормально.

| Флаг | По умолчанию | Что делает |
| :--- | :--- | :--- |
| `-ports` | `"8080:80,8096:8096"` | Какие порты открыть: `8096,25565`, `8080:80` или локально `127.0.0.1:8080:80`. В конце можно дописать `/tcp`, `/udp` или `/https`. |
| `-udp` | `true` | Открывать UDP вместе с TCP на всех портах по умолчанию (`-udp=false` оставит только TCP). |
| `-quic` | `"0.0.0.0:4242"` | Порт связи на ВПС (`0.0.0.0:4242`), а на домашнем ПК туда пишется адрес ВПС (`IP_ВПС:4242`). |
| `-token` | создается сам | Общий пароль между ВПС и домашним ПК. На ВПС генерируется сам, если не указать. |
| `-fingerprint` | `""` | Отпечаток сертификата ВПС (сам подставляется в готовую команду в консоли ВПС). |
| `-duck` | `""` | Опция для DuckDNS `"домен:токен"`. По умолчанию выключена. Если указать - обновляет IP на домене и использует (или создает, если еще нет) сертификат. |
| `-tls` | `false` | Включить встроенный HTTPS сразу на всех открытых портах. |
| `-vhosts` | `""` | Раздавать сайты по доменам и путям: `"site.ru:3000,site.ru/api:4000,*.site.ru:5000"`. |
| `-vhost-addr` | `":80"` | Порт для доменного режима (`-vhosts`). |
| `-https` | `""` | Дополнительный порт под HTTPS для доменов (например, `":443"`). |
| `-tls-cert` / `-tls-key` | `""` | Путь к своим файлам сертификата `.pem` (необязательно). |
| `-direct` | `":8888"` | Порт для прямого подключения по домашней локалке/Wi-Fi в обход ВПС без потери скорости (`""` чтобы выключить). |
| `-host` | `"127.0.0.1"` | Локальный адрес на домашнем ПК. |
| `-allow-ports` | `""` | Разрешить доступ только к указанным портам на домашнем ПК (например, `"80,8096,25565"`). |
| `-upnp` | `true` | Автоматически открывать порты на домашнем роутере через UPnP / NAT-PMP (в режиме `standalone`). |
| `-stun` | `"stun.l.google.com:19302"` | STUN-сервер для быстрой проверки внешнего IP (в режиме `standalone`). |
| `-stun-interval` | `1s` | Как часто проверять смену внешнего IP (в режиме `standalone`). |
| `-ddns-provider` | `""` | Другие DDNS-сервисы (если не `-duck`): `"cloudflare"` или `"noip"`. |
| `-ddns-domain` / `-ddns-token` | `""` | Домен и токен для Cloudflare или No-IP. |
| `-max-buf` / `-max-mem` | `16 МБ` / `256 МБ` | Лимиты оперативной памяти на одно соединение и на всю программу. |
| `-session-ttl` | `90s` | Сколько секунд удерживать соединение при переподключении интернета дома. |

---

### Чем отличается от других программ

| Что умеет | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Стримы и загрузки не рвутся при смене IP | Да (буфер 16 МБ в памяти) | Нет (обрыв соединения) | Нет (обрыв соединения) | Да |
| Может работать вообще без ВПС (`standalone`) | Да (Авто-UPnP + STUN + DDNS) | Нет | Нет | Нет |
| Встроенный HTTPS и сертификаты | Да | Нужно писать конфиги | Да | Нет (нужен Nginx/Caddy) |
| TCP + UDP открываются по умолчанию | Да | Нужно прописывать отдельно | Платно / урезанный UDP | Ручная настройка `iptables` |
| Прямое подключение дома по Wi-Fi в обход ВПС (без потери скорости) | Да (`-direct :8888`) | Нет | Нет | Нужен свой Split-DNS |
| Работает без прав root и сетевых карт | Да (один файл) | Да | Да | Нет |

## License

[MIT](LICENSE)
