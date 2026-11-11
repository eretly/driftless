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
- Active UDP game and voice sessions keep their port mapping and buffer brief link blips (up to 1024 datagrams within a strict 2-second freshness window so stale packets are never replayed after a long outage).

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

### How to connect from a phone or any device (WebSSH, AnyDesk, RDP, Jellyfin)

`driftless` only needs to run on **one device** (your Home PC with a dynamic IP, or VPS + Home PC). You **do not** need to install `driftless` or any VPN on your iPhone or Android, and you do not need to use a browser if you connect through apps like **WebSSH**, **AnyDesk**, or **Windows App (RDP)**.

#### 1. Direct connection via WebSSH, AnyDesk, or RDP (no browser needed)

**Step 1 (on your Home PC):**
Open the ports for the apps you use (`22` for WebSSH/SSH, `7070` for AnyDesk direct connection, `3389` for Windows Remote Desktop):
```powershell
.\driftless-windows-amd64.exe standalone -ports 22,7070,3389 -duck mypc:YOUR_DUCKDNS_TOKEN
```
*(If your ISP uses CGNAT / "gray" IP, run `./driftless server -ports 22,7070,3389` on a VPS and the printed `client` command on your PC. Your address will be `YOUR_VPS_IP` instead of `mypc.duckdns.org`.)*

**Step 2 (in the app on your iPhone / Android):**

- **In WebSSH / Termius / Blink (SSH & SFTP terminal):**
  - **Host / IP:** `mypc.duckdns.org` (or the current IP shown in the `driftless` console)
  - **Port:** `22`
  - **User:** your Windows / Linux username on the PC
  - **Password or Private Key:** your normal PC account password, or your standard SSH private key (`id_ed25519` / `id_rsa`) if you added your public key to `~/.ssh/authorized_keys` on the PC. (`driftless` itself does not require any special key on your phone).
- **In AnyDesk (direct lag-free connection without relay servers):**
  - On your PC, AnyDesk listens on TCP port `7070` for direct connections.
  - In the AnyDesk app on your iPhone/Android, instead of the 9-digit ID, enter: `mypc.duckdns.org:7070` and enter your AnyDesk unattended password.
- **In Windows App / Microsoft Remote Desktop (full Windows screen):**
  - **PC Name:** `mypc.duckdns.org:3389`
  - **User Account:** your Windows login and password.

| What you want to open on your PC | App for iPhone / Android | What to enter in the app |
| :--- | :--- | :--- |
| **SSH / SFTP console & files** | **WebSSH** / Termius / JuiceSSH | Host: `mypc.duckdns.org`, Port: `22`, PC login & password (or SSH key) |
| **AnyDesk (direct TCP mode)** | **AnyDesk** | Remote Address: `mypc.duckdns.org:7070` |
| **Windows Remote Desktop (RDP)** | **Windows App** (Microsoft Remote Desktop) | PC Name: `mypc.duckdns.org:3389`, Windows login & password |
| **PC gaming from phone (Sunshine)** | **Moonlight** | Host: `mypc.duckdns.org` (open ports `47984,47989,48010`) |
| **Movies & media (Jellyfin / Plex)** | **Jellyfin Mobile** / Swiftfin / Infuse | `http://mypc.duckdns.org:8096` |
| **Files / folders (SFTP)** | **WebSSH (SFTP)** / Owlfiles / Documents | Host: `mypc.duckdns.org`, Port: `22` |
| **Minecraft (Bedrock `:19132` / Java `:25565`)** | **Minecraft** / PojavLauncher | Server Address: `mypc.duckdns.org`, Port: `19132` or `25565` |

#### 2. Optional Stealth Mode (`-knock`)
If you want ports `22`, `3389`, and `7070` to stay **completely invisible and closed** to bots and scanners until you unlock them from your phone, add `-knock`:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,3389,22,7070 -duck mypc:YOUR_TOKEN -knock
```
What `-knock` does:
1. **Mandatory HTTPS/TLS & Let's Encrypt:** Enabling `-knock` automatically activates TLS and rejects unencrypted `http://` knock requests (`400 Bad Request`). On a public domain (such as `mypc.duckdns.org`), `driftless` obtains a real Let's Encrypt certificate (via DNS-01 or TLS-ALPN-01) and never silently downgrades to an untrusted self-signed certificate. For raw IP mode without a domain, `driftless` persists a local Root CA (`.driftless-certs/ca-root.crt`) and provides a 1-tap `/ca.crt` download + SHA-256 fingerprint so you can install/verify the CA once and prevent MITM.
2. **Short 1-Hour TTL, Per-Port Scope & Instant Revocation:** Opening the `https://` Magic Link unlocks your phone's IP for 1 hour by default (`-knock-ttl 1h`), scoped strictly to your mapped ports (no LAN pivoting or open proxy). You can unlock a single port only by adding `?port=22` (`/__driftless_knock/SECRET?port=22`), or revoke access immediately at any time with 1 tap (`/__driftless_knock/SECRET/revoke` or `/revoke?all=1`).
3. **Single-Port Universal Routing:** Even on restricted Wi-Fi where only one port (e.g. `8096`) is open, you can enter port `8096` directly inside **WebSSH** or **Windows App** and `driftless` automatically routes SSH (`SSH-2.0-`) to `:22` and RDP (`0x03 0x00`) to `:3389` (when that port is unlocked for your IP).

---

### Common Tasks

| Task | Command |
| :--- | :--- |
| **Game server (Minecraft, CS2, Rust, Valheim, Palworld)** - TCP + UDP | `./driftless server -ports 25565,27015` |
| **Jellyfin / Plex / Home Assistant** | `./driftless server -ports 8096,8123` |
| **Remote Desktop + SSH from phone with Stealth Magic Link** | `./driftless standalone -ports 8096,3389,22 -duck -knock` |
| **Website / API** (VPS port 80 -> Home PC port 3000) | `./driftless server -ports 80:3000` |
| **Ollama / OpenWebUI** with HTTPS | `./driftless server -ports 443:11434/https,3000` |
| **Multiple domains & URL paths** (with Let's Encrypt HTTPS) | `./driftless server -vhosts site.com:3000,site.com/api:4000,media.site.com:8096 -vhost-addr :80 -https :443` |
| **Behind Caddy / Nginx** (bind tunnel ports only to `127.0.0.1`) | `./driftless server -ports 127.0.0.1:8080:3000` |

---

### Built-in Features

- **QUIC + automatic TCP-Mux fallback (`-transport auto`):** Uses multiplexed QUIC (`UDP :4242`) by default and falls back to multiplexed TLS over TCP (`TCP :4242`) when UDP is blocked by firewalls or strict NATs.
- **Multi-Gateway failover:** Pass multiple VPS addresses in `-quic vps1:4242,vps2:4242` for automatic failover.
- **TCP + UDP by default:** Every port in `-ports` forwards both TCP and UDP automatically.
- **Zero-Client Mobile Knock & Single-Port Protocol Router (`-knock`):** Keep all TCP/UDP ports stealthed until unlocked by an HTTPS bookmark on your phone (1h default TTL, per-port `?port=22` support, and 1-tap `/revoke`), download auto-configured `.rdp` profiles, and route SSH, RDP, and HTTP over a single open port.
- **Smart Ephemeral Port Bridging (`standalone`):** If a local service (`3389`, `8096`, `25565`) is already listening on `0.0.0.0` on your Home PC, `standalone` mode automatically bridges router UPnP / NAT-PMP / PCP v2 external ports to an internal ephemeral listener so `-tls`, `-knock`, and `-allow-ips` work without port conflicts.
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
| `-knock` | `false` | Enable HTTPS Mobile Knock stealth gatekeeper (per-port unlock, instant IP revoke, `.rdp` / `ssh://` launchpad). |
| `-knock-token` | auto | Optional custom secret for `-knock` Magic Link (auto-generated and saved if omitted). |
| `-knock-ttl` | `1h` | How long a phone/device IP stays unlocked after opening the Magic Knock Link (default `1h`). |
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
| `-upnp` | `true` | Auto-open ports on home router via UPnP / NAT-PMP / PCP v2 (`standalone` mode). |
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
| Zero-Client Mobile Knock & Single-Port Mux | Yes (`-knock`) | No | No | Needs client app on phone |
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
Yes. Unlike HTTP-only tunnels (`Cloudflare Tunnel`, free `ngrok`), `driftless` forwards both TCP and UDP on every port by default, preserves per-client UDP port mappings across brief link blips, and enforces a 2-second packet freshness window so stale UDP datagrams are discarded rather than replayed after a longer disconnect (note that UDP itself does not guarantee packet delivery or order, so surviving multi-second outages depends on the game server's own client timeout).

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
- Для UDP (игры, голосовой чат) сохраняется привязка порта и буферизуются свежие пакеты (до 1024 датаграмм в окне свежести до 2 секунд) на время короткого переключения связи, при этом устаревшие пакеты старше 2 секунд автоматически отбрасываются.

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

Если провайдер дает динамический белый IP, покупать ВПС не нужно. Режим `standalone` сам откроет порты на домашнем роутере через UPnP / NAT-PMP / PCP v2 и каждую секунду проверяет внешний IP по STUN:

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

### Как подключиться к ПК с айфона или андроида через WebSSH, AnyDesk или RDP (без браузера)

Программа `driftless` ставится **только на одном устройстве** - на твоем домашнем ПК с динамическим IP (или на ВПС + ПК). На сам айфон или андроид **ничего ставить не нужно**, и браузер открывать не обязательно - ты подключаешься напрямую через свои привычные приложения (**WebSSH**, **AnyDesk**, **Windows App**).

#### 1. Прямое подключение через WebSSH, AnyDesk или RDP

Зачем вообще нужен `driftless`, если есть WebSSH или AnyDesk?
Когда на домашнем ПК динамический IP, роутер по умолчанию закрывает входящие порты (`22`, `7070`, `3389`), а провайдер периодически меняет сам IP-адрес, из-за чего старый IP в WebSSH перестает работать. `driftless` сам открывает нужные порты на роутере по UPnP / NAT-PMP / PCP v2 и каждую секунду обновляет твой постоянный адрес (например `mypc.duckdns.org`), удерживая активные сессии при смене IP.

**Шаг 1 (на домашнем ПК):**
Открой порты под свои программы (`22` - для WebSSH/SSH, `7070` - для прямого подключения AnyDesk, `3389` - для удаленного рабочего стола Windows):
```powershell
.\driftless-windows-amd64.exe standalone -ports 22,7070,3389 -duck mypc:ТВОЙ_ТОКЕН_DUCKDNS
```
*(Если не хочешь регистрировать DuckDNS, запусти просто `.\driftless-windows-amd64.exe standalone -ports 22,7070,3389` - программа напишет в консоли твой текущий внешний IP, который можно сразу вводить в WebSSH).*

**Шаг 2 (что вводить в приложении на айфоне / андроиде):**

- **Как подключиться через WebSSH (или Termius) на iPhone:**
  Открой **WebSSH** -> нажми **«+» (Add Connection)** и заполни поля:
  - **Host / IP:** `mypc.duckdns.org` (или внешний IP из консоли `driftless`, либо `IP_ВПС`, если работаешь через ВПС)
  - **Port:** `22`
  - **User (Имя пользователя):** имя твоей учетной записи на ПК (в Windows или Linux; важно: на самом ПК должен быть включен стандартный OpenSSH Server)
  - **Password или Private Key (Секретный ключ):**
    - Для самой программы `driftless` **никакой секретный ключ вводить не нужно**.
    - В поле **Password** введи обычный пароль от своей учетки ПК.
    - Поле **Private Key** в WebSSH нужно только в том случае, если ты сам настроил вход по SSH-ключу вместо пароля (тогда туда вставляется твой стандартный ключ `id_ed25519` / `id_rsa`).
- **Как подключиться через AnyDesk напрямую без лагов:**
  - По умолчанию AnyDesk гонит трафик через свои облачные ретрансляторы (по ID из 9 цифр), которые часто тормозят или режут скорость.
  - Когда `driftless` открыл порт `7070`, в приложении **AnyDesk** на айфоне в поле адреса вместо цифр ID впиши: `mypc.duckdns.org:7070` и введи свой постоянный пароль AnyDesk. Соединение пойдет **напрямую** телефон <-> твой ПК с минимальным пингом.
- **Как подключиться через Windows App (бывший Microsoft Remote Desktop):**
  - Добавь ПК -> в поле **Имя ПК (PC Name)** впиши `mypc.duckdns.org:3389`, укажи логин и пароль от своей учетки Windows.

| Через что подключаемся с телефона | Какой порт открыть в `-ports` на ПК | Что вводить в приложении на iPhone / Android |
| :--- | :--- | :--- |
| **WebSSH / Termius (терминал и SFTP-файлы)** | `22` | Host: `mypc.duckdns.org`, Port: `22`, логин и пароль от ПК (или свой SSH-ключ) |
| **AnyDesk (прямое подключение без облака)** | `7070` | В строке адреса вместо ID: `mypc.duckdns.org:7070` |
| **Windows App / RDP (рабочий стол Windows)** | `3389` | Компьютер: `mypc.duckdns.org:3389`, логин и пароль Windows |
| **Moonlight (ПК-игры через Sunshine)** | `47984,47989,48010` | Хост: `mypc.duckdns.org` |
| **Jellyfin / Plex / Infuse (фильмы с ПК)** | `8096` | Адрес сервера: `http://mypc.duckdns.org:8096` |
| **Minecraft (Bedrock `:19132` / Java `:25565`)** | `19132` или `25565` | Сервер: `mypc.duckdns.org`, порт `19132` или `25565` |

#### 2. По желанию: Стелс-защита портов (`-knock`)
Если не хочешь держать порты `22` (SSH) или `3389` (RDP) открытыми для всего интернета и ботов, добавь флаг `-knock`:
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,3389,22,7070 -duck mypc:ТВОЙ_ТОКЕН -knock
```
Что дает `-knock`:
1. **Обязательный HTTPS/TLS и защита от MITM:** При включении `-knock` программа автоматически включает шифрование TLS и отклоняет незашифрованные `http://` запросы (`400 Bad Request`). Для публичного домена (например `mypc.duckdns.org`) выпускается настоящий доверенный сертификат Let's Encrypt (через DNS-01 или TLS-ALPN-01) без тихого отката на самоподписанный сертификат. Если же подключаешься по IP без домена, программа сохраняет постоянный корневой сертификат (`.driftless-certs/ca-root.crt`) и показывает его SHA-256 отпечаток + кнопку скачивания `/ca.crt`, чтобы его можно было один раз установить на телефон.
2. **Короткий TTL (1 час), отдельные разрешения по портам и мгновенный отзыв IP:** Переход по `https://` ссылке открывает доступ для твоего мобильного IP по умолчанию на 1 час (`-knock-ttl 1h`) и только к указанным портам (без прокси в домашнюю локалку `192.168.x.x` и роутер). Можно разблокировать только один конкретный порт через `?port=22` (`/__driftless_knock/СЕКРЕТ?port=22`), а после работы мгновенно закрыть доступ одной кнопкой (`/__driftless_knock/СЕКРЕТ/revoke` или `/revoke?all=1`).
3. **Вход в WebSSH и RDP даже через один чужой порт:** Если ты в сети, где открыт только один порт (например `8096`), ты можешь в самом приложении **WebSSH** указать порт `8096` вместо `22` - `driftless` по первым байтам поймет, что это SSH, и сам перекинет соединение на `22` порт твоего ПК (если порт `22` разблокирован для твоего IP).

---

### Примеры команд под частые задачи

| Задача | Команда |
| :--- | :--- |
| **Игровой сервер (Minecraft, CS2, Rust, Valheim, Palworld)** - TCP и UDP | `./driftless server -ports 25565,27015` |
| **Медиасервер (Jellyfin / Plex / Home Assistant)** | `./driftless server -ports 8096,8123` |
| **Рабочий стол Windows + SSH с телефона по секретной ссылке** | `./driftless standalone -ports 8096,3389,22 -duck mypc:ТОКЕН -knock` |
| **Свой сайт / API** (порт 80 на ВПС -> порт 3000 дома) | `./driftless server -ports 80:3000` |
| **Нейронка (Ollama / OpenWebUI)** с HTTPS | `./driftless server -ports 443:11434/https,3000` |
| **Несколько сайтов и путей на разных доменах** (авто-HTTPS Let's Encrypt) | `./driftless server -vhosts site.ru:3000,site.ru/api:4000,media.site.ru:8096 -vhost-addr :80 -https :443` |
| **В связке с Caddy / Nginx** (открыть порты только внутри ВПС на `127.0.0.1`) | `./driftless server -ports 127.0.0.1:8080:3000` |

---

### Что еще встроено из коробки

- **Автовыбор транспорта QUIC / TCP-Mux (`-transport auto`):** По умолчанию работает по QUIC (`UDP :4242`), а если провайдер или корпоративный файрвол блокирует UDP, сам переключается на мультиплексирование потоков поверх одного TLS/TCP-соединения (`TCP :4242`).
- **Резервирование ВПС (Multi-Gateway):** В `-quic` можно указать несколько серверов через запятую (`-quic vps1:4242,vps2:4242`) для авто-переключения при падении узла.
- **TCP и UDP открываются сразу:** Игры и голосовой чат работают без ручного дописывания `/udp`.
- **Стелс-доступ с телефона и мультиплексор одного порта (`-knock`):** Держит все порты закрытыми от ботов до перехода по секретной HTTPS-закладке с телефона (TTL 1 час по умолчанию, разблокировка отдельных портов `?port=22` и мгновенный отзыв `/revoke`), генерирует готовый `.rdp`-профиль и умеет принимать HTTP, HTTPS, SSH и RDP на одном открытом порту.
- **Умный мост занятых портов (`standalone`):** Если на домашнем ПК порт (например `3389`, `8096` или `25565`) уже занят самой локальной программой на `0.0.0.0`, режим `standalone` не падает с ошибкой `address already in use`, а сам поднимает локальный мост и пробрасывает внешний порт роутера (UPnP / NAT-PMP / PCP v2) через защиту `-knock`, `-tls` и `-allow-ips`.
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
| `-knock` | `false` | Включить HTTPS стелс-защиту портов по секретной ссылке (разблокировка отдельных портов `?port=22`, кнопка отзыва `/revoke`, `.rdp` и `ssh://`). |
| `-knock-token` | создается сам | Свой секретный ключ для ссылки `-knock` (если не указать, создается и сохраняется сам). |
| `-knock-ttl` | `1h` | На сколько времени открывать доступ для IP телефона после перехода по секретной ссылке (по умолчанию `1h`). |
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
| `-upnp` | `true` | Авто-открытие портов на домашнем роутере через UPnP / NAT-PMP / PCP v2 (`standalone`). |
| `-stun` | `"stun.cloudflare.com:3478"` | Свой STUN-сервер или список через запятую для проверки внешнего IP (`standalone`). |
| `-stun-interval` | `1s` | Частота проверки внешнего IP по STUN (`standalone`). |
| `-ddns-provider` | `""` | Другие DDNS-сервисы: `"cloudflare"` или `"noip"`. |
| `-max-buf` / `-max-mem` | `16 МБ` / `256 МБ` | Лимиты оперативной памяти на одно соединение и на всю программу. |
| `-session-ttl` | `90s` | Сколько секунд удерживать соединение при переподключении интернета дома. |

---

### Сравнение с аналогами

| Что умеет | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare Tunnel | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| Стримы и загрузки не рвутся при смене IP | Да (буфер 16 МБ в памяти) | Нет (обрыв) | Нет (обрыв) | Да |
| Автовыбор QUIC и fallback на TCP-Mux | Да (`-transport auto`) | Отдельные конфиги | Да | Только UDP |
| Может работать вообще без ВПС (`standalone`) | Да (UPnP + STUN + DDNS) | Нет | Нет | Нет |
| Стелс-доступ с телефона и все протоколы на 1 порту | Да (`-knock`) | Нет | Нет | Нужен VPN-клиент на телефоне |
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
