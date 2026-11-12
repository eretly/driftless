# Driftless (v1.5.4)

**Static-IP Convenience for Dynamic IP Connections | Multi-Node Reverse Tunnel & Standalone Port Publisher**

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![Transport](https://img.shields.io/badge/Transport-QUIC_%2B_TLS_1.3_%2F_TCP--Mux-10b981?style=flat-square)](#architecture)
[![NAT Traversal](https://img.shields.io/badge/Router-UPnP_%2B_NAT--PMP_%2B_PCP_v2-3b82f6?style=flat-square)](#router-port-forwarding-upnp--nat-pmp--pcp)
[![License](https://img.shields.io/badge/License-MIT-a855f7?style=flat-square)](LICENSE)

[English Documentation](#1-what-driftless-is) | [Русская документация](#русская-документация-ru)

---

## 1. What Driftless Is

Most residential ISPs assign a **dynamic public IP address** that changes whenever your PPPoE session resets, your router reboots, or your DHCP lease expires. Some ISPs also place subscribers behind **CGNAT** (`100.64.0.0/10`), where inbound connections from the internet cannot reach your router at all.

**Driftless** gives you the convenience of a static IP on top of a dynamic home connection:
- **Network-layer transport & port publishing:** Driftless publishes your existing local TCP and UDP services (HTTP/HTTPS web apps, Jellyfin/Plex media servers, SSH, RDP, WireGuard, Minecraft/Valheim/CS2 game servers, APIs) under permanent domain names and public ports.
- **No interference with application auth:** Driftless does not inject custom login screens, custom SSH accounts, or proprietary HTTP Basic Auth layers. Your services use their own native authentication (OpenSSH keys/passwords, Windows RDP credentials, Jellyfin/Nextcloud accounts, TLS certificates).
- **Two operating modes in a single zero-config binary:**
  1. **Standalone Mode (`driftless standalone`):** Runs directly on your Home PC or home server without a VPS. Automatically opens ports on your router via **UPnP IGDv1/v2**, **NAT-PMP (RFC 6886)**, and **PCP v2 (RFC 6887)**, monitors your public IP every `1s` via **RFC 5389 UDP STUN**, updates **DuckDNS / No-IP / Cloudflare / Webhook DDNS** within milliseconds of an IP change, and verifies external reachability.
  2. **Gateway + Multi-Agent Mode (`driftless server` + `driftless client`):** Runs a Gateway on a public VPS and connects **one or multiple Home PCs simultaneously** (`pc1`, `pc2`, `pc3`) through encrypted **QUIC (TLS 1.3)** or **TCP-Mux** reverse tunnels. Works even behind strict **ISP CGNAT** and preserves active TCP streams and UDP sessions across home WAN IP changes without dropping connections.

---

## 2. How Dynamic IP + DDNS Works

1. **Millisecond External IP Detection (RFC 5389 UDP STUN):**
   Every `1s` (configurable via `-stun-interval`), Driftless sends a lightweight 20-byte UDP STUN Binding Request (`XOR-MAPPED-ADDRESS`, cookie `0x2112A442`) to redundant STUN servers (`stun.cloudflare.com:3478`, `stun.l.google.com:19302`, `stun1.l.google.com:19302`).
2. **Instant DDNS Synchronization:**
   The moment your ISP assigns a new public IPv4 address:
   - In **Standalone Mode**, Driftless immediately pushes the new IP to **DuckDNS**, **No-IP**, **Cloudflare DNS API v4**, or your custom `-ddns-url` webhook and refreshes router port mappings.
   - In **Gateway + Agent Mode**, the Agent immediately dials a new encrypted tunnel epoch to your VPS Gateway and replays in-flight ring buffers so active TCP downloads, SSH sessions, and UDP game packets continue uninterrupted.

---

## 3. Standalone Mode (No VPS Required)

Use **Standalone Mode** when your ISP gives your router a real (even if dynamic) public IPv4 address.

### First Run with DuckDNS (Saves Domain & Token Automatically)
1. Sign in at [duckdns.org](https://www.duckdns.org), create a subdomain (for example `mypc`), and copy your token.
2. Run Driftless on your PC:

**Windows (PowerShell):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565/both,22 -duck mypc:YOUR_DUCKDNS_TOKEN
```

**Linux / macOS:**
```bash
./driftless standalone -ports 8096,25565/both,22 -duck mypc:YOUR_DUCKDNS_TOKEN
```

### Subsequent Runs (Just `-duck`)
Driftless saves your DuckDNS credentials in `.driftless-ddns.json` (`0600` permissions). On every future run or reboot, simply pass `-duck`:

```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565/both,22 -duck
```

### Other DDNS Providers (No-IP, Cloudflare, Custom Webhook)
```bash
# Cloudflare DNS API v4 (ZoneID:APIToken)
./driftless standalone -ports 443,8096 -ddns-provider cloudflare -ddns-domain home.example.com -ddns-token ZONE_ID:CF_API_TOKEN -tls -acme-email you@example.com

# No-IP (username:password)
./driftless standalone -ports 8096,25565/both -ddns-provider noip -ddns-domain mypc.ddns.net -ddns-token USER:PASS

# Custom Webhook ({ip} and {domain} placeholders)
./driftless standalone -ports 8096 -ddns-domain home.example.com -ddns-url "https://dns.example.com/update?host={domain}&ip={ip}"
```

---

## 4. Gateway + Multi-Agent Mode (Multiple Home PCs Through One VPS)

When your ISP uses **CGNAT** (`100.64.0.0/10`), blocks inbound ports, or when you want to expose services from **multiple home computers (`pc1`, `pc2`, `pc3`) through a single VPS IP**, run `driftless server` on your VPS and `driftless client` on each home machine.

```text
                        +---------------------------------------+
                        |       Public VPS (driftless server)   |
                        |  -http :80  -tls :443  -addr :4443    |
                        +-------------------+-------------------+
                                            |
              +-----------------------------+-----------------------------+
              | QUIC / TCP-Mux              | QUIC / TCP-Mux              | QUIC / TCP-Mux
              | (-id pc1)                   | (-id pc2)                   | (-id pc3)
              v                             v                             v
   +--------------------+        +--------------------+        +--------------------+
   |   Home PC 1 (pc1)  |        |   Home PC 2 (pc2)  |        |   Home PC 3 (pc3)  |
   | media.example.com  |        |  site.example.com  |        |  game.example.com  |
   |  127.0.0.1:8096    |        |   127.0.0.1:3000   |        |  127.0.0.1:8080    |
   |  TCP :2221 -> :22  |        |   TCP :2222 -> :22 |        | UDP :25565->:25565 |
   +--------------------+        +--------------------+        +--------------------+
```

### Step 1: Start the Gateway on Your VPS
Point your DNS `A` records (`media.example.com`, `site.example.com`, `game.example.com`) to your VPS public IP.

```bash
./driftless server \
  -addr 0.0.0.0:4443 \
  -http 0.0.0.0:80 \
  -tls 0.0.0.0:443 \
  -acme-email admin@example.com
```
On first startup, the Gateway prints its persistent **Token** and **TLS SHA-256 Fingerprint** (stored in `.driftless-certs/token.secret`).

### Step 2: Connect Multiple Home Computers (`pc1`, `pc2`, `pc3`)
Each computer connects with its own `-id` (`-node`) and publishes its own domains (`-vhosts`) and TCP/UDP ports (`-ports`):

**Computer 1 (`pc1` - Media Server & SSH):**
```bash
./driftless client \
  -id pc1 \
  -gateway vps.example.com:4443 \
  -token YOUR_GATEWAY_TOKEN \
  -vhosts media.example.com:8096 \
  -ports 2221:22/tcp
```

**Computer 2 (`pc2` - Web Application & SSH):**
```bash
./driftless client \
  -id pc2 \
  -gateway vps.example.com:4443 \
  -token YOUR_GATEWAY_TOKEN \
  -vhosts site.example.com:3000 \
  -ports 2222:22/tcp
```

**Computer 3 (`pc3` - Game Server Status Page & UDP/TCP Game Port):**
```bash
./driftless client \
  -id pc3 \
  -gateway vps.example.com:4443 \
  -token YOUR_GATEWAY_TOKEN \
  -vhosts game.example.com:8080 \
  -ports 25565:25565/both
```

*(Optional)* You can also define static multi-node routing rules directly on the VPS Gateway:
```bash
./driftless server \
  -addr 0.0.0.0:4443 \
  -http 0.0.0.0:80 \
  -tls 0.0.0.0:443 \
  -vhosts media.example.com:pc1:8096,site.example.com:pc2:3000,game.example.com:pc3:8080 \
  -ports 2221:pc1:22/tcp,2222:pc2:22/tcp,25565:pc3:25565/both
```

**Multi-Agent Isolation Guarantee:**
- If `pc1` reboots or its ISP rotates its IP, `pc2` and `pc3` continue serving traffic with zero interruption.
- When `pc1` reconnects, its sessions and routes on `media.example.com` and port `2221` automatically resume.

---

## 5. Publishing TCP and UDP Services (`-ports`)

The `-ports` flag accepts comma-separated rules in any of these formats:
- `8096` -> Public TCP port `8096` to local TCP port `8096`
- `25565/both` -> Both TCP and UDP port `25565` to local port `25565`
- `51820/udp` -> Public UDP port `51820` to local UDP port `51820`
- `2222:22/tcp` -> Public TCP port `2222` to local TCP port `22`
- `127.0.0.1:8443:443/tcp` -> Bind only on `127.0.0.1:8443` and forward to local port `443`
- `25565:pc3:25565/both` -> (On Gateway) Route public TCP+UDP port `25565` to Agent node `pc3` port `25565`

---

## 6. Router Port Forwarding (UPnP / NAT-PMP / PCP) & Limitations

In Standalone Mode, Driftless automatically maps external ports on your router using three standard protocols:
1. **UPnP IGDv1 / IGDv2 (`WANIPConnection` & `WANPPPConnection`):** Parallel SSDP multicast discovery (`239.255.255.250:1900`), automatic fallback to gateway XML descriptions, and automatic fallback from `LeaseDuration=3600` to permanent leases (`0`) on consumer routers that return UPnP error `725 OnlyPermanentLeasesSupported`.
2. **PCP v2 (RFC 6887):** Port Control Protocol with 96-bit cryptographic nonce verification.
3. **NAT-PMP (RFC 6886):** Apple/IETF NAT Port Mapping Protocol on UDP port `5351`.

### Crash-Safe Cleanup & Self-Healing
- Active router mappings are atomically persisted in `.driftless-upnp-state.json` (`0600` permissions) with cross-process lock protection.
- Every `60s`, Driftless renews router mappings so router reboots never leave your ports closed.
- Running `./driftless stop` or pressing `Ctrl+C` deletes all UPnP / NAT-PMP / PCP mappings from your router.

### When Standalone Mode Cannot Work Without a VPS
Standalone Mode requires your home router to receive inbound packets from the internet. It **cannot** accept incoming connections without a VPS if:
1. **Your ISP uses CGNAT (`100.64.0.0/10`) or Double NAT:** Your router's WAN interface has a private/carrier-grade NAT address rather than a public IPv4 address.
2. **UPnP / NAT-PMP / PCP is disabled on your router** and you have not manually forwarded the ports in your router's admin UI.
3. **Your ISP firewall blocks inbound ports** (many residential ISPs block ports `80`, `443`, `22`, or `445`).
4. **Local OS firewall (Windows Defender Firewall / `ufw` / `nftables`)** blocks incoming connections to the `driftless` binary.

---

## 7. External Reachability Check & Diagnostics (`./driftless check`)

Driftless automatically checks your public IP, CGNAT status, and TCP port reachability on Standalone startup. You can also run a standalone diagnostic at any time:

```bash
./driftless check -ports 8096,25565/both,22 -duck
```

Example output:
```text
========================================================================
  DRIFTLESS NETWORK & REACHABILITY CHECK (v1.5.4)
========================================================================
  LAN IP Address        : 192.168.1.50
  Public IP (STUN)      : 198.51.100.42
  CGNAT Status          : OK (Public IPv4 detected)
  UPnP / NAT-PMP / PCP  : 4 router rule(s) mapped
  PORT 8096 (TCP)       : REACHABLE (198.51.100.42:8096)
  PORT 25565 (TCP)      : REACHABLE (198.51.100.42:25565)
  PORT 22 (TCP)         : UNREACHABLE (Check router port-forward / ISP CGNAT / local service)
========================================================================
```

---

## 8. CLI Reference: Start, Stop & Flags

### Subcommands
| Command | Description |
| :--- | :--- |
| `driftless standalone [flags]` | Run on Home PC without a VPS (STUN + DDNS + UPnP/NAT-PMP/PCP + TCP/UDP/TLS proxy) |
| `driftless server [flags]` | Run Gateway on a public VPS (accepts one or multiple Home PC Agents) |
| `driftless client [flags]` | Run Agent on a Home PC (connects to VPS Gateway with `-id` node name) |
| `driftless check [flags]` | Diagnose public IP via STUN, detect CGNAT, test UPnP/NAT-PMP/PCP, and verify port reachability |
| `driftless stop` | Gracefully stop running background/foreground instances and clean up router UPnP rules |

### Flags
| Flag | Default | Mode | Description |
| :--- | :--- | :--- | :--- |
| `-id`, `-node` | `default` | `client` | Unique computer/node ID when connecting multiple PCs to one VPS (`pc1`, `pc2`, `pc3`) |
| `-ports` | `8080:8080/tcp` | All | Comma-separated TCP/UDP mappings (`8096,25565/both,51820/udp,2222:22/tcp,25565:pc1:25565`) |
| `-vhosts` | *(none)* | All | HTTP/HTTPS virtual hosts (`media.example.com:8096` or `media.example.com:pc1:8096`) |
| `-duck` | *(none)* | `standalone`, `check` | DuckDNS shortcut: `-duck mypc:TOKEN` on first run, or bare `-duck` thereafter |
| `-ddns-provider` | *(auto)* | `standalone` | DDNS provider (`duckdns`, `cloudflare`, `noip`, `webhook`) |
| `-ddns-domain` | *(none)* | `standalone` | DDNS domain name (`mypc.duckdns.org`, `home.example.com`) |
| `-ddns-token` | *(none)* | `standalone` | DDNS token (`TOKEN` for DuckDNS, `ZoneID:APIToken` for Cloudflare, `user:pass` for No-IP) |
| `-ddns-url` | *(none)* | `standalone` | Custom DDNS webhook URL with `{ip}` and `{domain}` placeholders |
| `-upnp` | `true` | `standalone`, `check` | Automatically forward ports on home router via UPnP / NAT-PMP / PCP |
| `-gateway` | `127.0.0.1:4443` | `client` | Gateway address(es), comma-separated for High-Availability failover |
| `-addr` | `0.0.0.0:4443` | `server` | Tunnel listen address for incoming Agents |
| `-token` | *(auto)* | `server`, `client` | Shared secret token for Agent <-> Gateway HMAC-SHA256 channel-bound authentication |
| `-fingerprint` | *(TOFU)* | `client` | Optional Gateway TLS certificate SHA-256 fingerprint pin |
| `-transport` | `auto` | `server`, `client` | Tunnel transport: `auto` (QUIC with TCP fallback), `quic`, or `tcp` |
| `-http` | *(none)* | `server`, `standalone` | Public HTTP Virtual Host router bind address (e.g. `0.0.0.0:80`) |
| `-tls` | *(none)* | `server`, `standalone` | Enable HTTPS/TLS termination (`-tls` in standalone, or `-tls 0.0.0.0:443` on server) |
| `-acme-email` | *(none)* | `server`, `standalone` | Let's Encrypt ACME email for automatic trusted TLS certificates |
| `-acme-dns-cmd` | *(none)* | `server`, `standalone` | External command for ACME DNS-01 challenges when port 80/443 is blocked |
| `-stun` | `stun.cloudflare.com:3478` | `client`, `standalone` | STUN server(s) for RFC 5389 external IP monitoring |
| `-stun-interval` | `1s` | `client`, `standalone` | Interval for checking external IP changes via UDP STUN |
| `-allow-ports` | *(all)* | `client`, `standalone` | Optional whitelist of local ports allowed to be forwarded |
| `-proxy-proto` | `false` | `server`, `client` | Prepend HAProxy PROXY protocol v1 headers to preserve real visitor IP |
| `-health` | *(none)* | All | Local JSON telemetry & `/healthz` endpoint (e.g. `127.0.0.1:9090`) |
| `-d` | `false` | All | Run detached in the background (stop anytime with `./driftless stop`) |

---

# Русская документация (RU)

## 1. Что такое Driftless и какую задачу он решает

У большинства домашних провайдеров публичный IP-адрес является **динамическим** и меняется при переподключении PPPoE, перезагрузке роутера или обновлении аренды DHCP. Кроме того, многие провайдеры выдают «серый» IP за **CGNAT** (`100.64.0.0/10`), куда входящие подключения из интернета напрямую не доходят.

**Driftless** даёт пользователю с динамическим IP удобство статического IP:
- **Публикация существующих локальных TCP и UDP сервисов** (сайты, Jellyfin/Plex, SSH, RDP, WireGuard, игровые серверы Minecraft/Valheim/CS2, API) под постоянными доменными именами и портами.
- **Никакого вмешательства в прикладную авторизацию:** Driftless работает строго на сетевом/транспортном уровне. Он не добавляет собственные логины/пароли, встроенные SSH-серверы или веб-порталы. Ваши сервисы используют свою штатную аутентификацию (ключи и учётные записи OpenSSH, учётную запись Windows для RDP, логин/пароль вашего сайта или медиасервера).
- **Два режима работы в одном бинарном файле:**
  1. **Standalone без VPS (`driftless standalone`):** Запускается прямо на домашнем ПК или сервере. Автоматически открывает порты на роутере по **UPnP IGDv1/v2**, **NAT-PMP (RFC 6886)** и **PCP v2 (RFC 6887)**, каждую секунду отслеживает внешний IP через **UDP STUN (RFC 5389)**, мгновенно обновляет **DuckDNS / No-IP / Cloudflare** при смене IP и проверяет внешнюю доступность портов.
  2. **Gateway + Multi-Agent через один VPS (`driftless server` + `driftless client`):** На публичном VPS запускается единый шлюз (`Gateway`), к которому одновременно подключаются **несколько домашних компьютеров (`pc1`, `pc2`, `pc3`)**. Работает даже за жёстким **CGNAT** и сохраняет активные TCP-соединения и UDP-сессии при смене домашнего IP без обрыва связи.

---

## 2. Режим Standalone (без VPS)

Подходит, если ваш провайдер выдаёт роутеру «белый» (пусть и динамический) публичный IPv4-адрес.

### Первый запуск с DuckDNS (сохраняет домен и токен)
1. Зайдите на [duckdns.org](https://www.duckdns.org), создайте поддомен (например, `mypc`) и скопируйте токен.
2. Запустите Driftless на своём ПК:

**Windows (PowerShell):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565/both,22 -duck mypc:ТВОЙ_ТОКЕН_DUCKDNS
```

**Linux / macOS:**
```bash
./driftless standalone -ports 8096,25565/both,22 -duck mypc:ТВОЙ_ТОКЕН_DUCKDNS
```

### Повторные запуски (достаточно просто `-duck`)
После первого запуска домен и токен надёжно сохраняются в `.driftless-ddns.json`. В следующий раз достаточно указать просто `-duck`:

```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,25565/both,22 -duck
```

---

## 3. Несколько домашних компьютеров через один VPS (Multi-Agent Gateway)

Если у вас **CGNAT** (`100.64.0.0/10`) или вы хотите опубликовать сервисы сразу с **нескольких домашних компьютеров (`pc1`, `pc2`, `pc3`) через один VPS**, запустите `driftless server` на VPS, а на каждом компьютере запустите `driftless client` со своим `-id`:

### Шаг 1: Запуск Gateway на VPS
Направьте DNS `A`-записи ваших доменов (`media.example.com`, `site.example.com`, `game.example.com`) на IP-адрес VPS и запустите сервер:

```bash
./driftless server \
  -addr 0.0.0.0:4443 \
  -http 0.0.0.0:80 \
  -tls 0.0.0.0:443 \
  -acme-email admin@example.com
```
При первом запуске Gateway создаст и выведет в консоль секретный **Token** (сохраняется в `.driftless-certs/token.secret`).

### Шаг 2: Подключение компьютеров `pc1`, `pc2`, `pc3`

**Компьютер 1 (`pc1` - медиасервер `media.example.com` и SSH на порту `2221`):**
```bash
./driftless client \
  -id pc1 \
  -gateway vps.example.com:4443 \
  -token ВАШ_ТОКЕН_GATEWAY \
  -vhosts media.example.com:8096 \
  -ports 2221:22/tcp
```

**Компьютер 2 (`pc2` - веб-сайт `site.example.com` и SSH на порту `2222`):**
```bash
./driftless client \
  -id pc2 \
  -gateway vps.example.com:4443 \
  -token ВАШ_ТОКЕН_GATEWAY \
  -vhosts site.example.com:3000 \
  -ports 2222:22/tcp
```

**Компьютер 3 (`pc3` - статус-страница `game.example.com` и UDP/TCP игровой сервер `25565`):**
```bash
./driftless client \
  -id pc3 \
  -gateway vps.example.com:4443 \
  -token ВАШ_ТОКЕН_GATEWAY \
  -vhosts game.example.com:8080 \
  -ports 25565:25565/both
```

**Полная изоляция агентов:**
- Отключение или смена IP у `pc1` никак не влияет на работу `pc2` и `pc3`.
- При переподключении `pc1` все его маршруты и активные TCP/UDP-сессии автоматически восстанавливаются.

---

## 4. Диагностика внешней доступности и CGNAT (`./driftless check`)

Чтобы в любой момент проверить свой внешний IP, наличие CGNAT, работу UPnP/NAT-PMP/PCP на роутере и реальную доступность портов снаружи, выполните:

```bash
./driftless check -ports 8096,25565/both,22 -duck
```

### Когда режим Standalone НЕ сработает без VPS
1. **Провайдер использует CGNAT (`100.64.0.0/10`) или двойной NAT:** роутер получает не публичный IP, а внутренний адрес провайдера. В этом случае входящие подключения возможны только через VPS (`driftless server` + `driftless client`).
2. **На роутере отключён UPnP / NAT-PMP / PCP**, и порты не проброшены вручную в настройках роутера.
3. **Провайдер блокирует входящие порты** (например, `80`, `443`, `22`).
4. **Брандмауэр ОС (Windows Firewall / `ufw`)** блокирует входящие подключения к локальному сервису или `driftless`.

---

## 5. Управление и сборка

```bash
# Фоновый запуск (в режиме демона)
./driftless standalone -ports 8096,25565/both -duck -d

# Остановка фонового процесса и очистка правил UPnP на роутере
./driftless stop

# Запуск всех тестов с детектором гонок (Go Race Detector)
go test -race -v ./...
```
