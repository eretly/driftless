# Driftless (v1.5.6)

> 🌐 **Choose Language / Выберите язык:** [🇺🇸 English (Full Documentation)](#english-documentation) · [🇷🇺 Русский (Полная инструкция)](#ru)

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![Transport](https://img.shields.io/badge/Transport-QUIC_%2B_TLS_1.3_%2B_TCP--Mux-10b981?style=flat-square)](#english-documentation)
[![NAT Traversal](https://img.shields.io/badge/Router-UPnP_%2B_NAT--PMP_%2B_PCP_v2-3b82f6?style=flat-square)](#english-documentation)
[![License](https://img.shields.io/badge/License-MIT-a855f7?style=flat-square)](LICENSE)

---

<a id="english-documentation"></a>

## 🇺🇸 English Documentation

### What Driftless Does
When your ISP gives you a **dynamic public IPv4 address** (or places you behind **CGNAT**), **Driftless** keeps your home TCP and UDP services reachable:
- Opens **both TCP and UDP** ports automatically (`-udp=true` by default).
- Works **without a VPS** (`driftless standalone`, when your router has a public IPv4 address) or **through your own VPS** (`driftless server` + `driftless client`, which also works behind CGNAT).
- Supports **multiple Home PCs (`-id pc1`, `-id pc2`, `-id pc3`)** on a single VPS with strict public port and VHost conflict protection, plus **automatic failover to a 2nd backup VPS (`-vps2`)**.
- Never interferes with your services' own login/password (SSH, Windows RDP, Jellyfin, websites, game servers use their native authentication).

---

### 1. Run Without a VPS (`standalone` + `-duck`)

If your router receives a public IPv4 address from your ISP (even if it is dynamic), you have two ways to run with `-duck`:

#### Option 1A: Zero-Config Instant Start (`-duck` without a token)
**Windows (PowerShell):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,3389,22 -duck
```
**Linux / macOS:**
```bash
./driftless standalone -ports 8096,3389,22 -duck
```
- If you previously saved a DuckDNS token, Driftless automatically reloads it from `.driftless-ddns.json`.
- If no token is configured yet, Driftless binds a **temporary IP-based hostname** (`<ip>.sslip.io`, e.g. `198-51-100-42.sslip.io`) for immediate HTTPS/TLS access. *(Note: `sslip.io` embeds your current IP and changes if your ISP rotates your IP).*

#### Option 1B: Permanent Free Domain via DuckDNS (`-duck SUBDOMAIN:TOKEN`)
To get a **permanent** `*.duckdns.org` address that never changes when your ISP rotates your IP:
1. Sign in at **[https://www.duckdns.org](https://www.duckdns.org)**, create a subdomain (for example `myhome`), and copy your **token** from the top of the page.
2. Run Driftless **once** with `-duck myhome:YOUR_TOKEN`:
   **Windows (PowerShell):**
   ```powershell
   .\driftless-windows-amd64.exe standalone -ports 8096,3389,22 -duck myhome:a1b2c3d4-e5f6-7890-abcd-ef1234567890
   ```
   **Linux / macOS:**
   ```bash
   ./driftless standalone -ports 8096,3389,22 -duck myhome:a1b2c3d4-e5f6-7890-abcd-ef1234567890
   ```
3. Driftless saves `myhome.duckdns.org` and your token to `.driftless-ddns.json` (mode `0600`) and updates your IP automatically. On all future starts, you only need `-duck` (or just `./driftless standalone -ports 8096,3389,22`) without typing the token again.

**What happens automatically:**
1. **UPnP / NAT-PMP / PCP** opens TCP and UDP ports `8096`, `3389`, and `22` on your home router and re-applies them automatically if the router reboots.
2. **UDP STUN (`1s`)** detects your external IPv4 address and tracks any ISP IP rotation in real time.
3. **Domain & Auto-TLS:** updates your DuckDNS `A` record (`myhome.duckdns.org`) or binds `<ip>.sslip.io` and provisions TLS certificates automatically.

**What you see in the console:**
```text
[standalone] ==========================================================
[standalone] Published Endpoints (Domain [ddns (duckdns)]: myhome.duckdns.org | Public IP: 198.51.100.42):
[standalone]   Port :8096  -> :8096  : https://myhome.duckdns.org:8096  (TCP/UDP: myhome.duckdns.org:8096)
[standalone]   Remote Desktop (RDP)  : myhome.duckdns.org:3389 (uses your Windows account credentials)
[standalone]   SSH Service           : myhome.duckdns.org:22 (uses your system SSH server & OS credentials)
[standalone] ==========================================================
```

**How to connect from anywhere (phone / laptop):**
- **Browser / Jellyfin / Web App:** open `https://myhome.duckdns.org:8096` (or `https://198-51-100-42.sslip.io:8096`).
- **SSH (Termius / WebSSH / terminal):** Host `myhome.duckdns.org`, Port `22`, your OS username & password/key.
- **Windows Remote Desktop (RDP):** Computer `myhome.duckdns.org:3389`, your Windows username & password.

---

### 2. Permanent Domains: Custom Domains (`-domain`, `-vhosts`) & Dynamic DNS

Driftless separates three types of domains:
1. **Temporary IP-based hostname (`sslip.io`):** generated when `-duck` is used without a DDNS provider; changes when your ISP IP changes.
2. **Dynamic DNS domain (`duckdns`, `cloudflare`, `noip`, `dynu`, `-ddns-url`):** a permanent hostname automatically updated via DNS API whenever your ISP rotates your IP, persisted in `.driftless-ddns.json` across restarts.
3. **Custom domain (`-domain`, `-vhosts`):** your own domain pointed to your VPS or home IP.

#### Option A: One-Flag Custom Domain (`-domain`)
Point your domain's `A` record to your PC (or VPS) IP and pass `-domain`:
```bash
# Bind mysite.com with automatic HTTPS/TLS on your mapped ports
./driftless standalone -ports 8096,25565 -domain mysite.com

# Or route a domain directly to a local port on :80 / :443
./driftless standalone -domain media.mysite.com:8096 -https :443
```

#### Option B: Multiple Domains on Port 80 & 443 (`-vhosts`)
```bash
./driftless standalone -vhosts site.mysite.com:3000,media.mysite.com:8096 -vhost-addr :80 -https :443
```

#### Option C: Permanent Dynamic DNS (DuckDNS / Cloudflare / No-IP / Dynu)
Settings are saved to `.driftless-ddns.json` (mode `0600`) and automatically restored on future restarts:
```bash
# DuckDNS shorthand (get your subdomain & token at https://www.duckdns.org)
./driftless standalone -ports 8096 -duck myhome:YOUR_DUCKDNS_TOKEN

# Or DuckDNS via explicit flags
./driftless standalone -ports 8096 -ddns-provider duckdns -ddns-domain myhome.duckdns.org -ddns-token YOUR_DUCKDNS_TOKEN

# Cloudflare DNS API v4 (TTL=60s)
./driftless standalone -ports 8096 -ddns-provider cloudflare -ddns-zone YOUR_ZONE_ID -ddns-domain home.mysite.com -ddns-token YOUR_CF_TOKEN

# No-IP or Dynu
./driftless standalone -ports 8096 -ddns-provider noip -ddns-domain mypc.ddns.net -ddns-user USER -ddns-token PASS
./driftless standalone -ports 8096 -ddns-provider dynu -ddns-domain mypc.dynu.net -ddns-user USER -ddns-token PASS
```

---

### 3. Run With a VPS + Second Backup VPS + Multiple Home PCs

Use this mode if your ISP uses **CGNAT (`100.64.0.0/10`)** or if you want a permanent static VPS entry point.

#### Basic Setup (1 VPS + 1 Home PC)
1. **On your VPS:**
   ```bash
   ./driftless server -ports 8080:80,8096,25565
   ```
   The VPS prints a ready-to-copy `./driftless client ...` command with an auto-generated token and TLS fingerprint.
2. **On your Home PC:**
   ```bash
   ./driftless client -quic YOUR_VPS_IP:4242 -token YOUR_TOKEN
   ```

#### Adding a Second Backup VPS (`-vps2` Automatic Failover)
If you have a second VPS, run `driftless server` on both VPS servers with the same `-token`, and add `-vps2` on your Home PC:
```bash
./driftless client -quic VPS_1_IP:4242 -vps2 VPS_2_IP:4242 -token YOUR_SHARED_TOKEN
```
*(Or list both via comma: `-quic VPS_1_IP:4242,VPS_2_IP:4242`). If VPS #1 goes offline, the Home PC automatically switches to VPS #2.*

#### Connecting Multiple Home PCs (`pc1`, `pc2`, `pc3`) to One VPS
1. **On your VPS:**
   ```bash
   ./driftless server -quic 0.0.0.0:4242 -vhost-addr :80 -https :443
   ```
2. **On Home PC 1 (`pc1` - Media Server + SSH):**
   ```bash
   ./driftless client -id pc1 -quic YOUR_VPS_IP:4242 -token YOUR_TOKEN -vhosts media.mysite.com:8096 -ports 2221:22
   ```
3. **On Home PC 2 (`pc2` - Website + SSH):**
   ```bash
   ./driftless client -id pc2 -quic YOUR_VPS_IP:4242 -token YOUR_TOKEN -vhosts site.mysite.com:3000 -ports 2222:22
   ```
4. **On Home PC 3 (`pc3` - Game Server TCP+UDP):**
   ```bash
   ./driftless client -id pc3 -quic YOUR_VPS_IP:4242 -token YOUR_TOKEN -vhosts game.mysite.com:8080 -ports 25565:25565
   ```
- Disconnecting or rebooting `pc1` never interrupts `pc2` or `pc3`.
- If another Agent attempts to register a public port or VHost already owned by an active Agent, the Gateway blocks the conflict, logs a warning on both Gateway and Agent, and preserves traffic isolation so existing traffic is never redirected to the wrong computer.

---

### 4. Honest Reachability Diagnostics (`./driftless check` & `-probe-url`)

Driftless separates reachability into three distinct checks:
1. **`local_service_status`:** whether the local TCP/UDP target service on your PC is responding.
2. **`port_forward_status`:** whether UPnP IGD / NAT-PMP / PCP port forwarding rules are active on your router.
3. **`external_status`:** whether the port is genuinely reachable from outside your home network.

**Why local hairpin checks are not enough:** Dialing your own public IP from inside the same LAN (NAT hairpinning) often succeeds on the local router even when the ISP blocks inbound connections from the internet. Therefore:
- Without `-probe-url`, Driftless **never** claims a port is reachable from the internet based on a local dial; it reports `unverified-from-internet` (`не удалось проверить извне`).
- Every Driftless Gateway (`driftless server`) exposes a protected external probe endpoint on its `-direct` HTTP port (`http://VPS_IP:8888/probe`):
  - **Security & SSRF Protection:** `/probe` requires a valid Gateway token (`-token` / `Authorization: Bearer` / `?token=...`) or an authenticated Agent session, blocks all private/link-local/CGNAT addresses, and only checks the caller's own public IP (or registered Agent IP) so it can never be abused to scan third-party hosts.
  - **UDP 3-State Classification:** distinguishes between a confirmed UDP reply (`verified-from-internet`), a closed UDP port (`unreachable-from-internet` on ICMP Port Unreachable / `connection refused`), and an ordinary silent UDP service that ignores generic probes (`unconfirmed-udp` / `open|silent`), since absence of a reply from a protocol-specific UDP service does not mean the port is closed.
```bash
# Local + router check (reports external_status as unverified-from-internet)
./driftless check -ports 8096,25565,22 -duck

# Full external internet verification via an authenticated Gateway probe endpoint
./driftless check -ports 8096,25565,22 -probe-url http://YOUR_VPS_IP:8888/probe -token YOUR_VPS_TOKEN
```

### 5. Known Limitations & Unsupported Scenarios
- **CGNAT / Double NAT (`100.64.0.0/10`):** Standalone mode cannot receive direct inbound connections from the internet when your ISP places your router behind CGNAT or Double NAT. Use `driftless server` on a VPS + `driftless client` on your Home PC.
- **IPv4 vs IPv6:** Automatic STUN public IP detection, UPnP IGD / NAT-PMP / PCP router port mapping, and `sslip.io` auto-hostnames operate over **IPv4**. In IPv6-only networks without IPv4, use VPS Gateway + Agent mode or explicit IPv6 bindings.
- **Disabled Router UPnP / ISP Port Blocking:** If UPnP/NAT-PMP/PCP is disabled in router firmware, forward the ports manually on the router or use VPS Gateway mode.

---

### 6. Complete CLI Flags Reference (All Flags)

#### Subcommands
| Subcommand | Description |
| :--- | :--- |
| `driftless standalone` | Run directly on Home PC without a VPS (STUN + Auto-UPnP + Domain/DDNS + TCP/UDP/TLS) |
| `driftless server` | Run Gateway on a VPS (accepts one or multiple Home PC Agents) |
| `driftless client` | Run Agent on a Home PC (connects to VPS Gateway, supports `-id` and `-vps2`) |
| `driftless check` | Run external IP, CGNAT, local service, router port-forward, and external probe diagnostics |
| `driftless show-token` | Print the saved Gateway token and ready-to-copy client connection command |
| `driftless version` | Print `driftless v1.5.6` version string |

#### All CLI Flags
| Flag | Default | Description |
| :--- | :--- | :--- |
| `-mode` | `"agent"` | Operating mode: `server` (`gateway`), `client` (`agent`), or `standalone` (`direct`, `p2p`) |
| `-ports` | `"8080:80,8096:8096"` | Port mappings: `PORT`, `PUBLIC:LOCAL`, `PUBLIC:NODE_ID:LOCAL`, or `127.0.0.1:PUBLIC:LOCAL` (supports `/tcp`, `/udp`, `/both`, `/http`, `/https`) |
| `-udp` | `true` | Forward both TCP and UDP by default on all mapped ports |
| `-duck` | `""` | `-duck SUBDOMAIN:TOKEN` (free permanent `*.duckdns.org` domain from duckdns.org) or bare `-duck` (reload saved DDNS / temporary `<ip>.sslip.io` hostname) |
| `-domain` | `""` | Bind your own custom domain with Auto-TLS (`-domain mysite.com` or `-domain media.mysite.com:8096`) |
| `-vhosts` | `""` | Virtual Host domain routing (`domain:PORT` or `domain:NODE_ID:PORT`, e.g. `media.mysite.com:pc1:8096`) |
| `-vhost-addr` | `""` (`:80` if vhosts) | HTTP/HTTPS VHost router listen address (e.g. `:80`) |
| `-https` | `""` | Dedicated HTTPS VHost router listen address (e.g. `:443` or `:8443`) |
| `-tls` | `false` | Enable automatic HTTPS/TLS termination on mapped TCP ports |
| `-tls-cert` | `""` | Path to custom TLS certificate PEM file (auto-discovers Let's Encrypt / SNI if omitted) |
| `-tls-key` | `""` | Path to custom TLS private key PEM file |
| `-quic` | `"0.0.0.0:4242"` | Gateway tunnel address on VPS, or comma-separated failover list on PC (`VPS1:4242,VPS2:4242`) |
| `-gateway` | `""` | Alias for `-quic` |
| `-vps2` | `""` | Second backup VPS Gateway address for automatic failover (e.g. `BACKUP_VPS_IP:4242`) |
| `-id` / `-node` | `""` (`default`) | Unique computer/node ID when connecting multiple Home PCs to one VPS (`pc1`, `pc2`, `pc3`) |
| `-transport` | `"auto"` | Tunnel transport protocol: `auto` (QUIC with automatic TCP-Mux fallback), `quic`, or `tcp` |
| `-token` | `""` (auto on VPS) | Shared secret tunnel password or comma-separated token rotation list (`new_tok,old_tok`) |
| `-token-file` | `""` | Path to file containing shared secret tunnel password |
| `-fingerprint` | `""` (auto-TOFU) | Gateway TLS certificate SHA-256 fingerprint for strict pinning |
| `-direct` | `":8888"` | Direct LAN/Wi-Fi HTTP redirector and `/probe` listen address (`""` to disable) |
| `-probe-url` | `""` | External probe URL (e.g. `http://VPS_IP:8888/probe`) for independent internet TCP/UDP reachability verification |
| `-same-lan` | `true` | Redirect clients sharing the same WAN IP directly to the Agent's LAN IP |
| `-host` | `"127.0.0.1"` | Local target host IP on Home PC (`agent` / `standalone`) |
| `-lan-ip` | `""` (auto) | Override auto-detected local LAN IP address |
| `-allow-ports` | `""` (all) | Security whitelist of allowed local target ports on Home PC (e.g. `"80,8096,25565"`) |
| `-upnp` | `true` | Automatically open TCP+UDP ports on home router via UPnP IGDv1/v2, NAT-PMP, and PCP v2 |
| `-stun` | `"stun.cloudflare.com:3478"` | RFC 5389 UDP STUN server (or comma-separated list) for external IPv4 change detection |
| `-stun-interval` | `1s` | How often to check external IP via UDP STUN in standalone mode |
| `-ddns-provider` | `""` | Built-in Dynamic DNS provider: `duckdns`, `cloudflare`, `noip`, or `dynu` |
| `-ddns-domain` | `""` | Domain name to update when external IP changes |
| `-ddns-token` | `""` | API token or password for Dynamic DNS provider |
| `-ddns-user` | `""` | Username for No-IP / DynDNS / Dynu provider |
| `-ddns-zone` | `""` | Cloudflare Zone ID (when `-ddns-provider=cloudflare`) |
| `-ddns-url` | `""` | Custom DDNS webhook URL (replaces `{ip}` and `{domain}` automatically) |
| `-max-buf` | `16777216` (16 MiB) | Max per-session sliding ring buffer in RAM for zero-drop reconnects |
| `-max-mem` | `268435456` (256 MiB) | Max global buffered bytes across all active sessions |
| `-session-ttl` | `90s` | How long to hold frozen TCP/UDP sessions in RAM during a WAN IP outage |
| `-quic-idle-timeout` | `8s` | QUIC / TCP-Mux idle timeout before triggering reconnect |
| `-quic-keepalive` | `2s` | QUIC / TCP-Mux heartbeat keepalive interval |
| `-cert-dir` | `""` (`.driftless-certs`) | Directory to persist generated TLS certificates, CA, and tokens |
| `-client-ca` | `""` | CA PEM file on VPS to enforce mutual TLS (mTLS) client certificates from Agents |
| `-client-cert` | `""` | Client mTLS certificate PEM file on Home PC Agent |
| `-client-key` | `""` | Client mTLS private key PEM file on Home PC Agent |
| `-proxy-protocol` | `false` | Prepend HAProxy PROXY protocol v1 header so local servers see real visitor IPs |
| `-metrics` | `""` | Observability HTTP listen address for `/metrics` (Prometheus) and `/status` (JSON) |

---

<a id="ru"></a>

## 🇷🇺 Русская документация (Полная инструкция)

### Зачем нужен Driftless
Когда провайдер выдаёт **динамический публичный IPv4** (который меняется при переподключении роутера) или прячет домашнюю сеть за **CGNAT**, **Driftless** сохраняет доступ к вашим домашним TCP и UDP сервисам:
- По умолчанию открывает **и TCP, и UDP** для каждого указанного порта (`-udp=true`).
- Работает **без ВПС** (`driftless standalone`, если у роутера публичный IPv4) или **через ваш ВПС** (`driftless server` + `driftless client`, в том числе за CGNAT).
- Позволяет подключить **несколько домашних ПК (`-id pc1`, `-id pc2`, `-id pc3`) к одному ВПС** с защитой от конфликтов портов и доменов, а также указать **второй резервный ВПС (`-vps2`)**.
- Не вмешивается в авторизацию ваших сервисов: SSH, Windows RDP, сайты, Jellyfin и игровые серверы используют свои штатные логины, пароли и ключи.

---

### 1. Запуск без ВПС (`standalone` + `-duck`)

Если провайдер выдаёт роутеру публичный (пусть и динамический) IPv4-адрес, запустить программу с флагом `-duck` можно двумя способами:

#### Вариант 1А: Быстрый старт без токена (`-duck`)
**Windows (PowerShell):**
```powershell
.\driftless-windows-amd64.exe standalone -ports 8096,3389,22 -duck
```
**Linux / macOS:**
```bash
./driftless standalone -ports 8096,3389,22 -duck
```
- Если вы уже сохраняли токен DuckDNS ранее, программа автоматически загрузит ваш постоянный домен из `.driftless-ddns.json`.
- Если токен ещё не задан, программа создаст **временный IP-домен** вида `<ip>.sslip.io` (например, `198-51-100-42.sslip.io`) для быстрого входа по HTTPS/TLS. *(Обратите внимание: адрес `sslip.io` содержит текущий IP и изменится при смене IP провайдером).*

#### Вариант 1Б: Постоянный бесплатный домен DuckDNS с токеном (`-duck ПОДДОМЕН:ТОКЕН`)
Чтобы получить **постоянный** адрес `*.duckdns.org`, который никогда не меняется при смене вашего IP:
1. Зайдите на сайт **[https://www.duckdns.org](https://www.duckdns.org)** (вход через GitHub / Google / Reddit), придумайте имя поддомена (например, `myhome`) и скопируйте ваш **token** вверху страницы.
2. Запустите программу **один раз**, указав имя и токен через двоеточие `-duck myhome:ВАШ_ТОКЕН`:
   **Windows (PowerShell):**
   ```powershell
   .\driftless-windows-amd64.exe standalone -ports 8096,3389,22 -duck myhome:a1b2c3d4-e5f6-7890-abcd-ef1234567890
   ```
   **Linux / macOS:**
   ```bash
   ./driftless standalone -ports 8096,3389,22 -duck myhome:a1b2c3d4-e5f6-7890-abcd-ef1234567890
   ```
3. Программа сохранит `myhome.duckdns.org` и токен в файл `.driftless-ddns.json` (права `0600`) и сразу обновит IP. При всех следующих запусках вводить токен заново не нужно: достаточно запускать с `-duck` (или просто `./driftless standalone -ports 8096,3389,22`).

**Что делает программа автоматически:**
1. **UPnP / NAT-PMP / PCP** открывает порты `8096`, `3389` и `22` (TCP и UDP) на домашнем роутере и восстанавливает правила после перезагрузки роутера.
2. **UDP STUN (`1s`)** определяет внешний IPv4-адрес и каждую секунду отслеживает его смену провайдером.
3. **Домен и Auto-TLS:** при каждой смене IP мгновенно обновляет `A`-запись вашего домена `myhome.duckdns.org` (или `<ip>.sslip.io`) и выпускает TLS-сертификат.

**Что выводится в консоль:**
```text
[standalone] ==========================================================
[standalone] Published Endpoints (Domain [ddns (duckdns)]: myhome.duckdns.org | Public IP: 198.51.100.42):
[standalone]   Port :8096  -> :8096  : https://myhome.duckdns.org:8096  (TCP/UDP: myhome.duckdns.org:8096)
[standalone]   Remote Desktop (RDP)  : myhome.duckdns.org:3389 (uses your Windows account credentials)
[standalone]   SSH Service           : myhome.duckdns.org:22 (uses your system SSH server & OS credentials)
[standalone] ==========================================================
```

**Как подключаться с телефона или ноутбука:**
- **Браузер / Jellyfin / Сайт:** откройте `https://myhome.duckdns.org:8096` (или `https://198-51-100-42.sslip.io:8096`).
- **SSH (WebSSH / Termius на iPhone или Android):** Хост `myhome.duckdns.org`, Порт `22`, ваш системный логин и пароль/ключ от Windows/Linux.
- **Удалённый рабочий стол (Microsoft Remote Desktop):** Компьютер `myhome.duckdns.org:3389`, ваша учётная запись Windows.

---

### 2. Постоянные домены: свой домен (`-domain`, `-vhosts`) и DDNS

В Driftless чётко разделены три типа доменов:
1. **Временный IP-домен (`sslip.io`):** создаётся при запуске `-duck` без токена DDNS, зависит от текущего IP и меняется при смене IP провайдером.
2. **Постоянный DDNS-домен (`duckdns`, `cloudflare`, `noip`, `dynu`, `-ddns-url`):** сохраняется в `.driftless-ddns.json` (права `0600`), восстанавливается после перезапуска и автоматически обновляет `A`-запись при каждой смене внешнего IP.
3. **Собственный домен (`-domain`, `-vhosts`):** ваш купленный домен, направленный на IP вашего ВПС или домашнего ПК.

#### Вариант А: Подключение своего домена флагом `-domain`
Направьте `A`-запись вашего домена на IP компьютера (или ВПС) и укажите `-domain`:
```bash
# Привязать свой домен mysite.com (автоматически включит HTTPS/TLS)
./driftless standalone -ports 8096,25565 -domain mysite.com

# Или направить домен на конкретный локальный порт через :80 и :443
./driftless standalone -domain media.mysite.com:8096 -https :443
```

#### Вариант Б: Несколько своих доменов на портах 80 и 443 (`-vhosts`)
```bash
./driftless standalone -vhosts site.mysite.com:3000,media.mysite.com:8096 -vhost-addr :80 -https :443
```

#### Вариант В: Автообновление постоянного домена в DuckDNS, Cloudflare, No-IP или Dynu
Настройки сохраняются в `.driftless-ddns.json` и автоматически подхватываются при следующих запусках:
```bash
# DuckDNS короткой командой (получите поддомен и токен на https://www.duckdns.org)
./driftless standalone -ports 8096 -duck myhome:ТОКЕН_DUCKDNS

# Или DuckDNS через отдельные флаги
./driftless standalone -ports 8096 -ddns-provider duckdns -ddns-domain myhome.duckdns.org -ddns-token ТОКЕН_DUCKDNS

# Cloudflare (автоматически обновляет A-запись при смене IP провайдером, TTL=60s)
./driftless standalone -ports 8096 -ddns-provider cloudflare -ddns-zone ID_ЗОНЫ -ddns-domain home.mysite.com -ddns-token ТОКЕН_CLOUDFLARE

# No-IP или Dynu
./driftless standalone -ports 8096 -ddns-provider noip -ddns-domain mypc.ddns.net -ddns-user ЛОГИН -ddns-token ПАРОЛЬ
./driftless standalone -ports 8096 -ddns-provider dynu -ddns-domain mypc.dynu.net -ddns-user ЛОГИН -ddns-token ПАРОЛЬ
```

---

### 3. Запуск через ВПС + Второй резервный ВПС (`-vps2`) + Несколько ПК

Используйте этот режим, если у провайдера «серый» IP (**CGNAT `100.64.0.0/10`**) или вы хотите раздавать сервисы через постоянный IP своего ВПС.

#### Обычное подключение (1 ВПС + 1 домашний ПК)
1. **На ВПС:**
   ```bash
   ./driftless server -ports 8080:80,8096,25565
   ```
   ВПС сгенерирует пароль и выведет в консоль готовую команду для запуска на домашнем ПК.
2. **На домашнем ПК:**
   ```bash
   ./driftless client -quic IP_ВАШЕГО_ВПС:4242 -token ПАРОЛЬ_ИЗ_КОНСОЛИ_ВПС
   ```

#### Подключение второго резервного ВПС (`-vps2`)
Если у вас есть второй запасной ВПС, запустите на нём `driftless server` с тем же `-token`, а на домашнем ПК добавьте флаг `-vps2`:
```bash
./driftless client -quic IP_ВПС_1:4242 -vps2 IP_ВПС_2:4242 -token ВАШ_ОБЩИЙ_ТОКЕН
```
*(Либо через запятую: `-quic IP_ВПС_1:4242,IP_ВПС_2:4242`). При недоступности первого ВПС агент автоматически переключит туннель на второй ВПС.*

#### Подключение нескольких домашних компьютеров (`pc1`, `pc2`, `pc3`) к одному ВПС
1. **На ВПС (один общий сервер):**
   ```bash
   ./driftless server -quic 0.0.0.0:4242 -vhost-addr :80 -https :443
   ```
2. **На Компьютере 1 (`pc1` - медиасервер + SSH):**
   ```bash
   ./driftless client -id pc1 -quic IP_ВПС:4242 -token ВАШ_ТОКЕН -vhosts media.mysite.com:8096 -ports 2221:22
   ```
3. **На Компьютере 2 (`pc2` - веб-сайт + SSH):**
   ```bash
   ./driftless client -id pc2 -quic IP_ВПС:4242 -token ВАШ_ТОКЕН -vhosts site.mysite.com:3000 -ports 2222:22
   ```
4. **На Компьютере 3 (`pc3` - игровой сервер TCP+UDP):**
   ```bash
   ./driftless client -id pc3 -quic IP_ВПС:4242 -token ВАШ_ТОКЕН -vhosts game.mysite.com:8080 -ports 25565:25565
   ```
- Отключение или перезагрузка `pc1` не влияет на работу `pc2` и `pc3`.
- Если другой агент попытается занять уже используемый публичный порт или домен (`-vhosts`), Gateway отклонит конфликт, выведет предупреждение в лог и сохранит изоляцию трафика, чтобы запросы не попали на чужой компьютер.

---

### 4. Честная проверка доступности и CGNAT (`./driftless check` и `-probe-url`)

Диагностика `./driftless check` разделяет проверку на три независимых уровня:
1. **`local_service_status`:** отвечает ли локальный сервис (TCP или UDP с подтверждением ответа) на самом компьютере.
2. **`port_forward_status`:** создано ли правило проброса порта на роутере по UPnP / NAT-PMP / PCP.
3. **`external_status`:** реальная проверка доступности порта из интернета.

**Почему локальное подключение к своему публичному IP не считается доказательством:** подключение из домашней сети к собственному внешнему IP (NAT hairpinning) часто проходит внутри домашнего роутера даже тогда, когда провайдер блокирует входящие соединения из интернета. Поэтому:
- Без внешнего probe-сервера Driftless **не выдаёт** локальную проверку за интернет-доступность и честно возвращает статус `unverified-from-internet` (`не удалось проверить извне`).
- Для реальной внешней проверки TCP и UDP укажите `-probe-url http://IP_ВАШЕГО_ВПС:8888/probe -token ВАШ_ТОКЕН` (эндпоинт `/probe` встроен в каждый `driftless server` на порту `-direct`):
  - **Защита `/probe` от сканирования и SSRF:** на Gateway эндпоинт `/probe` требует токен (`-token`, заголовок `Authorization: Bearer` или `?token=...`) либо активную сессию авторизованного агента, жестко блокирует локальные/частные/CGNAT-сети и разрешает проверять только собственный внешний IP вызывающего клиента (или зарегистрированного агента), исключая использование ВПС для сканирования чужих адресов.
  - **Трёхстадийная оценка UDP (`confirmed` / `open|silent` / `closed`):** если UDP-сервис отвечает на пробник (или работает через UDP-прокси Driftless), возвращается `verified-from-internet`; если ОС явно вернула `connection refused` (ICMP Port Unreachable), возвращается `closed` / `unreachable-from-internet`; если обычный UDP-сервис ждёт специфичный пакет протокола и молча игнорирует неизвестные датаграммы, выводится честный статус `open|silent` / `unconfirmed-udp` (отсутствие ответа по UDP само по себе не означает, что порт закрыт).
```bash
# Проверка локального сервиса, CGNAT и правил роутера (внешний статус: не удалось проверить извне)
./driftless check -ports 8096,25565,22 -duck

# Независимая проверка реальной доступности TCP и UDP извне через защищённый эндпоинт ВПС
./driftless check -ports 8096,25565,22 -probe-url http://IP_ВАШЕГО_ВПС:8888/probe -token ВАШ_ТОКЕН_ВПС
```

### 5. Ограничения и неподдерживаемые сценарии
- **CGNAT и двойной NAT (`100.64.0.0/10`):** режим `standalone` (без ВПС) не может принимать входящие подключения из интернета, если провайдер выдаёт «серый» IP за CGNAT или если перед вашим роутером стоит второй NAT-маршрутизатор. В этом случае используйте связку `driftless server` на ВПС + `driftless client` на домашнем ПК.
- **IPv4 и IPv6:** автоматическое определение внешнего адреса по STUN, проброс портов на роутере по UPnP IGD / NAT-PMP / PCP и генерация `sslip.io` работают поверх **IPv4**. В сетях только с IPv6 (без публичного IPv4) используйте режим через ВПС.
- **Выключенный UPnP или блокировка портов провайдером:** если на роутере отключён UPnP/NAT-PMP/PCP, откройте порты вручную в веб-панели роутера или используйте режим с ВПС.

---

### 6. Полный справочник всех флагов CLI

#### Команды запуска
| Команда | Описание |
| :--- | :--- |
| `driftless standalone` | Работа на домашнем ПК без ВПС (STUN + Авто-UPnP + Домен/DDNS + TCP/UDP/TLS) |
| `driftless server` | Запуск шлюза (Gateway) на ВПС (принимает один или несколько домашних ПК) |
| `driftless client` | Запуск агента на домашнем ПК (подключается к ВПС, поддерживает `-id` и `-vps2`) |
| `driftless check` | Диагностика внешнего IP по STUN, CGNAT, локальных сервисов, проброса портов и внешней доступности |
| `driftless show-token` | Показать сохранённый токен ВПС и готовую команду подключения для домашнего ПК |
| `driftless version` | Вывести версию `driftless v1.5.6` |

#### Все флаги (полная таблица)
| Флаг | По умолчанию | Описание |
| :--- | :--- | :--- |
| `-mode` | `"agent"` | Режим работы: `server` (`gateway`), `client` (`agent`) или `standalone` (`direct`, `p2p`) |
| `-ports` | `"8080:80,8096:8096"` | Порты: `8096,25565`, `PUBLIC:LOCAL`, `PUBLIC:NODE_ID:LOCAL` или `127.0.0.1:PUBLIC:LOCAL` (суффиксы `/tcp`, `/udp`, `/both`, `/http`, `/https`) |
| `-udp` | `true` | Включено по умолчанию: пробрасывает и TCP, и UDP на всех портах |
| `-duck` | `""` | `-duck ПОДДОМЕН:ТОКЕН` (постоянный домен `*.duckdns.org` с сайта duckdns.org) или просто `-duck` (подхватить сохранённый DDNS / выдать временный `<ip>.sslip.io`) |
| `-domain` | `""` | Привязать свой собственный домен с Auto-TLS (`-domain mysite.com` или `-domain media.mysite.com:8096`) |
| `-vhosts` | `""` | Маршрутизация доменов (`домен:ПОРТ` или `домен:ID_ПК:ПОРТ`, например `media.mysite.com:pc1:8096`) |
| `-vhost-addr` | `""` (`:80` при vhosts) | Порт приёма HTTP/HTTPS для доменного роутера (например, `:80`) |
| `-https` | `""` | Выделенный порт HTTPS для доменного роутера (например, `:443` или `:8443`) |
| `-tls` | `false` | Включить автоматическую расшифровку HTTPS/TLS на обычных TCP-портах из `-ports` |
| `-tls-cert` | `""` | Путь к своему `.pem` сертификату (если не указать - авто Let's Encrypt / SNI) |
| `-tls-key` | `""` | Путь к своему закрытому ключу `.pem` |
| `-quic` | `"0.0.0.0:4242"` | Адрес туннеля (на ВПС `0.0.0.0:4242`, на ПК `IP_ВПС:4242` или список через запятую `ВПС1:4242,ВПС2:4242`) |
| `-gateway` | `""` | Синоним флага `-quic` |
| `-vps2` | `""` | Адрес второго резервного ВПС для автоматического переключения (`IP_ВТОРОГО_ВПС:4242`) |
| `-id` / `-node` | `""` (`default`) | Имя домашнего ПК при подключении нескольких компьютеров к одному ВПС (`pc1`, `pc2`, `pc3`) |
| `-transport` | `"auto"` | Протокол туннеля: `auto` (QUIC с автопереключением на TCP-Mux), `quic` или `tcp` |
| `-token` | `""` (авто на ВПС) | Общий секретный пароль между ВПС и ПК (или список ротации через запятую `новый,старый`) |
| `-token-file` | `""` | Путь к файлу с секретным паролем туннеля |
| `-fingerprint` | `""` (авто-TOFU) | SHA-256 отпечаток сертификата ВПС для жёсткой привязки (Pinning) |
| `-direct` | `":8888"` | Порт прямого LAN-редиректа и внешнего проверочного эндпоинта `/probe` (`""` чтобы отключить) |
| `-probe-url` | `""` | URL независимого внешнего узла (например `http://IP_ВПС:8888/probe`) для проверки TCP/UDP доступности извне |
| `-same-lan` | `true` | Автоматически перенаправлять клиентов из одной домашней сети напрямую на локальный IP ПК |
| `-host` | `"127.0.0.1"` | Локальный IP целевых сервисов на домашнем ПК |
| `-lan-ip` | `""` (авто) | Вручную задать локальный LAN IP домашнего ПК |
| `-allow-ports` | `""` (все) | Белый список разрешённых локальных портов на домашнем ПК (например, `"80,8096,25565"`) |
| `-upnp` | `true` | Автоматический проброс TCP и UDP портов на роутере через UPnP IGDv1/v2, NAT-PMP и PCP v2 |
| `-stun` | `"stun.cloudflare.com:3478"` | STUN-сервер (или список через запятую) для проверки смены внешнего IPv4 по UDP |
| `-stun-interval` | `1s` | Частота проверки внешнего IP через STUN (по умолчанию каждую секунду) |
| `-ddns-provider` | `""` | Провайдер динамического DNS: `duckdns`, `cloudflare` (TTL=60s), `noip` или `dynu` |
| `-ddns-domain` | `""` | Домен для автообновления при смене IP |
| `-ddns-token` | `""` | API-токен или пароль для DDNS-провайдера |
| `-ddns-user` | `""` | Логин для No-IP / DynDNS / Dynu |
| `-ddns-zone` | `""` | Zone ID для Cloudflare (при `-ddns-provider=cloudflare`) |
| `-ddns-url` | `""` | Свой Webhook URL для обновления DNS (автоматически подставляет `{ip}` и `{domain}`) |
| `-max-buf` | `16777216` (16 МБ) | Размер скользящего кольцевого буфера в RAM на одну сессию |
| `-max-mem` | `268435456` (256 МБ) | Общий лимит памяти RAM для всех буферов сессий |
| `-session-ttl` | `90s` | Время удержания «замороженных» TCP/UDP соединений в RAM во время смены IP |
| `-quic-idle-timeout` | `8s` | Таймаут простоя туннеля до переподключения |
| `-quic-keepalive` | `2s` | Интервал проверки активности туннеля (Keepalive) |
| `-cert-dir` | `""` (`.driftless-certs`) | Папка для хранения сертификатов, ключей и токена |
| `-client-ca` | `""` | Файл корневого сертификата CA на ВПС для включения двустороннего mTLS |
| `-client-cert` | `""` | Клиентский сертификат mTLS на домашнем ПК |
| `-client-key` | `""` | Закрытый ключ клиентского сертификата mTLS на домашнем ПК |
| `-proxy-protocol` | `false` | Передавать заголовок HAProxy PROXY protocol v1, чтобы локальный сервер видел реальный IP гостя |
| `-metrics` | `""` | Адрес локального сервера метрик `/metrics` (Prometheus) и `/status` (JSON) |
