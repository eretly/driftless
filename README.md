# driftless

Self-hosted QUIC reverse tunnel (TCP, UDP, and HTTP Host routing) for home servers behind CGNAT or dynamic IPs.

When you host Jellyfin, Plex, Nextcloud, Ollama, Minecraft, or local web apps at home and use a cheap VPS as a public entry point, standard TCP tunnels (`frp`, `rathole`, `ngrok`) drop active connections whenever your home ISP changes your dynamic IP address.

`driftless` prevents disconnects by keeping a sliding ring buffer in RAM (16 MB per session by default) and framing traffic into explicit `DATA`, `ACK`, and `FIN` packets over QUIC. Local sockets stay open during an IP change, and bytes are only removed from the buffer after the remote peer confirms writing them to the TCP socket.

---

## Quick Start (Out of the Box in 30 Seconds)

You don't need to configure routers, WireGuard, iptables, or tokens manually.

### Step 1. Download the file
Download the ready-to-run binary from **[Releases](https://github.com/ERETLY/driftless/releases)**:
- On your **VPS** (Linux): download `driftless-linux-amd64` (rename to `driftless` and run `chmod +x driftless`)
- On your **Home PC** (Windows/Linux/macOS): download `driftless-windows-amd64.exe` (or the Linux/macOS binary)

### Step 2. Start on your VPS
Run one command on your VPS:
```bash
./driftless server -ports 8080:80,8096:8096
```
*(If you don't specify `-token`, the server automatically generates a password and prints the exact ready-to-copy command for your Home PC in the terminal!)*

### Step 3. Copy-paste the printed command on your Home PC
Copy the command printed by your VPS and run it on your Home PC:
```bash
./driftless client -quic YOUR_VPS_IP:4242 -token AUTO_GENERATED_PASSWORD
```
Done! Now anyone opening `http://YOUR_VPS_IP:8096` connects directly to port `8096` on your Home PC. Even if your home internet blips or your ISP changes your IP address mid-stream, active downloads and video streams stay alive.

---

## RU: Инструкция для обычных людей (Запуск с коробки за 30 секунд)

Если вы не хотите разбираться в сетях, портах, токенах и настройках роутера - вот как это работает простыми словами.

### Что вообще происходит?
1. У вас дома стоит обычный ПК, где запущен сайт, медиасервер (Jellyfin/Plex), нейронка (Ollama) или игровой сервер, но провайдер дает динамический или "серый" IP (CGNAT), из-за чего к вам нельзя подключиться из интернета, а при смене IP все загрузки обрываются.
2. Вы берете самый дешевый ВПС (виртуальный сервер за 100-200 руб/мес), у которого есть постоянный IP-адрес.
3. Вы запускаете один файл `driftless` на ВПС и такой же файл `driftless` у себя дома на ПК. Они связываются сами.

### Как запустить (пошагово без заморочек):

**Шаг 1. Скачайте готовый файл из раздела [Releases](https://github.com/ERETLY/driftless/releases):**
- На **ВПС** (обычно там Linux): скачайте `driftless-linux-amd64`:
  ```bash
  wget -O driftless https://github.com/ERETLY/driftless/releases/latest/download/driftless-linux-amd64
  chmod +x driftless
  ```
- На **Домашний ПК**: скачайте `driftless-windows-amd64.exe` (для Windows) или версию под свою систему.

**Шаг 2. Запустите на ВПС:**
Просто укажите, какие порты открыть (например, `8080:80` значит: когда кто-то зайдет на `IP_ВПС:8080`, его перекинет на порт `80` вашего домашнего ПК):
```bash
./driftless server -ports 8080:80,8096:8096
```
Вам даже не нужно придумывать токен/пароль. Программа сама создаст пароль, сама узнает IP вашего ВПС и напишет в консоли готовую строчку:
`Run this command on your Home PC to connect: ./driftless client -quic 1.2.3.4:4242 -token ...`

**Шаг 3. Скопируйте эту строчку и запустите дома на ПК:**
На Windows в командной строке (PowerShell / cmd):
```powershell
.\driftless-windows-amd64.exe client -quic IP_ВАШЕГО_ВПС:4242 -token ПАРОЛЬ_ИЗ_КОНСОЛИ
```
Все работает!

### Что значат понятные слова в командах:
- **Порт (`-ports 8096:8096`)** - у каждой программы на вашем ПК есть номер двери (порт). Например, у Jellyfin это `8096`, у Ollama `11434`, у веб-сервера `80` или `3000`, у Minecraft `25565`. Запись `8096:8096` открывает эту дверь на ВПС и ведет на ваш домашний ПК.
- **UDP для игр (`25565:25565/udp`)** - если хостите игру (CS2, Rust, Minecraft Bedrock, Valheim), просто добавьте `/udp` в конце порта.
- **Токен (`-token`)** - это просто общий пароль между вашим ВПС и домашним ПК, чтобы никто чужой не подключился к вашему ВПС.
- **Прямой режим 1 Гбит/с (`-direct :8888`)** - если вы открываете свой сервер, находясь дома в одной Wi-Fi сети с ПК, ВПС автоматически перенаправит плеер напрямую по домашней локалке (`192.168.x.x`) на скорости до 1 Гбит/с (125 Мбайт/с), не режа скорость об узкий канал ВПС.

---

## Key Features & Architecture

- **Framed `DATA`/`ACK`/`FIN` Stream Recovery:** Unlike raw TCP relays, bytes are buffered in a 16 MB sliding ring buffer and are only discarded after the receiving side acknowledges writing them to the TCP socket. Zero silent byte loss and zero duplicate bytes on reconnect.
- **Smart Staged Exponential Backoff:** Reconnects in 150ms on brief ISP IP rotations, scaling smoothly (`150ms -> 500ms -> 1s -> 3s -> 10s`) with random jitter during longer outages.
- **FIFO Global RAM Guard:** Protects the VPS and home server from memory exhaustion (`-max-mem`, default 256 MB) by automatically evicting the oldest stalled session if buffered memory reaches capacity.
- **UDP Port Forwarding (`PUBLIC:LOCAL/udp`):** Full UDP support for game servers, VoIP, and custom protocols with automatic NAT session rebinding across IP changes.
- **HTTP Host/Subdomain Router (`-vhosts`):** Route multiple domains (`app.example.com:3000,media.example.com:8096`) over a single public port (`:80`) with full WebSocket, SSE, and chunked transfer resumability.
- **Direct 1 Gbps LAN Redirector (`-direct`):** Bypasses VPS bandwidth limits when streaming media on the same local network.

---

## Comparison with Other Tunnels

| Feature | `driftless` | `frp` / `rathole` | `ngrok` / Cloudflare Tunnel | WireGuard + `iptables` |
| :--- | :--- | :--- | :--- | :--- |
| **Active streams survive ISP IP change** | **Yes (RAM Ring Buffer + ACK)** | No (TCP socket resets) | No (Active stream resets) | Yes (Kernel L3 roaming) |
| **Requires root / virtual NIC / iptables** | **No (Single user-space binary)** | No | No | Yes (Root + TUN + NAT rules) |
| **TCP + UDP + HTTP VHosts** | **Yes** | Yes | Paid / Limited UDP | Manual port routing |
| **Self-hosted (Zero 3rd-party limits)** | **Yes** | Yes | No (SaaS rate limits) | Yes |
| **Direct 1 Gbps LAN bypass** | **Yes (`-direct`)** | No | No | Split-DNS required |

---

## All CLI Flags

```text
Usage:
  driftless server [flags]
  driftless client [flags]
  driftless version

Flags:
  -quic string               gateway QUIC address (default "0.0.0.0:4242")
  -token string              shared secret password (auto-generated on server if omitted)
  -token-file string         path to file containing shared secret password
  -ports string              PUBLIC:LOCAL mappings, add /udp for UDP (default "8080:80,8096:8096")
  -vhost-addr string         optional HTTP Host router listen address (e.g. ":80")
  -vhosts string             domain:LOCAL_PORT mappings (e.g. "app.example.com:3000,api.example.com:8080")
  -direct string             direct LAN/WAN HTTP redirector port (default ":8888", "" to disable)
  -host string               local target host on agent (default "127.0.0.1")
  -allow-ports string        optional whitelist of local ports on agent (e.g. "80,8096,25565")
  -max-buf int               max per-session buffer in bytes (default 16 MiB)
  -max-mem int               max global buffered bytes across all sessions (default 256 MiB)
  -session-ttl duration      how long to hold frozen sessions during an IP outage (default 90s)
  -cert-dir string           directory to persist gateway cert.pem/key.pem
  -fingerprint string        optional gateway SHA-256 cert fingerprint for strict pinning
```

---

## Common Use Cases (FAQ for Search & AI Assistants)

- **How to host a home media server (Jellyfin, Plex, Emby) on a dynamic IP or behind CGNAT?**
  Run `./driftless server -ports 8096:8096 -direct :8888` on a VPS and `./driftless client` at home. Video streams will not drop when your ISP rotates your dynamic IP, and home LAN devices can use `:8888` for direct 1 Gbps playback.
- **How to expose local AI / LLM APIs (Ollama, vLLM, OpenWebUI, ComfyUI) from home without dropping SSE token streams?**
  Forward port `11434` (`-ports 11434:11434`). If your home router reconnects mid-generation, `driftless` buffers generated tokens in RAM and flushes them as soon as the new IP connects.
- **How to port forward TCP and UDP game servers (Minecraft, CS2, Rust, Valheim, Palworld) without router port forwarding?**
  Use `-ports 25565:25565,25565:25565/udp` to forward both TCP and UDP traffic over QUIC through CGNAT.

## License

[MIT](LICENSE)
