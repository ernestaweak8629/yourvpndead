# YourVPNDead

Defensive security scanner for Android that demonstrates the **VLESS/xray/sing-box localhost SOCKS5 vulnerability**.

All popular VPN clients (v2rayNG, NekoBox, Hiddify, etc.) create an **unauthenticated SOCKS5 proxy on localhost**. Any app on the device — including spyware embedded in Yandex, WB, Ozon, or government-mandated apps — can connect to this proxy, route traffic through your VPN, and **discover your VPN server's exit IP**.

Knox, Shelter, Island, incognito mode, and per-app split tunneling **do not protect** against this attack.

## What it does

1. **Port Scanner** — Scans localhost for open proxy ports (known VPN client ports + full 65535 scan)
2. **SOCKS5 Probe** — Detects SOCKS5 proxies, checks if authentication is required (RFC 1928)
3. **Exit IP Resolver** — Connects through vulnerable SOCKS5 to reveal your VPN's exit IP
4. **xray API Detector** — Finds exposed xray gRPC API (HandlerService) that can dump your encryption keys
5. **Device Info** — Shows what spyware can learn: VPN status, network interfaces, direct IP
6. **Geolocation** — Locates the leaked exit IP (country, city, ISP, AS number)

## Download

Get the latest APK from [Releases](../../releases) or [Actions](../../actions) artifacts.

## Build

```bash
# Clone
git clone https://github.com/loop-uh/yourvpndead.git
cd yourvpndead

# Build debug APK
./gradlew assembleDebug

# APK at: app/build/outputs/apk/debug/app-debug.apk
```

Or open in Android Studio and run on device.

## Permissions

- `INTERNET` — for port scanning and IP lookup
- `ACCESS_NETWORK_STATE` — for VPN detection

**No data is sent to any server.** All scanning is local. Reports are shown only to the user.

## Background

- [Critical VLESS vulnerability (Habr, Russian)](https://habr.com/ru/articles/1020080/)
- [Per-app split bypass POC](https://github.com/runetfreedom/per-app-split-bypass-poc)
- [Meta & Yandex localhost tracking (USENIX Security 26)](https://localmess.github.io/)
- [CVE-2023-43644 — sing-box SOCKS5 auth bypass](https://github.com/advisories/GHSA-r5hm-mp3j-285g)

## Vulnerable clients

| Client | Engine | Default Port | Auth | Status |
|--------|--------|-------------|------|--------|
| v2rayNG | xray | 10808 | No | Vulnerable |
| NekoBox | sing-box | 2080 | No | Vulnerable |
| Hiddify | sing-box | ? | No | Vulnerable |
| v2RayTun | xray | ? | No | Vulnerable |
| Happ | xray | ? | No + API | **Critical — delete immediately** |
| Husi | sing-box | ? | **Yes** | Protected (enable auth) |
| Clash/mihomo | mihomo | disabled | N/A | Safe by default (no SOCKS port) |

## License

MIT
