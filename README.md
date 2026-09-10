<div align="center">

<img src="docs/logo.svg" alt="Adsorb Logo" width="96" height="96" />

# Adsorb

### **The Arrogant, Bare-Metal DNS Sinkhole for ESP32-S3**

*Why burn 15 Watts on a Raspberry Pi or babysit a noisy homelab Docker container just to drop UDP packets?*

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="docs/badges/badge-license.svg" alt="License: Apache 2.0" height="28" /></a>
  <a href="https://www.espressif.com/"><img src="docs/badges/badge-hardware.svg" alt="Hardware: ESP32-S3 N16R8" height="28" /></a>
  <img src="docs/badges/badge-memory.svg" alt="Memory: 8MB Octal PSRAM" height="28" />
  <img src="docs/badges/badge-power.svg" alt="Power Draw: ~0.58W" height="28" />
  <a href="https://the-masked-bear.github.io/Adsorb/"><img src="docs/badges/badge-site.svg" alt="Live Site: Online" height="28" /></a>
  <a href="https://adblock.turtlecute.org/"><img src="docs/badges/badge-adblock.svg" alt="Adblock Test: 100% Verified" height="28" /></a>
</p>

</div>

---

## ⚡ The Philosophy

In surface chemistry, **adsorption** is the phenomenon where molecules adhere to a surface rather than passing through. 

**Adsorb** does the exact same thing to the internet: it catches ad telemetry, tracking scripts, and surveillance beacons at the network boundary and swallows them whole into a silent blackhole before they ever reach your browser, smart TV, or phone.

No Linux kernel overhead. No SD-card corruption. No multi-gigabyte OS updates. Just pure, bare-metal C++ executing directly on dual Xtensa LX7 cores.

---

## 🚀 Key Highlights

* **⚡ Sub-Millisecond PSRAM LRU DNS Cache (< 0.2 ms)**  
  High-speed **2-way set-associative cache** (2,048 entries, ~1.05 MB) residing entirely in Octal PSRAM. Repeat queries are answered in under **200 microseconds** directly from memory without touching the network. Dynamically recalculates remaining TTL and rewrites DNS Transaction IDs on every hit.

* **🏎️ Ultra-Fast Parallel Race Upstream UDP & Encrypted DoH (RFC 8484)**  
  When an uncached domain is queried, Adsorb queries **both Cloudflare (`1.1.1.1`) and Google (`8.8.8.8`) concurrently** over UDP 53. The fastest response (12–25ms) wins, gets forwarded to the client, and is instantly cached in PSRAM. Also supports RFC 8484 binary DNS-over-HTTPS with automatic fast fallback.

* **📟 Physical 1.3" I2C OLED Telemetry Display (SH1106 / SSD1306)**  
  Real-time 128x64 physical status display running a 3-page diagnostic carousel on Core 0 (Executive Dashboard, Cache & DoH metrics, and Silicon Telemetry). Features non-blocking software I2C and safe weak-pulldown bus detection—if the display is unplugged, the engine idles gracefully with zero bus locks.

* **🛡️ Built-in OS Connectivity & Push Whitelist**  
  Hardened against false positives for Android captive portal checks, Google Play Services / Firebase Cloud Messaging (`firebaseinstallations.googleapis.com`), Apple APNs, and Windows NCSI, ensuring zero "Connected, no internet" warnings across household devices.

* **⚖️ RFC-Compliant SERVFAIL Failover**  
  In the event of upstream WAN connectivity failure, returns `SERVFAIL` (RCODE 2) rather than `NXDOMAIN` (RCODE 3). This instructs client operating systems to immediately query secondary DNS without poisoning local negative caches.

* **🕳️ Dual-Stack Zero Sinkhole**  
  Intercepts and sinkholes both **IPv4 (`0.0.0.0`)** and **IPv6 (`::`)**. Many consumer ad-blockers fail when browsers quietly fall back to IPv6; Adsorb seals both doors shut.

* **🛑 DNS-over-HTTPS (DoH) Neutralization**  
  Browsers love to bypass your router's DNS settings by silently tunneling queries through encrypted Cloudflare or Google DoH resolvers. Adsorb returns authoritative `NXDOMAIN` (RCODE 3) on Firefox/Chrome Canary domains (`use-application-dns.net`) and bootstrap endpoints (`chrome.cloudflare-dns.com`, `dns.google`), forcing clients to respect your local DNS sovereignty.

* **🎨 Neo-Brutalist Live Web Dashboard**  
  Built with raw, asynchronous ESP32 HTTP handling. Features a high-contrast porcelain theme, live real-time query counters, free PSRAM/Heap monitors, instant query inspection, and zero cloud dependencies.

* **🔌 Zero-Maintenance Hardware Footprint**  
  Consumes less than **120 mA (~0.58 Watts)** at 5V. Plug it into any dusty 5V phone charger brick next to your router and forget it exists. Boots and secures the network in under **1.5 seconds**.

---

## 📊 Benchmark & Test Results

Empirical benchmarks verified against live hardware (ESP32-S3 N16R8 @ 240MHz):

| Metric / Test Suite | Result | Mechanism |
| :--- | :---: | :--- |
| **Octal PSRAM LRU Cache Hit** | **< 0.2 ms** | 2-Way Set Associative (2,048 entries) |
| **Ad / Tracker Sinkhole** | **< 0.2 ms** | 64-Bit FNV-1a Binary Search Index |
| **Uncached Query (Parallel Race)** | **12 – 40 ms** | Simultaneous Cloudflare & Google UDP 53 |
| **[adblock.turtlecute.org](https://adblock.turtlecute.org/)** | **100.0%** | **131 / 131 Domains Blocked** |
| **d3ward Ad Block Test** | **100.0%** | **Clean Pass** |
| **Annual Electricity Cost** | **~ $0.45** | **0.58W Continuous Draw** |

---

## 🛠️ Hardware Requirements & OLED Pinout

* **Board:** ESP32-S3 DevKit with **N16R8** (16MB Quad SPI Flash + 8MB Octal PSRAM).
* **Display (Optional):** 1.3" I2C OLED Display (SH1106 or SSD1306 128x64).
* **Power:** Standard 5V USB-C cable and 5W USB wall adapter.
* **Network:** 2.4GHz 802.11 b/g/n Wi-Fi network.

### 🔌 OLED Display Wiring (SH1106 / SSD1306)
| OLED Pin | ESP32-S3 N16R8 Pin | Notes |
| :--- | :--- | :--- |
| **VCC** | `3V3` | 3.3V Power Supply |
| **GND** | `GND` | Ground |
| **SDA** | `GPIO 8` | I2C Data (Software I2C) |
| **SCL** | `GPIO 9` | I2C Clock (Software I2C) |

> ℹ️ **Plug & Play Safe:** If no display is attached, Adsorb detects the absent bus on boot and gracefully idles the display task with zero CPU overhead and zero bus hangs.

---

## 📦 Project Structure

```text
Adsorb/
├── include/
│   ├── Blocklist.hpp      # FNV-1a 64-bit PSRAM hash vector & OS whitelist
│   ├── Config.hpp         # System pins, network timeouts, and upstream mode
│   ├── DnsCache.hpp       # Sub-millisecond 2-way Octal PSRAM LRU Cache
│   ├── DnsServer.hpp      # Dual-stack UDP DNS engine & Parallel Race Resolver
│   ├── EncryptedDns.hpp   # RFC 8484 DNS-over-HTTPS (DoH) engine
│   ├── OledDisplay.hpp    # 1.3" I2C OLED multi-page telemetry carousel
│   └── WebDashboard.hpp   # Asynchronous Neo-Brutalist status UI & REST API
├── src/
│   └── main.cpp           # System orchestrator, FreeRTOS core pinning
├── ad-domains2.0.txt      # Curated blocklist of 255,042 domain rules
├── partitions_16MB.csv    # Custom flash partitioning (3MB app, SPIFFS/LittleFS)
├── platformio.ini         # PlatformIO build configuration with -O3 optimizations
├── LICENSE                # Apache License 2.0
└── README.md              # Project documentation
```

---

## 🔧 Building & Flashing

### 1. Prerequisites
Install [PlatformIO IDE](https://platformio.org/) (VS Code Extension or CLI).

### 2. Configure Wi-Fi Credentials
Edit `src/main.cpp` with your Wi-Fi credentials:
```cpp
const char* WIFI_SSID     = "Your_WiFi_Name";
const char* WIFI_PASSWORD = "Your_WiFi_Password";
```

### 3. Build & Flash via PlatformIO
Connect your ESP32-S3 via USB to your computer:
```bash
# Build the firmware
pio run

# Flash the firmware over USB
pio run --target upload

# Open the serial monitor (115200 baud)
pio device monitor
```

---

## 🌐 Router Configuration

To protect every phone, smart TV, console, and computer in your home automatically:

1. Open your router's administrative page (usually `192.168.1.1` or `192.168.0.1`).
2. Navigate to **DHCP / LAN Settings -> DNS Server**.
3. Set **Primary DNS** to your ESP32-S3's IP address:
   ```text
   Primary DNS:   192.168.1.101
   Secondary DNS: 192.168.1.101
   ```
   > ⚠️ **Important:** Set **both** Primary and Secondary DNS to your ESP32's IP. Operating systems like Windows, iOS, and Android query primary and secondary DNS concurrently; if you leave a public fallback like `1.1.1.1` or `8.8.8.8`, devices will leak queries around the ad-blocker!

4. Renew DHCP leases across your devices by reconnecting Wi-Fi or running:
   ```cmd
   ipconfig /renew
   ipconfig /flushdns
   ```

5. Open your browser and navigate to:
   ```text
   http://192.168.1.101/
   ```
   Enjoy your clean, arrogant, ad-free internet!

---

## 📄 License

Licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for complete terms and copyright notices.

```text
Copyright 2026 The Masked Bear

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
