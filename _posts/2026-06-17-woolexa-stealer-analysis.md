---
layout: post
title: "Woolexa Stealer - Full Malware Analysis Report"
date: 2026-06-17
author: Fahad
---

## Executive Summary

Woolexa Stealer is a .NET Framework 4.8 information stealer and remote access trojan (RAT) distributed via Discord as a fake Minecraft modpack titled *"Minecraft Nightmare 1.0.0"*. The malware exfiltrates browser credentials, cryptocurrency sessions, Discord tokens, and system intelligence to a compromised domain (`bigscreenmod.com`). It maintains persistent real-time access through WebSocket-based HVNC (Hidden Virtual Network Computing), enabling keystroke logging, microphone surveillance, screen streaming, and arbitrary command execution. The C2 infrastructure contains a critical authentication bypass vulnerability: the build key serves as the sole credential for all agent-facing endpoints, allowing anyone with the leaked keys (`mit`, `yatowoolexa`) to impersonate victims, decrypt exfiltrated data, and observe live operator commands.

![Woolexa modpack screenshot](/assets/images/image.webp)

![Discord distribution screenshot](/assets/images/image%20(1).webp)

**Severity:** Critical  
**Malware Class:** Infostealer / RAT  
**Target Sector:** General consumers (Discord gaming community)  
**Origin Attribution:** Turkish-speaking developer(s), tracked as `shelcodeloader`

---

## Key Judgments

- The malware uses a multi-layered exfiltration pipeline combining AES-256-CBC encryption with XOR obfuscation, keyed per-build.
- C2 authentication is fundamentally broken - a single shared secret (`buildKey`) authenticates all agents, endpoints, and WebSocket control channels.
- The `bigscreenmod.com` domain is the sole C2 infrastructure, registered March 2026 via GoDaddy, fronted by Cloudflare.
- No privilege escalation exploit is used; UAC bypass relies on registry manipulation and `runas` elevation.
- Persistence is primarily achieved through WMI event subscription, with a scheduled task fallback.
- The developer machine hostname (`KUXEY`) and PDB path point to a developer using the alias `shelcodeloader`.

---

## 1. Malware Identity

| Attribute | Value |
|---|---|
| **Malware Name** | Woolexa Stealer |
| **Assembly Name** | `BackendMinecraft` |
| **Fabric Mod ID** | `mcmod` (v1.0.0) |
| **Author Alias** | `shelcodeloader` |
| **Developer Machine** | `KUXEY` (from PDB path) |
| **PDB Path** | `C:\Users\KUXEY\Desktop\shelcodeloader\NativeHost\x64\Release\reflective_clr_host.pdb` |
| **Language / Framework** | C# (.NET Framework 4.8) |
| **Origin** | Turkish-speaking (code comments in Turkish) |
| **Attack Vector** | Social engineering via Discord modpack (`.mrpack`) |
| **Distribution Platform** | Discord (hijacked 7-year-old account) |
| **Detected AV Engines** | Not reported - no hashes available for VT lookup |

---

## 2. Incident Timeline (Reconstructed)

| Date (Estimated) | Event |
|---|---|
| March 2026 | `bigscreenmod.com` registered via GoDaddy |
| Pre-June 2026 | Woolexa Stealer developed on machine `KUXEY` by `shelcodeloader` |
| June 2026 | Malicious `.mrpack` distributed via compromised Discord account |
| June 2026 | Sample acquired and analysis conducted |
| June 13, 2026 | C2 panel infrastructure documented during active analysis |

---

## 3. Initial Access & Distribution

The malware was packaged as a Minecraft modpack file (`.mrpack`) and distributed through Discord from a hijacked account with seven years of trust history. This social engineering tactic exploits platform trust signals - a long-standing account appears legitimate, lowering victim suspicion.

Upon installation, the modpack loads `BackendMinecraft.dll` into the Minecraft process via Fabric mod loading, triggering the full infection chain.

![Malicious modpack distributed via Discord](/assets/images/malicious%20activity.png)

![Woolexa C2 panel](/assets/images/YOOOOOOO.png)

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Woolexa Implementation |
|---|---|---|---|
| **Execution** | T1204.002 | User Execution: Malicious File | Victim voluntarily installs `.mrpack` modpack |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | `cmd.exe` execution via `EXEC_COMMAND` |
| **Persistence** | T1546.003 | Event Triggered Execution: WMI Event Subscription | Permanent WMI filter running every 60s |
| **Persistence** | T1053.005 | Scheduled Task/Job | `USOHealthCheck` task on `ONSTART` |
| **Persistence** | T1574.002 | Hijack Execution Flow: DLL Side-Loading | `cryptbase.dll` proxy DLL injection |
| **Defense Evasion** | T1055.001 | Process Injection: DLL Injection | Reflective CLR hosting (memory-only load) |
| **Defense Evasion** | T1112 | Modify Registry | UAC lowering via `ConsentPromptBehaviorAdmin` |
| **Defense Evasion** | T1562.001 | Impair Defenses: Disable/Modify Tools | `WOOLEXA_ALLOW_INSECURE_SSL` disables SSL validation |
| **Defense Evasion** | T1070.004 | Indicator Removal: File Deletion | Cleans up `woolexa_*`, `err_*.vbs`, `elevate_*.vbs` |
| **Credential Access** | T1555.003 | Credentials from Password Stores: Web Browsers | Decrypts browser `Login Data` via DPAPI/AES-GCM/ChaCha20 |
| **Credential Access** | T1539 | Steal Web Session Cookie | Steals cookies for session hijacking |
| **Credential Access** | T1555 | Credentials from Password Stores | Discord token extraction from LevelDB |
| **Collection** | T1056.001 | Input Capture: Keylogging | WebSocket-controlled keylogger with window titles |
| **Collection** | T1123 | Audio Capture | Microphone recording at 48kHz/16-bit/mono |
| **Collection** | T1113 | Screen Capture | JPEG streaming at ~2 FPS, single screenshot |
| **Collection** | T1005 | Data from Local System | File listing, reading, and exfiltration |
| **Exfiltration** | T1560.003 | Archive Collected Data: Custom Encryption | AES-256-CBC + XOR before exfiltration |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | All data exfiltrated via HTTP POST to `/api/collect` |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | HTTPS for data, WSS for real-time C2 |
| **Discovery** | T1082 | System Information Discovery | HWID, OS, CPU, RAM, AV, IP geolocation |
| **Privilege Escalation** | T1134 | Access Token Manipulation | `SeDebugPrivilege`, SYSTEM impersonation from `lsass`/`winlogon` |
| **Impact** | T1491.001 | Defacement: Internal Defacement | `SET_WALLPAPER` command for victim harassment |

---

## 5. Internal Configuration

### 5.1 Hardcoded in `Config.cs`

| Key | Value | Purpose |
|---|---|---|
| `SteamApiKey` | `440D7F4D810EF9298D25EDDF37C1F902` | Steam API key for validating stolen Steam accounts |
| `SteamApiUrl` | `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/` | Steam API endpoint |
| `UserAgent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` | HTTP User-Agent |
| `BackendUrl` | **`https://bigscreenmod.com`** | C2 server (exfiltration endpoint) |
| `BuildKey` | `yatowoolexa` | Build identifier (ties victims to attackers in C2 panel) |
| `WsUrl` | **`wss://bigscreenmod.com/agent-ws`** | WebSocket URL for real-time C2 (HVNC/keylog/audio) |

### 5.2 Embedded Config (`ConfigEmbedded.cs`)

```json
{
  "backendUrl": "https://bigscreenmod.com",
  "wsUrl": "wss://bigscreenmod.com/agent-ws",
  "buildKey": "mit",
  "licenseKey": ""
}
```

The presence of two distinct build keys (`mit`, `yatowoolexa`) indicates a multi-tenant C2 panel - multiple operators share the same backend infrastructure. The empty `licenseKey` field suggests the panel's licensing mechanism was either disabled or not enforced at the agent level.

### 5.3 Environment Variable Overrides

Woolexa supports an extensive set of environment variable overrides, indicating a flexible C2 panel that operators can tune per-deployment:

| Env Var | Purpose |
|---|---|
| `WOOLEXA_BACKEND_URL` | Override C2 URL |
| `WOOLEXA_BUILD_KEY` | Override build key |
| `WOOLEXA_WS_URL` | Override WebSocket URL |
| `WOOLEXA_PERSIST_NO_COPY` | Skip persistence copy |
| `WOOLEXA_PERSIST_ALWAYS_COPY` | Force persistence copy |
| `WOOLEXA_PERSIST_COMMANDLINE` | Custom WMI persistence command |
| `WOOLEXA_ALLOW_INSECURE_SSL` | Disable SSL certificate validation |
| `WOOLEXA_DISABLE_PANEL_AGENT` | Disable HVNC panel |
| `WOOLEXA_HVNC_PRIMARY_ONLY` | Only capture primary monitor |
| `WOOLEXA_PANEL_RAM_GB` | Fake RAM report to C2 |
| `WOOLEXA_NO_ALERT` | Suppress C2 alert popup |
| `WOOLEXA_SHOW_ALERT` | Force alert popup |
| `WOOLEXA_RVC_SPAWNED` | Memory-loaded execution marker |
| `WOOLEXA_MEMORY_LOADER` | Memory-loaded execution marker |

---

## 6. C2 Infrastructure

![C2 panel login interface](/assets/images/Pasted%20image%2020260613143404.png)

### 6.1 Domains & Servers

| Component | Value |
|---|---|
| **C2 Domain** | `bigscreenmod.com` |
| **C2 Panel** | `https://bigscreenmod.com/auth` |
| **C2 WebSocket** | `wss://bigscreenmod.com/agent-ws` (fallback: `ws://{host}:3001`) |
| **Data Exfiltration** | `POST https://bigscreenmod.com/api/collect` |
| **Progress Tracking** | `POST https://bigscreenmod.com/api/progress` |
| **JPEG Screen Stream** | `POST https://bigscreenmod.com/api/stream` |
| **Panel Alert** | `GET https://bigscreenmod.com/api/stealer/alert` |
| **Mic Ingestion** | `POST https://bigscreenmod.com/api/mic-ingest/*` |
| **Origin IP** | `130.12.242.204` (AS210558) |
| **Cloudflare IPs** | `104.21.64.58`, `172.67.176.167` |
| **Registrar** | GoDaddy (registered March 2026) |

### 6.2 Infrastructure Analysis

The C2 architecture follows a standard two-tier design: Cloudflare fronts the origin server at `130.12.242.204`. The domain `bigscreenmod.com` was registered in March 2026, making this a relatively young operation at the time of analysis. The WebSocket fallback on port 3001 is notable - Cloudflare does not proxy non-standard ports by default, meaning direct origin access may be possible by bypassing Cloudflare entirely.

---

## 7. Data Exfiltration Capabilities

### 7.1 Browser Data Theft

Extracts credentials and session data from **ALL user profiles on ALL drives** across these browsers:

- **Chromium-based:** Chrome, Chrome Beta, Brave, Edge, Opera, Opera GX, Vivaldi, Yandex, Chromium, Comet
- **Gecko-based:** Firefox, Waterfox, LibreWolf, Zen

**Data stolen per browser:**

| Artifact | Source File | Decryption Method |
|---|---|---|
| Saved Passwords | `Login Data` (SQLite) | DPAPI / AES-GCM / ChaCha20-Poly1305 |
| Cookies | `Cookies` (SQLite) | Direct read - used for session hijacking |
| Credit Cards | `Web Data` (SQLite) | Card numbers, expiry dates, cardholder names |
| Auto-fill Data | `Web Data` (SQLite) | Names, addresses, phone numbers |
| Browsing History | `History` (SQLite) | URLs, visit counts, timestamps |
| Bookmarks | `Bookmarks` (JSON) | Direct read |
| Discord Tokens | LevelDB stores | Encrypted and plaintext extraction |

### 7.2 Discord Token Theft

Scans Discord desktop application LevelDB stores (`Local Storage/leveldb`) across five Discord variants: Discord stable, Discord PTB, Discord Canary, Discord Development, and Discord. Also extracts Discord tokens from browser-based LevelDB stores. Matches both encrypted tokens (`dQw4w9WgXcQ:...`) and plaintext token patterns.

### 7.3 Platform Account Hijacking

Each stolen cookie or session token is validated live against the platform's API to confirm it is still active:

| Platform | Cookie / Token Used | Data Extracted |
|---|---|---|
| **Roblox** | `.ROBLOSECURITY` | Account ID, username, display name, **Robux balance** |
| **Instagram** | `sessionid` | Username, email, phone number, full name, follower count |
| **TikTok** | `sessionid` | Username, email, display name, follower count |
| **Spotify** | `sp_dc` | Username, email, country |
| **Steam** | `loginusers.vdf` | SteamID (64-bit), profile name, profile URL (via Steam API) |

### 7.4 Victim System Profiling

The malware collects the following intelligence from each compromised host:

- **Public IP** - resolved via `api.ipify.org`, `ipinfo.io`, `ip-api.com`, `ipapi.co`
- **Geolocation** - country and city from IP geolocation
- **Hostname**
- **OS Version** - full Windows NT version string
- **Architecture** - x64 or x86
- **RAM** - total and used capacity
- **CPU Model** - from `PROCESSOR_IDENTIFIER` environment variable
- **Hardware ID (HWID)** - from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
- **Antivirus Status** - checks 22 installation paths and 11 running processes
- **Desktop Screenshot** - captured at infection time

### 7.5 Exfiltration Pipeline

1. All stolen data is staged to a temporary directory (`Browser-Datas/`)
2. Data is compressed (zipped) entirely in memory - no temporary archive written to disk
3. The zip archive is encrypted using AES-256-CBC with a key derived from SHA-256(`buildKey`); a random IV is prepended to the ciphertext
4. The AES ciphertext is then XOR-encrypted with the raw build key string
5. The final payload is transmitted as `application/octet-stream` via `POST /api/collect`
6. HTTP headers include: `X-Build-Key`, `X-Hostname`, `X-IP`

---

## 8. Remote Access (HVNC) Capabilities

The malware maintains a persistent WebSocket connection to `wss://bigscreenmod.com/agent-ws` for real-time command and control. The panel supports the following operations:

### 8.1 Remote Desktop (HVNC)

| Command | Description |
|---|---|
| `MOUSE_MOVE` | Move the mouse cursor to specified coordinates |
| `MOUSE_CLICK` | Simulate a click at specified coordinates |
| `KEY_DOWN` | Inject keystrokes into the victim's session |
| `LAUNCH_BROWSER` | Launch an isolated browser in a hidden desktop for covert browsing |
| `KILL_BROWSER` | Terminate the hidden browser process |
| `KILL_EXPLORER` | Terminate Windows Explorer |
| `START_EXPLORER` | Restart Windows Explorer |
| `SET_WALLPAPER` | Change the desktop wallpaper from a URL (harassment capability) |

### 8.2 Surveillance

| Capability | Details |
|---|---|
| **Keylogger** | Captures all keystrokes with associated window titles and timestamps. Controlled via WebSocket: `KEYLOG_START`, `KEYLOG_STOP`, `KEYLOG_DUMP` |
| **Microphone** | Records audio from the default microphone at 48 kHz / 16-bit / mono. Streams raw PCM data via HTTP to `/api/mic-ingest/{session}` |
| **Audio Playback** | Plays audio files (WAV/MP3) on the victim's speakers - enables bidirectional audio for harassment |
| **Clipboard** | On-demand clipboard read (text content only) |
| **JPEG Screen Streaming** | Continuous screen capture streamed to `/api/stream` at approximately 2 FPS |

### 8.3 File Management

| Command | Description |
|---|---|
| `FM_PLACES` | Enumerate special folders (Desktop, Downloads, Documents, etc.) |
| `FM_LIST` | List directory contents |
| `FM_READ` | Read a file and return base64-encoded content (up to 16 MB) |
| `FM_DOWNLOAD` | Download a file as base64 (up to 64 MB) |

### 8.4 Command Execution

| Command | Description |
|---|---|
| `EXEC_COMMAND` | Execute arbitrary `cmd.exe` commands with a 120-second timeout. Returns full interactive shell output |

---

## 9. Persistence Mechanisms

Woolexa implements multiple persistence mechanisms to survive reboot, implemented in `InferencePlanPersistence.cs`:

### 9.1 WMI Event Subscription (Primary)

Installs a permanent WMI event filter that triggers the malware executable every 60 seconds. Uses `__InstanceModificationEvent` on the `Win32_PerfFormattedData_PerfOS_System` class:

```
Query: SELECT * FROM __InstanceModificationEvent WITHIN 60
       WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'
Filter Name: WindowsUpdateHealthCheck
Consumer Name: WindowsUpdateHealthConsumer
```

### 9.2 Scheduled Task (Fallback)

- **Task Name:** `Microsoft\Windows\UpdateOrchestrator\USOHealthCheck`
- **Trigger:** `ONSTART` (system boot)
- **Privileges:** Highest available (runs with full privileges)

### 9.3 Payload Copy

Copies itself to `C:\ProgramData\Microsoft\Update\updatecheck.exe` with hidden and archive file attributes. This copy is skipped if the malware is already executing from a non-ephemeral (persistent) path.

### 9.4 DLL Proxy Injection

- Uses `cryptbase.dll` as a proxy DLL to hijack cryptbase lookups in other processes
- Supports COM hijacking via `--com-hijack-install` and `--com-hijack-remove` CLI arguments

---

## 10. Privilege Escalation & UAC Bypass

| Technique | Implementation |
|---|---|
| **UAC Lowering** | Sets `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin = 0` and `PromptOnSecureDesktop = 0` |
| **SeDebugPrivilege** | Enables debug privilege to enable process injection into privileged processes |
| **SYSTEM Impersonation** | Opens and duplicates access tokens from `winlogon.exe`, `lsass.exe`, or `services.exe` |
| **UAC Prompt** | Falls back to `runas` verb for administrative elevation |
| **Memory Loading** | The entire .NET assembly is loaded directly from memory via `ReflectiveClrHost.dll` - never touches disk |

---

## 11. Anti-Forensics & Evasion

- **Logging:** Operational logs written to `%TEMP%\BackendMinecraft.log` in Turkish
- **Cleanup:** Removes temporary artifacts on completion (`woolexa_*`, `err_*.vbs`, `elevate_*.vbs`)
- **Memory-Only Execution:** Full .NET assembly reflective loading via `ReflectiveClrHost.dll` leaves minimal disk forensic artifacts
- **Proxy Bypass:** All network communication uses `UseProxy = false` to bypass system proxy settings, preventing inspection by enterprise proxy appliances
- **SSL Pinning Bypass:** `WOOLEXA_ALLOW_INSECURE_SSL` environment variable disables certificate validation entirely
- **HeavyPacketBomb:** Floods browser windows with messages before credential extraction to crash or confuse forensic tools that hook browser windows

---

## 12. Detection Opportunities

### 12.1 YARA Rule

```yara
rule Woolexa_Stealer_Indicators {
    meta:
        author = "Threat Intelligence"
        description = "Detects Woolexa Stealer artifacts and behaviors"
        date = "2026-06-17"

    strings:
        $pdb = "reflective_clr_host.pdb" nocase
        $buildkey_mit = "mit" nocase
        $buildkey_woolexa = "yatowoolexa" nocase
        $ws_url = "bigscreenmod.com/agent-ws" nocase
        $backend_url = "bigscreenmod.com" nocase
        $steam_key = "440D7F4D810EF9298D25EDDF37C1F902"
        $env_prefix = "WOOLEXA_" nocase
        $config_backend = "BackendMinecraft" nocase
        $mod_id = "mcmod" nocase
        $log_path = "BackendMinecraft.log"

    condition:
        any of ($pdb, $buildkey_mit, $buildkey_woolexa, $ws_url,
                $backend_url, $steam_key, $config_backend, $mod_id)
        or 3 of ($env_prefix, $log_path, $buildkey_mit, $buildkey_woolexa)
}
```

### 12.2 Sigma Rule - WMI Persistence

```yaml
title: Woolexa Stealer WMI Persistence
id: 2a8f7c3b-9e1d-4f6a-bc5d-8e3f2a1c7b4d
status: experimental
description: Detects WMI event filter and consumer creation matching Woolexa persistence
author: Threat Intelligence
date: 2026-06-17
logsource:
    category: wmi_event
    product: windows
detection:
    selection_filter:
        EventID: 19
        FilterName: 'WindowsUpdateHealthCheck'
    selection_consumer:
        EventID: 20
        ConsumerName: 'WindowsUpdateHealthConsumer'
    selection_binding:
        EventID: 21
        FilterName: 'WindowsUpdateHealthCheck'
    condition: any of selection_*
falsepositives:
    - Legitimate Windows Update health checks (rare)
level: high
```

### 12.3 Sigma Rule - Scheduled Task

```yaml
title: Woolexa Scheduled Task Persistence
id: 3b9e8d4c-2f1a-4a6b-8c7d-1e2f3a4b5c6d
status: experimental
description: Detects Woolexa scheduled task creation
author: Threat Intelligence
date: 2026-06-17
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'schtasks.exe'
        CommandLine: '*Microsoft\Windows\UpdateOrchestrator\USOHealthCheck*'
    condition: selection
falsepositives:
    - Legitimate Windows Update task recreation (rare)
level: high
```

### 12.4 Splunk / ELK Query - Network IOC

```splunk
index=network sourcetype=proxy
url=*.bigscreenmod.com* OR url=*/api/collect OR url=*/api/stream
| stats count by src_ip, url, user_agent
```

```splunk
index=endpoint sourcetype=sysmon
(EventID=1 Image=*updatecheck.exe)
OR (EventID=19 "WindowsUpdateHealthCheck")
OR (CommandLine="*--com-hijack-install*")
| table _time, ComputerName, User, Image, CommandLine
```

### 12.5 Disk Forensic Artifact Paths

```
%TEMP%\BackendMinecraft.log
%ProgramData%\Microsoft\Update\updatecheck.exe
%TEMP%\woolexa_*
%TEMP%\err_*.vbs
%TEMP%\elevate_*.vbs
```

---

## 13. C2 Analysis & Exploitation

### 13.1 Authentication Weakness

The C2 panel uses the `buildKey` as the **sole authentication mechanism** for all agent-facing endpoints. There is no IP allowlisting, no per-machine secret, no session tokens, and no cryptographic challenge. Every API endpoint and WebSocket control channel authenticates solely via the `X-Build-Key` HTTP header or a `buildKey` JSON field.

The two leaked build keys - `mit` and `yatowoolexa` - function as **master keys to the entire C2 backend**.

### 13.2 Endpoint Access Matrix

| Endpoint | Method | Auth Method | What an Attacker with the Build Key Can Do |
|---|---|---|---|
| `/agent-ws` | WebSocket | `buildKey` in `AGENT_REGISTER` JSON | Register as fake agent, receive panel commands sent to victims |
| `/api/collect` | POST | `X-Build-Key` header | Decrypt intercepted stolen data, poison C2 database |
| `/api/progress` | POST | `X-Build-Key` header | Inject fake progress entries, potentially enumerate victims |
| `/api/stream` | POST | `X-Build-Key` header | Receive JPEG screen captures, pollute streaming data |
| `/api/stealer/alert` | GET | `X-Build-Key` header | Read panel-wide alerts configured by C2 operator |
| `/api/mic-ingest/*` | POST | `X-Build-Key` header | Receive live microphone audio streams |

### 13.3 WebSocket Agent Impersonation

The most impactful attack vector is WebSocket agent registration. The malware authenticates by sending:

```json
{
  "event": "AGENT_REGISTER",
  "instanceId": "<any_guid>",
  "hostname": "<any>",
  "hwid": "<any>",
  "platform": "windows",
  "arch": "x64",
  "osRelease": "<any>",
  "version": "vwolexa-cs",
  "localIp": "<any>",
  "publicIp": "<any>",
  "cpuModel": "<any>",
  "ramGb": 0,
  "licenseKey": "mit",
  "buildKey": "mit"
}
```

A fake agent registered this way will:
- Be accepted as a legitimate victim by the panel
- Receive `HEARTBEAT` acknowledgements every 7 seconds
- Receive any commands the panel broadcasts to active agents
- Appear in the panel's active client list alongside real victims

**Commands observable by a fake agent:**

| Command | What It Reveals |
|---|---|
| `KEYLOG_START` / `KEYLOG_STOP` / `KEYLOG_DUMP` | Panel is harvesting keystrokes from victims |
| `MIC_START` / ingest path | Panel is eavesdropping on victims' microphones |
| `EXEC_COMMAND` | Commands the panel is running on victims |
| `LAUNCH_BROWSER` | Panel is initiating covert browsing sessions |
| `FM_LIST` / `FM_READ` / `FM_DOWNLOAD` | Files the panel is exfiltrating from victims |
| `CLIPBOARD_READ` | Panel is reading victims' clipboard |

### 13.4 Data Decryption

Stolen data sent to `/api/collect` uses a build-key-derived encryption scheme:

```
encryption_key = SHA-256(buildKey)
```

The encryption pipeline:
1. AES-256-CBC with a random IV (prepended to ciphertext)
2. XOR-encrypted again with the raw build key

Since both `mit` and `yatowoolexa` are known, any intercepted stolen data can be decrypted. This also enables test submissions to reverse-engineer the C2 database schema.

### 13.5 Direct Origin Access

The origin server at `130.12.242.204` (AS210558) is behind Cloudflare. However:
- The malware hardcodes a fallback: if `WsUrl` is empty, it connects directly to `ws://{host}:3001`
- Cloudflare only proxies standard web ports (80/443) by default
- Port 3001 likely bypasses Cloudflare entirely

Probe commands:

```bash
wscat -c ws://130.12.242.204:3001
curl -H "Host: bigscreenmod.com" http://130.12.242.204/api/stealer/alert
curl -k https://130.12.242.204/api/stealer/alert
```

---

## 14. Indicators of Compromise (IOC)

### 14.1 Network IOCs

| Type | Value |
|---|---|
| **C2 Domain** | `bigscreenmod.com` |
| **C2 WebSocket** | `wss://bigscreenmod.com/agent-ws` |
| **Collect Endpoint** | `https://bigscreenmod.com/api/collect` |
| **Stream Endpoint** | `https://bigscreenmod.com/api/stream` |
| **Progress Endpoint** | `https://bigscreenmod.com/api/progress` |
| **Mic Ingest** | `https://bigscreenmod.com/api/mic-ingest/` |
| **Origin IP** | `130.12.242.204` |
| **Cloudflare IPs** | `104.21.64.58`, `172.67.176.167` |

### 14.2 Static IOCs

| Type | Value |
|---|---|
| **Steam API Key** | `440D7F4D810EF9298D25EDDF37C1F902` |
| **Build Keys** | `yatowoolexa`, `mit` |
| **XOR Key** | `qweqwe1` |
| **AES Key Derivation** | SHA-256(`"Shelcodeloader-embedded-key-v1"`) |
| **AES IV** | `AB AE A1 61 0C 9B 23 AA 03 5B F1 42 34 63 9C 2A` |

### 14.3 Host IOCs

| Type | Value |
|---|---|
| **Scheduled Task** | `Microsoft\Windows\UpdateOrchestrator\USOHealthCheck` |
| **WMI Filter Name** | `WindowsUpdateHealthCheck` |
| **WMI Consumer Name** | `WindowsUpdateHealthConsumer` |
| **WMI Binding Name** | `WindowsUpdateHealthBinding` |
| **Disk Artifact** | `%ProgramData%\Microsoft\Update\updatecheck.exe` |
| **Log File** | `%TEMP%\BackendMinecraft.log` |
| **Temp Staging** | `%TEMP%\woolexa_*` |
| **VBS Artifacts** | `%TEMP%\err_*.vbs`, `%TEMP%\elevate_*.vbs` |

### 14.4 Attacker Identity IOCs

| Type | Value |
|---|---|
| **Discord Username** | `shelcodeloader` |
| **Discord User ID** | `543708648233369610` |
| **Minecraft UUID** | `ac4b71bf-ca5a-4801-9654-829d67a9fc3b` |
| **Minecraft Username** | `dailussxd` |
| **Modpack Name** | `Minecraft Nightmare 1.0.0` |
| **Developer Machine** | `KUXEY` |
| **PDB Path** | `C:\Users\KUXEY\Desktop\shelcodeloader\NativeHost\x64\Release\reflective_clr_host.pdb` |

---

## 15. Attribution

The malware is attributed to a Turkish-speaking developer operating under the alias `KUXEY`. Attribution is supported by:

- **Code comments in Turkish** within the decompiled .NET assemblies
- **PDB path** referencing `C:\Users\KUXEY\Desktop\shelcodeloader\`
- **Discord account** `shelcodeloader` (ID: `543708648233369610`) used for distribution
- **Minecraft account** `dailussxd` (UUID: `ac4b71bf-ca5a-4801-9654-829d67a9fc3b`) linked to the same operator
- The hijacked Discord account used for distribution had 7 years of history, suggesting the attacker either compromised an established account or purchased access

The multi-tenant build key system (`mit`, `yatowoolexa`) suggests `shelcodeloader` may operate as a malware builder vendor, selling access to the Woolexa C2 panel to multiple affiliates.

---


### In Summary

The use of discord as a medium for spreading malware is widespread and common, Make sure to not download and execute any files especially if they are shared as Minecraft / Game mods or cheats. 