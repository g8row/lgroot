# LGroot

Small, self-contained desktop app that puts the **Homebrew Channel** on an LG
webOS TV. It finds your TV on the network, runs the [SlopBro] exploit, and walks
you through the one thing you have to do by hand: press **OK** on the TV remote.

No browser window, no Python, no Node, no installer. One native binary with the
exploit payload and the Homebrew Channel package compiled in.

The window looks like this:

```
┌────────────────┬─────────────────────────────────────┐
│ LGroot         │ Choose your TV                      │
│                │ Make sure the TV is on and on the   │
│ ● Find your TV │ same network as this computer.      │
│ ○ Allow on TV  │ ┌─────────────────────────────────┐ │
│ ○ Install      │ │ Living Room TV          LG TV > │ │
│ ○ Finish       │ │ 192.168.1.50 · OLED55C1PUB      │ │
│                │ └─────────────────────────────────┘ │
│ Network        ├─────────────────────────────────────┤
│ settings       │ Enter an IP address    [Scan again] │
└────────────────┴─────────────────────────────────────┘
```

## Use it

1. Turn the TV on and connect it to the **same Wi-Fi or LAN** as this computer.
2. Open **LGroot**. It scans automatically.
3. Click your TV.
4. A prompt appears on the TV asking to allow **SlopBro**. Press **OK / Yes** —
   you have 60 seconds.
5. Wait. The TV installs Homebrew Channel and shows its own reboot prompt.
6. Restart the TV. Homebrew Channel appears in the app list.

Nothing about the TV changes until you press OK. If the TV never asks, nothing
was installed.

## Where it works

| webOS version | Status |
| --- | --- |
| 3.x – 6.x (2016 – 2023 TVs) | Works. Uses the `com.webos.app.adoverlayex` / `adoverlay` / `acroverlay` launchers. |
| 11.x and newer (2024+) | Tries `com.webos.app.voiceweb` first. |
| 3.5 – 4.x, patched firmwares | Frequently patched. Try [`dejavuln-autoroot`][dejavuln] instead. |
| Very old (webOS 1 – 2) | Not supported. |

Check [cani.rootmy.tv] for your exact model before you start.

## Build

Requires Rust 1.82 or newer. The build vendors nothing; all dependencies come
from crates.io. The UI uses Slint's software renderer, so there is no OpenGL or
GPU requirement — it works over screen sharing and inside virtual machines.

```sh
cargo build --release
```

That produces a single executable:

* macOS: `target/release/lgroot`, then `sh scripts/make_app.sh` for `dist/LGroot.app`
* Linux: `target/release/lgroot`
* Windows: `target\release\lgroot.exe`

To make the macOS app bundle (icon included):

```sh
python3 scripts/make_icon.py   # only needed if assets/AppIcon.icns is missing
sh scripts/make_app.sh
open dist/LGroot.app
```

`make app` does the same thing. Other targets: `make build`, `make test`,
`make run`, `make clean`.

## How it works

```
 scan.rs     SSDP M-SEARCH for urn:lge-com:service:webos-second-screen:1,
             plus a TCP sweep of 3001/3000, plus the LG certificate
             fingerprint and the DIAL friendlyName on port 1925
 ssap.rs     hand-written RFC 6455 WebSocket client over rustls; pairing,
             listApps, launch, getAppInfo. No Origin header, so the TV's
             browser filter does not apply
 payload.rs  tiny HTTP server that serves the exploit page, autoroot.sh,
             and the bundled Homebrew Channel IPK from inside the binary
 session.rs  the flow: pair -> pick a launcher -> deliver -> poll getAppInfo
             until org.webosbrew.hbchannel exists
```

Two details worth knowing:

* **The IPK is embedded.** Upstream `autoroot.sh` downloads Homebrew Channel
  from GitHub on the TV itself, which fails on TVs with a wrong clock or broken
  TLS. LGroot passes `files=package.json;main.js;hbchannel.ipk` so the TV fetches
  everything from this computer and never needs the internet.
* **Success means the app exists.** The installer reporting "all files served"
  is not proof of anything, so the app keeps asking the TV whether
  `org.webosbrew.hbchannel` is installed, for up to three minutes.

## Troubleshooting

**No TVs found.**
The TV may be in standby. Most TVs keep their network stack alive, but a few do
not — turn it on properly. Also check that the router is not using "AP
isolation"/"client isolation", which blocks devices from talking to each other.
Wireless repeaters and guest networks often do this.

**The TV never asks to allow SlopBro.**
Usually the firmware is patched, or the launcher app LGroot picked is missing on
that model. Retry once; if it happens again, look up your model on
[cani.rootmy.tv].

**The install starts but Homebrew Channel never appears.**
Look at the TV screen. If `autoroot.sh` reports a failure, the TV's firmware is
probably patched. If it says the download failed, use **Network settings → This
computer's address** and type the address manually — the automatic choice can pick a
VPN or a second network card.

**Network settings → Test connection.**
Starts a tiny web server and gives you a URL. Open that URL in the TV's browser
(or any device on the same Wi-Fi). If you see *"Here's your slop, bro!"*, the TV
can reach this computer and the problem is elsewhere. If you do not, a firewall
or client isolation is in the way.

**macOS asks whether LGroot may find devices on the local network.**
Allow it. macOS 14+ blocks local network traffic — including the multicast
search — until you do. If you already said no: System Settings → Privacy &
Security → Local Network, and switch LGroot on.

**Pairing key.**
Once paired, the key is stored in `~/Library/Application Support/LGroot`
(macOS), `%APPDATA%\LGroot` (Windows) or `~/.config/lgroot` (Linux), readable
only by you. Delete the file to force a fresh prompt on the TV.

## Legal / licensing

LGroot is licensed **AGPL-3.0-or-later**. It embeds the [SlopBro] payload, which
is also AGPL-3.0-or-later, so redistributing a binary means offering the
complete corresponding source — that is what this repository is. See `LICENSE`
and `NOTICE`.

The exploit payload in `vendor/slopbro/` is upstream code, kept unmodified;
its own licence is in `vendor/slopbro/COPYING`. Homebrew Channel is bundled as
`assets/hbchannel.ipk` and remains the property of the [webOS Homebrew
Project][hbchannel] contributors.

There is no warranty. Rooting a TV may void its warranty, and a firmware update
can undo it. Read what you are installing.

[SlopBro]: https://github.com/throwaway96/slopbro
[dejavuln]: https://github.com/throwaway96/dejavuln-autoroot
[cani.rootmy.tv]: https://cani.rootmy.tv/
[hbchannel]: https://github.com/webosbrew/webos-homebrew-channel
