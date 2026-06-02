# Mainframe

Wi-Fi deauth tool — wraps `aircrack-ng` suite with an interactive picker.
Built for Kali, works on Debian / Ubuntu / Arch / Fedora / NetHunter chroot.

## Hardware reality

- Scans and deauths **both 2.4 and 5 GHz** with a dual-band injector adapter (e.g. Alfa AWUS036ACM, mt7612u chipset). Defaults to scanning all bands.
- Single-band cards still work — they just won't see the other band. The AR9271 is 2.4 GHz only; pass `-b 2.4` with it to skip the pointless 5 GHz channel hops.
- **DFS channels (52–144)** are the catch on 5 GHz. Most cards refuse injection on these in monitor mode because they require radar detection first, so a deauth there will silently fail even though the AP shows up in the scan. Non-DFS 5 GHz is **36/40/44/48** (and, outside the EU, 149–165). If your target is on a DFS channel, move your own router to 36–48 to test. The picker flags DFS channels with a yellow `DFS` tag.
- Dual-band routers usually broadcast both bands on the same SSID. Phones pick based on signal — often 5 GHz when close, dropping to 2.4 GHz farther away. The same SSID can therefore show up twice in the scan, once per band.
- On mobile, only NetHunter chroot can run this (Termux without root cannot do monitor mode). External USB-OTG adapter required.

## Install

One line:

```
curl -fsSL https://raw.githubusercontent.com/the-priest/mainframe/main/get.sh | sudo bash
```

Pulls the repo, detects your OS, installs `aircrack-ng` / `wireless-tools` / `iw` /
`network-manager`, drops the binary in `/usr/local/bin`, registers the icon and
desktop entry. Then either:

- run `sudo mainframe` from a terminal, or
- launch **Mainframe** from your app menu.

Manual, from a local clone:

```
git clone https://github.com/the-priest/mainframe.git && cd mainframe && sudo bash install.sh
```

## Usage

```
sudo mainframe
```

Flags:

- `-b {2.4,5,all}` — band to scan (default `all`)
- `-t MIN` — deauth duration in minutes (default 10)
- `-s SEC` — AP scan duration in seconds (default 20)
- `-c SEC` — focused client scan duration in seconds (default 30)

Scanning all bands hops a lot more channels, so each gets less dwell time — if a known AP doesn't surface, bump `-s 30` or narrow with `-b 5`.

Flow: pick wireless interface → monitor mode on → scan APs → pick AP → pick client MAC (or `a` for broadcast) → deauth → cleanup + back online.

## Reading the AP list

Channel column tells you the band:

- **1–14** — 2.4 GHz
- **36–48** — 5 GHz, non-DFS — deauth works here
- **52–144** — 5 GHz, **DFS** — flagged `DFS`; injection usually fails in monitor mode
- **149–165** — 5 GHz, non-DFS (not allocated in the EU)

If your home SSID doesn't appear and you know it's broadcasting, it's likely on a band you didn't scan, or the scan was too short to hop to its channel (try `-s 30`), or you're out of range.

## Uninstall

```
sudo bash uninstall.sh
```

## Legal

Run this only on networks you own or have explicit permission to test. Deauthing networks you don't have permission to interfere with is illegal in most jurisdictions (including Ireland under the Wireless Telegraphy Act and Criminal Damage Act). You are responsible for what you do with this.
