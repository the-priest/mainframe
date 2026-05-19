# Mainframe

Wi-Fi deauth tool — wraps `aircrack-ng` suite with an interactive picker.
Built for Kali, works on Debian / Ubuntu / Arch / Fedora / NetHunter chroot.

## Hardware reality

- AR9271 is **2.4 GHz only**. If your target is connected via 5 GHz, this can't reach them.
- Dual-band routers usually broadcast both bands on the same SSID. Phones pick based on signal — often 5 GHz when close, dropping to 2.4 GHz farther away.
- For full coverage you need a dual-band injector adapter (e.g. Alfa AWUS036ACM, mt7612u chipset).
- On mobile, only NetHunter chroot can run this (Termux without root cannot do monitor mode). External USB-OTG adapter required.

## Install

```
git clone git@github.com:the-priest/mainframe.git
cd mainframe
sudo bash install.sh
```

The installer detects your OS and installs `aircrack-ng`, `wireless-tools`, `iw`,
plus the desktop entry and icon. After install you can either:

- run `sudo mainframe` from a terminal, or
- launch **Mainframe** from your app menu.

## Usage

```
sudo mainframe
```

Flags:

- `-t MIN` — deauth duration in minutes (default 10)
- `-s SEC` — AP scan duration in seconds (default 15)

Flow: pick wireless interface → monitor mode on → scan APs → pick AP → pick client MAC (or `a` for broadcast) → deauth → cleanup + back online.

## Reading the AP list

Channel column tells you the band:

- **1–14** — 2.4 GHz (AR9271 can hit these)
- **36+**  — 5 GHz (needs a dual-band adapter; AR9271 won't even *see* these)

If your home SSID doesn't appear in the scan and you know it's broadcasting, it's probably 5 GHz only at the moment, or you're out of range.

## Uninstall

```
sudo bash uninstall.sh
```

## Legal

Run this only on networks you own or have explicit permission to test. Deauthing networks you don't have permission to interfere with is illegal in most jurisdictions (including Ireland under the Wireless Telegraphy Act and Criminal Damage Act). You are responsible for what you do with this.
