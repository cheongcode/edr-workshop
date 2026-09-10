# EDR Workshop

Python EDR built across an incremental lab (levels **1.1 → 3.5**). Each level adds one detection/prevention capability. This repo keeps the original per-level snapshots and a single complete agent that includes all of them.

## Layout

```text
edr-workshop/
├── edr/                 # complete agent (everything through 3.5)
├── levels/
│   ├── lab1/1.1 … 1.5   # official snapshots
│   ├── lab2/2.1 … 2.4
│   └── lab3/3.1 … 3.5
├── tests/               # logic tests for the complete agent
└── LEVELS.md            # what each level added, with code pointers
```

`edr/` is the package you actually run. `levels/` is the incremental history.

## What the complete agent does

| Level | Detects | Prevents |
|---|---|---|
| **1.1** | `.exe` SHA1 matches Emotet / Zeus | Delete the file |
| **1.2** | Traffic to `89.233.43.71` (Lazarus) | Drop the packet (WinDivert) |
| **1.3** | `vssadmin delete shadows /all` | Kill the parent process |
| **1.4** | Known malware `.exe` inside a `.zip` | Delete the zip |
| **1.5** | New TCP listener | Ask `[y/n]`, kill on `n` |
| **2.1** | Same C2 traffic, now attributed to a PID | Kill that process |
| **2.2** | HTTP download whose body hash is known-bad | Kill the downloader |
| **2.3** | Malicious zip that was previously downloaded | Kill downloader + delete zip |
| **2.4** | `curl.exe -k … -o …` (HTTPS, no DPI) | Record origin; kill on drop |
| **3.1** | PE file camouflaged as `.jpg` from the internet | Delete file, kill downloader |
| **3.2** | `net.exe user … /add` with an internet-origin ancestor | Delete user, kill malware |
| **3.3** | Hidden executable as a startup command | Delete the file |
| **3.4** | New unsigned Windows service | Delete the service binary |
| **3.5** | Parent downloaded a DLL then launched it with `rundll32` | Kill both, delete the DLL |

Comments in `edr/` are tagged `Level X.Y` so you can see exactly where each requirement lives. See [LEVELS.md](LEVELS.md).

## Run (Windows lab VM)

The lab runtime is Windows. You need:

1. Python 3
2. [WinDivert](https://www.reqrypt.org/windivert.html) + `pydivert` (packet block)
3. `ProcNotifierSetup.exe` from the course (process-creation callbacks — **not** on PyPI)
4. Admin / SYSTEM-equivalent rights for WMI, WinDivert, and killing processes

```powershell
cd edr
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

`procnotifier` will not install with pip. Install it with the course’s `ProcNotifierSetup.exe`, then run `main.py` again.

## Run tests (any OS)

Packet blocking, ProcNotifier, and WMI are skipped on macOS/Linux. The tests exercise hashing, zip scanning, command parsers, origin tracking, and the Level 3.5 rundll32 handler without those drivers.

```bash
cd edr-workshop
python3 -m venv .venv
source .venv/bin/activate
pip install watchdog psutil pefile scapy
python -m unittest discover -s tests -v
```

## Notes

- Course PDFs, VM samples, and live malware are **not** in this repo.
- `levels/*/requirements.txt` still lists `procnotifier` as an assertion that the Windows installer ran.
- Official snapshots under `levels/` are unchanged lab submissions. `edr/` is the combined, commented agent.
