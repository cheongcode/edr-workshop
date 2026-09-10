# Combined EDR (levels 1.1–3.5)

```powershell
pip install -r requirements.txt
python main.py
```

See the repo [README](../README.md) and [LEVELS.md](../LEVELS.md) for the feature map.

Install `../installers/ProcNotifierSetup.exe` once, then WinDivert/`pydivert` for packet block. On ARM64 Windows, use **AMD64 Python** (not `Python3xx-arm64`) or WinDivert will be skipped.
