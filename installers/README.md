# Windows installers

These are not on PyPI. Run them on the Windows lab machine **before** `python main.py`.

| File | What it installs |
|---|---|
| `ProcNotifierSetup.exe` | Python `procnotifier` module (`watch_new_processes`) for process-creation hooks |

After setup, open a new terminal so Python can see the package, then:

```powershell
cd edr
.\.venv\Scripts\activate
python -c "from procnotifier import watch_new_processes; print('ok')"
python main.py
```
