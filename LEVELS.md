# Level map

The complete agent in `edr/` is Level **3.5**. Every earlier level is still present; the table below points at the code that fulfills it.

## Lab 1

| Level | New capability | Where |
|---|---|---|
| **1.1** | Hash new `.exe` files against Emotet/Zeus SHA1 and delete | `filemon.py` `on_modified` (`.exe`); `main.py` `handle_exe_file` |
| **1.2** | Block packets to/from `89.233.43.71` | `firewall.py` `_detect_malicious_ip`; `main.py` `handle_blocked_malicious_ip` |
| **1.3** | `vssadmin … delete shadows /all` → kill parent | `procmon.py` ransomware branch; `main.py` `handle_ransomware_behavior` |
| **1.4** | Nested `.exe` in a `.zip` with a known hash | `filemon.py` (`.zip`); `main.py` `find_malware_in_zip` / `handle_zip_file` |
| **1.5** | New TCP listener → interactive allow/kill | `firewall.py` `_periodic_check_listeners`; `main.py` `handle_new_listener_detected` |

## Lab 2

| Level | New capability | Where |
|---|---|---|
| **2.1** | Resolve C2 packet to a PID via local port and kill it | `common.py` `find_pid_by_lport`; `firewall.py` PID on `blocked_malicious_ip` |
| **2.2** | Reassemble HTTP (src port 80) and hash the body | `streams.py`; `firewall.py` `_on_http_server_finished`; `main.py` `handle_http_download` |
| **2.3** | Remember download origin by content hash; enrich zip alerts | `main.py` `set_origin` / `origins`; zip branch of `handle_zip_file` |
| **2.4** | Track `curl.exe -k <url> -o <path>` (HTTPS, no body) | `procmon.py` `parse_curl_download`; `main.py` `handle_curl_download` |

## Lab 3

| Level | New capability | Where |
|---|---|---|
| **3.1** | `.jpg` that is actually a PE, with an internet origin | `filemon.py` `_is_executable`; `main.py` `handle_camouflaged_exe` |
| **3.2** | `net.exe user … /add` if an ancestor image is internet-origin | `procmon.py` `parse_net_user_add`; `main.py` `handle_user_added` |
| **3.3** | Hidden executable registered as `Win32_StartupCommand` | `wmimon.py` `_monitor_scheduled_jobs`; `main.py` `handle_new_startup_command` |
| **3.4** | New unsigned `Win32_Service` image | `wmimon.py` `_monitor_services`; `main.py` `handle_new_service` |
| **3.5** | Downloader parent launches that DLL with `rundll32` | `procmon.py` `parse_rundll32_dll`; `main.py` `handle_rundll32_exec` |

## Snapshots

Unmodified per-level solutions:

- `levels/lab1/1.1` … `levels/lab1/1.5`
- `levels/lab2/2.1` … `levels/lab2/2.4`
- `levels/lab3/3.1` … `levels/lab3/3.5`

Level 3.5 under `levels/lab3/3.5` is the last official snapshot. `edr/` is that stack plus comments, a slightly more robust rundll32 parser, origin lookup by **hash or path**, and macOS fallbacks so the repo can be imported and tested off the lab VM.
