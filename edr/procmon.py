"""Process-creation monitor.

Windows uses ProcNotifier (ProcNotifierSetup.exe). On macOS the import is
optional and this component logs a warning instead of crashing.
"""
import logging
import re

from common import Component

try:
    from procnotifier import watch_new_processes
except ImportError:
    watch_new_processes = None


def win_basename(path):
    """Basename that understands Windows paths even when running on macOS."""
    return (path or '').replace('\\', '/').rstrip('/').split('/')[-1]


def parse_curl_download(args):
    """Level 2.4 — curl.exe -k <url> -o <path>."""
    parts = args.split()
    if '-k' not in parts or '-o' not in parts:
        return None
    k = parts.index('-k')
    o = parts.index('-o')
    if k + 1 >= len(parts) or o + 1 >= len(parts):
        return None
    return {'url': parts[k + 1], 'download_path': parts[o + 1]}


def parse_net_user_add(args):
    """Level 3.2 — net.exe user <name> ... /add."""
    if not args.strip().startswith('user ') or ' /add' not in args:
        return None
    for arg in args.split():
        if arg != 'user' and arg != '/add':
            return arg
    return None


def parse_rundll32_dll(args):
    """Level 3.5 — first token that looks like a DLL path."""
    for token in args.split():
        candidate = token.strip('"')
        if ',' in candidate:
            candidate = candidate.split(',', 1)[0]
        if candidate.lower().endswith('.dll'):
            return candidate
        match = re.search(r'(?i).+\.dll', candidate)
        if match:
            return match.group(0)
    return None


class ProcMon(Component):
    def __init__(self, event_queue):
        Component.__init__(self, event_queue, 'ProcMon')
        if watch_new_processes is None:
            logging.warning(
                "ProcNotifier is Windows-only; process creation monitoring is disabled"
            )
            return
        watch_new_processes(self._handle_new_process)

    def _handle_new_process(self, event):
        path = event.get('path') or ''
        args = event.get('args') or ''
        basename = win_basename(path)

        # Level 1.3 — ransomware shadow-copy deletion
        if 'vssadmin' in path and 'delete shadows /all' in args.lower():
            self.send_event({
                "kind": "ransomware_behavior",
                "info": "Shadow copy deletion",
                "pid": event['ppid'],
            })

        # Level 2.4 — HTTPS downloads via curl (opaque to DPI)
        if basename.lower() == 'curl.exe':
            parsed = parse_curl_download(args)
            if parsed:
                self.send_event({
                    "kind": "curl_download",
                    "url": parsed['url'],
                    "download_path": parsed['download_path'],
                    "pid": event['pid'],
                    "parent": event['ppid'],
                })

        # Level 3.2 — backdoor local user
        if basename.lower() == 'net.exe':
            username = parse_net_user_add(args)
            if username:
                self.send_event({
                    "kind": "user_added",
                    "username": username,
                    "pid": event['pid'],
                    "process_name": "net.exe",
                    "parent": event['ppid'],
                })

        # Level 3.5 — remote DLL loader
        if basename.lower() == 'rundll32.exe':
            dll_path = parse_rundll32_dll(args)
            if dll_path:
                self.send_event({
                    "kind": "rundll32_exec",
                    "path": dll_path,
                    "pid": event['pid'],
                    "parent": event['ppid'],
                })
