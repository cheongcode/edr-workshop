"""Complete EDR agent (Labs 1.1 through 3.5).

Each handler is tagged with the level that introduced it. Run this on the
Windows lab VM with WinDivert + ProcNotifier installed. On macOS, FileMon
still works; packet/process/WMI hooks are disabled.
"""
import logging
import os
import queue
import subprocess
import traceback
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from string import Formatter

import psutil

from common import *
from filemon import FileMon
from firewall import Firewall
from procmon import ProcMon
from wmimon import WMIMon

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Level 1.1 — known-bad SHA1
MALWARES_SHA1 = {
    "f5524f0acd2dbb535c800a33cf207e4bfd4f5297": "Emotet",
    "4a100aca2953b51b7856a5029e4667d6ebabe2f4": "Zeus",
}

# Level 1.2 — Lazarus C2
C2_IPS = {
    '89.233.43.71': "Lazarus Group",
}

alert_history = {}
REPEATED_ALERT_TIMEOUT = timedelta(seconds=10)

# Level 2.3 / 2.4 — map content-hash or download path -> origin
origins = {}


def set_origin(data_hash, serveraddr, time, pid):
    origin = {
        'serveraddr': serveraddr,
        'download_time': time,
        'downloader_pid': pid,
        'downloader_process_name': get_process_name(pid),
        'downloader_program_path': get_program_path(pid),
    }
    origin['origin_str'] = (
        "\nDownloaded from {} at {} by program {} (PID {})"
        .format(
            origin['serveraddr'],
            datetime.fromtimestamp(origin['download_time']).strftime('%Y-%m-%d %H:%M:%S'),
            origin['downloader_process_name'],
            origin['downloader_pid'],
        )
    )
    origins[data_hash] = origin
    return origin


def lookup_origin(*keys):
    for key in keys:
        if key and key in origins:
            return origins[key]
    return None


class Prevention:
    def __init__(self):
        self.msg = ''

    def kill_process(self, pid):
        if not pid:
            return
        try:
            process = psutil.Process(pid)
            name = process.name()
            process.terminate()
            try:
                while process.status() == psutil.STATUS_RUNNING:
                    pass
            except psutil.NoSuchProcess:
                pass
            self.add_custom_msg('Killed process {} ({})'.format(name, process.pid))
        except Exception:
            logging.debug("Error terminating process {}: {}".format(
                pid, traceback.format_exc()))

    def delete_file(self, path):
        try:
            os.unlink(path)
            self.add_custom_msg('Deleted file {}'.format(path))
        except Exception:
            logging.debug("Error removing file {}: {}".format(
                path, traceback.format_exc()))

    def delete_user(self, username):
        # Level 3.2
        result = subprocess.run(
            ["net", "user", username, "/delete"],
            capture_output=True, text=True,
        )
        if "The command completed successfully" in result.stdout:
            self.add_custom_msg('Deleted user {}'.format(username))

    def add_custom_msg(self, msg):
        self.msg += '\n- {}'.format(msg)

    def __str__(self):
        return self.msg if self.msg else '\nNone'


def alert(event, title, detection, prevention):
    d = defaultdict(str)
    d.update(event)
    fmtr = Formatter()
    msg = "\n* Detection: {}\n{}\n\n* Prevention:".format(
        title, fmtr.vformat(detection, (), d))
    if (msg in alert_history) and (alert_history[msg] + REPEATED_ALERT_TIMEOUT > datetime.now()):
        return
    alert_history[msg] = datetime.now()
    msg += str(prevention)
    logging.warning(
        f"\n\n[======= {event['component']} alert ======]" + msg + '\n===============================\n'
    )


# ---------------------------------------------------------------------------
# FileMon events
# ---------------------------------------------------------------------------

def handle_exe_file(event):
    """Level 1.1 — known malware hash. Level 2.4 — also kill the curl downloader."""
    event['hash'] = hash_file(event['path'])
    if event['hash'] not in MALWARES_SHA1:
        return

    p = Prevention()
    event['malware_name'] = MALWARES_SHA1[event['hash']]

    origin = lookup_origin(event['path'], event['hash'])
    if origin:
        event.update(origin)
        p.kill_process(origin['downloader_pid'])

    p.delete_file(event['path'])
    alert(event,
          "Malicious file",
          "File ({path}) detected as {malware_name}; Hash: {hash}{origin_str}",
          p)


def find_malware_in_zip(zip_path):
    """Level 1.4 — first nested .exe whose SHA1 is known-bad."""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for file_name in zf.namelist():
            with zf.open(file_name) as f:
                file_content = f.read()
            if file_name.endswith(".exe"):
                file_hash = calculate_hash(file_content)
                if file_hash in MALWARES_SHA1:
                    return file_name, file_hash
    return None, None


def handle_zip_file(event):
    """Level 1.4 delete zip. Level 2.3 also kill HTTP downloader when origin is known."""
    zip_path = event['path']
    zip_hash = hash_file(zip_path)
    if not zip_hash:
        return

    file_name, file_hash = find_malware_in_zip(zip_path)
    if not file_name or not file_hash:
        return

    event['malware_name'] = MALWARES_SHA1[file_hash]
    event['name_in_zip'] = file_name
    event['hash'] = file_hash
    event['zip_path'] = zip_path
    event['ziphash'] = zip_hash

    p = Prevention()
    p.delete_file(zip_path)
    origin = lookup_origin(zip_hash)
    if origin:
        event.update(origin)
        p.kill_process(origin['downloader_pid'])
        alert(event,
              "Malicious ZIP download",
              "File {name_in_zip} (Hash: {hash}) in zip file {zip_path} (Hash: {ziphash}); detected as {malware_name}{origin_str}",
              p)
    else:
        alert(event,
              "Malicious file in ZIP",
              "File {name_in_zip} (Hash: {hash}) in zip file {zip_path} (Hash: {ziphash}); detected as {malware_name}",
              p)


def handle_camouflaged_exe(event):
    """Level 3.1 — PE file with a .jpg extension that came from the internet."""
    file_hash = hash_file(event['path'])
    origin = lookup_origin(file_hash, event['path'])
    if not origin:
        return

    p = Prevention()
    event.update(origin)
    p.kill_process(origin['downloader_pid'])
    p.delete_file(event['path'])
    alert(event,
          "Executable extension masquerading",
          "Executable file {path} camouflaged with extension {extension}{origin_str}",
          p)


# ---------------------------------------------------------------------------
# Firewall events
# ---------------------------------------------------------------------------

def handle_blocked_malicious_ip(event):
    """Level 1.2 block packet. Level 2.1 also kill the communicating process."""
    p = Prevention()
    p.add_custom_msg('Blocked')
    event['threat_actor'] = C2_IPS[event['addr']]

    if event.get('pid'):
        event['process_name'] = get_process_name(event['pid'])
        if not event['process_name']:
            return
        p.kill_process(event['pid'])
        alert(event,
              "Malicious network connection",
              "Program {process_name} ({pid}) - {direction} malicious communication with {addr} (Threat actor {threat_actor})",
              p)
    else:
        alert(event,
              "Malicious network connection",
              "{direction} malicious communication with {addr} (Threat actor {threat_actor})",
              p)


def handle_new_listener_detected(event, ask=input):
    """Level 1.5 — prompt before allowing a new TCP listener."""
    p = Prevention()
    event['listener_name'] = get_process_name(event['pid'])
    alert(event,
          "TCP listener",
          "Process {listener_name} (PID {pid}) started listening on port {port}",
          p)
    if ask('Allow? [y/n]\n> ') == 'n':
        p.kill_process(event['pid'])
        alert(event,
              "TCP listener refused",
              "Process {listener_name} (PID {pid}) refused to listen on port {port}",
              p)


def handle_http_download(event):
    """Level 2.2 detect in-memory malware. Level 2.3 always record origin by hash."""
    set_origin(event['hash'], event['serveraddr'], event['time'], event['pid'])
    if event['hash'] not in MALWARES_SHA1:
        return

    p = Prevention()
    event['malware_name'] = MALWARES_SHA1[event['hash']]
    event['process_name'] = get_process_name(event['pid'])
    p.kill_process(event['pid'])
    alert(event,
          "Malicious download",
          "{malware_name} (Hash {hash}) Downloaded from {serveraddr}:{port}; Downloaded by {process_name} ({pid})",
          p)


# ---------------------------------------------------------------------------
# ProcMon events
# ---------------------------------------------------------------------------

def handle_ransomware_behavior(event):
    """Level 1.3 — vssadmin delete shadows /all."""
    p = Prevention()
    event['ransomware_name'] = get_process_name(event['pid'])
    event['ransomware_pid'] = event['pid']
    p.kill_process(event['pid'])
    alert(event,
          "Ransomware behavior",
          "{ransomware_name} ({ransomware_pid}): {info}",
          p)


def handle_curl_download(event):
    """Level 2.4 — origin keyed by output path (HTTPS, so no DPI body hash)."""
    set_origin(event['download_path'], event['url'], event['time'], event['parent'])


def handle_user_added(event):
    """Level 3.2 — net user /add is malicious if an ancestor came from the internet."""
    proc_tree = [(event['pid'], event['process_name'])]
    process_id = event['parent']

    while process_id:
        name = get_process_name(process_id)
        path = get_program_path(process_id)
        file_hash = hash_file(path)
        if not file_hash:
            return

        proc_tree.append((process_id, name))
        origin = lookup_origin(file_hash)
        if origin:
            p = Prevention()
            event['malware_pid'] = process_id
            event['malware_path'] = path
            p.kill_process(process_id)
            p.delete_file(path)
            p.delete_user(event['username'])
            proc_tree.reverse()
            event['proc_tree_str'] = ''.join(
                ['\n{}{} ({})'.format(' ' * 4 * i, item[1], item[0])
                 for i, item in enumerate(proc_tree)]
            )
            alert(event,
                  "Backdoor Account Creation",
                  "Suspicious internet-origin program led to user creation ('{username}'): {malware_path} (PID {malware_pid})\n{proc_tree_str}\n",
                  p)
            return
        process_id = get_process_parent(process_id)


def handle_rundll32_exec(event):
    """Level 3.5 — parent downloaded the DLL then launched it with rundll32."""
    origin = lookup_origin(hash_file(event['path']))
    if not origin:
        return
    if origin['downloader_pid'] != event['parent']:
        return

    p = Prevention()
    event.update(origin)
    event['malware_path'] = get_program_path(event['parent'])
    p.kill_process(event['pid'])
    p.kill_process(event['parent'])
    p.delete_file(event['path'])
    alert(event,
          "Remote DLL loader",
          "{malware_path} (PID {parent}) downloaded and executed DLL {path}{origin_str}",
          p)


# ---------------------------------------------------------------------------
# WMIMon events
# ---------------------------------------------------------------------------

def handle_new_startup_command(event):
    """Level 3.3 — hidden executable registered as a startup command."""
    if not is_hidden(event['path']):
        return
    p = Prevention()
    p.delete_file(event['path'])
    alert(event,
          "Startup Command Persistence",
          "Suspicious new startup command with hidden executable {path}",
          p)


def handle_new_service(event):
    """Level 3.4 — new unsigned service image."""
    if is_signed(event['path']):
        return
    p = Prevention()
    p.delete_file(event['path'])
    alert(event,
          "Malicious Service Creation",
          "Suspicious new service - service {name} unsigned executable {path}",
          p)


event_handlers = {
    # Lab 1
    'exe_file': handle_exe_file,                          # 1.1
    'blocked_malicious_ip': handle_blocked_malicious_ip,  # 1.2 / 2.1
    'ransomware_behavior': handle_ransomware_behavior,    # 1.3
    'zip_file': handle_zip_file,                          # 1.4 / 2.3
    'new_listener_detected': handle_new_listener_detected,# 1.5
    # Lab 2
    'http_download': handle_http_download,                # 2.2 / 2.3
    'curl_download': handle_curl_download,                # 2.4
    # Lab 3
    'camouflaged_exe': handle_camouflaged_exe,            # 3.1
    'user_added': handle_user_added,                      # 3.2
    'new_startup_command': handle_new_startup_command,    # 3.3
    'new_service': handle_new_service,                    # 3.4
    'rundll32_exec': handle_rundll32_exec,                # 3.5
}


def main():
    logging.info("Starting components")
    event_queue = queue.Queue()
    FileMon(event_queue)
    Firewall(event_queue, C2_IPS.keys())
    ProcMon(event_queue)
    WMIMon(event_queue)

    logging.info("Monitoring started")
    while True:
        try:
            event = event_queue.get(timeout=1)
            try:
                event_handlers[event['kind']](event)
            except Exception:
                logging.error("Failed to handle event:\n{}".format(traceback.format_exc()))
        except queue.Empty:
            pass
        except KeyboardInterrupt:
            logging.error("Ctrl+C detected")
            break
        except Exception:
            logging.error("Unhandled exception in main: \n{}\n\n".format(traceback.format_exc()))
            break

    logging.info("Exiting...")
    os._exit(1)


if __name__ == '__main__':
    main()
