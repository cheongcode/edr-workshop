import os
import logging
import traceback
import queue
import subprocess
import psutil
import zipfile
from datetime import datetime, timedelta
from collections import defaultdict
from string import Formatter

from common import *
from filemon import FileMon
from firewall import Firewall
from procmon import ProcMon

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Threat intelligence and definitions
MALWARES_SHA1 = {
    "f5524f0acd2dbb535c800a33cf207e4bfd4f5297": "Emotet",
    "4a100aca2953b51b7856a5029e4667d6ebabe2f4": "Zeus"
}

C2_IPS = {
    '89.233.43.71': "Lazarus Group"
}

# Alert messages
alert_history = {}
REPEATED_ALERT_TIMEOUT = timedelta(seconds=10)

class Prevention():
    def __init__(self):
        self.msg = ''

    def kill_process(self, pid):
        if not pid:
            return

        try:
            process = psutil.Process(pid)
            name = process.name()
            process.terminate()

            # Wait for process to terminate
            try:
                while process.status() == psutil.STATUS_RUNNING:
                    pass
            except psutil.NoSuchProcess:
                pass

            self.add_custom_msg('Killed process {} ({})'.format(name, process.pid))
        except:
            logging.debug("Error terminating process {}: {}".format(
                pid, traceback.format_exc()))

    def delete_file(self, path):
        try:
            os.unlink(path)
            self.add_custom_msg('Deleted file {}'.format(path))
        except:
            logging.debug("Error removing file {}: {}".format(
                path, traceback.format_exc()))

    def add_custom_msg(self, msg):
        self.msg += '\n- {}'.format(msg)

    def __str__(self):
        if self.msg:
            return self.msg
        else:
            return '\nNone'


def alert(event, title, detection, prevention):
    """
    We use 'event' as the keywords dict for the detection and prevention 
    strings formatting, e.g.:
    - detection = 'Detected file {path} as malware'
    - event = {'path': 'C:\\a.exe'}
    """
    d = defaultdict(str)
    d.update(event)

    fmtr = Formatter()

    msg = "\n* Detection: {}\n{}\n\n* Prevention:".format(title, fmtr.vformat(detection, (), d))
    if (msg in alert_history) and (alert_history[msg] + REPEATED_ALERT_TIMEOUT > datetime.now()):
        return

    alert_history[msg] = datetime.now()

    msg += str(prevention)
    logging.warning(f"\n\n[======= {event['component']} alert ======]" + msg + '\n===============================\n')

# Filemon events

def handle_exe_file(event):
    event['hash'] = hash_file(event['path'])
    if event['hash'] in MALWARES_SHA1:
        p = Prevention()
        event['malware_name'] = MALWARES_SHA1[event['hash']]
        p.delete_file(event['path'])

        alert(  event,
                "Malicious file",
                "File ({path}) detected as {malware_name}; Hash: {hash}",
                p)

def _find_malware_in_zip(zip_path):
    zf = zipfile.ZipFile(zip_path, 'r')
    for file_name in zf.namelist():
        # Read the file content into memory
        with zf.open(file_name) as f:
            file_content = f.read()
            if file_name.endswith(".exe"):
                file_hash = calculate_hash(file_content)
                if file_hash in MALWARES_SHA1:
                    return file_name, file_hash
    
    return None, None

def handle_zip_file(event):
    zip_path = event['path']
    zip_hash = hash_file(zip_path)
    if not zip_hash:
        return

    file_name, file_hash = _find_malware_in_zip(zip_path)
    if not file_name or not file_hash:
        return

    event['malware_name'] = MALWARES_SHA1[file_hash]
    event['name_in_zip'] = file_name
    event['hash'] = file_hash
    event['zip_path'] = zip_path
    event['ziphash'] = zip_hash

    p = Prevention()
    p.delete_file(zip_path)
    alert(  event,
            "Malicious file in ZIP",
            "File {name_in_zip} (Hash: {hash}) in zip file {zip_path} (Hash: {ziphash}); detected as {malware_name}",
            p)


# Firewall events

def handle_blocked_malicious_ip(event):
    p = Prevention()
    p.add_custom_msg('Blocked')
    event['threat_actor'] = C2_IPS[event['addr']]
    
    if event['pid']:
        event['process_name'] = get_process_name(event['pid'])
        if not event['process_name']:
            # Duplicate event - process already terminated
            return

        p.kill_process(event['pid'])
        alert(  event,
                "Malicious network connection",
                "Program {process_name} ({pid}) - {direction} malicious communication with {addr} (Threat actor {threat_actor})",
                p)
    else:
        alert(  event,
                "Malicious network connection",
                "{direction} malicious communication with {addr} (Threat actor {threat_actor})",
                p)

def handle_new_listener_detected(event):
    p = Prevention()
    event['listener_name'] = get_process_name(event['pid'])

    alert(  event,
            "TCP listener",
            "Process {listener_name} (PID {pid}) started listening on port {port}",
            p)

    if input('Allow? [y/n]\n> ') == 'n':
        p.kill_process(event['pid'])
        alert(  event,
                "TCP listener refused",
                "Process {listener_name} (PID {pid}) refused to listen on port {port}",
                p)

# ProcMon events

def handle_ransomware_behavior(event):
    p = Prevention()
    event['ransomware_name'] = get_process_name(event['pid'])
    event['ransomware_pid'] = event['pid']
    
    p.kill_process(event['pid'])

    alert(  event,
            "Ransomware behavior",
            "{ransomware_name} ({ransomware_pid}): {info}",
            p)

# Main

event_handlers = {
    'exe_file': handle_exe_file,
    'blocked_malicious_ip': handle_blocked_malicious_ip,
    'ransomware_behavior': handle_ransomware_behavior,
    'zip_file': handle_zip_file,
    'new_listener_detected': handle_new_listener_detected
}

def main():
    logging.info("Starting components")
    event_queue = queue.Queue()
    components = [FileMon(event_queue), Firewall(event_queue, C2_IPS.keys()), ProcMon(event_queue)]

    logging.info("Monitoring started")
    while True:
        try:
            event = event_queue.get(timeout=1)  # Wait for an item from the queue
            try:
                event_handlers[event['kind']](event) # Handle it
            except:
                logging.error("Failed to handle event:\n{}".format(traceback.format_exc()))
            
        except queue.Empty:
            pass

        except KeyboardInterrupt:
            logging.error("Ctrl+C detected")
            break

        except:
            logging.error("Unhandled exception in main: \n{}\n\n".format(traceback.format_exc()))
            break
            
    logging.info("Exiting...")
    os._exit(1)

if __name__ == '__main__':
    main()
