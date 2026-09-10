import os
import logging
import traceback
import queue
from datetime import datetime, timedelta
from collections import defaultdict
from string import Formatter

from common import *
from filemon import FileMon
from firewall import Firewall

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

def alert(event, title, detection, prevention='None'):
    """
    We use 'event' as the keywords dict for the detection and prevention 
    strings formatting, e.g.:
    - detection = 'Detected file {path} as malware'
    - prevention = 'Deleted file {path}'
    - event = {'path': 'C:\\a.exe'}
    """
    d = defaultdict(str)
    d.update(event)

    fmtr = Formatter()

    msg = "\n* Detection: {}\n{}\n\n* Prevention:\n".format(title, fmtr.vformat(detection, (), d))
    if (msg in alert_history) and (alert_history[msg] + REPEATED_ALERT_TIMEOUT > datetime.now()):
        return

    alert_history[msg] = datetime.now()

    msg += fmtr.vformat(prevention, (), d)
    logging.warning(f"\n\n[======= {event['component']} alert ======]" + msg + '\n===============================\n')

def delete_file(path):
    try:
        os.unlink(path)
    except:
        logging.debug("Error removing file {}: {}".format(
            path, traceback.format_exc()))

# Filemon events

def handle_exe_file(event):
    event['hash'] = hash_file(event['path'])
    if event['hash'] in MALWARES_SHA1:
        event['malware_name'] = MALWARES_SHA1[event['hash']]
        delete_file(event['path'])

        alert(  event,
                "Malicious file",
                "File ({path}) detected as {malware_name}; Hash: {hash}",
                "- Deleted file {path}")

# Firewall events

def handle_blocked_malicious_ip(event):
    event['threat_actor'] = C2_IPS[event['addr']]
    
    alert(  event,
            "Malicious network connection",
            "{direction} malicious communication with {addr} (Threat actor {threat_actor})",
            "- Blocked")


# Main

event_handlers = {
    'exe_file': handle_exe_file,
    'blocked_malicious_ip': handle_blocked_malicious_ip
}

def main():
    logging.info("Starting components")
    event_queue = queue.Queue()
    components = [FileMon(event_queue), Firewall(event_queue, C2_IPS.keys())]

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
