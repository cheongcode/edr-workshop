import hashlib
import psutil
import time
import logging
import traceback
import threading

# General

class Component:
    def __init__(self, event_queue, name, threads=None):
        self._event_queue = event_queue
        self._name = name
        self._cache = []

        if threads == None:
            return

        self._threads = [threading.Thread(target=t) for t in threads]
        for t in self._threads:
            t.start()

    def send_event(self, info):
        info['time'] = time.time()
        info['component'] = self._name
        self._event_queue.put(info)

def calculate_hash(data):
    return hashlib.sha1(data).hexdigest()

# File

def hash_file(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        return calculate_hash(data)
    except:
        return None

# Process

def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except Exception as e:
        logging.debug("Error getting name of process {}: {}".format(
            pid, traceback.format_exc()))
        return ''

def get_program_path(pid):
    try:
        process = psutil.Process(pid)
        return process.exe()
    except Exception as e:
        logging.error("Error getting path of process {}: {}".format(
            pid, traceback.format_exc()))
        return ''

def get_process_parent(pid):
    try:
        process = psutil.Process(pid)
        return process.ppid()
    except Exception as e:
        logging.debug("Error getting parent of process {}: {}".format(
            pid, traceback.format_exc()))
        return None

# Network

def find_pid_by_lport(lport):
    """Find the process using a specific port."""
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == lport:
            return conn.pid
    return None
