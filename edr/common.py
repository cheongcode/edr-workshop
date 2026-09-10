"""Shared EDR helpers (hashing, process lookup, Windows attribute checks)."""
import hashlib
import logging
import os
import subprocess
import threading
import time
import traceback

import psutil


class Component:
    def __init__(self, event_queue, name, threads=None):
        self._event_queue = event_queue
        self._name = name
        self._cache = []
        self._threads = []

        if threads is None:
            return

        self._threads = [threading.Thread(target=t, daemon=True) for t in threads]
        for t in self._threads:
            t.start()

    def send_event(self, info):
        info['time'] = time.time()
        info['component'] = self._name
        self._event_queue.put(info)

    def shutdown(self):
        pass


def calculate_hash(data):
    return hashlib.sha1(data).hexdigest()


def hash_file(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        return calculate_hash(data)
    except Exception:
        return None


# Level 3.3 — hidden-file check for startup persistence
def is_hidden(file_path):
    if os.name != 'nt':
        return False
    command = "powershell -Command \"(Get-Item '{}' -Force).Attributes -match 'Hidden'\"".format(file_path)
    result = subprocess.run(command, capture_output=True, shell=True, text=True)
    return 'True' in result.stdout


# Level 3.4 — Authenticode check for new services
def is_signed(path):
    if os.name != 'nt':
        return False
    command = "powershell -Command \"(Get-AuthenticodeSignature '{}').Status\"".format(path)
    result = subprocess.run(command, capture_output=True, shell=True, text=True)
    return 'Valid' in result.stdout


def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except Exception:
        logging.debug("Error getting name of process {}: {}".format(
            pid, traceback.format_exc()))
        return ''


def get_program_path(pid):
    try:
        process = psutil.Process(pid)
        return process.exe()
    except Exception:
        logging.debug("Error getting path of process {}: {}".format(
            pid, traceback.format_exc()))
        return ''


# Level 3.2 — walk ancestors of net.exe /add
def get_process_parent(pid):
    try:
        process = psutil.Process(pid)
        return process.ppid()
    except Exception:
        logging.debug("Error getting parent of process {}: {}".format(
            pid, traceback.format_exc()))
        return None


# Level 2.1 — map a local TCP port back to a PID
def find_pid_by_lport(lport):
    """Find the process using a specific local port."""
    try:
        connections = psutil.net_connections(kind='inet')
    except (psutil.AccessDenied, PermissionError):
        connections = []
        for proc in psutil.process_iter(['pid']):
            try:
                connections.extend(proc.net_connections(kind='inet'))
            except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
                continue

    for conn in connections:
        if conn.laddr and conn.laddr.port == lport:
            return conn.pid
    return None
