"""File-system monitor.

Level 1.1  .exe hash
Level 1.4  .zip nested malware
Level 3.1  PE camouflaged as .jpg
"""
import logging
import os
import traceback

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from common import *

try:
    import pefile
except ImportError:
    pefile = None


class FileEventHandler(FileSystemEventHandler):
    def __init__(self, filemon):
        self._filemon = filemon
        self._locked = {}
        FileSystemEventHandler.__init__(self)

    def on_created(self, event):
        self.on_modified(event)

    def on_modified(self, event):
        try:
            self._filemon.on_modified(event)
        except Exception:
            logging.error("Error handling file modification event {}: {}".format(
                event.src_path, traceback.format_exc()))


class FileMon(Component):
    def __init__(self, event_queue, watch_path=None):
        Component.__init__(self, event_queue, 'FileMon')

        if watch_path is None:
            if os.name == 'nt':
                watch_path = 'C:\\'
            else:
                watch_path = os.environ.get(
                    'EDR_WATCH_PATH',
                    os.path.expanduser('~/Downloads'),
                )

        self._observer = Observer()
        self._observer.schedule(FileEventHandler(self), watch_path, recursive=True)
        self._observer.start()
        logging.info("FileMon watching %s", watch_path)

    def on_modified(self, event):
        path = event.src_path
        lower = path.lower()

        # Level 1.1
        if lower.endswith('.exe'):
            self.send_event({"kind": "exe_file", "path": path})

        # Level 1.4
        if lower.endswith('.zip'):
            self.send_event({"kind": "zip_file", "path": path})

        # Level 3.1 — PE content with a .jpg extension
        if lower.endswith('.jpg') and self._is_executable(path):
            self._handle_camouflaged_exe(event)

    def _is_executable(self, path):
        if pefile is None:
            return False
        try:
            pe = pefile.PE(path)
            pe.close()
            return True
        except Exception:
            return False

    def _handle_camouflaged_exe(self, event):
        self.send_event({
            "kind": "camouflaged_exe",
            "path": event.src_path,
            "extension": os.path.splitext(event.src_path)[1],
        })
