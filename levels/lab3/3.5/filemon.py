import logging
import traceback
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from common import *
import pefile

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, filemon):
        self._filemon = filemon
        self._locked = {}
        FileSystemEventHandler.__init__(self)

    def on_modified(self, event):
        try:
            self._filemon.on_modified(event)

        except Exception as e:
            logging.error("Error handling file modification event {}: {}".format(
                event.src_path, traceback.format_exc()))

class FileMon(Component):
    def __init__(self, event_queue):
        Component.__init__(self, event_queue, 'FileMon')

        self._observer = Observer()
        self._observer.schedule(FileEventHandler(self), 'C:\\', recursive=True)
        self._observer.start()

    def on_modified(self, event):
        if event.src_path.endswith('.exe'):
            self.send_event({"kind": "exe_file", "path": event.src_path})
        
        if event.src_path.endswith('.zip'):
            self.send_event({"kind": "zip_file", "path": event.src_path})
        
        if event.src_path.endswith('.jpg'):
            if self._is_executable(event.src_path):
                self._handle_camouflaged_exe(event)

    def _is_executable(self, path):
        try:
            # Try loading the file with pefile
            pe = pefile.PE(path)
            pe.close()
            return True
        except:
            # Not a valid Windows executable
            return False

    def _handle_camouflaged_exe(self, event):
        self.send_event({"kind": "camouflaged_exe",
                    "path": event.src_path,
                    "extension": os.path.splitext(event.src_path)[1]})
