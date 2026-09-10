"""WMI persistence monitor (Windows only).

Level 3.3  Win32_StartupCommand
Level 3.4  Win32_Service
"""
import logging
import os

from common import Component

try:
    import pythoncom
    import wmi
except ImportError:
    pythoncom = None
    wmi = None


class WMIMon(Component):
    def __init__(self, event_queue):
        self._stop = False
        threads = []
        if wmi is None or os.name != 'nt':
            logging.warning("WMI is Windows-only; persistence monitoring is disabled")
            Component.__init__(self, event_queue, 'WMIMon')
            return

        threads = [self._monitor_scheduled_jobs, self._monitor_services]
        Component.__init__(self, event_queue, 'WMIMon', threads)

    def _monitor_scheduled_jobs(self):
        pythoncom.CoInitialize()
        watcher = wmi.WMI().Win32_StartupCommand.watch_for("creation")
        while not self._stop:
            try:
                cmd = watcher(timeout_ms=1000)
            except wmi.x_wmi_timed_out:
                continue
            if cmd:
                self.send_event({
                    "kind": "new_startup_command",
                    "path": cmd.Command,
                })
        pythoncom.CoUninitialize()

    def _monitor_services(self):
        pythoncom.CoInitialize()
        watcher = wmi.WMI().Win32_Service.watch_for("creation")
        while not self._stop:
            try:
                service = watcher(timeout_ms=1000)
            except wmi.x_wmi_timed_out:
                continue
            if service:
                self.send_event({
                    "kind": "new_service",
                    "name": service.Name,
                    "path": service.PathName,
                })
        pythoncom.CoUninitialize()

    def shutdown(self):
        self._stop = True
        for t in self._threads:
            t.join(timeout=2)
