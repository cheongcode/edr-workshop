import logging
import wmi
import pythoncom
from common import Component

class WMIMon(Component):
    def __init__(self, event_queue):
        self._stop = False
        Component.__init__(self, event_queue, 'WMIMon', [self._monitor_scheduled_jobs,
                                                         self._monitor_services])

    def _monitor_scheduled_jobs(self):
        pythoncom.CoInitialize()  # Initialize COM
        watcher = wmi.WMI().Win32_StartupCommand.watch_for("creation")

        while not self._stop:
            try:
                cmd = watcher(timeout_ms=1000)
            except wmi.x_wmi_timed_out:
                continue

            if cmd:
                self.send_event({"kind": "new_startup_command",
                            "path": cmd.Command})
        
        pythoncom.CoUninitialize();

    def _monitor_services(self):
        pythoncom.CoInitialize()  # Initialize COM
        watcher = wmi.WMI().Win32_Service.watch_for("creation")
        while not self._stop:
            try:
                service  = watcher(timeout_ms=1000)
            except wmi.x_wmi_timed_out:
                continue

            if service:
                self.send_event({"kind": "new_service",
                            "name": service.Name,
                            "path": service.PathName
                            })

        pythoncom.CoUninitialize();

    def shutdown(self):
        self._stop = True
        for t in self._threads:
            t.join()
