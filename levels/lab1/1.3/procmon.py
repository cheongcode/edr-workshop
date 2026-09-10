from common import Component
from procnotifier import watch_new_processes

class ProcMon(Component):
    def __init__(self, event_queue):
        Component.__init__(self, event_queue, 'ProcMon')
        watch_new_processes(self._handle_new_process)

    def _handle_new_process(self, event):
        if 'vssadmin' in event['path'] and 'delete shadows /all' in event['args'].lower():
            self.send_event({"kind": "ransomware_behavior", "info": "Shadow copy deletion",
                        "pid": event['ppid']})
