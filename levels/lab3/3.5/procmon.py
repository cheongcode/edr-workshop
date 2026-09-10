from common import Component
from procnotifier import watch_new_processes
import os
import re
import logging

class ProcMon(Component):
    def __init__(self, event_queue):
        Component.__init__(self, event_queue, 'ProcMon')
        watch_new_processes(self._handle_new_process)

    def _handle_new_process(self, event):
        if 'vssadmin' in event['path'] and 'delete shadows /all' in event['args'].lower():
            self.send_event({"kind": "ransomware_behavior", "info": "Shadow copy deletion",
                        "pid": event['ppid']})

        if os.path.basename(event['path']) == 'curl.exe':
            args = event['args'].split()
            url = args[args.index('-k') + 1]
            path = args[args.index('-o') + 1]
            self.send_event({"kind": "curl_download", "url": url, "download_path": path,
                        "pid": event['pid'], "parent": event['ppid']})

        if os.path.basename(event['path']) == 'net.exe' and event['args'].strip().startswith("user ") and ' /add' in event['args']:
            args = event['args'].split()
            username = None
            for arg in args:
                if arg != 'user' and arg != '/add':
                    username = arg
                    break

            self.send_event({"kind": "user_added", "username": username, 
                        "pid": event['pid'], "process_name": "net.exe", "parent": event['ppid']})

        if os.path.basename(event['path']) == 'rundll32.exe':
            dll_path = None
            for a in event['args'].split():
                m = re.match(r'(.*\.dll)?', a)
                if m[0]:
                    dll_path = m[0]
            
            if dll_path:
                self.send_event({"kind": "rundll32_exec", "path": dll_path, 
                            "pid": event['pid'], "parent": event['ppid']})

