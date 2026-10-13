# Copyright 2026 Yextep. See LICENSE and NOTICE for the applicable terms.
import base64
import concurrent.futures
import contextlib
import http.server
import io
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.parse
import urllib.request

import union_lan as lan

def fixture_key(seed):
    # Datos sinteticos de prueba: no identifican ningun dispositivo real.
    raw = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + lan.hashlib.sha256(seed.encode()).digest()
    return 'ssh-ed25519 ' + base64.b64encode(raw).decode()


DEVICE_KEY = fixture_key('union-lan-test-device')
OTHER_KEY = fixture_key('union-lan-test-other')


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.manager = lan.Manager(self.directory.name)
        self.node = lan.validate_node('telefono', '192.168.1.5', 'u0_a123', DEVICE_KEY)
        self.manager.save({'nodos': {'telefono': self.node}, 'redes': ['192.168.1.0/29']})

    def test_reassigned_ip_does_not_impersonate_registered_device(self):
        def available(ip, port, **kwargs):
            return {'192.168.1.5': OTHER_KEY, '192.168.1.6': DEVICE_KEY}.get(ip)
        with patch.object(lan, 'probe', side_effect=available), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.manager.resolve('telefono'), ('192.168.1.6', 8022))
        stored = self.manager.load()['nodos']['telefono']
        self.assertEqual(stored['ip'], '192.168.1.6')
        self.assertEqual(stored['clave'], DEVICE_KEY)

    def test_known_address_tolerates_lan_latency_without_rescanning(self):
        def delayed_connect(address, timeout):
            if timeout < 1:
                raise TimeoutError('Respuesta de la LAN demorada por carga')
            return contextlib.nullcontext()
        result = type('Result', (), {'stdout': '[192.168.1.5]:8022 ' + DEVICE_KEY + '\n'})()
        with patch.object(lan.socket, 'create_connection', side_effect=delayed_connect), \
             patch.object(lan.subprocess, 'run', return_value=result), \
             patch.object(self.manager, 'networks', side_effect=AssertionError('No debe barrer la LAN')):
            self.assertEqual(self.manager.resolve('telefono'), ('192.168.1.5', 8022))

    def test_unknown_host_key_is_never_adopted(self):
        with patch.object(lan, 'probe', return_value=OTHER_KEY), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'No se encontro'):
                self.manager.resolve('telefono')
        self.assertEqual(self.manager.load()['nodos']['telefono'], self.node)

    def test_search_scope_is_bounded(self):
        with self.assertRaisesRegex(ValueError, '1024'):
            self.manager.networks({'redes': ['192.168.0.0/16']}, self.node)

    def test_internet_and_overlay_addresses_are_outside_lan_scope(self):
        for ip in ('8.8.8.8', '100.100.1.1', '0.0.0.0', '192.0.2.1'):
            with self.assertRaisesRegex(ValueError, 'red local'):
                lan.validate_node('telefono', ip, 'u0_a123', DEVICE_KEY)

    def test_discovery_does_not_scan_public_networks(self):
        with self.assertRaisesRegex(ValueError, 'locales'):
            self.manager.networks({'redes': ['8.8.8.0/24']}, self.node)

    def test_existing_alias_cannot_silently_change_identity(self):
        replacement = dict(self.node, clave=OTHER_KEY)
        with patch.object(self.manager, 'check_access'):
            with self.assertRaisesRegex(ValueError, 'otro dispositivo'):
                self.manager.register('telefono', replacement)
        self.assertEqual(self.manager.load()['nodos']['telefono'], self.node)

    def test_shell_syntax_is_not_accepted_as_device_name_or_username(self):
        for alias, user in [('movil;id', 'u0_a123'), ('movil', 'u0_a123$(id)')]:
            with self.assertRaises(ValueError):
                lan.validate_node(alias, '192.168.1.5', user, DEVICE_KEY)


class InvitationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.manager = lan.Manager(self.directory.name)
        self.manager.prepare_identity = Mock(return_value=OTHER_KEY)
        self.manager.register = Mock()
        self.invitation = lan.Invitation(self.manager, 'movil3', 'http://127.0.0.1:8765')
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), lan.handler_for(self.invitation))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)

    def stop_server(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def post(self, token):
        body = urllib.parse.urlencode({'token': token, 'usuario': 'u0_a123', 'clave': DEVICE_KEY}).encode()
        try:
            with urllib.request.urlopen(self.url + '/incorporar', data=body, timeout=5) as reply:
                return reply.status, reply.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_incorrect_and_non_ascii_tokens_do_not_register(self):
        for token in ('incorrecto', 'invitacion-ñ'):
            self.assertEqual(self.post(token)[0], 403)
        self.manager.register.assert_not_called()

    def test_expired_invitation_cannot_register(self):
        self.invitation.expires = 0
        self.assertEqual(self.post(self.invitation.token)[0], 403)
        self.manager.register.assert_not_called()

    def test_invitation_is_single_use_even_for_concurrent_requests(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool, contextlib.redirect_stdout(io.StringIO()):
            responses = list(pool.map(self.post, [self.invitation.token] * 2))
        self.assertEqual(sorted(code for code, _ in responses), [200, 403])
        self.manager.register.assert_called_once()
        registered = self.manager.register.call_args.args[1]
        self.assertEqual(registered['ip'], '127.0.0.1')
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(self.url + '/instalar/' + self.invitation.token, timeout=5)
        self.assertEqual(error.exception.code, 403)

    def test_failed_ssh_validation_leaves_invitation_available_to_retry(self):
        self.manager.register.side_effect = ValueError('SSH no autentico')
        self.assertEqual(self.post(self.invitation.token)[0], 400)
        self.assertFalse(self.invitation.used)

    def test_installer_integrity_digest_matches_download(self):
        with urllib.request.urlopen(self.url + '/instalar/' + self.invitation.token, timeout=5) as reply:
            script = reply.read()
        self.assertIn(lan.hashlib.sha256(script).hexdigest(), self.invitation.command())
        self.assertNotIn(b'PRIVATE KEY', script)
        self.assertIn(b'Required Notice: Copyright 2026 Yextep', script)
        self.assertIn(b'Commons Clause', script)
        subprocess.run(['bash', '-n'], input=script, check=True)

    def test_repeating_installer_preserves_keys_and_adds_startup_only_once(self):
        phone = Path(self.directory.name) / 'phone'
        prefix = phone / 'usr'
        binaries = prefix / 'bin'
        binaries.mkdir(parents=True)
        (binaries / 'sh').symlink_to('/bin/sh')
        ssh = prefix / 'etc/ssh'
        ssh.mkdir(parents=True)
        (ssh / 'ssh_host_ed25519_key.pub').write_text(DEVICE_KEY + '\n')
        stubs = {'id': 'printf "20347\\n"', 'whoami': 'printf "u0_a123\\n"',
                 'pkg': 'exit 0', 'sshd': 'exit 0', 'ssh-keygen': 'exit 0',
                 'curl': 'printf "Incorporado\\n"'}
        for name, body in stubs.items():
            executable = binaries / name
            executable.write_text('#!/bin/sh\n' + body + '\n')
            executable.chmod(0o700)
        authorized = phone / '.ssh/authorized_keys'
        authorized.parent.mkdir()
        authorized.write_text(DEVICE_KEY + '\n')
        # Sustituir referencias al home solo en la copia de prueba, sin cambiar HOME.
        script = self.invitation.script.decode().replace('$HOME', str(phone))
        env = dict(os.environ, PREFIX=str(prefix), PATH=str(binaries) + ':' + os.environ['PATH'])
        for _ in range(2):
            result = subprocess.run(['bash'], input=script, text=True, env=env, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        lines = authorized.read_text().splitlines()
        self.assertEqual(lines.count(DEVICE_KEY), 1)
        self.assertEqual(lines.count(OTHER_KEY), 1)
        self.assertEqual((phone / '.bashrc').read_text().count('# union-lan: iniciar SSH'), 1)
        self.assertEqual((phone / '.termux/boot/90-union-lan').stat().st_mode & 0o777, 0o700)

        # Una clave existente con comentario tiene la misma identidad y no se duplica.
        authorized.write_text(DEVICE_KEY + '\n' + OTHER_KEY + ' nombre-original\n')
        result = subprocess.run(['bash'], input=script, text=True, env=env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(authorized.read_text(), DEVICE_KEY + '\n' + OTHER_KEY + ' nombre-original\n')


if __name__ == '__main__':
    unittest.main()
