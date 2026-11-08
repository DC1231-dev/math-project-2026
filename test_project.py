"""이 폴더에서 python3 -m unittest -v test_project로 전체 검증을 실행한다."""
import base64
import json
import logging
import math
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest

from Crypto.Cipher import AES

import alice
import bob
import crypto_math as cm
from attacker import attack
from wire import JSONConnection, MAX_MESSAGE, ProtocolError


class PairTest(unittest.TestCase):
    def pair(self, client, server):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        results, errors = [], []

        def serve():
            try:
                results.append(server(b))
            except Exception as exc:
                errors.append(exc)
            finally:
                b.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            result = client(a)
        finally:
            a.close()
            worker.join(3)
        self.assertFalse(worker.is_alive(), 'peer did not finish')
        if errors:
            raise errors[0]
        return result, results


class MathTests(unittest.TestCase):
    def test_primes_and_generators_against_exhaustive_reference(self):
        for p in range(400, 501):
            prime = all(p % d for d in range(2, p))
            self.assertEqual(cm.is_prime(p), prime)
            if prime:
                for g in range(1, p):
                    residues = {pow(g, k, p) for k in range(1, p)}
                    self.assertEqual(cm.is_generator(g, p), len(residues) == p - 1)
        for bad in [-1, 0, 1, True, '461']:
            self.assertFalse(cm.is_prime(bad))
        self.assertFalse(cm.is_generator(2, 403))

    def test_rsa_all_prime_pairs_and_all_bytes(self):
        primes = [p for p in range(400, 501) if cm.is_prime(p)]
        for index, p in enumerate(primes):
            for q in primes[index+1:]:
                phi = (p-1)*(q-1)
                e = 65537
                d = cm.inverse(e, phi)
                self.assertTrue(cm.verify_rsa(p, q, e, d))
                for value in range(256):
                    self.assertEqual(pow(pow(value, e, p*q), d, p*q), value)
        rsa = cm.generate_rsa()
        key = bytes(range(32))
        self.assertEqual(cm.rsa_decrypt_key(cm.rsa_encrypt_key(key, rsa.e, rsa.n), rsa.d, rsa.n), key)
        self.assertFalse(cm.verify_rsa(rsa.p, rsa.q, rsa.e, rsa.d + 1))
        for bad in [[], [True]*32, [-1]*32, [rsa.n]*32]:
            with self.assertRaises(ValueError):
                cm.rsa_decrypt_key(bad, rsa.d, rsa.n)
        with self.assertRaises(ValueError):
            cm.inverse(2, 4)

    def test_dh_agreement_and_key_derivation(self):
        for p in [401, 461, 499]:
            g = cm.generate_generator(p)
            a, A = cm.dh_keypair(p, g)
            b, B = cm.dh_keypair(p, g)
            self.assertEqual(cm.dh_shared(B, a, p), cm.dh_shared(A, b, p))
        self.assertEqual(cm.dh_aes_key(258), b'\x01\x02' * 16)
        for public in [0, 461, True]:
            with self.assertRaises(ValueError):
                cm.dh_shared(public, 5, 461)


class AESTests(unittest.TestCase):
    def test_boundaries_and_utf8(self):
        key = bytes(range(32))
        for text in ['', 'a', 'a'*15, 'a'*16, '안녕하세요', '한글abc']:
            self.assertEqual(cm.decrypt_message(key, cm.encrypt_message(key, text)), text)
        self.assertEqual(len(base64.b64decode(cm.encrypt_message(key, 'a'*16))), 32)
        for text in ['a'*17, '한'*6]:
            with self.assertRaises(ValueError):
                cm.encrypt_message(key, text)

    def test_professor_style_unpadded_16_chars(self):
        # aes_bob.py 방식: pad = 16 - len(msg) 이므로 16글자면 패딩 없음
        key = bytes(32)
        msg = 'Hello, Bob! 1234'
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(msg.encode())
        self.assertEqual(cm.decrypt_message(key, base64.b64encode(encrypted).decode()), msg)

class WireTests(PairTest):
    def test_fragmented_utf8_and_concatenated_objects(self):
        raw = '{"text":"한글"}{"number":2}'.encode()

        def server(sock):
            for byte in raw:
                sock.sendall(bytes([byte]))

        def client(sock):
            wire = JSONConnection(sock)
            return wire.receive(), wire.receive()

        result, _ = self.pair(client, server)
        self.assertEqual(result, ({'text': '한글'}, {'number': 2}))

    def test_closed_malformed_and_oversized(self):
        for payload in [b'{', b'[]', b'{"x":', b'\xff', b' '* (MAX_MESSAGE+1), b'{"x":"' + b'x'*MAX_MESSAGE + b'"}']:
            with self.subTest(payload=payload[:15]):
                a, b = socket.socketpair()
                with a, b:
                    worker = threading.Thread(target=lambda: self.send_close(b, payload), daemon=True)
                    worker.start()
                    with self.assertRaises(ProtocolError):
                        JSONConnection(a).receive()
                    a.close()
                    worker.join(1)

    @staticmethod
    def send_close(sock, payload):
        try:
            sock.sendall(payload)
        except OSError:
            pass
        finally:
            sock.close()

    def test_timeout(self):
        a, b = socket.socketpair()
        with a, b:
            start = time.monotonic()
            with self.assertRaises(TimeoutError):
                JSONConnection(a, timeout=0.05).receive()
            self.assertLess(time.monotonic()-start, 1)


class ProtocolTests(PairTest):
    def test_all_normal_protocols(self):
        for protocol in ['RSAKey', 'RSA', 'DH']:
            with self.subTest(protocol=protocol):
                result, server = self.pair(
                    lambda s: alice.exchange(JSONConnection(s), protocol, 'Alice 한글'),
                    lambda s: bob.exchange(JSONConnection(s), 'Bob message'))
                if protocol == 'RSAKey':
                    self.assertTrue(result['correct'])
                else:
                    self.assertEqual(result, 'Bob message')
                    self.assertEqual(server, ['Alice 한글'])

    def test_both_dh_errors(self):
        for mode, expected in [('prime', 'incorrect prime number'), ('generator', 'incorrect generator')]:
            def server(sock):
                with self.assertRaisesRegex(ProtocolError, expected):
                    bob.exchange(JSONConnection(sock), 'Bob', mode)
            def client(sock):
                with self.assertRaisesRegex(ProtocolError, expected):
                    alice.exchange(JSONConnection(sock), 'DH', 'Alice')
            self.pair(client, server)

    def test_prime_error_precedes_generator_error(self):
        def server(sock):
            w = JSONConnection(sock)
            w.receive()
            w.send({'opcode': 1, 'type': 'DH', 'public': 1, 'parameter': {'p': 403, 'g': 1}})
            self.assertEqual(w.receive(), {'opcode': 3, 'error': 'incorrect prime number'})
        def client(sock):
            with self.assertRaisesRegex(ProtocolError, 'incorrect prime number'):
                alice.exchange(JSONConnection(sock), 'DH', 'Alice')
        self.pair(client, server)

    def test_invalid_rsa_keypair(self):
        def server(sock):
            w = JSONConnection(sock)
            w.receive()
            w.send({'opcode': 0, 'type': 'RSAKey', 'public': 3, 'private': 7,
                    'parameter': {'p': 403, 'q': 499}})
        def client(sock):
            with self.assertRaisesRegex(ProtocolError, 'incorrect RSA keypair'):
                alice.exchange(JSONConnection(sock), 'RSAKey')
        self.pair(client, server)


# 같은 구현끼리만 맞는 오류를 피하려고 독립 상대는 통신·수학 공통 모듈을 쓰지 않는다.
def ref_receive(sock, state):
    decoder = json.JSONDecoder()
    while True:
        try:
            obj, end = decoder.raw_decode(state[0].lstrip())
            state[0] = state[0].lstrip()[end:]
            return obj
        except json.JSONDecodeError:
            chunk = sock.recv(2048)
            if not chunk:
                raise ValueError('reference peer got EOF')
            state[0] += chunk.decode('ascii')


def ref_send(sock, obj):
    sock.sendall(json.dumps(obj).encode('ascii'))


def ref_encrypt(key, text):
    data = text.encode()
    count = 16 - len(data) % 16
    return base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(data + bytes([count])*count)).decode()


def ref_decrypt(key, text):
    data = AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(text))
    return data[:-data[-1]].decode()


class IndependentPeerTests(PairTest):
    def test_alice_against_reference_bob(self):
        for protocol in ['RSAKey', 'RSA', 'DH']:
            def server(sock):
                sock.settimeout(2)
                state = ['']
                request = ref_receive(sock, state)
                self.assertEqual(request, {'opcode': 0, 'type': protocol})
                p, q, e = 499, 487, 65537
                d = pow(e, -1, (p-1)*(q-1))
                if protocol == 'RSAKey':
                    ref_send(sock, {'opcode': 0, 'type': protocol, 'public': e, 'private': d,
                                    'parameter': {'p': p, 'q': q}})
                    return
                if protocol == 'RSA':
                    ref_send(sock, {'opcode': 1, 'type': protocol, 'public': e, 'parameter': {'n': p*q}})
                    reply = ref_receive(sock, state)
                    key = bytes(pow(x, d, p*q) for x in reply['encrypted_key'])
                else:
                    p, g, b = 461, 314, 17
                    ref_send(sock, {'opcode': 1, 'type': protocol, 'public': pow(g, b, p), 'parameter': {'p': p, 'g': g}})
                    reply = ref_receive(sock, state)
                    key = pow(reply['public'], b, p).to_bytes(2, 'big') * 16
                ref_send(sock, {'opcode': 2, 'type': 'AES', 'encryption': ref_encrypt(key, 'B'*16)})
                reply = ref_receive(sock, state)
                self.assertEqual(ref_decrypt(key, reply['encryption']), '안녕')
            result, _ = self.pair(lambda s: alice.exchange(JSONConnection(s), protocol, '안녕'), server)
            if protocol != 'RSAKey':
                self.assertEqual(result, 'B'*16)

    def test_bob_against_reference_alice(self):
        for protocol in ['RSAKey', 'RSA', 'DH']:
            def client(sock):
                sock.settimeout(2)
                state = ['']
                ref_send(sock, {'opcode': 0, 'type': protocol})
                reply = ref_receive(sock, state)
                if protocol == 'RSAKey':
                    p, q = reply['parameter']['p'], reply['parameter']['q']
                    self.assertEqual(reply['public']*reply['private'] % ((p-1)*(q-1)), 1)
                    return
                if protocol == 'RSA':
                    key = bytes(range(32))
                    n, e = reply['parameter']['n'], reply['public']
                    ref_send(sock, {'opcode': 2, 'type': 'RSA', 'encrypted_key': [pow(x, e, n) for x in key]})
                else:
                    p, g, a = reply['parameter']['p'], reply['parameter']['g'], 19
                    ref_send(sock, {'opcode': 1, 'type': 'DH', 'public': pow(g, a, p)})
                    key = pow(reply['public'], a, p).to_bytes(2, 'big') * 16
                reply = ref_receive(sock, state)
                self.assertEqual(ref_decrypt(key, reply['encryption']), 'B'*16)
                ref_send(sock, {'opcode': 2, 'type': 'AES', 'encryption': ref_encrypt(key, '안녕')})
            _, results = self.pair(client, lambda s: bob.exchange(JSONConnection(s), 'B'*16))
            if protocol != 'RSAKey':
                self.assertEqual(results, ['안녕'])


class AttackTests(unittest.TestCase):
    def test_all_supplied_logs(self):
        directory = Path(__file__).parent
        files = sorted(directory.glob('adv_*.log'))
        if not files:
            self.skipTest('copy the supplied adv_*.log files beside the tests')
        self.assertEqual(len(files), 12)
        expected = {
            'adv_protocol_two.log': ['mathematics'],
            'adv_protocol_two-1.log': ['ubuntu'],
            'adv_protocol_two-2.log': ['monday'],
            'adv_protocol_two-3.log': ['software'],
            'adv_protocol_two-prob-1.log': ['Saja Boys', 'sODA pOP'],
            'adv_protocol_two-prob-2.log': ['Huntrix', 'Golden'],
            'adv_protocol_three.log': ['Enjoy', 'Your Life!'],
            'adv_protocol_three-1.log': ['el2001', 'happy'],
            'adv_protocol_three-2.log': ['bottle', 'neck'],
            'adv_protocol_three-3.log': ['cpu', 'memory'],
            'adv_protocol_three-prob-1.log': ['how it is done', 'demon hunters'],
            'adv_protocol_three-prob-2.log': ['YOUR IDOL', 'rumi ZOEY mira'],
        }
        for f in files:
            with self.subTest(log=f.name):
                result = attack('RSA' if 'two' in f.name else 'DH', f)
                self.assertEqual(result['plaintexts'], expected[f.name])


class CLITests(unittest.TestCase):
    def test_missing_message_and_oversized_message(self):
        directory = Path(__file__).parent
        cases = [('alice.py', ['--addr', '127.0.0.1', '--port', '1', '--protocol', 'RSA']),
                 ('alice.py', ['--addr', '127.0.0.1', '--port', '1', '--message', 'x'*17]),
                 ('bob.py', ['--port', '1', '--message', 'x'*17])]
        for filename, args in cases:
            process = subprocess.run([sys.executable, str(directory/filename), *args], capture_output=True, text=True, timeout=3)
            self.assertEqual(process.returncode, 2)
            self.assertIn('message', process.stderr)

    def test_tcp_server_and_repeated_connections_after_bad_request(self):
        directory = Path(__file__).parent
        # 테스트가 포트를 미리 소유해서 다른 프로세스와 포트가 겹치지 않게 한다.
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(5)
            port = listener.getsockname()[1]
            failures = []

            def serve():
                try:
                    for _ in range(4):
                        listener.settimeout(5)
                        conn, _ = listener.accept()
                        bob.handler(conn, 'Bob TCP')
                except Exception as exc:
                    failures.append(exc)

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            with socket.create_connection(('127.0.0.1', port)) as bad:
                bad.sendall(b'{"opcode":0,"type":"unknown"}')
                self.assertEqual(bad.recv(1), b'')
            for protocol in ['RSAKey', 'RSA', 'DH']:
                process = subprocess.run(
                    [sys.executable, str(directory/'alice.py'), '--addr', '127.0.0.1',
                     '--port', str(port), '--protocol', protocol, '--message', 'Alice TCP'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(process.returncode, 0, process.stderr)
                if protocol != 'RSAKey':
                    self.assertIn('Decrypted: Bob TCP', process.stderr)
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertFalse(failures)


if __name__ == '__main__':
    logging.disable(logging.CRITICAL)
    unittest.main()
