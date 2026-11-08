"""이 폴더에서 python3 -m unittest -v test_project로 전체 검증을 실행한다."""
#
# 처음 읽는 사람을 위한 안내: 이 파일은 프로그램을 자동으로 채점하는 연습 시험지다.
# python3 -m unittest -v test_project를 실행하면 test_로 시작하는 시험들을 찾는다.
# 시험 통과는 여기 준비한 상황에서 맞았다는 뜻이며 교수님 서버와의 실제 호환성을 보장하지는 않는다.
#
# unittest.TestCase는 시험을 만드는 기본 틀이고, self.assertEqual(a, b)는 a와 b가 같은지 검사한다.
# self.assertTrue(x)는 참이어야 통과, assertFalse(x)는 거짓이어야 통과한다.
# with self.assertRaises(ValueError)는 '이번에는 일부러 틀린 값을 넣었으니 오류가 나야 정답'이라는 뜻이다.
# subTest는 반복 중 어떤 입력에서 틀렸는지 구분해 준다. 테스트는 올바른 입력과 틀린 입력을 둘 다 확인한다.
#
# 이 파일의 키·비밀지수 중 일부는 답을 비교하기 위해 고정한 연습용 값이다.
# 본 프로그램의 secrets 난수 생성 방식을 이 고정값으로 바꾸라는 뜻이 아니다.
# socketpair는 같은 컴퓨터 안에서 연결된 소켓 두 개를 만들어 통신을 연습한다.
# thread는 Bob 역할을 옆에서 실행해, Alice와 Bob이 서로의 답장을 기다릴 수 있게 한다.
# subprocess는 별도 Python 프로그램을 실행해 함수뿐 아니라 실제 명령행 사용도 검사한다.
#
# 독립 상대(ref_ 함수)는 같은 공통 함수의 실수를 양쪽이 함께 반복하지 않도록 별도로 쓴 코드다.
# 공격 로그 기대값은 복호화의 정답을 비교할 때만 쓴다. attacker.py는 이 정답표를 읽지 않는다.
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


# 두 소켓과 서버 스레드로 작은 Alice/Bob 실험실을 만드는 공통 틀이다.
class PairTest(unittest.TestCase):
    # client와 server라는 함수 두 개를 받아 서로 연결한 뒤 결과를 모은다. 서버 쪽 오류도 숨기지 않고 테스트 실패로 돌린다.
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


# 수학 도구가 맞는지 다른 계산 방법의 답과 비교한다.
class MathTests(unittest.TestCase):
    # 400~500의 소수 여부를 모든 약수로 검사한 정답과 비교한다. 생성원도 실제 모든 나머지를 만드는지 따로 확인한다.
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

    # 범위 안 서로 다른 소수 쌍마다 0~255의 모든 바이트를 암호화했다 풀어 원래 값인지 확인한다. 잘못된 키 목록도 거부해야 한다.
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
            # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
            with self.assertRaises(ValueError):
                cm.rsa_decrypt_key(bad, rsa.d, rsa.n)
        # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
        with self.assertRaises(ValueError):
            cm.inverse(2, 4)

    # Alice와 Bob이 계산한 공유 비밀이 같은지, 258을 01 02의 16회 반복으로 바꾸는지, 범위 밖 공개값을 거부하는지 확인한다.
    def test_dh_agreement_and_key_derivation(self):
        for p in [401, 461, 499]:
            g = cm.generate_generator(p)
            a, A = cm.dh_keypair(p, g)
            b, B = cm.dh_keypair(p, g)
            self.assertEqual(cm.dh_shared(B, a, p), cm.dh_shared(A, b, p))
        self.assertEqual(cm.dh_aes_key(258), b'\x01\x02' * 16)
        for public in [0, 461, True]:
            # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
            with self.assertRaises(ValueError):
                cm.dh_shared(public, 5, 461)


# AES의 입력 경계와 문자·바이트 변환을 확인하는 시험 묶음이다.
class AESTests(unittest.TestCase):
    # 빈 글, 1·15·16바이트, 한글의 왕복을 확인한다. 영문 17바이트와 한글 18바이트는 허용하면 안 된다.
    def test_boundaries_and_utf8(self):
        key = bytes(range(32))
        for text in ['', 'a', 'a'*15, 'a'*16, '안녕하세요', '한글abc']:
            self.assertEqual(cm.decrypt_message(key, cm.encrypt_message(key, text)), text)
        self.assertEqual(len(base64.b64decode(cm.encrypt_message(key, 'a'*16))), 32)
        for text in ['a'*17, '한'*6]:
            # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
            with self.assertRaises(ValueError):
                cm.encrypt_message(key, text)

    # Base64가 아닌 글, 빈 암호문, AES 블록 길이에 맞지 않는 암호문을 넣어 오류가 나는지 확인한다.
    def test_invalid_base64_length(self):
        key = bytes(32)
        for text in ['!!', '', base64.b64encode(b'x').decode()]:
            # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
            with self.assertRaises(ValueError):
                cm.decrypt_message(key, text)

    # 패딩 없이 AES로 만든 한 블록을 수정본이 읽을 수 있는지 확인한다. 이것이 모든 패딩 오류를 검출한다는 뜻은 아니다.
    def test_professor_style_unpadded_16_chars(self):
        # aes_bob.py 방식: pad = 16 - len(msg) 이므로 16글자면 패딩 없음
        key = bytes(32)
        msg = 'Hello, Bob! 1234'
        encrypted = AES.new(key, AES.MODE_ECB).encrypt(msg.encode())
        self.assertEqual(cm.decrypt_message(key, base64.b64encode(encrypted).decode()), msg)

# 통신이 예쁘게 한 번씩 도착하지 않아도 JSON 객체를 올바르게 읽는지 확인한다.
class WireTests(PairTest):
    # 두 JSON을 붙인 뒤 한 바이트씩 보낸다. 한글 바이트도 잘라 보내도 원래 두 객체로 복원되어야 한다.
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

    # 미완성 JSON, 객체 아닌 값, 잘못된 UTF-8, 크기 초과 데이터를 넣는다. 모두 정상 편지로 받아들이면 안 된다.
    def test_closed_malformed_and_oversized(self):
        for payload in [b'{', b'[]', b'{"x":', b'\xff', b' '* (MAX_MESSAGE+1), b'{"x":"' + b'x'*MAX_MESSAGE + b'"}']:
            with self.subTest(payload=payload[:15]):
                a, b = socket.socketpair()
                with a, b:
                    worker = threading.Thread(target=lambda: self.send_close(b, payload), daemon=True)
                    worker.start()
                    # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
                    with self.assertRaises(ProtocolError):
                        JSONConnection(a).receive()
                    a.close()
                    worker.join(1)

    # 일부러 준비한 데이터를 보낸 뒤 연결을 닫는 테스트 도우미다. 상대가 먼저 닫아 생긴 송신 오류는 이 실험에서 무시한다.
    @staticmethod
    def send_close(sock, payload):
        try:
            sock.sendall(payload)
        except OSError:
            pass
        finally:
            sock.close()

    # 상대가 아무것도 보내지 않을 때 짧게 정한 0.05초 제한으로 끝나는지 확인한다. 끝없이 기다리면 실패다.
    def test_timeout(self):
        a, b = socket.socketpair()
        with a, b:
            start = time.monotonic()
            # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
            with self.assertRaises(TimeoutError):
                JSONConnection(a, timeout=0.05).receive()
            self.assertLess(time.monotonic()-start, 1)


# 우리 Alice와 Bob을 서로 연결해서 프로토콜 순서 전체를 확인한다.
class ProtocolTests(PairTest):
    # RSAKey는 검증 성공을, RSA/DH는 상대방 평문이 정확히 도착했는지 확인한다.
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

    # 잘못된 소수와 잘못된 생성원을 각각 보내 Alice와 Bob 양쪽에 지정된 오류가 전달되는지 확인한다.
    def test_both_dh_errors(self):
        for mode, expected in [('prime', 'incorrect prime number'), ('generator', 'incorrect generator')]:
            def server(sock):
                # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
                with self.assertRaisesRegex(ProtocolError, expected):
                    bob.exchange(JSONConnection(sock), 'Bob', mode)
            def client(sock):
                # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
                with self.assertRaisesRegex(ProtocolError, expected):
                    alice.exchange(JSONConnection(sock), 'DH', 'Alice')
            self.pair(client, server)

    # p와 g가 둘 다 틀렸을 때 소수 오류를 먼저 보내는지 확인한다.
    def test_prime_error_precedes_generator_error(self):
        def server(sock):
            w = JSONConnection(sock)
            w.receive()
            w.send({'opcode': 1, 'type': 'DH', 'public': 1, 'parameter': {'p': 403, 'g': 1}})
            self.assertEqual(w.receive(), {'opcode': 3, 'error': 'incorrect prime number'})
        def client(sock):
            # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
            with self.assertRaisesRegex(ProtocolError, 'incorrect prime number'):
                alice.exchange(JSONConnection(sock), 'DH', 'Alice')
        self.pair(client, server)

    # 일부러 틀린 RSA 키를 보내 Alice가 correct=True라고 착각하지 않는지 확인한다.
    def test_invalid_rsa_keypair(self):
        def server(sock):
            w = JSONConnection(sock)
            w.receive()
            w.send({'opcode': 0, 'type': 'RSAKey', 'public': 3, 'private': 7,
                    'parameter': {'p': 403, 'q': 499}})
        def client(sock):
            # 여기서는 일부러 실패시킨다. 다음 동작에서 지정한 오류가 나야 테스트 성공이다.
            with self.assertRaisesRegex(ProtocolError, 'incorrect RSA keypair'):
                alice.exchange(JSONConnection(sock), 'RSAKey')
        self.pair(client, server)


# 같은 구현끼리만 맞는 오류를 피하려고 독립 상대는 통신·수학 공통 모듈을 쓰지 않는다.
# 독립 상대의 간단한 JSON 수신기다. 공통 wire.py를 쓰지 않아 같은 버그를 양쪽이 공유할 가능성을 줄인다.
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


# 독립 상대가 딕셔너리를 JSON 바이트로 전송하는 최소 동작이다.
def ref_send(sock, obj):
    sock.sendall(json.dumps(obj).encode('ascii'))


# 독립 상대는 패딩을 직접 붙인다. 본체 encrypt_message()를 호출해 자기 답을 자기 답과 비교하지 않는다.
def ref_encrypt(key, text):
    data = text.encode()
    count = 16 - len(data) % 16
    return base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(data + bytes([count])*count)).decode()


# 독립 상대가 정상 암호문을 풀 때 쓰는 최소 도우미다. 본체의 모든 입력 오류 검증을 대신하는 함수는 아니다.
def ref_decrypt(key, text):
    data = AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(text))
    return data[:-data[-1]].decode()


# 우리 프로그램 한쪽을 따로 작성한 상대와 연결해 통신 약속을 교차 확인한다.
class IndependentPeerTests(PairTest):
    # 우리 Alice에게 독립 Bob이 재료를 보낸다. Alice의 키 전달/합의와 복호화·답장이 맞아야 한다.
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

    # 독립 Alice가 우리 Bob에게 요청하고 키를 준비한다. Bob이 보낸 글과 Bob이 복원한 답장을 모두 확인한다.
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


# 제공된 통신 기록을 실제 계산으로 해독했는지 확인한다.
class AttackTests(unittest.TestCase):
    # 12개 로그를 각각 공격 도구에 넣어 평문을 정답표와 비교한다. 정답표는 시험 채점에만 쓰며 공격 계산에는 넘기지 않는다.
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


# 함수 호출뿐 아니라 터미널에서 실행하는 방식도 올바른지 확인한다.
class CLITests(unittest.TestCase):
    # 메시지 누락이나 길이 초과 때 접속을 시도하기 전에 사용법 오류(종료 코드 2)로 끝나야 한다.
    def test_missing_message_and_oversized_message(self):
        directory = Path(__file__).parent
        cases = [('alice.py', ['--addr', '127.0.0.1', '--port', '1', '--protocol', 'RSA']),
                 ('alice.py', ['--addr', '127.0.0.1', '--port', '1', '--message', 'x'*17]),
                 ('bob.py', ['--port', '1', '--message', 'x'*17])]
        for filename, args in cases:
            process = subprocess.run([sys.executable, str(directory/filename), *args], capture_output=True, text=True, timeout=3)
            self.assertEqual(process.returncode, 2)
            self.assertIn('message', process.stderr)

    # 실제 로컬 TCP에서 잘못된 요청 뒤에도 RSAKey/RSA/DH 접속이 이어지는지 확인한다. 외부 학교 서버에는 접속하지 않는다.
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
