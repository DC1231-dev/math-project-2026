"""Bob 서버: 최초 요청으로 프로토콜을 선택하고 Alice와 암호화 통신한다."""
import argparse
import logging
import socket
import threading

from crypto_math import (generate_rsa, generate_prime, generate_generator,
                         rsa_decrypt_key, dh_keypair, dh_shared, dh_aes_key,
                         message_bytes, encrypt_message, decrypt_message)
from wire import JSONConnection, ProtocolError, expect, integer


def exchange(wire, message=None, dh_error='none'):
    """키와 비밀값은 함수의 지역변수로 두어 다른 연결과 섞이지 않게 한다."""
    request = wire.receive()
    protocol = request.get('type')
    if protocol not in ('RSAKey', 'RSA', 'DH'):
        raise ProtocolError('unknown protocol')
    expect(request, 0, protocol)
    if protocol == 'RSAKey':
        # Protocol I: p, q, e, d를 보내 Alice가 키 쌍의 정합성을 검사하게 한다.
        rsa = generate_rsa()
        wire.send({'opcode': 0, 'type': 'RSAKey', 'private': rsa.d,
                   'public': rsa.e, 'parameter': {'p': rsa.p, 'q': rsa.q}})
        return None
    if message is None:
        raise ProtocolError('Bob requires --message for RSA and DH')
    message_bytes(message)
    if protocol == 'RSA':
        # Protocol II: 개인키 d는 보관하고 n과 e만 공개한다.
        rsa = generate_rsa()
        wire.send({'opcode': 1, 'type': 'RSA', 'public': rsa.e, 'parameter': {'n': rsa.n}})
        response = expect(wire.receive(), 2, 'RSA')
        key = rsa_decrypt_key(response.get('encrypted_key'), rsa.d, rsa.n)
    else:
        # Protocol III: 정상 소수와 생성원을 만들고 Bob의 공개값을 보낸다.
        p = generate_prime()
        g = generate_generator(p)
        if dh_error == 'prime':
            # Protocol IV 시연용. 정상 동작에서는 이 분기로 들어가지 않는다.
            p = 403
        elif dh_error == 'generator':
            g = 1
        elif dh_error != 'none':
            raise ValueError('invalid DH error mode')
        private, public = dh_keypair(p, g)
        wire.send({'opcode': 1, 'type': 'DH', 'public': public, 'parameter': {'p': p, 'g': g}})
        response = expect(wire.receive(), 1, 'DH')
        if dh_error != 'none':
            raise ProtocolError('peer accepted intentionally invalid DH parameters')
        key = dh_aes_key(dh_shared(integer(response, 'public'), private, p))
    # Bob이 자기 메시지를 먼저 전송한 뒤 Alice의 메시지를 복호화한다.
    wire.send({'opcode': 2, 'type': 'AES', 'encryption': encrypt_message(key, message)})
    response = expect(wire.receive(), 2, 'AES')
    plaintext = decrypt_message(key, response.get('encryption'))
    logging.info('Decrypted: %s', plaintext)
    return plaintext


def handler(sock, message=None, dh_error='none'):
    # 한 연결의 오류는 여기서 처리하여 서버의 다음 접속 수신을 막지 않는다.
    with sock:
        try:
            return exchange(JSONConnection(sock), message, dh_error)
        except (OSError, ValueError) as exc:
            logging.error('%s', exc)
            return None


def run(addr, port, message=None, dh_error='none'):
    if message is not None:
        message_bytes(message)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((addr, port))
        server.listen(10)
        logging.info('Bob is listening on %s:%s', addr, port)
        while True:
            conn, info = server.accept()
            logging.info('Bob accepts %s:%s', *info)
            # 각 연결을 따로 처리하고 서버 종료 시 처리 스레드도 종료한다.
            threading.Thread(target=handler, args=(conn, message, dh_error), daemon=True).start()


def command_line_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-a', '--addr', default='0.0.0.0')
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-m', '--message', help='required for RSA/DH; omit for RSAKey-only server')
    parser.add_argument('--dh-error', choices=['none', 'prime', 'generator'], default='none')
    parser.add_argument('-l', '--log', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO')
    args = parser.parse_args()
    if args.message is not None:
        try:
            message_bytes(args.message)
        except ValueError as exc:
            parser.error(str(exc))
    return args


def main():
    args = command_line_args()
    logging.basicConfig(level=args.log, format='%(levelname)s %(message)s')
    try:
        run(args.addr, args.port, args.message, args.dh_error)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError) as exc:
        logging.error('%s', exc)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
