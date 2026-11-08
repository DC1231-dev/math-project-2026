"""Alice 클라이언트: 키를 요청·검증하고 Bob과 암호화 메시지를 교환한다."""
import argparse
import logging
import secrets
import socket

from crypto_math import (verify_rsa, is_prime, is_generator, rsa_encrypt_key,
                         dh_keypair, dh_shared, dh_aes_key, message_bytes,
                         encrypt_message, decrypt_message)
from wire import JSONConnection, ProtocolError, expect, integer, parameters


def exchange(wire, protocol, message=None):
    """연결 하나에서 선택한 프로토콜을 수행한다. 예외가 나면 호출자가 연결을 닫는다."""
    if protocol not in ('RSAKey', 'RSA', 'DH'):
        raise ProtocolError('unknown protocol')
    if protocol != 'RSAKey':
        if message is None:
            raise ValueError('--message is required for RSA and DH')
        message_bytes(message)
    wire.send({'opcode': 0, 'type': protocol})
    if protocol == 'RSAKey':
        # Protocol I은 키 쌍을 검증하는 실습이므로 개인지수도 받는다.
        # 일반 키 메시지와 달리 이 응답의 opcode는 슬라이드에 맞춰 0이다.
        response = expect(wire.receive(), 0, 'RSAKey')
        param = parameters(response)
        p, q = integer(param, 'p'), integer(param, 'q')
        e, d = integer(response, 'public'), integer(response, 'private')
        correct = verify_rsa(p, q, e, d)
        logging.info('RSA keypair: p=%s q=%s n=%s e=%s d=%s correct=%s', p, q, p*q, e, d, correct)
        if not correct:
            raise ProtocolError('incorrect RSA keypair')
        return {'correct': True, 'public': e, 'private': d}
    response = expect(wire.receive(), 1, protocol)
    param = parameters(response)
    public = integer(response, 'public')
    if protocol == 'RSA':
        # Protocol II: Alice가 만든 AES 키를 Bob의 RSA 공개키로 보호해 전달한다.
        key = secrets.token_bytes(32)
        encrypted = rsa_encrypt_key(key, public, integer(param, 'n'))
        wire.send({'opcode': 2, 'type': 'RSA', 'encrypted_key': encrypted})
    else:
        # Protocol III/IV: 소수부터 검증해야 생성원 검사의 수학적 전제가 성립한다.
        p, g = integer(param, 'p'), integer(param, 'g')
        if not 400 <= p <= 500 or not is_prime(p):
            wire.send({'opcode': 3, 'error': 'incorrect prime number'})
            raise ProtocolError('incorrect prime number')
        if not is_generator(g, p):
            wire.send({'opcode': 3, 'error': 'incorrect generator'})
            raise ProtocolError('incorrect generator')
        private, own_public = dh_keypair(p, g)
        key = dh_aes_key(dh_shared(public, private, p))
        wire.send({'opcode': 1, 'type': 'DH', 'public': own_public})
    # 키 준비 이후 흐름은 RSA와 DH가 같다. Bob이 먼저 보내고 Alice가 답장한다.
    response = expect(wire.receive(), 2, 'AES')
    plaintext = decrypt_message(key, response.get('encryption'))
    logging.info('Decrypted: %s', plaintext)
    wire.send({'opcode': 2, 'type': 'AES', 'encryption': encrypt_message(key, message)})
    return plaintext


def run(addr, port, protocol='RSAKey', message=None):
    # with 문으로 정상 종료와 오류 종료 모두 소켓이 닫히도록 한다.
    with socket.create_connection((addr, port), timeout=10) as sock:
        logging.info('Alice connected to %s:%s', addr, port)
        return exchange(JSONConnection(sock), protocol, message)


def command_line_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-a', '--addr', required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('--protocol', choices=['RSAKey', 'RSA', 'DH'], default='RSAKey')
    parser.add_argument('-m', '--message')
    parser.add_argument('-l', '--log', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO')
    args = parser.parse_args()
    if args.protocol != 'RSAKey' and args.message is None:
        parser.error('--message is required for RSA and DH')
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
        run(args.addr, args.port, args.protocol, args.message)
    except (OSError, ValueError) as exc:
        logging.error('%s', exc)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
