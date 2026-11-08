"""Alice 클라이언트: 키를 요청·검증하고 Bob과 암호화 메시지를 교환한다."""
#
# 처음 읽는 사람을 위한 안내: Alice는 먼저 전화를 거는 사람이다.
# Bob은 전화를 기다리는 사람이고, 둘은 인터넷 연결(socket)로 정보를 주고받는다.
# 이 파일의 역할은 '무엇을 먼저 보내고, 어떤 답장을 기다릴지' 순서를 지키는 것이다.
# 실제 계산은 crypto_math.py, 편지를 JSON으로 주고받는 일은 wire.py에 맡긴다.
#
# 읽는 순서: 맨 아래 시작점 → main() → run() → exchange().
# def는 '여러 번 사용할 일 묶음에 이름 붙이기', 함수 호출은 '그 일을 실행하기'다.
# 변수는 값에 붙인 이름표다. message는 보낼 글, key는 글을 잠그는 암호 키다.
# return은 함수의 결과를 돌려주는 말이고, raise는 문제가 생겨 정상 순서를 멈추는 말이다.
# if/else는 조건에 따라 갈림길을 고르고, try/except는 문제가 생겼을 때의 대처를 정한다.
#
# 세 가지 실행 흐름:
# 1. RSAKey: Bob에게 수학 문제의 재료와 답을 받아 키가 올바른지만 검사한다.
# 2. RSA: Alice가 AES 키를 만들고 Bob의 RSA 공개키로 잠가서 전달한다.
# 3. DH: 서로 공개값을 주고받고, 각자 계산해서 같은 AES 키를 만든다.
# RSA/DH가 끝나면 Bob의 암호문을 먼저 읽고 Alice가 자기 암호문으로 답장한다.
#
# JSON은 이름표가 붙은 편지다. 예를 들어 {'type': 'DH', 'public': 226}에서
# 'type'은 편지 종류, 'public'은 공개값을 담을 칸의 이름이다.
# opcode 0=요청, 1=키 정보, 2=암호문, 3=오류이며 RSAKey 응답은 과제 규격상 0이다.
# 공개키는 남에게 알려줘도 되는 계산 재료이고, 비밀지수·AES 키와는 역할이 다르다.
# 이 파일의 import들은 필요한 도구를 가져오는 부분이다.
import argparse
import logging
import secrets
import socket

from crypto_math import (verify_rsa, is_prime, is_generator, rsa_encrypt_key,
                         dh_keypair, dh_shared, dh_aes_key, message_bytes,
                         encrypt_message, decrypt_message)
from wire import JSONConnection, ProtocolError, expect, integer, parameters


# Alice가 통신 한 번을 진행하는 순서표다.
# 입력 wire=이미 연결된 편지 통로, protocol=RSAKey/RSA/DH, message=보낼 글.
# 키 검증만 할 때는 검사 결과 딕셔너리, 메시지 교환 때는 Bob에게서 받은 평문을 반환한다.
# 이름이 exchange라고 해서 매번 자동 반복하는 채팅방은 아니다. 정해진 한 차례 교환만 한다.
def exchange(wire, protocol, message=None):
    """연결 하나에서 선택한 프로토콜을 수행한다. 예외가 나면 호출자가 연결을 닫는다."""
    if protocol not in ('RSAKey', 'RSA', 'DH'):
        raise ProtocolError('unknown protocol')
    if protocol != 'RSAKey':
        if message is None:
            raise ValueError('--message is required for RSA and DH')
        message_bytes(message)
    # 첫 편지: 어떤 실험을 할지 알린다. 아직 AES 키나 평문을 보내는 단계가 아니다.
    wire.send({'opcode': 0, 'type': protocol})
    if protocol == 'RSAKey':
        # Protocol I은 키 쌍을 검증하는 실습이므로 개인지수도 받는다.
        # 일반 키 메시지와 달리 이 응답의 opcode는 슬라이드에 맞춰 0이다.
        response = expect(wire.receive(), 0, 'RSAKey')
        param = parameters(response)
        # 편지 안에서 재료를 꺼낸다. p,q는 소수, e,d는 암호화·복호화 지수다.
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
        # 32개의 임의 바이트를 새로 만든다. --message의 글과는 전혀 다른 데이터다.
        key = secrets.token_bytes(32)
        encrypted = rsa_encrypt_key(key, public, integer(param, 'n'))
        # Bob만 d를 갖고 있으므로 RSA로 잠근 AES 키를 받으면 Bob이 원래 키를 복원한다.
        wire.send({'opcode': 2, 'type': 'RSA', 'encrypted_key': encrypted})
    else:
        # Protocol III/IV: 소수부터 검증해야 생성원 검사의 수학적 전제가 성립한다.
        p, g = integer(param, 'p'), integer(param, 'g')
        # 범위와 소수 여부부터 확인한다. 잘못된 재료로 생성원 검사나 DH 계산을 시작하면 안 된다.
        if not 400 <= p <= 500 or not is_prime(p):
            wire.send({'opcode': 3, 'error': 'incorrect prime number'})
            raise ProtocolError('incorrect prime number')
        if not is_generator(g, p):
            wire.send({'opcode': 3, 'error': 'incorrect generator'})
            raise ProtocolError('incorrect generator')
        # private는 나만 보관하고 own_public만 전송한다. 상대 public과 혼동하지 않는다.
        private, own_public = dh_keypair(p, g)
        # 괄호 안쪽부터 실행: 공유 비밀 계산 → 2바이트 big 변환 → 16번 반복해서 AES 키 완성.
        key = dh_aes_key(dh_shared(public, private, p))
        wire.send({'opcode': 1, 'type': 'DH', 'public': own_public})
    # 키 준비 이후 흐름은 RSA와 DH가 같다. Bob이 먼저 보내고 Alice가 답장한다.
    response = expect(wire.receive(), 2, 'AES')
    # 받은 Base64 암호문을 같은 AES 키로 푼다. 복원된 plaintext가 Bob의 원래 글이다.
    plaintext = decrypt_message(key, response.get('encryption'))
    logging.info('Decrypted: %s', plaintext)
    # 이번에는 내 평문을 같은 키로 잠가 답장한다. 키 자체나 평문을 이 편지에 직접 담지 않는다.
    wire.send({'opcode': 2, 'type': 'AES', 'encryption': encrypt_message(key, message)})
    return plaintext


# Bob에게 실제로 연결하는 입구다.
# 주소와 포트로 연결한 뒤 JSONConnection에 소켓을 맡기고 exchange()를 한 번 실행한다.
# with 블록이 끝나면 연결을 닫으므로 성공하거나 오류가 나도 연결이 계속 남지 않는다.
def run(addr, port, protocol='RSAKey', message=None):
    # with 문으로 정상 종료와 오류 종료 모두 소켓이 닫히도록 한다.
    with socket.create_connection((addr, port), timeout=10) as sock:
        logging.info('Alice connected to %s:%s', addr, port)
        return exchange(JSONConnection(sock), protocol, message)


# 터미널에서 적은 옵션을 읽는 함수다.
# 예: --addr 127.0.0.1 --port 6666 --protocol DH --message world.
# argparse가 옵션을 args.addr, args.port 같은 이름표로 정리해 준다.
# 필수 옵션이 없거나 메시지가 너무 길면 연결 전에 사용법과 오류를 보여 준다.
def command_line_args():
    parser = argparse.ArgumentParser(description=__doc__)
    # --addr는 Bob의 주소, --port는 Bob 프로그램이 기다리는 문 번호다.
    parser.add_argument('-a', '--addr', required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('--protocol', choices=['RSAKey', 'RSA', 'DH'], default='RSAKey')
    # --message는 보내고 싶은 평문이다. RSA 공개키를 이 칸에 적는 것이 아니다.
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


# 프로그램의 총괄 안내원이다. 옵션 읽기 → 로그 설정 → 실제 실행 순서로 일한다.
# 성공이면 0, 통신·데이터 오류면 1을 반환한다. 이 숫자는 원격으로 보내는 opcode와 다르다.
# 예를 들어 Protocol IV에서 오류 파라미터를 잘 검출해도 이 프로그램은 1로 종료한다.
def main():
    args = command_line_args()
    logging.basicConfig(level=args.log, format='%(levelname)s %(message)s')
    try:
        run(args.addr, args.port, args.protocol, args.message)
    except (OSError, ValueError) as exc:
        logging.error('%s', exc)
        return 1
    return 0


# 파일을 직접 실행했을 때만 main()을 시작한다. 다른 파일이 import할 때는 자동 실행하지 않는다.
if __name__ == '__main__':
    raise SystemExit(main())
