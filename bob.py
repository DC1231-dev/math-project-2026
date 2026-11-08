"""Bob 서버: 최초 요청으로 프로토콜을 선택하고 Alice와 암호화 통신한다."""
#
# 처음 읽는 사람을 위한 안내: Bob은 먼저 실행해 놓고 Alice의 전화를 기다리는 서버다.
# Alice는 요청 종류를 정하고, Bob은 받은 요청에 맞는 답장을 만든다.
# 이 파일은 순서를 담당한다. 수학 계산은 crypto_math.py, JSON 송수신은 wire.py가 맡는다.
#
# 읽는 순서: 맨 아래 시작점 → main() → run()의 접속 대기 → handler() → exchange().
# addr은 어느 네트워크 주소에서 받을지, port는 그 컴퓨터의 어느 문으로 받을지 뜻한다.
# 127.0.0.1은 자기 컴퓨터, 0.0.0.0은 이 컴퓨터의 모든 IPv4 인터페이스에서 받겠다는 뜻이다.
# 0.0.0.0은 상대에게 알려줄 접속 주소가 아니다. 상대는 Bob의 실제 IP로 접속한다.
# message는 Bob이 보낼 원래 글이고 key는 그 글을 잠그는 AES 키다.
#
# RSAKey에서는 p, q, e, d를 모두 보내 Alice가 수학 관계를 검사하게 한다.
# RSA에서는 n, e만 보낸 뒤 Alice가 잠가 보낸 AES 키를 d로 복원한다.
# DH에서는 p, g, 공개값을 보내고 Alice의 공개값을 받아 같은 비밀을 계산한다.
# 키가 준비되면 Bob이 먼저 AES 암호문을 보내고 Alice의 답장을 복호화한다.
#
# thread(스레드)는 접속한 사람을 따로 맡아 주는 일꾼에 비유할 수 있다.
# 여러 연결의 비밀키가 섞이지 않도록 키 변수는 각 exchange() 호출 안에 둔다.
# 문제가 생긴 연결은 닫되, 서버 전체가 다음 전화를 못 받게 끝내지는 않는다.
# import는 통신·동시 처리·수학 같은 도구를 가져오는 부분이다.
import argparse
import logging
import socket
import threading

from crypto_math import (generate_rsa, generate_prime, generate_generator,
                         rsa_decrypt_key, dh_keypair, dh_shared, dh_aes_key,
                         message_bytes, encrypt_message, decrypt_message)
from wire import JSONConnection, ProtocolError, expect, integer


# Alice 한 명의 요청을 처리하는 순서표다.
# wire는 그 Alice와 연결된 통로, message는 Bob의 평문, dh_error는 오류 시연 종류다.
# Alice가 보낸 type을 읽어 RSAKey/RSA/DH 중 어느 계산을 할지 고른다.
# RSAKey는 답장 후 끝나고, RSA/DH는 Alice에게서 복호화한 평문을 결과로 돌려준다.
def exchange(wire, message=None, dh_error='none'):
    """키와 비밀값은 함수의 지역변수로 두어 다른 연결과 섞이지 않게 한다."""
    # 먼저 Alice의 요청을 기다린다. 받은 JSON의 type이 어떤 실험인지 알려 준다.
    request = wire.receive()
    protocol = request.get('type')
    if protocol not in ('RSAKey', 'RSA', 'DH'):
        raise ProtocolError('unknown protocol')
    expect(request, 0, protocol)
    if protocol == 'RSAKey':
        # Protocol I: p, q, e, d를 보내 Alice가 키 쌍의 정합성을 검사하게 한다.
        # 이번 연결에서 사용할 RSA 키를 새로 만든다. 다른 사람의 연결에서 만든 키를 재사용하지 않는다.
        rsa = generate_rsa()
        wire.send({'opcode': 0, 'type': 'RSAKey', 'private': rsa.d,
                   'public': rsa.e, 'parameter': {'p': rsa.p, 'q': rsa.q}})
        return None
    if message is None:
        raise ProtocolError('Bob requires --message for RSA and DH')
    message_bytes(message)
    if protocol == 'RSA':
        # Protocol II: 개인키 d는 보관하고 n과 e만 공개한다.
        # 이번 연결에서 사용할 RSA 키를 새로 만든다. 다른 사람의 연결에서 만든 키를 재사용하지 않는다.
        rsa = generate_rsa()
        wire.send({'opcode': 1, 'type': 'RSA', 'public': rsa.e, 'parameter': {'n': rsa.n}})
        response = expect(wire.receive(), 2, 'RSA')
        # Alice가 정수 32개로 보낸 암호문을 개인지수 d로 풀어 원래 32바이트 AES 키를 얻는다.
        key = rsa_decrypt_key(response.get('encrypted_key'), rsa.d, rsa.n)
    else:
        # Protocol III: 정상 소수와 생성원을 만들고 Bob의 공개값을 보낸다.
        p = generate_prime()
        g = generate_generator(p)
        if dh_error == 'prime':
            # Protocol IV 시연용. 정상 동작에서는 이 분기로 들어가지 않는다.
            # 403=13*31이므로 소수가 아니다. Alice가 이 잘못을 잡는지 일부러 시험한다.
            p = 403
        elif dh_error == 'generator':
            # 1의 거듭제곱은 계속 1이라 다른 나머지를 만들 수 없다. 그래서 의도적으로 틀린 생성원이다.
            g = 1
        elif dh_error != 'none':
            raise ValueError('invalid DH error mode')
        private, public = dh_keypair(p, g)
        wire.send({'opcode': 1, 'type': 'DH', 'public': public, 'parameter': {'p': p, 'g': g}})
        # 정상이면 Alice 공개값을 받는다. Alice가 opcode 3 오류를 보내면 expect()가 여기서 중단한다.
        response = expect(wire.receive(), 1, 'DH')
        if dh_error != 'none':
            raise ProtocolError('peer accepted intentionally invalid DH parameters')
        # 내 비밀지수와 Alice 공개값으로 공유 비밀을 얻는다. Alice와 같은 키가 나와야 한다.
        key = dh_aes_key(dh_shared(integer(response, 'public'), private, p))
    # Bob이 자기 메시지를 먼저 전송한 뒤 Alice의 메시지를 복호화한다.
    wire.send({'opcode': 2, 'type': 'AES', 'encryption': encrypt_message(key, message)})
    response = expect(wire.receive(), 2, 'AES')
    plaintext = decrypt_message(key, response.get('encryption'))
    logging.info('Decrypted: %s', plaintext)
    return plaintext


# 전화 한 통을 맡는 일꾼이다.
# exchange()에서 오류가 나면 오류 내용을 표시하고 그 소켓을 닫는다.
# 예외를 여기서 받아 처리하므로 접속 하나가 실패해도 run()의 대기 반복은 계속된다.
def handler(sock, message=None, dh_error='none'):
    # 한 연결의 오류는 여기서 처리하여 서버의 다음 접속 수신을 막지 않는다.
    with sock:
        try:
            return exchange(JSONConnection(sock), message, dh_error)
        except (OSError, ValueError) as exc:
            logging.error('%s', exc)
            return None


# 전화국을 열고 접속을 계속 받는 함수다.
# 서버용 socket은 접수 창구이고 accept()가 주는 conn은 방금 접속한 사람과의 전용 통로다.
# 각 conn을 새 스레드에 맡기므로 한 사람이 응답을 기다리는 동안에도 다음 접속을 받을 수 있다.
def run(addr, port, message=None, dh_error='none'):
    if message is not None:
        message_bytes(message)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        # 서버를 다시 실행할 때 직전 연결의 주소 재사용 대기 때문에 막히는 경우를 줄인다.
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 이 주소와 포트로 오는 전화를 받겠다고 접수 창구를 등록한다.
        server.bind((addr, port))
        # 연결 대기를 시작한다. 10은 대기 연결 큐의 요청 크기이며 평문 길이나 키 길이가 아니다.
        server.listen(10)
        logging.info('Bob is listening on %s:%s', addr, port)
        while True:
            # 접속이 올 때까지 기다린다. conn은 전용 통로, info는 접속자 주소와 포트다.
            conn, info = server.accept()
            logging.info('Bob accepts %s:%s', *info)
            # 각 연결을 따로 처리하고 서버 종료 시 처리 스레드도 종료한다.
            # handler에 통로와 메시지·오류 옵션을 건넨다. start()가 옆에서 실제 처리를 시작한다.
            threading.Thread(target=handler, args=(conn, message, dh_error), daemon=True).start()


# Bob을 어떤 주소·포트에서 열고 어떤 평문을 보낼지 터미널 옵션으로 읽는다.
# RSAKey만 처리할 때는 메시지가 필요 없어서 --message를 생략할 수 있다.
# 그 상태로 RSA/DH 요청이 오면 exchange()가 메시지 누락 오류를 알린다.
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


# 옵션을 읽어 서버를 시작하고, 서버 시작 오류나 Ctrl+C를 처리한다.
# KeyboardInterrupt는 사용자가 Ctrl+C로 중단했다는 신호여서 정상 종료로 취급한다.
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


# 직접 실행할 때만 서버를 켠다. 테스트가 import할 때 서버가 저절로 켜지면 안 된다.
if __name__ == '__main__':
    raise SystemExit(main())
