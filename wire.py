"""TCP 바이트 스트림에서 JSON 객체를 하나씩 꺼내는 공통 통신 모듈."""
#
# 처음 읽는 사람을 위한 안내: 이 파일은 인터넷 편지를 포장하고 다시 읽는 도구다.
# Alice/Bob은 {'opcode': 0, 'type': 'DH'} 같은 Python 딕셔너리(이름표와 값의 묶음)를 쓴다.
# 인터넷에는 그 딕셔너리 자체를 실을 수 없으므로 JSON 글로 바꾸고 바이트로 보내야 한다.
# 받는 쪽은 바이트를 글로 바꾸고, JSON을 읽어 다시 딕셔너리로 만든다.
#
# 보낼 때: 딕셔너리 → JSON 문자열 → 바이트 → socket.
# 받을 때: socket → 바이트 → 문자열 → JSON 파서 → 딕셔너리.
# 파서는 글의 구조를 읽는 도구이고, 버퍼(buffer)는 아직 처리하지 않은 글을 잠시 담는 통이다.
#
# TCP는 편지봉투 단위가 아니라 이어진 바이트 흐름을 전달한다.
# 예를 들어 {'a':1}을 한 번 보냈어도 {'a': 와 1}로 나누어 도착할 수 있다.
# 반대로 두 객체가 한 번에 {'a':1}{'b':2}처럼 붙어서 올 수도 있다.
# 그래서 recv() 한 번의 결과를 바로 json.loads() 하는 대신, 끝난 객체만 꺼내고 나머지를 남긴다.
#
# 예외(오류 알림)는 상대가 규칙을 어겼거나 연결이 끊긴 상황을 호출자에게 알려 준다.
# 이 모듈은 일반적인 잘못된 입력을 처리하지만 모든 악성 입력을 막는 완전한 방어 도구는 아니다.
import codecs
import json
import logging
import time

# 64KiB=65536바이트. 평문 16바이트 제한과 달리 통신 JSON 한 객체 전체의 크기 제한이다.
MAX_MESSAGE = 64 * 1024
# 상대가 답장을 주지 않을 때 무한 대기하지 않도록 기본 10초를 정한다.
TIMEOUT = 10


# 통신 약속을 어긴 경우에 쓸 오류 이름이다. ValueError를 바탕으로 만든다.
# pass는 아직 별도 작업을 더 적지 않았다는 뜻이다. 기존 오류 동작을 그대로 물려받는다.
class ProtocolError(ValueError):
    pass


# JSON 편지의 특정 칸이 정수인지 검사한 다음 값을 꺼낸다.
# 예: integer({'public': 226}, 'public')는 226을 돌려준다.
# obj.get(key)는 칸이 없으면 None을 주므로, 누락도 잘못된 타입으로 처리된다.
def integer(obj, key):
    # Python에서는 bool도 int의 하위형이므로 정확한 타입을 비교한다.
    value = obj.get(key)
    if type(value) is not int:
        raise ProtocolError(f'{key} must be an integer')
    return value


# 편지 안의 parameter 상자를 꺼내고 다시 딕셔너리인지 확인한다.
# RSA에서는 {'n': ...}, DH에서는 {'p': ..., 'g': ...} 같은 작은 상자가 들어간다.
def parameters(obj):
    value = obj.get('parameter')
    if not isinstance(value, dict):
        raise ProtocolError('parameter must be an object')
    return value


# 지금 단계에서 기다리던 종류의 편지가 맞는지 검사한다.
# AES 암호문을 기다리는데 DH 공개값이 오면 다음 계산을 하지 않고 오류를 알린다.
# 오류 편지(opcode 3)는 종류와 상관없이 즉시 읽어 오류 내용을 전달한다.
def expect(obj, opcode, kind):
    # 어느 단계에서든 상대가 오류를 보내면 다음 암호화 단계로 진행하지 않는다.
    if obj.get('opcode') == 3:
        raise ProtocolError(f"Peer error: {obj.get('error', 'unknown error')}")
    if type(obj.get('opcode')) is not int or obj['opcode'] != opcode or obj.get('type') != kind:
        raise ProtocolError(f'expected opcode={opcode}, type={kind}')
    return obj


# 연결된 소켓과 수신 대기용 버퍼를 함께 들고 있는 통신 도우미다.
# self는 이 도우미 자신을 가리킨다. self.buffer는 이 연결에만 속한 보관함이다.
class JSONConnection:
    """한 번의 recv가 메시지 한 개와 같다고 가정하지 않고 남은 데이터를 보존한다."""
    # 새 JSONConnection을 만들 때 한 번 실행되는 준비 작업이다.
    # sock은 이미 연결된 통로다. 이 생성자는 새로 전화하지 않는다.
    # UTF-8 디코더는 한 글자의 바이트가 도중에 잘려 오면 남은 조각을 기억한다.
    def __init__(self, sock, timeout=TIMEOUT):
        self.sock = sock
        self.timeout = timeout
        # 아직 읽을 글이 없으므로 빈 문자열로 시작한다. 이후 수신 조각을 여기에 이어 붙인다.
        self.buffer = ''
        self.decoder = json.JSONDecoder()
        # UTF-8 한 글자가 여러 TCP 조각으로 나뉘어 와도 올바르게 복원한다.
        self.utf8 = codecs.getincrementaldecoder('utf-8')()
        sock.settimeout(timeout)

    # Python 딕셔너리 하나를 JSON으로 바꾸어 모두 전송한다.
    # ensure_ascii=True는 한글도 ASCII 이스케이프로 표현하게 한다. 상대가 JSON을 풀면 한글이 복원된다.
    # sendall은 전체 바이트 전송을 시도하며, 실패하면 예외를 낸다.
    # 로그 출력은 터미널 설명이다. INFO Sent: 같은 접두사는 실제 전송 JSON에 붙이지 않는다.
    def send(self, obj):
        # 임의의 길이 헤더를 추가하지 않아 제공된 예제 프로그램과 형식을 맞춘다.
        # dumps는 객체를 JSON 글로 만드는 함수다. loads/raw_decode는 반대 방향이다.
        data = json.dumps(obj, ensure_ascii=True).encode('ascii')
        if len(data) > MAX_MESSAGE:
            raise ProtocolError('JSON message exceeds 64KiB')
        self.sock.sendall(data)
        logging.info('Sent: %s', data.decode('ascii'))

    # 수신 버퍼에서 완성된 JSON 객체 하나만 꺼낸다. 부족하면 더 받고, 다음 객체는 남긴다.
    # raw_decode는 객체와 그 객체가 끝난 위치를 함께 준다.
    # 예: 두 객체가 붙어 있으면 첫 번째의 끝 위치 뒤를 버퍼에 남겨 다음 receive()가 읽게 한다.
    # 최대 크기와 대기 시간을 넘기거나 중간에 연결이 끊기면 오류로 종료한다.
    def receive(self):
        # 조각을 조금씩 보내는 상대 때문에 대기가 끝없이 연장되지 않도록
        # recv마다 시간이 아니라 객체 하나를 받을 때의 전체 제한 시간을 적용한다.
        # 지금부터 허용 시간 뒤를 마감 시각으로 저장한다. monotonic은 시계 보정 때문에 거꾸로 가지 않는다.
        deadline = time.monotonic() + self.timeout
        try:
            while True:
                # 객체 앞의 공백은 JSON 내용을 바꾸지 않으므로 파싱할 후보에서는 제거한다.
                candidate = self.buffer.lstrip()
                # 공백을 지웠어도 크기 제한에서 빠뜨리지 않기 위해 앞 공백의 바이트 수를 따로 센다.
                leading_bytes = len(self.buffer[:len(self.buffer) - len(candidate)].encode('utf-8'))
                if candidate and not candidate.startswith('{'):
                    raise ProtocolError('expected a JSON object')
                try:
                    # 완성된 첫 JSON 객체와 끝 위치를 얻는다. 다음 객체가 뒤에 붙어 있어도 첫 것만 읽는다.
                    obj, end = self.decoder.raw_decode(candidate)
                except json.JSONDecodeError:
                    # JSON이 아직 완성되지 않았을 수 있으므로 다음 조각을 이어 받는다.
                    if len(self.buffer.encode('utf-8')) > MAX_MESSAGE:
                        raise ProtocolError('JSON message exceeds 64KiB')
                else:
                    if leading_bytes + len(candidate[:end].encode('utf-8')) > MAX_MESSAGE:
                        raise ProtocolError('JSON message exceeds 64KiB')
                    # 예: 첫 편지가 7글자에서 끝났다면 7번째 뒤의 글은 다음 편지용으로 남겨 둔다.
                    self.buffer = candidate[end:]
                    # 같은 recv로 다음 객체까지 들어왔다면 남은 문자열은 다음 호출에서 쓴다.
                    logging.info('Received: %s', json.dumps(obj))
                    return obj
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('JSON receive timed out')
                self.sock.settimeout(remaining)
                # 최대 4096바이트를 받는다. 반드시 4096바이트나 JSON 한 개가 온다는 뜻은 아니다.
                chunk = self.sock.recv(4096)
                # 빈 바이트가 오면 상대가 연결을 닫았다는 뜻이다. 아무 글도 안 온 대기 상태와 다르다.
                if not chunk:
                    raise ProtocolError('connection closed before a complete JSON object')
                try:
                    # +=는 기존 글 뒤에 새 글을 이어 붙인다는 뜻이다. 덜 온 한글 바이트는 디코더가 기억한다.
                    self.buffer += self.utf8.decode(chunk)
                except UnicodeDecodeError as exc:
                    raise ProtocolError('invalid UTF-8 JSON') from exc
        # 성공·오류 어느 쪽으로 끝나든 실행하는 정리 단계다. 다음 작업의 기본 대기 시간을 되돌린다.
        finally:
            self.sock.settimeout(self.timeout)
