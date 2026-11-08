"""TCP 바이트 스트림에서 JSON 객체를 하나씩 꺼내는 공통 통신 모듈."""
import codecs
import json
import logging
import time

MAX_MESSAGE = 64 * 1024
TIMEOUT = 10


class ProtocolError(ValueError):
    pass


def integer(obj, key):
    # Python에서는 bool도 int의 하위형이므로 정확한 타입을 비교한다.
    value = obj.get(key)
    if type(value) is not int:
        raise ProtocolError(f'{key} must be an integer')
    return value


def parameters(obj):
    value = obj.get('parameter')
    if not isinstance(value, dict):
        raise ProtocolError('parameter must be an object')
    return value


def expect(obj, opcode, kind):
    # 어느 단계에서든 상대가 오류를 보내면 다음 암호화 단계로 진행하지 않는다.
    if obj.get('opcode') == 3:
        raise ProtocolError(f"Peer error: {obj.get('error', 'unknown error')}")
    if type(obj.get('opcode')) is not int or obj['opcode'] != opcode or obj.get('type') != kind:
        raise ProtocolError(f'expected opcode={opcode}, type={kind}')
    return obj


class JSONConnection:
    """한 번의 recv가 메시지 한 개와 같다고 가정하지 않고 남은 데이터를 보존한다."""
    def __init__(self, sock, timeout=TIMEOUT):
        self.sock = sock
        self.timeout = timeout
        self.buffer = ''
        self.decoder = json.JSONDecoder()
        # UTF-8 한 글자가 여러 TCP 조각으로 나뉘어 와도 올바르게 복원한다.
        self.utf8 = codecs.getincrementaldecoder('utf-8')()
        sock.settimeout(timeout)

    def send(self, obj):
        # 임의의 길이 헤더를 추가하지 않아 제공된 예제 프로그램과 형식을 맞춘다.
        data = json.dumps(obj, ensure_ascii=True).encode('ascii')
        if len(data) > MAX_MESSAGE:
            raise ProtocolError('JSON message exceeds 64KiB')
        self.sock.sendall(data)
        logging.info('Sent: %s', data.decode('ascii'))

    def receive(self):
        # 조각을 조금씩 보내는 상대 때문에 대기가 끝없이 연장되지 않도록
        # recv마다 시간이 아니라 객체 하나를 받을 때의 전체 제한 시간을 적용한다.
        deadline = time.monotonic() + self.timeout
        try:
            while True:
                candidate = self.buffer.lstrip()
                leading_bytes = len(self.buffer[:len(self.buffer) - len(candidate)].encode('utf-8'))
                if candidate and not candidate.startswith('{'):
                    raise ProtocolError('expected a JSON object')
                try:
                    obj, end = self.decoder.raw_decode(candidate)
                except json.JSONDecodeError:
                    # JSON이 아직 완성되지 않았을 수 있으므로 다음 조각을 이어 받는다.
                    if len(self.buffer.encode('utf-8')) > MAX_MESSAGE:
                        raise ProtocolError('JSON message exceeds 64KiB')
                else:
                    if leading_bytes + len(candidate[:end].encode('utf-8')) > MAX_MESSAGE:
                        raise ProtocolError('JSON message exceeds 64KiB')
                    self.buffer = candidate[end:]
                    # 같은 recv로 다음 객체까지 들어왔다면 남은 문자열은 다음 호출에서 쓴다.
                    logging.info('Received: %s', json.dumps(obj))
                    return obj
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('JSON receive timed out')
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise ProtocolError('connection closed before a complete JSON object')
                try:
                    self.buffer += self.utf8.decode(chunk)
                except UnicodeDecodeError as exc:
                    raise ProtocolError('invalid UTF-8 JSON') from exc
        finally:
            self.sock.settimeout(self.timeout)
