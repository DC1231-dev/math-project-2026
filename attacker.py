"""통신을 바꾸지 않고 제공 로그의 작은 RSA·DH 공개값만으로 평문을 복원한다."""
#
# 처음 읽는 사람을 위한 안내: 이 프로그램은 이미 기록된 통신 로그를 읽는 관찰자다.
# Alice나 Bob에게 접속하지 않고, 원본 로그 파일도 고치지 않는다.
# 목표는 '공개된 숫자와 암호문만 보고도 작은 수로 만든 키를 알아낼 수 있다'는 것을 보이는 것이다.
#
# 로그 한 줄은 JSON 편지 한 개다. 편지를 모두 읽고 공개키, 암호화된 키, AES 암호문을 찾는다.
# RSA 공격: n을 나누어 p와 q를 찾음 → d 계산 → AES 키 복원 → 평문 복호화.
# DH 공격: g^a mod p가 A가 되는 a를 하나씩 시도 → 공유 비밀 계산 → AES 키 생성 → 평문 복호화.
# 큰 실전 숫자에서는 이런 단순 탐색을 쉽게 끝낼 수 없지만, 과제 숫자는 작아서 가능하다.
#
# next(후보들, None)은 조건에 맞는 첫 후보를 꺼내고 없으면 None(찾지 못함)을 준다.
# next(후보들)처럼 기본값이 없으면 후보가 없을 때 StopIteration 오류가 난다.
# 여기서는 필수 편지가 로그에 없다는 뜻이고, main()에서 실행 실패로 알려 준다.
# 로그에서 만든 목록을 읽는 것이므로 통신이 새로 생겨도 이 입력 파일이 자동 갱신되지는 않는다.
import argparse
import json
from math import isqrt
from pathlib import Path

from crypto_math import (is_prime, inverse, rsa_decrypt_key, dh_aes_key,
                         decrypt_message, encrypt_message)


# 로그를 읽어 키와 평문을 복원하고 결과 상자를 돌려주는 본체다.
# 입력 protocol은 RSA 또는 DH, logfile은 로그 파일 경로다.
# 출력 evidence는 계산 근거, aes_key_hex는 키를 16진수로 표현한 글,
# plaintexts는 로그에 담긴 순서대로 복원한 평문 목록이다.
def attack(protocol, logfile):
    # 로그는 한 줄에 JSON 객체 하나가 담긴 형식이다. 원본은 읽기만 한다.
    # 파일을 읽고 줄로 나눈 뒤 빈 줄은 건너뛰고 각 JSON을 딕셔너리로 바꿔 목록에 모은다.
    messages = [json.loads(line) for line in Path(logfile).read_text(encoding='utf-8').splitlines() if line.strip()]
    # 요청·암호문 편지를 제외하고, Bob이 공개키와 계산 재료를 담아 보낸 편지를 고른다.
    public_message = next(m for m in messages if m.get('type') == protocol and m.get('opcode') == 1 and 'parameter' in m)
    param = public_message['parameter']
    if protocol == 'RSA':
        # 작은 n을 나누어 보는 것으로 p와 q를 알아내면 개인지수 d도 계산할 수 있다.
        n, e = param['n'], public_message['public']
        # 예: n=35라면 2,3,4,5를 시도해 5를 찾고, q=35//5=7도 알아낸다.
        p = next((x for x in range(2, isqrt(n) + 1) if n % x == 0), None)
        if p is None or not is_prime(p) or not is_prime(n // p) or p == n // p:
            raise ValueError('RSA modulus must be the product of two distinct primes')
        q = n // p
        # p,q를 알아냈으므로 Bob이 원래 비밀로 보관한 복호화 지수 d를 계산할 수 있다.
        d = inverse(e, (p - 1) * (q - 1))
        encrypted = next(m['encrypted_key'] for m in messages if m.get('type') == 'RSA' and m.get('opcode') == 2)
        # 새로 알아낸 d로 암호화된 키 목록을 풀면 Alice/Bob이 사용한 AES 키가 복원된다.
        key = rsa_decrypt_key(encrypted, d, n)
        evidence = {'p': p, 'q': q, 'n': n, 'e': e, 'd': d}
    elif protocol == 'DH':
        # A=g^a mod p에 맞는 a를 전수 탐색한다. A와 B는 로그에 공개돼 있다.
        p, g, bob_public = param['p'], param['g'], public_message['public']
        alice_public = next(m['public'] for m in messages if m.get('type') == 'DH' and m.get('opcode') == 1 and 'parameter' not in m)
        # 가능한 a를 하나씩 시험한다. 같은 공개값을 만드는 지수를 찾으면 공유 비밀 계산에 사용할 수 있다.
        private = next((a for a in range(1, p) if pow(g, a, p) == alice_public), None)
        if private is None:
            raise ValueError('DH discrete logarithm not found')
        # Bob의 공개값 B를 찾은 a로 거듭제곱한다. 정상 Alice가 계산한 공유 비밀과 같은 값이다.
        shared = pow(bob_public, private, p)
        key = dh_aes_key(shared)
        evidence = {'p': p, 'g': g, 'alice_public': alice_public, 'bob_public': bob_public,
                    'recovered_alice_private': private, 'shared': shared}
    else:
        raise ValueError('expected RSA or DH')
    # 복호화한 글을 차례대로 담을 빈 목록이다. 한 로그에 AES 편지가 여러 개 있을 수 있다.
    plaintexts = []
    for m in messages:
        if m.get('type') == 'AES' and m.get('opcode') == 2:
            text = decrypt_message(key, m['encryption'])
            # 복원한 키로 다시 암호화해 원본 암호문과 일치하는지도 검증한다.
            # 같은 키와 같은 평문이면 ECB 암호문도 같다. 다르면 현재 복원/패딩 규칙으로는 맞지 않는 결과다.
            if encrypt_message(key, text) != m['encryption']:
                raise ValueError('re-encryption mismatch')
            # 정답표에서 꺼내는 게 아니라 실제 암호문을 풀어 얻은 글을 결과 목록 끝에 추가한다.
            plaintexts.append(text)
    if not plaintexts:
        raise ValueError('no AES ciphertext found')
    return {'protocol': protocol, 'evidence': evidence, 'aes_key_hex': key.hex(), 'plaintexts': plaintexts}


# 터미널에서 받은 프로토콜과 로그 경로로 attack()을 실행한다.
# 파일이 없거나 필요한 JSON 칸이 없거나 수학 계산이 실패하면 실패 이유를 출력한다.
# 성공 결과는 사람이 읽기 좋게 들여쓴 JSON으로 화면에 보여 준다.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protocol', choices=['RSA', 'DH'], required=True)
    parser.add_argument('--logfile', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = attack(args.protocol, args.logfile)
    except (OSError, ValueError, KeyError, StopIteration) as exc:
        parser.exit(1, f'Attack failed: {exc}\n')
    # 화면 표시용 JSON이다. indent=2는 들여쓰기 두 칸, ensure_ascii=False는 한글을 그대로 표시한다.
    print(json.dumps(result, ensure_ascii=False, indent=2))


# 이 파일을 직접 실행할 때만 터미널 옵션을 읽는다. 테스트에서 import할 때는 공격을 시작하지 않는다.
if __name__ == '__main__':
    main()
