"""통신을 바꾸지 않고 제공 로그의 작은 RSA·DH 공개값만으로 평문을 복원한다."""
import argparse
import json
from math import isqrt
from pathlib import Path

from crypto_math import (is_prime, inverse, rsa_decrypt_key, dh_aes_key,
                         decrypt_message, encrypt_message)


def attack(protocol, logfile):
    # 로그는 한 줄에 JSON 객체 하나가 담긴 형식이다. 원본은 읽기만 한다.
    messages = [json.loads(line) for line in Path(logfile).read_text(encoding='utf-8').splitlines() if line.strip()]
    public_message = next(m for m in messages if m.get('type') == protocol and m.get('opcode') == 1 and 'parameter' in m)
    param = public_message['parameter']
    if protocol == 'RSA':
        # 작은 n을 나누어 보는 것으로 p와 q를 알아내면 개인지수 d도 계산할 수 있다.
        n, e = param['n'], public_message['public']
        p = next((x for x in range(2, isqrt(n) + 1) if n % x == 0), None)
        if p is None or not is_prime(p) or not is_prime(n // p) or p == n // p:
            raise ValueError('RSA modulus must be the product of two distinct primes')
        q = n // p
        d = inverse(e, (p - 1) * (q - 1))
        encrypted = next(m['encrypted_key'] for m in messages if m.get('type') == 'RSA' and m.get('opcode') == 2)
        key = rsa_decrypt_key(encrypted, d, n)
        evidence = {'p': p, 'q': q, 'n': n, 'e': e, 'd': d}
    elif protocol == 'DH':
        # A=g^a mod p에 맞는 a를 전수 탐색한다. A와 B는 로그에 공개돼 있다.
        p, g, bob_public = param['p'], param['g'], public_message['public']
        alice_public = next(m['public'] for m in messages if m.get('type') == 'DH' and m.get('opcode') == 1 and 'parameter' not in m)
        private = next((a for a in range(1, p) if pow(g, a, p) == alice_public), None)
        if private is None:
            raise ValueError('DH discrete logarithm not found')
        shared = pow(bob_public, private, p)
        key = dh_aes_key(shared)
        evidence = {'p': p, 'g': g, 'alice_public': alice_public, 'bob_public': bob_public,
                    'recovered_alice_private': private, 'shared': shared}
    else:
        raise ValueError('expected RSA or DH')
    plaintexts = []
    for m in messages:
        if m.get('type') == 'AES' and m.get('opcode') == 2:
            text = decrypt_message(key, m['encryption'])
            # 복원한 키로 다시 암호화해 원본 암호문과 일치하는지도 검증한다.
            if encrypt_message(key, text) != m['encryption']:
                raise ValueError('re-encryption mismatch')
            plaintexts.append(text)
    if not plaintexts:
        raise ValueError('no AES ciphertext found')
    return {'protocol': protocol, 'evidence': evidence, 'aes_key_hex': key.hex(), 'plaintexts': plaintexts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protocol', choices=['RSA', 'DH'], required=True)
    parser.add_argument('--logfile', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = attack(args.protocol, args.logfile)
    except (OSError, ValueError, KeyError, StopIteration) as exc:
        parser.exit(1, f'Attack failed: {exc}\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
