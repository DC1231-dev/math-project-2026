"""과제용 작은 정수 암호 연산. RSA·DH 수학은 직접 구현하고 AES만 라이브러리를 쓴다."""
from dataclasses import dataclass
from math import isqrt
import base64
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def is_prime(n):
    """짝수를 먼저 제외한 뒤 제곱근 이하의 홀수 약수만 검사한다."""
    if type(n) is not int or n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    return all(n % d for d in range(3, isqrt(n) + 1, 2))


def generate_prime():
    # 과제에서 지정한 범위의 소수 중 하나를 무작위로 고른다.
    return secrets.choice([n for n in range(400, 501) if is_prime(n)])


def gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a, b):
    """a*x + b*y = g를 만족하는 최대공약수 g와 베주 계수 x, y를 반환한다."""
    old_r, r, old_x, x, old_y, y = a, b, 1, 0, 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


def inverse(a, modulus):
    # gcd(a, modulus)=1일 때 베주 계수 x가 a의 모듈러 역원이다.
    g, x, _ = extended_gcd(a, modulus)
    if modulus <= 1 or g != 1:
        raise ValueError('modular inverse does not exist')
    return x % modulus


def prime_factors(n):
    """생성원 검사에 필요한 서로 다른 소인수만 모아 반환한다."""
    factors = set()
    divisor = 2
    while divisor * divisor <= n:
        while n % divisor == 0:
            factors.add(divisor)
            n //= divisor
        divisor += 1
    if n > 1:
        factors.add(n)
    return factors


def is_generator(g, p):
    # 소수 p에서 g의 위수가 p-1인지 확인한다.
    # p-1의 소인수 r 중 하나라도 g^((p-1)/r)=1이면 전체 군을 생성하지 못한다.
    return (is_prime(p) and type(g) is int and 1 < g < p
            and all(pow(g, (p - 1) // r, p) != 1 for r in prime_factors(p - 1)))


def generate_generator(p):
    if not is_prime(p):
        raise ValueError('generator requires a prime modulus')
    return secrets.choice([g for g in range(2, p) if is_generator(g, p)])


@dataclass(frozen=True)
class RSAKey:
    p: int
    q: int
    n: int
    e: int
    d: int


def generate_rsa():
    """서로 다른 두 소수로 n, 공개지수 e, 개인지수 d를 만든다."""
    p, q = generate_prime(), generate_prime()
    while p == q:
        q = generate_prime()
    phi = (p - 1) * (q - 1)
    # e와 phi는 서로소여야 한다. 그래야 e*d ≡ 1 (mod phi)인 d가 존재한다.
    e = 65537
    if not 1 < e < phi or gcd(e, phi) != 1:
        e = next(x for x in range(3, phi, 2) if gcd(x, phi) == 1)
    return RSAKey(p, q, p * q, e, inverse(e, phi))


def verify_rsa(p, q, e, d):
    """받은 소수 조건과 공개지수·개인지수의 역원 관계를 함께 확인한다."""
    primes_ok = (is_prime(p) and is_prime(q) and p != q
                 and 400 <= p <= 500 and 400 <= q <= 500)
    if not primes_ok or type(e) is not int or type(d) is not int:
        return False
    phi = (p - 1) * (q - 1)
    return 1 < e < phi and 0 < d < phi and gcd(e, phi) == 1 and e * d % phi == 1


def rsa_encrypt_key(key, e, n):
    # RSA로 평문 메시지가 아닌 32바이트 AES 키를 한 바이트씩 암호화한다.
    # 결과는 바이트가 아닌 정수 32개의 목록이므로 JSON에 그대로 담는다.
    if len(key) != 32 or type(e) is not int or type(n) is not int or not 1 < e < n or n <= 255:
        raise ValueError('invalid RSA public key or AES key length')
    return [pow(byte, e, n) for byte in key]


def rsa_decrypt_key(encrypted, d, n):
    # RSA 복호화 결과가 0~255 범위여야 원래 AES 키 바이트로 복원할 수 있다.
    if (not isinstance(encrypted, list) or len(encrypted) != 32
            or any(type(x) is not int or not 0 <= x < n for x in encrypted)):
        raise ValueError('encrypted_key must contain 32 RSA ciphertext integers')
    values = [pow(x, d, n) for x in encrypted]
    if any(x > 255 for x in values):
        raise ValueError('RSA decryption did not produce bytes')
    return bytes(values)


def dh_keypair(p, g):
    # 비밀지수는 전송하지 않고 공개값 g^private mod p만 상대에게 보낸다.
    private = secrets.randbelow(p - 2) + 1
    return private, pow(g, private, p)


def dh_shared(public, private, p):
    # 상대 공개값을 내 비밀지수로 거듭제곱하면 양쪽 모두 g^(a*b) mod p를 얻는다.
    if type(public) is not int or not 1 <= public < p:
        raise ValueError('invalid DH public value')
    return pow(public, private, p)


def dh_aes_key(shared):
    # 과제 지정 규칙: 공유 비밀을 빅엔디언 2바이트로 표현하고 16번 반복한다.
    return shared.to_bytes(2, byteorder='big') * 16


def message_bytes(message):
    # 한글의 글자 수와 바이트 수는 다르므로 UTF-8 변환 후 길이를 검사한다.
    data = message.encode('utf-8')
    if len(data) > 16:
        raise ValueError('message must be at most 16 UTF-8 bytes')
    return data


def encrypt_message(key, message):
    """평문 → UTF-8 바이트 → PKCS#7 패딩 → AES 암호문 → Base64 문자열."""
    if len(key) != 32:
        raise ValueError('AES key must be 32 bytes')
    # 정확히 16바이트인 평문에도 패딩 블록을 붙여 복호화 시 끝을 구별한다.
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(message_bytes(message), 16))
    return base64.b64encode(encrypted).decode('ascii')


def decrypt_message(key, encoded):
    """Base64를 풀고 복호화한 뒤 패딩을 검증·제거하여 원래 문자열을 얻는다."""
    if len(key) != 32 or not isinstance(encoded, str):
        raise ValueError('invalid AES key or ciphertext')
    encrypted = base64.b64decode(encoded, validate=True)
    if not encrypted or len(encrypted) % 16:
        raise ValueError('AES ciphertext length must be a positive multiple of 16')
    decrypted = AES.new(key, AES.MODE_ECB).decrypt(encrypted)
    try:
        data = unpad(decrypted, 16)
    except ValueError:
        # 교수님 예제(aes_bob.py)는 16글자 메시지에 패딩을 붙이지 않는다.
        # PKCS#7 패딩이 맞지 않으면 패딩 없는 평문으로 보고 그대로 사용한다.
        data = decrypted
    return data.decode('utf-8')
