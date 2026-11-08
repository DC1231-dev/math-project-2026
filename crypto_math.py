
"""과제용 작은 정수 암호 연산. RSA·DH 수학은 직접 구현하고 AES만 라이브러리를 쓴다."""
#
# 처음 읽는 사람을 위한 안내: 이 파일은 Alice와 Bob이 함께 쓰는 계산 도구 상자다.
# 같은 계산을 두 파일에 따로 적으면 한쪽만 고쳤을 때 서로 결과가 달라질 수 있다.
# 그래서 수학과 AES 처리를 여기 모으고 필요한 곳에서 함수를 불러 쓴다.
#
# 용어부터 알아두기:
# - 평문: hello처럼 사람이 원래 보내고 싶은 글. 암호문: 키로 변환해 놓은 데이터.
# - byte(바이트): 0~255 중 하나를 담는 작은 칸. 32바이트 키는 이런 칸 32개다.
# - AES 키: 메시지를 잠그고 다시 푸는 데 양쪽이 똑같이 사용하는 32바이트 데이터.
# - RSA의 e/d: 각각 잠그기/풀기에 쓰는 지수. n과 e를 함께 공개키로 사용한다.
# - DH의 비밀지수: 자기만 보관하는 수. 공개값을 주고받아 같은 공유 비밀을 계산한다.
# - Base64: 바이트를 전송하기 편한 글자로 표현하는 방법. 암호화가 아니다.
# - 패딩: AES가 요구하는 16바이트 묶음을 채우는 약속된 덧붙임 데이터.
#
# Python 기호 읽기:
# %는 나눗셈의 나머지다. 17 % 5는 2다. //는 정수 나눗셈으로 17 // 5는 3이다.
# **는 거듭제곱이고, pow(a, b, n)은 a의 b승을 n으로 나눈 나머지를 구한다.
# ==는 같은지 비교, !=는 다른지 비교, =는 오른쪽 값을 왼쪽 이름에 저장한다.
# and는 모든 조건이 맞아야 참, or는 하나만 맞아도 참이라는 뜻이다.
# range(3, 8)은 3~7이므로 끝 숫자는 포함하지 않는다.
# [식 for x in 목록]은 목록의 각 값을 식으로 바꿔 새 목록을 만드는 짧은 반복문이다.
#
# 중요: 아래 작은 소수와 키 반복 규칙은 수업 과제의 규격이다.
# 키가 32바이트여도 작은 DH 공유 비밀을 반복한 것이므로 256비트의 무작위 비밀이 생기지는 않는다.
from dataclasses import dataclass
from math import isqrt
import base64
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# n이 소수인지 True/False로 답한다. 소수는 1과 자기 자신으로만 나누어떨어지는 2 이상 정수다.
# 예: 7은 소수, 9는 3으로 나누어떨어지므로 합성수, 1은 소수가 아니다.
# 어떤 수가 두 약수의 곱이면 둘 중 하나는 제곱근 이하라서 그 범위까지만 검사해도 충분하다.
def is_prime(n):
    """짝수를 먼저 제외한 뒤 제곱근 이하의 홀수 약수만 검사한다."""
    if type(n) is not int or n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    # 각 나머지가 모두 0이 아니면 나누어떨어지는 약수가 없다는 뜻이다. all은 전부 참인지 묻는다.
    return all(n % d for d in range(3, isqrt(n) + 1, 2))


# 400부터 500까지 소수 후보를 모으고 하나를 무작위로 고른다.
# secrets.choice는 목록에서 하나를 고르는 도구다. 모든 정수를 소수라고 가정하지 않는다.
def generate_prime():
    # 과제에서 지정한 범위의 소수 중 하나를 무작위로 고른다.
    return secrets.choice([n for n in range(400, 501) if is_prime(n)])


# 두 수의 최대공약수, 즉 둘을 모두 나눌 수 있는 가장 큰 수를 구한다.
# 예: 12와 8 → (8, 4) → (4, 0)이므로 답은 4다.
# gcd(e, phi)=1이면 e와 phi가 1 이외의 공통 약수를 갖지 않는다는 뜻이다.
def gcd(a, b):
    while b:
        # 오른쪽을 먼저 계산하고 이름표 둘을 동시에 바꾼다. 두 번째 값이 0이 될 때까지 반복한다.
        a, b = b, a % b
    return abs(a)


# 최대공약수뿐 아니라 a*x+b*y=g가 되는 x와 y도 구하는 확장 유클리드 알고리즘이다.
# 예: a=3, b=10이면 3*7 + 10*(-2)=1이다. 여기서 x=7은 3의 mod 10 역원으로 쓸 수 있다.
# old_r/r은 나눗셈에서 남은 수들, old_x/x와 old_y/y는 그 수를 만드는 계수들이다.
# 반복할 때 나머지와 계수를 함께 갱신해서 마지막에도 같은 등식이 유지되게 한다.
def extended_gcd(a, b):
    """a*x + b*y = g를 만족하는 최대공약수 g와 베주 계수 x, y를 반환한다."""
    old_r, r, old_x, x, old_y, y = a, b, 1, 0, 0, 1
    while r:
        # 몫 q를 구하고, 큰 수에서 q번의 작은 수를 빼서 다음 나머지로 넘어간다.
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


# a와 곱했을 때 modulus로 나눈 나머지가 1이 되는 수를 찾는다.
# 예: inverse(3, 10)은 7이다. 3*7=21이고 21 % 10=1이기 때문이다.
# 최대공약수가 1이 아니면 역원이 없으므로 계산을 계속하지 않고 오류를 낸다.
def inverse(a, modulus):
    # gcd(a, modulus)=1일 때 베주 계수 x가 a의 모듈러 역원이다.
    g, x, _ = extended_gcd(a, modulus)
    if modulus <= 1 or g != 1:
        raise ValueError('modular inverse does not exist')
    # 계수 x가 음수여도 나머지를 취하면 0~modulus-1 범위의 같은 역원을 얻는다.
    return x % modulus


# n을 구성하는 서로 다른 소수 재료를 구한다.
# 예: 12=2*2*3이므로 결과는 {2, 3}이다. set은 같은 값을 중복 저장하지 않는 모음이다.
# 생성원 검사는 같은 소인수를 여러 번 검사할 필요가 없어 이런 모음을 사용한다.
def prime_factors(n):
    """생성원 검사에 필요한 서로 다른 소인수만 모아 반환한다."""
    factors = set()
    divisor = 2
    # 작은 약수부터 찾는다. 남은 n보다 제곱이 커지면 더 큰 작은-짝 약수는 없다.
    while divisor * divisor <= n:
        # 예: 12에서 2를 찾았으면 12→6→3으로 같은 약수를 전부 제거한다.
        while n % divisor == 0:
            factors.add(divisor)
            # //=는 현재 n을 divisor로 정수 나눈 결과를 다시 n에 저장한다는 줄임말이다.
            n //= divisor
        divisor += 1
    if n > 1:
        factors.add(n)
    return factors


# g가 소수 p의 나머지 세계에서 모든 1~p-1을 만들 수 있는 생성원인지 검사한다.
# 예: p=7, g=3이면 3의 거듭제곱 나머지가 3,2,6,4,5,1로 모든 수를 지난다.
# 거듭제곱을 반복해 처음 1로 돌아오는 주기를 위수라고 한다. 생성원의 주기는 p-1이다.
# 소수일 때 주기는 p-1의 약수다. 짧은 주기라면 p-1의 어떤 소인수 r에 대해
# g^((p-1)/r) mod p가 벌써 1이 되므로 이 경우를 모두 제외하면 된다.
def is_generator(g, p):
    # 소수 p에서 g의 위수가 p-1인지 확인한다.
    # p-1의 소인수 r 중 하나라도 g^((p-1)/r)=1이면 전체 군을 생성하지 못한다.
    return (is_prime(p) and type(g) is int and 1 < g < p
            and all(pow(g, (p - 1) // r, p) != 1 for r in prime_factors(p - 1)))


# 주어진 소수 p에 쓸 수 있는 생성원 후보들을 찾고 하나를 무작위로 고른다.
# 이 과제는 p가 작아서 후보를 전부 살펴봐도 빠르다. 큰 실전 소수용 설계와는 다르다.
def generate_generator(p):
    if not is_prime(p):
        raise ValueError('generator requires a prime modulus')
    return secrets.choice([g for g in range(2, p) if is_generator(g, p)])


# 관련된 숫자 다섯 개를 함께 들고 다니는 이름표 상자다.
# p,q는 비밀 소수, n=p*q는 공개할 수, e는 암호화 지수, d는 복호화 지수다.
# dataclass는 이 상자를 만드는 반복 코드를 대신 써 준다.
# frozen=True이므로 만들어진 상자의 칸을 실수로 다시 대입하지 못하게 한다.
@dataclass(frozen=True)
class RSAKey:
    p: int
    q: int
    n: int
    e: int
    d: int


# RSA 열쇠 한 쌍을 만든다. 공개키는 (n,e), 개인키 계산에는 d를 쓴다.
# 1. 서로 다른 소수 p,q를 고른다. 2. n과 phi를 계산한다.
# 3. phi와 서로소인 e를 고른다. 4. e의 mod phi 역원 d를 구한다.
# 이 과제의 평문 키 바이트는 0~255라 n보다 작다. 계산은 각 바이트마다 따로 한다.
def generate_rsa():
    """서로 다른 두 소수로 n, 공개지수 e, 개인지수 d를 만든다."""
    p, q = generate_prime(), generate_prime()
    while p == q:
        q = generate_prime()
    # 서로 다른 소수 p,q에서 phi(n)=(p-1)*(q-1)이다. RSA 지수의 역원 계산에 쓴다.
    phi = (p - 1) * (q - 1)
    # e와 phi는 서로소여야 한다. 그래야 e*d ≡ 1 (mod phi)인 d가 존재한다.
    e = 65537
    if not 1 < e < phi or gcd(e, phi) != 1:
        e = next(x for x in range(3, phi, 2) if gcd(x, phi) == 1)
    return RSAKey(p, q, p * q, e, inverse(e, phi))


# Bob이 보낸 재료와 열쇠가 과제 조건에 맞는지 확인한다.
# p,q는 범위 안의 서로 다른 소수여야 하고, e,d는 정수여야 한다.
# 마지막 e*d % phi == 1이 잠그기·풀기 지수의 짝이 맞는지 확인하는 핵심 조건이다.
def verify_rsa(p, q, e, d):
    """받은 소수 조건과 공개지수·개인지수의 역원 관계를 함께 확인한다."""
    primes_ok = (is_prime(p) and is_prime(q) and p != q
                 and 400 <= p <= 500 and 400 <= q <= 500)
    if not primes_ok or type(e) is not int or type(d) is not int:
        return False
    # 서로 다른 소수 p,q에서 phi(n)=(p-1)*(q-1)이다. RSA 지수의 역원 계산에 쓴다.
    phi = (p - 1) * (q - 1)
    return 1 < e < phi and 0 < d < phi and gcd(e, phi) == 1 and e * d % phi == 1


# AES 키를 RSA로 잠가 보내기 위한 함수다. 입력 key는 32바이트다.
# 바이트 하나를 M이라 하면 암호화 결과는 C=pow(M,e,n)이다.
# 결과는 32바이트가 아니라 정수 32개다. C는 255보다 클 수 있어서 한 바이트에 안 들어간다.
# 그래서 JSON 목록으로 보내며, 원래 키를 문자열로 바꿔 글자씩 암호화하는 방식이 아니다.
def rsa_encrypt_key(key, e, n):
    # RSA로 평문 메시지가 아닌 32바이트 AES 키를 한 바이트씩 암호화한다.
    # 결과는 바이트가 아닌 정수 32개의 목록이므로 JSON에 그대로 담는다.
    if len(key) != 32 or type(e) is not int or type(n) is not int or not 1 < e < n or n <= 255:
        raise ValueError('invalid RSA public key or AES key length')
    # key의 각 바이트를 꺼내 M^e mod n을 계산해 순서대로 목록에 넣는다.
    return [pow(byte, e, n) for byte in key]


# RSA 정수 목록 32개를 다시 AES 키 바이트 32개로 되돌린다.
# 각 C에 pow(C,d,n)을 적용해 원래 M을 얻는다. 길이와 각 값의 범위를 먼저 확인한다.
# bytes([1,2,255])는 정수 목록을 실제 바이트 데이터로 바꾼다. '1,2,255'라는 글을 만드는 게 아니다.
def rsa_decrypt_key(encrypted, d, n):
    # RSA 복호화 결과가 0~255 범위여야 원래 AES 키 바이트로 복원할 수 있다.
    if (not isinstance(encrypted, list) or len(encrypted) != 32
            or any(type(x) is not int or not 0 <= x < n for x in encrypted)):
        raise ValueError('encrypted_key must contain 32 RSA ciphertext integers')
    values = [pow(x, d, n) for x in encrypted]
    if any(x > 255 for x in values):
        raise ValueError('RSA decryption did not produce bytes')
    return bytes(values)


# DH의 비밀지수와 공개값을 한 쌍으로 만든다.
# 예를 들어 비밀지수가 a이면 공개값은 g^a mod p다. a는 숨기고 공개값만 전송한다.
# randbelow(p-2)는 0~p-3이므로 1을 더하면 과제에서 쓸 1~p-2 범위가 된다.
def dh_keypair(p, g):
    # 비밀지수는 전송하지 않고 공개값 g^private mod p만 상대에게 보낸다.
    private = secrets.randbelow(p - 2) + 1
    return private, pow(g, private, p)


# 받은 공개값과 내 비밀지수로 같은 공유 비밀을 계산한다.
# Alice는 B^a mod p, Bob은 A^b mod p를 계산한다. 둘 다 g^(ab) mod p라 값이 같다.
# pow의 세 번째 인자가 있으므로 거대한 거듭제곱 전체를 먼저 만들 필요 없이 나머지를 계산한다.
def dh_shared(public, private, p):
    # 상대 공개값을 내 비밀지수로 거듭제곱하면 양쪽 모두 g^(a*b) mod p를 얻는다.
    if type(public) is not int or not 1 <= public < p:
        raise ValueError('invalid DH public value')
    return pow(public, private, p)


# 작은 DH 공유 비밀을 교수님이 지정한 AES 키 표현으로 바꾼다.
# 예: shared=258이면 big 방식 2바이트는 0x01,0x02다. 큰 자리 숫자가 앞에 온다.
# 이 두 칸을 16번 이어 붙여 총 32칸을 만든다. 숫자 258 자체에 16을 곱하는 게 아니다.
# AES가 요구하는 키 길이를 맞추는 단계이며, DH 지수 연산을 32바이트로 하라는 뜻도 아니다.
def dh_aes_key(shared):
    # 과제 지정 규칙: 공유 비밀을 빅엔디언 2바이트로 표현하고 16번 반복한다.
    # 예: 258 → 바이트 01 02 → 01 02가 16번 반복된 32바이트. 길이는 2*16=32다.
    return shared.to_bytes(2, byteorder='big') * 16


# 사람의 글을 UTF-8 바이트로 바꾸고 과제의 평문 길이 제한을 검사한다.
# 영문 a는 1바이트, 한글 가는 3바이트다. 그래서 글자 수 len(message)로 검사하면 틀릴 수 있다.
# 예: 안녕하세요는 5글자지만 UTF-8에서는 15바이트라 허용된다.
def message_bytes(message):
    # 한글의 글자 수와 바이트 수는 다르므로 UTF-8 변환 후 길이를 검사한다.
    # encode는 글을 바이트로 표현한다. 같은 글이라도 어떤 문자 인코딩인지 약속해야 한다.
    data = message.encode('utf-8')
    if len(data) > 16:
        raise ValueError('message must be at most 16 UTF-8 bytes')
    return data


# 평문을 AES로 잠근 뒤 JSON에 넣을 수 있는 Base64 글로 돌려준다.
# AES-256에서 256은 키 길이 256비트=32바이트다. AES 블록 크기는 별개로 16바이트다.
# 예: hello는 5바이트라 패딩 숫자 11을 11칸 붙인다. 정확히 16바이트도 패딩 블록을 하나 붙인다.
# ECB는 블록마다 같은 키로 변환하는 과제 지정 모드다.
def encrypt_message(key, message):
    """평문 → UTF-8 바이트 → PKCS#7 패딩 → AES 암호문 → Base64 문자열."""
    if len(key) != 32:
        raise ValueError('AES key must be 32 bytes')
    # 정확히 16바이트인 평문에도 패딩 블록을 붙여 복호화 시 끝을 구별한다.
    # 안쪽부터 평문 바이트화, 16칸 패딩, AES 암호화 순서다. AES 내부 라운드는 라이브러리가 처리한다.
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(message_bytes(message), 16))
    # b64encode의 결과도 바이트다. decode로 Python 문자열을 만들어 JSON 칸에 넣을 수 있게 한다.
    return base64.b64encode(encrypted).decode('ascii')


# 암호문을 반대 순서로 풀어 원래 글을 얻는다.
# Base64 해제 → AES 복호화 → 패딩 제거 시도 → UTF-8 글로 변환 순서다.
# 현재 수정본은 패딩 오류 시에도 복호화 데이터를 그대로 사용하는 호환 동작을 한다.
# 따라서 아래 except는 '모든 데이터의 정상 여부를 검증했다'는 뜻이 아니다.
# 이번 작업은 주석 추가이므로 그 호환 동작을 그대로 유지한다.
def decrypt_message(key, encoded):
    """Base64를 풀고 복호화한 뒤 패딩을 검증·제거하여 원래 문자열을 얻는다."""
    if len(key) != 32 or not isinstance(encoded, str):
        raise ValueError('invalid AES key or ciphertext')
    # Base64를 원래 암호문 바이트로 되돌린다. validate=True는 허용되지 않는 문자를 거부한다.
    encrypted = base64.b64decode(encoded, validate=True)
    if not encrypted or len(encrypted) % 16:
        raise ValueError('AES ciphertext length must be a positive multiple of 16')
    decrypted = AES.new(key, AES.MODE_ECB).decrypt(encrypted)
    try:
        # 끝에 적힌 패딩 길이와 실제 덧붙인 값이 맞는지 검사하고 그 부분만 떼어 낸다.
        data = unpad(decrypted, 16)
    except ValueError:
        # 교수님 예제(aes_bob.py)는 16글자 메시지에 패딩을 붙이지 않는다.
        # PKCS#7 패딩이 맞지 않으면 패딩 없는 평문으로 보고 그대로 사용한다.
        # 주의: 현재 코드의 호환 처리다. 패딩이 틀렸다는 이유로 거부하지 않고 원시 데이터를 사용한다.
        data = decrypted
    # 마지막에 바이트를 사람이 읽는 글로 복원한다. UTF-8로 해석할 수 없으면 오류가 난다.
    return data.decode('utf-8')
