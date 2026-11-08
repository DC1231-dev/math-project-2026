# Project 1: Alice / Bob 암호화 통신

EL2001 Mathematical Foundation of Computer Science, Project 1-1.
Protocol I~IV(RSA 키 생성, RSA 키 전달, DH 키 교환, DH 오류 처리)와 추가 과제(RSA·DH 도청 공격)를 구현했다. Python 3.10 이상을 사용한다.

## 팀 구성과 역할

| 이름 | 담당 |
|---|---|
| 유희선 | 초기 구현 전체: `crypto_math.py`, `wire.py`, `alice.py`, `bob.py`, `attacker.py`, `test_project.py`, 문서 초안, 주석 추가 |
| 신동찬 | 검토 및 수정: 강의자료·교수님 예제·공지와의 호환성 대조, AES 패딩 호환성 수정과 테스트 추가, 문서 정리, 테스트 서버 통신 확인 |
| 공동 | 두 컴퓨터 간 통신 시연, 인터뷰 준비 |

## 설치

이 문서와 `alice.py`, `bob.py`가 있는 폴더에서 실행한다.

```bash
python3 -m pip install -r requirements.txt
python3 -c "from Crypto.Cipher import AES; print('AES OK')"
```

설치 패키지는 `pycryptodome`이고 코드의 모듈 이름은 `Crypto`다. 강의자료의 `pycrypto`와 같은 `Crypto` 인터페이스를 쓴다.

## 교수님 테스트 서버 접속 (Alice 역할)

1. 웹브라우저로 `vpn.kentech.ac.kr`에 접속하여 KENTECH 계정으로 로그인한다.
2. 프로토콜에 맞는 포트로 Alice를 실행한다.

```bash
python3 alice.py --addr 10.41.12.51 --port 5551 --protocol RSAKey                   # Protocol I
python3 alice.py --addr 10.41.12.51 --port 5552 --protocol RSA --message "world"    # Protocol II
python3 alice.py --addr 10.41.12.51 --port 5553 --protocol DH  --message "world"    # Protocol III
python3 alice.py --addr 10.41.12.51 --port 5554 --protocol DH  --message "world"    # Protocol IV
```

- `--protocol`은 포트와 맞춰 직접 지정한다. Protocol IV도 `DH`다.
- RSA·DH에는 `--message`가 필요하다. 평문은 UTF-8 기준 최대 16바이트이며 한글은 보통 한 글자에 3바이트다.
- 교수님 Bob은 Protocol II·III에서 `hello`를 AES로 암호화해 먼저 보낸다. 정상이면 `Decrypted: hello`가 출력된다.
- Protocol IV에서는 `incorrect prime number` 또는 `incorrect generator`를 보내고 종료한다. 이때 종료 코드 1은 정상 동작이다.
- 응답이 없으면 VPN·방화벽 문제일 수 있다.

## 우리 Bob 실행 (서버 역할)

```bash
python3 bob.py --port 6666 --message "hello"
python3 alice.py --addr 127.0.0.1 --port 6666 --protocol RSAKey
python3 alice.py --addr 127.0.0.1 --port 6666 --protocol RSA --message "world"
python3 alice.py --addr 127.0.0.1 --port 6666 --protocol DH  --message "world"
```

- Bob은 기본으로 `0.0.0.0`에 바인딩하고 계속 접속을 받는다. Ctrl+C로 중지한다.
- 다른 컴퓨터에서 접속할 때는 Bob 컴퓨터의 IP(`ifconfig` / `ipconfig`)를 사용하고 방화벽에서 포트를 허용한다.
- Protocol IV 시연은 Bob을 다음 옵션으로 다시 실행한다.

```bash
python3 bob.py --port 6666 --message "hello" --dh-error prime       # p=403(=13×31) 전송
python3 bob.py --port 6666 --message "hello" --dh-error generator   # 정상 소수와 g=1 전송
```

## 파일별 기능

| 파일 | 기능 |
|---|---|
| `crypto_math.py` | 소수 판별, 최대공약수·확장 유클리드·모듈러 역원, 생성원 판별, RSA·DH 연산, AES/Base64/패딩 |
| `wire.py` | TCP 스트림에서 JSON 객체를 하나씩 송수신하는 공통 통신 모듈 |
| `alice.py` | 클라이언트: 요청, RSA 키 검증, DH 파라미터 검증, 키 합의, AES 메시지 교환 |
| `bob.py` | 서버: 요청별 키 생성, DH 오류 시연, AES 메시지 교환 |
| `attacker.py` | 제공 로그에서 RSA 소인수분해 또는 DH 지수 전수 탐색으로 평문 복원 |
| `test_project.py` | 수학, 경계값, 오류, 독립 상대, 로컬 TCP, 공격 로그 자동 검증 |

RSA·DH 수학 함수는 직접 구현했고 모듈러 거듭제곱은 Python의 `pow`를 사용한다. AES와 PKCS#7 패딩은 PyCryptodome을 사용한다.

## 프로토콜 요약

| 프로토콜 | 메시지 흐름 | 핵심 계산 |
|---|---|---|
| I (RSAKey) | A→B `opcode 0` 요청 / B→A `opcode 0`, `public=e`, `private=d`, `parameter={p,q}` | Alice가 p·q 소수 여부(400~500), `gcd(e,φ)=1`, `e·d mod φ = 1` 검증 후 `correct=True/False` 출력 |
| II (RSA) | 요청 / B→A `opcode 1`, `public=e`, `parameter={n}` / A→B `opcode 2`, `encrypted_key=[정수 32개]` / B→A AES / A→B AES | 32바이트 세션키를 한 바이트씩 `c = k^e mod n`, Bob은 `k = c^d mod n` |
| III (DH) | 요청 / B→A `opcode 1`, `public=B`, `parameter={p,g}` / A→B `opcode 1`, `public=A` / B→A AES / A→B AES | 공유 비밀 `B^a = A^b = g^(ab) mod p`, AES 키 `shared.to_bytes(2,'big') * 16` |
| IV (DH 오류) | B→A에 비소수 p 또는 비생성원 g / A→B `opcode 3`, `error` 후 종료 | 소수 검사를 먼저 하고, `p-1`의 모든 소인수 r에 대해 `g^((p-1)/r) ≠ 1 (mod p)`로 생성원 판별 |

AES 메시지는 `opcode 2`, `type AES`, `encryption=Base64 문자열`이다. 키가 준비된 뒤의 AES 교환 코드는 Protocol II·III가 공통으로 사용한다(`alice.py` `exchange()` 마지막 부분, `bob.py` `exchange()` 마지막 부분).

## 통신 규격과 호환성

- 공개키는 제공 로그와 같이 정수로 주고받는다. Protocol IV 그림의 Base64 공개키 표기는 교수님 공지에서 "하지 않아도 된다"고 정정되었다.
- Protocol I 응답 opcode는 슬라이드 3에 따라 0으로 구현했다. 메시지 표의 일반 규칙(키 메시지는 1)과 다르므로 테스트 서버로 확인한다.
- JSON 객체를 별도 헤더나 줄바꿈 없이 전송한다. 수신 측은 객체 경계를 직접 구분하고 남은 데이터를 다음 수신에 사용한다. 송신은 ASCII 이스케이프 JSON이다.
- 메시지는 64KiB 이하, 객체 하나의 수신 대기는 최대 10초다. 잘못된 입력이나 연결 종료 시 해당 연결을 닫는다.
- AES는 ECB 256-bit다. 송신 시 UTF-8 바이트에 PKCS#7 패딩을 적용하며, 교수님 예제의 복호화 방식으로도 풀린다.
- 수신 시 PKCS#7 패딩이 맞지 않으면 패딩 없는 평문으로 보고 그대로 사용한다. 교수님 예제(`aes_bob.py`)는 `pad = 16 - len(msg)`이므로 16글자 메시지에 패딩이 붙지 않기 때문이다.

이 프로그램은 작은 소수, ECB, 인증되지 않은 DH를 사용하는 수업 실습이며 실제 서비스용 암호 구현이 아니다.

## 추가 과제: 로그 복호화

```bash
python3 attacker.py --protocol RSA --logfile adv_protocol_two-prob-1.log
python3 attacker.py --protocol DH  --logfile adv_protocol_three-prob-1.log
```

- RSA: 공개된 n을 √n 이하의 수로 나누어 p, q를 찾고 φ와 d를 계산해 AES 키를 복원한다.
- DH: `g^a mod p = A`를 만족하는 a를 1부터 p-1까지 전수 탐색하고 `B^a mod p`로 공유 비밀을 복원한다.
- 복원한 키로 로그의 모든 AES 메시지를 복호화하고, 다시 암호화해 원본 암호문과 같은지 확인한다. 입력 로그는 변경하지 않는다.

강의자료상 한 공격 성공 시 가산점 1점, 두 공격 모두 해도 최대 1점이다.

## 검증

```bash
python3 -m unittest -v test_project
```

18개 테스트로 다음을 확인한다: 400~500 소수 전수 판별, 모든 소수 쌍의 RSA 바이트 왕복, 생성원 전수 비교, DH 합의, AES 0·1·15·16바이트와 한글, 17바이트 거부, 잘못된 Base64·길이 거부, 패딩 없는 16바이트(교수님 예제 방식) 복호화, JSON 분할·연속 수신, 수신 제한·시간 초과·조기 종료, 독립 상대 코드와의 통신, 제공 로그 12개의 평문.

자동 테스트는 교수님 테스트 서버와의 통신이나 두 컴퓨터 간 통신을 대신하지 않는다.

## 평가 전 확인 목록

- [ ] VPN 접속 후 테스트 서버 5551~5554에 각각 Alice로 접속해 결과 확인
- [ ] 두 컴퓨터 사이에서 우리 Bob/Alice 정상·오류 시나리오 실행
- [ ] GitHub에 작업 단위별 커밋 기록 관리
- [ ] 두 사람 모두 전체 흐름과 인터뷰 문항 설명 연습

## 인터뷰 준비

1. **RSA의 d는 어떻게 구하는가?** φ와 e가 서로소이므로 확장 유클리드 알고리즘으로 `e·d ≡ 1 (mod φ)`인 d를 구한다.
2. **생성원은 어떻게 확인하는가?** p-1의 각 서로 다른 소인수 r에 대해 `g^((p-1)/r) mod p`가 1이 아닌지 확인한다. g의 위수는 p-1의 약수이므로, 위수가 p-1보다 작으면 어떤 r에서 반드시 1이 된다.
3. **왜 소수 검사를 먼저 하는가?** 위 생성원 판별법은 p가 소수일 때만 성립한다.
4. **DH에서 왜 같은 키가 나오는가?** `B^a = (g^b)^a = g^(ab) = (g^a)^b = A^b`이다. 비밀 지수 a, b는 전송하지 않는다.
5. **RSA 복호화는 왜 원래 값을 돌려주는가?** `ed = 1 + tφ`이고 오일러 정리 `k^φ ≡ 1 (mod n)`에 의해 `c^d = k^(ed) ≡ k`다. 바이트 값(0~255)이 n보다 작으므로 정확히 복원된다.
6. **RSA와 DH의 역할 차이는?** RSA는 Alice가 만든 AES 키를 암호화해 전달하고, DH는 양쪽이 각자 같은 키를 계산한다.
7. **Base64는 암호화인가?** 바이트를 JSON 문자열로 표현하는 인코딩이며 누구나 디코딩할 수 있다.
8. **왜 공격이 가능한가?** 소수 범위가 400~500으로 작아 n의 소인수분해와 DH 이산 로그 전수 탐색이 즉시 끝난다.
9. **JSON 분할 수신을 왜 처리하는가?** TCP는 바이트 스트림이므로 send 한 번과 recv 한 번이 항상 대응하지 않는다.
