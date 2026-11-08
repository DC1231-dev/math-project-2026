# Project 1: Alice / Bob 암호화 통신

Protocol I~IV와 RSA·DH 로그 복호화 도구를 구현했다. Python 3.10 이상을 사용한다.

## 설치와 실행

이 문서와 `alice.py`, `bob.py`가 있는 `Project1_Submission` 폴더에서 실행한다.

```bash
python3 -m pip install -r requirements.txt
python3 -c "from Crypto.Cipher import AES; print('AES OK')"
```

설치 패키지는 `pycryptodome`, 코드에서 사용하는 모듈 이름은 `Crypto`다. 소문자 `crypto` 또는 `AES`라는 별도 패키지를 설치하는 것으로 대체할 수 없다. 설치 기록은 있지만 import가 실패하면 동일 환경에 설치된 `crypto`와의 충돌을 확인한다.

### Bob 실행 (첫 번째 터미널)

```bash
python3 bob.py --port 6666 --message "Hello from Bob"
```

Bob은 계속 접속을 받는다. 중지하려면 Ctrl+C를 누른다. 기본 바인딩은 `0.0.0.0`이고, 자신의 컴퓨터에서만 실습하려면 `--addr 127.0.0.1`을 추가한다.

### Alice 실행 (두 번째 터미널)

각 명령은 별도의 연결로 실행된다. Bob을 먼저 실행한다.

```bash
# I: RSA 키 쌍 생성 및 검증
python3 alice.py --addr 127.0.0.1 --port 6666 --protocol RSAKey

# II: RSA로 AES 키 전달 후 양방향 메시지 교환
python3 alice.py --addr 127.0.0.1 --port 6666 --protocol RSA --message "Hello Alice"

# III: DH로 AES 키 합의 후 양방향 메시지 교환
python3 alice.py --addr 127.0.0.1 --port 6666 --protocol DH --message "안녕하세요"
```

다른 컴퓨터에 연결할 때는 `127.0.0.1` 대신 Bob 컴퓨터의 IP를 입력하고 해당 포트의 접속을 허용한다. `--message`는 키가 아니라 암호화할 평문이다. UTF-8 기준 최대 16바이트이며, 한글은 보통 한 글자당 3바이트다. 빈 문자열도 `--message ""`로 입력할 수 있다.

각 프로그램은 보내고 받은 JSON과 `Decrypted:` 결과를 출력한다. RSAKey 결과는 `correct=True`로 검증 성공을 표시한다. Alice의 오류는 종료 코드 1, 잘못된 명령행은 종료 코드 2로 표시한다.

### IV: 오류 처리 시연

기존 Bob을 중지한 뒤 아래 명령 중 하나로 다시 실행하고 Alice의 DH 명령을 실행한다.

```bash
python3 bob.py --port 6666 --message "Bob" --dh-error prime
python3 bob.py --port 6666 --message "Bob" --dh-error generator
```

- `prime`: Bob이 `p=403`을 전송. Alice가 `opcode=3`, `incorrect prime number`를 전송하고 종료.
- `generator`: Bob이 정상 소수와 `g=1`을 전송. Alice가 `opcode=3`, `incorrect generator`를 전송하고 종료.
- Bob은 받은 오류를 출력하고 해당 연결을 닫는다. 이후 접속도 계속 받지만 오류 시연 옵션은 재시작할 때까지 유지된다.
- 정상 모드는 `--dh-error none`이며 기본값이다.

## 파일별 기능

| 파일 | 기능 |
|---|---|
| `alice.py` | 요청, RSA 키 검증, DH 파라미터 검증, 키 합의 및 AES 교환 |
| `bob.py` | 요청별 서버 처리, 키 생성, 오류 시연, AES 교환 |
| `crypto_math.py` | 소수·생성원·역원·RSA·DH 연산과 AES/Base64/패딩 |
| `wire.py` | 분할 수신과 연속 JSON을 처리하는 공통 통신 모듈 |
| `attacker.py` | 제공 로그의 RSA 소인수분해 또는 DH 지수 탐색 |
| `test_project.py` | 수학, 경계값, 오류, 독립 상대, 로컬 TCP, 공격 로그 검증 |

RSA·DH 수학 함수는 직접 구현했고 모듈러 거듭제곱은 Python의 `pow`를 사용한다. AES와 PKCS#7 패딩은 PyCryptodome을 사용한다.

## 통신 규격과 호환성

- 최초 요청은 `opcode=0`, `type=RSAKey|RSA|DH`다.
- Protocol I 응답은 슬라이드 3에 따라 **opcode 0**이다. `public=e`, `private=d`, `parameter={p,q}`를 보낸다. 이는 키 검증 실습용 프로토콜이다.
- Protocol II 공개키 응답은 `opcode=1`, `type=RSA`, `public=e`, `parameter={n}`이다. 키 전송은 `opcode=2`, `type=RSA`, `encrypted_key=[정수 32개]`다.
- DH 응답은 `opcode=1`, `type=DH`, `public=정수`, Bob의 응답에만 `parameter={p,g}`가 있다.
- AES 메시지는 `opcode=2`, `type=AES`, `encryption=Base64 문자열`이다.
- DH 키는 `shared.to_bytes(2, byteorder="big") * 16`으로 32바이트를 만든다.
- JSON 객체를 별도 헤더나 필수 줄바꿈 없이 전송한다. 수신 파서가 객체 경계를 구분하고 나머지 데이터를 보존한다. ASCII 이스케이프 송신, UTF-8 수신을 지원한다.
- 메시지는 64KiB 이하, 객체 하나를 기다리는 시간은 최대 10초다. 잘못된 입력·연결 종료 시 현재 연결을 닫는다.
- AES는 과제의 ECB 256-bit 조건을 따른다. UTF-8 바이트에 PKCS#7 패딩을 적용하므로 정확히 16바이트인 입력은 암호문이 32바이트가 된다.

이 제출용 폴더에는 실행 코드·테스트·공격용 원본 로그·설명서만 포함했다. 강의자료, 학습 예제, 개발 캐시, 별도 베이즈 과제는 제외했다.

평가용 프로그램은 아직 직접 시험하지 않았다. 슬라이드 일부의 Base64 공개키 설명 및 opcode 일반 표와 상세 흐름이 다르므로, 상세 흐름과 실제 제공 로그의 정수 형식을 기준으로 구현했다. 평가 프로그램이 나오면 opcode, 공개키 표현, 패딩 규칙을 대조한다. 예제의 16바이트 입력 패딩 결함은 복제하지 않았다.

이 프로그램은 작은 소수, ECB, 인증되지 않은 DH를 사용하는 수업 실습이다. 실제 서비스의 암호화 구현으로 사용하지 않는다.

## 추가 점수: 로그 복호화

```bash
python3 attacker.py --protocol RSA --logfile adv_protocol_two-prob-1.log
python3 attacker.py --protocol DH --logfile adv_protocol_three-prob-1.log
```

RSA에서는 공개된 n을 소인수분해하고 phi와 개인키 d를 계산하여 AES 키를 복원한다. DH에서는 공개값에 대응하는 지수를 전수 탐색하고 공유 비밀을 복원한다. 결과에는 계산 근거, 복원 키, 로그의 모든 평문이 포함된다. 각 암호문은 복호화 후 재암호화하여 원본과 같은지 확인한다. 입력 로그는 변경하지 않는다.

강의자료상 한 공격 성공 시 가산점 1점, 두 공격을 모두 해도 최대 1점이다. 추가 공지의 제출·시연 조건은 별도로 확인한다.

## 검증

```bash
python3 -m unittest -v test_project
```

테스트는 소수 범위 전체 및 모든 소수 쌍의 RSA 바이트 왕복, 생성원 전수 비교, DH 합의, AES 0·1·15·16바이트와 한글, 17바이트 거부, 잘못된 패딩, JSON 분할·연속 수신, 수신 제한·시간 초과·조기 종료를 확인한다. 독립 상대 코드는 본체의 수학·통신 도우미를 사용하지 않고 Alice/Bob을 각각 검증한다. 제공 로그 12개의 평문도 기대값과 비교한다.

두 컴퓨터 간 통신, 교수 평가 프로그램과의 통신은 별도 시연이 필요하다. 자동 테스트 성공이 이 두 항목의 확인을 대신하지 않는다.

## 역할 분담과 GitHub 기록

아래는 제안 역할표이며 실제 이름과 검토 기록을 팀이 채워야 한다. 자동 생성한 코드를 팀원별 실제 기여로 간주하거나 검토 기록을 꾸며 쓰지 않는다.

| 담당 | 이름 | 맡을 부분 | 검토 |
|---|---|---|---|
| 팀원 A | 미지정 | 수학·암호 모듈과 로그 공격 원리 이해 및 보완 | 통신 흐름 검토 |
| 팀원 B | 미지정 | 통신·프로토콜·실행 환경 이해 및 보완 | 수학·공격 결과 검토 |
| 공동 | 두 사람 | 실제 통신, 평가 프로그램 검증, 인터뷰 | 전체 흐름 설명 |

- [ ] 각자 담당 코드와 수정 사항을 이해하고 역할표에 이름 기입.
- [ ] GitHub에 실제 변경 단위로 커밋하고 상대방 검토 기록 남기기.
- [ ] 두 컴퓨터에서 정상·오류 시나리오 실행.
- [ ] 평가 프로그램과 양쪽 역할로 통신.
- [ ] 추가 과제 공지와 제출 방식 확인.

이 작업에서는 GitHub에 커밋·푸시·이슈 작성은 하지 않는다. 변경 내용과 검증 결과를 검토한 뒤 팀이 실제 작업 기록으로 관리한다.

## 인터뷰 준비

1. **RSA의 d는 어떻게 구하는가?** phi와 e가 서로소이므로 확장 유클리드 알고리즘으로 e의 모듈러 역원을 구한다.
2. **생성원은 어떻게 확인하는가?** p-1의 각 서로 다른 소인수 r에 대해 g^((p-1)/r) mod p가 1이 아닌지 확인한다.
3. **DH에서 왜 같은 키인가?** B^a와 A^b가 모두 g^(ab) mod p이기 때문이다. 비밀 지수 자체는 전송하지 않는다.
4. **RSA와 DH의 역할은?** RSA는 AES 키를 암호화해 전달하고, DH는 양쪽이 같은 AES 키 재료를 계산한다.
5. **Base64는 암호화인가?** 바이트를 JSON 문자열로 표현하는 인코딩이며 누구나 디코딩할 수 있다.
6. **왜 입력 길이와 키 길이가 다른가?** AES 키는 32바이트, 블록은 16바이트이고 이 과제 평문 제한은 16바이트다.
7. **왜 공격이 가능한가?** 과제의 소수 범위가 작아 RSA 소인수분해와 DH 이산 로그 전수 탐색이 빠르게 끝난다.
8. **JSON 분할 수신을 왜 처리하는가?** TCP는 바이트 스트림이므로 send 한 번과 recv 한 번이 항상 대응하지 않는다.
