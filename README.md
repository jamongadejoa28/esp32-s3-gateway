# MESTIO 게이트웨이 (ESP32-S3)

Waveshare **ESP32-S3-ETH-8DI-8RO** 보드에서 동작하는 MESTIO 게이트웨이 펌웨어와 내장 웹 UI입니다.
RS485(Modbus RTU)로 **MEX150** 항온항습기 컨트롤러와 통신하고, 웹 대시보드와 SNMP v1/v2c/v3로
상태·경보·설정값을 제공합니다.

- 펌웨어: ESP-IDF **v6.1**, W5500 이더넷, 복구용 Wi-Fi SoftAP, LittleFS, OTA(롤백 지원)
- 웹 UI: 순수 HTML·CSS·JavaScript SPA(LittleFS 저장, gzip 256 KiB 초과 시 검토 경고), 실시간 차트 대시보드, 한국어/영어, 라이트/다크
- SNMP: MIB-II system + 엔터프라이즈 MIB(`MESTIO-GW-MIB`), 트랩/인폼, 외부 통합관제 연동용 확장 구조

상세 문서: [DESIGN](docs/DESIGN.md) · [ARCHITECTURE](docs/ARCHITECTURE.md) · [API](docs/API.md) ·
[SNMP](docs/SNMP.md) · [HW_TEST](docs/HW_TEST.md) · [DECISIONS](docs/DECISIONS.md) · [계획(원문)](docs/PLAN.ko.md)

## 1. 하드웨어 배선

| 게이트웨이 | MEX150 / 설정 |
|---|---|
| RS485 **A** | **TRX+** |
| RS485 **B** | **TRX−** |
| GND (가능하면) | 신호 GND, 차폐 연선 사용 |
| **120 Ω 종단 점퍼** | **ON** (버스 양 끝단에만. 전원 OFF 상태에서 A–B 간 약 60 Ω이면 양단 종단 정상) |
| 통신 설정 | 9600 bps 8N1, 슬레이브 1 (MEX150 패널과 일치시킬 것) |

보드 핀: RS485 UART1 TX 17 / RX 18(자동 방향 전환, DE 없음), W5500 SPI 13/14/15/16, INT 12, RST 39,
RTC(PCF85063) I²C 42/41, 상태 LED(WS2812) 38, BOOT 버튼 0. DI1–8과 릴레이(TCA9554)는 사용하지 않으며
구동하지 않습니다.

## 2. 초기 접속

| 항목 | 기본값 |
|---|---|
| IP | **192.168.10.150** / 255.255.255.0, GW·DNS 192.168.10.1 (DHCP 꺼짐) |
| 웹 계정 | **admin / mestio150!** — 첫 로그인 시 비밀번호 변경 강제(변경 전에는 다른 API 사용 불가) |
| 비밀번호 정책 | 10–64자, 4종류 중 3종 이상, 아이디·초기값·이전 비밀번호와 달라야 함 |
| 호스트명 | `mestio-gw-XXXX` (MAC 끝 2바이트). mDNS는 없음, DHCP/DNS에 등록된 경우만 이름 접속 |
| 계정 | 최대 4개, 역할 admin / operator(설정값·운전·경보확인) / viewer |

PC를 192.168.10.0/24(예: 192.168.10.20)로 설정한 뒤 `http://192.168.10.150/`에 접속합니다.

## 3. 복구 AP와 BOOT 버튼

| 동작 | 결과 |
|---|---|
| BOOT **3–8초** 누름 | 복구 AP 시작 |
| 이더넷 링크/IP 없이 **120초** 경과 | 복구 AP 자동 시작 (`fallback_after_s`로 변경 가능) |
| BOOT **10초 이상** 누름 후 놓음 | 공장 초기화 (10초에 LED 빨강 고정, 놓을 때 실행. 8–10초 사이에 놓으면 취소) |

- SSID `MESTIO-GW-XXXX`, WPA2/WPA3. **PSK는 기기마다 무작위**이며, 바꾸기 전까지 부팅 시 USB 시리얼 콘솔에
  출력됩니다(공장 초기화 후에도 유지, 제품 라벨용).
- AP 주소 `http://192.168.150.1/`, 최대 2대, 마지막 단말이 나간 뒤 15분 후 자동 종료.
  AP 단말은 IP 허용목록과 무관하게 접속할 수 있습니다.
- 네트워크 설정 변경은 120초 안에 새 주소에서 "확인"하지 않으면 이전 설정으로 되돌아갑니다.
- 공장 초기화는 웹(관리자 비밀번호 + `RESET` 입력, 네트워크 유지 옵션)과 USB 콘솔
  `factory-reset --yes`로도 가능합니다.

## 4. 빌드

### VS Code (ESP-IDF 확장 v6.1)
1. ESP-IDF 확장 설치 후 이 폴더를 엽니다. `.vscode/settings.json`이 IDF 경로
   (`/home/hajun/esp-idf-v6.1/v6.1/esp-idf`), 도구 루트 `/home/hajun/.espressif`, 대상 `esp32s3`,
   프로젝트 `.venv`, Node v24 PATH를 지정합니다. 설정 변경 후에는 **Developer: Reload Window**를 실행합니다.
2. 확장의 **Build** 버튼 또는 작업 **GW: build (IDF 6.1)** 실행. 웹 UI는 CMake 빌드 중에 자동으로 번들링되어
   별도 LittleFS 이미지로 생성됩니다(Node v24는 개발 PC의 빌드에만 필요).
3. 플래시는 수동: 확장의 Flash(UART, 포트 직접 선택) 또는 작업 **GW: HARDWARE flash + monitor**
   (`tools/run_device.py --port <포트> --yes`, 두 옵션이 모두 있어야 실행).

### CLI
```sh
uv sync --locked                                   # 최초 1회 (.venv, LittleFS 이미지 도구 포함)
npm ci                                             # 웹 빌드 도구 설치
uv run --locked python tools/idf.py build          # → mestio_gw.bin + web.bin + mestio_gw.gwota
uv run --locked python tools/idf.py size
```
앱 슬롯은 각각 2.5 MiB이고, 각 슬롯 뒤의 512 KiB LittleFS(`web_0`, `web_1`)에 웹 파일을 저장합니다.
`data` 파티션의 위치·크기는 유지합니다. 실제 앱 크기는 빌드 출력 또는 `idf.py size`로 확인합니다.
웹 파일은 1 KiB 버퍼로 스트리밍하며 전체 자산을 PSRAM에 복사하지 않습니다. Node.js는 ESP32나
사용자 브라우저에서 실행되지 않습니다. 화면 구성·차트는 사용자 브라우저에서 실행됩니다.

**기존 펌웨어에서 최초 전환:** 파티션 테이블이 바뀌므로 USB로 전체 `flash`를 한 번 실행해야 합니다.
기존 OTA 웹페이지에 새 `.bin`/`.gwota`를 올리는 방식으로는 파티션을 전환할 수 없습니다.
`flash`에는 새 파티션 테이블·앱·양쪽 웹 이미지가 포함되며 `data`/NVS를 지우는 erase-flash는 필요 없습니다.
실제 장치 작업은 사용자가 수동 실행합니다. 이후 웹 업데이트에는 **`build/mestio_gw.gwota`**를 선택합니다.
앱과 웹을 비활성 슬롯 쌍에 기록·검증한 다음 부팅 슬롯을 바꾸므로 자동/수동 롤백 시 이전 웹도 선택됩니다.
독립 `.bin` 업로드는 웹과 백엔드 버전 불일치를 막기 위해 거부합니다.

## 5. 웹 개발 (모의 서버)

```sh
export PATH=$HOME/.nvm/versions/node/v24.15.0/bin:$PATH
npm ci
npm run build:web                                  # web/dist + gzip 크기 보고(256 KiB 초과 경고)
node tools/mock_server.mjs --port 8080             # http://127.0.0.1:8080, 초기 계정 admin/mestio150!
node tools/mock_server.mjs --dev --ready           # 소스 직접 서빙, admin 비밀번호 Mestio-Admin#2026
node tools/mock_server.mjs --proxy http://192.168.10.150   # /api, /ws를 실제 장비로 전달
```
모의 서버는 `regmap.def`/`alarm_catalog.def`를 그대로 읽고 모든 요청을 JSON 스키마(`docs/api/`)로
검증하며, 통신 끊김·경보·OTA·로그 등을 펌웨어와 같은 규칙으로 흉내 냅니다.
옵션: `--devices 1..4`, `--time-invalid`, `--no-comm-loss`, `--no-faults`, `--coredump`, `--seed N`.

## 6. 테스트

```sh
uv run --locked pytest -q            # 호스트 C/파이썬 테스트 + API 계약 + 모의 서버 (1236개)
npm test                             # 웹 단위 테스트 (65개)
uv run --locked python tools/hw_smoke.py --url http://127.0.0.1:8080   # 모의 서버 대상 E2E (127개 항목)
```
실제 장비 시험은 [docs/HW_TEST.md](docs/HW_TEST.md) 체크리스트를 따릅니다(`hw_smoke.py`,
`snmp_smoke.py`는 네트워크만 사용). 비밀번호는 명령행이 아닌 `GW_PASSWORD`/`GW_NEW_PASSWORD`
환경변수로 전달하십시오.

## 7. SNMP 연동 요약

- 기본 **비활성**. 웹 설정 → SNMP에서 켜고, 보안 설정의 서비스 `snmp`도 켜야 응답합니다.
- v1/v2c: RO 커뮤니티를 먼저 정해야 활성화 가능, RW 커뮤니티가 비어 있으면 SET 불가.
  v3: `gwmonitor`(RO), `gwadmin`(RW), authPriv SHA/AES 전용, 패스프레이즈 8–64바이트.
- 트랩/인폼은 v1/v2c(lwIP 제약으로 v3 트랩 없음). 기본 트랩 커뮤니티 `mestio-trap`.
  경보 발생/해제, 통신 끊김/복구, 설정 변경, 펌웨어 갱신, 콜드스타트, 인증 실패, 시험 트랩.
- 엔터프라이즈 OID 루트 `1.3.6.1.4.1.<PEN>.1`. **PEN 32473은 RFC 5612 문서용 임시값**입니다.
  실사용 전 IANA PEN을 받아 `CONFIG_GW_SNMP_ENTERPRISE_PEN`(menuconfig)을 바꾸고 다시 빌드하십시오
  (엔진 ID와 MIB도 함께 바뀜, 절차는 [SNMP.md §7](docs/SNMP.md)).
- **MIB 다운로드**: 웹 설정 → SNMP → "MIB 다운로드" 또는 `GET /api/v1/snmp/mib`(빌드와 PEN에 맞는 사본).
  기본 PEN 사본: [docs/mib/MESTIO-GW-MIB.txt](docs/mib/MESTIO-GW-MIB.txt).
- 확장(새 테이블·알림 추가) 방법과 OID 전체 목록은 [docs/SNMP.md](docs/SNMP.md)를 참조하십시오.

## 8. 보안 참고

- 웹은 **HTTP 전용**(TLS 없음). 신뢰할 수 있는 관리망에서만 사용하고, 필요하면 IP 허용목록(최대 8개 CIDR,
  웹과 SNMP 모두 적용)을 설정하십시오.
- 비밀번호 PBKDF2-HMAC-SHA256(10,000회), 세션 쿠키 `HttpOnly; SameSite=Strict`, 유휴 15분(5–120)·절대 12시간.
- 모든 변경 요청에 CSRF 토큰 + Origin/Referer 검사, Host 허용목록(DNS 리바인딩 방지, 위반 시 421).
- 로그인 제한: IP·대상 계정별 5분 내 5회 실패 시 5분 잠금(반복 시 최대 30분까지 2배).
- 로그인 전 응답에는 모델·버전·MAC·호스트명 등 장비 정보가 없습니다.
- 감사 로그(로그인, 계정 변경, 설정 변경, 레지스터 쓰기, OTA, 재부팅, 초기화)와 syslog(RFC 5424) 전송.
- 난수: HMAC_DRBG-SHA256, 부팅 시 ADC 엔트로피로 시드 + 하드웨어 RNG 혼합.
- **OTA 이미지는 서명되지 않습니다**(v1 수용 위험). SHA-256 무결성, 프로젝트명, 버전(다운그레이드 거부)만
  확인하므로 관리자 계정 보호가 곧 펌웨어 보호입니다. 부팅 후 60초간 정상이어야 확정되며, 아니면 이전
  이미지로 롤백합니다.

## 9. 알려진 제한 사항

- **실장비 미검증**: 이번 개발은 하드웨어 접근 없이 진행되었습니다. 빌드·호스트 테스트·모의 서버 E2E만
  통과했으며, 아래 항목은 [HW_TEST.md](docs/HW_TEST.md)에서 확인해야 합니다.
  - 내부 RAM 기준(AP + WS 4개 + SNMP walk에서 최소 여유 > 60 KB): 완화책 1–3 적용 후에도 측정 전.
    부족하면 ARCHITECTURE §6.2 완화책 0(일부 태스크 스택 PSRAM 이동) 적용.
  - W5500 INT 12 / RST 39 핀, MEX150 레지스터 40006–40008 비트 위치(상위 바이트 가정),
    RS485 에코·턴어라운드(`gap_ms`/`timeout_ms`), PBKDF2 로그인 시간(≤ 0.4 s 목표).
- 2–5일 범위 추세 조회는 일별 파일을 읽어 느릴 수 있음. 48시간보다 오래된 구간은 10분 단위 정밀도.
- 이벤트/감사 로그는 10초 단위로 저장되어 전원 차단 시 최대 10초 분량이 유실될 수 있음.
- mDNS 미지원, Host 허용목록 때문에 호스트명 외의 DNS 이름으로는 웹 접속 불가.
- SNMP v3 트랩 없음(lwIP), 인폼 대상은 IP 기준으로만 구분, PEN은 임시값.
- 이력 레코드 시간 필드는 2038-01-19 이전에 형식 변경 필요.
- 웹 UI gzip 예산 잔여 약 0.6 KB: 다음 UI 기능 추가 전 공간 확보 필요.
- 접속 시 제품명 표시 기능은 요구사항에 따라 제외했습니다.
