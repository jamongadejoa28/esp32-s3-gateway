# MESTIO ESP32-S3 게이트웨이 웹서비스 구현 계획

## Context
- `/home/hajun/dev_ws/esp32-s3-gateway`는 현재 `docs/`(Waveshare ESP32-S3-ETH-8DI-8RO 위키 PDF, MEX150 `modbusmap.pdf`)와 `MESTIO_Symbol.svg`만 있는 빈 프로젝트다.
- 목표: Waveshare 보드의 RS485(GPIO17 TX / GPIO18 RX, 자동 방향 전환)를 MEX150 TRX 단자에 연결해 Modbus RTU 9600 8N1로 통신하는 게이트웨이 펌웨어와 웹서비스를 만든다.
- 기능 범위는 `/home/hajun/dev_ws/recovery-gateway`(ofats, IDF 5.0.2, 클래식 ESP32)를 참고하되, 기본값과 브랜딩은 쓰지 않고 그쪽 보안 결함은 고친다.
- 빌드: VS Code ESP-IDF 확장, IDF v6.1(`/home/hajun/esp-idf-v6.1`), LittleFS.

### 사용자 결정사항
- 네트워크: W5500 이더넷이 주 회선. Wi-Fi SoftAP는 복구용으로만 쓴다.
- MEX150만 지원한다. 보드 DI/릴레이는 구현하지 않고 `board_io` 훅만 남긴다.
- UI는 한/영 전환.
- SNMP: v1/v2c와 Trap에 SNMPv3 USM(SHA/AES)까지 지원하고, MIB 모듈 레지스트리 구조로 만든다.
- 연결 시 제품명을 띄우는 기능은 생략한다. 비인증 상태에서는 장치 정보를 노출하지 않는다.

### 탐색으로 확정한 사실
1. **MEX150 프로토콜 코드 재사용.** `esp32-s3-monitor`에 IDF 6.1에서 실제로 쓰는 MEX150 RTU 코드가 있다.
   - 위치: `/home/hajun/dev_ws/esp32-s3-monitor/src/domain/model.c`, `src/services/service.c`
   - 포함 기능: CRC, 응답 검증, 쓰기 범위·인터락, 쓰기 후 read-back 검증
   - 이를 이식하고 일반화한다.
2. **SNMP 컴포넌트 구성.** IDF lwip는 `apps/snmp`를 컴파일하지 않으므로, recovery-gateway 방식대로 로컬 컴포넌트와 프로젝트 전역 define을 쓴다.
   - 문제: `snmpv3_mbedtls.c`는 mbedTLS 4.1에서 사용할 수 없다. md5/sha1/cipher 헤더가 private가 됐고 DES는 제거됐다.
   - 해결: PSA 기반 `snmpv3_psa.c`를 직접 작성한다.
   - lwIP 제약: v3 trap 미지원, VACM 없음. 그래서 v3 RO/RW 구분은 자체 요청 컨텍스트로 처리한다.
   - `SNMP_MAX_COMMUNITY_STR_LEN`의 기본값이 7자이므로 32로 늘린다.
3. **W5500 드라이버.** IDF 6.x 트리에서 빠졌으므로 레지스트리 컴포넌트 `espressif/w5500`(2.0.x)을 쓴다.
   - 기본 `int_gpio_num=4`가 DI1과 충돌하므로 **12로 지정**한다.
   - RST는 GPIO39다. 위키 텍스트표에는 없으므로 Phase 0에서 확인한다.
   - W5500에는 고유 MAC이 없으므로 eFuse MAC을 주입한다.
4. **기타 의존성.**
   - cJSON은 IDF 6.0에서 제거됐다. `espressif/cjson`을 쓴다.
   - LittleFS는 `joltwallet/littlefs` 1.22.3을 쓴다(6.1 지원).
   - httpd WS는 `CONFIG_HTTPD_WS_SUPPORT`와 pre-handshake 콜백을 쓴다.
5. **Modbus 맵 해석.**
   - PDU 주소는 ADDRESS-1이다.
   - 40036(현재온도)은 signed로 해석한다.
   - 코일 17–32(경보)는 monitor 코드가 읽지 않으므로 블록을 추가한다.
   - FC16은 지원하지 않는다. 코일은 8개 단위로 읽는다.

## 기본값 (recovery-gateway와 다르게)
| 항목 | 값 |
|---|---|
| 이더넷 | 고정 IP `192.168.10.150/24`, GW `192.168.10.1`, DNS `192.168.10.1` |
| 복구 AP | SSID `MESTIO-GW-XXXX`, AP IP `192.168.150.1/24`. PSK는 첫 부팅 때 하드웨어 난수로 만든 장치별 값(80bit)이며 팩토리리셋 후에도 유지된다. 변경 전까지 시리얼 로그에만 표시하고 API로는 읽을 수 없다(쓰기 전용, 설정 화면에서 변경). MAC 파생은 공개 정보라 쓰지 않는다 |
| 복구 AP 진입 | BOOT 3–8초 누름, 또는 링크/IP 없이 120초 경과 |
| 팩토리리셋 | BOOT 10초 이상 누름 / 웹 메뉴 / USB 콘솔 |
| 웹 계정 | `admin` / `mestio150!`. **첫 로그인 시 비밀번호 변경을 강제**한다. 역할은 admin / operator / viewer |
| SNMP | 기본 비활성. v1/v2c 꺼짐, RO 커뮤니티 기본값 없음(설정해야 v1/v2c를 켤 수 있음), RW 커뮤니티는 비움. v3 사용자 `gwmonitor`(RO), `gwadmin`(RW)이며 패스프레이즈는 사용자가 입력해야 함 |
| 엔터프라이즈 OID | `1.3.6.1.4.1.32473` (RFC 5612 문서용 PEN). Kconfig `GW_SNMP_ENTERPRISE_PEN`으로 교체 가능 |
| Modbus | slave 1, 9600 8N1, 폴링 1000ms, 타임아웃 300ms, 재시도 1회 |

## 아키텍처
- **파티션(16MB):** `nvs`, `otadata`, `phy`, `ota_0`/`ota_1`(각 3MB), `data` littlefs(약 9.8MB), `coredump`.
  - 웹 UI는 gzip C 배열로 앱 이미지에 넣는다. 펌웨어와 UI가 함께 OTA·롤백되므로 계약 불일치가 생기지 않는다.
  - LittleFS에는 설정, 비밀정보, 이력, 로그를 둔다.
- **컴포넌트(`components/`):**

  | 컴포넌트 | 내용 |
  |---|---|
  | `gw_core` | 이벤트 루프, JSON writer, ring, crypto 추상화 |
  | `board` | I2C, PCF85063 RTC(monitor `clock.c` 이식), WS2812 LED, 부저(Low 고정), BOOT 버튼, `board_io` 스텁 |
  | `net` | W5500, 복구 AP, `net_mgr`(적용 후 120초 내 확인이 없으면 되돌림), SNTP, IP 허용목록 |
  | `mex150` | `regmap.def`(X-macro 단일 레지스터 테이블), frame, model, poll_plan, service |
  | `store` | atomic 파일 쓰기(`tmp` → `bak` → `rename`), 설정 JSON(스키마 버전·마이그레이션), secrets, PSRAM 이력 링, 이벤트·감사 로그, persist 태스크 |
  | `alarm` | 경보 카탈로그(코일 17–31, 40003 오염, 통신두절), 디바운스, ack, 사용자 임계 규칙 최대 8개 |
  | `auth` | PBKDF2-SHA256(PSA), 세션, 레이트리밋·잠금 |
  | `web` | httpd, 기본 거부 라우터, 정적 자산, REST API, OTA, WS 허브 |
  | `snmp_lwip` | lwIP snmp 소스 일부 + `snmpv3_psa.c` + 자체 단일 스레드 `snmp_transport.c` |
  | `snmp_gw` | 모듈 레지스트리, USM, traps, MIB 모듈 |
  | `sysmgr` | supervisor(60초 헬스 후 `mark_app_valid`), OTA writer, factory reset, syslog, 콘솔, 진단 |

- **태스크:**
  - `mex_poll`(prio 10, core1): UART1을 단독으로 쓴다. 블록 사이마다 쓰기 큐를 확인한다.
  - `gw_evt`(7, core1): 경보, 1Hz 이력, WS 프레임 생성.
  - `httpd`(5, core0, 8KB), `snmp_agent`(4, core0), `persist`(3): flash 쓰기 전담.
  - `supervisor`(2).
- **Modbus 폴링:**
  - 빠른 그룹(매 주기): 코일 `{0,8}{8,8}{16,8}{24,8}`, 홀딩 `{1,3}{4,4}{10,12}{35,2}`.
  - 느린 그룹(10초마다, 쓰기 직후): `{26,4}{52,2}{58,1}`.
  - 쓰기 결과는 APPLIED / REJECTED / UNCERTAIN으로 구분한다.
  - 운전 중에는 보정값과 40027 이상 레지스터 쓰기를 금지한다(monitor 인터락 유지).
  - 장치 최대 4대까지 확장 가능한 구조로 만든다.
- **보안:**
  - 세션: 128bit 토큰, HttpOnly + SameSite=Strict 쿠키, 유휴 15분 / 절대 12시간 만료.
  - CSRF 헤더와 Origin 검사. WS도 pre-handshake에서 쿠키와 Origin을 검사한다.
  - 로그인 5회 실패 시 잠금(최대 30분까지 증가).
  - OTA: 인증 + SHA-256 검증 + 앱 롤백.
  - CORS 헤더 없음, 파일 경로 API 없음, `Server` 헤더 없음, CSP 적용.
  - 비밀번호, SNMP 키 등 비밀정보는 API로 읽어갈 수 없다(write-only).

### REST / WS 요약 (상세는 `docs/API.md`)
- **REST** (`/api/v1`): `auth/login|logout|password`, `session`, `meta/registers|alarms`(UI가 맵을 중복 보유하지 않음), `devices/{d}/live|registers/{addr}|run|history|history.csv|stats`, `alarms/active|ack|history`, `config/general|network(+confirm)|modbus|snmp|time|security|notify|rules`, `users`, `snmp/mib|test-trap`, `system/info|firmware|rollback|config export/import|reboot|factory-reset|logs|coredump`.
- **WS** `/ws`(서버 → 클라이언트 push 전용):
  - `hello`: 접속 직후. 클라이언트는 이를 받으면 REST `history`로 1시간치 데이터를 채운다.
  - `snap`: 1Hz 변경분, 30초마다 전체 프레임.
  - `alarm`, `write`, `comm`, `sys`, `bye`.
  - 쓰기는 항상 REST로만 한다.

### 이력
- PSRAM 링 두 개: 1초 간격 1시간치, 1분 간격(min/avg/max) 48시간치.
- 1분 레코드를 10분마다 `/data/hist/YYYYMMDD.bin`에 저장하고 30일 보존한다. 부팅 시 24시간치를 다시 읽는다.

### SNMP MIB (`.1.3.6.1.4.1.PEN.1`)
| 모듈 | 내용 |
|---|---|
| `mib_system` | MIB-II system |
| framework / usm | lwIP 제공 MIB |
| `gw(.1.1)` | 게이트웨이 정보 |
| `devTable(.1.2)` | 장치 목록 |
| `mexStatusTable(.1.3)` | 상태값 |
| `mexSetpointTable(.1.4)` | 설정값. SET은 REST와 같은 검증 경로를 탄다 |
| `mexRegTable(.1.5)` | 범용 레지스터. 향후 다른 컨트롤러로 확장하는 지점 |
| `alarm(.1.6)` | 경보 |
| `comm(.1.7)` | 통신 통계 |
| notifications `.1.0.N` | `gwAlarmRaised/Cleared`, `gwCommLost/Restored`, `gwConfigChanged`, `gwFirmwareUpdated` |

- Trap 대상은 최대 4개(v1/v2c, inform 선택), 초당 10개로 레이트리밋한다.
- MIB 텍스트는 `tools/gen_mib.py`가 `regmap.def`와 alarm 카탈로그에서 생성한다. 웹에서 다운로드할 수 있다.

## 프론트엔드 (디자인·성능)
### 빌드
- 바닐라 JS ES 모듈을 esbuild로 번들·압축하고(버전 고정), 해시 파일명을 붙여 gzip -9로 압축한다.
- `tools/gen_web_assets.py`로 C 테이블을 만든다. **gzip 합계가 64KB를 넘으면 빌드를 실패**시킨다.
- 캐시: 해시 파일은 `immutable`, `index.html`은 ETag와 304로 처리한다.

### 디자인 원칙: 산업 HMI 톤
- 웹폰트 없이 시스템 폰트 스택(`Apple SD Gothic Neo`, `Malgun Gothic` 포함)을 쓰고 숫자는 tabular-nums로 표시한다.
- 중립 회색 팔레트에 **강조색은 MESTIO 블루 `#3155E7` 하나만** 쓴다.
- 상태색은 ok / warn / alarm 세 가지다. 라이트·다크 모드를 지원한다.
- 8px 그리드, 1px 헤어라인, radius 4–6px.
- 그라데이션, 글래스, 이모지, 카드 남발은 쓰지 않는다.
- 아이콘은 직접 그린 라인 SVG 스프라이트를 쓴다.
- 레이아웃: 좌측 56px 레일 + 40px 상태 스트립(사이트 / RUN·STOP / 통신·데이터 나이 / 경보 수 / 시계 / KO·EN / 테마 / 사용자).

### 화면
| 화면 | 내용 |
|---|---|
| 로그인 | 심볼과 폼만. 제품 정보는 표시하지 않는다 |
| 대시보드 | KPI(온도/습도/전류/모드, 설정값·Δ), 실시간 밴드 차트 2개, 단계 동작 스트립, 장비 매트릭스, 활성 경보, RTT 스파크라인 |
| 차트 구성 | 실측, 설정값, 데드밴드 음영, 경보한계 점선 |
| 컨트롤러 | 그룹별 레지스터 인라인 편집(pending → applied/rejected), 운전/정지 확인 다이얼로그 |
| 트렌드 | 15분 / 1시간 / 24시간 / 7일 / 30일, CSV 내보내기 |
| 경보 | 활성 경보, 이력, ack |
| 설정 | 네트워크 / RS485 / SNMP / 시간 / 사용자·보안 / 시스템(OTA는 브라우저에서 SHA-256 계산, 백업·복원, 재부팅, 리셋, 로그, 진단) |

### 커스텀 캔버스 차트(약 8KB)
- TypedArray 링 버퍼, 그리드 캔버스와 데이터 캔버스 분리, DPR 대응.
- 픽셀 열 단위 min/max 데시메이션.
- rAF는 변경이 있을 때만 그리고 최대 30fps.
- 공유 크로스헤어.
- 탭이 숨겨지면 그리기를 멈추고, WS는 지수 백오프로 재연결한다.

### 기타
- **i18n:** `i18n/ko.js`와 `en.js`를 두고, 레지스터·경보 이름은 `/meta`에서 받는다.
- **목 서버:** `tools/mock_server.mjs`가 시뮬레이션 MEX150으로 REST와 WS 계약 전체를 구현한다. `--proxy` 옵션으로 실장비에 연결할 수 있다.

## 프로젝트 레이아웃 / 툴링
- **루트 파일:**
  - `CMakeLists.txt`: IDF 6.1이 아니면 FATAL_ERROR. 프로젝트 전역 SNMP define 지정.
  - `version.txt`, `partitions.csv`, `sdkconfig.defaults`(+`.debug`)
  - `pyproject.toml`/`uv.lock`, `package.json`(esbuild 고정)
  - `.vscode/settings.json`: monitor 설정을 복사한다(`idf.currentSetup=/home/hajun/esp-idf-v6.1`, `IDF_TOOLS_PATH=/home/hajun/dev_ws/wokwipj/.tools/espressif`, `IDF_PYTHON_ENV_PATH=<proj>/.venv`).
  - `tasks.json`
- **`sdkconfig.defaults` 핵심 항목:**
  - 16MB QIO, OCT PSRAM 80M(`XIP_FROM_PSRAM`), USB-Serial-JTAG 콘솔
  - `HTTPD_WS_SUPPORT` + `PRE_HANDSHAKE_CB`, `BOOTLOADER_APP_ROLLBACK_ENABLE`, `UART_ISR_IN_IRAM`
  - `ETH_USE_SPI_ETHERNET`, `ESP_WIFI_NVS_ENABLED=n`, 작은 Wi-Fi 버퍼
  - mbedTLS: HW AES/SHA, `MD5`/`SHA1`/`CFB`
  - TWDT 10초 + coredump
- **`main/idf_component.yml`:** `idf ==6.1.0`, `espressif/w5500`, `joltwallet/littlefs ==1.22.3`, `espressif/cjson`, `espressif/led_strip`
- **`tools/`:**
  - `idf.py`: monitor 래퍼에 nvm node 경로를 추가한 것
  - `build_web.mjs`, `gen_web_assets.py`, `gen_mib.py`, `mock_server.mjs`, `hw_smoke.py`, `snmp_smoke.py`(pysnmp)
- **`cmake/gw_host_sources.cmake`:** 순수 C 소스를 IDF 빌드와 호스트 테스트가 함께 쓴다(monitor 패턴).

### 재사용 원본
- `/home/hajun/dev_ws/esp32-s3-monitor/src/domain/model.c` → `mex150/frame.c`, `model.c` 그리고 regmap의 범위·인터락 값
- `/home/hajun/dev_ws/esp32-s3-monitor/src/services/service.c` → `mex150/service.c`
- `/home/hajun/dev_ws/esp32-s3-monitor/src/board/clock.c` → `board/rtc_pcf85063.c`
- `/home/hajun/dev_ws/esp32-s3-monitor/tools/idf.py`, `.vscode/*`, `tests/conftest.py` 패턴, `.clang-format`
- `/home/hajun/dev_ws/recovery-gateway/firmware/components/lwip_snmp/CMakeLists.txt`, `firmware/CMakeLists.txt` → `snmp_lwip` 컴포넌트와 전역 define 패턴
- `/home/hajun/esp-idf-v6.1/components/lwip/lwip/src/apps/snmp/snmpv3_mbedtls.c`, `snmp_netconn.c` → `snmpv3_psa.c`와 `snmp_transport.c`의 템플릿

## 실행 순서 (ultracode: Phase마다 워크플로우, 단계 사이 검토)
1. **Phase 0: 스캐폴드와 위험 제거** (한 에이전트가 순서대로)
   - 할 일: 골격, 잠금 파일, VS Code 설정, 빈 컴포넌트를 만들고 `idf.py build`가 통과하게 한다.
   - 스파이크:
     - A. W5500 ping. INT=12, RST=39 확인
     - B. `snmp_lwip` + PSA로 v2c/v3 SHA/AES 빌드
     - C. LittleFS atomic rename + WS echo + PBKDF2 시간 측정
     - D. UART1 ↔ MEX150 `exchange`
   - **인터페이스 동결:** `gw_events.h`, `gw_crypto.h`, `regmap.h`/`.def`, `mex150/service.h`, `store/config.h`·`history.h`·`eventlog.h`, `alarm.h`, `auth.h`, `web/router.h`, `snmp_gw/registry.h`, `snmp_transport.h`, `net.h`, `board.h`, `docs/API.md`와 JSON 스키마.
2. **Phase 1: 병렬 워크플로우** (디렉터리별로 소유자를 나눠 충돌을 막는다)

   | 스트림 | 담당 범위 |
   |---|---|
   | A | Modbus |
   | B | store + alarm |
   | C | web 백엔드 + auth |
   | D | 프론트엔드 + 목 서버 |
   | E | SNMP + `gen_mib` |
   | F | net / board / sysmgr |
   | G | 툴링 |

   - 각 스트림이 끝나면 적대적 리뷰 에이전트로 검증한다.
3. **Phase 2: 통합.** `app_main` 연결, 스텁 교체, 페이로드 예산과 내부 힙 최소 60KB 이상 확인.
4. **Phase 3: 하드닝.** 프레임·설정 JSON 퍼징, 보안 리뷰(CSRF / CSWSH / 잠금 / OTA), 72시간 소크.
5. **Phase 4: 문서화.** `ARCHITECTURE.md`, `SNMP.md`, `HW_TEST.md`, 병합 바이너리.
6. **이후 옵션:** HTTPS, 서명 OTA, v3 notification, mDNS, 보드 I/O.

## 검증
- **호스트 테스트** (`uv run --locked pytest -q`):
  - CRC, 프레임, regmap 범위·sentinel·인터락(monitor `mex_validate`와 동치 확인), signed 디코딩, 폴링 계획
  - 경보 디바운스와 통신두절 억제, 규칙 hysteresis
  - 설정 JSON 검증·마이그레이션·손상 입력
  - PBKDF2 벡터, 비밀번호 정책, 레이트리밋, CIDR
  - SNMPv3 RFC 3414/3826 벡터, 이력 링·집계, pysmi로 MIB 컴파일, 목 서버 ↔ JSON 스키마 계약
- **웹 테스트** (`npm test`, `node --test`): 데시메이션, 링, 축 눈금, i18n 키 일치. 빌드 시 64KB 예산 게이트.
- **펌웨어 빌드:** `uv run --locked python tools/idf.py build`, 그리고 VS Code 확장 빌드 모두 통과해야 한다.
- **실장비** (`docs/HW_TEST.md`, `tools/hw_smoke.py`, `tools/snmp_smoke.py`):
  1. 배선: A/B를 MEX150 TRX+/−에 연결하고 120R 점퍼를 켠다. 10분간 CRC 오류 0, RTT 로그를 확인한다.
  2. HTTP: `curl`로 확인한다.
     - 비인증 요청은 401이고 `Server` 헤더가 없어야 한다.
     - 로그인하면 `must_change`가 내려온다.
     - 설정온도 23.5를 쓰면 MEX150 패널에 반영돼야 한다.
     - 네거티브 케이스: CSRF 누락 403, 악성 Origin 403, 6회 실패 429, 비인증 OTA 401, 해시 불일치 422, 운전 중 보정값 쓰기 409.
  3. WS: `hello` 후 1Hz `snap`이 와야 하고, 쿠키가 없으면 업그레이드가 실패해야 한다.
  4. SNMP:
     - RO 커뮤니티를 설정하고 v2c를 켠 뒤 `snmpwalk -v2c -c <ro> 192.168.10.150 1.3.6.1.4.1.32473`
     - v3 authPriv get/set: RO 사용자의 set은 거부돼야 한다.
     - `snmptrapd`로 테스트 trap을 받는다. RS485를 분리하면 `gwCommLost`가 와야 한다.
  5. OTA: 정상 업로드 → `PENDING_VERIFY` → 60초 후 valid. 부팅 중 패닉하는 이미지를 올리면 롤백돼야 한다.
  6. 복구·리셋: BOOT 5초 → AP 접속(`192.168.150.1`), BOOT 10초 → 팩토리리셋, 이더넷을 뽑고 120초 → AP.
  7. 브라우저 성능: 프레임 16ms 이하, LAN에서 TTI 1초 미만, 초기 로딩 요청 약 7개.

## 위험 / 사용자 확인 필요
- PEN 32473은 플레이스홀더다. 외부 통합 전에 실제 PEN으로 바꿔야 한다.
- SNMPv3 제약(lwIP): SHA-2와 DES 미지원, v3 trap 없음.
- 공통 초기 비밀번호는 첫 로그인 강제 변경으로 대응한다. 인증 심사 시 검토가 필요하다.
- `MESTIO_Symbol.svg`의 메타데이터에 "Not a registered or cleared brand"라고 적혀 있다. 빌드할 때 메타데이터는 제거한다.
- RS485 자동 방향 전환 시 에코·턴어라운드 문제는 스파이크 D에서 측정하고 파라미터로 조정한다.
