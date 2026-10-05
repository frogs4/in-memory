#!/bin/bash
# shellcheck disable=SC2154
#   SC2154(referenced but not assigned) 는 v07 에서 도입한 _read/_read_secret 래퍼가
#   변수명을 인자로 받아 간접 대입(read -r "$name")하기 때문에 발생하는 오탐입니다.
#   실제로는 모든 변수가 호출 시점에 대입됩니다.
# ==============================================================================
#  Oracle Datapump Migration Helper (Enterprise Multitenant Adaptive Edition)
#  (Linux, IBM AIX, HP-UX, Solaris Compatible)
#  작성자: Antigravity AI
#  버전: v09.01.00 (Enterprise Multitenant + Automation + Deep Validation Edition)
#        - Adaptive CDB/PDB Support, 19c Non-CDB to 23c PDB Transition
#        - Live Monitor, Tuning Advisor, Data Integrity & Sequence Sync
#        - HTML Audit Reports, Master Pipeline Runner
#        - [NEW v07] Config Save/Load & Unattended Batch Mode
#        - [NEW v07] Data Pump Job Resume/Attach & Pipeline Checkpoint Retry
#        - [NEW v07] Advanced Pre-flight Requirement Verification
#        - [NEW v07] Dump Compression, MD5 Checksum & Transfer Integrity
#        - [NEW v08] DEEP DIFF: ASIS<->TOBE Dictionary Bi-directional MINUS
#                    (권한/프로파일/쿼터/시노님/DB링크 등 29개 항목 심층 대조)
#        - [NEW v08] Actual COUNT(*) Parallel Row Verification (log-independent)
#        - [NEW v08] Unified Exclude-Owner List & MUST_MATCH/INFORMATIONAL 분류
#        - [NEW v08] HTML 감사 보고서에 Deep Diff / Row Count 섹션 통합
#        - [SEC v08.01] 접속 문자열의 OS 프로세스 목록(ps -ef) 노출 제거 (CWE-214)
#                       expdp/impdp: USERID 를 PARFILE(0600) 로 이동
#                       sqlplus    : -S /nolog + heredoc connect 방식으로 전환
#                       Data Pump attach: 임시 PARFILE(0600) 사용
#        - [FIX v08.02] 생성 스크립트를 셔뱅과 일치하게 bash 로 실행
#        - [FIX v08.02] 공백 포함 경로(예: /backup/my dumps) 안전 처리
#        - [FIX v08.02] 건수 수집 중지를 PID 파일 기반으로 전환
#        - [NEW v08.03] 파티션 단위 실측 건수 대조 (opt-in) — 테이블 총계는 맞는데
#                       파티션 경계가 어긋난 경우를 잡아낸다
#        - [NEW v08.03] HTML 감사 보고서에 Pre-flight / Checksum / Partition 섹션 추가
#        - [FIX v08.03] 임시 파일을 mktemp 기반 0700 전용 디렉토리로 격리 (심볼릭 링크
#                       공격·동시 실행 충돌 방지), 종료 시 trap 으로 일괄 정리
#        - [FIX v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입 시 값 누수 차단
#        - [FIX v08.03] 체크리스트 자동 체크를 "결과가 깨끗할 때"로 한정
#                       (실패한 검증을 통과로 표시하던 문제)
#        - [FIX v08.04] PDB 완전 삭제 시 CDB$ROOT 전환 + RAC INSTANCES=ALL
#                       (ORA-65040 / ORA-65025 방어)
#        - [FIX v08.04] Truncate 클린업이 외부 스키마의 inbound FK 로 실패하던 문제와
#                       그 실패가 조용히 묻히던 문제 (ORA-02266 은폐)
#        - [FIX v08.04] 목록 입력 구분자 정규화 (공백 입력 시 잘못된 대상 생성)
#        - [FIX v08.04] HTML 보고서 엔티티 이스케이프 (에러 메시지 일부 소실)
#        - [FIX v08.04] grep -m1 제거 (AIX/HP-UX/Solaris 비호환)
#        - [FIX v08.04] DEEP DIFF 상세조회 컬럼 폭 지정 (라인 래핑 제거)
#        - [FIX v08.05] NETWORK_LINK 모드 impdp 소스 파라미터 누락 수정
#                       (메뉴에는 있으나 실제로는 동작하지 않던 상태)
#        - [NEW v08.05] NETWORK_LINK 전용 사전 검증 — DB Link 도달성 / 원격 버전·
#                       문자셋 / LONG·LONG RAW 검출 (네트워크 모드 이동 불가 객체)
#        - [NEW v08.05] 네트워크 모드 병렬 특성(PQ 미사용) 안내 및 파티션 우회 가이드
#        - [FIX v08.06] 커트오버 체크리스트를 전부 "결과 기반" 판정으로 전환
#                       (DEEP DIFF 3항목 / 실측 건수 / 로그 대조가 실패해도
#                        체크되어 승인 문서에 통과로 표시되던 문제)
#        - [FIX v08.06] 무조건 체크되어 있던 2개 항목 정정
#                       (로그 대조는 결과 기반으로, UTLRP 은 수동 항목으로)
#        - [FIX v08.06] DEEP DIFF 의 MUST_MATCH 위반과 비교실패(ERROR) 분리 계상
#        - [FIX v08.07] Solaris 이식성 — /usr/xpg4/bin 을 PATH 앞에 두어
#                       구형 oawk(gsub/sub/-v 미지원)와 sed -E 부재 문제 해소
#        - [FIX v08.07] 접속문자열 마스킹을 BRE 로 낮춤 (xpg4 없이도 동작)
#        - [NEW v09.00] HASH VERIFY — 행 내용 해시 대조 (메뉴 7-4)
#                       건수가 같아도 값이 바뀐 경우를 탐지. 문자셋 정규화
#                       (CONVERT AL32UTF8) 로 문자셋 변경 이관에서도 유효
#        - [NEW v09.00] SQL over DB Link 데이터 이관 (메뉴 2 -> 방식 3)
#                       증분 캐치업용. 단일 APPEND / 청크 병렬 선택
#        - [NEW v09.00] 서브파티션 단위 건수 대조 (수집 단위 3택)
#        - [FIX v09.01] PDB Data Pump 접속에 자격증명이 빠져 ORA-01017 로
#                       실패하던 문제 (서비스명만 USERID 에 들어가고 있었음)
#        - [FIX v09.01] 건수 수집 동시 실행을 배치 wait 에서 슬롯 감시로 전환
#        - [SEC v09.02] 패스워드 특수문자 처리 — IDENTIFIED BY "..." 로 들어가는
#                       5개 지점에 SET DEFINE OFF 추가(& 치환변수 오염 차단) 및
#                       표현 불가 문자(") 사전 차단. 재현 확인된 결함
#        - [SEC v09.02] 안전하지 않은 eval 형태를 가진 미사용 함수 제거
#                       (confirm_yn — 호출부 없음, 복붙 씨앗 차단)
#        - [FIX v09.02] local 31곳 제거 — ksh 에서 "local: not found" 가 나고
#                       선언 변수가 초기화되지 않던 문제 (AIX/HP-UX 기본 셸)
#        - [FIX v09.02] DB Link 생성 실패를 성공으로 보고하던 문제 (2곳) —
#                       복붙된 heredoc 을 공통 함수로 묶고 종료코드로 판정
#        - [FIX v09.02] 접속 판정을 종료코드 기반으로 전환. 딕셔너리 한 줄만
#                       권한으로 실패해도 전체 수동 입력으로 떨어지던 것 해소
#
#  [설계 메모] WHENEVER SQLERROR 의 EXIT / CONTINUE 선택 기준
#        EXIT FAILURE 를 쓰는 곳 — 실패하면 뒤 단계가 의미를 잃는 전제조건
#            접속 프로브 / PDB 생성 / DB Link 생성 / CDB$ROOT 전환
#            셸은 로그를 정규식으로 긁지 않고 $? 로 판정한다.
#        CONTINUE 를 쓰는 곳 — "에러까지 전부 기록하는 것" 이 목적인 검증 단계
#            DEEP DIFF(29항목 결과를 ERROR 로라도 남겨야 한다)
#            ROW COUNT / HASH 버킷(테이블 하나가 깨져도 나머지를 다 세야 한다)
#            재실행 대비 DROP TABLE(첫 실행의 ORA-00942 는 정상이다)
#        즉 전면 EXIT FAILURE 는 검증 기능을 망가뜨린다. 지점별로 다르게 둔다.
#
#  목적: Oracle 구버전 -> 신버전 이관 스크립트 생성 및 마이그레이션 종합 지원 툴
# ==============================================================================

# 스크립트 버전 정의 (XX.XX.XX 형태)
SCRIPT_VERSION="09.02.00"

# ------------------------------------------------------------------------------
# [FIX v08.07] Solaris 이식성 — POSIX 도구를 PATH 앞에 둔다.
#
#   Solaris 의 /usr/bin/awk 는 1977년판 oawk 라 gsub / sub / toupper / -v 를
#   지원하지 않는다. /usr/bin/sed 도 -E 가 없다. 이 도구는 세 가지를 모두 쓰므로
#   Solaris 에서 그대로 두면 크기 산출과 로그 파싱이 조용히 빈 값을 낸다.
#   /usr/xpg4/bin 은 Solaris 가 제공하는 POSIX 준수 도구 모음이다. 여기를
#   앞에 두면 awk / sed / grep 이 한 번에 해결된다.
#   AIX 와 HP-UX 의 기본 awk 는 nawk 계열이라 해당 없음.
# ------------------------------------------------------------------------------
case "$(uname -s 2>/dev/null)" in
    SunOS)
        [ -d /usr/xpg4/bin ] && PATH="/usr/xpg4/bin:$PATH" && export PATH
        [ -d /usr/xpg6/bin ] && PATH="/usr/xpg6/bin:$PATH" && export PATH
        ;;
esac

# OS & 환경 감지용 글로벌 변수
OS_TYPE=""
CPU_CORES=1
MEM_SIZE="Unknown"
MOCK_MODE="false"

# ==============================================================================
# [v09.02] MOCK 우회 경로 대장 (MOCK BYPASS INVENTORY)
#
#   왜 이 목록이 있는가 — MOCK 분기가 실제 로직을 '대체' 하면 그 로직은 MOCK E2E
#   를 몇 종 돌려도 검증되지 않는다. 실제로 두 번 같은 식으로 당했다.
#     v09.01 ①  fetch_db_info 가 PDB 접속문자열을 자격증명째로 하드코딩해서,
#                join_pdb_connect 가 없던 시절의 ORA-01017 결함이 E2E 9종을
#                전부 통과했다.
#     v09.02 B1  setup_deep_dblink 가 MOCK 에서 early return 해서, 패스워드의
#                " / & 가 생성 SQL 을 깨뜨리는 결함이 그대로 남아 있었다.
#                우회를 걷어내자마자 빈 사용자명/TNS 미검증 결함까지 추가로 나왔다.
#
#   판단 기준 — 그 분기가 '생성물의 내용을 만드는 로직' 을 대체하는가?
#     [생성 로직 대체]  위험. MOCK 도 실제 경로를 타게 해야 한다.
#     [환경 관측 대체]  허용. 수치/목록만 가짜이고, 틀리면 실환경에서 바로 보인다.
#
#   현재 상태 (총 22곳)
#     ── 생성 로직 대체: 해소됨 ──────────────────────────────────────────
#       fetch_db_info            PDB 접속문자열을 join_pdb_connect 로 산출 (v09.02)
#       setup_deep_dblink        링크 미존재로 가정해 생성 DDL 경로를 태움 (v09.02)
#     ── 환경 관측 대체: 의도된 우회 ─────────────────────────────────────
#       detect_os_and_hw         OS/CPU/메모리 수치
#       check_disk_space         디스크 여유
#       check_db_env             DB 환경 점검
#       check_dir_writable       디렉토리 쓰기 가능 여부
#       estimate_target_size_bytes / free_space_bytes   용량 추정치
#       run_live_monitor         실시간 모니터 화면
#       run_resume_mode (2곳)    진행 중 Data Pump 작업 목록
#     ── 목록·수치만 가짜, 생성 로직은 그대로 통과 ───────────────────────
#       setup_db_directory               dba_directories 목록
#       select_migration_targets (3곳)   스키마/테이블/TBS 목록
#       generate_target_env_ddl          대상 목록
#       generate_grants_and_synonyms_scripts  의존 객체 목록
#       run_network_link_checks          사전점검 결과를 OK 로 고정
#       run_source_mode (2곳)            SCN / 세그먼트 크기 분류
#       run_target_mode (2곳)            테이블스페이스 목록
#
#   규칙 — MOCK 분기를 새로 넣을 때는 반드시 이 목록에 추가하고, '생성 로직'
#   쪽이면 넣지 말고 실제 경로가 MOCK 입력으로도 돌아가게 만들 것.
# ==============================================================================

# Oracle DB 정보 변수
DB_VERSION=""
DB_CPU_COUNT=1
DB_SGA_GB="Unknown"
DB_PGA_GB="Unknown"
DB_CHARSET="Unknown"
DB_CONN="/ as sysdba"
LANG_PREF=""
DBLINK_SUFFIX=""
# [FIX v07/R2] cluster_database 값은 메타데이터 조회 실패 시에도 반드시 초기값을 갖도록 선언
DB_CLUSTER="FALSE"

# Oracle Multitenant (CDB/PDB) 적응형 글로벌 변수
IS_CDB="NO"
CURRENT_CON_NAME="UNKNOWN"
SELECTED_PDB=""
PDB_CONNECT_STR=""
PDB_SWITCH_SQL=""

# ------------------------------------------------------------------------------
# [NEW v07] 설정(Config) 저장/불러오기 및 무인(Unattended) 배치 모드 글로벌 변수
# ------------------------------------------------------------------------------
UNATTENDED="false"          # true 이면 프롬프트를 띄우지 않고 config/기본값으로 진행
CONFIG_FILE=""              # --config 로 읽어들일 응답 정의 파일
SAVE_CONFIG_FILE=""         # --save-config 로 기록할 응답 저장 파일
CONFIG_RECORD_FILE=""       # 실행 중 응답을 누적 기록하는 임시 파일
AUTO_MENU=""                # --run=1|2|... 무인 실행 시 자동 선택할 메뉴 번호

# [NEW v07] 압축 / 체크섬 / 전송 무결성 글로벌 변수
COMPRESSION_PARAM=""        # COMPRESSION=ALL 등
COMPRESSION_ALGO_PARAM=""   # COMPRESSION_ALGORITHM=MEDIUM 등
CHECKSUM_ENABLED="false"
GENERATED_CHECKSUM_SCRIPTS=""

# [NEW v07] 사전 검증 / 버전 호환성 글로벌 변수
TARGET_DB_VERSION=""        # Source 모드에서 입력받는 Target DB 버전 (VERSION= 파라미터 산출용)
VERSION_PARAM=""            # VERSION=19.0.0 형태
PREFLIGHT_RESULT="PASS"     # PASS / WARN / FAIL

# 생성 스크립트 목록 글로벌 (모드 진입 시 반드시 초기화됨 - FIX v07/B2)
GENERATED_EST_SCRIPTS=""
GENERATED_EXEC_SCRIPTS=""
GENERATED_META_SCRIPTS=""
GENERATED_STATS_SCRIPTS=""
GENERATED_XFER_SCRIPTS=""
GENERATED_TARGET_SCRIPTS=""
GENERATED_UTIL_SCRIPTS=""

# [NEW v08] DEEP VALIDATION 관련 전역 변수
GENERATED_DEEPDIFF_SCRIPTS=""
GENERATED_DEEPDIFF_PRE=""
GENERATED_ROWCOUNT_SCRIPTS=""
DEEP_EXTRA_EXCLUDE=""
ROWCOUNT_BUCKETS=""
ROWCOUNT_PARALLEL_DEG=""
ROWCOUNT_TABLESPACE=""
ROWCOUNT_PART_MODE="NONE"   # [v09.00] NONE | PART | SUBPART — 건수 수집 단위
HASH_BUCKETS=""             # [NEW v09.00] 해시 수집 병렬 버킷 수
HASH_PDEG=""                # [NEW v09.00] 테이블당 PARALLEL 도수
HASH_TABLESPACE=""          # [NEW v09.00] 해시 결과 테이블 테이블스페이스
HASH_FUNC_USED=""           # STANDARD_HASH | ORA_HASH
GENERATED_HASH_SCRIPTS=""
HASH_STATUS=""              # PASS / FAIL — 체크리스트 판정용
HASH_BAD_CNT="0"
DL_LINK_NAME=""             # [NEW v09.00] DB Link 데이터 이관용
DL_OWNER_IN=""
DL_TABLE_IN=""
DL_WHERE_CLAUSE=""
DL_WHERE_EXTRA=""
DL_PARALLEL_MODE="SINGLE"   # SINGLE | CHUNK
DL_CHUNK_COL=""
DL_CHUNKS=16
DL_PDEG=4
ROWCOUNT_PART_STATUS=""   # [NEW v08.03] 파티션 단위 대조 결과 PASS / FAIL
DEEP_DIFF_STATUS=""       # [NEW v08.06] DEEP DIFF 판정 PASS / FAIL
DEEP_DIFF_BAD_CNT="0"     # MUST_MATCH 위반 건수
DEEP_DIFF_ERR_CNT="0"     # 비교 실패(ERROR) 건수
ROWCOUNT_STATUS=""        # [NEW v08.06] 실측 건수 판정 PASS / FAIL
ROWCOUNT_BAD_CNT="0"      # 불일치+누락 건수
NETWORK_PRECHECK_RESULT=""  # [NEW v08.05] NETWORK_LINK 사전 점검 PASS / FAIL
PREFLIGHT_CSV_STATUS=""   # PASS / WARN / FAIL — 체크리스트 자동 체크 판정용
CHECKSUM_CSV_STATUS=""    # PASS / FAIL
CHECKSUM_BAD_CNT="0"      # 불일치+누락 건수

# ------------------------------------------------------------------------------
# 사용법 출력
# ------------------------------------------------------------------------------
print_usage() {
    cat <<'USAGE'
Oracle Datapump Migration Helper Tool

사용법 / Usage:
  oracle_migration_helper.sh [옵션]

옵션 / Options:
  -v, --version              버전 출력 후 종료
      --mock                 MOCK 테스트 모드 (DB 접속 없이 화면/로직 검증)
  -c, --config <FILE>        저장된 응답 파일을 읽어 프롬프트를 자동 응답
      --save-config <FILE>   이번 실행의 모든 응답을 FILE 로 저장 (재사용용)
  -y, --unattended           무인 모드. 프롬프트를 띄우지 않고 config/기본값 사용
      --run <N>              무인 모드에서 실행할 메인 메뉴 번호 (1~9)
      --lang <KO|EN>         언어를 지정 (지정 시 언어 선택 화면 생략)
  -h, --help                 이 도움말 출력

무인 배치 실행 예시 / Unattended batch example:
  # 1) 대화형으로 1회 수행하면서 응답을 저장
  ./oracle_migration_helper.sh --save-config mig_prod.conf

  # 2) 이후 동일 시나리오를 무인으로 반복 수행
  ./oracle_migration_helper.sh --config mig_prod.conf --unattended --run 1

주의: --unattended 사용 시 비밀번호(TDE/DB Link)는 보안상 config 에 저장되지 않으므로
      환경변수 MIG_TDE_PASSWORD / MIG_DBLINK_PASSWORD 로 전달해야 합니다.
USAGE
}

# ------------------------------------------------------------------------------
# 커맨드라인 옵션 처리 (-v, --version, --mock, --config, --unattended 등)
# ------------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -v|--version|-version|version)
            echo "Oracle Datapump Migration Helper Tool v${SCRIPT_VERSION} (Enterprise Multitenant + Automation + Deep Validation Edition)"
            exit 0
            ;;
        -h|--help|help)
            print_usage
            exit 0
            ;;
        --mock)
            MOCK_MODE="true"
            ;;
        -c|--config)
            shift; CONFIG_FILE="$1"
            ;;
        --config=*)
            CONFIG_FILE=$(echo "$1" | cut -d'=' -f2-)
            ;;
        --save-config)
            shift; SAVE_CONFIG_FILE="$1"
            ;;
        --save-config=*)
            SAVE_CONFIG_FILE=$(echo "$1" | cut -d'=' -f2-)
            ;;
        -y|--unattended|--yes)
            UNATTENDED="true"
            ;;
        --run)
            shift; AUTO_MENU="$1"
            ;;
        --run=*)
            AUTO_MENU=$(echo "$1" | cut -d'=' -f2-)
            ;;
        --lang)
            shift; LANG_PREF=$(echo "$1" | tr 'a-z' 'A-Z')
            ;;
        --lang=*)
            LANG_PREF=$(echo "$1" | cut -d'=' -f2- | tr 'a-z' 'A-Z')
            ;;
        *)
            echo "[WARN] 알 수 없는 옵션 무시 / Unknown option ignored: $1"
            ;;
    esac
    shift
done

if [ -n "$CONFIG_FILE" ] && [ ! -f "$CONFIG_FILE" ]; then
    echo "[ERROR] Config 파일을 찾을 수 없습니다 / Config file not found: $CONFIG_FILE"
    exit 1
fi

# ------------------------------------------------------------------------------
# [FIX v07/B3] 트랩 분리
#   - EXIT : 임시파일 정리 + 터미널 에코 복구 (정상 종료 경로)
#   - INT/TERM : 정리 후 명시적으로 종료해야 Ctrl+C 가 실제로 동작함
#     (기존 v06 은 INT 트랩이 exit 를 호출하지 않아 Live Monitor 루프를
#      빠져나갈 수 없었음)
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# [NEW v08.03] 임시파일 전용 작업 디렉토리
#   기존에는 현재 디렉토리에 ./xxx_$$.tmp 를 만들고 트랩에서 `rm -f ./*_$$.*` 로
#   지웠다. 이 글롭은 PID 가 우연히 일치하는 사용자 파일(예: report_12345.html)
#   까지 지울 수 있고, 현재 디렉토리에 쓰기 권한이 없으면 동작하지 않았다.
#   mktemp 로 전용 디렉토리를 만들어 그 안에서만 작업하고 통째로 정리한다.
# ------------------------------------------------------------------------------
MIG_TMPDIR=""

init_tmpdir() {
    [ -n "$MIG_TMPDIR" ] && [ -d "$MIG_TMPDIR" ] && return 0
    if command -v mktemp >/dev/null 2>&1; then
        MIG_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/mighelper.XXXXXX" 2>/dev/null)
    fi
    # mktemp 가 없거나 실패한 구형 UNIX 대비 폴백
    if [ -z "$MIG_TMPDIR" ] || [ ! -d "$MIG_TMPDIR" ]; then
        MIG_TMPDIR="${TMPDIR:-/tmp}/mighelper.$$"
        mkdir -p "$MIG_TMPDIR" 2>/dev/null
    fi
    if [ ! -d "$MIG_TMPDIR" ]; then
        # 마지막 폴백: 현재 디렉토리 (기존 동작)
        MIG_TMPDIR="./.migtmp_$$"
        mkdir -p "$MIG_TMPDIR" 2>/dev/null
    fi
    chmod 700 "$MIG_TMPDIR" 2>/dev/null
    return 0
}

# 임시파일 경로 생성기 :  tmpf <이름>  ->  <작업디렉토리>/<이름>
tmpf() {
    init_tmpdir
    echo "${MIG_TMPDIR}/$1"
}

cleanup_tmp_files() {
    stty echo 2>/dev/null
    # [FIX v08.03] 위험한 글롭 삭제를 제거하고 전용 디렉토리만 정리한다.
    if [ -n "$MIG_TMPDIR" ] && [ -d "$MIG_TMPDIR" ]; then
        case "$MIG_TMPDIR" in
            */mighelper.*|*/.migtmp_*) rm -rf "$MIG_TMPDIR" 2>/dev/null ;;
        esac
    fi
}

on_interrupt() {
    cleanup_tmp_files
    echo ""
    echo ">> 사용자 중단(Ctrl+C) / Interrupted by user."
    exit 130
}

trap 'cleanup_tmp_files' EXIT
trap 'on_interrupt' INT TERM

# [중요] tmpf 는 $( ) 안에서 호출되어 서브셸에서 실행된다. 서브셸이 만든 디렉토리
#   경로는 부모로 전파되지 않으므로, 여기서 부모 셸이 먼저 한 번 만들어 둔다.
#   이후 서브셸의 init_tmpdir 는 이미 설정된 값을 보고 즉시 반환한다.
init_tmpdir

# 화면 클리어 함수
clear_screen() {
    clear 2>/dev/null || tput clear 2>/dev/null || echo ""
}

# ------------------------------------------------------------------------------
# [NEW v07] 숫자 정규화 헬퍼
#   sqlplus 출력이 비었거나 공백/개행/경고가 섞여도 안전하게 정수를 얻는다.
#   [FIX v07/R1] `[ $(...) -eq 0 ]` 형태의 미인용 명령치환으로 인한
#                "unary operator expected" 오류와 분기 오판을 제거한다.
# ------------------------------------------------------------------------------
to_num() {
    _tn_val=$(echo "$1" | tr -dc '0-9')
    if [ -z "$_tn_val" ]; then echo "0"; else echo "$_tn_val"; fi
}

# ------------------------------------------------------------------------------
# [NEW v07] Config(응답 파일) 조회 / 기록 헬퍼
#   형식: KEY=VALUE (한 줄에 하나, '#' 로 시작하면 주석)
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# [SEC v08.01] 접속 문자열 마스킹
#   user/password@service -> user/****@service
#   config 자동응답 출력이 콘솔과 nohup 로그에 패스워드를 남기던 문제를 막는다.
# ------------------------------------------------------------------------------
mask_conn_value() {
    # [FIX v08.07] sed -E 는 Solaris /usr/bin/sed 에 없다. BRE 로 낮춘다.
    #   마스킹은 실패해도 조용히 빈 값이 되어 화면에서만 사라지므로 눈치채기 어렵다.
    #   XPG4 PATH 보정과 별개로, 이 경로만은 기본 sed 로도 동작하게 둔다.
    echo "$1" | sed 's#^\([^/ 	]*\)/[^@ 	]*\(@.*\)*$#\1/****\2#'
}

# 값이 자격증명처럼 보이는지 판정 (키 이름 또는 user/pass@svc 패턴)
is_secretish() {
    case "$1" in
        *conn*|*CONN*|*pwd*|*PWD*|*pass*|*PASS*|*userid*|*USERID*|*tns*|*TNS*) return 0 ;;
    esac
    echo "$2" | grep -qE '^[^/[:space:]]+/[^@[:space:]]+@' && return 0
    return 1
}

# ------------------------------------------------------------------------------
# [SEC v09.02] 패스워드를 SQL 의 IDENTIFIED BY "..." 안에 넣을 때의 안전성 점검
#
#   배경 — 외부 리뷰에서 지적된 결함. 실제로 재현된다.
#     MIG_DBLINK_PASSWORD='p"w&1$x' 로 실행하면 생성물이 이렇게 나왔다.
#       CREATE DATABASE LINK AS_LINK CONNECT TO SYSTEM IDENTIFIED BY "p"w&1$x" ...
#
#   두 문자가 서로 다른 방식으로 깨진다.
#     "  Oracle 의 따옴표 식별자(quoted identifier)는 큰따옴표 자체를 담을 수 없다.
#        ("" 로 이중화해도 통하지 않는다 — 문법 차원에서 표현 불가)
#        -> 조용히 고칠 방법이 없으므로 '막고 알린다'.
#     &  SQL*Plus 는 DEFINE 이 기본 ON 이라 &xyz 를 치환변수로 먹는다.
#        문법 오류가 나지 않고 '다른 패스워드로 생성'된 뒤 나중에 ORA-01017 로
#        나타나므로 " 보다 오히려 위험하다.
#        -> SET DEFINE OFF 로 해결된다 (sql_define_off 가 그 한 줄을 낸다).
#
#   반환값: 0 = SQL 에 넣어도 안전, 1 = 넣을 수 없음(호출부에서 중단/재입력 유도)
# ------------------------------------------------------------------------------
sql_define_off() {
    # 패스워드를 품은 생성 SQL 의 머리에 반드시 붙인다.
    echo "SET DEFINE OFF"
}

# ------------------------------------------------------------------------------
# [v09.02] DB Link 를 즉석에서 만드는 공통 경로
#
#   v09.01 까지는 NETWORK_LINK 설정부(2곳)에 같은 heredoc 이 복붙돼 있었고,
#   둘 다 생성 성공 여부를 보지 않고 "DB Link 생성을 완료했습니다" 를 찍었다.
#   실패해도 성공 메시지가 나오므로, 뒤 단계에서 ORA-02019 로 터질 때까지
#   작업자가 모른다.
#
#   여기서 세 가지를 한꺼번에 고친다.
#     1) 패스워드 안전성 선검사 (" 차단, & 는 SET DEFINE OFF 로 처리)
#     2) SET DEFINE OFF + WHENEVER SQLERROR EXIT FAILURE
#     3) 종료코드로 성공/실패 판정 — 로그 정규식 파싱에 의존하지 않는다
#
#   create_dblink_live <LINK_NAME> <USER> <PWD> <TNS>
#   반환값: 0 = 생성 성공, 1 = 실패(호출부에서 중단 여부 결정)
# ------------------------------------------------------------------------------
create_dblink_live() {
    _cdl_name="$1"
    _cdl_user="$2"
    _cdl_pwd="$3"
    _cdl_tns="$4"

    # [FIX v09.02] 빈 사용자명/TNS 로 깨진 DDL 을 실행하지 않는다.
    if [ -z "$_cdl_user" ] || [ -z "$_cdl_tns" ]; then
        if [ "$LANG_PREF" = "EN" ]; then
            echo "  >> [SKIPPED] DB Link '${_cdl_name}': username and TNS are both required."
        else
            echo "  >> [건너뜀] DB Link '${_cdl_name}': 사용자명과 TNS 가 모두 필요합니다."
            echo "             (사용자명='${_cdl_user}', TNS='${_cdl_tns}')"
        fi
        return 1
    fi

    check_sql_pwd_safe "DB Link 패스워드 / DB Link password" "$_cdl_pwd" || return 1

    _cdl_out="$(tmpf dblink_create.out)"
    sqlplus -S /nolog > "$_cdl_out" 2>&1 <<SQL_EOF
connect $DB_CONN
SET DEFINE OFF
WHENEVER SQLERROR EXIT FAILURE
WHENEVER OSERROR EXIT FAILURE
$PDB_SWITCH_SQL
CREATE DATABASE LINK ${_cdl_name} CONNECT TO ${_cdl_user} IDENTIFIED BY "${_cdl_pwd}" USING '${_cdl_tns}';
EXIT;
SQL_EOF
    _cdl_rc=$?

    if [ "$_cdl_rc" -ne 0 ]; then
        if [ "$LANG_PREF" = "EN" ]; then
            echo "  >> [FAILED] DB Link '${_cdl_name}' was NOT created (sqlplus exit=${_cdl_rc})."
        else
            echo "  >> [실패] DB Link '${_cdl_name}' 를 생성하지 못했습니다 (sqlplus exit=${_cdl_rc})."
        fi
        # 메시지에 접속 문자열이 섞여 나올 수 있으므로 마스킹해서 보여준다.
        grep -E 'ORA-|SP2-' "$_cdl_out" 2>/dev/null | head -n 3 | while IFS= read -r _cdl_l; do
            echo "       $(mask_conn_value "$_cdl_l")"
        done
        rm -f "$_cdl_out"
        return 1
    fi

    rm -f "$_cdl_out"
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> DB Link '${_cdl_name}' created."
    else echo "  >> DB Link '${_cdl_name}' 를 생성했습니다."; fi
    return 0
}

check_sql_pwd_safe() {
    _cp_label="$1"
    _cp_val="$2"
    [ -z "$_cp_val" ] && return 0

    # 큰따옴표 — 표현 불가. 반드시 막는다.
    case "$_cp_val" in
        *'"'*)
            echo ""
            if [ "$LANG_PREF" = "EN" ]; then
                echo "  [BLOCKED] ${_cp_label}: the password contains a double quote (\")."
                echo "            Oracle quoted identifiers cannot contain \" at all, so"
                echo "            IDENTIFIED BY \"...\" cannot express this password."
                echo "            Change the password, or create the object by hand."
            else
                echo "  [차단] ${_cp_label}: 패스워드에 큰따옴표(\") 가 있습니다."
                echo "         Oracle 따옴표 식별자는 \" 를 담을 수 없어 IDENTIFIED BY \"...\" 로"
                echo "         표현할 방법이 없습니다 (\"\" 이중화도 통하지 않습니다)."
                echo "         패스워드를 바꾸거나 해당 객체는 수동으로 생성하십시오."
            fi
            echo ""
            return 1
            ;;
    esac

    # & — SET DEFINE OFF 로 해결되지만, 왜 그 줄이 붙는지 알려 둔다.
    case "$_cp_val" in
        *'&'*)
            if [ "$LANG_PREF" = "EN" ]; then
                echo "  [NOTE] ${_cp_label}: password contains '&'. SET DEFINE OFF is emitted"
                echo "         so SQL*Plus will not treat it as a substitution variable."
                echo "         Do not remove that line when editing the generated SQL."
            else
                echo "  [안내] ${_cp_label}: 패스워드에 '&' 가 있습니다. SQL*Plus 치환변수로"
                echo "         해석되지 않도록 생성 SQL 에 SET DEFINE OFF 를 넣었습니다."
                echo "         생성물을 편집하실 때 그 줄을 지우지 마십시오."
            fi
            ;;
    esac
    return 0
}

cfg_get() {
    [ -z "$CONFIG_FILE" ] && return 1
    _cg_line=$(grep "^$1=" "$CONFIG_FILE" 2>/dev/null | tail -n 1)
    [ -z "$_cg_line" ] && return 1
    echo "$_cg_line" | cut -d'=' -f2-
    return 0
}

cfg_record() {
    [ -z "$CONFIG_RECORD_FILE" ] && return 0
    # 메뉴 이동/더미 응답은 시나리오 재현과 무관하므로 저장하지 않는다.
    case "$1" in
        main_choice|_dummy|lang_choice) return 0 ;;
    esac
    # [SEC v08.01] 패스워드가 포함된 접속 문자열은 설정 파일에 저장하지 않는다.
    #   대신 주석으로 자리만 남겨 사용자가 인지하고 직접 채우도록 한다.
    if [ -n "$2" ] && is_secretish "$1" "$2"; then
        printf '# %s=<보안상 저장 안 함. 실행 시 직접 입력하거나 이 줄의 주석을 풀고 값을 채우십시오>\n' "$1" >> "$CONFIG_RECORD_FILE"
        return 0
    fi
    printf '%s=%s\n' "$1" "$2" >> "$CONFIG_RECORD_FILE"
    return 0
}

# ------------------------------------------------------------------------------
# [NEW v07] 프롬프트 입력 래퍼
#   _read <VAR_NAME>
#     1) --config 에 동일 키가 있으면 그 값을 사용 (화면에 표시)
#     2) --unattended 이면 빈 값을 넣어 각 호출부의 기본값 로직이 동작하게 함
#     3) 그 외에는 read -r 로 실제 입력 (백슬래시 훼손 방지 - FIX v07/M4)
#   _read_secret <VAR_NAME> [ENV_VAR_NAME]
#     비밀번호 전용. 에코를 끄고 입력받으며 config 에는 절대 저장하지 않는다.
# ------------------------------------------------------------------------------
_read() {
    _rd_name="$1"
    if _rd_val=$(cfg_get "$_rd_name"); then
        eval "$_rd_name=\"\$_rd_val\""
        # [SEC v08.01] 자격증명처럼 보이는 값은 마스킹해서 출력
        if is_secretish "$_rd_name" "$_rd_val"; then
            echo "[CONFIG] ${_rd_name} = $(mask_conn_value "$_rd_val")"
        else
            echo "[CONFIG] ${_rd_name} = ${_rd_val}"
        fi
        return 0
    fi
    if [ "$UNATTENDED" = "true" ]; then
        eval "$_rd_name=\"\""
        echo "[AUTO] ${_rd_name} : 기본값 사용 / using default"
        return 0
    fi
    # shellcheck disable=SC2229  # 변수명을 인자로 받아 그 변수에 읽어들이는 의도된 패턴
    IFS= read -r "$_rd_name"
    eval "_rd_now=\"\$$_rd_name\""
    cfg_record "$_rd_name" "$_rd_now"
    return 0
}

_read_secret() {
    _rs_name="$1"
    _rs_env="$2"
    if [ -n "$_rs_env" ]; then
        eval "_rs_envval=\"\$$_rs_env\""
        if [ -n "$_rs_envval" ]; then
            eval "$_rs_name=\"\$_rs_envval\""
            echo "[ENV] ${_rs_name} : 환경변수 ${_rs_env} 값 사용 / taken from environment"
            return 0
        fi
    fi
    if [ "$UNATTENDED" = "true" ]; then
        eval "$_rs_name=\"\""
        echo "[AUTO] ${_rs_name} : 미입력으로 처리 (환경변수 ${_rs_env} 미설정)"
        return 0
    fi
    stty -echo 2>/dev/null
    # shellcheck disable=SC2229  # 의도된 간접 read
    IFS= read -r "$_rs_name"
    stty echo 2>/dev/null
    echo ""
    return 0
}

# ------------------------------------------------------------------------------
# [제거 v09.02] confirm_yn() 을 삭제했다.
#
#   v07 에서 Y/N 프롬프트용으로 만들었지만 한 번도 호출되지 않은 죽은 코드였고,
#   본문에 이 스크립트의 eval 중 유일하게 안전하지 않은 형태가 들어 있었다.
#
#       eval "$_cy_name=\"$_cy_def\""        <-- 위험
#
#   왜 위험한가 — eval 에 넘기는 문자열을 '조립할 때' $_cy_def 가 먼저 펼쳐지므로,
#   그 값에 들어 있던 메타문자가 eval 의 파서에게 코드로 읽힌다. 실측으로
#   _cy_def='Y"; touch HIT; echo "' 를 주면 touch 가 실행된다.
#   호출부가 전부 리터럴 Y/N 이어서 악용 경로는 없었지만, 복붙 씨앗이라 지운다.
#
#   안전한 형태 — 값 쪽을 \$ 로 이스케이프해서 eval 자신의 파서가 큰따옴표 안에서
#   한 번만 펼치게 한다. 펼친 결과는 재스캔되지 않으므로 값에 " 나 $(...) 가
#   있어도 코드가 되지 않는다. _read / _read_secret 이 쓰는 방식이다.
#
#       eval "$_name=\"\$_value\""           <-- 안전
#
#   메타문자 11종 × bash/dash 로 검증했다 (명령 실행 0건, 값 100% 보존).
#   앞으로 간접 대입이 필요하면 반드시 아래쪽 형태를 쓸 것.
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Config 기록 시작 (--save-config)
# ------------------------------------------------------------------------------
if [ -n "$SAVE_CONFIG_FILE" ]; then
    CONFIG_RECORD_FILE="$(tmpf cfg_record.tmp)"
    : > "$CONFIG_RECORD_FILE"
fi

save_config_if_requested() {
    [ -z "$SAVE_CONFIG_FILE" ] && return 0
    [ ! -f "$CONFIG_RECORD_FILE" ] && return 0
    {
        echo "# ============================================================"
        echo "# Oracle Datapump Migration Helper - Saved Answer Config"
        echo "# Generated : $(date '+%Y-%m-%d %H:%M:%S') by v${SCRIPT_VERSION}"
        echo "# 사용법    : ./oracle_migration_helper.sh --config $(basename "$SAVE_CONFIG_FILE") --unattended --run <N>"
        echo "# 주의      : 비밀번호는 저장되지 않습니다 (MIG_TDE_PASSWORD 등 환경변수 사용)"
        echo "# ============================================================"
        echo "LANG_PREF_SAVED=$LANG_PREF"
        # 동일 키가 여러 번 기록된 경우 마지막 값만 유지
        awk -F'=' '{ key=$1; sub(/^[^=]*=/, "", $0); val[key]=$0; order[key]=NR }
                   END { for (k in val) printf "%s\t%s=%s\n", order[k], k, val[k] }' "$CONFIG_RECORD_FILE" \
            | sort -n | cut -f2-
    } > "$SAVE_CONFIG_FILE"
    chmod 600 "$SAVE_CONFIG_FILE" 2>/dev/null
    echo ""
    echo ">> [CONFIG SAVED] 응답이 저장되었습니다: $SAVE_CONFIG_FILE"
    echo "   재사용: $0 --config $SAVE_CONFIG_FILE --unattended --run <메뉴번호>"
    return 0
}

# ---------------------------------------------------------
# 언어 선택 모듈 (--lang / --config / --unattended 시 생략)
# ---------------------------------------------------------
if [ -z "$LANG_PREF" ]; then
    if _cfg_lang=$(cfg_get "LANG_PREF_SAVED"); then
        LANG_PREF="$_cfg_lang"
    elif [ "$UNATTENDED" = "true" ]; then
        LANG_PREF="KO"
    else
        clear_screen
        echo "======================================================================"
        echo "  Select Language / 언어를 선택하세요"
        echo "  1. 한국어 (Korean)"
        echo "  2. English"
        echo "======================================================================"
        printf "  Select (1-2) [Default: 1]: "
        # shellcheck disable=SC2229
        IFS= read -r lang_choice
        if [ "$lang_choice" = "2" ]; then
            LANG_PREF="EN"
        else
            LANG_PREF="KO"
        fi
    fi
fi
[ "$LANG_PREF" != "EN" ] && LANG_PREF="KO"

# OS 감지 및 HW 정보 수집
detect_os_and_hw() {
    OS_TYPE=$(uname -s)
    
    if [ "$MOCK_MODE" = "true" ]; then
        OS_TYPE="Linux (Mocked)"
        CPU_CORES=16
        MEM_SIZE="64 GB"
        return
    fi

    case "$OS_TYPE" in
        Linux)
            if command -v nproc >/dev/null 2>&1; then
                CPU_CORES=$(nproc)
            else
                CPU_CORES=$(grep -c ^processor /proc/cpuinfo)
            fi
            MEM_SIZE=$(free -g 2>/dev/null | awk '/Mem:/ {print $2" GB"}')
            if [ -z "$MEM_SIZE" ]; then
                mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
                MEM_SIZE="$((mem_kb / 1024 / 1024)) GB"
            fi
            ;;
        AIX)
            CPU_CORES=$(bindprocessor -q 2>/dev/null | awk '{print $NF+1}')
            if [ -z "$CPU_CORES" ] || [ "$CPU_CORES" -le 1 ]; then
                CPU_CORES=$(lsdev -Cc processor 2>/dev/null | wc -l | awk '{print $1}')
            fi
            MEM_SIZE=$(prtconf 2>/dev/null | awk '/Memory Size:/ {print $3" "$4}')
            if [ -z "$MEM_SIZE" ]; then
                mem_kb=$(bootinfo -r 2>/dev/null)
                MEM_SIZE="$((mem_kb / 1024 / 1024)) GB"
            fi
            ;;
        HP-UX)
            if [ -f /usr/contrib/bin/machinfo ]; then
                CPU_CORES=$(/usr/contrib/bin/machinfo | grep -i "Number of CPUs" | awk '{print $NF}')
                MEM_SIZE=$(/usr/contrib/bin/machinfo | grep -i "Memory" | awk '{print $(NF-1)" GB"}')
            fi
            if [ -z "$CPU_CORES" ]; then
                CPU_CORES=$(ioscan -fnC processor 2>/dev/null | grep -c processor)
            fi
            if [ -z "$CPU_CORES" ] || [ "$CPU_CORES" -eq 0 ]; then
                CPU_CORES=1
            fi
            ;;
        *)
            CPU_CORES=2
            MEM_SIZE="8 GB"
            ;;
    esac
}

# 디스크 여유 공간 체크
check_disk_space() {
    target_path="$1"
    if [ "$MOCK_MODE" = "true" ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  [MOCK] Disk Path: $target_path (Free: 500 GB)"
        else echo "  [MOCK] 디스크 경로: $target_path (여유 공간: 500 GB)"; fi
        return 0
    fi

    if [ ! -d "$target_path" ]; then
        if [ "$LANG_PREF" = "EN" ]; then printf "  Directory '$target_path' does not exist. Create it? (y/n): "
        else printf "  디렉토리 '$target_path'가 존재하지 않습니다. 생성하시겠습니까? (y/n): "; fi
        
        _read ans
        if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
            mkdir -p "$target_path"
            if [ $? -ne 0 ]; then
                if [ "$LANG_PREF" = "EN" ]; then echo "  [ERROR] Failed to create directory. Check permissions."
                else echo "  [오류] 디렉토리를 생성할 수 없습니다. 권한을 확인하십시오."; fi
                return 1
            fi
        else
            return 1
        fi
    fi

    free_kb=$(df -P "$target_path" | tail -n 1 | awk '{print $4}')
    free_gb=$((free_kb / 1024 / 1024))
    if [ "$LANG_PREF" = "EN" ]; then echo "  Free Disk Space: ${free_gb} GB"
    else echo "  디스크 여유 공간: ${free_gb} GB"; fi
    
    return 0
}

# DB 설정 및 sqlplus 확인
check_db_env() {
    if [ "$MOCK_MODE" = "true" ]; then
        return 0
    fi

    if [ -z "$ORACLE_HOME" ]; then
        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter ORACLE_HOME path: "
        else printf "  ORACLE_HOME 경로를 입력하세요: "; fi
        _read ORACLE_HOME
        export ORACLE_HOME
    fi

    if [ -z "$ORACLE_SID" ]; then
        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter ORACLE_SID: "
        else printf "  ORACLE_SID를 입력하세요: "; fi
        _read ORACLE_SID
        export ORACLE_SID
    fi

    if ! echo "$PATH" | grep -q "$ORACLE_HOME/bin"; then
        export PATH="$ORACLE_HOME/bin:$PATH"
    fi

    if ! command -v sqlplus >/dev/null 2>&1; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  [ERROR] sqlplus not found. Check Oracle environment variables."
        else echo "  [오류] sqlplus를 찾을 수 없습니다. Oracle 환경 변수를 재확인하십시오."; fi
        return 1
    fi
    return 0
}

# SQL*Plus를 통한 DB 세부 리소스 및 Multitenant 탐색
fetch_db_info() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _manual_rac _pname
    if [ "$LANG_PREF" = "EN" ]; then echo "  Analyzing Oracle Database Specifications..."
    else echo "  Oracle Database 사양 분석 중..."; fi
    
    IS_CDB="NO"
    CURRENT_CON_NAME="UNKNOWN"
    SELECTED_PDB=""
    PDB_CONNECT_STR=""
    PDB_SWITCH_SQL=""

    if [ "$MOCK_MODE" = "true" ]; then
        DB_VERSION="19.3.0.0.0 (Mocked Target CDB)"
        DB_CPU_COUNT=16
        DB_SGA_GB="32.00"
        DB_PGA_GB="16.00"
        DB_CHARSET="AL32UTF8"
        DB_CLUSTER="FALSE"
        IS_CDB="YES"
        CURRENT_CON_NAME="CDB\$ROOT"
        echo "  [Mock] DB Version: $DB_VERSION | CPU Count: $DB_CPU_COUNT | SGA: ${DB_SGA_GB}G | PGA: ${DB_PGA_GB}G | Charset: $DB_CHARSET | Multitenant: $IS_CDB ($CURRENT_CON_NAME)"
        
        echo "----------------------------------------------------------------------"
        if [ "$LANG_PREF" = "EN" ]; then echo "  [Oracle Multitenant Detected: Select Target PDB]"
        else echo "  [Oracle Multitenant 환경 감지: 작업 대상 PDB 선택]"; fi
        echo "   1) ORCLPDB1 (OPEN READ WRITE - 12.5 GB)"
        echo "   2) SALESPDB (OPEN READ WRITE - 45.2 GB)"
        echo "   N) 신규 PDB 생성/지정 (Create New PDB)"
        echo "----------------------------------------------------------------------"
        printf "  Select PDB (1-2 or N) [Default: 1]: "
        _read mock_pdb_sel
        if [ "$mock_pdb_sel" = "2" ]; then
            SELECTED_PDB="SALESPDB"
        elif [ "$mock_pdb_sel" = "N" ] || [ "$mock_pdb_sel" = "n" ]; then
            SELECTED_PDB="APP_PDB"
        else
            SELECTED_PDB="ORCLPDB1"
        fi
        PDB_SWITCH_SQL="ALTER SESSION SET CONTAINER = ${SELECTED_PDB};"

        # [FIX v09.02] MOCK 우회 경로 점검 — 여기는 v09.01 까지
        #   PDB_CONNECT_STR="system/manager@//localhost:1521/..." 를 하드코딩했다.
        #   그 탓에 join_pdb_connect(자격증명 승계) 로직이 MOCK 에서 한 번도
        #   타지 않았고, 실환경에서 즉시 ORA-01017 로 죽는 상태로 E2E 9종을
        #   전부 통과했다. 같은 구멍을 다시 만들지 않도록, MOCK 도 실제 경로와
        #   똑같이 서비스명을 입력받아 join_pdb_connect 를 거친다.
        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter PDB TNS Service Name or Easy Connect for Data Pump [Default: //localhost:1521/%s]: " "$SELECTED_PDB"
        else printf "  Data Pump(expdp/impdp) 연결용 PDB 서비스명/TNS 입력 [기본값: //localhost:1521/%s]: " "$SELECTED_PDB"; fi
        _read user_pdb_tns
        [ -z "$user_pdb_tns" ] && user_pdb_tns="//localhost:1521/${SELECTED_PDB}"

        PDB_CONNECT_STR=$(join_pdb_connect "$DB_CONN" "$user_pdb_tns")
        if [ -z "$PDB_CONNECT_STR" ]; then
            echo "  [안내] OS 인증(/ as sysdba)은 PDB 서비스로 재지정할 수 없습니다."
            echo "         Data Pump 전용 접속 계정을 입력하십시오."
            printf "  Data Pump 접속 계정 (예: system/pw@%s): " "$user_pdb_tns"
            _read_secret dp_pdb_conn MIG_DP_PDB_CONN
            if [ -n "$dp_pdb_conn" ]; then
                PDB_CONNECT_STR="$dp_pdb_conn"
            else
                echo "  [경고] 미입력 — Data Pump 는 메인 접속을 사용합니다."
                PDB_CONNECT_STR=""
            fi
        fi
        echo "  >> Target PDB: $SELECTED_PDB (Context Switch Auto-Configured)"
        echo "  >> Data Pump 접속: $(mask_conn_value "$PDB_CONNECT_STR")"
        return 0
    fi

    tmp_sql="$(tmpf db_info.sql)"
    tmp_out="$(tmpf db_info.out)"

    cat <<EOF > "$tmp_sql"
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 200 TRIMSPOOL ON SERVEROUTPUT ON
-- [v09.02] 접속은 EXIT FAILURE 로 잡고(아래 heredoc), 딕셔너리 조회는 CONTINUE 다.
--   계정에 v\$parameter SELECT 권한이 없어 한 줄만 실패하는 경우까지 '접속 실패' 로
--   몰아 전체 수동 입력으로 떨어지던 것을 막는다. 못 받은 항목은 각 변수의
--   [ -z ] 기본값 처리로 덮인다.
WHENEVER SQLERROR CONTINUE
SELECT 'VERSION:' || version FROM v\$instance;
SELECT 'CPU_COUNT:' || value FROM v\$parameter WHERE name='cpu_count';
SELECT 'SGA_TARGET:' || ROUND(value/1024/1024/1024, 2) FROM v\$parameter WHERE name='sga_target';
SELECT 'PGA_AGGREGATE_TARGET:' || ROUND(value/1024/1024/1024, 2) FROM v\$parameter WHERE name='pga_aggregate_target';
SELECT 'CHARSET:' || value FROM nls_database_parameters WHERE parameter='NLS_CHARACTERSET';
SELECT 'CLUSTER_DATABASE:' || UPPER(value) FROM v\$parameter WHERE name='cluster_database';
DECLARE
  v_is_cdb VARCHAR2(10) := 'NO';
  v_con_name VARCHAR2(128) := 'NON_CDB';
BEGIN
  -- CDB 여부 및 컨테이너 이름 조회 (11g 이하 버전 호환 동적 SQL)
  BEGIN
    EXECUTE IMMEDIATE 'SELECT cdb FROM v\$database' INTO v_is_cdb;
  EXCEPTION WHEN OTHERS THEN
    v_is_cdb := 'NO';
  END;
  BEGIN
    v_con_name := sys_context('USERENV', 'CON_NAME');
  EXCEPTION WHEN OTHERS THEN
    v_con_name := 'NON_CDB';
  END;
  IF v_con_name IS NULL THEN
    v_con_name := 'NON_CDB';
  END IF;
  DBMS_OUTPUT.PUT_LINE('IS_CDB:' || v_is_cdb);
  DBMS_OUTPUT.PUT_LINE('CON_NAME:' || v_con_name);
EXCEPTION WHEN OTHERS THEN
  DBMS_OUTPUT.PUT_LINE('IS_CDB:NO');
  DBMS_OUTPUT.PUT_LINE('CON_NAME:NON_CDB');
END;
/
EXIT;
EOF

    # [v09.02] 접속 실패를 '종료코드' 로 판정한다.
    #   WHENEVER SQLERROR EXIT FAILURE 를 connect 앞에 두면 접속 실패 시 sqlplus 가
    #   비0 으로 끝난다. tmp_sql 첫 줄에서 바로 CONTINUE 로 되돌리므로, 딕셔너리
    #   조회 한 줄이 권한 때문에 실패하는 것은 접속 실패로 취급되지 않는다.
    #   grep 은 2차 신호로만 남긴다 — 메시지 본문은 NLS 로 번역될 수 있지만
    #   ORA/SP2 코드 자체는 번역되지 않으므로 보조 판정으로는 유효하다.
    sqlplus -S /nolog <<CONNECT_EOF > "$tmp_out" 2>&1
WHENEVER SQLERROR EXIT FAILURE
WHENEVER OSERROR EXIT FAILURE
connect $DB_CONN
@$tmp_sql
CONNECT_EOF
    _fdi_rc=$?

    # 접속 자체가 깨졌는지 / 아무것도 못 받았는지를 먼저 가른다.
    #   _fdi_rc != 0        접속 또는 스크립트 기동 실패 (가장 확실한 신호)
    #   접속계열 ORA/SP2    인증·리스너·컨테이너 오류 (코드는 NLS 로 번역되지 않는다)
    #   VERSION 미수신      접속은 됐지만 딕셔너리를 전혀 못 읽은 경우
    # 반대로 v$parameter 한 줄만 권한으로 실패하는 상황은 여기서 걸리지 않고,
    # 아래 [ -z ] 기본값 처리로 넘어간다 (v09.01 까지는 전체 수동 입력이었다).
    _fdi_ver=$(grep "VERSION:" "$tmp_out" 2>/dev/null | cut -d':' -f2)
    if [ "$_fdi_rc" -ne 0 ] \
       || grep -qE "ORA-0?1017|ORA-12[0-9]{3}|ORA-28009|ORA-28000|ORA-65[0-9]{3}|SP2-0640|SP2-0306" "$tmp_out" \
       || [ -z "$_fdi_ver" ]; then
        if [ "$LANG_PREF" = "EN" ]; then
            echo "  [WARNING] DB connection failed or metadata cannot be retrieved. (sqlplus exit=${_fdi_rc})"
            echo "  Proceeding with manual input."
            printf "  - Oracle DB Version (e.g. 19.3.0.0.0 or 23.4.0.0.0): "
            _read DB_VERSION
            printf "  - DB CPU Count parameter: "
            _read DB_CPU_COUNT
            printf "  - NLS_CHARACTERSET (e.g. AL32UTF8): "
            _read DB_CHARSET
        else
            echo "  [경고] DB 접속에 실패하였거나 메타데이터 조회를 할 수 없습니다. (sqlplus exit=${_fdi_rc})"
            echo "  계정 권한이나 입력 정보를 확인해주세요. (수동 입력을 진행합니다.)"
            printf "  - Oracle DB 버전 (예: 19.3.0.0.0 또는 23.4.0.0.0): "
            _read DB_VERSION
            printf "  - DB CPU Count 파라미터값: "
            _read DB_CPU_COUNT
            printf "  - NLS_CHARACTERSET 문자셋 (예: AL32UTF8): "
            _read DB_CHARSET
        fi
        # [FIX v07/R2] v06 은 이 수동 입력 경로에서 DB_CLUSTER 를 설정하지 않아
        #              RAC 환경인데도 expdp/impdp 파라미터에 CLUSTER=N 이 누락되었다.
        #              (RAC 에서 워커가 타 노드로 분산되면 로컬 덤프 접근 실패)
        if [ "$LANG_PREF" = "EN" ]; then printf "  - Is this a RAC (cluster_database=TRUE) database? (y/N) [Default: N]: "
        else printf "  - 이 데이터베이스는 RAC(cluster_database=TRUE) 환경입니까? (y/N) [기본값: N]: "; fi
        _read _manual_rac
        case "$_manual_rac" in
            y|Y|yes|YES|true|TRUE) DB_CLUSTER="TRUE" ;;
            *) DB_CLUSTER="FALSE" ;;
        esac
        if [ "$DB_CLUSTER" = "TRUE" ]; then
            echo "  >> RAC 모드로 처리합니다. 생성되는 par 파일에 CLUSTER=N 이 자동 추가됩니다."
        fi
        rm -f "$tmp_sql" "$tmp_out"
        return 1
    fi

    DB_VERSION=$(grep "VERSION:" "$tmp_out" | cut -d':' -f2)
    DB_CPU_COUNT=$(grep "CPU_COUNT:" "$tmp_out" | cut -d':' -f2)
    DB_SGA_GB=$(grep "SGA_TARGET:" "$tmp_out" | cut -d':' -f2)
    DB_PGA_GB=$(grep "PGA_AGGREGATE_TARGET:" "$tmp_out" | cut -d':' -f2)
    DB_CHARSET=$(grep "CHARSET:" "$tmp_out" | cut -d':' -f2)
    # [v09.02] 수집 SQL 이 이미 UPPER(value) 를 쓰므로 소문자가 올 일은 없지만,
    #   바로 아래 IS_CDB / CON_NAME 은 셸에서 tr 을 한 번 더 거는 반면 이 값만
    #   SQL 에만 의존하는 비대칭이 있었다. 수동 입력 경로(아래)와도 형태를
    #   맞춰 두면 "= TRUE" 비교가 어느 경로로 들어와도 성립한다.
    DB_CLUSTER=$(grep "CLUSTER_DATABASE:" "$tmp_out" | cut -d':' -f2 | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')
    IS_CDB=$(grep "IS_CDB:" "$tmp_out" | cut -d':' -f2 | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')
    CURRENT_CON_NAME=$(grep "CON_NAME:" "$tmp_out" | cut -d':' -f2 | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')

    [ -z "$DB_VERSION" ] && DB_VERSION="Unknown"
    [ -z "$DB_CPU_COUNT" ] && DB_CPU_COUNT=1
    [ -z "$DB_SGA_GB" ] && DB_SGA_GB="0"
    [ -z "$DB_PGA_GB" ] && DB_PGA_GB="0"
    [ -z "$DB_CHARSET" ] && DB_CHARSET="Unknown"
    [ -z "$DB_CLUSTER" ] && DB_CLUSTER="FALSE"
    [ -z "$IS_CDB" ] && IS_CDB="NO"
    [ -z "$CURRENT_CON_NAME" ] && CURRENT_CON_NAME="NON_CDB"

    if [ "$LANG_PREF" = "EN" ]; then echo "  >> Success! DB Version: $DB_VERSION | cpu_count: $DB_CPU_COUNT | SGA: ${DB_SGA_GB}G | PGA: ${DB_PGA_GB}G | Charset: $DB_CHARSET | Multitenant: $IS_CDB ($CURRENT_CON_NAME)"
    else echo "  >> 수집 성공! DB 버전: $DB_VERSION | cpu_count: $DB_CPU_COUNT | SGA: ${DB_SGA_GB}G | PGA: ${DB_PGA_GB}G | 문자셋: $DB_CHARSET | Multitenant: $IS_CDB ($CURRENT_CON_NAME)"; fi
    
    rm -f "$tmp_sql" "$tmp_out"

    # Multitenant 적응형 PDB 선택 로직
    if [ "$IS_CDB" = "YES" ]; then
        if [ "$CURRENT_CON_NAME" = "CDB\$ROOT" ]; then
            pdb_tmp="$(tmpf pdb_list.tmp)"
            pdb_idx="$(tmpf pdb_list.indexed)"
            rm -f "$pdb_tmp" "$pdb_idx"

            sqlplus -S /nolog <<SQL_EOF > "$pdb_tmp" 2>/dev/null
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 200 TRIMSPOOL ON
SELECT name || '|' || open_mode || '|' || restricted FROM v\$pdbs WHERE name != 'PDB\$SEED' ORDER BY name;
EXIT;
SQL_EOF
            pdb_count=0
            echo "----------------------------------------------------------------------"
            if [ "$LANG_PREF" = "EN" ]; then echo "  [Oracle Multitenant Detected: Select Target PDB]"
            else echo "  [Oracle Multitenant 환경 감지: 작업 대상 PDB 선택]"; fi
            
            while IFS="|" read -r _pname _pmode _prestr; do
                _pname=$(echo "$_pname" | awk '{$1=$1;print}')
                _pmode=$(echo "$_pmode" | awk '{$1=$1;print}')
                if [ -n "$_pname" ] && ! echo "$_pname" | grep -qE "ORA-|SP2-"; then
                    pdb_count=$((pdb_count + 1))
                    printf "   %2d) %-25s (Open Mode: %s)\n" "$pdb_count" "$_pname" "$_pmode"
                    echo "$pdb_count:$_pname" >> "$pdb_idx"
                fi
            done < "$pdb_tmp"
            rm -f "$pdb_tmp"

            echo "    N) 신규 PDB 생성/지정 (Create New PDB DDL Mode)"
            echo "----------------------------------------------------------------------"
            
            while true; do
                if [ "$LANG_PREF" = "EN" ]; then printf "  Select PDB (1-%d or N) [Default: 1]: " "$pdb_count"
                else printf "  작업 대상 PDB를 선택하세요 (1-%d 또는 N) [기본값: 1]: " "$pdb_count"; fi
                _read pdb_choice
                [ -z "$pdb_choice" ] && pdb_choice="1"
                pdb_choice_upper=$(echo "$pdb_choice" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')

                if [ "$pdb_choice_upper" = "N" ]; then
                    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter New PDB Name to Create [Default: APP_PDB]: "
                    else printf "  신규 생성할 PDB 이름을 입력하세요 [기본값: APP_PDB]: "; fi
                    _read new_pdb_input
                    [ -z "$new_pdb_input" ] && new_pdb_input="APP_PDB"
                    SELECTED_PDB=$(echo "$new_pdb_input" | tr 'a-z' 'A-Z')
                    break
                elif echo "$pdb_choice" | grep -qE '^[0-9]+$'; then
                    matched_pdb=$(grep "^${pdb_choice}:" "$pdb_idx" 2>/dev/null | cut -d':' -f2)
                    if [ -n "$matched_pdb" ]; then
                        SELECTED_PDB="$matched_pdb"
                        break
                    fi
                fi
                echo "  [오류] 올바른 번호 또는 N을 입력하세요."
            done
            rm -f "$pdb_idx"

            PDB_SWITCH_SQL="ALTER SESSION SET CONTAINER = ${SELECTED_PDB};"
            echo "  >> Target PDB: ${SELECTED_PDB} (SQL 컨테이너 자동 전환 설정 완료)"

            # Data Pump 연결용 Easy Connect / TNS Service Name 질의
            if [ "$LANG_PREF" = "EN" ]; then printf "  Enter PDB TNS Service Name or Easy Connect for Data Pump [Default: //localhost:1521/%s]: " "$SELECTED_PDB"
            else printf "  Data Pump(expdp/impdp) 연결용 PDB 서비스명/TNS 입력 [기본값: //localhost:1521/%s]: " "$SELECTED_PDB"; fi
            _read user_pdb_tns
            [ -z "$user_pdb_tns" ] && user_pdb_tns="//localhost:1521/${SELECTED_PDB}"

            # [FIX v09.01] 서비스명만으로는 expdp/impdp 가 접속하지 못한다.
            #   메인 접속의 자격증명을 붙여 완전한 접속 문자열로 만든다.
            PDB_CONNECT_STR=$(join_pdb_connect "$DB_CONN" "$user_pdb_tns")
            if [ -z "$PDB_CONNECT_STR" ]; then
                echo "  [안내] OS 인증(/ as sysdba)은 PDB 서비스로 재지정할 수 없습니다."
                echo "         Data Pump 전용 접속 계정을 입력하십시오."
                printf "  Data Pump 접속 계정 (예: system/pw@%s): " "$user_pdb_tns"
                _read_secret dp_pdb_conn MIG_DP_PDB_CONN
                if [ -n "$dp_pdb_conn" ]; then
                    PDB_CONNECT_STR="$dp_pdb_conn"
                else
                    echo "  [경고] 미입력 — Data Pump 는 메인 접속(${SELECTED_PDB} 아님)을 사용합니다."
                    PDB_CONNECT_STR=""
                fi
            fi
            if [ -n "$PDB_CONNECT_STR" ]; then
                echo "  >> Data Pump 접속: $(mask_conn_value "$PDB_CONNECT_STR")"
            fi

        else
            SELECTED_PDB="$CURRENT_CON_NAME"
            PDB_SWITCH_SQL=""
            echo "  >> Currently inside PDB: ${SELECTED_PDB}"
        fi
    fi

    return 0
}

# DB Directory Object 목록 조회 및 신규 제안
setup_db_directory() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _create_opt _dir_sel _dname _sel_name _sel_path
    echo ""
    if [ "$LANG_PREF" = "EN" ]; then echo "  [DB Directory Object Setup]"
    else echo "  [DB Directory Object 설정]"; fi

    _dir_tmp="$(tmpf dir_list.tmp)"
    _dir_idx="$(tmpf dir_list.indexed)"
    rm -f "$_dir_tmp" "$_dir_idx"

    if [ "$MOCK_MODE" = "true" ]; then
        # [FIX v07] 파서가 '|' 구분자를 사용하므로 MOCK 데이터도 동일 형식이어야 한다
        printf "MIG_DIR|/backup/dump\n" >> "$_dir_tmp"
        printf "DATA_PUMP_DIR|/u01/app/oracle/admin/dpdump\n" >> "$_dir_tmp"
    else
        sqlplus -S /nolog <<SQL_EOF > "$_dir_tmp" 2>/dev/null
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500 TRIMSPOOL ON
$PDB_SWITCH_SQL
SELECT directory_name || '|' || directory_path FROM dba_directories ORDER BY directory_name;
EXIT;
SQL_EOF
        if grep -qE "ORA-|SP2-" "$_dir_tmp" 2>/dev/null; then
            echo "  [경고/WARNING] dba_directories 조회 실패. 직접 이름을 입력합니다."
            rm -f "$_dir_tmp" "$_dir_idx"
            while true; do
                printf "  Directory Object Name (Name): "
                _read DIR_OBJ_NAME
                DIR_OBJ_NAME=$(echo "$DIR_OBJ_NAME" | awk '{$1=$1;print}')
                [ -n "$DIR_OBJ_NAME" ] && break
                if [ "$UNATTENDED" = "true" ]; then
                    echo "  [무인모드/ERROR] 필수 입력값이 비어 있습니다. config 파일에 값을 지정하십시오."
                    return 1
                fi
            done
            while true; do
                printf "  Physical Disk Path (Path): "
                _read DIR_PHYSICAL_PATH
                DIR_PHYSICAL_PATH=$(echo "$DIR_PHYSICAL_PATH" | awk '{$1=$1;print}')
                [ -n "$DIR_PHYSICAL_PATH" ] && break
                if [ "$UNATTENDED" = "true" ]; then
                    echo "  [무인모드/ERROR] 필수 입력값이 비어 있습니다. config 파일에 값을 지정하십시오."
                    return 1
                fi
            done
            check_disk_space "$DIR_PHYSICAL_PATH"
            if [ -n "$PDB_SWITCH_SQL" ]; then
                CREATE_DIR_SQL="${PDB_SWITCH_SQL}
CREATE OR REPLACE DIRECTORY $DIR_OBJ_NAME AS '$DIR_PHYSICAL_PATH';"
            else
                CREATE_DIR_SQL="CREATE OR REPLACE DIRECTORY $DIR_OBJ_NAME AS '$DIR_PHYSICAL_PATH';"
            fi
            GRANT_DIR_SQL="GRANT READ, WRITE ON DIRECTORY $DIR_OBJ_NAME TO PUBLIC;"
            return 0
        fi
    fi

    _dir_count=0
    echo "  --------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "  Current Directory List:"
    else echo "  현재 등록된 Directory 목록:"; fi
    
    while IFS="|" read -r _dname _dpath; do
        _dname=$(echo "$_dname" | awk '{$1=$1;print}')
        _dpath=$(echo "$_dpath" | awk '{$1=$1;print}')
        if [ -n "$_dname" ] && [ -n "$_dpath" ]; then
            _dir_count=$((_dir_count + 1))
            printf "   %3d) %-30s --> %s\n" "$_dir_count" "$_dname" "$_dpath"
            printf "%d\t%s\t%s\n" "$_dir_count" "$_dname" "$_dpath" >> "$_dir_idx"
        fi
    done < "$_dir_tmp"
    echo "  --------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "   N  ) Create New Directory Object"
    else echo "   N  ) 신규 Directory Object 생성"; fi
    echo "  --------------------------------------------------"
    rm -f "$_dir_tmp"

    _sel_name=""
    _sel_path=""
    _is_existing="false"

    # [NEW v07] 등록된 Directory 가 하나도 없으면 선택 루프 대신 신규 생성으로 유도
    if [ "$_dir_count" -eq 0 ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  [INFO] No directory object found. Switching to new-directory creation."
        else echo "  [안내] 등록된 Directory Object 가 없어 신규 생성 모드로 전환합니다."; fi
        _dir_sel_forced="N"
    else
        _dir_sel_forced=""
    fi

    while true; do
        if [ -n "$_dir_sel_forced" ]; then
            _dir_sel="$_dir_sel_forced"
            _dir_sel_upper="N"
            _dir_sel_forced=""
        else
        if [ "$LANG_PREF" = "EN" ]; then printf "  Select number or N (New): "
        else printf "  번호를 선택하거나 N(신규)을 입력하세요: "; fi
        
        _read _dir_sel
        # [NEW v07] 무인 모드에서 값이 없으면 목록 1번을 사용해 무한 대기를 방지
        if [ -z "$_dir_sel" ] && [ "$UNATTENDED" = "true" ]; then
            echo "  [무인모드] Directory 선택값이 없어 목록 1번을 사용합니다."
            _dir_sel="1"
        fi
        _dir_sel_upper=$(echo "$_dir_sel" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')
        fi

        if [ "$_dir_sel_upper" = "N" ]; then
            while true; do
                if [ "$LANG_PREF" = "EN" ]; then printf "  Enter New Directory Object Name: "
                else printf "  새로 생성할 Directory Object 이름을 입력하세요: "; fi
                _read _sel_name
                _sel_name=$(echo "$_sel_name" | awk '{$1=$1;print}')
                [ -n "$_sel_name" ] && break
                if [ "$UNATTENDED" = "true" ]; then
                    echo "  [무인모드/ERROR] 필수 입력값이 비어 있습니다. config 파일에 값을 지정하십시오."
                    return 1
                fi
            done
            while true; do
                if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Physical Disk Path: "
                else printf "  실제 물리 디스크 경로를 입력하세요: "; fi
                _read _sel_path
                _sel_path=$(echo "$_sel_path" | awk '{$1=$1;print}')
                [ -n "$_sel_path" ] && break
                if [ "$UNATTENDED" = "true" ]; then
                    echo "  [무인모드/ERROR] 필수 입력값이 비어 있습니다. config 파일에 값을 지정하십시오."
                    return 1
                fi
            done
            _is_existing="false"
            break
        elif echo "$_dir_sel" | grep -qE '^[0-9]+$'; then
            _matched=$(grep "^${_dir_sel}	" "$_dir_idx" 2>/dev/null)
            if [ -n "$_matched" ]; then
                _sel_name=$(echo "$_matched" | cut -f2)
                _sel_path=$(echo "$_matched" | cut -f3)
                echo "  >> Selected: $_sel_name  -->  $_sel_path"
                _is_existing="true"
                break
            else
                echo "  [ERROR] Invalid Number."
                if [ "$UNATTENDED" = "true" ]; then
                    echo "  [무인모드/ERROR] config 의 _dir_sel 값이 목록에 없습니다. 처리를 중단합니다."
                    rm -f "$_dir_idx"
                    return 1
                fi
            fi
        else
            echo "  [ERROR] Enter Number or N."
            if [ "$UNATTENDED" = "true" ]; then
                echo "  [무인모드/ERROR] config 에 유효한 _dir_sel 값을 지정하십시오. 처리를 중단합니다."
                rm -f "$_dir_idx"
                return 1
            fi
        fi
    done

    rm -f "$_dir_idx"

    DIR_OBJ_NAME="$_sel_name"
    DIR_PHYSICAL_PATH="$_sel_path"

    check_disk_space "$DIR_PHYSICAL_PATH"

    _dir_prefix=""
    if [ -n "$PDB_SWITCH_SQL" ]; then
        _dir_prefix="${PDB_SWITCH_SQL}
"
    fi

    if [ "$_is_existing" = "true" ]; then
        if [ "$LANG_PREF" = "EN" ]; then printf "  Directory already exists in DB. Replace(Recreate) during script execution? (y/N) [Default: N]: "
        else printf "  DB에 이미 존재하는 디렉토리입니다. 스크립트 실행 시 재생성(REPLACE) 하시겠습니까? (y/N) [기본값: N]: "; fi
        
        _read _create_opt
        if [ "$_create_opt" = "y" ] || [ "$_create_opt" = "Y" ]; then
            CREATE_DIR_SQL="${_dir_prefix}CREATE OR REPLACE DIRECTORY $DIR_OBJ_NAME AS '$DIR_PHYSICAL_PATH';"
            GRANT_DIR_SQL="GRANT READ, WRITE ON DIRECTORY $DIR_OBJ_NAME TO PUBLIC;"
        else
            CREATE_DIR_SQL=""
            GRANT_DIR_SQL=""
        fi
    else
        if [ "$LANG_PREF" = "EN" ]; then printf "  Create this Directory Object during script execution? (Y/n) [Default: Y]: "
        else printf "  스크립트 실행 시 해당 Directory Object를 생성하시겠습니까? (Y/n) [기본값: Y]: "; fi
        _read _create_opt
        if [ -z "$_create_opt" ] || [ "$_create_opt" = "y" ] || [ "$_create_opt" = "Y" ]; then
            CREATE_DIR_SQL="${_dir_prefix}CREATE OR REPLACE DIRECTORY $DIR_OBJ_NAME AS '$DIR_PHYSICAL_PATH';"
            GRANT_DIR_SQL="GRANT READ, WRITE ON DIRECTORY $DIR_OBJ_NAME TO PUBLIC;"
        else
            CREATE_DIR_SQL=""
            GRANT_DIR_SQL=""
        fi
    fi
}

# 최적 Parallel 도수 계산
calculate_parallel_degree() {
    case "$CPU_CORES" in
        ''|*[!0-9]*) os_cpu=1 ;;
        *) os_cpu=$CPU_CORES ;;
    esac

    eff_cpu=$os_cpu
    if [ -n "$DB_CPU_COUNT" ] && echo "$DB_CPU_COUNT" | grep -qE '^[0-9]+$' 2>/dev/null; then
        if [ "$DB_CPU_COUNT" -gt 0 ] && [ "$DB_CPU_COUNT" -lt "$os_cpu" ]; then
            eff_cpu=$DB_CPU_COUNT
        fi
    fi

    CALC_PARALLEL=$(( eff_cpu / 2 ))
    [ $CALC_PARALLEL -lt 1 ] && CALC_PARALLEL=1
    
    if [ "$LANG_PREF" = "EN" ]; then printf "  >> Recommended PARALLEL degree: $CALC_PARALLEL (Based on ${eff_cpu} cpu cores).\n  Adjust? (Enter: Default, 0: Disable PARALLEL): "
    else printf "  >> 추천 PARALLEL 도수(기본값): $CALC_PARALLEL (CPU 코어 ${eff_cpu}개 기준 산정).\n  조정하시겠습니까? (엔터: 기본값 사용, 0: PARALLEL 미사용): "; fi
    _read user_parallel
    if [ -n "$user_parallel" ] && echo "$user_parallel" | grep -qE '^[0-9]+$' 2>/dev/null; then
        CALC_PARALLEL=$user_parallel
    fi
    
    if [ "$CALC_PARALLEL" -eq 0 ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> [INFO] PARALLEL is disabled."
        else echo "  >> [안내] PARALLEL 도수를 0으로 입력하셨습니다. PARALLEL 옵션을 강제 미사용합니다."; fi
    else
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> Final PARALLEL degree applied: $CALC_PARALLEL"
        else echo "  >> 최종 PARALLEL 도수 적용: $CALC_PARALLEL"; fi
    fi
}

generate_run_prompt() {
    script_file="$1"
    desc="$2"
    
    cat <<EOF >> "$script_file"

# ==============================================================================
# 안전 장치: 사용자 명시적 동의 후 실행 (백그라운드 감지 시 자동 스킵)
# ==============================================================================
if [ -t 0 ]; then
    printf "\n"
    printf "=====================================================================\n"
    printf "  [실행 확인/Run Check] $desc\n"
    printf "  대상 스크립트/Target Script: \$(basename \$0)\n"
    printf "=====================================================================\n"
    printf "정말로 이 스크립트를 즉시 실행하시겠습니까? / Run this script now? (y/N): "
    read _conf_ans
    if [ "\$_conf_ans" != "y" ] && [ "\$_conf_ans" != "Y" ]; then
        echo ">> 실행이 취소되었습니다. / Execution cancelled."
        exit 1
    fi
    echo ">> 작업을 백그라운드(nohup)로 실행하기를 권장합니다. / Background execution is recommended."
    echo ">> 백그라운드로 실행할 경우: nohup bash \$(basename \$0) > \$(basename \$0).out 2>&1 &"
    printf "지금 바로 이 창에서 포그라운드로 실행하시겠습니까? / Run in foreground? (y/N): "
    read _fg_ans
    if [ "\$_fg_ans" != "y" ] && [ "\$_fg_ans" != "Y" ]; then
        echo ">> 실행하지 않고 종료합니다. / Exiting without execution."
        exit 0
    fi
else
    echo ">> [INFO] 백그라운드(비대화형) 실행이 감지되어 사용자 확인 절차를 생략하고 즉시 실행합니다."
fi

EOF
}

# [NEW v07/B2] 모드 진입 시 생성물/선택 상태 전역 변수 초기화
reset_generation_state() {
    GENERATED_EST_SCRIPTS=""
    GENERATED_EXEC_SCRIPTS=""
    GENERATED_META_SCRIPTS=""
    GENERATED_STATS_SCRIPTS=""
    GENERATED_XFER_SCRIPTS=""
    GENERATED_TARGET_SCRIPTS=""
    GENERATED_UTIL_SCRIPTS=""
    GENERATED_CHECKSUM_SCRIPTS=""
    GENERATED_DEEPDIFF_SCRIPTS=""
    GENERATED_DEEPDIFF_PRE=""
    GENERATED_ROWCOUNT_SCRIPTS=""
    SELECTED_LIST=""
    FINAL_LIST=""
    FINAL_IN_CLAUSE=""
    SCHEMAS_LIST=""
    TABLES_LIST=""
    TBS_LIST=""
    REMAP_PARAMS=""
    TABLE_EXISTS_ACTION_PARAM=""
    MIG_PARAMS=""
    IMP_SOURCE_PARAM=""
    EXP_SOURCE_PARAM=""
    DUMP_EXISTS=0
    COMPRESSION_PARAM=""
    COMPRESSION_ALGO_PARAM=""
    VERSION_PARAM=""
    PREFLIGHT_RESULT="PASS"
    return 0
}

ask_to_run_script() {
    script_path="$1"
    if [ "$LANG_PREF" = "EN" ]; then printf "  >> Execute the generated script (${script_path}) now? (y/n): "
    else printf "  >> 방금 생성된 스크립트(${script_path})를 지금 실행하시겠습니까? (y/n): "; fi
    _read run_now
    if [ "$run_now" = "y" ] || [ "$run_now" = "Y" ]; then
        # [FIX v08.02] 생성 스크립트는 #!/bin/bash 셔뱅을 갖는다. sh 로 강제 실행하면
        #   Debian/Ubuntu 계열에서 sh=dash 라 셔뱅과 실행 셸이 어긋난다.
        #   (현재 생성물은 POSIX 호환이라 당장 깨지지는 않지만, 이후 bash 문법이
        #    추가되면 조용히 실패하므로 셔뱅과 일치시킨다.)
        bash "$script_path"
    else
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> Script execution pending. File: $script_path"
        else echo "  >> 스크립트 실행은 사용자가 보류하였습니다. 파일 위치: $script_path"; fi
    fi
}

# Multitenant 신규 Target PDB 생성 DDL 모듈 (23c / 19c)
generate_target_pdb_ddl() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _default_new_pdb
    if [ "$IS_CDB" != "YES" ]; then
        return 0
    fi

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "  [Oracle Multitenant: Target PDB Provisioning Generator]"
    else echo "  [Oracle Multitenant: Target PDB 신규 생성 DDL 모듈]"; fi
    
    if [ "$LANG_PREF" = "EN" ]; then printf "  Generate Target PDB Creation DDL (00_create_target_pdb_${UNIQUE_ID}.sql)? (Y/n) [Default: Y]: "
    else printf "  Target DB에 신규 PDB 생성 DDL(00_create_target_pdb_${UNIQUE_ID}.sql)을 생성하시겠습니까? (Y/n) [기본값: Y]: "; fi
    _read gen_pdb_opt
    if [ -z "$gen_pdb_opt" ] || [ "$gen_pdb_opt" = "y" ] || [ "$gen_pdb_opt" = "Y" ]; then
        _default_new_pdb="APP_PDB"
        [ -n "$SELECTED_PDB" ] && [ "$SELECTED_PDB" != "CDB\$ROOT" ] && _default_new_pdb="$SELECTED_PDB"

        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter New PDB Name to Create [Default: %s]: " "$_default_new_pdb"
        else printf "  생성할 PDB 이름을 입력하세요 [기본값: %s]: " "$_default_new_pdb"; fi
        _read user_pdb_name
        [ -z "$user_pdb_name" ] && user_pdb_name="$_default_new_pdb"
        user_pdb_name=$(echo "$user_pdb_name" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')

        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter PDB Admin Username [Default: pdbadmin]: "
        else printf "  PDB 관리자(Admin) 계정명을 입력하세요 [기본값: pdbadmin]: "; fi
        _read pdb_admin_user
        [ -z "$pdb_admin_user" ] && pdb_admin_user="pdbadmin"

        # [FIX v07/M3] 패스워드는 에코를 끄고 입력받으며, config 에 저장하지 않는다.
        #              환경변수 MIG_PDB_ADMIN_PASSWORD 로도 주입할 수 있다.
        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter PDB Admin Password (input hidden, Enter=default): "
        else printf "  PDB 관리자 패스워드를 입력하세요 (입력 숨김, 엔터=기본값): "; fi
        _read_secret pdb_admin_pwd MIG_PDB_ADMIN_PASSWORD
        if [ -z "$pdb_admin_pwd" ]; then
            pdb_admin_pwd="Manager2026!#"
            if [ "$LANG_PREF" = "EN" ]; then echo "  [SECURITY WARNING] Default password is used. Change it right after migration."
            else echo "  [보안 경고] 기본 패스워드가 사용되었습니다. 이관 직후 반드시 변경하십시오."; fi
        fi

        # [SEC v09.02] IDENTIFIED BY "..." 로 표현 가능한 패스워드인지 먼저 본다.
        #   큰따옴표가 있으면 생성물이 조용히 깨지므로 재입력을 유도한다.
        while ! check_sql_pwd_safe "PDB ADMIN 패스워드 / PDB admin password" "$pdb_admin_pwd"; do
            if [ "$UNATTENDED" = "true" ]; then
                if [ "$LANG_PREF" = "EN" ]; then echo "  [ABORT] Unattended mode cannot re-prompt. Fix MIG_PDB_ADMIN_PASSWORD and re-run."
                else echo "  [중단] 무인 모드에서는 재입력을 받을 수 없습니다. MIG_PDB_ADMIN_PASSWORD 를 고쳐 다시 실행하십시오."; fi
                return 1
            fi
            if [ "$LANG_PREF" = "EN" ]; then printf "  Re-enter PDB Admin Password (no double quotes): "
            else printf "  PDB 관리자 패스워드를 다시 입력하세요 (큰따옴표 제외): "; fi
            _read_secret pdb_admin_pwd ""
            [ -z "$pdb_admin_pwd" ] && pdb_admin_pwd="Manager2026!#"
        done

        # Check OMF (Oracle Managed Files)
        if [ "$LANG_PREF" = "EN" ]; then printf "  Is Target DB using OMF (Oracle Managed Files)? (Y/n) [Default: Y]: "
        else printf "  Target DB가 OMF(Oracle Managed Files, db_create_file_dest) 환경입니까? (Y/n) [기본값: Y]: "; fi
        _read is_omf_opt
        
        PDB_SQL="00_create_target_pdb_${UNIQUE_ID}.sql"
        PDB_SH="00_create_target_pdb_${UNIQUE_ID}.sh"
        echo "  * 생성 중: $PDB_SQL 및 $PDB_SH"

        cat <<EOF > "$PDB_SQL"
-- ==============================================================================
--  Oracle Multitenant Target PDB Provisioning Script
--  Target PDB: ${user_pdb_name}
--  Generated for Job: ${UNIQUE_ID}
-- ==============================================================================
SET ECHO ON LOGONLY SERVEROUTPUT ON
-- [SEC v09.02] ADMIN USER 패스워드에 '&' 가 있어도 SQL*Plus 치환변수로 먹히지
--   않도록 반드시 켜 둔다. 이 줄을 지우면 다른 패스워드로 PDB 가 만들어진다.
$(sql_define_off)
-- [v09.02] 생성 실패를 셸이 \$? 로 알 수 있게 한다. PDB 생성은 뒤 단계의
--   전제조건이므로 여기서 멈추는 것이 맞다 (ROW COUNT / DEEP DIFF 처럼
--   '에러를 전부 기록해야 하는' 성격이 아니다).
WHENEVER SQLERROR EXIT FAILURE
WHENEVER OSERROR EXIT FAILURE
SPOOL 00_create_target_pdb_${UNIQUE_ID}.log

PROMPT ========================================================================
PROMPT 1. Creating Pluggable Database ${user_pdb_name} from PDB\$SEED
PROMPT ========================================================================
EOF

        if [ -z "$is_omf_opt" ] || [ "$is_omf_opt" = "y" ] || [ "$is_omf_opt" = "Y" ]; then
            cat <<EOF >> "$PDB_SQL"
CREATE PLUGGABLE DATABASE ${user_pdb_name}
  ADMIN USER ${pdb_admin_user} IDENTIFIED BY "${pdb_admin_pwd}"
  ROLES = (DBA)
  DEFAULT TABLESPACE USERS;
EOF
        else
            if [ "$LANG_PREF" = "EN" ]; then printf "  Enter PDB Target Datafile Directory: "
            else printf "  PDB 데이터파일 저장 디렉토리 경로: "; fi
            _read pdb_df_dir
            [ -z "$pdb_df_dir" ] && pdb_df_dir="$DIR_PHYSICAL_PATH"
            cat <<EOF >> "$PDB_SQL"
CREATE PLUGGABLE DATABASE ${user_pdb_name}
  ADMIN USER ${pdb_admin_user} IDENTIFIED BY "${pdb_admin_pwd}"
  ROLES = (DBA)
  DEFAULT TABLESPACE USERS
  DATAFILE SIZE 100M AUTOEXTEND ON NEXT 100M MAXSIZE UNLIMITED
  FILE_NAME_CONVERT = ('pdbseed', '${user_pdb_name}');
EOF
        fi

        cat <<EOF >> "$PDB_SQL"

PROMPT ========================================================================
PROMPT 2. Opening PDB and Saving State (Auto-open on DB restart)
PROMPT ========================================================================
ALTER PLUGGABLE DATABASE ${user_pdb_name} OPEN READ WRITE;
ALTER PLUGGABLE DATABASE ${user_pdb_name} SAVE STATE;

PROMPT ========================================================================
PROMPT 3. Configuring Local Undo Retention inside ${user_pdb_name}
PROMPT ========================================================================
ALTER SESSION SET CONTAINER = ${user_pdb_name};
BEGIN
  EXECUTE IMMEDIATE 'ALTER SYSTEM SET undo_retention = 14400 SCOPE=BOTH';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

SPOOL OFF
EXIT;
EOF

        cat <<EOF > "$PDB_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo ">> Target Multitenant CDB에 신규 PDB(${user_pdb_name})를 생성하고 기동합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$PDB_SQL
CONNECT_EOF
# [v09.02] SQL 측에 WHENEVER SQLERROR EXIT FAILURE 를 걸었으므로 종료코드로 판정한다.
#   로그를 ORA- 정규식으로 긁는 방식보다 확실하다 (PDB 생성 SQL 에는 실패가
#   정상인 문장이 없어서 이 방식을 쓸 수 있다).
_pdb_rc=\$?
if [ "\$_pdb_rc" -ne 0 ]; then
    echo ">> [실패] PDB 생성이 실패했습니다 (exit=\$_pdb_rc)."
    echo ">>        로그를 확인하십시오: 00_create_target_pdb_${UNIQUE_ID}.log"
    exit "\$_pdb_rc"
fi
echo ">> PDB 생성이 완료되었습니다. 로그: 00_create_target_pdb_${UNIQUE_ID}.log"
EOF
        chmod 700 "$PDB_SH"
        # [SEC v09.02] 이 SQL 에는 ADMIN USER 패스워드가 평문으로 들어간다.
        #   DEEP DIFF 의 DB Link 생성 SQL 은 600 으로 보호하면서 여기만 644 로
        #   남아 있었다(다른 OS 계정이 읽을 수 있음). 같은 기준으로 맞춘다.
        chmod 600 "$PDB_SQL" 2>/dev/null
        if [ "$LANG_PREF" = "EN" ]; then
            echo "  >> NOTE: ${PDB_SQL} contains the admin password in clear text (mode 600)."
            echo "           Delete it after use, and strip the password before sharing."
        else
            echo "  >> 주의: ${PDB_SQL} 에는 관리자 패스워드가 평문으로 들어 있습니다 (권한 600)."
            echo "           사용 후 삭제하시고, 공유하실 때는 패스워드를 지워 주십시오."
        fi

        GENERATED_TARGET_SCRIPTS="$PDB_SH $GENERATED_TARGET_SCRIPTS"
        SELECTED_PDB="$user_pdb_name"
        PDB_SWITCH_SQL="ALTER SESSION SET CONTAINER = ${SELECTED_PDB};"
    fi
}

select_migration_targets() {
    target_type="$1"
    conn_str="$2"
    
    echo ""
    if [ "$LANG_PREF" = "EN" ]; then echo "  [Target List Inquiry & Selection]"
    else echo "  [대상 목록 조회 및 선택]"; fi
    
    items_file="$(tmpf mig_items.tmp)"
    rm -f "$items_file"
    
    case "$target_type" in
        SCHEMA)
            sqlplus -S /nolog <<EOF > "$items_file" 2>&1
connect $conn_str
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 100
$PDB_SWITCH_SQL
SELECT username FROM dba_users${DBLINK_SUFFIX} 
WHERE username NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','WMSYS','XDB','ANONYMOUS','XS\$NULL','ORDDATA','ORDPLUGINS','SI_INFORMTN_SCHEMA','MDSYS','ORACLE_OCM', 'DIP', 'ORACLE_MAINT', 'GSMADMIN_INTERNAL', 'GSMCATUSER', 'GGSYS', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSMAC', 'C##DIV', 'AUDSYS')
ORDER BY username;
EXIT;
EOF
            ;;
        TABLE)
            if [ "$LANG_PREF" = "EN" ]; then echo "  [Schema List for Table Selection]"
            else echo "  [대상 스키마 목록 조회 (기본 시스템 계정 제외)]"; fi
            
            schema_file="$(tmpf mig_schemas.tmp)"
            schema_idx="$(tmpf mig_schemas.indexed)"
            rm -f "$schema_file" "$schema_idx"

            if [ "$MOCK_MODE" = "true" ]; then
                cat <<EOF > "$schema_file"
BLK_FIN_02
KMSUNG
SCOTT
TEST
EOF
            else
                sqlplus -S /nolog <<EOF > "$schema_file" 2>&1
connect $conn_str
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 100
$PDB_SWITCH_SQL
SELECT username FROM dba_users${DBLINK_SUFFIX} 
WHERE username NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','WMSYS','XDB','ANONYMOUS','XS\$NULL','ORDDATA','ORDPLUGINS','SI_INFORMTN_SCHEMA','MDSYS','ORACLE_OCM', 'DIP', 'ORACLE_MAINT', 'GSMADMIN_INTERNAL', 'GSMCATUSER', 'GGSYS', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSMAC', 'C##DIV', 'AUDSYS')
ORDER BY username;
EXIT;
EOF
            fi

            echo "  --------------------------------------------------"
            sch_count=0
            while read -r s; do
                s=$(echo "$s" | awk '{$1=$1;print}')
                if [ -n "$s" ] && ! echo "$s" | grep -qE "ORA-|SP2-"; then
                    sch_count=$((sch_count + 1))
                    echo "$sch_count:$s" >> "$schema_idx"
                    printf "   %3d) %s\n" "$sch_count" "$s"
                fi
            done < "$schema_file"
            echo "  --------------------------------------------------"
            rm -f "$schema_file"

            if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Schema Name or Number (Comma/Space, Range e.g. 2-5, Empty for all): "
            else printf "  테이블을 조회할 스키마명 또는 번호를 입력하세요 (쉼표/공백 구분, 범위: 2-5, 공백 시 전체) [예: 9 또는 KMSUNG 또는 1,2]: "; fi
            _read sch_input

            sch_input_cleaned=$(echo "$sch_input" | tr ',' ' ')
            selected_schemas=""

            for sch_item in $sch_input_cleaned; do
                sch_item_upper=$(echo "$sch_item" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')
                if echo "$sch_item_upper" | grep -qE '^[0-9]+-[0-9]+$'; then
                    r_start=$(echo "$sch_item_upper" | cut -d'-' -f1)
                    r_end=$(echo "$sch_item_upper" | cut -d'-' -f2)
                    if [ "$r_start" -le "$r_end" ] && [ "$r_start" -ge 1 ] && [ "$r_end" -le "$sch_count" ]; then
                        si=$r_start
                        while [ $si -le $r_end ]; do
                            matched_sch=$(grep "^${si}:" "$schema_idx" 2>/dev/null | cut -d':' -f2)
                            if [ -n "$matched_sch" ]; then
                                if [ -z "$selected_schemas" ]; then selected_schemas="'$matched_sch'"; else selected_schemas="${selected_schemas},'$matched_sch'"; fi
                            fi
                            si=$((si + 1))
                        done
                    fi
                elif echo "$sch_item_upper" | grep -qE '^[0-9]+$'; then
                    matched_sch=$(grep "^${sch_item_upper}:" "$schema_idx" 2>/dev/null | cut -d':' -f2)
                    if [ -n "$matched_sch" ]; then
                        if [ -z "$selected_schemas" ]; then selected_schemas="'$matched_sch'"; else selected_schemas="${selected_schemas},'$matched_sch'"; fi
                    fi
                elif [ -n "$sch_item_upper" ] && [ "$sch_item_upper" != "ALL" ]; then
                    if [ -z "$selected_schemas" ]; then selected_schemas="'$sch_item_upper'"; else selected_schemas="${selected_schemas},'$sch_item_upper'"; fi
                fi
            done
            rm -f "$schema_idx"

            if [ -n "$selected_schemas" ]; then
                where_clause="WHERE t.owner IN ($selected_schemas)"
            else
                where_clause="WHERE t.owner NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','WMSYS','XDB','ANONYMOUS','XS\$NULL','ORDDATA','ORDPLUGINS','SI_INFORMTN_SCHEMA','MDSYS','ORACLE_OCM')"
            fi
            
            if [ "$LANG_PREF" = "EN" ]; then echo "  >> Fetching Table list and calculating sizes..."
            else echo "  >> 테이블 목록 및 사이즈 정보를 수집 중입니다..."; fi

            if [ "$MOCK_MODE" = "true" ]; then
                cat <<EOF > "$items_file"
KMSUNG.TB_CUSTOMER_INFO|Normal|524288000
KMSUNG.TB_ORDER_HIST|Partition|2147483648
KMSUNG.TB_PAYMENT_LOG|Partition|5368709120
KMSUNG.TB_PRODUCT_CATALOG|Normal|104857600
SCOTT.EMP|Normal|1048576
SCOTT.DEPT|Normal|524288
EOF
            else
                sqlplus -S /nolog <<EOF > "$items_file" 2>&1
connect $conn_str
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500
$PDB_SWITCH_SQL
SELECT 
    t.owner || '.' || t.table_name || '|' ||
    CASE WHEN pt.table_name IS NOT NULL THEN 'Partition' ELSE 'Normal' END || '|' ||
    NVL(SUM(s.bytes), 0)
FROM dba_tables${DBLINK_SUFFIX} t
LEFT JOIN dba_part_tables${DBLINK_SUFFIX} pt ON t.owner = pt.owner AND t.table_name = pt.table_name
LEFT JOIN dba_segments${DBLINK_SUFFIX} s ON t.owner = s.owner AND t.table_name = s.segment_name
$where_clause
GROUP BY t.owner, t.table_name, pt.table_name
ORDER BY t.table_name;
EXIT;
EOF
            fi
            ;;
        TABLESPACE)
            if [ "$MOCK_MODE" = "true" ]; then
                cat <<EOF > "$items_file"
USERS|524288000
WWW|0
XXX|0
EOF
            else
                sqlplus -S /nolog <<EOF > "$items_file" 2>&1
connect $conn_str
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500
$PDB_SWITCH_SQL
SELECT t.tablespace_name || '|' || NVL(s.bytes, 0)
FROM dba_tablespaces${DBLINK_SUFFIX} t
LEFT JOIN (SELECT tablespace_name, SUM(bytes) bytes FROM dba_segments${DBLINK_SUFFIX} GROUP BY tablespace_name) s
ON t.tablespace_name = s.tablespace_name
ORDER BY t.tablespace_name;
EXIT;
EOF
            fi
            ;;
    esac

    if grep -q "ORA-" "$items_file" 2>/dev/null; then
        echo "  [경고/WARNING] Cannot query target list from DB. Proceeding manually."
        rm -f "$items_file"
        return 1
    fi

    count=0
    
    if [ "$target_type" = "TABLE" ]; then
        echo "  --------------------------------------------------------------------------------"
        if [ "$LANG_PREF" = "EN" ]; then printf "  %4s | %-35s | %-12s | %-15s\n" "No." "Table Name (SCHEMA.TABLE)" "Type" "Size"
        else printf "  %4s | %-35s | %-12s | %-15s\n" "번호" "테이블명 (SCHEMA.TABLE_NAME)" "Type" "Size"; fi
        echo "  --------------------------------------------------------------------------------"
        
        while IFS="|" read -r t_name t_type t_bytes; do
            if echo "$t_name" | grep -qE "ORA-|SP2-"; then continue; fi
            if [ -n "$t_name" ] && [ -n "$t_type" ] && [ -n "$t_bytes" ]; then
                count=$((count + 1))
                echo "$count:$t_name" >> "${items_file}.indexed"
                
                size_str=$(awk -v b="$t_bytes" 'BEGIN {
                    if (b >= 1073741824) printf "%.2f GB", b/1073741824
                    else printf "%.2f MB", b/1048576
                }')
                
                printf "  %4d | %-35s | %-12s | %-15s\n" "$count" "$t_name" "$t_type" "$size_str"
            fi
        done < "$items_file"
        echo "  --------------------------------------------------------------------------------"
    else
        echo "  --------------------------------------------------------------------------------"
        while IFS="|" read -r item_name item_bytes; do
            item_name=$(echo "$item_name" | awk '{$1=$1;print}')
            if echo "$item_name" | grep -qE "ORA-|SP2-"; then continue; fi
            if [ -n "$item_name" ]; then
                count=$((count + 1))
                echo "$count:$item_name" >> "${items_file}.indexed"
                
                if [ -n "$item_bytes" ] && echo "$item_bytes" | grep -qE '^[0-9]+$' 2>/dev/null; then
                    if [ "$item_bytes" -eq 0 ]; then
                        if [ "$LANG_PREF" = "EN" ]; then printf "   %3d) %-30s (0 MB - [Warning] Empty/No Segments)\n" "$count" "$item_name"
                        else printf "   %3d) %-30s (0 MB - [주의] 세그먼트/데이터 없음)\n" "$count" "$item_name"; fi
                    else
                        size_str=$(awk -v b="$item_bytes" 'BEGIN {
                            if (b >= 1073741824) printf "%.2f GB", b/1073741824
                            else printf "%.2f MB", b/1048576
                        }')
                        printf "   %3d) %-30s (%s)\n" "$count" "$item_name" "$size_str"
                    fi
                else
                    printf "   %3d) %s\n" "$count" "$item_name"
                fi
            fi
        done < "$items_file"
        echo "  --------------------------------------------------------------------------------"
    fi

    if [ $count -eq 0 ]; then
        echo "  조회된 대상이 없습니다. 수동 입력을 진행합니다. / No targets found. Manual input."
        rm -f "$items_file" "${items_file}.indexed"
        return 1
    fi

    if [ "$LANG_PREF" = "EN" ]; then printf "  Select targets by number (Comma separated, e.g. 1,2,5 or Range 2-5, or ALL): "
    else printf "  이관할 대상을 번호로 선택하십시오 (쉼표/공백 구분, 예: 1,2,5 또는 1 3 4, 범위: 2-5, 전체: ALL): "; fi
    _read choices

    # [NEW v07] 무인 모드에서 선택값이 없으면 전체(ALL)로 간주
    if [ -z "$choices" ] && [ "$UNATTENDED" = "true" ]; then
        echo "  [무인모드] 대상 선택값이 없어 ALL 로 처리합니다."
        choices="ALL"
    fi
    choices_upper=$(echo "$choices" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')
    if [ "$choices_upper" = "ALL" ]; then
        selected_items=""
        i=1
        while [ $i -le $count ]; do
            item_val=$(grep "^${i}:" "${items_file}.indexed" | cut -d':' -f2)
            if [ -n "$item_val" ]; then
                if [ -z "$selected_items" ]; then
                    selected_items="$item_val"
                else
                    selected_items="${selected_items},${item_val}"
                fi
            fi
            i=$((i + 1))
        done
        rm -f "$items_file" "${items_file}.indexed"
        echo "  >> [ALL] 전체 ${count}개 대상이 선택되었습니다: $selected_items"
        SELECTED_LIST="$selected_items"
        return 0
    fi

    selected_items=""
    choices_cleaned=$(echo "$choices" | tr ',' ' ')

    for ch in $choices_cleaned; do
        if echo "$ch" | grep -qE '^[0-9]+-[0-9]+$'; then
            range_start=$(echo "$ch" | cut -d'-' -f1)
            range_end=$(echo "$ch" | cut -d'-' -f2)
            if [ "$range_start" -le "$range_end" ] && [ "$range_start" -ge 1 ] && [ "$range_end" -le "$count" ]; then
                i=$range_start
                while [ $i -le $range_end ]; do
                    item_val=$(grep "^${i}:" "${items_file}.indexed" | cut -d':' -f2)
                    if [ -n "$item_val" ]; then
                        if [ -z "$selected_items" ]; then
                            selected_items="$item_val"
                        else
                            selected_items="${selected_items},${item_val}"
                        fi
                    fi
                    i=$((i + 1))
                done
            fi
        else
            case "$ch" in
                [0-9]*)
                    item_val=$(grep "^${ch}:" "${items_file}.indexed" | cut -d':' -f2)
                    if [ -n "$item_val" ]; then
                        if [ -z "$selected_items" ]; then
                            selected_items="$item_val"
                        else
                            selected_items="${selected_items},${item_val}"
                        fi
                    fi
                    ;;
                *)
                    item_val=$(echo "$ch" | tr 'a-z' 'A-Z')
                    if [ -z "$selected_items" ]; then
                        selected_items="$item_val"
                    else
                        selected_items="${selected_items},${item_val}"
                    fi
                    ;;
            esac
        fi
    done

    rm -f "$items_file" "${items_file}.indexed"
    SELECTED_LIST="$selected_items"
    echo "  >> 선택 완료: $SELECTED_LIST"
    return 0
}

generate_target_env_ddl() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _tgt_in_clause
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "  [Target Environment Setup DDL Generator]"
    else echo "  [Target DB 사전 환경 구축 DDL 생성 모듈]"; fi
    
    if [ "$LANG_PREF" = "EN" ]; then printf "  Generate Target User & Tablespace creation DDL (00_create_target_env_${UNIQUE_ID}.sql)? (Y/n) [Default: Y]: "
    else printf "  Target DB 사전 적용용 계정/테이블스페이스 DDL 생성 (00_create_target_env_${UNIQUE_ID}.sql)? (Y/n) [기본값: Y]: "; fi
    _read gen_env_opt
    if [ -z "$gen_env_opt" ] || [ "$gen_env_opt" = "y" ] || [ "$gen_env_opt" = "Y" ]; then
        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Target DB Datafile Storage Directory [Default: %s]: " "$DIR_PHYSICAL_PATH"
        else printf "  Target DB 데이터파일(Datafile) 저장 디렉토리 경로 입력 [기본값: %s]: " "$DIR_PHYSICAL_PATH"; fi
        _read user_df_dir
        [ -z "$user_df_dir" ] && user_df_dir="$DIR_PHYSICAL_PATH"

        ENV_SQL="00_create_target_env_${UNIQUE_ID}.sql"
        ENV_SH="00_create_target_env_${UNIQUE_ID}.sh"
        echo "  * 생성 중: $ENV_SQL 및 $ENV_SH"
        
        cat <<EOF > "$ENV_SQL"
-- ==============================================================================
--  Target DB Pre-requisite Setup Script (Tablespaces & Users)
--  Generated for Migration Job: ${UNIQUE_ID}
-- ==============================================================================
SET ECHO ON LOGONLY
SPOOL 00_create_target_env_${UNIQUE_ID}.log

-- [Multitenant Mode] Switch session container to target PDB
$PDB_SWITCH_SQL

-- [Oracle 12c+ Compatibility] Bypass C## prefix requirement if in CDB\$ROOT
BEGIN
  EXECUTE IMMEDIATE 'ALTER SESSION SET "_ORACLE_SCRIPT"=true';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

PROMPT ========================================================================
PROMPT 1. Creating Tablespaces (Default size: 100M with AUTOEXTEND)
PROMPT ========================================================================
EOF

        if [ "$MOCK_MODE" = "true" ]; then
            cat <<EOF >> "$ENV_SQL"
CREATE TABLESPACE USERS DATAFILE '${user_df_dir}/users01.dbf' SIZE 100M AUTOEXTEND ON NEXT 100M MAXSIZE UNLIMITED;
CREATE BIGFILE TABLESPACE TS_DATA DATAFILE '${user_df_dir}/ts_data01.dbf' SIZE 500M AUTOEXTEND ON NEXT 100M MAXSIZE UNLIMITED;

PROMPT ========================================================================
PROMPT 2. Creating Database Users & Granting Privileges
PROMPT ========================================================================
CREATE USER KMSUNG IDENTIFIED BY "oracle" DEFAULT TABLESPACE USERS TEMPORARY TABLESPACE TEMP;
GRANT CONNECT, RESOURCE, CREATE SESSION, UNLIMITED TABLESPACE TO KMSUNG;

CREATE USER SCOTT IDENTIFIED BY "tiger" DEFAULT TABLESPACE USERS TEMPORARY TABLESPACE TEMP;
GRANT CONNECT, RESOURCE, CREATE SESSION, UNLIMITED TABLESPACE TO SCOTT;

-- [Oracle 23c Compatibility] Grant DB_DEVELOPER_ROLE if available
BEGIN
  EXECUTE IMMEDIATE 'GRANT DB_DEVELOPER_ROLE TO KMSUNG';
  EXECUTE IMMEDIATE 'GRANT DB_DEVELOPER_ROLE TO SCOTT';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
EOF
        else
            _tgt_raw_list=""
            if [ -n "$FINAL_LIST" ]; then _tgt_raw_list="$FINAL_LIST"
            elif [ -n "$SELECTED_LIST" ]; then _tgt_raw_list="$SELECTED_LIST"
            elif [ -n "$SCHEMAS_LIST" ]; then _tgt_raw_list="$SCHEMAS_LIST"
            elif [ -n "$TABLES_LIST" ]; then _tgt_raw_list="$TABLES_LIST"
            elif [ -n "$TBS_LIST" ]; then _tgt_raw_list="$TBS_LIST"
            fi

            _tgt_in_clause=""
            IFS_BACKUP=$IFS; IFS=","
            for _itm in $_tgt_raw_list; do
                _itm_c=$(echo "$_itm" | awk '{$1=$1;print}')
                if [ -n "$_itm_c" ]; then
                    [ -n "$_tgt_in_clause" ] && _tgt_in_clause="${_tgt_in_clause},"
                    _tgt_in_clause="${_tgt_in_clause}'${_itm_c}'"
                fi
            done
            IFS=$IFS_BACKUP

            _tbs_where_clause="WHERE t.tablespace_name NOT IN ('SYSTEM','SYSAUX','TEMP','UNDOTBS1','UNDOTBS2','USERS')"
            _usr_where_clause="WHERE username NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','WMSYS','XDB','ANONYMOUS','XS\$NULL','ORDDATA','ORDPLUGINS','SI_INFORMTN_SCHEMA','MDSYS','ORACLE_OCM', 'DIP', 'ORACLE_MAINT', 'GSMADMIN_INTERNAL', 'GSMCATUSER', 'GGSYS', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSMAC', 'AUDSYS')"

            if [ -n "$_tgt_in_clause" ] && [ "$MIG_TYPE" != "FULL" ]; then
                if [ "$MIG_TYPE" = "SCHEMA" ]; then
                    _tbs_where_clause="WHERE t.tablespace_name IN (SELECT default_tablespace FROM dba_users${DBLINK_SUFFIX} WHERE username IN ($_tgt_in_clause) UNION SELECT tablespace_name FROM dba_segments${DBLINK_SUFFIX} WHERE owner IN ($_tgt_in_clause)) AND t.tablespace_name NOT IN ('SYSTEM','SYSAUX','TEMP','UNDOTBS1','UNDOTBS2','USERS')"
                    _usr_where_clause="WHERE username IN ($_tgt_in_clause) AND username NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','WMSYS','XDB','ANONYMOUS','XS\$NULL','ORDDATA','ORDPLUGINS','SI_INFORMTN_SCHEMA','MDSYS','ORACLE_OCM', 'DIP', 'ORACLE_MAINT', 'GSMADMIN_INTERNAL', 'GSMCATUSER', 'GGSYS', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSMAC', 'AUDSYS')"
                elif [ "$MIG_TYPE" = "TABLE" ]; then
                    _tbs_where_clause="WHERE t.tablespace_name IN (SELECT tablespace_name FROM dba_tables${DBLINK_SUFFIX} WHERE owner || '.' || table_name IN ($_tgt_in_clause) UNION SELECT tablespace_name FROM dba_segments${DBLINK_SUFFIX} WHERE owner || '.' || segment_name IN ($_tgt_in_clause)) AND t.tablespace_name NOT IN ('SYSTEM','SYSAUX','TEMP','UNDOTBS1','UNDOTBS2','USERS')"
                    _usr_where_clause="WHERE username IN (SELECT owner FROM dba_tables${DBLINK_SUFFIX} WHERE owner || '.' || table_name IN ($_tgt_in_clause)) AND username NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','WMSYS','XDB','ANONYMOUS','XS\$NULL','ORDDATA','ORDPLUGINS','SI_INFORMTN_SCHEMA','MDSYS','ORACLE_OCM', 'DIP', 'ORACLE_MAINT', 'GSMADMIN_INTERNAL', 'GSMCATUSER', 'GGSYS', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSMAC', 'AUDSYS')"
                elif [ "$MIG_TYPE" = "TABLESPACE" ]; then
                    _tbs_where_clause="WHERE t.tablespace_name IN ($_tgt_in_clause) AND t.tablespace_name NOT IN ('SYSTEM','SYSAUX','TEMP','UNDOTBS1','UNDOTBS2','USERS')"
                    _usr_where_clause="WHERE username IN (SELECT owner FROM dba_segments${DBLINK_SUFFIX} WHERE tablespace_name IN ($_tgt_in_clause)) AND username NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','WMSYS','XDB','ANONYMOUS','XS\$NULL','ORDDATA','ORDPLUGINS','SI_INFORMTN_SCHEMA','MDSYS','ORACLE_OCM', 'DIP', 'ORACLE_MAINT', 'GSMADMIN_INTERNAL', 'GSMCATUSER', 'GGSYS', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSMAC', 'AUDSYS')"
                fi
            fi

            sqlplus -S /nolog <<SQL_EOF >> "$ENV_SQL" 2>/dev/null
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500 TRIMSPOOL ON
$PDB_SWITCH_SQL
SELECT 'CREATE ' || CASE WHEN NVL(t.bigfile, 'NO') = 'YES' OR NVL(s.total_mb, 0) >= 30720 THEN 'BIGFILE ' ELSE '' END ||
       'TABLESPACE ' || t.tablespace_name || ' DATAFILE ''' || '$user_df_dir/' || LOWER(t.tablespace_name) || '01.dbf'' SIZE 100M AUTOEXTEND ON NEXT 100M MAXSIZE UNLIMITED;'
FROM dba_tablespaces${DBLINK_SUFFIX} t
LEFT JOIN (SELECT tablespace_name, SUM(bytes)/1024/1024 as total_mb FROM dba_data_files${DBLINK_SUFFIX} GROUP BY tablespace_name) s
  ON t.tablespace_name = s.tablespace_name
$_tbs_where_clause;

SELECT 'CREATE USER ' || username || ' IDENTIFIED BY "oracle" DEFAULT TABLESPACE ' || NVL(default_tablespace, 'USERS') || ' TEMPORARY TABLESPACE ' || NVL(temporary_tablespace, 'TEMP') || ';' || CHR(10) ||
       'GRANT CONNECT, RESOURCE, CREATE SESSION, UNLIMITED TABLESPACE TO ' || username || ';'
FROM dba_users${DBLINK_SUFFIX}
$_usr_where_clause;
EXIT;
SQL_EOF
        fi
        
        cat <<EOF >> "$ENV_SQL"

SPOOL OFF
EXIT;
EOF
        cat <<EOF > "$ENV_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
        generate_run_prompt "$ENV_SH" "Target 사전 계정 및 테이블스페이스 생성 DDL 적용"
        cat <<EOF >> "$ENV_SH"
echo ">> Target DB 사전 계정 및 테이블스페이스 생성 DDL을 적용합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$ENV_SQL
CONNECT_EOF
EOF
        chmod 700 "$ENV_SH"
        if [ -n "$GENERATED_TARGET_SCRIPTS" ]; then
            GENERATED_TARGET_SCRIPTS="$ENV_SH $GENERATED_TARGET_SCRIPTS"
        elif [ -n "$GENERATED_META_SCRIPTS" ]; then
            GENERATED_META_SCRIPTS="$ENV_SH $GENERATED_META_SCRIPTS"
        fi
    fi
}

# 의존성 분리 캡처: Public Synonym 및 타 계정 부여 권한(Grants) 후행 DDL 생성 함수
generate_grants_and_synonyms_scripts() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _dep_in_clause
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "  [Dependency Capture: Public Synonyms & Cross-Schema Grants DDL]"
    else echo "  [의존성 분리 캡처: Public Synonym 및 타 계정 부여 객체권한(Grants) DDL 생성 모듈]"; fi

    if [ "$LANG_PREF" = "EN" ]; then printf "  Generate Post-Migration Grants & Synonyms DDL (99_post_grants_synonyms_${UNIQUE_ID}.sql)? (Y/n) [Default: Y]: "
    else printf "  후행 적용용 권한(Grants) 및 Public Synonym DDL 생성 (99_post_grants_synonyms_${UNIQUE_ID}.sql)? (Y/n) [기본값: Y]: "; fi
    _read gen_dep_opt
    if [ -z "$gen_dep_opt" ] || [ "$gen_dep_opt" = "y" ] || [ "$gen_dep_opt" = "Y" ]; then
        DEP_SQL="99_post_grants_synonyms_${UNIQUE_ID}.sql"
        DEP_SH="99_post_grants_synonyms_${UNIQUE_ID}.sh"
        echo "  * 생성 중: $DEP_SQL 및 $DEP_SH"

        cat <<EOF > "$DEP_SQL"
-- ==============================================================================
--  Post-Migration Dependencies: Public Synonyms & Cross-Schema Object Grants
--  Generated for Job: ${UNIQUE_ID}
-- ==============================================================================
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500 TRIMSPOOL ON SERVEROUTPUT ON
SPOOL 99_post_grants_synonyms_${UNIQUE_ID}.log

$PDB_SWITCH_SQL

PROMPT ========================================================================
PROMPT 1. Creating/Recreating Public Synonyms
PROMPT ========================================================================
EOF

        if [ "$MOCK_MODE" = "true" ]; then
            cat <<EOF >> "$DEP_SQL"
CREATE OR REPLACE PUBLIC SYNONYM EMP FOR SCOTT.EMP;
CREATE OR REPLACE PUBLIC SYNONYM DEPT FOR SCOTT.DEPT;

PROMPT ========================================================================
PROMPT 2. Granting Object Privileges to Other Users / Roles
PROMPT ========================================================================
GRANT SELECT, INSERT, UPDATE, DELETE ON SCOTT.EMP TO KMSUNG;
GRANT SELECT ON SCOTT.DEPT TO KMSUNG;

PROMPT ========================================================================
PROMPT 3. Granting Role Privileges to Target Users
PROMPT ========================================================================
GRANT CONNECT, RESOURCE TO SCOTT;
GRANT CONNECT, RESOURCE TO KMSUNG;
EOF
        else
            _dep_raw_list=""
            if [ -n "$FINAL_LIST" ]; then _dep_raw_list="$FINAL_LIST"
            elif [ -n "$SCHEMAS_LIST" ]; then _dep_raw_list="$SCHEMAS_LIST"
            elif [ -n "$SELECTED_LIST" ]; then _dep_raw_list="$SELECTED_LIST"
            elif [ -n "$TABLES_LIST" ]; then _dep_raw_list="$TABLES_LIST"
            fi

            _dep_in_clause=""
            IFS_BACKUP=$IFS; IFS=","
            for _itm in $_dep_raw_list; do
                _itm_c=$(echo "$_itm" | awk '{$1=$1;print}')
                if [ -n "$_itm_c" ]; then
                    [ -n "$_dep_in_clause" ] && _dep_in_clause="${_dep_in_clause},"
                    _dep_in_clause="${_dep_in_clause}'${_itm_c}'"
                fi
            done
            IFS=$IFS_BACKUP

            _syn_where="WHERE owner = 'PUBLIC'"
            _tab_priv_where="WHERE grantee NOT IN ('SYS','SYSTEM','XDB','WMSYS','MDSYS','ORDDATA','CTXSYS','AUDSYS','DBSNMP')"
            _role_priv_where="WHERE grantee NOT IN ('SYS','SYSTEM')"

            if [ -n "$_dep_in_clause" ] && [ "$MIG_TYPE" != "FULL" ]; then
                if [ "$MIG_TYPE" = "SCHEMA" ]; then
                    _syn_where="WHERE owner = 'PUBLIC' AND table_owner IN ($_dep_in_clause)"
                    _tab_priv_where="WHERE owner IN ($_dep_in_clause) AND grantee NOT IN ('SYS','SYSTEM','XDB','WMSYS','MDSYS','ORDDATA','CTXSYS','AUDSYS','DBSNMP')"
                    _role_priv_where="WHERE grantee IN ($_dep_in_clause) AND grantee NOT IN ('SYS','SYSTEM')"
                elif [ "$MIG_TYPE" = "TABLE" ]; then
                    _syn_where="WHERE owner = 'PUBLIC' AND table_owner || '.' || table_name IN ($_dep_in_clause)"
                    _tab_priv_where="WHERE owner || '.' || table_name IN ($_dep_in_clause) AND grantee NOT IN ('SYS','SYSTEM','XDB','WMSYS','MDSYS','ORDDATA','CTXSYS','AUDSYS','DBSNMP')"
                    _role_priv_where="WHERE grantee IN (SELECT owner FROM dba_tables${DBLINK_SUFFIX} WHERE owner || '.' || table_name IN ($_dep_in_clause)) AND grantee NOT IN ('SYS','SYSTEM')"
                fi
            fi

            sqlplus -S /nolog <<SQL_EOF >> "$DEP_SQL" 2>/dev/null
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500 TRIMSPOOL ON
$PDB_SWITCH_SQL

SELECT 'CREATE OR REPLACE PUBLIC SYNONYM "' || synonym_name || '" FOR "' || table_owner || '"."' || table_name || '";'
FROM dba_synonyms${DBLINK_SUFFIX}
$_syn_where
ORDER BY table_owner, synonym_name;

PROMPT ========================================================================
PROMPT 2. Granting Object Privileges to Other Users / Roles
PROMPT ========================================================================
SELECT 'GRANT ' || privilege || ' ON "' || owner || '"."' || table_name || '" TO "' || grantee || '"' ||
       CASE WHEN grantable = 'YES' THEN ' WITH GRANT OPTION;' ELSE ';' END
FROM dba_tab_privs${DBLINK_SUFFIX}
$_tab_priv_where
ORDER BY owner, table_name, grantee;

PROMPT ========================================================================
PROMPT 3. Granting Role Privileges to Target Users
PROMPT ========================================================================
SELECT 'GRANT "' || granted_role || '" TO "' || grantee || '"' ||
       CASE WHEN admin_option = 'YES' THEN ' WITH ADMIN OPTION;' ELSE ';' END
FROM dba_role_privs${DBLINK_SUFFIX}
$_role_priv_where
ORDER BY grantee, granted_role;
EXIT;
SQL_EOF
        fi

        cat <<EOF >> "$DEP_SQL"

SPOOL OFF
EXIT;
EOF

        cat <<EOF > "$DEP_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
        generate_run_prompt "$DEP_SH" "후행 권한(Grants) 및 Public Synonym DDL 적용"
        cat <<EOF >> "$DEP_SH"
echo ">> Target DB에 후행 권한(Grants) 및 Public Synonym DDL을 적용합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$DEP_SQL
CONNECT_EOF
EOF
        chmod 700 "$DEP_SH"
        if [ -n "$GENERATED_TARGET_SCRIPTS" ]; then
            GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $DEP_SH"
        elif [ -n "$GENERATED_EXEC_SCRIPTS" ]; then
            GENERATED_EXEC_SCRIPTS="$GENERATED_EXEC_SCRIPTS $DEP_SH"
        fi
    fi
}

# ==============================================================================
# [NEW v07] 덤프 파일 MD5 체크섬 매니페스트 생성 / 검증 스크립트
#   - Source: 덤프 생성 직후 체크섬 매니페스트(.md5) 작성
#   - Target: 전송된 덤프가 손상되지 않았는지 매니페스트로 대조 검증
#   - OS 별 md5 도구 차이(Linux md5sum / Solaris digest / AIX csum / openssl) 자동 처리
# ==============================================================================
generate_checksum_scripts() {
    [ "$CHECKSUM_ENABLED" != "true" ] && return 0

    CHK_CREATE_SH="checksum_create_${UNIQUE_ID}.sh"
    CHK_VERIFY_SH="checksum_verify_${UNIQUE_ID}.sh"
    CHK_MANIFEST="${UNIQUE_ID}_dumpfiles.md5"
    echo "  * 생성 중: $CHK_CREATE_SH / $CHK_VERIFY_SH (덤프 무결성 체크섬)"

    cat <<EOF > "$CHK_CREATE_SH"
#!/bin/bash
# ==============================================================================
#  Dump File MD5 Checksum Manifest Generator
#  Job ID    : ${UNIQUE_ID}
#  Manifest  : ${CHK_MANIFEST}
# ==============================================================================
SRC_DIR="\${1:-${DIR_PHYSICAL_PATH}}"
MANIFEST="\${SRC_DIR}/${CHK_MANIFEST}"

md5_of() {
    if command -v md5sum >/dev/null 2>&1; then
        md5sum "\$1" | awk '{print \$1}'
    elif command -v digest >/dev/null 2>&1; then
        digest -a md5 "\$1"
    elif command -v csum >/dev/null 2>&1; then
        csum -h MD5 "\$1" | awk '{print \$1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -md5 "\$1" | awk '{print \$NF}'
    else
        echo "NO_MD5_TOOL"
    fi
}

echo "======================================================================"
echo "  [Checksum] 덤프 파일 MD5 매니페스트를 생성합니다"
echo "  - 대상 경로 : \$SRC_DIR"
echo "  - 매니페스트: \$MANIFEST"
echo "======================================================================"

if [ ! -d "\$SRC_DIR" ]; then
    echo "  [ERROR] 덤프 디렉토리가 존재하지 않습니다: \$SRC_DIR"
    exit 1
fi
if [ ! -w "\$SRC_DIR" ]; then
    echo "  [ERROR] 덤프 디렉토리에 쓰기 권한이 없습니다: \$SRC_DIR"
    exit 1
fi

: > "\$MANIFEST"
_cnt=0
for f in "\$SRC_DIR"/${UNIQUE_ID}*.dmp; do
    [ -e "\$f" ] || continue
    _sum=\$(md5_of "\$f")
    if [ "\$_sum" = "NO_MD5_TOOL" ]; then
        echo "  [ERROR] 이 서버에서 MD5 도구(md5sum/digest/csum/openssl)를 찾을 수 없습니다."
        exit 1
    fi
    printf '%s  %s\n' "\$_sum" "\$(basename "\$f")" >> "\$MANIFEST"
    _cnt=\$((_cnt + 1))
    echo "  [OK] \$(basename "\$f")  ->  \$_sum"
done

if [ \$_cnt -eq 0 ]; then
    echo "  [WARN] 체크섬 대상 덤프 파일이 없습니다: \$SRC_DIR/${UNIQUE_ID}*.dmp"
    exit 1
fi
echo "======================================================================"
echo ">> 총 \${_cnt}개 덤프 파일의 체크섬을 기록했습니다: \$MANIFEST"
echo ">> Target 서버에서 checksum_verify_${UNIQUE_ID}.sh 로 검증하십시오."
EOF
    chmod 700 "$CHK_CREATE_SH"

    cat <<EOF > "$CHK_VERIFY_SH"
#!/bin/bash
# ==============================================================================
#  Dump File MD5 Integrity Verifier (Target Server)
#  Job ID    : ${UNIQUE_ID}
#  Manifest  : ${CHK_MANIFEST}
# ==============================================================================
TGT_DIR="\${1:-${DIR_PHYSICAL_PATH}}"
MANIFEST="\${TGT_DIR}/${CHK_MANIFEST}"

md5_of() {
    if command -v md5sum >/dev/null 2>&1; then
        md5sum "\$1" | awk '{print \$1}'
    elif command -v digest >/dev/null 2>&1; then
        digest -a md5 "\$1"
    elif command -v csum >/dev/null 2>&1; then
        csum -h MD5 "\$1" | awk '{print \$1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -md5 "\$1" | awk '{print \$NF}'
    else
        echo "NO_MD5_TOOL"
    fi
}

echo "======================================================================"
echo "  [Checksum Verify] 전송된 덤프 파일 무결성 검증"
echo "  - 검증 경로 : \$TGT_DIR"
echo "======================================================================"

if [ ! -f "\$MANIFEST" ]; then
    echo "  [ERROR] 매니페스트 파일이 없습니다: \$MANIFEST"
    echo "          Source 서버에서 생성한 ${CHK_MANIFEST} 를 먼저 전송하십시오."
    exit 1
fi

# [NEW v08.03] HTML 감사 보고서 연동용 결과 CSV
RESULT_CSV="./checksum_result_${UNIQUE_ID}.csv"
: > "\$RESULT_CSV"

_ok=0; _ng=0; _miss=0
while read -r _exp_sum _fname; do
    [ -z "\$_fname" ] && continue
    _target="\${TGT_DIR}/\${_fname}"
    if [ ! -f "\$_target" ]; then
        printf "  %-45s | %-10s\n" "\$_fname" "[누락]"
        printf '%s|%s|%s|%s\n' "\$_fname" "\$_exp_sum" "-" "MISSING" >> "\$RESULT_CSV"
        _miss=\$((_miss + 1)); continue
    fi
    _act_sum=\$(md5_of "\$_target")
    if [ "\$_act_sum" = "\$_exp_sum" ]; then
        printf "  %-45s | %-10s\n" "\$_fname" "[일치]"
        printf '%s|%s|%s|%s\n' "\$_fname" "\$_exp_sum" "\$_act_sum" "MATCH" >> "\$RESULT_CSV"
        _ok=\$((_ok + 1))
    else
        printf "  %-45s | %-10s (expected=\$_exp_sum actual=\$_act_sum)\n" "\$_fname" "[불일치]"
        printf '%s|%s|%s|%s\n' "\$_fname" "\$_exp_sum" "\$_act_sum" "MISMATCH" >> "\$RESULT_CSV"
        _ng=\$((_ng + 1))
    fi
done < "\$MANIFEST"

echo "======================================================================"
echo ">> 일치 \${_ok}건 / 불일치 \${_ng}건 / 누락 \${_miss}건"
if [ \$_ng -gt 0 ] || [ \$_miss -gt 0 ]; then
    echo ">> [FAIL] 무결성 검증 실패. impdp 를 진행하지 마시고 재전송하십시오."
    exit 1
fi
echo ">> [SUCCESS] 모든 덤프 파일의 무결성이 확인되었습니다."
EOF
    chmod 700 "$CHK_VERIFY_SH"

    GENERATED_CHECKSUM_SCRIPTS="$CHK_CREATE_SH $CHK_VERIFY_SH"
    return 0
}

generate_monitoring_and_stop_scripts() {
    MON_SH="monitor_job_${UNIQUE_ID}.sh"
    STOP_SH="stop_job_${UNIQUE_ID}.sh"
    echo "  * 생성 중: $MON_SH 및 $STOP_SH (모니터링 & 중지 헬퍼)"

    cat <<EOF > "$MON_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo "======================================================================"
echo "  [Data Pump Job Monitor] 실시간 진행 상태 조회 (UNIQUE_ID: ${UNIQUE_ID})"
echo "======================================================================"
sqlplus -S /nolog <<SQL_EOF
connect $DB_CONN
SET LINES 250 PAGES 100 TRIMSPOOL ON
$PDB_SWITCH_SQL
COL OWNER_NAME FORMAT A15
COL JOB_NAME FORMAT A30
COL OPERATION FORMAT A12
COL JOB_MODE FORMAT A12
COL STATE FORMAT A15

PROMPT [1. DBA_DATAPUMP_JOBS Status]
SELECT owner_name, job_name, operation, job_mode, state, degree, attached_sessions 
FROM dba_datapump_jobs 
WHERE job_name LIKE '%${UNIQUE_ID}%' OR job_name LIKE '%META%' OR job_name LIKE '%EXP%' OR job_name LIKE '%IMP%';

PROMPT
PROMPT [2. V\$SESSION_LONGOPS Progress]
COL OPNAME FORMAT A30
COL TARGET_DESC FORMAT A30
COL PROGRESS FORMAT A12
SELECT opname, target_desc, sofar, totalwork, 
       ROUND(sofar/NULLIF(totalwork,0)*100, 2) || '%' AS PROGRESS, 
       time_remaining AS REMAIN_SEC
FROM v\$session_longops 
WHERE (opname LIKE '%EXPORT%' OR opname LIKE '%IMPORT%' OR opname LIKE '%DATAPUMP%') 
  AND totalwork > 0;
EXIT;
SQL_EOF
EOF
    chmod 700 "$MON_SH"

    cat <<EOF > "$STOP_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo "======================================================================"
echo "  [Data Pump Job Safe Stop] 진행 중인 Data Pump 작업 안전 중지"
echo "======================================================================"
printf "중지할 Data Pump JOB_NAME을 입력하세요 (예: ${UNIQUE_ID}_EXP_GROUP): "
read job_name_input
[ -z "\$job_name_input" ] && job_name_input="${UNIQUE_ID}_EXP_GROUP"

_dp_conn_target="$DB_CONN"
[ -n "$PDB_CONNECT_STR" ] && _dp_conn_target="$PDB_CONNECT_STR"

echo ">> Data Pump Job '\$job_name_input' 에 접속합니다..."
echo ">> 프롬프트(Export> 또는 Import>)가 나오면 아래 순서대로 입력하세요:"
echo "   1) STOP_JOB=IMMEDIATE"
echo "   2) Are you sure... 되물음에 'YES' 입력"
# [SEC v08.01] attach 시에도 접속 문자열이 ps 에 노출되지 않도록 임시 PARFILE 사용
_dp_par="./.dp_attach_\$\$.par"
_old_umask=\$(umask); umask 077
printf 'USERID="%s"\\nATTACH=%s\\n' "\$_dp_conn_target" "\$job_name_input" > "\$_dp_par"
umask "\$_old_umask"
trap 'rm -f "\$_dp_par"' EXIT INT TERM
expdp PARFILE="\$_dp_par" 2>/dev/null || impdp PARFILE="\$_dp_par"
rm -f "\$_dp_par"
EOF
    chmod 700 "$STOP_SH"

    GENERATED_UTIL_SCRIPTS="$MON_SH $STOP_SH"
}

# 마스터 실행 파이프라인 러너 (00_RUN_ALL_MASTER.sh) 생성 함수
generate_master_runner_script() {
    _runner_role="$1"
    _script_list="$2"

    MASTER_RUNNER_SH="00_RUN_ALL_MASTER_${UNIQUE_ID}.sh"
    echo "  * 생성 중: $MASTER_RUNNER_SH (통합 마스터 파이프라인 러너 - 체크포인트/재개 지원)"

    # 공백 정리된 스텝 목록
    _clean_steps=$(echo "$_script_list" | tr -s ' ' | sed 's/^ //;s/ $//')

    cat <<EOF > "$MASTER_RUNNER_SH"
#!/bin/bash
# ==============================================================================
#  Oracle Datapump Master Pipeline Orchestrator (${_runner_role})
#  Job ID  : ${UNIQUE_ID}
#  Created : $(date '+%Y-%m-%d %H:%M:%S') by Migration Helper v${SCRIPT_VERSION}
#
#  [NEW v07] 체크포인트 기반 재개(RESUME) 및 스텝 재시도(RETRY) 지원
#    ./$(basename "$MASTER_RUNNER_SH") --list           # 스텝 목록/진행 상태 확인
#    ./$(basename "$MASTER_RUNNER_SH") -y               # 무인 전체 실행
#    ./$(basename "$MASTER_RUNNER_SH") -y --resume      # 실패 지점부터 이어서 재개
#    ./$(basename "$MASTER_RUNNER_SH") -y --retry 2     # 스텝별 최대 2회 재시도
#    ./$(basename "$MASTER_RUNNER_SH") --from 3         # 3번 스텝부터 실행
#    ./$(basename "$MASTER_RUNNER_SH") --reset          # 체크포인트 초기화
# ==============================================================================
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

MASTER_LOG="master_run_${UNIQUE_ID}.log"
STATE_FILE="master_state_${UNIQUE_ID}.state"
STEP_LIST="${_clean_steps}"

UNATTENDED="false"
RESUME="false"
MAX_RETRY=1
FROM_STEP=1
LIST_ONLY="false"

while [ \$# -gt 0 ]; do
    case "\$1" in
        -y|--yes|--unattended) UNATTENDED="true" ;;
        --resume)              RESUME="true" ;;
        --retry)               shift; MAX_RETRY="\$1" ;;
        --retry=*)             MAX_RETRY=\$(echo "\$1" | cut -d'=' -f2) ;;
        --from)                shift; FROM_STEP="\$1" ;;
        --from=*)              FROM_STEP=\$(echo "\$1" | cut -d'=' -f2) ;;
        --list)                LIST_ONLY="true" ;;
        --reset)               rm -f "\$STATE_FILE"; echo ">> 체크포인트를 초기화했습니다: \$STATE_FILE"; exit 0 ;;
        -h|--help)
            grep '^#' "\$0" | sed 's/^# \\{0,1\\}//' | head -n 20
            exit 0 ;;
        *) echo "[WARN] 알 수 없는 옵션 무시: \$1" ;;
    esac
    shift
done

echo "\$MAX_RETRY" | grep -qE '^[0-9]+\$' || MAX_RETRY=1
[ "\$MAX_RETRY" -lt 1 ] && MAX_RETRY=1
echo "\$FROM_STEP" | grep -qE '^[0-9]+\$' || FROM_STEP=1
[ "\$FROM_STEP" -lt 1 ] && FROM_STEP=1

touch "\$STATE_FILE" 2>/dev/null

log_msg() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" | tee -a "\$MASTER_LOG"
}

is_done() {
    grep -qx "DONE:\$1" "\$STATE_FILE" 2>/dev/null
}

mark_done() {
    grep -qx "DONE:\$1" "\$STATE_FILE" 2>/dev/null || echo "DONE:\$1" >> "\$STATE_FILE"
}

total_steps=0
for _s in \$STEP_LIST; do total_steps=\$((total_steps + 1)); done

# --list : 실행 없이 스텝 목록과 체크포인트 상태만 출력
if [ "\$LIST_ONLY" = "true" ]; then
    echo "====================================================================="
    echo "  Pipeline Steps (${_runner_role}) - Job ${UNIQUE_ID}"
    echo "====================================================================="
    _i=0
    for _s in \$STEP_LIST; do
        _i=\$((_i + 1))
        if is_done "\$_s"; then _st="[DONE]"; else _st="[    ]"; fi
        printf "  %2d) %s %s\\n" "\$_i" "\$_st" "\$_s"
    done
    echo "====================================================================="
    echo "  체크포인트 파일: \$STATE_FILE"
    exit 0
fi

START_EPOCH=\$(date +%s 2>/dev/null || echo 0)

log_msg "====================================================================="
log_msg "  [START] Oracle Datapump Master Pipeline Execution (${_runner_role})"
log_msg "  - Unique Migration ID : ${UNIQUE_ID}"
log_msg "  - Total Steps         : \$total_steps"
log_msg "  - Mode                : unattended=\$UNATTENDED resume=\$RESUME retry=\$MAX_RETRY from=\$FROM_STEP"
log_msg "  - Log / State         : \$MASTER_LOG / \$STATE_FILE"
log_msg "====================================================================="

step_num=0
failed_steps=0
skipped_steps=0

for s_file in \$STEP_LIST; do
    step_num=\$((step_num + 1))

    if [ "\$step_num" -lt "\$FROM_STEP" ]; then
        log_msg ">> [SKIP] Step \$step_num/\$total_steps (--from \$FROM_STEP): \$s_file"
        skipped_steps=\$((skipped_steps + 1))
        continue
    fi

    # [NEW v07] 재개 모드: 이미 성공한 스텝은 건너뛴다
    if [ "\$RESUME" = "true" ] && is_done "\$s_file"; then
        log_msg ">> [RESUME-SKIP] Step \$step_num/\$total_steps 이미 완료됨: \$s_file"
        skipped_steps=\$((skipped_steps + 1))
        continue
    fi

    if [ ! -f "\$s_file" ]; then
        log_msg ">> [WARN] 스텝 파일이 없어 건너뜁니다: \$s_file"
        skipped_steps=\$((skipped_steps + 1))
        continue
    fi

    log_msg "---------------------------------------------------------------------"
    log_msg ">> [Step \$step_num/\$total_steps] Running: \$s_file"
    log_msg "---------------------------------------------------------------------"

    if [ "\$UNATTENDED" != "true" ] && [ -t 0 ]; then
        printf "실행하시겠습니까? / Proceed with \$s_file? (Y/n/q:quit): "
        read _step_ans
        case "\$_step_ans" in
            q|Q) log_msg ">> User requested abort. Pipeline stopped."; exit 1 ;;
            n|N) log_msg ">> Skipped step: \$s_file"; skipped_steps=\$((skipped_steps + 1)); continue ;;
        esac
    fi

    _attempt=1
    step_rc=1
    while [ \$_attempt -le \$MAX_RETRY ]; do
        [ \$_attempt -gt 1 ] && log_msg ">> [RETRY \$_attempt/\$MAX_RETRY] \$s_file"
        step_start=\$(date +%s 2>/dev/null || echo 0)

        # [FIX v07/B5] v06 은 'sh step | tee' 형태라 \$? 가 tee 의 종료코드였고,
        #              실제 스텝이 실패해도 항상 [PASS] 로 기록되었다.
        #              rc 파일을 사용해 실제 스텝의 종료코드를 정확히 취득한다.
        _rc_file="./.step_rc_\$\$"
        # [FIX v08.02] 셔뱅(#!/bin/bash)과 일치하도록 bash 로 실행
        { bash "\$s_file" 2>&1; echo \$? > "\$_rc_file"; } | tee -a "\$MASTER_LOG"
        step_rc=\$(cat "\$_rc_file" 2>/dev/null)
        rm -f "\$_rc_file"
        echo "\$step_rc" | grep -qE '^[0-9]+\$' || step_rc=1

        step_end=\$(date +%s 2>/dev/null || echo 0)
        step_duration=\$((step_end - step_start))
        [ \$step_rc -eq 0 ] && break
        _attempt=\$((_attempt + 1))
        [ \$_attempt -le \$MAX_RETRY ] && sleep 5
    done

    if [ \$step_rc -eq 0 ]; then
        log_msg ">> [PASS] \$s_file completed successfully (Elapsed: \${step_duration}s)"
        mark_done "\$s_file"
    else
        failed_steps=\$((failed_steps + 1))
        log_msg ">> [FAIL] \$s_file exited with return code: \$step_rc"
        if [ "\$UNATTENDED" = "true" ]; then
            log_msg ">> 무인 모드: 오류로 파이프라인을 중단합니다."
            log_msg ">> 조치 후 재개: bash \$(basename "\$0") -y --resume"
            exit \$step_rc
        fi
        if [ -t 0 ]; then
            printf "오류가 발생했습니다. 파이프라인을 계속 진행하시겠습니까? / Continue despite error? (y/N): "
            read _err_ans
            if [ "\$_err_ans" != "y" ] && [ "\$_err_ans" != "Y" ]; then
                log_msg ">> Pipeline halted due to error in \$s_file"
                log_msg ">> 조치 후 재개: bash \$(basename "\$0") --resume"
                exit \$step_rc
            fi
        else
            exit \$step_rc
        fi
    fi
done

END_EPOCH=\$(date +%s 2>/dev/null || echo 0)
TOTAL_ELAPSED=\$((END_EPOCH - START_EPOCH))
hours=\$((TOTAL_ELAPSED / 3600))
mins=\$(( (TOTAL_ELAPSED % 3600) / 60 ))
secs=\$((TOTAL_ELAPSED % 60))

log_msg "====================================================================="
if [ \$failed_steps -eq 0 ]; then
    log_msg "  [COMPLETED] Master Pipeline Execution Finished Successfully!"
else
    log_msg "  [COMPLETED WITH ERRORS] 실패 스텝 \$failed_steps 건 - 로그를 확인하십시오."
fi
log_msg "  - Total Duration : \${hours}h \${mins}m \${secs}s (\${TOTAL_ELAPSED} seconds)"
log_msg "  - Skipped Steps  : \$skipped_steps"
log_msg "  - Master Log     : \$MASTER_LOG"
log_msg "  - Checkpoint     : \$STATE_FILE"
log_msg "====================================================================="
[ \$failed_steps -eq 0 ] || exit 1
EOF

    chmod 700 "$MASTER_RUNNER_SH"
}

# ==============================================================================
# [NEW v07] 사전 요구사항 자동 검증 (Pre-flight Requirement Verification)
# ==============================================================================

# Directory Object 물리 경로에 실제로 쓰기가 가능한지 touch 로 실증한다.
check_dir_writable() {
    _cw_path="$1"
    if [ "$MOCK_MODE" = "true" ]; then return 0; fi
    [ -z "$_cw_path" ] && return 1
    [ ! -d "$_cw_path" ] && return 1
    _cw_probe="${_cw_path}/.mig_write_probe_$$"
    if ( : > "$_cw_probe" ) 2>/dev/null; then
        rm -f "$_cw_probe" 2>/dev/null
        return 0
    fi
    return 1
}

# 이관 대상의 실제 세그먼트 총합(byte)을 조회한다. 실패 시 0 을 반환.
estimate_target_size_bytes() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _ei _es_in _es_list
    if [ "$MOCK_MODE" = "true" ]; then echo "53687091200"; return 0; fi

    _es_list=""
    case "$MIG_TYPE" in
        SCHEMA)     _es_list="$SCHEMAS_LIST" ;;
        TABLE)      _es_list="$TABLES_LIST" ;;
        TABLESPACE) _es_list="$TBS_LIST" ;;
    esac
    [ -z "$_es_list" ] && _es_list="$FINAL_LIST"

    _es_in=""
    IFS_BACKUP=$IFS; IFS=","
    for _ei in $_es_list; do
        _ei=$(echo "$_ei" | awk '{$1=$1;print}')
        if [ -n "$_ei" ]; then
            [ -n "$_es_in" ] && _es_in="${_es_in},"
            _es_in="${_es_in}'${_ei}'"
        fi
    done
    IFS=$IFS_BACKUP

    _es_where="WHERE owner NOT IN ('SYS','SYSTEM','XDB','WMSYS','AUDSYS','OUTLN','DBSNMP')"
    if [ -n "$_es_in" ]; then
        case "$MIG_TYPE" in
            SCHEMA)     _es_where="WHERE owner IN ($_es_in)" ;;
            TABLE)      _es_where="WHERE owner || '.' || segment_name IN ($_es_in)" ;;
            TABLESPACE) _es_where="WHERE tablespace_name IN ($_es_in)" ;;
        esac
    fi

    _es_out=$(sqlplus -S /nolog <<SQL_EOF 2>/dev/null
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 100 TRIMSPOOL ON
$PDB_SWITCH_SQL
SELECT NVL(SUM(bytes),0) FROM dba_segments${DBLINK_SUFFIX} $_es_where;
EXIT;
SQL_EOF
)
    to_num "$_es_out"
    return 0
}

# 바이트를 사람이 읽기 좋은 단위로 변환
human_bytes() {
    awk -v b="$1" 'BEGIN {
        if (b >= 1099511627776) printf "%.2f TB", b/1099511627776;
        else if (b >= 1073741824) printf "%.2f GB", b/1073741824;
        else printf "%.2f MB", b/1048576;
    }'
}

# 지정 경로의 여유 공간(byte)
free_space_bytes() {
    if [ "$MOCK_MODE" = "true" ]; then echo "536870912000"; return 0; fi
    _fs_kb=$(df -P "$1" 2>/dev/null | tail -n 1 | awk '{print $4}')
    _fs_kb=$(to_num "$_fs_kb")
    echo $((_fs_kb * 1024))
    return 0
}

# Source DB 버전 > Target DB 버전 이면 expdp 에 VERSION= 을 넣어야 임포트가 가능하다.
check_version_compatibility() {
    VERSION_PARAM=""
    [ -z "$TARGET_DB_VERSION" ] && return 0
    _src_major=$(echo "$DB_VERSION" | cut -d'.' -f1 | tr -dc '0-9')
    _tgt_major=$(echo "$TARGET_DB_VERSION" | cut -d'.' -f1 | tr -dc '0-9')
    [ -z "$_src_major" ] && return 0
    [ -z "$_tgt_major" ] && return 0
    if [ "$_src_major" -gt "$_tgt_major" ]; then
        VERSION_PARAM="VERSION=$TARGET_DB_VERSION"
        if [ "$LANG_PREF" = "EN" ]; then
            echo "  [ACTION] Source(${_src_major}) is newer than Target(${_tgt_major}) -> adding ${VERSION_PARAM}"
        else
            echo "  [자동조치] Source(${_src_major}c) 가 Target(${_tgt_major}c) 보다 상위 버전 -> ${VERSION_PARAM} 자동 추가"
        fi
        return 1
    fi
    return 0
}

# 문자셋 확장(싱글바이트/EUC -> AL32UTF8) 위험 판정
check_charset_risk() {
    case "$DB_CHARSET" in
        KO16MSWIN949|KO16KSC5601|WE8MSWIN1252|WE8ISO8859P1|US7ASCII|ZHS16GBK|JA16SJIS)
            if [ "$LANG_PREF" = "EN" ]; then
                echo "  [WARN] Source charset ${DB_CHARSET} -> AL32UTF8 can expand up to 3x (ORA-12899 risk)."
                echo "         Run menu 5 (DIAGNOSTICS) to list columns at risk before migrating."
            else
                echo "  [경고] Source 문자셋 ${DB_CHARSET} -> AL32UTF8 변환 시 최대 3배 확장 (ORA-12899 위험)."
                echo "         이관 전 메뉴 5(DIAGNOSTICS)로 위험 컬럼 목록을 먼저 확인하십시오."
            fi
            return 1
            ;;
    esac
    return 0
}

# [NEW v08.03] 사전 검증 결과를 HTML 리포트용으로 기록
#   UNIQUE_ID 가 아직 정해지기 전에 실행되므로 임시 파일에 모았다가
#   flush_preflight_csv 로 preflight_result_<UID>.csv 에 확정 기록한다.
pf_record() {
    printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "$(tmpf preflight.csv)"
}

flush_preflight_csv() {
    _fp_src="$(tmpf preflight.csv)"
    [ -s "$_fp_src" ] || return 0
    [ -z "$UNIQUE_ID" ] && return 0
    cp "$_fp_src" "./preflight_result_${UNIQUE_ID}.csv" 2>/dev/null
    return 0
}

# ------------------------------------------------------------------------------
# [FIX v08.04] 사용자가 직접 입력한 목록의 구분자 정규화
#   화면 안내는 "쉼표 구분"이지만 실제로는 공백으로 끊어 적는 경우가 잦다.
#   기존 처리(tr -d ' ')는 "HR SCOTT" 을 "HRSCOTT" 이라는 없는 계정명으로 만들고,
#   정규화가 아예 없는 경로는 IN ('HR SCOTT') 같은 잘못된 SQL 을 만들어 냈다.
#   여기서 공백/탭을 쉼표로 승격시켜 소비 지점(IFS=",")이 항상 옳게 쪼개도록 한다.
# ------------------------------------------------------------------------------
normalize_list() {
    echo "$1" | tr '\t' ' ' \
        | sed -e 's/  */ /g' -e 's/ *, */,/g' -e 's/ /,/g' \
              -e 's/,,*/,/g' -e 's/^,//' -e 's/,$//'
}

# ------------------------------------------------------------------------------
# [NEW v08.05] NETWORK_LINK 모드 전용 사전 검증
#   네트워크 임포트는 덤프 방식과 실패 양상이 다르다. 특히 LONG / LONG RAW 는
#   DB link 너머로 이동 자체가 불가능한데, 그 사실이 몇 시간 돌린 뒤 해당 테이블
#   차례에 가서야 드러난다. 시작 전에 드러내는 것이 이 함수의 목적이다.
#     run_network_link_checks <대상목록(쉼표구분)>
# ------------------------------------------------------------------------------
run_network_link_checks() {
    # [v09.02] local 제거 (ksh 비호환): _nl_list _nl_owners _nl_out _nl_rc
    _nl_list="$1"
    NETWORK_PRECHECK_RESULT="PASS"

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "  [PRE-FLIGHT] NETWORK_LINK Mode Verification"
    else echo "  [사전 검증] NETWORK_LINK 모드 전용 점검"; fi
    echo "----------------------------------------------------------------------"

    if [ "$MOCK_MODE" = "true" ]; then
        echo "   [ OK ] DB Link 도달성 : ${DBLINK_NAME} (MOCK)"
        pf_record "NETWORK" "DB Link 도달성" "OK" "${DBLINK_NAME} (MOCK)"
        echo "   [ OK ] LONG/LONG RAW  : 검출되지 않음 (MOCK)"
        pf_record "NETWORK" "LONG/LONG RAW 컬럼" "OK" "검출되지 않음 (MOCK)"
        echo "   [INFO] 병렬 처리      : 네트워크 모드는 PQ 슬레이브를 사용하지 않습니다"
        pf_record "NETWORK" "병렬 처리 특성" "INFO" "테이블당 워커 1개 - PQ 미사용"
        echo "----------------------------------------------------------------------"
        return 0
    fi

    # 1) DB Link 도달성
    _nl_out=$(sqlplus -S /nolog <<EOF | tr -d ' ' | sed '/^$/d' | head -n 1
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0
WHENEVER SQLERROR EXIT 1
$PDB_SWITCH_SQL
SELECT 'LINKOK' FROM dual@${DBLINK_NAME};
EXIT;
EOF
)
    if [ "$_nl_out" = "LINKOK" ]; then
        printf "   [ OK ] DB Link 도달성 : %s\n" "$DBLINK_NAME"
        pf_record "NETWORK" "DB Link 도달성" "OK" "$DBLINK_NAME"
    else
        printf "   [FAIL] DB Link 도달성 : %s 로 원격 접속에 실패했습니다\n" "$DBLINK_NAME"
        echo "          (ORA-12154 / ORA-01017 / ORA-02019 등 - tnsnames 와 계정을 확인하십시오)"
        pf_record "NETWORK" "DB Link 도달성" "FAIL" "${DBLINK_NAME} 원격 접속 실패"
        NETWORK_PRECHECK_RESULT="FAIL"
        echo "----------------------------------------------------------------------"
        return 1
    fi

    # 2) 원격(Source) 버전 / 문자셋
    _nl_out=$(sqlplus -S /nolog <<EOF | sed '/^$/d' | head -n 1
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 200
$PDB_SWITCH_SQL
SELECT (SELECT version FROM v\$instance@${DBLINK_NAME}) || ' / ' ||
       (SELECT value FROM nls_database_parameters@${DBLINK_NAME}
         WHERE parameter='NLS_CHARACTERSET') FROM dual;
EXIT;
EOF
)
    _nl_out=$(echo "$_nl_out" | awk '{$1=$1;print}')
    if [ -n "$_nl_out" ]; then
        printf "   [INFO] 원격 소스      : %s\n" "$_nl_out"
        pf_record "NETWORK" "원격 소스 버전/문자셋" "INFO" "$_nl_out"
    fi

    # 3) LONG / LONG RAW — 네트워크 모드로 이동 불가
    if [ -n "$_nl_list" ] && [ "$MIG_TYPE" != "FULL" ]; then
        _nl_owners=$(echo "$_nl_list" | sed "s/[^,]*/'&'/g" | tr 'a-z' 'A-Z')
        _nl_out=$(sqlplus -S /nolog <<EOF | tr -d ' ' | sed '/^$/d' | head -n 1
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0
$PDB_SWITCH_SQL
SELECT COUNT(*) FROM dba_tab_columns@${DBLINK_NAME}
 WHERE data_type IN ('LONG','LONG RAW') AND owner IN (${_nl_owners});
EXIT;
EOF
)
    else
        _nl_out=$(sqlplus -S /nolog <<EOF | tr -d ' ' | sed '/^$/d' | head -n 1
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0
$PDB_SWITCH_SQL
SELECT COUNT(*) FROM dba_tab_columns@${DBLINK_NAME}
 WHERE data_type IN ('LONG','LONG RAW') AND owner NOT IN (${DEEP_EXCL_OWNERS});
EXIT;
EOF
)
    fi
    _nl_out=$(to_num "$_nl_out")

    if [ "$_nl_out" -gt 0 ]; then
        printf "   [FAIL] LONG/LONG RAW  : %s 개 컬럼 검출 - 네트워크 모드로 이동할 수 없습니다\n" "$_nl_out"
        echo "          해당 테이블은 Dump File 방식(메뉴 1 -> 2)으로 따로 옮기십시오."
        pf_record "NETWORK" "LONG/LONG RAW 컬럼" "FAIL" "${_nl_out} 개 검출 - 네트워크 모드 이동 불가"
        NETWORK_PRECHECK_RESULT="FAIL"
    else
        echo "   [ OK ] LONG/LONG RAW  : 검출되지 않음"
        pf_record "NETWORK" "LONG/LONG RAW 컬럼" "OK" "검출되지 않음"
    fi

    # 4) 병렬 처리 특성 안내
    echo "   [INFO] 병렬 처리      : 네트워크 모드는 PQ 슬레이브를 사용하지 않습니다"
    pf_record "NETWORK" "병렬 처리 특성" "INFO" "테이블당 워커 1개 - PQ 미사용"

    echo "----------------------------------------------------------------------"
    if [ "$NETWORK_PRECHECK_RESULT" = "FAIL" ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> NETWORK PRE-CHECK: FAIL"
        else echo "  >> 네트워크 모드 사전 점검: FAIL"; fi
        echo "----------------------------------------------------------------------"
        if [ "$UNATTENDED" = "true" ]; then
            echo "  [무인 모드] 치명 항목이 있어 중단합니다."
            return 1
        fi
        printf "  그래도 계속 진행하시겠습니까? (y/N): "
        _read nl_force
        [ "$nl_force" != "y" ] && [ "$nl_force" != "Y" ] && return 1
    else
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> NETWORK PRE-CHECK: PASS"
        else echo "  >> 네트워크 모드 사전 점검: PASS"; fi
        echo "----------------------------------------------------------------------"
    fi
    return 0
}

# ------------------------------------------------------------------------------
# [FIX v09.01] Data Pump 용 PDB 접속 문자열 조립
#
#   Data Pump 는 ALTER SESSION SET CONTAINER 를 따라가지 않으므로 PDB 서비스로
#   직접 붙어야 한다. 그런데 기존에는 사용자가 입력한 "서비스명"을 그대로
#   USERID 에 넣고 있었다. 기본값(//localhost:1521/PDB)을 그대로 수락하면
#       USERID="//localhost:1521/ORCLPDB1"
#   이 되어 계정도 패스워드도 없이 expdp 가 기동되고 ORA-01017 로 즉시 죽는다.
#
#   MOCK 경로는 자격증명이 박힌 값을 하드코딩하고 있어 이 결함이 가려져 있었다.
#   메인 접속에서 자격증명 부분만 떼어 서비스명에 다시 붙인다.
#       system/pw@//h:1521/CDB  +  //h:1521/ORCLPDB1
#         -> system/pw@//h:1521/ORCLPDB1
# ------------------------------------------------------------------------------
join_pdb_connect() {
    _jp_base="$1"
    _jp_svc="$2"

    if [ -z "$_jp_svc" ]; then echo "$_jp_base"; return 0; fi

    # 사용자가 이미 user/pass@svc 를 통째로 입력했으면 그대로 쓴다.
    if echo "$_jp_svc" | grep -qE '^[^/@ 	]+/[^@ 	]+@'; then
        echo "$_jp_svc"; return 0
    fi

    # OS 인증(/ as sysdba)은 원격 서비스로 재지정할 수 없다.
    if echo "$_jp_base" | grep -qE '^[ 	]*/[ 	]*as[ 	][ 	]*[Ss][Yy][Ss]'; then
        echo ""
        return 1
    fi

    # 역할 구문(as sysdba / as sysoper)은 반드시 보존한다.
    #   sys/pw@CDB as sysdba 에서 역할을 떨어뜨리면 SYS 접속이
    #   ORA-28009 (connection as SYS should be as SYSDBA or SYSOPER) 로 막힌다.
    _jp_role=""
    if echo "$_jp_base" | grep -qi '[ 	]as[ 	][ 	]*sysdba[ 	]*$'; then
        _jp_role=" as sysdba"
    elif echo "$_jp_base" | grep -qi '[ 	]as[ 	][ 	]*sysoper[ 	]*$'; then
        _jp_role=" as sysoper"
    fi

    _jp_cred=$(echo "$_jp_base" | sed -e 's/@.*//' -e 's/[ 	][ 	]*[Aa][Ss][ 	].*$//')
    _jp_svc_clean=$(echo "$_jp_svc" | sed 's/^@//')
    echo "${_jp_cred}@${_jp_svc_clean}${_jp_role}"
    return 0
}

# 전체 사전 점검 오케스트레이션
#   run_preflight_checks <SOURCE|TARGET>
run_preflight_checks() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _pf_bin _pf_cont
    _pf_mode="$1"
    PREFLIGHT_RESULT="PASS"
    _pf_warn=0
    _pf_fail=0
    : > "$(tmpf preflight.csv)"

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "  [PRE-FLIGHT] Migration Requirement Verification"
    else echo "  [사전 검증] 이관 사전 요구사항 자동 점검"; fi
    echo "----------------------------------------------------------------------"

    # 1) 필수 바이너리
    if [ "$MOCK_MODE" != "true" ]; then
        for _pf_bin in sqlplus expdp impdp; do
            if command -v "$_pf_bin" >/dev/null 2>&1; then
                printf "   [ OK ] binary : %s\n" "$_pf_bin"
                pf_record "BINARY" "$_pf_bin" "OK" "PATH 에서 확인됨"
            else
                printf "   [FAIL] binary : %s 를 PATH 에서 찾을 수 없습니다\n" "$_pf_bin"
                pf_record "BINARY" "$_pf_bin" "FAIL" "PATH 에서 찾을 수 없음"
                _pf_fail=$((_pf_fail + 1))
            fi
        done
    else
        echo "   [SKIP] MOCK 모드 - 바이너리 점검 생략"
    fi

    # 2) Directory Object 경로 쓰기 권한 실검사
    if [ -n "$DIR_PHYSICAL_PATH" ]; then
        if check_dir_writable "$DIR_PHYSICAL_PATH"; then
            printf "   [ OK ] 쓰기권한 : %s\n" "$DIR_PHYSICAL_PATH"
            pf_record "DIRECTORY" "쓰기 권한" "OK" "$DIR_PHYSICAL_PATH"
        else
            printf "   [FAIL] 쓰기권한 : %s 에 파일을 생성할 수 없습니다 (OS 계정 권한 확인)\n" "$DIR_PHYSICAL_PATH"
            pf_record "DIRECTORY" "쓰기 권한" "FAIL" "$DIR_PHYSICAL_PATH 에 파일 생성 불가"
            _pf_fail=$((_pf_fail + 1))
        fi
    fi

    # 3) 예상 덤프 크기 vs 디스크 여유 공간
    if [ "$_pf_mode" = "SOURCE" ] && [ -n "$DIR_PHYSICAL_PATH" ]; then
        _pf_est=$(estimate_target_size_bytes)
        _pf_free=$(free_space_bytes "$DIR_PHYSICAL_PATH")
        if [ -n "$COMPRESSION_PARAM" ]; then
            _pf_need=$((_pf_est / 3))          # COMPRESSION=ALL 기준 보수적 1/3 추정
            _pf_note="(압축 적용, 1/3 추정)"
        else
            _pf_need=$_pf_est
            _pf_note="(무압축 기준)"
        fi
        _pf_need=$(( _pf_need + (_pf_need / 10) ))   # 10% 안전 마진
        printf "   [INFO] 대상 세그먼트 총합 : %s\n" "$(human_bytes "$_pf_est")"
        printf "   [INFO] 필요 예상 공간     : %s %s\n" "$(human_bytes "$_pf_need")" "$_pf_note"
        printf "   [INFO] 디스크 여유 공간   : %s (%s)\n" "$(human_bytes "$_pf_free")" "$DIR_PHYSICAL_PATH"
        if [ "$_pf_est" -eq 0 ]; then
            echo "   [WARN] 세그먼트 크기를 산출하지 못했습니다 (권한/대상 확인 필요)"
            pf_record "CAPACITY" "세그먼트 크기 산출" "WARN" "산출 실패 - 권한/대상 확인 필요"
            _pf_warn=$((_pf_warn + 1))
        elif [ "$_pf_free" -lt "$_pf_need" ]; then
            echo "   [FAIL] 디스크 여유 공간이 부족합니다. 공간 확보 또는 COMPRESSION 적용이 필요합니다."
            pf_record "CAPACITY" "디스크 여유 공간" "FAIL" "필요 $(human_bytes "$_pf_need") / 여유 $(human_bytes "$_pf_free")"
            _pf_fail=$((_pf_fail + 1))
        else
            echo "   [ OK ] 디스크 여유 공간 충분"
            pf_record "CAPACITY" "디스크 여유 공간" "OK" "필요 $(human_bytes "$_pf_need") / 여유 $(human_bytes "$_pf_free")"
        fi
    fi

    # 4) 버전 호환성
    if ! check_version_compatibility; then
        _pf_warn=$((_pf_warn + 1))
        pf_record "VERSION" "버전 호환성" "WARN" "Source 가 상위 버전 - ${VERSION_PARAM} 자동 추가"
    else
        if [ -n "$TARGET_DB_VERSION" ]; then
            echo "   [ OK ] 버전 호환성 : Source ${DB_VERSION} -> Target ${TARGET_DB_VERSION}"
            pf_record "VERSION" "버전 호환성" "OK" "Source ${DB_VERSION} -> Target ${TARGET_DB_VERSION}"
        fi
    fi

    # 5) 문자셋 확장 위험
    if ! check_charset_risk; then
        _pf_warn=$((_pf_warn + 1))
        pf_record "CHARSET" "문자셋 확장 위험" "WARN" "${DB_CHARSET} -> AL32UTF8 최대 3배 확장 (ORA-12899 위험)"
    else
        echo "   [ OK ] 문자셋 : ${DB_CHARSET}"
        pf_record "CHARSET" "문자셋 확장 위험" "OK" "${DB_CHARSET}"
    fi

    # 6) RAC 인지 여부 안내
    if [ "$DB_CLUSTER" = "TRUE" ]; then
        echo "   [INFO] RAC 감지 : 생성되는 모든 par 에 CLUSTER=N 이 적용됩니다"
        pf_record "RAC" "클러스터 대응" "INFO" "CLUSTER=N 자동 적용"
    fi

    echo "----------------------------------------------------------------------"
    if [ "$_pf_fail" -gt 0 ]; then
        PREFLIGHT_RESULT="FAIL"
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> PRE-FLIGHT RESULT: FAIL (${_pf_fail} blocking issue(s), ${_pf_warn} warning(s))"
        else echo "  >> 사전 검증 결과: FAIL (치명 ${_pf_fail}건 / 경고 ${_pf_warn}건)"; fi
    elif [ "$_pf_warn" -gt 0 ]; then
        PREFLIGHT_RESULT="WARN"
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> PRE-FLIGHT RESULT: WARN (${_pf_warn} warning(s))"
        else echo "  >> 사전 검증 결과: WARN (경고 ${_pf_warn}건)"; fi
    else
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> PRE-FLIGHT RESULT: PASS"
        else echo "  >> 사전 검증 결과: PASS (모든 항목 정상)"; fi
    fi
    echo "----------------------------------------------------------------------"

    if [ "$PREFLIGHT_RESULT" = "FAIL" ]; then
        if [ "$UNATTENDED" = "true" ]; then
            echo "  [무인모드] 치명적 문제가 있어 계속 진행하지만, 실행 전 반드시 조치하십시오."
            return 0
        fi
        if [ "$LANG_PREF" = "EN" ]; then printf "  Continue anyway? (y/N) [Default: N]: "
        else printf "  그래도 계속 진행하시겠습니까? (y/N) [기본값: N]: "; fi
        _read _pf_cont
        if [ "$_pf_cont" != "y" ] && [ "$_pf_cont" != "Y" ]; then
            return 1
        fi
    fi
    return 0
}

# 1. Source Server Mode (expdp 스크립트 생성)
run_source_mode() {
    # [FIX v07/B2] 메인 메뉴 루프에서 재진입할 때 이전 실행의 스크립트 목록이
    #              누적/재실행되지 않도록 관련 전역 변수를 모두 초기화한다.
    reset_generation_state
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [1] SOURCE SERVER: Check Resources & Generate expdp Scripts"
    else echo " [1] SOURCE SERVER: 리소스 점검 및 expdp 스크립트 생성"; fi
    echo "======================================================================"
    
    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE"
    echo "  * CPU Cores: $CPU_CORES"
    echo "  * Memory: $MEM_SIZE"
    echo "----------------------------------------------------------------------"
    
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Oracle connection account [Default: / as sysdba]: "
    else printf "  Oracle 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info
    calculate_parallel_degree

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [Select Export Method]"
        echo "  1) Local Database Export (Dump File)"
        echo "  2) NETWORK_LINK Direct Export (Extract from Remote DB via DB Link)"
        printf "  Select (1-2) [Default: 1]: "
    else
        echo "  [Export 방식 선택]"
        echo "  1) Local Database Export (Dump 파일 기반 일반 모드)"
        echo "  2) NETWORK_LINK Export (DB Link를 통해 원격 DB에서 추출하여 덤프 생성)"
        printf "  선택 (1-2) [기본값: 1]: "
    fi
    _read exp_method_opt
    if [ "$exp_method_opt" = "2" ]; then 
        EXPORT_METHOD="NETWORK_LINK"
    else 
        EXPORT_METHOD="LOCAL"
    fi

    DBLINK_SUFFIX=""
    EXP_SOURCE_PARAM=""
    if [ "$EXPORT_METHOD" = "NETWORK_LINK" ]; then
        echo "----------------------------------------------------------------------"
        if [ "$LANG_PREF" = "EN" ]; then echo "  [NETWORK_LINK Setup]"
        else echo "  [NETWORK_LINK 설정 (Database Link)]"; fi
        
        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Database Link Name to use or create [Default: MIG_LINK]: "
        else printf "  사용하거나 새로 생성할 Database Link 이름을 입력하세요 [기본값: MIG_LINK]: "; fi
        _read DBLINK_NAME
        [ -z "$DBLINK_NAME" ] && DBLINK_NAME="MIG_LINK"
        DBLINK_NAME=$(echo "$DBLINK_NAME" | tr 'a-z' 'A-Z')

        if [ "$MOCK_MODE" != "true" ]; then
            link_cnt=$(sqlplus -S /nolog <<EOF
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0
$PDB_SWITCH_SQL
SELECT COUNT(*) FROM dba_db_links WHERE db_link = '$DBLINK_NAME';
EXIT;
EOF
)
            link_cnt=$(to_num "$link_cnt")
            if [ "$link_cnt" -eq 0 ]; then
                if [ "$LANG_PREF" = "EN" ]; then echo "  >> DB Link '$DBLINK_NAME' not found. Let's create it."
                else echo "  >> DB Link '$DBLINK_NAME'가 존재하지 않습니다. 생성을 진행합니다."; fi
                printf "  - Remote DB Username (e.g. SYSTEM): "; _read src_user
                printf "  - Remote DB Password (input hidden / 입력 숨김): "
                _read_secret src_pwd MIG_DBLINK_PASSWORD
                printf "  - Remote DB TNS Alias or IP:PORT/SERVICE_NAME: "; _read src_tns

                # [v09.02] 복붙돼 있던 heredoc 을 공통 함수로 돌린다.
                #   패스워드 특수문자 검사 + SET DEFINE OFF + 종료코드 판정이 들어간다.
                if ! create_dblink_live "$DBLINK_NAME" "$src_user" "$src_pwd" "$src_tns"; then
                    if [ "$LANG_PREF" = "EN" ]; then
                        echo "  >> NETWORK_LINK import cannot proceed without the DB Link."
                    else
                        echo "  >> DB Link 없이는 NETWORK_LINK 임포트를 진행할 수 없습니다."
                    fi
                    return 1
                fi
            else
                if [ "$LANG_PREF" = "EN" ]; then echo "  >> DB Link '$DBLINK_NAME' exists. We will use it."
                else echo "  >> 기존에 존재하는 DB Link '$DBLINK_NAME'를 사용합니다."; fi
            fi
        fi
        EXP_SOURCE_PARAM="NETWORK_LINK=$DBLINK_NAME"
        DBLINK_SUFFIX="@$DBLINK_NAME"
    fi

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter expdp Dump File Size (GB) for splitting [Default: 10]: "
    else printf "  expdp 덤프 파일 사이즈 및 PARALLEL 기준(GB)을 입력하세요 [기본값: 10]: "; fi
    _read DUMP_FILE_SIZE_GB
    DUMP_FILE_SIZE_GB=${DUMP_FILE_SIZE_GB:-10}
    if ! echo "$DUMP_FILE_SIZE_GB" | grep -qE '^[0-9]+$'; then DUMP_FILE_SIZE_GB=10; fi
    SIZE_THRESHOLD_BYTES=$((DUMP_FILE_SIZE_GB * 1024 * 1024 * 1024))
    echo "  >> DUMP 파일 분할 사이즈 및 기준 크기: ${DUMP_FILE_SIZE_GB}GB 설정 완료"

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [Select expdp Migration Scope]"
        echo "  1) SCHEMA Mode"
        echo "  2) TABLE Mode"
        echo "  3) TABLESPACE Mode"
        echo "  4) FULL Mode"
        printf "  Select (1-4): "
    else
        echo "  [expdp 마이그레이션 이관 범위 선택]"
        echo "  1) SCHEMA 모드 (특정 사용자/스키마 기준 백업)"
        echo "  2) TABLE 모드 (특정 테이블 지정 백업)"
        echo "  3) TABLESPACE 모드 (특정 테이블스페이스 기준 백업)"
        echo "  4) FULL 모드 (전체 데이터베이스 백업)"
        printf "  선택 (1-4): "
    fi
    _read mig_mode

    case "$mig_mode" in
        1)
            MIG_TYPE="SCHEMA"
            if select_migration_targets "SCHEMA" "$DB_CONN"; then SCHEMAS_LIST="$SELECTED_LIST"; else _read SCHEMAS_LIST; SCHEMAS_LIST=$(normalize_list "$SCHEMAS_LIST"); fi
            MIG_PARAMS="SCHEMAS=$SCHEMAS_LIST"
            ;;
        2)
            MIG_TYPE="TABLE"
            if select_migration_targets "TABLE" "$DB_CONN"; then TABLES_LIST="$SELECTED_LIST"; else _read TABLES_LIST; fi
            MIG_PARAMS="TABLES=$TABLES_LIST"
            ;;
        3)
            MIG_TYPE="TABLESPACE"
            if select_migration_targets "TABLESPACE" "$DB_CONN"; then TBS_LIST="$SELECTED_LIST"; else _read TBS_LIST; fi
            MIG_PARAMS="TABLESPACES=$TBS_LIST"
            ;;
        4)
            MIG_TYPE="FULL"
            MIG_PARAMS="FULL=Y"
            ;;
        *)
            echo "  [오류/ERROR] 올바르지 않은 선택입니다."
            return 1
            ;;
    esac

    setup_db_directory || return 1

    # ------------------------------------------------------------------
    # [NEW v07] Target DB 버전 입력 (VERSION= 파라미터 자동 산출용)
    # ------------------------------------------------------------------
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter TARGET DB version for compatibility check (e.g. 19.0.0, empty to skip): "
    else printf "  호환성 점검을 위한 Target DB 버전을 입력하세요 (예: 19.0.0, 생략 시 엔터): "; fi
    _read TARGET_DB_VERSION

    # ------------------------------------------------------------------
    # [NEW v07] 덤프 압축(COMPRESSION) 설정
    # ------------------------------------------------------------------
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [Dump Compression]"
        echo "   1) NONE (default)"
        echo "   2) METADATA_ONLY  (no extra license required)"
        echo "   3) ALL            (requires Advanced Compression Option license)"
        echo "   4) DATA_ONLY      (requires Advanced Compression Option license)"
        printf "  Select (1-4) [Default: 1]: "
    else
        echo "  [덤프 압축(COMPRESSION) 설정]"
        echo "   1) 사용 안함 (기본값)"
        echo "   2) METADATA_ONLY  (별도 라이선스 불필요)"
        echo "   3) ALL            (Advanced Compression Option 라이선스 필요)"
        echo "   4) DATA_ONLY      (Advanced Compression Option 라이선스 필요)"
        printf "  선택 (1-4) [기본값: 1]: "
    fi
    _read comp_opt
    COMPRESSION_PARAM=""
    COMPRESSION_ALGO_PARAM=""
    case "$comp_opt" in
        2) COMPRESSION_PARAM="COMPRESSION=METADATA_ONLY" ;;
        3) COMPRESSION_PARAM="COMPRESSION=ALL" ;;
        4) COMPRESSION_PARAM="COMPRESSION=DATA_ONLY" ;;
        *) COMPRESSION_PARAM="" ;;
    esac
    if [ "$comp_opt" = "3" ] || [ "$comp_opt" = "4" ]; then
        if [ "$LANG_PREF" = "EN" ]; then
            echo "  [LICENSE NOTICE] COMPRESSION=ALL/DATA_ONLY requires the Advanced Compression Option."
            echo "                   Verify your licensing before running in production."
            printf "  Compression algorithm (1:BASIC 2:LOW 3:MEDIUM 4:HIGH) [Default: 3]: "
        else
            echo "  [라이선스 주의] COMPRESSION=ALL/DATA_ONLY 는 Advanced Compression Option 라이선스가 필요합니다."
            echo "                  운영 적용 전 반드시 라이선스 보유 여부를 확인하십시오."
            printf "  압축 알고리즘 선택 (1:BASIC 2:LOW 3:MEDIUM 4:HIGH) [기본값: 3]: "
        fi
        _read comp_algo_opt
        case "$comp_algo_opt" in
            1) COMPRESSION_ALGO_PARAM="COMPRESSION_ALGORITHM=BASIC" ;;
            2) COMPRESSION_ALGO_PARAM="COMPRESSION_ALGORITHM=LOW" ;;
            4) COMPRESSION_ALGO_PARAM="COMPRESSION_ALGORITHM=HIGH" ;;
            *) COMPRESSION_ALGO_PARAM="COMPRESSION_ALGORITHM=MEDIUM" ;;
        esac
        echo "  >> 적용: $COMPRESSION_PARAM / $COMPRESSION_ALGO_PARAM"
    fi

    # ------------------------------------------------------------------
    # [NEW v07] 덤프 체크섬(MD5) 생성 여부
    # ------------------------------------------------------------------
    if [ "$LANG_PREF" = "EN" ]; then printf "  Generate MD5 checksum manifest for dump files? (Y/n) [Default: Y]: "
    else printf "  덤프 파일 MD5 체크섬(무결성 검증용) 스크립트를 생성하시겠습니까? (Y/n) [기본값: Y]: "; fi
    _read chk_opt
    if [ -z "$chk_opt" ] || [ "$chk_opt" = "y" ] || [ "$chk_opt" = "Y" ]; then
        CHECKSUM_ENABLED="true"
    else
        CHECKSUM_ENABLED="false"
    fi

    # ------------------------------------------------------------------
    # [NEW v07] 사전 요구사항 자동 검증
    # ------------------------------------------------------------------
    run_preflight_checks "SOURCE" || return 1

    DATE_STR=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$")
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Unique Migration ID [Default: MIG_${MIG_TYPE}_${DATE_STR}]: "
    else printf "  이관 작업의 고유 ID를 입력하세요 [기본값: MIG_${MIG_TYPE}_${DATE_STR}]: "; fi
    _read user_id
    if [ -z "$user_id" ]; then
        UNIQUE_ID="MIG_${MIG_TYPE}_${DATE_STR}"
    else
        UNIQUE_ID=$(echo "$user_id" | tr ' ' '_')
    fi
    # [NEW v08.03] 사전 검증 결과를 HTML 리포트가 읽을 수 있도록 확정 기록
    flush_preflight_csv

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  Use Flashback SCN for consistent dump? (y/n) [Default: n]: "
    else printf "  Flashback SCN 옵션을 사용하여 일관성 있는 덤프를 수행하시겠습니까? (y/n) [기본값: n]: "; fi
    _read use_scn
    FLASHBACK_PARAM=""
    if [ "$use_scn" = "y" ] || [ "$use_scn" = "Y" ]; then
        if [ "$MOCK_MODE" = "true" ]; then CURRENT_SCN="1234567890"
        else
            scn_sql="$(tmpf get_scn.sql)"
            echo "SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 100 TRIMSPOOL ON;" > "$scn_sql"
            echo "SELECT current_scn FROM v\$database;" >> "$scn_sql"
            echo "EXIT;" >> "$scn_sql"
            CURRENT_SCN=$(sqlplus -S /nolog <<CONNECT_EOF | grep -v '^$' | tr -d ' ' | head -n 1
connect $DB_CONN
@$scn_sql
CONNECT_EOF
            )
            rm -f "$scn_sql"
        fi
        
        if echo "$CURRENT_SCN" | grep -qE '^[0-9]+$'; then
            echo "  >> Current DB SCN: $CURRENT_SCN"
            if [ "$LANG_PREF" = "EN" ]; then printf "  Press Enter to use this SCN, or type a custom SCN: "
            else printf "  위 SCN을 사용하시려면 엔터를, 다른 SCN을 지정하시려면 값을 입력하세요: "; fi
            _read custom_scn
            if [ -n "$custom_scn" ] && echo "$custom_scn" | grep -qE '^[0-9]+$'; then FINAL_SCN="$custom_scn"; else FINAL_SCN="$CURRENT_SCN"; fi
            echo "  >> Applied SCN: $FINAL_SCN"
            FLASHBACK_PARAM="FLASHBACK_SCN=$FINAL_SCN"
        else
            echo "  [경고/WARNING] Failed to fetch SCN. Skipping Flashback SCN."
        fi
    fi

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  [Security] Enter TDE Encryption Password (leave empty if not using TDE): "
    else printf "  [보안 검토] DB에 암호화(TDE)가 적용되어 있습니까? 패스워드를 입력하세요 (입력 숨김, 미사용 시 엔터): "; fi
    _read_secret tde_pwd MIG_TDE_PASSWORD
    TDE_PARAM=""
    if [ -n "$tde_pwd" ]; then
        TDE_PARAM="ENCRYPTION_PASSWORD=\"$tde_pwd\""
    fi

    # 데이터 서브세팅 (QUERY / SAMPLE 필터)
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  [Data Subsetting] Apply QUERY or SAMPLE filter? (y/N) [Default: N]: "
    else printf "  [데이터 필터링/샘플링] 조건부 추출(QUERY) 또는 샘플링(SAMPLE)을 설정하시겠습니까? (y/N) [기본값: N]: "; fi
    _read use_filter_opt
    QUERY_FILTER_PARAM=""
    SAMPLE_FILTER_PARAM=""
    if [ "$use_filter_opt" = "y" ] || [ "$use_filter_opt" = "Y" ]; then
        if [ "$LANG_PREF" = "EN" ]; then printf "  - Enter QUERY filter (e.g. TABLE:\"WHERE CREATE_DATE >= SYSDATE-30\" or empty): "
        else printf "  - QUERY 조건식 입력 (예: TABLE:\"WHERE CREATE_DATE >= SYSDATE-30\" 또는 미사용시 엔터): "; fi
        _read user_query_filter
        [ -n "$user_query_filter" ] && QUERY_FILTER_PARAM="QUERY=${user_query_filter}"
        
        if [ "$LANG_PREF" = "EN" ]; then printf "  - Enter SAMPLE percentage (1-99, e.g. 10 for 10%% data or empty): "
        else printf "  - SAMPLE 추출 비율(%%) 입력 (1-99, 예: 10 또는 미사용시 엔터): "; fi
        _read user_sample_pct
        if [ -n "$user_sample_pct" ] && echo "$user_sample_pct" | grep -qE '^[0-9]+$'; then
            SAMPLE_FILTER_PARAM="SAMPLE=${user_sample_pct}"
        fi
    fi

    if [ "$EXPORT_METHOD" = "NETWORK_LINK" ]; then
        STAT_EXCLUDE=""
    else
        STAT_EXCLUDE="EXCLUDE=STATISTICS"
    fi

    GENERATED_EST_SCRIPTS=""
    GENERATED_EXEC_SCRIPTS=""
    GENERATED_META_SCRIPTS=""
    GENERATED_STATS_SCRIPTS=""
    GENERATED_XFER_SCRIPTS=""

    # expdp 실행용 connection string 설정 (PDB 모드이면 PDB TNS 바인딩)
    EXPDP_USERID_STR="$DB_CONN"
    if [ -n "$PDB_CONNECT_STR" ]; then
        EXPDP_USERID_STR="$PDB_CONNECT_STR"
    fi

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "  [Mandatory: Generating Custom Metadata Backup Script for DDL extraction]"
    else echo "  [필수: 이관 범위 맞춤형(Custom) 메타데이터 백업 스크립트 생성]"; fi
    
    META_SH="expdp_0_meta_custom_${UNIQUE_ID}.sh"
    META_PAR="expdp_0_meta_custom_${UNIQUE_ID}.par"
    echo "  * 생성 중: $META_SH 및 $META_PAR"
    
    cat <<EOF > "$META_PAR"
# [SEC v08.01] 접속 문자열을 커맨드라인이 아닌 PARFILE 에 둔다.
#   커맨드라인에 두면 같은 서버의 다른 OS 계정이 ps -ef 로 패스워드를
#   평문으로 볼 수 있다(CWE-214). 이 파일은 chmod 600 으로 보호된다.
USERID="$EXPDP_USERID_STR"
DIRECTORY=$DIR_OBJ_NAME
DUMPFILE=${UNIQUE_ID}_meta_custom_%U.dmp
LOGFILE=${UNIQUE_ID}_expdp_meta_custom.log
FILESIZE=${DUMP_FILE_SIZE_GB}G
$MIG_PARAMS
CONTENT=METADATA_ONLY
LOGTIME=ALL
METRICS=YES
JOB_NAME=${UNIQUE_ID}_META_CUS
EOF
    # [FIX v07] 메타데이터 expdp 에도 RAC 대응 CLUSTER=N 을 적용 (v06 누락)
    if [ "$DB_CLUSTER" = "TRUE" ]; then echo "CLUSTER=N" >> "$META_PAR"; fi
    if [ -n "$EXP_SOURCE_PARAM" ]; then echo "$EXP_SOURCE_PARAM" >> "$META_PAR"; fi
    if [ -n "$STAT_EXCLUDE" ]; then echo "$STAT_EXCLUDE" >> "$META_PAR"; fi
    if [ -n "$FLASHBACK_PARAM" ]; then echo "$FLASHBACK_PARAM" >> "$META_PAR"; fi
    if [ -n "$TDE_PARAM" ]; then echo "$TDE_PARAM" >> "$META_PAR"; fi
    # [NEW v07] 하위 버전 Target 호환 및 압축
    if [ -n "$VERSION_PARAM" ]; then echo "$VERSION_PARAM" >> "$META_PAR"; fi
    if [ -n "$COMPRESSION_PARAM" ]; then echo "$COMPRESSION_PARAM" >> "$META_PAR"; fi
    if [ -n "$COMPRESSION_ALGO_PARAM" ]; then echo "$COMPRESSION_ALGO_PARAM" >> "$META_PAR"; fi

    cat <<EOF > "$META_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
    generate_run_prompt "$META_SH" "Target DDL 추출용 맞춤형 메타데이터 덤프 생성"
    if [ -n "$CREATE_DIR_SQL" ]; then
        cat <<EOF >> "$META_SH"
sqlplus -S /nolog <<SQL_EOF
connect $DB_CONN
$CREATE_DIR_SQL
$GRANT_DIR_SQL
EXIT;
SQL_EOF

EOF
    fi
    cat <<EOF >> "$META_SH"
expdp PARFILE=$META_PAR
EOF
    chmod 700 "$META_SH"; chmod 600 "$META_PAR" 2>/dev/null   # [FIX v07/M1] par 내 TDE 패스워드 보호
    GENERATED_META_SCRIPTS="$META_SH"

    BIG_ITEMS=""
    SMALL_ITEMS=""
    
    if [ "$MIG_TYPE" = "FULL" ]; then
        SMALL_ITEMS="FULL"
    elif [ "$MOCK_MODE" = "true" ]; then
        if [ "$MIG_TYPE" = "SCHEMA" ]; then BIG_ITEMS=$(echo "$SCHEMAS_LIST" | cut -d',' -f1); SMALL_ITEMS=$(echo "$SCHEMAS_LIST" | cut -d',' -f2-); fi
        [ "$BIG_ITEMS" = "$SMALL_ITEMS" ] && SMALL_ITEMS=""
    else
        echo "  [Segment Size 검사 중 (기준 크기: ${DUMP_FILE_SIZE_GB}GB) ...]"
        size_check_sql="$(tmpf size_check.sql)"
        size_check_out="$(tmpf size_check.out)"
        
        TARGET_IN_CLAUSE=""
        IFS_BACKUP=$IFS; IFS=","
        ITEM_LIST="$SCHEMAS_LIST$TABLES_LIST$TBS_LIST"
        for itm in $ITEM_LIST; do
            [ -n "$TARGET_IN_CLAUSE" ] && TARGET_IN_CLAUSE="$TARGET_IN_CLAUSE,"
            TARGET_IN_CLAUSE="$TARGET_IN_CLAUSE'$itm'"
        done
        IFS=$IFS_BACKUP

        if [ "$MIG_TYPE" = "SCHEMA" ]; then
            cat <<EOF > "$size_check_sql"
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500
$PDB_SWITCH_SQL
SELECT owner || '|' || SUM(bytes) FROM dba_segments${DBLINK_SUFFIX} WHERE owner IN ($TARGET_IN_CLAUSE) GROUP BY owner;
EXIT;
EOF
        elif [ "$MIG_TYPE" = "TABLESPACE" ]; then
            cat <<EOF > "$size_check_sql"
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500
$PDB_SWITCH_SQL
SELECT tablespace_name || '|' || SUM(bytes) FROM dba_segments${DBLINK_SUFFIX} WHERE tablespace_name IN ($TARGET_IN_CLAUSE) GROUP BY tablespace_name;
EXIT;
EOF
        elif [ "$MIG_TYPE" = "TABLE" ]; then
            COND=""
            IFS_BACKUP=$IFS; IFS=","
            for itm in $ITEM_LIST; do
                own_part=$(echo "$itm" | cut -d'.' -f1); tab_part=$(echo "$itm" | cut -d'.' -f2)
                [ -n "$COND" ] && COND="$COND OR "
                COND="$COND(owner='$own_part' AND segment_name='$tab_part')"
            done
            IFS=$IFS_BACKUP
            cat <<EOF > "$size_check_sql"
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500
$PDB_SWITCH_SQL
SELECT owner || '.' || segment_name || '|' || SUM(bytes) FROM dba_segments${DBLINK_SUFFIX} WHERE $COND GROUP BY owner, segment_name;
EXIT;
EOF
        fi
        
        sqlplus -S /nolog <<CONNECT_EOF > "$size_check_out" 2>/dev/null
connect $DB_CONN
@$size_check_sql
CONNECT_EOF
        
        IFS_BACKUP=$IFS; IFS=","
        for itm in $ITEM_LIST; do
            found_line=$(grep -i "^[[:space:]]*${itm}|" "$size_check_out" 2>/dev/null | head -n 1)
            if [ -n "$found_line" ]; then
                itm_size=$(echo "$found_line" | cut -d'|' -f2 | awk '{$1=$1;print}')
                if [ -n "$itm_size" ] && echo "$itm_size" | grep -qE '^[0-9]+$' 2>/dev/null; then
                    if [ "$itm_size" -ge "$SIZE_THRESHOLD_BYTES" ]; then
                        [ -n "$BIG_ITEMS" ] && BIG_ITEMS="$BIG_ITEMS,"
                        BIG_ITEMS="$BIG_ITEMS$itm"
                        continue
                    fi
                fi
            else
                if [ "$LANG_PREF" = "EN" ]; then echo "  [WARNING] Target '$itm' has no allocated segments in DB."
                else echo "  [경고] '$itm' 대상은 DB 내에 할당된 데이터 세그먼트가 없습니다."; fi
            fi
            [ -n "$SMALL_ITEMS" ] && SMALL_ITEMS="$SMALL_ITEMS,"
            SMALL_ITEMS="$SMALL_ITEMS$itm"
        done
        IFS=$IFS_BACKUP
        rm -f "$size_check_sql" "$size_check_out"
    fi

    generate_expdp_scripts() {
        _exp_target_items="$1"
        _exp_suffix="$2"
        _exp_p_type="$3"
        _exp_use_parallel="$4"
        
        _exp_m_params=""
        if [ "$_exp_p_type" = "FULL" ]; then _exp_m_params="FULL=Y"; else _exp_m_params="${_exp_p_type}=${_exp_target_items}"; fi

        _exp_est_sh="expdp_estimate_${UNIQUE_ID}_${_exp_suffix}.sh"
        _exp_est_par="expdp_estimate_${UNIQUE_ID}_${_exp_suffix}.par"
        echo "  * 생성 중: $_exp_est_sh 및 $_exp_est_par"
        
        cat <<EOF > "$_exp_est_par"
# [SEC v08.01] 접속 문자열을 커맨드라인이 아닌 PARFILE 에 둔다.
#   커맨드라인에 두면 같은 서버의 다른 OS 계정이 ps -ef 로 패스워드를
#   평문으로 볼 수 있다(CWE-214). 이 파일은 chmod 600 으로 보호된다.
USERID="$EXPDP_USERID_STR"
DIRECTORY=$DIR_OBJ_NAME
LOGFILE=${UNIQUE_ID}_expdp_estimate_${_exp_suffix}.log
$_exp_m_params
ESTIMATE_ONLY=YES
EOF
        if [ "$DB_CLUSTER" = "TRUE" ]; then echo "CLUSTER=N" >> "$_exp_est_par"; fi
        if [ -n "$EXP_SOURCE_PARAM" ]; then echo "$EXP_SOURCE_PARAM" >> "$_exp_est_par"; fi
        if [ -n "$STAT_EXCLUDE" ]; then echo "$STAT_EXCLUDE" >> "$_exp_est_par"; else echo "EXCLUDE=STATISTICS" >> "$_exp_est_par"; fi
        if [ -n "$VERSION_PARAM" ]; then echo "$VERSION_PARAM" >> "$_exp_est_par"; fi

        cat <<EOF > "$_exp_est_sh"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
        generate_run_prompt "$_exp_est_sh" "expdp 용량 예측 시뮬레이션 ($_exp_suffix)"
        cat <<EOF >> "$_exp_est_sh"
expdp PARFILE=$_exp_est_par
EOF
        chmod 700 "$_exp_est_sh"; chmod 600 "$_exp_est_par" 2>/dev/null   # [FIX v07/M1] par 내 TDE 패스워드 보호

        _exp_exec_sh="expdp_execute_${UNIQUE_ID}_${_exp_suffix}.sh"
        _exp_exec_par="expdp_execute_${UNIQUE_ID}_${_exp_suffix}.par"
        echo "  * 생성 중: $_exp_exec_sh 및 $_exp_exec_par"

        cat <<EOF > "$_exp_exec_par"
# [SEC v08.01] 접속 문자열을 커맨드라인이 아닌 PARFILE 에 둔다.
#   커맨드라인에 두면 같은 서버의 다른 OS 계정이 ps -ef 로 패스워드를
#   평문으로 볼 수 있다(CWE-214). 이 파일은 chmod 600 으로 보호된다.
USERID="$EXPDP_USERID_STR"
DIRECTORY=$DIR_OBJ_NAME
DUMPFILE=${UNIQUE_ID}_${_exp_suffix}_%U.dmp
LOGFILE=${UNIQUE_ID}_expdp_${_exp_suffix}.log
FILESIZE=${DUMP_FILE_SIZE_GB}G
$_exp_m_params
STATUS=30
LOGTIME=ALL
METRICS=YES
JOB_NAME=${UNIQUE_ID}_EXP_${_exp_suffix}
EOF
        if [ "$DB_CLUSTER" = "TRUE" ]; then echo "CLUSTER=N" >> "$_exp_exec_par"; fi
        if [ -n "$EXP_SOURCE_PARAM" ]; then echo "$EXP_SOURCE_PARAM" >> "$_exp_exec_par"; fi
        if [ -n "$STAT_EXCLUDE" ]; then echo "$STAT_EXCLUDE" >> "$_exp_exec_par"; fi
        if [ "$_exp_use_parallel" = "YES" ] && [ "$CALC_PARALLEL" -gt 0 ]; then echo "PARALLEL=$CALC_PARALLEL" >> "$_exp_exec_par"; fi
        if [ -n "$FLASHBACK_PARAM" ]; then echo "$FLASHBACK_PARAM" >> "$_exp_exec_par"; fi
        if [ -n "$TDE_PARAM" ]; then echo "$TDE_PARAM" >> "$_exp_exec_par"; fi
        if [ -n "$QUERY_FILTER_PARAM" ]; then echo "$QUERY_FILTER_PARAM" >> "$_exp_exec_par"; fi
        if [ -n "$SAMPLE_FILTER_PARAM" ]; then echo "$SAMPLE_FILTER_PARAM" >> "$_exp_exec_par"; fi
        # [NEW v07] Target 하위버전 호환(VERSION=) 및 덤프 압축(COMPRESSION=)
        if [ -n "$VERSION_PARAM" ]; then echo "$VERSION_PARAM" >> "$_exp_exec_par"; fi
        if [ -n "$COMPRESSION_PARAM" ]; then echo "$COMPRESSION_PARAM" >> "$_exp_exec_par"; fi
        if [ -n "$COMPRESSION_ALGO_PARAM" ]; then echo "$COMPRESSION_ALGO_PARAM" >> "$_exp_exec_par"; fi

        cat <<EOF > "$_exp_exec_sh"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
        generate_run_prompt "$_exp_exec_sh" "실제 데이터 expdp ($_exp_suffix)"
        cat <<EOF >> "$_exp_exec_sh"
expdp PARFILE=$_exp_exec_par
EOF
        chmod 700 "$_exp_exec_sh"; chmod 600 "$_exp_exec_par" 2>/dev/null   # [FIX v07/M1] par 내 TDE 패스워드 보호

        GENERATED_EST_SCRIPTS="$GENERATED_EST_SCRIPTS $_exp_est_sh"
        GENERATED_EXEC_SCRIPTS="$GENERATED_EXEC_SCRIPTS $_exp_exec_sh"
    }

    PARAM_TYPE="FULL"
    if [ "$MIG_TYPE" = "SCHEMA" ]; then PARAM_TYPE="SCHEMAS"; fi
    if [ "$MIG_TYPE" = "TABLE" ]; then PARAM_TYPE="TABLES"; fi
    if [ "$MIG_TYPE" = "TABLESPACE" ]; then PARAM_TYPE="TABLESPACES"; fi

    if [ -n "$BIG_ITEMS" ]; then
        IFS_BACKUP=$IFS; IFS=","
        for b_item in $BIG_ITEMS; do
            b_suffix=$(echo "$b_item" | tr '.:' '__')
            echo "  [개별(기준 이상) 대상 스크립트 생성] $b_item"
            generate_expdp_scripts "$b_item" "$b_suffix" "$PARAM_TYPE" "YES"
        done
        IFS=$IFS_BACKUP
    fi

    if [ -n "$SMALL_ITEMS" ]; then
        echo "  [그룹화(기준 미만) 대상 스크립트 생성]"
        generate_expdp_scripts "$SMALL_ITEMS" "GROUP" "$PARAM_TYPE" "NO"
    fi

    if [ "$EXPORT_METHOD" = "LOCAL" ]; then
        echo "----------------------------------------------------------------------"
        if [ "$LANG_PREF" = "EN" ]; then echo "  [Generate DBMS_STATS Migration Script]"
        else echo "  [통계정보(DBMS_STATS) 전용 이관 스크립트 생성]"; fi
        STAT_OWN="SYSTEM"
        STAT_TAB="MIG_STAT_${UNIQUE_ID}"
        STATS_SQL="export_dbms_stats_${UNIQUE_ID}.sql"
        STATS_SH="export_dbms_stats_${UNIQUE_ID}.sh"
        STATS_PAR="export_dbms_stats_${UNIQUE_ID}.par"
        
        echo "  * 생성 중: $STATS_SQL, $STATS_SH 및 $STATS_PAR"
        
        cat <<EOF > "$STATS_SQL"
$PDB_SWITCH_SQL
BEGIN
  BEGIN
    DBMS_STATS.DROP_STAT_TABLE('$STAT_OWN', '$STAT_TAB');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  DBMS_STATS.CREATE_STAT_TABLE('$STAT_OWN', '$STAT_TAB');

EOF
        
        if [ "$MIG_TYPE" = "FULL" ]; then
            echo "  DBMS_STATS.EXPORT_DATABASE_STATS(statown => '$STAT_OWN', stattab => '$STAT_TAB');" >> "$STATS_SQL"
        elif [ "$MIG_TYPE" = "SCHEMA" ]; then
            IFS_BACKUP=$IFS; IFS=","
            for sch in $SCHEMAS_LIST; do
                echo "  DBMS_STATS.EXPORT_SCHEMA_STATS(ownname => '$sch', statown => '$STAT_OWN', stattab => '$STAT_TAB');" >> "$STATS_SQL"
            done
            IFS=$IFS_BACKUP
        elif [ "$MIG_TYPE" = "TABLE" ]; then
            IFS_BACKUP=$IFS; IFS=","
            for tbl in $TABLES_LIST; do
                sch_p=$(echo "$tbl" | cut -d'.' -f1); tbl_p=$(echo "$tbl" | cut -d'.' -f2)
                echo "  DBMS_STATS.EXPORT_TABLE_STATS(ownname => '$sch_p', tabname => '$tbl_p', statown => '$STAT_OWN', stattab => '$STAT_TAB');" >> "$STATS_SQL"
            done
            IFS=$IFS_BACKUP
        elif [ "$MIG_TYPE" = "TABLESPACE" ]; then
            echo "  FOR rec IN (SELECT owner, table_name FROM dba_tables WHERE tablespace_name IN ($TARGET_IN_CLAUSE)) LOOP" >> "$STATS_SQL"
            echo "    DBMS_STATS.EXPORT_TABLE_STATS(ownname => rec.owner, tabname => rec.table_name, statown => '$STAT_OWN', stattab => '$STAT_TAB');" >> "$STATS_SQL"
            echo "  END LOOP;" >> "$STATS_SQL"
        fi
        
        cat <<EOF >> "$STATS_SQL"
END;
/
EXIT;
EOF

        cat <<EOF > "$STATS_PAR"
# [SEC v08.01] 접속 문자열을 커맨드라인이 아닌 PARFILE 에 둔다.
#   커맨드라인에 두면 같은 서버의 다른 OS 계정이 ps -ef 로 패스워드를
#   평문으로 볼 수 있다(CWE-214). 이 파일은 chmod 600 으로 보호된다.
USERID="$EXPDP_USERID_STR"
DIRECTORY=$DIR_OBJ_NAME
DUMPFILE=${UNIQUE_ID}_stats_%U.dmp
LOGFILE=${UNIQUE_ID}_expdp_stats.log
TABLES=$STAT_OWN.$STAT_TAB
STATUS=30
LOGTIME=ALL
METRICS=YES
JOB_NAME=${UNIQUE_ID}_STAT_EXP
EOF
        if [ -n "$TDE_PARAM" ]; then echo "$TDE_PARAM" >> "$STATS_PAR"; fi
        if [ "$DB_CLUSTER" = "TRUE" ]; then echo "CLUSTER=N" >> "$STATS_PAR"; fi
        if [ -n "$VERSION_PARAM" ]; then echo "$VERSION_PARAM" >> "$STATS_PAR"; fi
        
        cat <<EOF > "$STATS_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
        generate_run_prompt "$STATS_SH" "DBMS_STATS 통계정보 추출(SQL) 및 통계테이블 expdp"
        cat <<EOF >> "$STATS_SH"
echo ">> DBMS_STATS 통계정보를 Stat Table에 담는 중입니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$STATS_SQL
CONNECT_EOF
 
echo ">> Stat Table 백업을 위해 expdp를 실행합니다..."
expdp PARFILE=$STATS_PAR

echo ">> Export 완료 후 임시 통계 테이블(${STAT_OWN}.${STAT_TAB})을 삭제합니다..."
sqlplus -S /nolog <<SQL_EOF
connect $DB_CONN
$PDB_SWITCH_SQL
BEGIN
  DBMS_STATS.DROP_STAT_TABLE('${STAT_OWN}', '${STAT_TAB}');
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
EXIT;
SQL_EOF
EOF
        chmod 700 "$STATS_SH"; chmod 600 "$STATS_PAR" 2>/dev/null   # [FIX v07/M1] par 내 TDE 패스워드 보호
        GENERATED_STATS_SCRIPTS="$STATS_SH"
    fi

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  [Transfer] Generate auto-transfer script (scp) to Target server? (y/N): "
    else printf "  [작업 단절 해소] 생성된 덤프 파일들을 Target 서버로 즉시 전송하는 스크립트를 만드시겠습니까? (y/N): "; fi
    _read gen_xfer
    if [ "$gen_xfer" = "y" ] || [ "$gen_xfer" = "Y" ]; then
        printf "  - Target 서버 IP 주소: "
        _read tgt_ip
        printf "  - Target 서버 OS 계정 (예: oracle): "
        _read tgt_user
        printf "  - Target 서버 저장 경로 (예: /backup/dump): "
        _read tgt_path
        
        if [ "$LANG_PREF" = "EN" ]; then printf "  - Max retry count on transfer failure [Default: 3]: "
        else printf "  - 전송 실패 시 최대 재시도 횟수 [기본값: 3]: "; fi
        _read xfer_retry
        if ! echo "$xfer_retry" | grep -qE '^[0-9]+$'; then xfer_retry=3; fi
        [ "$xfer_retry" -lt 1 ] && xfer_retry=1

        XFER_SH="transfer_dumps_to_target_${UNIQUE_ID}.sh"
        echo "  * 생성 중: $XFER_SH (재시도 + 무결성 검증 포함)"
        cat <<EOF > "$XFER_SH"
#!/bin/bash
# ==============================================================================
#  [NEW v07] Auto Transfer with Retry & Integrity Verification
#  Job ID  : ${UNIQUE_ID}
#  Target  : ${tgt_user}@${tgt_ip}:${tgt_path}
#  특징    : 파일 단위 전송 / 실패 시 재시도 / rsync 우선 사용 / 전송 후 체크섬 검증
# ==============================================================================
SRC_DIR="\${1:-${DIR_PHYSICAL_PATH}}"
TGT_USER="${tgt_user}"
TGT_IP="${tgt_ip}"
TGT_PATH="${tgt_path}"
MAX_RETRY=${xfer_retry}
XFER_LOG="transfer_${UNIQUE_ID}.log"

log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" | tee -a "\$XFER_LOG"; }

# rsync 가 있으면 중단 지점 이어받기(--partial)가 가능해 대용량에 유리하다.
if command -v rsync >/dev/null 2>&1; then
    XFER_TOOL="rsync"
else
    XFER_TOOL="scp"
fi

send_one() {
    _f="\$1"
    _try=1
    while [ \$_try -le \$MAX_RETRY ]; do
        if [ "\$XFER_TOOL" = "rsync" ]; then
            rsync -a --partial --timeout=120 "\$_f" "\${TGT_USER}@\${TGT_IP}:\${TGT_PATH}/" && return 0
        else
            scp -p "\$_f" "\${TGT_USER}@\${TGT_IP}:\${TGT_PATH}/" && return 0
        fi
        log "   [RETRY \$_try/\$MAX_RETRY] 전송 실패: \$(basename "\$_f")"
        _try=\$((_try + 1))
        sleep 5
    done
    return 1
}

log "====================================================================="
log "  [Auto Transfer] Target Server 로 덤프/로그 전송 시작 (tool: \$XFER_TOOL)"
log "  - Source : \$SRC_DIR"
log "  - Target : \${TGT_USER}@\${TGT_IP}:\${TGT_PATH}"
log "  - Retry  : \$MAX_RETRY"
log "====================================================================="

_sent=0; _failed=0
for f in "\$SRC_DIR"/${UNIQUE_ID}*.dmp "\$SRC_DIR"/${UNIQUE_ID}*.log "\$SRC_DIR"/${UNIQUE_ID}_dumpfiles.md5; do
    [ -e "\$f" ] || continue
    if send_one "\$f"; then
        log "   [ OK ] \$(basename "\$f")"
        _sent=\$((_sent + 1))
    else
        log "   [FAIL] \$(basename "\$f") - 최대 재시도 초과"
        _failed=\$((_failed + 1))
    fi
done

log "---------------------------------------------------------------------"
log ">> 전송 완료: 성공 \${_sent}건 / 실패 \${_failed}건"

if [ \$_failed -gt 0 ]; then
    log ">> [FAIL] 일부 파일 전송에 실패했습니다. 재실행하면 성공한 파일은 빠르게 건너뜁니다."
    exit 1
fi

# 전송 후 원격지 무결성 검증 (체크섬 매니페스트가 함께 전송된 경우)
if [ -f "\$SRC_DIR/${UNIQUE_ID}_dumpfiles.md5" ]; then
    log ">> 원격 서버에서 체크섬 무결성 검증을 시도합니다..."
    if scp -p "./checksum_verify_${UNIQUE_ID}.sh" "\${TGT_USER}@\${TGT_IP}:\${TGT_PATH}/" 2>/dev/null; then
        ssh "\${TGT_USER}@\${TGT_IP}" "bash \${TGT_PATH}/checksum_verify_${UNIQUE_ID}.sh \${TGT_PATH}" 2>&1 | tee -a "\$XFER_LOG"
    else
        log "   [INFO] 검증 스크립트 전송 실패. Target 에서 수동으로 checksum_verify_${UNIQUE_ID}.sh 를 실행하십시오."
    fi
fi
log ">> 전송 작업이 종료되었습니다. 로그: \$XFER_LOG"
EOF
        chmod 700 "$XFER_SH"
        GENERATED_XFER_SCRIPTS="$XFER_SH"
    fi

    # [NEW v07] 덤프 무결성 체크섬 스크립트 생성
    generate_checksum_scripts

    generate_target_env_ddl
    generate_grants_and_synonyms_scripts
    generate_monitoring_and_stop_scripts

    # 마스터 실행 파이프라인 러너 생성
    # [NEW v07] 체크섬 생성은 expdp 이후 / 전송 이전에 위치해야 매니페스트가 함께 전송된다.
    CHK_CREATE_IN_FLOW=""
    if [ "$CHECKSUM_ENABLED" = "true" ] && [ -n "$GENERATED_CHECKSUM_SCRIPTS" ]; then
        CHK_CREATE_IN_FLOW=$(echo "$GENERATED_CHECKSUM_SCRIPTS" | awk '{print $1}')
    fi
    ALL_SRC_FLOW="$GENERATED_META_SCRIPTS $GENERATED_EXEC_SCRIPTS $GENERATED_STATS_SCRIPTS $CHK_CREATE_IN_FLOW $GENERATED_XFER_SCRIPTS"
    generate_master_runner_script "Source Server Export Pipeline" "$ALL_SRC_FLOW"

    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> Script Generation Complete!"
    else echo "  >> 스크립트 생성 완료!"; fi
    echo "  [Master Orchestrator Pipeline]"
    echo "  * $MASTER_RUNNER_SH"
    echo "  [Individual Step Scripts]"
    for gs in $GENERATED_META_SCRIPTS; do echo "  - $gs"; done
    for gs in $GENERATED_EST_SCRIPTS; do echo "  - $gs"; done
    for gs in $GENERATED_EXEC_SCRIPTS; do echo "  - $gs"; done
    for gs in $GENERATED_STATS_SCRIPTS; do echo "  - $gs"; done
    for gs in $GENERATED_XFER_SCRIPTS; do echo "  - $gs"; done
    if [ -n "$GENERATED_CHECKSUM_SCRIPTS" ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  [Integrity Checksum Scripts]"; else echo "  [덤프 무결성 체크섬 스크립트]"; fi
        for gs in $GENERATED_CHECKSUM_SCRIPTS; do echo "  * $gs"; done
        if [ "$LANG_PREF" = "EN" ]; then echo "    (Copy checksum_verify_*.sh to the Target server and run it before impdp)"
        else echo "    (checksum_verify_*.sh 는 Target 서버로 복사해 impdp 이전에 실행하십시오)"; fi
    fi
    if [ -n "$GENERATED_UTIL_SCRIPTS" ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  [Monitoring & Stop Utilities]"; else echo "  [모니터링 및 안전 중지 헬퍼 유틸리티]"; fi
        for gs in $GENERATED_UTIL_SCRIPTS; do echo "  * $gs"; done
    fi
    echo "======================================================================"

    for gs in $GENERATED_META_SCRIPTS; do ask_to_run_script "$gs"; done
    for gs in $GENERATED_EST_SCRIPTS; do ask_to_run_script "$gs"; done
    for gs in $GENERATED_EXEC_SCRIPTS; do ask_to_run_script "$gs"; done
}

# 2. Target Server Mode (impdp 복구 스크립트 생성)
# ==============================================================================
# [NEW v09.00] DB Link 기반 SQL 데이터 이관 (이관 3방식 중 ③)
#
#  위치
#  ---------------------------------------------------------------------------
#    ① Data Pump 파일 기반        대용량 전체 이관. PQ 를 제대로 쓰는 유일한 방법
#    ② Data Pump NETWORK_LINK     덤프 없이. 단 PQ 슬레이브를 쓰지 않음
#    ③ 순수 SQL over DB Link      ← 이 모듈
#
#  ③ 이 유리한 경우
#    - ① 로 SCN 시점 대량 적재 후 그 이후 변경분만 따라잡는 증분 캐치업
#    - 일부 테이블만, 또는 WHERE 조건으로 걸러 옮길 때
#    - 옮기면서 값을 바꿔야 할 때
#
#  ③ 의 한계 (스크립트가 사전에 차단합니다)
#    - LONG / LONG RAW 는 DB Link 너머로 SELECT 자체가 안 됨 (ORA-00997)
#    - LOB 는 되지만 느리고, 원격 LOB 로케이터 연산은 ORA-22992
#    - 메타데이터를 전혀 옮기지 않음 — 인덱스/제약/트리거/권한은 별도
#
#  APPEND 와 병렬에 대하여 — 흔히 틀리는 지점
#  ---------------------------------------------------------------------------
#    INSERT /*+ APPEND */ 는 다이렉트 패스라 테이블 세그먼트에 배타 락을 건다.
#    따라서 DBMS_PARALLEL_EXECUTE 로 청크를 여러 세션이 동시에 밀어 넣으면
#    서로 락에 걸려 직렬화되거나 실패한다. 둘은 같이 쓸 수 없다.
#      단일 세션 모드 -> APPEND 사용 (빠름, 테이블 락)
#      청크 병렬 모드 -> APPEND 제외 (일반 경로, 동시 실행 가능)
#    이 스크립트는 모드에 따라 힌트를 자동으로 바꾼다.
# ==============================================================================
generate_dblink_copy_scripts() {
    # [v09.02] local 제거 (ksh 비호환): _dl_tbl _dl_hint _dl_mode_desc
    DL_PRE_SQL="dblink_0_precheck_${UNIQUE_ID}.sql"
    DL_COPY_SQL="dblink_1_copy_${UNIQUE_ID}.sql"
    DL_COPY_SH="dblink_1_copy_${UNIQUE_ID}.sh"
    DL_VERIFY_SQL="dblink_9_verify_${UNIQUE_ID}.sql"
    DL_VERIFY_SH="dblink_9_verify_${UNIQUE_ID}.sh"

    if [ "$DL_PARALLEL_MODE" = "CHUNK" ]; then
        _dl_hint=""
        _dl_mode_desc="청크 병렬 (DBMS_PARALLEL_EXECUTE, APPEND 미사용)"
    else
        _dl_hint="/*+ APPEND */ "
        _dl_mode_desc="단일 세션 (INSERT /*+ APPEND */)"
    fi

    # ---------------- 0) 사전 점검 ----------------
    echo "  * 생성 중: $DL_PRE_SQL (LONG/LOB 및 대상 존재 점검)"
    cat <<EOF > "$DL_PRE_SQL"
-- ==============================================================================
--  DB Link COPY Step 0 : 사전 점검
--  Job ID : ${UNIQUE_ID} / Link : ${DL_LINK_NAME}
--  이 단계에서 FAIL 이 나오면 해당 테이블은 DB Link 방식으로 옮길 수 없습니다.
-- ==============================================================================
SET SERVEROUTPUT ON SIZE UNLIMITED LINESIZE 200 PAGESIZE 100 FEEDBACK OFF
WHENEVER SQLERROR CONTINUE
SPOOL dblink_0_precheck_${UNIQUE_ID}.log

${PDB_SWITCH_SQL}

PROMPT ========================================================================
PROMPT 1. DB Link 도달성
PROMPT ========================================================================
DECLARE v VARCHAR2(30);
BEGIN
  SELECT 'LINK OK' INTO v FROM dual@${DL_LINK_NAME};
  DBMS_OUTPUT.PUT_LINE('  ${DL_LINK_NAME} : ' || v);
EXCEPTION WHEN OTHERS THEN
  DBMS_OUTPUT.PUT_LINE('  ${DL_LINK_NAME} : *** ' || SUBSTR(SQLERRM,1,120));
  RAISE_APPLICATION_ERROR(-20910, 'DB Link 접속 실패 - 이후 단계를 진행할 수 없습니다.');
END;
/

PROMPT
PROMPT ========================================================================
PROMPT 2. LONG / LONG RAW 검출 (DB Link 로 이동 불가)
PROMPT ========================================================================
DECLARE n NUMBER := 0;
BEGIN
  FOR r IN (SELECT owner, table_name, column_name, data_type
              FROM dba_tab_columns@${DL_LINK_NAME}
             WHERE data_type IN ('LONG','LONG RAW')
               AND owner IN (${DL_OWNER_IN})) LOOP
    DBMS_OUTPUT.PUT_LINE('  *** ' || r.owner || '.' || r.table_name ||
                         '.' || r.column_name || ' (' || r.data_type || ')');
    n := n + 1;
  END LOOP;
  IF n > 0 THEN
    DBMS_OUTPUT.PUT_LINE('  ------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('  [FAIL] LONG/LONG RAW ' || n || ' 개. 해당 테이블은 Data Pump 로 옮기십시오.');
  ELSE
    DBMS_OUTPUT.PUT_LINE('  LONG / LONG RAW 없음.');
  END IF;
END;
/

PROMPT
PROMPT ========================================================================
PROMPT 3. LOB 컬럼 (이동은 되지만 느립니다)
PROMPT ========================================================================
SELECT owner, table_name, COUNT(*) AS lob_cols
  FROM dba_tab_columns@${DL_LINK_NAME}
 WHERE data_type IN ('CLOB','NCLOB','BLOB')
   AND owner IN (${DL_OWNER_IN})
 GROUP BY owner, table_name ORDER BY 3 DESC;

PROMPT
PROMPT ========================================================================
PROMPT 4. 대상 테이블 존재 여부 (로컬에 먼저 DDL 이 있어야 합니다)
PROMPT ========================================================================
DECLARE n NUMBER; miss NUMBER := 0;
BEGIN
  FOR r IN (SELECT owner, table_name FROM dba_tables@${DL_LINK_NAME}
             WHERE owner IN (${DL_OWNER_IN})) LOOP
    SELECT COUNT(*) INTO n FROM dba_tables
     WHERE owner = r.owner AND table_name = r.table_name;
    IF n = 0 THEN
      DBMS_OUTPUT.PUT_LINE('  *** 로컬에 없음: ' || r.owner || '.' || r.table_name);
      miss := miss + 1;
    END IF;
  END LOOP;
  IF miss > 0 THEN
    DBMS_OUTPUT.PUT_LINE('  ------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('  [FAIL] ' || miss || ' 개 테이블이 로컬에 없습니다.');
    DBMS_OUTPUT.PUT_LINE('         impdp SQLFILE 로 DDL 을 먼저 적용하십시오.');
  ELSE
    DBMS_OUTPUT.PUT_LINE('  대상 테이블 전부 존재합니다.');
  END IF;
END;
/

SPOOL OFF
EXIT;
EOF

    # ---------------- 1) 복사 ----------------
    echo "  * 생성 중: $DL_COPY_SQL (${_dl_mode_desc})"
    if [ "$DL_PARALLEL_MODE" = "CHUNK" ]; then
        cat <<EOF > "$DL_COPY_SQL"
-- ==============================================================================
--  DB Link COPY Step 1 : 청크 병렬 복사
--  Job ID : ${UNIQUE_ID} / Link : ${DL_LINK_NAME}
--
--  DBMS_PARALLEL_EXECUTE 로 ${DL_CHUNK_COL} 범위를 ${DL_CHUNKS} 등분해
--  ${DL_PDEG} 개 세션이 동시에 적재합니다.
--
--  [중요] 이 모드에서는 INSERT 에 APPEND 힌트를 쓰지 않습니다.
--         APPEND 는 다이렉트 패스라 테이블에 배타 락을 걸어, 여러 세션이
--         같은 테이블에 동시에 넣으면 서로 막힙니다. 일반 경로로 넣습니다.
-- ==============================================================================
SET SERVEROUTPUT ON SIZE UNLIMITED FEEDBACK ON
WHENEVER SQLERROR CONTINUE
SPOOL dblink_1_copy_${UNIQUE_ID}.log

${PDB_SWITCH_SQL}

DECLARE
  v_task  VARCHAR2(128);
  v_sql   VARCHAR2(4000);
  v_chunk VARCHAR2(4000);
  v_st    NUMBER;
BEGIN
  FOR t IN (SELECT owner, table_name FROM dba_tables
             WHERE owner IN (${DL_OWNER_IN})
               AND table_name IN (${DL_TABLE_IN})
             ORDER BY owner, table_name) LOOP

    v_task := 'DLCOPY_${UNIQUE_ID}_' || t.table_name;
    BEGIN DBMS_PARALLEL_EXECUTE.DROP_TASK(v_task); EXCEPTION WHEN OTHERS THEN NULL; END;
    DBMS_PARALLEL_EXECUTE.CREATE_TASK(v_task);

    -- 원격 테이블의 ${DL_CHUNK_COL} 값을 ${DL_CHUNKS} 구간으로 나눈다.
    v_chunk := 'SELECT MIN(c) AS start_id, MAX(c) AS end_id FROM ('
            || '  SELECT ${DL_CHUNK_COL} c, NTILE(${DL_CHUNKS}) OVER (ORDER BY ${DL_CHUNK_COL}) g'
            || '    FROM "' || t.owner || '"."' || t.table_name || '"@${DL_LINK_NAME}'
            || ') GROUP BY g';
    DBMS_PARALLEL_EXECUTE.CREATE_CHUNKS_BY_SQL(v_task, v_chunk, false);

    v_sql := 'INSERT INTO "' || t.owner || '"."' || t.table_name || '" '
          || 'SELECT * FROM "' || t.owner || '"."' || t.table_name || '"@${DL_LINK_NAME}'
          || ' WHERE ${DL_CHUNK_COL} BETWEEN :start_id AND :end_id${DL_WHERE_EXTRA}';

    DBMS_PARALLEL_EXECUTE.RUN_TASK(v_task, v_sql, DBMS_SQL.NATIVE,
                                   parallel_level => ${DL_PDEG});

    v_st := DBMS_PARALLEL_EXECUTE.TASK_STATUS(v_task);
    DBMS_OUTPUT.PUT_LINE(RPAD(t.owner || '.' || t.table_name, 50) ||
      CASE v_st WHEN DBMS_PARALLEL_EXECUTE.FINISHED THEN ' : OK'
                ELSE ' : *** status=' || v_st || ' (user_parallel_execute_chunks 확인)' END);
    COMMIT;
  END LOOP;
END;
/

SPOOL OFF
EXIT;
EOF
    else
        cat <<EOF > "$DL_COPY_SQL"
-- ==============================================================================
--  DB Link COPY Step 1 : 단일 세션 복사 (INSERT /*+ APPEND */)
--  Job ID : ${UNIQUE_ID} / Link : ${DL_LINK_NAME}
--
--  APPEND 는 다이렉트 패스라 빠르지만 테이블에 배타 락을 겁니다.
--  같은 테이블에 다른 세션이 동시에 쓰고 있으면 안 됩니다.
--  각 테이블마다 COMMIT 하므로 중간에 멈춰도 완료된 테이블은 유지됩니다.
-- ==============================================================================
SET SERVEROUTPUT ON SIZE UNLIMITED FEEDBACK ON
WHENEVER SQLERROR CONTINUE
SPOOL dblink_1_copy_${UNIQUE_ID}.log

${PDB_SWITCH_SQL}
ALTER SESSION ENABLE PARALLEL DML;

DECLARE
  v_sql VARCHAR2(4000);
  v_n   NUMBER;
  v_ok  NUMBER := 0;
  v_ng  NUMBER := 0;
BEGIN
  FOR t IN (SELECT owner, table_name FROM dba_tables
             WHERE owner IN (${DL_OWNER_IN})
               AND table_name IN (${DL_TABLE_IN})
             ORDER BY owner, table_name) LOOP
    BEGIN
      v_sql := 'INSERT ${_dl_hint}INTO "' || t.owner || '"."' || t.table_name || '" '
            || 'SELECT * FROM "' || t.owner || '"."' || t.table_name || '"@${DL_LINK_NAME}'
            || '${DL_WHERE_CLAUSE}';
      EXECUTE IMMEDIATE v_sql;
      v_n := SQL%ROWCOUNT;
      COMMIT;
      DBMS_OUTPUT.PUT_LINE(RPAD(t.owner || '.' || t.table_name, 50) || ' : ' || v_n || ' rows');
      v_ok := v_ok + 1;
    EXCEPTION WHEN OTHERS THEN
      ROLLBACK;
      DBMS_OUTPUT.PUT_LINE(RPAD(t.owner || '.' || t.table_name, 50) ||
                           ' : *** ' || SUBSTR(SQLERRM,1,120));
      v_ng := v_ng + 1;
    END;
  END LOOP;

  DBMS_OUTPUT.PUT_LINE('  ------------------------------------------------------');
  DBMS_OUTPUT.PUT_LINE('  성공 ' || v_ok || ' / 실패 ' || v_ng);
  IF v_ng > 0 THEN
    RAISE_APPLICATION_ERROR(-20911, 'DB Link 복사 실패 ' || v_ng || ' 건');
  END IF;
END;
/

SPOOL OFF
EXIT;
EOF
    fi

    # ---------------- 9) 검증 ----------------
    echo "  * 생성 중: $DL_VERIFY_SQL (원격/로컬 건수 대조)"
    cat <<EOF > "$DL_VERIFY_SQL"
-- ==============================================================================
--  DB Link COPY Step 9 : 건수 대조
--  원격(ASIS)과 로컬(TOBE)의 건수를 같은 조건으로 비교합니다.
--  값까지 확인하려면 메뉴 7-4 HASH VERIFY 를 사용하십시오.
-- ==============================================================================
SET SERVEROUTPUT ON SIZE UNLIMITED LINESIZE 200 FEEDBACK OFF
WHENEVER SQLERROR CONTINUE
SPOOL dblink_9_verify_${UNIQUE_ID}.log

${PDB_SWITCH_SQL}

DECLARE
  v_r NUMBER; v_l NUMBER; v_bad NUMBER := 0; v_tot NUMBER := 0;
BEGIN
  DBMS_OUTPUT.PUT_LINE(RPAD('TABLE',46) || RPAD('REMOTE',14) || RPAD('LOCAL',14) || 'STATUS');
  DBMS_OUTPUT.PUT_LINE(RPAD('-',86,'-'));
  FOR t IN (SELECT owner, table_name FROM dba_tables
             WHERE owner IN (${DL_OWNER_IN})
               AND table_name IN (${DL_TABLE_IN})
             ORDER BY owner, table_name) LOOP
    v_tot := v_tot + 1;
    BEGIN
      EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM "' || t.owner || '"."' || t.table_name ||
                        '"@${DL_LINK_NAME}${DL_WHERE_CLAUSE}' INTO v_r;
      EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM "' || t.owner || '"."' || t.table_name ||
                        '"${DL_WHERE_CLAUSE}' INTO v_l;
      DBMS_OUTPUT.PUT_LINE(RPAD(t.owner || '.' || t.table_name, 46) ||
        RPAD(TO_CHAR(v_r), 14) || RPAD(TO_CHAR(v_l), 14) ||
        CASE WHEN v_r = v_l THEN 'MATCH' ELSE '*** MISMATCH' END);
      IF v_r <> v_l THEN v_bad := v_bad + 1; END IF;
    EXCEPTION WHEN OTHERS THEN
      DBMS_OUTPUT.PUT_LINE(RPAD(t.owner || '.' || t.table_name, 46) || '*** ' || SUBSTR(SQLERRM,1,80));
      v_bad := v_bad + 1;
    END;
  END LOOP;
  DBMS_OUTPUT.PUT_LINE(RPAD('-',86,'-'));
  IF v_bad = 0 THEN
    DBMS_OUTPUT.PUT_LINE('  RESULT: PASS  (' || v_tot || ' 개 테이블 건수 일치)');
  ELSE
    DBMS_OUTPUT.PUT_LINE('  RESULT: FAIL  (' || v_bad || ' / ' || v_tot || ' 불일치)');
  END IF;
END;
/

SPOOL OFF
EXIT;
EOF

    for _pair in "$DL_COPY_SH:$DL_COPY_SQL:DB Link 데이터 복사" \
                 "$DL_VERIFY_SH:$DL_VERIFY_SQL:DB Link 복사 결과 건수 대조"; do
        _sh=$(echo "$_pair" | cut -d: -f1)
        _sq=$(echo "$_pair" | cut -d: -f2)
        _ti=$(echo "$_pair" | cut -d: -f3)
        cat <<EOF > "$_sh"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
echo ">> ${_ti} 를 실행합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@${_sq}
CONNECT_EOF
echo ">> 완료."
EOF
        chmod 700 "$_sh"
    done
    return 0
}

# ------------------------------------------------------------------------------
# [NEW v09.00] DB Link 데이터 이관 모드 (메뉴 2 -> Import 방식 3)
# ------------------------------------------------------------------------------
run_dblink_copy_mode() {
    # [v09.02] local 제거 (ksh 비호환): _dl_raw _dl_scope _dl_where_esc
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [2-3] SQL over DB Link : Data-only copy"
    else echo " [2-3] SQL over DB Link : 데이터만 복사 (메타데이터 제외)"; fi
    echo "======================================================================"
    echo "  이 방식은 데이터만 옮깁니다. 인덱스 · 제약 · 트리거 · 권한 · 통계는"
    echo "  옮기지 않으므로, impdp SQLFILE 로 DDL 을 먼저 적용해 두어야 합니다."
    echo "  증분 캐치업(대량 적재 후 변경분 따라잡기)에 특히 유용합니다."
    echo "======================================================================"

    if [ "$LANG_PREF" = "EN" ]; then printf "  Database Link 이름 [기본값: MIG_LINK]: "
    else printf "  사용할 Database Link 이름 [기본값: MIG_LINK]: "; fi
    _read DL_LINK_NAME
    [ -z "$DL_LINK_NAME" ] && DL_LINK_NAME="MIG_LINK"
    DL_LINK_NAME=$(echo "$DL_LINK_NAME" | tr 'a-z' 'A-Z')

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  대상 스키마 (쉼표 구분, 예: HR,SCOTT): "
    else printf "  대상 스키마를 입력하세요 (쉼표 구분, 예: HR,SCOTT): "; fi
    _read dl_owners
    dl_owners=$(normalize_list "$dl_owners")
    if [ -z "$dl_owners" ]; then
        echo "  [오류] 대상 스키마가 필요합니다."
        return 1
    fi
    DL_OWNER_IN=$(echo "$dl_owners" | sed "s/[^,]*/'&'/g" | tr 'a-z' 'A-Z')

    if [ "$LANG_PREF" = "EN" ]; then printf "  대상 테이블 (쉼표 구분, 전체는 엔터): "
    else printf "  대상 테이블을 지정하세요 (쉼표 구분, 스키마 전체는 엔터): "; fi
    _read dl_tables
    dl_tables=$(normalize_list "$dl_tables")
    if [ -z "$dl_tables" ]; then
        DL_TABLE_IN="SELECT table_name FROM dba_tables WHERE owner IN (${DL_OWNER_IN})"
        _dl_scope="스키마 전체"
    else
        DL_TABLE_IN=$(echo "$dl_tables" | sed "s/[^,]*/'&'/g" | tr 'a-z' 'A-Z')
        _dl_scope="지정 테이블 ${dl_tables}"
    fi

    # ------------------------------------------------------------------
    # 증분 조건
    # ------------------------------------------------------------------
    echo "----------------------------------------------------------------------"
    echo "  [복사 범위]"
    echo "   1) 전체 복사"
    echo "   2) 증분 — WHERE 조건 지정 (예: LAST_UPD >= TO_DATE('20260101','YYYYMMDD'))"
    if [ "$LANG_PREF" = "EN" ]; then printf "  선택 (1-2) [기본값: 1]: "
    else printf "  선택 (1-2) [기본값: 1]: "; fi
    _read dl_incr_opt
    DL_WHERE_CLAUSE=""
    DL_WHERE_EXTRA=""
    if [ "$dl_incr_opt" = "2" ]; then
        if [ "$LANG_PREF" = "EN" ]; then printf "  WHERE 조건 (WHERE 는 빼고 조건만): "
        else printf "  WHERE 조건을 입력하세요 (WHERE 키워드 없이 조건만): "; fi
        _read dl_where
        if [ -n "$dl_where" ]; then
            # [중요] 이 조건문은 생성될 PL/SQL 안에서 "문자열 리터럴" 로 들어간다.
            #   사용자가 TO_DATE('20260101','YYYYMMDD') 처럼 작은따옴표를 쓰면
            #   리터럴이 거기서 끊겨 컴파일 에러가 난다. 미리 두 번으로 늘린다.
            _dl_where_esc=$(printf '%s' "$dl_where" | sed "s/'/''/g")
            DL_WHERE_CLAUSE=" WHERE ${_dl_where_esc}"
            DL_WHERE_EXTRA=" AND (${_dl_where_esc})"
            echo "  >> 증분 조건: ${dl_where}"
            echo "     [주의] 모든 대상 테이블에 같은 조건이 적용됩니다."
            echo "            해당 컬럼이 없는 테이블은 실패로 기록됩니다."
        fi
    fi

    # ------------------------------------------------------------------
    # 병렬 방식
    # ------------------------------------------------------------------
    echo "----------------------------------------------------------------------"
    echo "  [적재 방식]"
    echo "   1) 단일 세션 INSERT /*+ APPEND */   - 빠름. 테이블에 배타 락"
    echo "   2) 청크 병렬 (DBMS_PARALLEL_EXECUTE) - 여러 세션 동시. APPEND 미사용"
    echo ""
    echo "   APPEND 는 다이렉트 패스라 테이블 전체에 배타 락을 겁니다. 그래서"
    echo "   청크를 여러 세션이 동시에 밀어 넣는 2번과는 함께 쓸 수 없습니다."
    echo "   2번을 고르면 APPEND 를 빼고 일반 경로로 넣습니다."
    if [ "$LANG_PREF" = "EN" ]; then printf "  선택 (1-2) [기본값: 1]: "
    else printf "  선택 (1-2) [기본값: 1]: "; fi
    _read dl_par_opt
    if [ "$dl_par_opt" = "2" ]; then
        DL_PARALLEL_MODE="CHUNK"
        if [ "$LANG_PREF" = "EN" ]; then printf "  청크 분할 기준 숫자/날짜 컬럼 (예: ID): "
        else printf "  청크 분할 기준 컬럼 (모든 대상에 공통으로 있어야 함, 예: ID): "; fi
        _read DL_CHUNK_COL
        if [ -z "$DL_CHUNK_COL" ]; then
            echo "  [오류] 청크 병렬에는 분할 기준 컬럼이 필요합니다."
            return 1
        fi
        DL_CHUNK_COL=$(echo "$DL_CHUNK_COL" | tr 'a-z' 'A-Z')
        printf "  청크 개수 [기본값: 16]: "
        _read DL_CHUNKS
        echo "$DL_CHUNKS" | grep -qE '^[0-9]+$' || DL_CHUNKS=16
        printf "  동시 실행 세션 수 [기본값: 4]: "
        _read DL_PDEG
        echo "$DL_PDEG" | grep -qE '^[0-9]+$' || DL_PDEG=4
    else
        DL_PARALLEL_MODE="SINGLE"
        DL_CHUNK_COL=""
        DL_CHUNKS=0
        DL_PDEG=1
    fi

    DATE_STR=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$")
    if [ -z "$UNIQUE_ID" ]; then UNIQUE_ID="DLCOPY_${DATE_STR}"; fi

    echo "----------------------------------------------------------------------"
    generate_dblink_copy_scripts || return 1

    echo "======================================================================"
    echo "  >> DB Link 데이터 이관 스크립트 생성 완료"
    echo "======================================================================"
    echo "  대상        : ${_dl_scope} (스키마 ${dl_owners})"
    echo "  DB Link     : ${DL_LINK_NAME}"
    if [ "$DL_PARALLEL_MODE" = "CHUNK" ]; then
        echo "  적재 방식   : 청크 병렬 (${DL_CHUNK_COL} 기준 ${DL_CHUNKS} 청크 / ${DL_PDEG} 세션)"
    else
        echo "  적재 방식   : 단일 세션 INSERT /*+ APPEND */"
    fi
    [ -n "$DL_WHERE_CLAUSE" ] && echo "  증분 조건   :${DL_WHERE_CLAUSE}"
    echo "----------------------------------------------------------------------"
    echo "  [실행 순서]"
    echo "   1) sqlplus <conn> @${DL_PRE_SQL}      (사전 점검 - 반드시 먼저)"
    echo "   2) impdp SQLFILE 로 DDL 적용          (대상 테이블이 없다면)"
    echo "   3) bash ${DL_COPY_SH}"
    echo "   4) bash ${DL_VERIFY_SH}"
    echo "   5) 메뉴 7-4 HASH VERIFY 로 값까지 대조 (권장)"
    echo "======================================================================"
    return 0
}

run_target_mode() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _fi _lf _src_ts_list _sts
    # [FIX v07/B2] 재진입 시 이전 실행 잔여 상태 제거 (v06 의 누적 실행 버그 수정)
    reset_generation_state
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [2] TARGET SERVER: Check Resources & Generate impdp Scripts"
    else echo " [2] TARGET SERVER: 리소스 점검 및 impdp 스크립트 생성"; fi
    echo "======================================================================"
    
    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE"
    echo "  * CPU Cores: $CPU_CORES"
    echo "  * Memory: $MEM_SIZE"
    echo "----------------------------------------------------------------------"
    
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Oracle connection account [Default: / as sysdba]: "
    else printf "  Oracle 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info
    calculate_parallel_degree

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Unique Migration ID (UNIQUE_ID) to identify this job: "
    else printf "  이 작업의 고유 이관 ID(UNIQUE_ID)를 입력하세요 (Source에서 생성한 ID와 동일): "; fi
    _read user_id
    if [ -z "$user_id" ]; then
        echo "  [오류/ERROR] UNIQUE_ID is required."
        return 1
    fi
    UNIQUE_ID=$(echo "$user_id" | tr ' ' '_')

    # Target PDB 신규 생성 모듈 (23c / 19c CDB 환경 지원)
    generate_target_pdb_ddl

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [Select Import Method]"
        echo "  1) Dump File Import (Requires Source Dump Files)"
        echo "  2) NETWORK_LINK Direct Import (No dump files, uses DB Link)"
        echo "  3) SQL over DB Link (Data only - for incremental catch-up)  [NEW]"
        printf "  Select (1-3) [Default: 1]: "
    else
        echo "  [Import 방식 선택]"
        echo "  1) Dump File 기반 복원 (Source의 Dump 파일 필요)"
        echo "  2) NETWORK_LINK 기반 Direct 복원 (Dump 파일 불필요, DB Link 연동)"
        echo "  3) SQL over DB Link (데이터만 - 증분 캐치업용)              [신규]"
        printf "  선택 (1-3) [기본값: 1]: "
    fi
    _read imp_method_opt
    if [ "$imp_method_opt" = "3" ]; then
        # [NEW v09.00] 순수 SQL over DB Link — Data Pump 흐름을 타지 않는
        #   독립 경로이므로 여기서 처리하고 돌아간다.
        run_dblink_copy_mode
        return $?
    elif [ "$imp_method_opt" = "2" ]; then
        IMPORT_METHOD="NETWORK_LINK"
    else
        IMPORT_METHOD="DUMP"
    fi

    setup_db_directory || return 1

    # [NEW v07] Target 측 사전 요구사항 검증 (바이너리/디렉토리 권한/문자셋)
    run_preflight_checks "TARGET" || return 1
    flush_preflight_csv

    if [ "$IMPORT_METHOD" = "NETWORK_LINK" ]; then
        echo "----------------------------------------------------------------------"
        if [ "$LANG_PREF" = "EN" ]; then echo "  [NETWORK_LINK Setup]"
        else echo "  [NETWORK_LINK 설정 (Database Link)]"; fi
        
        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Database Link Name to use or create [Default: MIG_LINK]: "
        else printf "  사용하거나 새로 생성할 Database Link 이름을 입력하세요 [기본값: MIG_LINK]: "; fi
        _read DBLINK_NAME
        [ -z "$DBLINK_NAME" ] && DBLINK_NAME="MIG_LINK"
        DBLINK_NAME=$(echo "$DBLINK_NAME" | tr 'a-z' 'A-Z')

        if [ "$MOCK_MODE" != "true" ]; then
            link_cnt=$(sqlplus -S /nolog <<EOF
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0
$PDB_SWITCH_SQL
SELECT COUNT(*) FROM dba_db_links WHERE db_link = '$DBLINK_NAME';
EXIT;
EOF
)
            link_cnt=$(to_num "$link_cnt")
            if [ "$link_cnt" -eq 0 ]; then
                if [ "$LANG_PREF" = "EN" ]; then echo "  >> DB Link '$DBLINK_NAME' not found. Let's create it."
                else echo "  >> Target DB에 DB Link '$DBLINK_NAME'가 존재하지 않습니다. 생성을 진행합니다."; fi
                printf "  - Source DB Username (e.g. SYSTEM): "; _read src_user
                printf "  - Source DB Password (input hidden / 입력 숨김): "
                _read_secret src_pwd MIG_DBLINK_PASSWORD
                printf "  - Source DB TNS Alias or IP:PORT/SERVICE_NAME: "; _read src_tns

                # [v09.02] 위와 동일한 공통 경로를 쓴다 (복붙 제거).
                if ! create_dblink_live "$DBLINK_NAME" "$src_user" "$src_pwd" "$src_tns"; then
                    if [ "$LANG_PREF" = "EN" ]; then
                        echo "  >> NETWORK_LINK import cannot proceed without the DB Link."
                    else
                        echo "  >> DB Link 없이는 NETWORK_LINK 임포트를 진행할 수 없습니다."
                    fi
                    return 1
                fi
            else
                if [ "$LANG_PREF" = "EN" ]; then echo "  >> DB Link '$DBLINK_NAME' exists. We will use it."
                else echo "  >> 기존에 존재하는 DB Link '$DBLINK_NAME'를 사용합니다."; fi
            fi
        fi
    fi

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [Select Migration Mode]"
        echo "  1) SCHEMA Recovery Mode"
        echo "  2) TABLE Recovery Mode"
        echo "  3) TABLESPACE Recovery Mode"
        echo "  4) FULL Recovery Mode"
        printf "  Select (1-4): "
    else
        echo "  [선택] 어떠한 모드로 마이그레이션을 진행하십니까?"
        echo "  1) SCHEMA 모드 복구"
        echo "  2) TABLE 모드 복구"
        echo "  3) TABLESPACE 모드 복구"
        echo "  4) FULL 모드 복구"
        printf "  입력 (1-4): "
    fi
    _read mig_mode
    case "$mig_mode" in
        1) MIG_TYPE="SCHEMA" ;;
        2) MIG_TYPE="TABLE" ;;
        3) MIG_TYPE="TABLESPACE" ;;
        4) MIG_TYPE="FULL"; MIG_PARAMS="FULL=Y" ;;
        *) echo "  [오류/ERROR] Invalid selection."; return 1 ;;
    esac

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "  [Pre-Check Conflicts & Select Target List]"
    else echo "  [사전 충돌 검증 및 대상 목록 선택]"; fi
    
    if [ "$IMPORT_METHOD" = "DUMP" ]; then
        DUMP_FILES=$(ls "${DIR_PHYSICAL_PATH}"/${UNIQUE_ID}*.dmp 2>/dev/null)
        DUMP_EXISTS=$(echo "$DUMP_FILES" | grep -c "\.dmp$")
        if [ "$DUMP_EXISTS" -eq 0 ]; then
            if [ "$LANG_PREF" = "EN" ]; then
                echo "  [WARNING] No dump files matching ${UNIQUE_ID} found in ${DIR_PHYSICAL_PATH}."
                printf "  Ignore and proceed manually? (y/n): "
            else
                echo "  [경고] 디렉토리(${DIR_PHYSICAL_PATH})에 ${UNIQUE_ID} 덤프 파일이 없습니다."
                printf "  무시하고 수동으로 진행하시겠습니까? (y/n): "
            fi
            _read force_cont
            if [ "$force_cont" != "y" ] && [ "$force_cont" != "Y" ]; then return 1; fi
        else
            if [ "$LANG_PREF" = "EN" ]; then echo "  >> Dump files verified ($DUMP_EXISTS detected)"
            else echo "  >> Dump 파일 확인 완료 ($DUMP_EXISTS 개 감지)"; fi
            ls -1 "${DIR_PHYSICAL_PATH}"/${UNIQUE_ID}*.dmp 2>/dev/null | while read -r df; do
                echo "     - $(basename "$df")"
            done
        fi
    fi

    FINAL_LIST=""
    REMAP_PARAMS=""
    TABLE_EXISTS_ACTION_PARAM=""
    NEEDS_TEA="false"

    if [ "$MIG_TYPE" = "FULL" ]; then
        if [ "$LANG_PREF" = "EN" ]; then
            echo "  [INFO] Skipping pre-check for FULL mode."
            printf "  Select TABLE_EXISTS_ACTION (1: SKIP, 2: APPEND, 3: TRUNCATE, 4: REPLACE) [Default: 1]: "
        else
            echo "  [안내] FULL 모드는 전체 DB를 대상으로 하므로, 상세 객체 단위의 충돌 사전 검증 표 출력을 생략합니다."
            printf "  기존 개체 존재 시 처리 정책(TABLE_EXISTS_ACTION)을 선택하세요.\n  (1: SKIP, 2: APPEND, 3: TRUNCATE, 4: REPLACE) [기본값: 1]: "
        fi
        _read tea_opt
        case "$tea_opt" in
            2) TABLE_EXISTS_ACTION_PARAM="TABLE_EXISTS_ACTION=APPEND" ;;
            3) TABLE_EXISTS_ACTION_PARAM="TABLE_EXISTS_ACTION=TRUNCATE" ;;
            4) TABLE_EXISTS_ACTION_PARAM="TABLE_EXISTS_ACTION=REPLACE" ;;
            *) TABLE_EXISTS_ACTION_PARAM="TABLE_EXISTS_ACTION=SKIP" ;;
        esac
    else
        CANDIDATES_FILE="$(tmpf candidates.tmp)"
        : > "$CANDIDATES_FILE"
        
        if [ "$IMPORT_METHOD" = "DUMP" ]; then
            # [FIX v07/R3] ls|grep 대신 글롭 순회로 안전하게 목록 구성
            # [FIX v08.02] 공백이 포함된 경로 대응.
            #   v08.01 까지는 파일 목록을 공백으로 이어붙인 뒤 `cat $LOG_FILES` 로 썼기
            #   때문에 DIR_PHYSICAL_PATH 에 공백이 있으면(예: /backup/my dumps)
            #   경로가 단어 단위로 찢어져 검증 로직이 통째로 마비되었다.
            #   목록을 개행 구분 파일에 담고 한 건씩 처리해 공백에 영향받지 않게 한다.
            LOG_LIST_FILE="$(tmpf log_list.tmp)"
            : > "$LOG_LIST_FILE"
            for _lf in "${DIR_PHYSICAL_PATH}"/${UNIQUE_ID}*expdp*.log; do
                [ -e "$_lf" ] || continue
                case "$_lf" in
                    *_meta_custom*|*_estimate_*|*_stats_*) continue ;;
                esac
                printf '%s\n' "$_lf" >> "$LOG_LIST_FILE"
            done
            if [ -s "$LOG_LIST_FILE" ]; then
                if [ "$LANG_PREF" = "EN" ]; then echo "  >> Analyzing log files to extract migration targets..."
                else echo "  >> 로그 파일을 모두 분석하여 이관 내역을 추출합니다..."; fi

                if [ "$MIG_TYPE" = "SCHEMA" ]; then
                    while IFS= read -r _lf; do
                        [ -n "$_lf" ] || continue
                        awk '/\.\ \.\ exported/ { line=$0; gsub(/"/, "", line); split(line, parts); for(i=1;i<=NF;i++) { if(parts[i]=="exported") { split(parts[i+1], obj, "."); print obj[1]; break; } } }' "$_lf"
                    done < "$LOG_LIST_FILE" | sort | uniq > "$CANDIDATES_FILE"
                elif [ "$MIG_TYPE" = "TABLE" ]; then
                    while IFS= read -r _lf; do
                        [ -n "$_lf" ] || continue
                        awk '/\.\ \.\ exported/ { line=$0; gsub(/"/, "", line); split(line, parts); for(i=1;i<=NF;i++) { if(parts[i]=="exported") { print parts[i+1]; break; } } }' "$_lf"
                    done < "$LOG_LIST_FILE" | sort | uniq > "$CANDIDATES_FILE"
                elif [ "$MIG_TYPE" = "TABLESPACE" ]; then
                    while IFS= read -r _lf; do
                        [ -n "$_lf" ] || continue
                        awk -F 'TABLESPACES=' '{if(NF>1) { split($2, a, " "); split(a[1], b, ","); for(i in b) print b[i]; }}' "$_lf"
                    done < "$LOG_LIST_FILE" | sort | uniq > "$CANDIDATES_FILE"
                fi
            fi
            
            if [ ! -s "$CANDIDATES_FILE" ]; then
                if [ "$LANG_PREF" = "EN" ]; then printf "  [WARNING] Target list could not be extracted. Enter targets manually (comma-separated): "
                else echo "  [경고] 로그 파일에서 대상을 찾지 못했습니다."; printf "  이관할 대상을 직접 입력하십시오 (쉼표 구분): "; fi
                _read manual_items
                normalize_list "$manual_items" | tr ',' '\n' > "$CANDIDATES_FILE"
            fi
        else
            if [ "$LANG_PREF" = "EN" ]; then printf "  Enter targets to migrate via DB Link (comma-separated): "
            else printf "  DB Link로 Pulling해 올 대상(Target)을 직접 입력하십시오 (쉼표 구분, 예: HR,SCOTT 또는 HR.EMP): "; fi
            _read manual_items
            normalize_list "$manual_items" | tr ',' '\n' > "$CANDIDATES_FILE"
        fi

        GLOBAL_OBJ_COLLISION=0
        if [ "$MIG_TYPE" = "TABLESPACE" ] && [ "$IMPORT_METHOD" = "DUMP" ] && [ "$MOCK_MODE" != "true" ]; then
            # [FIX v08.02] 공백 경로 대응 - 목록 파일을 한 건씩 awk 에 전달
            OBJ_LIST=$(while IFS= read -r _lf; do
                           [ -n "$_lf" ] || continue
                           awk '/\.\ \.\ exported/ { line=$0; gsub(/"/, "", line); split(line, parts); for(i=1;i<=NF;i++) { if(parts[i]=="exported") { print parts[i+1]; break; } } }' "$_lf"
                       done < "$LOG_LIST_FILE" 2>/dev/null | sort | uniq | awk -F'.' '{printf "(\047%s\047,\047%s\047)\n", $1, $2}' | paste -sd,)
            if [ -n "$OBJ_LIST" ]; then
                GLOBAL_OBJ_COLLISION=$(sqlplus -S /nolog <<EOF | tr -d ' ' | sed '/^$/d'
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 100
$PDB_SWITCH_SQL
SELECT COUNT(*) FROM dba_tables WHERE (owner, table_name) IN ($OBJ_LIST);
EXIT;
EOF
)
            fi
            [ -z "$GLOBAL_OBJ_COLLISION" ] && GLOBAL_OBJ_COLLISION=0
        fi

        TABLE_FILE="$(tmpf table_data.tmp)"
        : > "$TABLE_FILE"
        idx=1
        
        for item in $(cat "$CANDIDATES_FILE"); do
            conflict="false"
            conflict_detail=""
            if [ "$MIG_TYPE" = "SCHEMA" ]; then
                cnt=$(sqlplus -S /nolog <<EOF
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF
$PDB_SWITCH_SQL
SELECT COUNT(*) FROM dba_users WHERE username='$item';
EXIT;
EOF
)
                cnt=$(to_num "$cnt")
                if [ "$cnt" -gt 0 ]; then
                    conflict="true"
                    conflict_detail="User/Schema Exists"
                fi
            elif [ "$MIG_TYPE" = "TABLE" ]; then
                own_p=$(echo "$item" | cut -d'.' -f1); tab_p=$(echo "$item" | cut -d'.' -f2)
                cnt=$(sqlplus -S /nolog <<EOF
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF
$PDB_SWITCH_SQL
SELECT COUNT(*) FROM dba_tables WHERE owner='$own_p' AND table_name='$tab_p';
EXIT;
EOF
)
                cnt=$(to_num "$cnt")
                if [ "$cnt" -gt 0 ]; then
                    conflict="true"
                    conflict_detail="Table Exists"
                fi
            elif [ "$MIG_TYPE" = "TABLESPACE" ]; then
                if [ "$MOCK_MODE" = "true" ]; then
                    ts_cnt=1; tbl_cnt=2; sample_objs="TB_A,TB_B"; link_obj_coll=0
                else
                    res=$(sqlplus -S /nolog <<EOF
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 100 TRIMSPOOL ON
$PDB_SWITCH_SQL
SELECT 
    (SELECT COUNT(*) FROM dba_tablespaces WHERE tablespace_name = '$item') || '|' ||
    (SELECT COUNT(*) FROM dba_segments WHERE tablespace_name = '$item') || '|' ||
    (SELECT LISTAGG(segment_name, ',') WITHIN GROUP (ORDER BY segment_name) FROM (SELECT segment_name FROM dba_segments WHERE tablespace_name = '$item' AND ROWNUM <= 3))
FROM dual;
EXIT;
EOF
)
                    ts_cnt=$(echo "$res" | cut -d'|' -f1 | tr -d ' ' | sed '/^$/d')
                    tbl_cnt=$(echo "$res" | cut -d'|' -f2 | tr -d ' ' | sed '/^$/d')
                    sample_objs=$(echo "$res" | cut -d'|' -f3 | sed 's/^ *//g' | sed 's/ *$//g' | sed '/^$/d')
                    
                    [ -z "$ts_cnt" ] && ts_cnt=0
                    [ -z "$tbl_cnt" ] && tbl_cnt=0
                    [ -z "$sample_objs" ] && sample_objs="None"
                    
                    link_obj_coll=0
                    if [ "$IMPORT_METHOD" = "NETWORK_LINK" ] && [ "$MOCK_MODE" != "true" ]; then
                        link_obj_coll=$(sqlplus -S /nolog <<EOF | tr -d ' ' | sed '/^$/d'
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 100
$PDB_SWITCH_SQL
SELECT COUNT(*) FROM dba_tables t JOIN dba_tables@$DBLINK_NAME s ON t.owner=s.owner AND t.table_name=s.table_name WHERE s.tablespace_name='$item';
EXIT;
EOF
)
                    fi
                fi
                [ -z "$link_obj_coll" ] && link_obj_coll=0
                
                if [ "$ts_cnt" -gt 0 ]; then
                    if [ "$tbl_cnt" -gt 0 ]; then
                        conflict="true"
                        if [ "$tbl_cnt" -gt 3 ]; then
                            conflict_detail="Tablespace & ${tbl_cnt} Objects Exist (e.g. ${sample_objs}...)"
                        else
                            conflict_detail="Tablespace & ${tbl_cnt} Objects Exist (${sample_objs})"
                        fi
                    else
                        conflict="true"
                        conflict_detail="Tablespace Exists (Empty/0 Segments)"
                    fi
                else
                    if [ "$IMPORT_METHOD" = "DUMP" ] && [ "$GLOBAL_OBJ_COLLISION" -gt 0 ]; then
                        conflict="true"
                        conflict_detail="Tablespace New, but ${GLOBAL_OBJ_COLLISION} Dump Tables Exist in Target DB"
                    elif [ "$IMPORT_METHOD" = "NETWORK_LINK" ] && [ "$link_obj_coll" -gt 0 ]; then
                        conflict="true"
                        conflict_detail="Tablespace New, but ${link_obj_coll} Tables Already Exist in Target DB"
                    else
                        conflict="false"
                        conflict_detail="Clean (New Tablespace)"
                    fi
                fi
            fi
            
            echo "${idx}|${item}|${conflict}|${conflict_detail}" >> "$TABLE_FILE"
            idx=$((idx + 1))
        done
        rm -f "$CANDIDATES_FILE"

        echo "  ------------------------------------------------------------------------------------------------------------------"
        if [ "$LANG_PREF" = "EN" ]; then
            printf "  %4s | %-25s | %-12s | %-55s\n" "No." "Target Item" "Status" "Conflict Detail"
        else
            printf "  %4s | %-25s | %-12s | %-55s\n" "번호" "이관 대상 항목" "충돌 상태" "상세 충돌 내역"
        fi
        echo "  ------------------------------------------------------------------------------------------------------------------"
        
        while IFS='|' read -r t_idx t_item t_conf t_detail; do
            if [ "$t_conf" = "true" ]; then
                if [ "$LANG_PREF" = "EN" ]; then
                    printf "  %4s | %-25s | \033[33m%-12s\033[0m | %-55s\n" "$t_idx" "$t_item" "[CONFLICT]" "$t_detail"
                else
                    printf "  %4s | %-25s | \033[33m%-12s\033[0m | %-55s\n" "$t_idx" "$t_item" "[충돌 감지]" "$t_detail"
                fi
            else
                if [ "$LANG_PREF" = "EN" ]; then
                    printf "  %4s | %-25s | \033[32m%-12s\033[0m | %-55s\n" "$t_idx" "$t_item" "[CLEAN]" "No existing objects found"
                else
                    printf "  %4s | %-25s | \033[32m%-12s\033[0m | %-55s\n" "$t_idx" "$t_item" "[정상/신규]" "기존 대상 없음"
                fi
            fi
        done < "$TABLE_FILE"
        echo "  ------------------------------------------------------------------------------------------------------------------"

        total_cand=$(cat "$TABLE_FILE" | wc -l | awk '{$1=$1;print}')
        if [ "$LANG_PREF" = "EN" ]; then printf "  Select targets by number (Comma/Space e.g. 1,2, Range 2-5, or ALL) [Default: ALL]: "
        else printf "  복구할 대상을 선택하세요 (쉼표/공백 구분 예: 1,2, 범위: 2-5, 전체: ALL) [기본값: ALL]: "; fi
        _read user_picks
        [ -z "$user_picks" ] && user_picks="ALL"

        selected_items_list=""
        picks_upper=$(echo "$user_picks" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')
        
        if [ "$picks_upper" = "ALL" ]; then
            while IFS='|' read -r t_idx t_item t_conf t_detail; do
                [ -n "$selected_items_list" ] && selected_items_list="${selected_items_list},"
                selected_items_list="${selected_items_list}${t_item}"
            done < "$TABLE_FILE"
        else
            picks_cleaned=$(echo "$user_picks" | tr ',' ' ')
            for p in $picks_cleaned; do
                if echo "$p" | grep -qE '^[0-9]+-[0-9]+$'; then
                    p_start=$(echo "$p" | cut -d'-' -f1); p_end=$(echo "$p" | cut -d'-' -f2)
                    if [ "$p_start" -le "$p_end" ] && [ "$p_start" -ge 1 ] && [ "$p_end" -le "$total_cand" ]; then
                        pi=$p_start
                        while [ $pi -le $p_end ]; do
                            matched_item=$(grep "^${pi}|" "$TABLE_FILE" | cut -d'|' -f2)
                            if [ -n "$matched_item" ]; then
                                [ -n "$selected_items_list" ] && selected_items_list="${selected_items_list},"
                                selected_items_list="${selected_items_list}${matched_item}"
                            fi
                            pi=$((pi + 1))
                        done
                    fi
                elif echo "$p" | grep -qE '^[0-9]+$'; then
                    matched_item=$(grep "^${p}|" "$TABLE_FILE" | cut -d'|' -f2)
                    if [ -n "$matched_item" ]; then
                        [ -n "$selected_items_list" ] && selected_items_list="${selected_items_list},"
                        selected_items_list="${selected_items_list}${matched_item}"
                    fi
                fi
            done
        fi

        for itm in $(echo "$selected_items_list" | tr ',' '\n'); do
            rec=$(grep "|${itm}|" "$TABLE_FILE" | head -n 1)
            if [ -n "$rec" ]; then
                is_conf=$(echo "$rec" | cut -d'|' -f3)
                if [ "$is_conf" = "true" ]; then
                    echo ""
                    if [ "$LANG_PREF" = "EN" ]; then
                        echo "  [CONFLICT RESOLUTION] '$itm' already exists in Target DB!"
                        echo "  1) REMAP (Rename Target)"
                        echo "  2) OVERWRITE / APPEND (Use TABLE_EXISTS_ACTION)"
                        printf "  Select action for '$itm' (1-2) [Default: 2]: "
                    else
                        echo "  [충돌 해결] '$itm' 이(가) Target DB에 이미 존재합니다!"
                        echo "  1) 이름 변경 (REMAP 적용)"
                        echo "  2) 기존 객체에 덮어쓰기/추가 (TABLE_EXISTS_ACTION 적용)"
                        printf "  '$itm' 에 대한 조치 선택 (1-2) [기본값: 2]: "
                    fi
                    _read c_act
                    if [ "$c_act" = "1" ]; then
                        if [ "$LANG_PREF" = "EN" ]; then printf "     -> Enter new name for '$itm': "
                        else printf "     -> '$itm'을(를) 대체할 새로운 이름을 입력하세요: "; fi
                        _read new_name
                        if [ "$MIG_TYPE" = "SCHEMA" ]; then REMAP_PARAMS="$REMAP_PARAMS REMAP_SCHEMA=${itm}:${new_name}"
                        elif [ "$MIG_TYPE" = "TABLESPACE" ]; then REMAP_PARAMS="$REMAP_PARAMS REMAP_TABLESPACE=${itm}:${new_name}"
                        elif [ "$MIG_TYPE" = "TABLE" ]; then REMAP_PARAMS="$REMAP_PARAMS REMAP_TABLE=${itm}:${new_name}"
                        fi
                    else
                        NEEDS_TEA="true"
                    fi
                fi
                FINAL_LIST="${FINAL_LIST}${itm},"
            fi
        done
        rm -f "$TABLE_FILE"
        
        FINAL_LIST=$(echo "$FINAL_LIST" | sed 's/,$//')

        # [FIX v07/B1] v06 에서는 통계 Lock/Unlock SQL 이 정의되지 않은 $FINAL_IN_CLAUSE 를
        #              참조해 "... IN ()" 이 생성되어 ORA-00936 으로 실패했다.
        #              여기서 FINAL_LIST 를 SQL IN 절 형태('A','B')로 미리 만들어 둔다.
        FINAL_IN_CLAUSE=""
        IFS_BACKUP=$IFS; IFS=","
        for _fi in $FINAL_LIST; do
            _fi=$(echo "$_fi" | awk '{$1=$1;print}')
            if [ -n "$_fi" ]; then
                [ -n "$FINAL_IN_CLAUSE" ] && FINAL_IN_CLAUSE="${FINAL_IN_CLAUSE},"
                FINAL_IN_CLAUSE="${FINAL_IN_CLAUSE}'${_fi}'"
            fi
        done
        IFS=$IFS_BACKUP

        if [ -z "$FINAL_LIST" ]; then
            echo "  [오류/ERROR] 최종 선택된 이관 대상이 존재하지 않아 프로세스를 중단합니다."
            return 1
        fi

        if [ "$MIG_TYPE" = "SCHEMA" ]; then MIG_PARAMS="SCHEMAS=$FINAL_LIST"; fi
        if [ "$MIG_TYPE" = "TABLE" ]; then MIG_PARAMS="TABLES=$FINAL_LIST"; fi
        if [ "$MIG_TYPE" = "TABLESPACE" ]; then MIG_PARAMS="TABLESPACES=$FINAL_LIST"; fi

        # [NEW v08.05] 대상이 확정된 뒤 네트워크 모드 전용 점검을 수행한다.
        #   (LONG 컬럼 검사는 대상 목록이 있어야 의미가 있으므로 이 시점)
        if [ "$IMPORT_METHOD" = "NETWORK_LINK" ]; then
            _nl_owner_list="$FINAL_LIST"
            if [ "$MIG_TYPE" = "TABLE" ]; then
                _nl_owner_list=$(echo "$FINAL_LIST" | tr ',' '\n' | cut -d'.' -f1 | sort -u | tr '\n' ',' | sed 's/,$//')
            fi
            run_network_link_checks "$_nl_owner_list" || return 1
            flush_preflight_csv
        fi

        echo "----------------------------------------------------------------------"
        if [ "$LANG_PREF" = "EN" ]; then printf "  [Remap Options] Do you want to configure REMAP_SCHEMA or REMAP_TABLESPACE? (y/N): "
        else printf "  [REMAP 옵션] 스크립트에 REMAP_SCHEMA 또는 지능형 REMAP_TABLESPACE를 지정하시겠습니까? (y/N): "; fi
        _read add_remap_opt
        if [ "$add_remap_opt" = "y" ] || [ "$add_remap_opt" = "Y" ]; then
            if [ "$LANG_PREF" = "EN" ]; then printf "  - Enter REMAP_SCHEMA pairs (e.g. SRC_USER:TGT_USER,SRC2:TGT2 or empty to skip): "
            else printf "  - REMAP_SCHEMA 매핑 입력 (예: SRC_USER:TGT_USER 또는 미사용시 엔터): "; fi
            _read user_remap_sch
            if [ -n "$user_remap_sch" ]; then
                user_remap_sch_cleaned=$(echo "$user_remap_sch" | tr ',' ' ')
                for rpair in $user_remap_sch_cleaned; do
                    REMAP_PARAMS="$REMAP_PARAMS REMAP_SCHEMA=${rpair}"
                done
            fi
            
            echo "----------------------------------------------------------------------"
            if [ "$LANG_PREF" = "EN" ]; then echo "  [Intelligent Storage REMAP_TABLESPACE Wizard]"
            else echo "  [지능형 스토리지 REMAP_TABLESPACE 자동화 매핑]"; fi
            echo "   1) 단일 Target 테이블스페이스로 일괄 통합 매핑 (All-in-One Consolidation)"
            echo "   2) 용도별 자동 분기 매핑 (DATA* -> TS_DATA, IDX* -> TS_INDEX, LOB* -> TS_LOB)"
            echo "   3) 수동 직접 입력 (쉼표 구분, 예: SRC_TS:TGT_TS)"
            echo "   4) 테이블스페이스 REMAP 건너뛰기 (Skip)"
            if [ "$LANG_PREF" = "EN" ]; then printf "  Select Storage Remap Mode (1-4) [Default: 4]: "
            else printf "  스토리지 매핑 방식을 선택하세요 (1-4) [기본값: 4]: "; fi
            _read tbs_remap_mode
            [ -z "$tbs_remap_mode" ] && tbs_remap_mode="4"
            
            if [ "$tbs_remap_mode" = "1" ]; then
                if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Target Unified Tablespace Name [Default: USERS]: "
                else printf "  통합할 Target 테이블스페이스명을 입력하세요 [기본값: USERS]: "; fi
                _read tgt_unified_ts
                [ -z "$tgt_unified_ts" ] && tgt_unified_ts="USERS"
                tgt_unified_ts=$(echo "$tgt_unified_ts" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')
                
                # 소스 테이블스페이스 목록 수집
                _src_ts_list=""
                if [ "$MOCK_MODE" = "true" ]; then
                    _src_ts_list="TS_DATA TS_APP_DATA TS_INDEX"
                else
                    _src_ts_list=$(sqlplus -S /nolog <<SQL_EOF 2>/dev/null | tr -d ' ' | sed '/^$/d' | grep -vE 'ORA-|SP2-|TABLESPACE'
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0
$PDB_SWITCH_SQL
SELECT DISTINCT tablespace_name FROM dba_segments${DBLINK_SUFFIX} WHERE tablespace_name NOT IN ('SYSTEM','SYSAUX','TEMP','UNDOTBS1','UNDOTBS2');
EXIT;
SQL_EOF
)
                    [ -z "$_src_ts_list" ] && _src_ts_list="TS_DATA TS_APP_DATA TS_INDEX"
                fi
                for _sts in $_src_ts_list; do
                    if [ "$_sts" != "$tgt_unified_ts" ]; then
                        REMAP_PARAMS="$REMAP_PARAMS REMAP_TABLESPACE=${_sts}:${tgt_unified_ts}"
                    fi
                done
                echo "  >> [자동 매핑 완료] Target '$tgt_unified_ts' 로 모든 테이블스페이스 매핑 생성됨."
            elif [ "$tbs_remap_mode" = "2" ]; then
                if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Target DATA Tablespace [Default: TS_DATA]: "
                else printf "  Target DATA 테이블스페이스명 [기본값: TS_DATA]: "; fi
                _read tgt_data_ts; [ -z "$tgt_data_ts" ] && tgt_data_ts="TS_DATA"
                tgt_data_ts=$(echo "$tgt_data_ts" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')
                
                if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Target INDEX Tablespace [Default: TS_INDEX]: "
                else printf "  Target INDEX 테이블스페이스명 [기본값: TS_INDEX]: "; fi
                _read tgt_idx_ts; [ -z "$tgt_idx_ts" ] && tgt_idx_ts="TS_INDEX"
                tgt_idx_ts=$(echo "$tgt_idx_ts" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')
                
                _src_ts_list="TS_DATA TS_DATA01 TS_DATA02 TS_IDX TS_INDEX01 TS_APP_LOB"
                if [ "$MOCK_MODE" != "true" ]; then
                    _db_ts_list=$(sqlplus -S /nolog <<SQL_EOF 2>/dev/null | tr -d ' ' | sed '/^$/d' | grep -vE 'ORA-|SP2-|TABLESPACE'
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0
$PDB_SWITCH_SQL
SELECT DISTINCT tablespace_name FROM dba_segments${DBLINK_SUFFIX} WHERE tablespace_name NOT IN ('SYSTEM','SYSAUX','TEMP','UNDOTBS1','UNDOTBS2');
EXIT;
SQL_EOF
)
                    [ -n "$_db_ts_list" ] && _src_ts_list="$_db_ts_list"
                fi
                for _sts in $_src_ts_list; do
                    if echo "$_sts" | grep -qiE "IDX|INDEX"; then
                        [ "$_sts" != "$tgt_idx_ts" ] && REMAP_PARAMS="$REMAP_PARAMS REMAP_TABLESPACE=${_sts}:${tgt_idx_ts}"
                    else
                        [ "$_sts" != "$tgt_data_ts" ] && REMAP_PARAMS="$REMAP_PARAMS REMAP_TABLESPACE=${_sts}:${tgt_data_ts}"
                    fi
                done
                echo "  >> [용도별 자동 분기 매핑 완료] DATA/INDEX 스토리지 분리 매핑 적용됨."
            elif [ "$tbs_remap_mode" = "3" ]; then
                if [ "$LANG_PREF" = "EN" ]; then printf "  - Enter REMAP_TABLESPACE pairs (e.g. SRC_TS:TGT_TS or empty to skip): "
                else printf "  - REMAP_TABLESPACE 매핑 입력 (예: SRC_TS:TGT_TS 또는 미사용시 엔터): "; fi
                _read user_remap_ts
                if [ -n "$user_remap_ts" ]; then
                    user_remap_ts_cleaned=$(echo "$user_remap_ts" | tr ',' ' ')
                    for rpair in $user_remap_ts_cleaned; do
                        REMAP_PARAMS="$REMAP_PARAMS REMAP_TABLESPACE=${rpair}"
                    done
                fi
            fi
        fi

        if [ "$NEEDS_TEA" = "true" ]; then
            if [ "$LANG_PREF" = "EN" ]; then
                echo "  [WARNING] You chose to overwrite/append to existing objects."
                printf "  Select TABLE_EXISTS_ACTION (1: SKIP, 2: APPEND, 3: TRUNCATE, 4: REPLACE) [Default: 1]: "
            else
                echo "  [주의] 기존 개체를 덮어쓰거나 추가하기 위한 정책을 선택하세요."
                printf "  (1: SKIP, 2: APPEND, 3: TRUNCATE, 4: REPLACE) [기본값: 1]: "
            fi
            _read tea_opt
            case "$tea_opt" in
                2) TABLE_EXISTS_ACTION_PARAM="TABLE_EXISTS_ACTION=APPEND" ;;
                3) TABLE_EXISTS_ACTION_PARAM="TABLE_EXISTS_ACTION=TRUNCATE" ;;
                4) TABLE_EXISTS_ACTION_PARAM="TABLE_EXISTS_ACTION=REPLACE" ;;
                *) TABLE_EXISTS_ACTION_PARAM="TABLE_EXISTS_ACTION=SKIP" ;;
            esac
        fi
    fi

    if [ "$DB_CLUSTER" = "TRUE" ]; then
        CLUSTER_PARAM="CLUSTER=N"
    else
        CLUSTER_PARAM=""
    fi

    if [ "$IMPORT_METHOD" = "DUMP" ]; then
        IMP_DUMPFILES=""
        if [ "$DUMP_EXISTS" -gt 0 ]; then
            PREFIXES=$(ls -1 "${DIR_PHYSICAL_PATH}"/${UNIQUE_ID}*.dmp 2>/dev/null | sed 's/_[0-9][0-9]*\.dmp$/_%U.dmp/' | awk -F'/' '{print $NF}' | sort | uniq | grep -v '_meta_custom' | grep -v '_stats_')
            for pfx in $PREFIXES; do
                [ -n "$IMP_DUMPFILES" ] && IMP_DUMPFILES="$IMP_DUMPFILES,"
                IMP_DUMPFILES="$IMP_DUMPFILES$pfx"
            done
        fi
        if [ -z "$IMP_DUMPFILES" ]; then
            IMP_SOURCE_PARAM="DUMPFILE=${UNIQUE_ID}_%U.dmp"
        else
            IMP_SOURCE_PARAM="DUMPFILE=$IMP_DUMPFILES"
        fi
    fi

    if [ "$IMPORT_METHOD" = "NETWORK_LINK" ]; then
        STAT_EXCLUDE=""
        # ----------------------------------------------------------------------
        # [FIX v08.05] 네트워크 모드의 데이터 소스 지정.
        #   v08.04 까지 IMP_SOURCE_PARAM 이 DUMP 분기에서만 설정되어,
        #   NETWORK_LINK 모드로 생성한 impdp par 에 DUMPFILE 도 NETWORK_LINK 도
        #   들어가지 않았다. impdp 는 소스 없이 기동되어 3단계 전부 실패한다.
        #   (메뉴에는 노출되지만 실제로는 동작하지 않던 상태)
        # ----------------------------------------------------------------------
        IMP_SOURCE_PARAM="NETWORK_LINK=$DBLINK_NAME"
    else
        STAT_EXCLUDE="EXCLUDE=STATISTICS"
    fi

    echo "----------------------------------------------------------------------"
    if [ "$IMPORT_METHOD" = "DUMP" ]; then
        if [ "$LANG_PREF" = "EN" ]; then printf "  [Security] Enter TDE Encryption Password applied during backup (leave empty if none): "
        else printf "  [보안 검토] Source 백업 시 적용된 TDE 암호화 패스워드를 입력하세요 (입력 숨김, 미사용 시 엔터): "; fi
        _read_secret tde_pwd MIG_TDE_PASSWORD
        TDE_PARAM=""
        if [ -n "$tde_pwd" ]; then
            TDE_PARAM="ENCRYPTION_PASSWORD=\"$tde_pwd\""
        fi
    else
        TDE_PARAM=""
    fi

    # impdp 실행용 connection string 설정 (PDB 모드이면 PDB TNS 바인딩)
    IMPDP_USERID_STR="$DB_CONN"
    if [ -n "$PDB_CONNECT_STR" ]; then
        IMPDP_USERID_STR="$PDB_CONNECT_STR"
    fi

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "  [Generate Clean DDL Extraction Script (SQLFILE)]"
    else echo "  [사전 DDL 추출 스크립트 생성 (물리속성 Clean SQLFILE)]"; fi

    if [ "$IMPORT_METHOD" = "DUMP" ]; then
        DDL_SOURCE_PARAM="DUMPFILE=${UNIQUE_ID}_meta_custom_%U.dmp"
    else
        DDL_SOURCE_PARAM="NETWORK_LINK=$DBLINK_NAME"
    fi

    DDL_EXTRACT_SH="impdp_0_extract_ddl_${UNIQUE_ID}.sh"
    DDL_EXTRACT_PAR="impdp_0_extract_ddl_${UNIQUE_ID}.par"
    echo "  * 생성 중: $DDL_EXTRACT_SH 및 $DDL_EXTRACT_PAR"

    cat <<EOF > "$DDL_EXTRACT_PAR"
# [SEC v08.01] 접속 문자열을 커맨드라인이 아닌 PARFILE 에 둔다.
#   커맨드라인에 두면 같은 서버의 다른 OS 계정이 ps -ef 로 패스워드를
#   평문으로 볼 수 있다(CWE-214). 이 파일은 chmod 600 으로 보호된다.
USERID="$IMPDP_USERID_STR"
DIRECTORY=$DIR_OBJ_NAME
$DDL_SOURCE_PARAM
LOGFILE=${UNIQUE_ID}_impdp_ddl_extract.log
SQLFILE=${UNIQUE_ID}_pre_ddl_clean.sql
$MIG_PARAMS
EXCLUDE=STATISTICS
TRANSFORM=SEGMENT_ATTRIBUTES:N
TRANSFORM=STORAGE:N
TRANSFORM=OID:N
EOF
    if [ -n "$CLUSTER_PARAM" ]; then echo "$CLUSTER_PARAM" >> "$DDL_EXTRACT_PAR"; fi
    if [ -n "$TDE_PARAM" ]; then echo "$TDE_PARAM" >> "$DDL_EXTRACT_PAR"; fi
    if [ -n "$REMAP_PARAMS" ]; then
        for rp in $REMAP_PARAMS; do
            echo "$rp" >> "$DDL_EXTRACT_PAR"
        done
    fi

    cat <<EOF > "$DDL_EXTRACT_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
    generate_run_prompt "$DDL_EXTRACT_SH" "Target 사전 반영용 물리속성 제외 Clean DDL 추출"
    if [ -n "$CREATE_DIR_SQL" ]; then
        cat <<EOF >> "$DDL_EXTRACT_SH"
sqlplus -S /nolog <<SQL_EOF
connect $DB_CONN
$CREATE_DIR_SQL
$GRANT_DIR_SQL
EXIT;
SQL_EOF

EOF
    fi
    cat <<EOF >> "$DDL_EXTRACT_SH"
impdp PARFILE=$DDL_EXTRACT_PAR
EOF

    chmod 700 "$DDL_EXTRACT_SH"; chmod 600 "$DDL_EXTRACT_PAR" 2>/dev/null   # [FIX v07/M1] par 내 TDE 패스워드 보호
    GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $DDL_EXTRACT_SH"

    echo "----------------------------------------------------------------------"
    if [ "$MIG_TYPE" = "TABLE" ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> [TABLE Mode] Generating scripts for selected tables: $FINAL_LIST"
        else echo "  >> [TABLE 모드] 선택한 Table 복원 스크립트를 생성합니다. (대상: $FINAL_LIST)"; fi
    fi

    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [Select impdp Workflow Options]"
        echo "  1) Full Integration (Import Metadata & Data at once)"
        echo "  2) Step-by-Step 분할 (Table Meta -> Data -> Rest Obj) [Recommended]"
        printf "  Select (1-2) [Default: 2]: "
    else
        echo "  [impdp 작업 순서(Workflow) 선택]"
        echo "  1) 통합 복구 (모든 데이터 및 오브젝트 한번에 임포트)"
        echo "  2) 단계별 분할 복구 (Table 구조 생성 -> Data 복구 -> 나머지 Object 복구) [권장]"
        printf "  선택 (1-2) [기본값: 2]: "
    fi
    _read workflow_opt
    [ -z "$workflow_opt" ] && workflow_opt="2"

    if [ "$workflow_opt" = "2" ]; then
        IMP_P1="impdp_1_table_meta_${UNIQUE_ID}.sh"
        IMP_P1_PAR="impdp_1_table_meta_${UNIQUE_ID}.par"
        echo "  * 생성 중: $IMP_P1 및 $IMP_P1_PAR (Table 구조 생성)"

        cat <<EOF > "$IMP_P1_PAR"
# [SEC v08.01] 접속 문자열을 커맨드라인이 아닌 PARFILE 에 둔다.
#   커맨드라인에 두면 같은 서버의 다른 OS 계정이 ps -ef 로 패스워드를
#   평문으로 볼 수 있다(CWE-214). 이 파일은 chmod 600 으로 보호된다.
USERID="$IMPDP_USERID_STR"
DIRECTORY=$DIR_OBJ_NAME
LOGFILE=${UNIQUE_ID}_impdp_p1_table.log
$MIG_PARAMS
$REMAP_PARAMS
STATUS=30
INCLUDE=TABLE
CONTENT=METADATA_ONLY
LOGTIME=ALL
METRICS=YES
JOB_NAME=${UNIQUE_ID}_IMP_P1
EOF
        if [ -n "$CLUSTER_PARAM" ]; then echo "$CLUSTER_PARAM" >> "$IMP_P1_PAR"; fi
        if [ -n "$IMP_SOURCE_PARAM" ]; then echo "$IMP_SOURCE_PARAM" >> "$IMP_P1_PAR"; fi
        # Notice: CONTENT=METADATA_ONLY 모드에서는 PARALLEL 제외 (ORA-39144 충돌 방지)
        if [ -n "$TABLE_EXISTS_ACTION_PARAM" ]; then echo "$TABLE_EXISTS_ACTION_PARAM" >> "$IMP_P1_PAR"; fi
        if [ -n "$TDE_PARAM" ]; then echo "$TDE_PARAM" >> "$IMP_P1_PAR"; fi

        cat <<EOF > "$IMP_P1"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
        generate_run_prompt "$IMP_P1" "1단계: Table 구조(Metadata) 생성"
        cat <<EOF >> "$IMP_P1"
impdp PARFILE=$IMP_P1_PAR
EOF
        chmod 700 "$IMP_P1"; chmod 600 "$IMP_P1_PAR" 2>/dev/null   # [FIX v07/M1] par 내 TDE 패스워드 보호
        GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $IMP_P1"

        DIS_SQL="impdp_1_1_disable_constraints_${UNIQUE_ID}.sql"
        DIS_SH="impdp_1_1_disable_constraints_${UNIQUE_ID}.sh"
        ENA_SQL="impdp_2_1_enable_constraints_${UNIQUE_ID}.sql"
        ENA_SH="impdp_2_1_enable_constraints_${UNIQUE_ID}.sh"

        echo "  * 생성 중: $DIS_SH 및 $ENA_SH (제약조건/트리거 비활성화 및 재활성화)"

        cat <<EOF > "$DIS_SQL"
SET SERVEROUTPUT ON LINES 200
$PDB_SWITCH_SQL
PROMPT =======================================================================
PROMPT Disabling Foreign Key Constraints and Triggers before Data Load...
PROMPT =======================================================================
DECLARE
  v_count NUMBER := 0;
BEGIN
  FOR r IN (
    SELECT table_name, constraint_name, owner 
    FROM dba_constraints 
    WHERE constraint_type = 'R' AND status = 'ENABLED' AND owner NOT IN ('SYS','SYSTEM','XDB','WMSYS')
  ) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER TABLE "' || r.owner || '"."' || r.table_name || '" DISABLE CONSTRAINT "' || r.constraint_name || '"';
      v_count := v_count + 1;
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
  DBMS_OUTPUT.PUT_LINE('>> Disabled ' || v_count || ' Foreign Key constraints.');
  
  v_count := 0;
  FOR r IN (
    SELECT trigger_name, owner 
    FROM dba_triggers 
    WHERE status = 'ENABLED' AND owner NOT IN ('SYS','SYSTEM','XDB','WMSYS')
  ) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER TRIGGER "' || r.owner || '"."' || r.trigger_name || '" DISABLE';
      v_count := v_count + 1;
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
  DBMS_OUTPUT.PUT_LINE('>> Disabled ' || v_count || ' Triggers.');
END;
/
EXIT;
EOF

        cat <<EOF > "$DIS_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo ">> 2단계 Data 임포트 전 FK 제약조건 및 Trigger를 비활성화합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$DIS_SQL
CONNECT_EOF
EOF
        chmod 700 "$DIS_SH"
        GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $DIS_SH"

        IMP_P2="impdp_2_data_${UNIQUE_ID}.sh"
        IMP_P2_PAR="impdp_2_data_${UNIQUE_ID}.par"
        echo "  * 생성 중: $IMP_P2 및 $IMP_P2_PAR"

        cat <<EOF > "$IMP_P2_PAR"
# [SEC v08.01] 접속 문자열을 커맨드라인이 아닌 PARFILE 에 둔다.
#   커맨드라인에 두면 같은 서버의 다른 OS 계정이 ps -ef 로 패스워드를
#   평문으로 볼 수 있다(CWE-214). 이 파일은 chmod 600 으로 보호된다.
USERID="$IMPDP_USERID_STR"
DIRECTORY=$DIR_OBJ_NAME
LOGFILE=${UNIQUE_ID}_impdp_p2_data.log
$MIG_PARAMS
$REMAP_PARAMS
STATUS=30
CONTENT=DATA_ONLY
LOGTIME=ALL
METRICS=YES
JOB_NAME=${UNIQUE_ID}_IMP_P2
EOF
        if [ -n "$CLUSTER_PARAM" ]; then echo "$CLUSTER_PARAM" >> "$IMP_P2_PAR"; fi
        if [ -n "$IMP_SOURCE_PARAM" ]; then echo "$IMP_SOURCE_PARAM" >> "$IMP_P2_PAR"; fi
        if [ "$CALC_PARALLEL" -gt 0 ]; then echo "PARALLEL=$CALC_PARALLEL" >> "$IMP_P2_PAR"; fi
        # [NEW v08.05] 네트워크 모드의 병렬 특성을 par 주석으로 남긴다.
        #   PARALLEL 은 "테이블/파티션 단위 워커 수"로만 작동하고 PQ 슬레이브는
        #   기동하지 않는다. 큰 테이블 1개짜리 작업에서는 값을 올려도 효과가 없다.
        if [ "$IMPORT_METHOD" = "NETWORK_LINK" ]; then
            {
                echo "# [NETWORK_LINK 주의] 네트워크 모드는 PQ 슬레이브를 사용하지 않습니다."
                echo "#   PARALLEL 은 테이블(파티션) 단위 워커 수로만 작동합니다."
                echo "#   - 대상이 큰 테이블 1개면 PARALLEL 을 올려도 빨라지지 않습니다."
                echo "#   - 소스 테이블이 파티션되어 있으면 워커가 파티션별로 붙어 병렬화됩니다."
                echo "#   - 단일 대용량 테이블은 Dump File 방식이 더 빠릅니다."
            } >> "$IMP_P2_PAR"
        fi
        if [ -n "$TABLE_EXISTS_ACTION_PARAM" ]; then echo "$TABLE_EXISTS_ACTION_PARAM" >> "$IMP_P2_PAR"; fi
        if [ -n "$TDE_PARAM" ]; then echo "$TDE_PARAM" >> "$IMP_P2_PAR"; fi

        cat <<EOF > "$IMP_P2"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
        generate_run_prompt "$IMP_P2" "2단계: Data(행) 복구"
        cat <<EOF >> "$IMP_P2"
impdp PARFILE=$IMP_P2_PAR
EOF
        chmod 700 "$IMP_P2"; chmod 600 "$IMP_P2_PAR" 2>/dev/null   # [FIX v07/M1] par 내 TDE 패스워드 보호
        GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $IMP_P2"

        cat <<EOF > "$ENA_SQL"
SET SERVEROUTPUT ON LINES 200
$PDB_SWITCH_SQL
PROMPT =======================================================================
PROMPT Re-enabling Foreign Key Constraints (NOVALIDATE) and Triggers...
PROMPT =======================================================================
DECLARE
  v_count NUMBER := 0;
BEGIN
  FOR r IN (
    SELECT table_name, constraint_name, owner 
    FROM dba_constraints 
    WHERE constraint_type = 'R' AND status = 'DISABLED' AND owner NOT IN ('SYS','SYSTEM','XDB','WMSYS')
  ) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER TABLE "' || r.owner || '"."' || r.table_name || '" ENABLE NOVALIDATE CONSTRAINT "' || r.constraint_name || '"';
      v_count := v_count + 1;
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
  DBMS_OUTPUT.PUT_LINE('>> Enabled (NOVALIDATE) ' || v_count || ' Foreign Key constraints.');
  
  v_count := 0;
  FOR r IN (
    SELECT trigger_name, owner 
    FROM dba_triggers 
    WHERE status = 'DISABLED' AND owner NOT IN ('SYS','SYSTEM','XDB','WMSYS')
  ) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER TRIGGER "' || r.owner || '"."' || r.trigger_name || '" ENABLE';
      v_count := v_count + 1;
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
  DBMS_OUTPUT.PUT_LINE('>> Enabled ' || v_count || ' Triggers.');
END;
/
EXIT;
EOF

        cat <<EOF > "$ENA_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo ">> 2단계 Data 임포트 완료 후 FK 제약조건 및 Trigger를 재활성화합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$ENA_SQL
CONNECT_EOF
EOF
        chmod 700 "$ENA_SH"
        GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $ENA_SH"

        if [ "$MIG_TYPE" != "TABLE" ]; then
            IMP_P3="impdp_3_rest_${UNIQUE_ID}.sh"
            IMP_P3_PAR="impdp_3_rest_${UNIQUE_ID}.par"
            echo "  * 생성 중: $IMP_P3 및 $IMP_P3_PAR"

            cat <<EOF > "$IMP_P3_PAR"
# [SEC v08.01] 접속 문자열을 커맨드라인이 아닌 PARFILE 에 둔다.
#   커맨드라인에 두면 같은 서버의 다른 OS 계정이 ps -ef 로 패스워드를
#   평문으로 볼 수 있다(CWE-214). 이 파일은 chmod 600 으로 보호된다.
USERID="$IMPDP_USERID_STR"
DIRECTORY=$DIR_OBJ_NAME
LOGFILE=${UNIQUE_ID}_impdp_p3_rest.log
$MIG_PARAMS
$REMAP_PARAMS
STATUS=30
LOGTIME=ALL
METRICS=YES
JOB_NAME=${UNIQUE_ID}_IMP_P3
EOF
            if [ -n "$CLUSTER_PARAM" ]; then echo "$CLUSTER_PARAM" >> "$IMP_P3_PAR"; fi
            if [ -n "$IMP_SOURCE_PARAM" ]; then echo "$IMP_SOURCE_PARAM" >> "$IMP_P3_PAR"; fi
            # [FIX v07/M2] 'TABLE/TABLE' 은 Data Pump 표준 object path 가 아니어서
            #              3단계 impdp 가 실패했다. 테이블 본체만 제외하려면 EXCLUDE=TABLE 사용.
            if [ -n "$STAT_EXCLUDE" ]; then
                echo "EXCLUDE=TABLE,STATISTICS" >> "$IMP_P3_PAR"
            else
                echo "EXCLUDE=TABLE" >> "$IMP_P3_PAR"
            fi
            if [ "$CALC_PARALLEL" -gt 0 ]; then echo "PARALLEL=$CALC_PARALLEL" >> "$IMP_P3_PAR"; fi
            if [ -n "$TDE_PARAM" ]; then echo "$TDE_PARAM" >> "$IMP_P3_PAR"; fi

            cat <<EOF > "$IMP_P3"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
            generate_run_prompt "$IMP_P3" "3단계: 나머지 오브젝트(인덱스,뷰,트리거 등) 복구"
            cat <<EOF >> "$IMP_P3"
impdp PARFILE=$IMP_P3_PAR
EOF
            chmod 700 "$IMP_P3"; chmod 600 "$IMP_P3_PAR" 2>/dev/null   # [FIX v07/M1] par 내 TDE 패스워드 보호
            GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $IMP_P3"
        fi

    else
        IMP_ALL="impdp_1_execute_all_${UNIQUE_ID}.sh"
        IMP_ALL_PAR="impdp_1_execute_all_${UNIQUE_ID}.par"
        echo "  * 생성 중: $IMP_ALL 및 $IMP_ALL_PAR"

        cat <<EOF > "$IMP_ALL_PAR"
# [SEC v08.01] 접속 문자열을 커맨드라인이 아닌 PARFILE 에 둔다.
#   커맨드라인에 두면 같은 서버의 다른 OS 계정이 ps -ef 로 패스워드를
#   평문으로 볼 수 있다(CWE-214). 이 파일은 chmod 600 으로 보호된다.
USERID="$IMPDP_USERID_STR"
DIRECTORY=$DIR_OBJ_NAME
LOGFILE=${UNIQUE_ID}_impdp_all.log
$MIG_PARAMS
$REMAP_PARAMS
STATUS=30
LOGTIME=ALL
METRICS=YES
JOB_NAME=${UNIQUE_ID}_IMP_ALL
EOF
        if [ -n "$CLUSTER_PARAM" ]; then echo "$CLUSTER_PARAM" >> "$IMP_ALL_PAR"; fi
        if [ -n "$IMP_SOURCE_PARAM" ]; then echo "$IMP_SOURCE_PARAM" >> "$IMP_ALL_PAR"; fi
        if [ -n "$STAT_EXCLUDE" ]; then echo "$STAT_EXCLUDE" >> "$IMP_ALL_PAR"; fi
        if [ "$CALC_PARALLEL" -gt 0 ]; then echo "PARALLEL=$CALC_PARALLEL" >> "$IMP_ALL_PAR"; fi
        if [ -n "$TABLE_EXISTS_ACTION_PARAM" ]; then echo "$TABLE_EXISTS_ACTION_PARAM" >> "$IMP_ALL_PAR"; fi
        if [ -n "$TDE_PARAM" ]; then echo "$TDE_PARAM" >> "$IMP_ALL_PAR"; fi

        cat <<EOF > "$IMP_ALL"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
        generate_run_prompt "$IMP_ALL" "실제 데이터 통합 impdp"
        cat <<EOF >> "$IMP_ALL"
impdp PARFILE=$IMP_ALL_PAR
EOF
        chmod 700 "$IMP_ALL"; chmod 600 "$IMP_ALL_PAR" 2>/dev/null   # [FIX v07/M1] par 내 TDE 패스워드 보호
        GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $IMP_ALL"
    fi

    if [ "$IMPORT_METHOD" = "DUMP" ]; then
        echo "----------------------------------------------------------------------"
        if [ "$LANG_PREF" = "EN" ]; then echo "  [Generate DBMS_STATS Import Script]"
        else echo "  [통계정보(DBMS_STATS) 전용 복원 스크립트 생성]"; fi
        STAT_OWN="SYSTEM"
        STAT_TAB="MIG_STAT_${UNIQUE_ID}"
        IMP_STATS_SQL="import_dbms_stats_${UNIQUE_ID}.sql"
        IMP_STATS_SH="import_dbms_stats_${UNIQUE_ID}.sh"
        IMP_STATS_PAR="import_dbms_stats_${UNIQUE_ID}.par"
        
        STATS_DUMP_PARAM="DUMPFILE=${UNIQUE_ID}_stats_%U.dmp"

        echo "  * 생성 중: $IMP_STATS_SQL, $IMP_STATS_SH 및 $IMP_STATS_PAR"
        
        cat <<EOF > "$IMP_STATS_SQL"
$PDB_SWITCH_SQL
BEGIN
EOF
        
        if [ "$MIG_TYPE" = "FULL" ]; then
            echo "  DBMS_STATS.IMPORT_DATABASE_STATS(statown => '$STAT_OWN', stattab => '$STAT_TAB');" >> "$IMP_STATS_SQL"
        elif [ "$MIG_TYPE" = "SCHEMA" ]; then
            IFS_BACKUP=$IFS; IFS=","
            for sch in $FINAL_LIST; do
                target_sch="$sch"
                if echo "$REMAP_PARAMS" | grep -q "REMAP_SCHEMA=${sch}:"; then
                    target_sch=$(echo "$REMAP_PARAMS" | sed -n "s/.*REMAP_SCHEMA=${sch}:\([^ ]*\).*/\1/p")
                    echo "  UPDATE $STAT_OWN.$STAT_TAB SET C5 = UPPER('$target_sch') WHERE UPPER(C5) = UPPER('$sch');" >> "$IMP_STATS_SQL"
                fi
                echo "  DBMS_STATS.IMPORT_SCHEMA_STATS(ownname => '$target_sch', statown => '$STAT_OWN', stattab => '$STAT_TAB');" >> "$IMP_STATS_SQL"
            done
            IFS=$IFS_BACKUP
        elif [ "$MIG_TYPE" = "TABLE" ]; then
            IFS_BACKUP=$IFS; IFS=","
            for tbl in $FINAL_LIST; do
                sch_p=$(echo "$tbl" | cut -d'.' -f1); tbl_p=$(echo "$tbl" | cut -d'.' -f2)
                target_sch="$sch_p"
                target_tbl="$tbl_p"
                if echo "$REMAP_PARAMS" | grep -q "REMAP_TABLE=${tbl}:"; then
                    new_full=$(echo "$REMAP_PARAMS" | sed -n "s/.*REMAP_TABLE=${tbl}:\([^ ]*\).*/\1/p")
                    target_sch=$(echo "$new_full" | cut -d'.' -f1)
                    target_tbl=$(echo "$new_full" | cut -d'.' -f2)
                    echo "  UPDATE $STAT_OWN.$STAT_TAB SET C5 = UPPER('$target_sch'), C1 = UPPER('$target_tbl') WHERE UPPER(C5) = UPPER('$sch_p') AND UPPER(C1) = UPPER('$tbl_p');" >> "$IMP_STATS_SQL"
                fi
                echo "  DBMS_STATS.IMPORT_TABLE_STATS(ownname => '$target_sch', tabname => '$target_tbl', statown => '$STAT_OWN', stattab => '$STAT_TAB');" >> "$IMP_STATS_SQL"
            done
            IFS=$IFS_BACKUP
        elif [ "$MIG_TYPE" = "TABLESPACE" ]; then
            echo "  -- TABLESPACE 단위 통계 복원 (선택된 목록 한정)" >> "$IMP_STATS_SQL"
            echo "  FOR rec IN (SELECT DISTINCT c5 as owner, c1 as table_name FROM $STAT_OWN.$STAT_TAB) LOOP" >> "$IMP_STATS_SQL"
            echo "    DBMS_STATS.IMPORT_TABLE_STATS(ownname => rec.owner, tabname => rec.table_name, statown => '$STAT_OWN', stattab => '$STAT_TAB');" >> "$IMP_STATS_SQL"
            echo "  END LOOP;" >> "$IMP_STATS_SQL"
        fi
        
        cat <<EOF >> "$IMP_STATS_SQL"
  COMMIT;
END;
/
EXIT;
EOF
        
        cat <<EOF > "$IMP_STATS_PAR"
# [SEC v08.01] 접속 문자열을 커맨드라인이 아닌 PARFILE 에 둔다.
#   커맨드라인에 두면 같은 서버의 다른 OS 계정이 ps -ef 로 패스워드를
#   평문으로 볼 수 있다(CWE-214). 이 파일은 chmod 600 으로 보호된다.
USERID="$IMPDP_USERID_STR"
DIRECTORY=$DIR_OBJ_NAME
$STATS_DUMP_PARAM
LOGFILE=${UNIQUE_ID}_impdp_stats.log
TABLES=$STAT_OWN.$STAT_TAB
TABLE_EXISTS_ACTION=REPLACE
STATUS=30
LOGTIME=ALL
METRICS=YES
JOB_NAME=${UNIQUE_ID}_STAT_IMP
EOF
        if [ -n "$TDE_PARAM" ]; then echo "$TDE_PARAM" >> "$IMP_STATS_PAR"; fi

        cat <<EOF > "$IMP_STATS_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
        generate_run_prompt "$IMP_STATS_SH" "DBMS_STATS 통계정보 테이블 impdp 및 적용(SQL)"
        cat <<EOF >> "$IMP_STATS_SH"
echo ">> Stat Table을 임포트 중입니다..."
impdp PARFILE=$IMP_STATS_PAR

echo ">> DBMS_STATS 복원 스크립트를 실행하여 통계를 딕셔너리에 반영합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$IMP_STATS_SQL
CONNECT_EOF

echo ">> 통계 반영 완료 후 임시 통계 테이블(${STAT_OWN}.${STAT_TAB})을 삭제합니다..."
sqlplus -S /nolog <<SQL_EOF
connect $DB_CONN
$PDB_SWITCH_SQL
BEGIN
  DBMS_STATS.DROP_STAT_TABLE('${STAT_OWN}', '${STAT_TAB}');
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
EXIT;
SQL_EOF
EOF
        chmod 700 "$IMP_STATS_SH"; chmod 600 "$IMP_STATS_PAR" 2>/dev/null   # [FIX v07/M1] par 내 TDE 패스워드 보호
        GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $IMP_STATS_SH"
    fi
    
    # ------------------------------------------------------------------
    # 실행 계획 안정화 (Statistics Lock / Unlock) 스크립트 생성
    # ------------------------------------------------------------------
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then echo "  [Generate Statistics Lock/Unlock Scripts (Stabilize Execution Plans)]"
    else echo "  [실행 계획 안정화: 통계 잠금(Lock) 및 해제(Unlock) 스크립트 생성]"; fi
    
    LOCK_SQL="lock_stats_${UNIQUE_ID}.sql"
    LOCK_SH="lock_stats_${UNIQUE_ID}.sh"
    UNLOCK_SQL="unlock_stats_${UNIQUE_ID}.sql"
    UNLOCK_SH="unlock_stats_${UNIQUE_ID}.sh"
    
    echo "  * 생성 중: $LOCK_SQL, $LOCK_SH, $UNLOCK_SQL, $UNLOCK_SH"
    
    cat <<EOF > "$LOCK_SQL"
-- ==============================================================================
--  Lock Optimizer Statistics to Prevent Nightly Auto Task Plan Regression
--  Job ID: ${UNIQUE_ID}
-- ==============================================================================
SET ECHO ON LOGONLY SERVEROUTPUT ON
SPOOL lock_stats_${UNIQUE_ID}.log
$PDB_SWITCH_SQL

PROMPT =======================================================================
PROMPT Locking Table/Schema Optimizer Statistics...
PROMPT =======================================================================
BEGIN
EOF

    if [ "$MIG_TYPE" = "FULL" ]; then
        cat <<EOF >> "$LOCK_SQL"
  FOR r IN (SELECT username FROM dba_users WHERE username NOT IN ('SYS','SYSTEM','AUDSYS','XDB','WMSYS','MDSYS','ORDDATA','CTXSYS','DBSNMP')) LOOP
    BEGIN
      DBMS_STATS.LOCK_SCHEMA_STATS(ownname => r.username);
      DBMS_OUTPUT.PUT_LINE('>> Locked Schema Stats: ' || r.username);
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
EOF
    elif [ "$MIG_TYPE" = "SCHEMA" ]; then
        IFS_BACKUP=$IFS; IFS=","
        for sch in $FINAL_LIST; do
            target_sch="$sch"
            if echo "$REMAP_PARAMS" | grep -q "REMAP_SCHEMA=${sch}:"; then
                target_sch=$(echo "$REMAP_PARAMS" | sed -n "s/.*REMAP_SCHEMA=${sch}:\([^ ]*\).*/\1/p")
            fi
            cat <<EOF >> "$LOCK_SQL"
  BEGIN
    DBMS_STATS.LOCK_SCHEMA_STATS(ownname => '$target_sch');
    DBMS_OUTPUT.PUT_LINE('>> Locked Schema Stats: $target_sch');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
EOF
        done
        IFS=$IFS_BACKUP
    elif [ "$MIG_TYPE" = "TABLE" ]; then
        IFS_BACKUP=$IFS; IFS=","
        for tbl in $FINAL_LIST; do
            sch_p=$(echo "$tbl" | cut -d'.' -f1); tbl_p=$(echo "$tbl" | cut -d'.' -f2)
            target_sch="$sch_p"; target_tbl="$tbl_p"
            if echo "$REMAP_PARAMS" | grep -q "REMAP_TABLE=${tbl}:"; then
                new_full=$(echo "$REMAP_PARAMS" | sed -n "s/.*REMAP_TABLE=${tbl}:\([^ ]*\).*/\1/p")
                target_sch=$(echo "$new_full" | cut -d'.' -f1)
                target_tbl=$(echo "$new_full" | cut -d'.' -f2)
            fi
            cat <<EOF >> "$LOCK_SQL"
  BEGIN
    DBMS_STATS.LOCK_TABLE_STATS(ownname => '$target_sch', tabname => '$target_tbl');
    DBMS_OUTPUT.PUT_LINE('>> Locked Table Stats: ${target_sch}.${target_tbl}');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
EOF
        done
        IFS=$IFS_BACKUP
    elif [ "$MIG_TYPE" = "TABLESPACE" ]; then
        cat <<EOF >> "$LOCK_SQL"
  FOR r IN (SELECT owner, table_name FROM dba_tables WHERE tablespace_name IN (${FINAL_IN_CLAUSE:-NULL})) LOOP
    BEGIN
      DBMS_STATS.LOCK_TABLE_STATS(ownname => r.owner, tabname => r.table_name);
      DBMS_OUTPUT.PUT_LINE('>> Locked Table Stats: ' || r.owner || '.' || r.table_name);
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
EOF
    fi

    cat <<EOF >> "$LOCK_SQL"
END;
/
SPOOL OFF
EXIT;
EOF

    cat <<EOF > "$LOCK_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
    generate_run_prompt "$LOCK_SH" "Target DB 이관 객체 통계 잠금(Lock Table Stats) 적용"
    cat <<EOF >> "$LOCK_SH"
echo ">> Target DB Optimizer 통계 잠금을 실행합니다 (야간 Auto Task 변경 차단)..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$LOCK_SQL
CONNECT_EOF
EOF
    chmod 700 "$LOCK_SH"
    GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $LOCK_SH"

    # Unlock Script 생성
    cat <<EOF > "$UNLOCK_SQL"
-- ==============================================================================
--  Unlock Optimizer Statistics for Maintenance
--  Job ID: ${UNIQUE_ID}
-- ==============================================================================
SET ECHO ON LOGONLY SERVEROUTPUT ON
SPOOL unlock_stats_${UNIQUE_ID}.log
$PDB_SWITCH_SQL

PROMPT =======================================================================
PROMPT Unlocking Table/Schema Optimizer Statistics...
PROMPT =======================================================================
BEGIN
EOF
    if [ "$MIG_TYPE" = "FULL" ]; then
        cat <<EOF >> "$UNLOCK_SQL"
  FOR r IN (SELECT username FROM dba_users WHERE username NOT IN ('SYS','SYSTEM','AUDSYS','XDB','WMSYS','MDSYS','ORDDATA','CTXSYS','DBSNMP')) LOOP
    BEGIN
      DBMS_STATS.UNLOCK_SCHEMA_STATS(ownname => r.username);
      DBMS_OUTPUT.PUT_LINE('>> Unlocked Schema Stats: ' || r.username);
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
EOF
    elif [ "$MIG_TYPE" = "SCHEMA" ]; then
        IFS_BACKUP=$IFS; IFS=","
        for sch in $FINAL_LIST; do
            target_sch="$sch"
            if echo "$REMAP_PARAMS" | grep -q "REMAP_SCHEMA=${sch}:"; then
                target_sch=$(echo "$REMAP_PARAMS" | sed -n "s/.*REMAP_SCHEMA=${sch}:\([^ ]*\).*/\1/p")
            fi
            cat <<EOF >> "$UNLOCK_SQL"
  BEGIN
    DBMS_STATS.UNLOCK_SCHEMA_STATS(ownname => '$target_sch');
    DBMS_OUTPUT.PUT_LINE('>> Unlocked Schema Stats: $target_sch');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
EOF
        done
        IFS=$IFS_BACKUP
    elif [ "$MIG_TYPE" = "TABLE" ]; then
        IFS_BACKUP=$IFS; IFS=","
        for tbl in $FINAL_LIST; do
            sch_p=$(echo "$tbl" | cut -d'.' -f1); tbl_p=$(echo "$tbl" | cut -d'.' -f2)
            target_sch="$sch_p"; target_tbl="$tbl_p"
            if echo "$REMAP_PARAMS" | grep -q "REMAP_TABLE=${tbl}:"; then
                new_full=$(echo "$REMAP_PARAMS" | sed -n "s/.*REMAP_TABLE=${tbl}:\([^ ]*\).*/\1/p")
                target_sch=$(echo "$new_full" | cut -d'.' -f1)
                target_tbl=$(echo "$new_full" | cut -d'.' -f2)
            fi
            cat <<EOF >> "$UNLOCK_SQL"
  BEGIN
    DBMS_STATS.UNLOCK_TABLE_STATS(ownname => '$target_sch', tabname => '$target_tbl');
    DBMS_OUTPUT.PUT_LINE('>> Unlocked Table Stats: ${target_sch}.${target_tbl}');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
EOF
        done
        IFS=$IFS_BACKUP
    elif [ "$MIG_TYPE" = "TABLESPACE" ]; then
        cat <<EOF >> "$UNLOCK_SQL"
  FOR r IN (SELECT owner, table_name FROM dba_tables WHERE tablespace_name IN (${FINAL_IN_CLAUSE:-NULL})) LOOP
    BEGIN
      DBMS_STATS.UNLOCK_TABLE_STATS(ownname => r.owner, tabname => r.table_name);
      DBMS_OUTPUT.PUT_LINE('>> Unlocked Table Stats: ' || r.owner || '.' || r.table_name);
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
EOF
    fi

    cat <<EOF >> "$UNLOCK_SQL"
END;
/
SPOOL OFF
EXIT;
EOF

    cat <<EOF > "$UNLOCK_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
    generate_run_prompt "$UNLOCK_SH" "Target DB 이관 객체 통계 잠금 해제(Unlock Table Stats)"
    cat <<EOF >> "$UNLOCK_SH"
echo ">> Target DB Optimizer 통계 잠금을 해제합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$UNLOCK_SQL
CONNECT_EOF
EOF
    chmod 700 "$UNLOCK_SH"
    GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $UNLOCK_SH"

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  [Validation] Generate Post-Migration Validation script (UTLRP, Size & Log Check)? (y/N): "
    else printf "  [사후 완벽 검증] Invalid 객체 재컴파일, 용량/오브젝트수 체크 및 로그(Row Count) 검증 스크립트를 만드시겠습니까? (y/N): "; fi
    _read gen_val
    if [ "$gen_val" = "y" ] || [ "$gen_val" = "Y" ]; then
        if [ -z "$DBLINK_NAME" ]; then
            printf "  - 비교 검증을 위해 Source DB와 연결할 DB Link 이름을 입력하세요 (미입력 시 소스 비교 생략) [MIG_LINK]: "; _read val_dblink
            [ -z "$val_dblink" ] && val_dblink="MIG_LINK"
        else
            val_dblink="$DBLINK_NAME"
        fi
        
        VAL_SH="impdp_4_post_validate_${UNIQUE_ID}.sh"
        VAL_SQL="post_validate_${UNIQUE_ID}.sql"
        echo "  * 생성 중: $VAL_SH 및 $VAL_SQL"
        
        cat <<EOF > "$VAL_SQL"
SET LINES 250 PAGES 1000
$PDB_SWITCH_SQL
COL OWNER FORMAT A20
COL OBJECT_TYPE FORMAT A25
COL TARGET_MB FORMAT 999,999,999.99
COL SOURCE_MB FORMAT 999,999,999.99
COL DIFF_PERCENT FORMAT 999.99
COL TARGET_COUNT FORMAT 999,999,999
COL SOURCE_COUNT FORMAT 999,999,999
COL DIFF FORMAT 999,999,999

PROMPT =======================================================================
PROMPT 1. Invalid Object Summary (Target DB) - Status Check
PROMPT =======================================================================
SELECT owner, object_type, count(*) as invalid_count 
FROM dba_objects 
WHERE status = 'INVALID' AND owner NOT IN ('SYS','SYSTEM')
GROUP BY owner, object_type
ORDER BY owner, object_type;

PROMPT =======================================================================
PROMPT 2. Target Schema Object Count Summary
PROMPT =======================================================================
SELECT owner, object_type, count(*) as object_count
FROM dba_objects
WHERE owner NOT IN ('SYS','SYSTEM','XDB','WMSYS','OJVMSYS','OUTLN','DBSNMP','AUDSYS')
GROUP BY owner, object_type
ORDER BY 1, 2;

BEGIN
  EXECUTE IMMEDIATE 'SELECT 1 FROM dual@$val_dblink';
  DBMS_OUTPUT.PUT_LINE('=======================================================================');
  DBMS_OUTPUT.PUT_LINE('3. Segment Size Comparison (Target vs Source: $val_dblink)');
  DBMS_OUTPUT.PUT_LINE('=======================================================================');
EXCEPTION WHEN OTHERS THEN
  DBMS_OUTPUT.PUT_LINE('>> [INFO] DB Link ($val_dblink) is not accessible. Skipping remote cross-check.');
END;
/

WITH src AS (SELECT owner, SUM(bytes) bytes FROM dba_segments@$val_dblink GROUP BY owner),
     tgt AS (SELECT owner, SUM(bytes) bytes FROM dba_segments GROUP BY owner)
SELECT NVL(tgt.owner, src.owner) as OWNER,
       ROUND(NVL(tgt.bytes,0)/1024/1024, 2) AS TARGET_MB,
       ROUND(NVL(src.bytes,0)/1024/1024, 2) AS SOURCE_MB,
       ROUND(ABS(NVL(tgt.bytes,0) - NVL(src.bytes,0)) / NULLIF(NVL(src.bytes,0), 0) * 100, 2) AS DIFF_PERCENT
FROM tgt FULL OUTER JOIN src ON tgt.owner = src.owner
WHERE NVL(tgt.owner, src.owner) NOT IN ('SYS','SYSTEM','XDB','WMSYS','OJVMSYS','OUTLN','DBSNMP')
ORDER BY 1;

EXIT;
EOF
        cat <<EOF > "$VAL_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo ">> [1/3] Invalid Object 자동 재컴파일을 수행합니다 (utlrp.sql)..."
sqlplus -S /nolog <<SQL_EOF
connect $DB_CONN
$PDB_SWITCH_SQL
@\$ORACLE_HOME/rdbms/admin/utlrp.sql
EXIT;
SQL_EOF

echo ">> [2/3] 용량 및 객체 상태 검증 리포트를 추출합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$VAL_SQL
CONNECT_EOF

echo ">> [3/3] Migration Data Row Count Validation (expdp vs impdp logs)..."
# [FIX v08.02] 공백이 포함된 경로 대응.
#   ls|grep 결과를 공백 구분 문자열로 쓰면 경로에 공백이 있을 때(예: /backup/my dumps)
#   단어 단위로 찢어져 검증이 통째로 마비된다. 글롭 순회로 개행 구분 목록을 만든다.
exp_list="val_exp_list_\$\$.tmp"
imp_list="val_imp_list_\$\$.tmp"
: > "\$exp_list"; : > "\$imp_list"

for _l in "\${DIR_PHYSICAL_PATH}"/\${UNIQUE_ID}_expdp_*.log; do
    [ -e "\$_l" ] || continue
    case "\$_l" in *_meta_custom*|*_stats_*|*_estimate_*) continue ;; esac
    printf '%s\\n' "\$_l" >> "\$exp_list"
done
for _l in "\${DIR_PHYSICAL_PATH}"/\${UNIQUE_ID}_impdp_*.log; do
    [ -e "\$_l" ] || continue
    case "\$_l" in *_meta_custom*|*_stats_*|*_ddl_extract*|*_estimate_*) continue ;; esac
    printf '%s\\n' "\$_l" >> "\$imp_list"
done

if [ ! -s "\$exp_list" ] || [ ! -s "\$imp_list" ]; then
    rm -f "\$exp_list" "\$imp_list"
    echo "  [INFO] expdp 또는 impdp 로그 파일을 찾을 수 없어 Row Count 검증을 건너뜁니다."
else
    exp_tmp="val_exp_rows_\$\$.tmp"
    imp_tmp="val_imp_rows_\$\$.tmp"
    
    # [FIX v08.02] 공백 포함 경로 대응 - 목록 파일을 한 건씩 awk 에 전달
    while IFS= read -r _l; do
        [ -n "\$_l" ] || continue
        awk '/\.\ \.\ (exported|imported)/ { line=\$0; gsub(/"/, "", line); split(line, parts); tbl=""; rows=0; for (i=1; i<=NF; i++) { if (parts[i]=="exported" || parts[i]=="imported") { tbl=parts[i+1]; sub(/:.*/, "", tbl); for (j=i+2; j<=NF; j++) { if (parts[j]=="rows") { rows=parts[j-1]; gsub(/[^0-9]/, "", rows); break; } } break; } } if (tbl != "") { sum[tbl] += rows; } } END { for (t in sum) print t "," sum[t]; }' "\$_l"
    done < "\$exp_list" | sort | uniq > \$exp_tmp
    
    # [FIX v08.02] 공백 포함 경로 대응 - 목록 파일을 한 건씩 awk 에 전달
    while IFS= read -r _l; do
        [ -n "\$_l" ] || continue
        awk '/\.\ \.\ (exported|imported)/ { line=\$0; gsub(/"/, "", line); split(line, parts); tbl=""; rows=0; for (i=1; i<=NF; i++) { if (parts[i]=="exported" || parts[i]=="imported") { tbl=parts[i+1]; sub(/:.*/, "", tbl); for (j=i+2; j<=NF; j++) { if (parts[j]=="rows") { rows=parts[j-1]; gsub(/[^0-9]/, "", rows); break; } } break; } } if (tbl != "") { sum[tbl] += rows; } } END { for (t in sum) print t "," sum[t]; }' "\$_l"
    done < "\$imp_list" | sort | uniq > \$imp_tmp
    
    echo "  --------------------------------------------------------------------------------------"
    printf "  %-38s | %-12s | %-12s | %-10s\n" "Table Name" "Exp. Count" "Imp. Count" "Status"
    echo "  --------------------------------------------------------------------------------------"
    
    mismatches=0; matches=0
    while IFS=, read -r tbl exp_cnt; do
        imp_cnt=\$(grep "^\${tbl}," \$imp_tmp | cut -d',' -f2)
        if [ -z "\$imp_cnt" ]; then
            tbl_only=\$(echo "\$tbl" | cut -d'.' -f2)
            imp_match_line=\$(grep "\.\${tbl_only}," \$imp_tmp | head -n 1)
            if [ -n "\$imp_match_line" ]; then
                imp_cnt=\$(echo "\$imp_match_line" | cut -d',' -f2)
                tbl_mapped=\$(echo "\$imp_match_line" | cut -d',' -f1)
                tbl="\$tbl -> \$tbl_mapped"
            fi
        fi

        if [ -z "\$imp_cnt" ]; then printf "  %-38s | %-12s | %-12s | \033[31m%-10s\033[0m\n" "\$tbl" "\$exp_cnt" "MISSING" "[누락]"; mismatches=\$((mismatches + 1))
        elif [ "\$exp_cnt" = "\$imp_cnt" ]; then printf "  %-38s | %-12s | %-12s | \033[32m%-10s\033[0m\n" "\$tbl" "\$exp_cnt" "\$imp_cnt" "[일치]"; matches=\$((matches + 1))
        else printf "  %-38s | %-12s | %-12s | \033[33m%-10s\033[0m\n" "\$tbl" "\$exp_cnt" "\$imp_cnt" "[불일치]"; mismatches=\$((mismatches + 1))
        fi
    done < \$exp_tmp

    while IFS=, read -r tbl imp_cnt; do
        if ! grep -q "^\${tbl}," \$exp_tmp; then
            tbl_only=\$(echo "\$tbl" | cut -d'.' -f2)
            if ! grep -q "\.\${tbl_only}," \$exp_tmp; then
                printf "  %-38s | %-12s | %-12s | \033[36m%-10s\033[0m\n" "\$tbl" "N/A" "\$imp_cnt" "[추가됨]"
                mismatches=\$((mismatches + 1))
            fi
        fi
    done < \$imp_tmp

    echo "  --------------------------------------------------------------------------------------"
    if [ \$mismatches -eq 0 ]; then
        echo "  >> [SUCCESS] \${matches}개 테이블 건수가 완전히 일치합니다!"
    else
        echo "  >> [WARNING] \${mismatches}건의 불일치/누락 항목이 검출되었습니다."
    fi
    rm -f \$exp_tmp \$imp_tmp "\$exp_list" "\$imp_list"
fi
EOF
        chmod 700 "$VAL_SH"
        GENERATED_TARGET_SCRIPTS="$GENERATED_TARGET_SCRIPTS $VAL_SH"
    fi

    # [NEW v07] impdp 이전 덤프 무결성 검증 단계 생성
    if [ "$IMPORT_METHOD" = "DUMP" ]; then
        echo "----------------------------------------------------------------------"
        if [ "$LANG_PREF" = "EN" ]; then printf "  [Integrity] Add MD5 checksum verification step before import? (Y/n) [Default: Y]: "
        else printf "  [무결성] impdp 이전에 덤프 MD5 체크섬 검증 단계를 추가하시겠습니까? (Y/n) [기본값: Y]: "; fi
        _read tgt_chk_opt
        if [ -z "$tgt_chk_opt" ] || [ "$tgt_chk_opt" = "y" ] || [ "$tgt_chk_opt" = "Y" ]; then
            CHECKSUM_ENABLED="true"
            generate_checksum_scripts
            if [ -n "$CHK_VERIFY_SH" ]; then
                # 검증 스크립트를 파이프라인 맨 앞에 배치 -> 손상된 덤프로 impdp 하는 사고 방지
                GENERATED_TARGET_SCRIPTS="$CHK_VERIFY_SH $GENERATED_TARGET_SCRIPTS"
            fi
        fi
    fi

    generate_target_env_ddl
    generate_grants_and_synonyms_scripts
    generate_monitoring_and_stop_scripts

    # 마스터 실행 파이프라인 러너 생성
    generate_master_runner_script "Target Server Import Pipeline" "$GENERATED_TARGET_SCRIPTS"

    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> Script Generation Complete!"
    else echo "  >> 임포트 스크립트 생성 완료!"; fi
    echo "  [Master Orchestrator Pipeline]"
    echo "  * $MASTER_RUNNER_SH"
    echo "  [Individual Step Scripts]"
    for gs in $GENERATED_TARGET_SCRIPTS; do echo "  - $gs"; done
    if [ -n "$GENERATED_UTIL_SCRIPTS" ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  [Monitoring & Stop Utilities]"; else echo "  [모니터링 및 안전 중지 헬퍼 유틸리티]"; fi
        for gs in $GENERATED_UTIL_SCRIPTS; do echo "  * $gs"; done
    fi

    # [NEW v08.05] 네트워크 모드 운영 요약 — 덤프 방식과 기대치가 다르다는 점을 명시
    if [ "$IMPORT_METHOD" = "NETWORK_LINK" ]; then
        echo "----------------------------------------------------------------------"
        if [ "$LANG_PREF" = "EN" ]; then echo "  [NETWORK_LINK Mode Notes]"
        else echo "  [NETWORK_LINK 모드 운영 참고]"; fi
        echo "   - 덤프 파일이 없으므로 전송 · 체크섬 단계가 생략됩니다 (DB Link: ${DBLINK_NAME})"
        echo "   - 네트워크 모드는 PQ 슬레이브를 사용하지 않습니다. PARALLEL=${CALC_PARALLEL} 은"
        echo "     테이블(파티션) 단위 워커 수로만 작동합니다."
        echo "   - 소스가 파티션 테이블이면 워커가 파티션별로 붙어 실질 병렬화가 됩니다."
        echo "   - 단일 대용량 테이블 · LOB 비중이 큰 경우 Dump File 방식이 더 빠릅니다."
        echo "   - LONG / LONG RAW 는 DB Link 를 통과하지 못합니다 (위 사전 점검 참조)."
        echo "   - Source 서버에서 메뉴 1 을 실행할 필요가 없습니다."
    fi
    echo "======================================================================"

    for gs in $GENERATED_TARGET_SCRIPTS; do ask_to_run_script "$gs"; done
}

# ------------------------------------------------------------------------------
# [NEW v08] DEEP DIFF 결과를 HTML 보고서 섹션으로 추가
#   deepdiff_result_*.csv (파이프 구분) 를 찾아 표로 렌더링한다.
#   파일이 없으면 아무것도 하지 않는다(기존 동작 유지).
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# [FIX v08.04] HTML 감사 보고서용 엔티티 이스케이프
#   SQLERRM / 제약조건명 / 인덱스 표현식에는 < > & 가 흔히 들어간다.
#   (예: ORA-00904: "A"."B" & "C"<D>: invalid identifier)
#   이스케이프 없이 <td> 안에 넣으면 브라우저가 <D> 를 태그로 해석해
#   해당 문자열이 화면에서 "조용히 사라진다" — 감사 문서에서 가장 위험한 형태의 오류.
#   셀마다 호출하면 서브셸이 폭증하므로 CSV 단위로 한 번에 변환해 쓴다.
#   순서 주의: & 를 먼저 바꿔야 뒤에 만든 &lt; 가 다시 변환되지 않는다.
# ------------------------------------------------------------------------------
html_escape_csv() {
    # $1 = 원본 CSV 경로 / stdout = 이스케이프된 내용
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$1"
}

esc_csv() {
    # $1 = 원본 CSV 경로 → 이스케이프 사본 경로를 echo
    _ec_out="$(tmpf "esc_$(basename "$1")")"
    html_escape_csv "$1" > "$_ec_out" 2>/dev/null || cp "$1" "$_ec_out" 2>/dev/null
    echo "$_ec_out"
}

find_latest_csv() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _fc
    _fc_pat="$1"
    _fc_found=""
    for _fc in $_fc_pat; do
        [ -e "$_fc" ] || continue
        _fc_found="$_fc"
    done
    echo "$_fc_found"
}

# ------------------------------------------------------------------------------
# [NEW v08.03] 사전 검증(Pre-flight) 결과를 HTML 보고서 섹션으로 추가
# ------------------------------------------------------------------------------
html_append_preflight_section() {
    # [v09.02] local 제거 (ksh 비호환): _hp_src _hp_file _hp_uid _hp_csv _hp_ok _hp_warn _hp_fail _hp_tag
    _hp_file="$1"
    _hp_uid="$2"

    _hp_csv=$(find_latest_csv "./preflight_result_${_hp_uid}*.csv")
    [ -z "$_hp_csv" ] && _hp_csv=$(find_latest_csv "./preflight_result_*.csv")
    [ -z "$_hp_csv" ] && return 0
    [ -s "$_hp_csv" ] || return 0

    # [FIX v08.04] 표시용 원본 파일명을 먼저 확보한 뒤, 읽기는 이스케이프 사본으로 한다.
    _hp_src="$(basename "$_hp_csv")"
    _hp_csv="$(esc_csv "$_hp_csv")"

    _hp_ok=0; _hp_warn=0; _hp_fail=0
    while IFS='|' read -r _c _i _st _d; do
        [ -z "$_i" ] && continue
        case "$_st" in
            OK)   _hp_ok=$((_hp_ok + 1)) ;;
            WARN) _hp_warn=$((_hp_warn + 1)) ;;
            FAIL) _hp_fail=$((_hp_fail + 1)) ;;
        esac
    done < "$_hp_csv"

    cat <<EOF >> "$_hp_file"

  <div class="section-title"><span>Pre-flight Requirement Verification</span></div>
  <p class="subnote">이관 실행 전에 수행한 환경 점검 결과입니다. 바이너리 · Directory 쓰기권한 · 용량 · 버전 호환성 · 문자셋 확장 위험을 확인합니다. (source: ${_hp_src})</p>

  <div class="grid">
    <div class="card success"><div class="label">Passed</div><div class="val">${_hp_ok}</div></div>
    <div class="card $([ "$_hp_warn" -gt 0 ] && echo 'warning' || echo 'success')"><div class="label">Warnings</div><div class="val">${_hp_warn}</div></div>
    <div class="card $([ "$_hp_fail" -gt 0 ] && echo 'danger' || echo 'success')"><div class="label">Blocking Issues</div><div class="val">${_hp_fail}</div></div>
  </div>

  <table>
    <thead><tr><th>Category</th><th>Item</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>
EOF

    while IFS='|' read -r _c _i _st _d; do
        [ -z "$_i" ] && continue
        case "$_st" in
            OK)   _hp_tag='<span class="tag pass">OK</span>' ;;
            WARN) _hp_tag='<span class="tag diff">WARN</span>' ;;
            FAIL) _hp_tag='<span class="tag error">FAIL</span>' ;;
            *)    _hp_tag='<span class="tag info">INFO</span>' ;;
        esac
        echo "      <tr><td>${_c}</td><td><strong>${_i}</strong></td><td>${_hp_tag}</td><td>${_d}</td></tr>" >> "$_hp_file"
    done < "$_hp_csv"

    cat <<EOF >> "$_hp_file"
    </tbody>
  </table>
EOF
    # [NEW v08.03] 결과가 깨끗할 때만 체크리스트를 자동 체크한다.
    #   존재 여부가 아니라 실제 판정으로 결정 — FAIL/WARN 을 "확인됨"으로 표시하면
    #   DBA 가 미조치 항목을 통과한 것으로 오인한다.
    if [ "$_hp_fail" -gt 0 ]; then
        PREFLIGHT_CSV_STATUS="FAIL"
    elif [ "$_hp_warn" -gt 0 ]; then
        PREFLIGHT_CSV_STATUS="WARN"
    else
        PREFLIGHT_CSV_STATUS="PASS"
    fi
    return 0
}

# ------------------------------------------------------------------------------
# [NEW v08.03] 덤프 MD5 무결성 검증 결과를 HTML 보고서 섹션으로 추가
# ------------------------------------------------------------------------------
html_append_checksum_section() {
    # [v09.02] local 제거 (ksh 비호환): _hc_src _hc_file _hc_uid _hc_csv _hc_ok _hc_bad _hc_total _hc_tag
    _hc_file="$1"
    _hc_uid="$2"

    _hc_csv=$(find_latest_csv "./checksum_result_${_hc_uid}*.csv")
    [ -z "$_hc_csv" ] && _hc_csv=$(find_latest_csv "./checksum_result_*.csv")
    [ -z "$_hc_csv" ] && return 0
    [ -s "$_hc_csv" ] || return 0

    # [FIX v08.04] 표시용 원본 파일명을 먼저 확보한 뒤, 읽기는 이스케이프 사본으로 한다.
    _hc_src="$(basename "$_hc_csv")"
    _hc_csv="$(esc_csv "$_hc_csv")"

    _hc_ok=0; _hc_bad=0; _hc_total=0
    while IFS='|' read -r _f _e _a _st; do
        [ -z "$_f" ] && continue
        _hc_total=$((_hc_total + 1))
        if [ "$_st" = "MATCH" ]; then _hc_ok=$((_hc_ok + 1)); else _hc_bad=$((_hc_bad + 1)); fi
    done < "$_hc_csv"

    cat <<EOF >> "$_hc_file"

  <div class="section-title"><span>Dump File Integrity (MD5)</span></div>
  <p class="subnote">Source 에서 생성한 체크섬 매니페스트와 Target 에 도착한 덤프 파일을 대조한 결과입니다. 전송 중 손상을 impdp 이전에 잡아냅니다. (source: ${_hc_src})</p>

  <div class="grid">
    <div class="card info"><div class="label">Dump Files</div><div class="val">${_hc_total}</div></div>
    <div class="card success"><div class="label">Verified</div><div class="val">${_hc_ok}</div></div>
    <div class="card $([ "$_hc_bad" -gt 0 ] && echo 'danger' || echo 'success')"><div class="label">Corrupted / Missing</div><div class="val">${_hc_bad}</div></div>
  </div>

  <table>
    <thead><tr><th>File</th><th>Expected MD5</th><th>Actual MD5</th><th>Status</th></tr></thead>
    <tbody>
EOF

    while IFS='|' read -r _f _e _a _st; do
        [ -z "$_f" ] && continue
        case "$_st" in
            MATCH)    _hc_tag='<span class="tag match">MATCH</span>' ;;
            MISSING)  _hc_tag='<span class="tag missing">MISSING</span>' ;;
            *)        _hc_tag='<span class="tag mismatch">MISMATCH</span>' ;;
        esac
        echo "      <tr><td><strong>${_f}</strong></td><td><code>${_e}</code></td><td><code>${_a}</code></td><td>${_hc_tag}</td></tr>" >> "$_hc_file"
    done < "$_hc_csv"

    cat <<EOF >> "$_hc_file"
    </tbody>
  </table>
EOF
    # [NEW v08.03] 불일치/누락이 하나라도 있으면 자동 체크하지 않는다.
    if [ "$_hc_bad" -gt 0 ]; then
        CHECKSUM_CSV_STATUS="FAIL"
        CHECKSUM_BAD_CNT="$_hc_bad"
    else
        CHECKSUM_CSV_STATUS="PASS"
        CHECKSUM_BAD_CNT="0"
    fi
    return 0
}

html_append_deepdiff_section() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _hd_src _hd_csv _no
    _hd_file="$1"
    _hd_uid="$2"

    _hd_csv=$(find_latest_csv "./deepdiff_result_${_hd_uid}*.csv")
    [ -z "$_hd_csv" ] && _hd_csv=$(find_latest_csv "./deepdiff_result_*.csv")
    [ -z "$_hd_csv" ] && return 0
    [ -s "$_hd_csv" ] || return 0

    # [FIX v08.04] 표시용 원본 파일명을 먼저 확보한 뒤, 읽기는 이스케이프 사본으로 한다.
    _hd_src="$(basename "$_hd_csv")"
    _hd_csv="$(esc_csv "$_hd_csv")"

    _hd_must_fail=0
    _hd_err=0
    _hd_pass=0
    _hd_total=0
    while IFS='|' read -r _no _name _cat _sev _a _t _at _ta _st _msg; do
        [ -z "$_name" ] && continue
        _hd_total=$((_hd_total + 1))
        case "$_st" in
            PASS)  _hd_pass=$((_hd_pass + 1)) ;;
            ERROR) _hd_err=$((_hd_err + 1)) ;;
        esac
        # [FIX v08.06] 위반과 비교실패를 분리해 센다.
        #   기존에는 MUST_MATCH + (PASS 아님) 으로 세어, ERROR 행 하나가
        #   "위반"과 "비교실패" 양쪽에 잡혀 문제가 2건인 것처럼 보였다.
        #   ERROR 는 "다르다"가 아니라 "확인하지 못했다"이므로 별도로 둔다.
        if [ "$_sev" = "MUST_MATCH" ] && [ "$_st" = "DIFF" ]; then
            _hd_must_fail=$((_hd_must_fail + 1))
        fi
    done < "$_hd_csv"

    if [ "$_hd_must_fail" -gt 0 ]; then _hd_card="danger"; else _hd_card="success"; fi

    # [FIX v08.06] 체크리스트 자동 체크 판정용으로 결과를 내보낸다.
    #   MUST_MATCH 위반이 있거나 비교 자체가 ERROR 로 끝났으면 "확인됨"이 아니다.
    #   INFORMATIONAL 차이는 정상 이관에서도 발생하므로 판정에 넣지 않는다.
    DEEP_DIFF_BAD_CNT="$_hd_must_fail"
    DEEP_DIFF_ERR_CNT="$_hd_err"
    if [ "$_hd_must_fail" -gt 0 ] || [ "$_hd_err" -gt 0 ]; then
        DEEP_DIFF_STATUS="FAIL"
    else
        DEEP_DIFF_STATUS="PASS"
    fi

    cat <<EOF >> "$_hd_file"

  <div class="section-title"><span>Dictionary Deep Diff (ASIS &harr; TOBE)</span></div>
  <p class="subnote">Data Pump 로그로는 알 수 없는 권한 · 프로파일 · 쿼터 · 시노님 · DB Link · 제약 · 시퀀스를 양방향 MINUS 로 대조한 결과입니다. <strong>MUST_MATCH</strong> 는 정상 이관이면 반드시 일치해야 하는 항목, <strong>INFORMATIONAL</strong> 은 정상 이관에서도 차이가 나는 참고 항목입니다. (source: ${_hd_src})</p>

  <div class="grid">
    <div class="card info"><div class="label">Compared Items</div><div class="val">${_hd_total}</div></div>
    <div class="card success"><div class="label">Passed</div><div class="val">${_hd_pass}</div></div>
    <div class="card ${_hd_card}"><div class="label">MUST_MATCH Violations</div><div class="val">${_hd_must_fail}</div></div>
    <div class="card $([ "$_hd_err" -gt 0 ] && echo 'danger' || echo 'success')"><div class="label">Comparison Errors</div><div class="val">${_hd_err}</div></div>
  </div>

  <table>
    <thead><tr>
      <th>#</th><th>Entry</th><th>Category</th><th>Severity</th>
      <th>ASIS</th><th>TOBE</th><th>A&minus;T</th><th>T&minus;A</th><th>Status</th><th>Detail</th>
    </tr></thead>
    <tbody>
EOF

    while IFS='|' read -r _no _name _cat _sev _a _t _at _ta _st _msg; do
        [ -z "$_name" ] && continue
        case "$_st" in
            PASS)  _tag='<span class="tag pass">PASS</span>' ;;
            DIFF)  _tag='<span class="tag diff">DIFF</span>' ;;
            ERROR) _tag='<span class="tag error">ERROR</span>' ;;
            *)     _tag="<span class=\"tag info\">${_st}</span>" ;;
        esac
        if [ "$_sev" = "MUST_MATCH" ]; then
            _sevtag='<span class="tag must">MUST</span>'
        else
            _sevtag='<span class="tag info">INFO</span>'
        fi
        echo "      <tr><td>${_no}</td><td><strong>${_name}</strong></td><td>${_cat}</td><td>${_sevtag}</td><td>${_a}</td><td>${_t}</td><td>${_at}</td><td>${_ta}</td><td>${_tag}</td><td>${_msg}</td></tr>" >> "$_hd_file"
    done < "$_hd_csv"

    cat <<EOF >> "$_hd_file"
    </tbody>
  </table>
EOF
    return 0
}

# ------------------------------------------------------------------------------
# [NEW v08] 실측 행 건수 대조 결과를 HTML 보고서 섹션으로 추가
# ------------------------------------------------------------------------------
html_append_rowcount_section() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _hr_src _hr_bad _hr_csv _hr_total _own
    _hr_file="$1"
    _hr_uid="$2"

    _hr_csv=$(find_latest_csv "./rowcount_result_${_hr_uid}*.csv")
    [ -z "$_hr_csv" ] && _hr_csv=$(find_latest_csv "./rowcount_result_*.csv")
    [ -z "$_hr_csv" ] && return 0
    [ -s "$_hr_csv" ] || return 0

    # [FIX v08.04] 표시용 원본 파일명을 먼저 확보한 뒤, 읽기는 이스케이프 사본으로 한다.
    _hr_src="$(basename "$_hr_csv")"
    _hr_csv="$(esc_csv "$_hr_csv")"

    _hr_match=0; _hr_bad=0; _hr_total=0
    while IFS='|' read -r _own _tab _ac _tc _df _st; do
        [ -z "$_tab" ] && continue
        _hr_total=$((_hr_total + 1))
        if [ "$_st" = "MATCH" ]; then _hr_match=$((_hr_match + 1)); else _hr_bad=$((_hr_bad + 1)); fi
    done < "$_hr_csv"

    # [FIX v08.06] 체크리스트 자동 체크 판정용
    ROWCOUNT_BAD_CNT="$_hr_bad"
    if [ "$_hr_bad" -gt 0 ]; then ROWCOUNT_STATUS="FAIL"; else ROWCOUNT_STATUS="PASS"; fi

    cat <<EOF >> "$_hr_file"

  <div class="section-title"><span>Actual Row Count Verification (COUNT(*) based)</span></div>
  <p class="subnote">Data Pump 로그가 아닌 양쪽 DB 의 실제 <code>COUNT(*)</code> 결과입니다. 임포트 이후 데이터가 변경된 경우까지 잡아냅니다. 아래 표에는 <strong>불일치/누락 항목만</strong> 표시됩니다. (source: ${_hr_src})</p>

  <div class="grid">
    <div class="card info"><div class="label">Tables Compared</div><div class="val">${_hr_total}</div></div>
    <div class="card success"><div class="label">Exact Match</div><div class="val">${_hr_match}</div></div>
    <div class="card $([ "$_hr_bad" -gt 0 ] && echo 'danger' || echo 'success')"><div class="label">Mismatch / Missing</div><div class="val">${_hr_bad}</div></div>
  </div>
EOF

    if [ "$_hr_bad" -eq 0 ]; then
        cat <<EOF >> "$_hr_file"
  <div class="log-box">모든 테이블의 실측 건수가 일치합니다.</div>
EOF
        return 0
    fi

    cat <<EOF >> "$_hr_file"
  <table>
    <thead><tr><th>Owner</th><th>Table</th><th>ASIS Count</th><th>TOBE Count</th><th>Diff</th><th>Status</th></tr></thead>
    <tbody>
EOF
    while IFS='|' read -r _own _tab _ac _tc _df _st; do
        [ -z "$_tab" ] && continue
        [ "$_st" = "MATCH" ] && continue
        case "$_st" in
            MISSING_IN_TOBE) _rtag='<span class="tag missing">MISSING</span>' ;;
            ONLY_IN_TOBE)    _rtag='<span class="tag added">ADDED</span>' ;;
            *)               _rtag='<span class="tag mismatch">MISMATCH</span>' ;;
        esac
        echo "      <tr><td>${_own}</td><td><strong>${_tab}</strong></td><td>${_ac}</td><td>${_tc}</td><td>${_df}</td><td>${_rtag}</td></tr>" >> "$_hr_file"
    done < "$_hr_csv"

    cat <<EOF >> "$_hr_file"
    </tbody>
  </table>
EOF
    return 0
}

# ------------------------------------------------------------------------------
# [NEW v08.03] 파티션 단위 실측 건수 결과를 HTML 보고서 섹션으로 추가
#   파티션 단위 수집을 켠 경우에만 CSV 가 생성되므로, 없으면 조용히 건너뛴다.
# ------------------------------------------------------------------------------
html_append_rowcount_part_section() {
    # [v09.02] local 제거 (ksh 비호환): _hq_src _hq_file _hq_uid _hq_csv _hq_match _hq_bad _hq_total _hq_tag
    # [v09.02] local 제거 (ksh 비호환): _own _hq_tab _prt _hq_ac _hq_tc _hq_df _hq_st
    _hq_file="$1"
    _hq_uid="$2"

    _hq_csv=$(find_latest_csv "./rowcount_part_result_${_hq_uid}*.csv")
    [ -z "$_hq_csv" ] && _hq_csv=$(find_latest_csv "./rowcount_part_result_*.csv")
    [ -z "$_hq_csv" ] && return 0
    [ -s "$_hq_csv" ] || return 0

    # [FIX v08.04] 표시용 원본 파일명을 먼저 확보한 뒤, 읽기는 이스케이프 사본으로 한다.
    _hq_src="$(basename "$_hq_csv")"
    _hq_csv="$(esc_csv "$_hq_csv")"

    _hq_match=0; _hq_bad=0; _hq_total=0
    while IFS='|' read -r _own _hq_tab _prt _hq_ac _hq_tc _hq_df _hq_st; do
        [ -z "$_prt" ] && continue
        _hq_total=$((_hq_total + 1))
        if [ "$_hq_st" = "MATCH" ]; then _hq_match=$((_hq_match + 1)); else _hq_bad=$((_hq_bad + 1)); fi
    done < "$_hq_csv"

    [ "$_hq_total" -eq 0 ] && return 0

    cat <<EOF >> "$_hq_file"

  <div class="section-title"><span>Partition / Subpartition Row Count Verification</span></div>
  <p class="subnote">파티션(또는 서브파티션) 단위 실측 건수 대조입니다. 테이블 총계는 일치하지만 파티션 경계가 어긋난 경우(파티션 키 매핑 오류로 데이터가 인접 파티션에 적재된 경우)를 잡아냅니다. 서브파티션 단위로 수집한 경우 <code>파티션/서브파티션</code> 형태로 표시됩니다. 아래 표에는 <strong>불일치/누락 항목만</strong> 표시됩니다. (source: ${_hq_src})</p>

  <div class="grid">
    <div class="card info"><div class="label">Grains Compared</div><div class="val">${_hq_total}</div></div>
    <div class="card success"><div class="label">Exact Match</div><div class="val">${_hq_match}</div></div>
    <div class="card $([ "$_hq_bad" -gt 0 ] && echo 'danger' || echo 'success')"><div class="label">Mismatch / Missing</div><div class="val">${_hq_bad}</div></div>
  </div>
EOF

    if [ "$_hq_bad" -eq 0 ]; then
        cat <<EOF >> "$_hq_file"
  <div class="log-box">모든 파티션의 실측 건수가 일치합니다.</div>
EOF
        ROWCOUNT_PART_STATUS="PASS"
        return 0
    fi

    ROWCOUNT_PART_STATUS="FAIL"
    cat <<EOF >> "$_hq_file"
  <table>
    <thead><tr><th>Owner</th><th>Table</th><th>Partition / Subpartition</th><th>ASIS Count</th><th>TOBE Count</th><th>Diff</th><th>Status</th></tr></thead>
    <tbody>
EOF
    while IFS='|' read -r _own _hq_tab _prt _hq_ac _hq_tc _hq_df _hq_st; do
        [ -z "$_prt" ] && continue
        [ "$_hq_st" = "MATCH" ] && continue
        case "$_hq_st" in
            MISSING_IN_TOBE) _hq_tag='<span class="tag missing">MISSING</span>' ;;
            ONLY_IN_TOBE)    _hq_tag='<span class="tag added">ADDED</span>' ;;
            *)               _hq_tag='<span class="tag mismatch">MISMATCH</span>' ;;
        esac
        echo "      <tr><td>${_own}</td><td><strong>${_hq_tab}</strong></td><td><code>${_prt}</code></td><td>${_hq_ac}</td><td>${_hq_tc}</td><td>${_hq_df}</td><td>${_hq_tag}</td></tr>" >> "$_hq_file"
    done < "$_hq_csv"

    cat <<EOF >> "$_hq_file"
    </tbody>
  </table>
EOF
    return 0
}

# ------------------------------------------------------------------------------
# [NEW v09.00] 해시 대조 결과를 HTML 보고서 섹션으로 추가
# ------------------------------------------------------------------------------
html_append_hash_section() {
    # [v09.02] local 제거 (ksh 비호환): _hh_src _hh_file _hh_uid _hh_csv _hh_match _hh_bad _hh_total _hh_tag _hh_skip
    # [v09.02] local 제거 (ksh 비호환): _own _hh_tab _ar _tr _ah _th _sk _hh_st
    _hh_file="$1"
    _hh_uid="$2"

    _hh_csv=$(find_latest_csv "./hash_result_${_hh_uid}*.csv")
    [ -z "$_hh_csv" ] && _hh_csv=$(find_latest_csv "./hash_result_*.csv")
    [ -z "$_hh_csv" ] && return 0
    [ -s "$_hh_csv" ] || return 0

    _hh_src="$(basename "$_hh_csv")"
    _hh_csv="$(esc_csv "$_hh_csv")"

    _hh_match=0; _hh_bad=0; _hh_total=0; _hh_skip=0
    while IFS='|' read -r _own _hh_tab _ar _tr _ah _th _sk _hh_st; do
        [ -z "$_hh_tab" ] && continue
        _hh_total=$((_hh_total + 1))
        if [ "$_hh_st" = "MATCH" ]; then _hh_match=$((_hh_match + 1)); else _hh_bad=$((_hh_bad + 1)); fi
        case "$_sk" in ''|0) : ;; *) _hh_skip=$((_hh_skip + 1)) ;; esac
    done < "$_hh_csv"

    [ "$_hh_total" -eq 0 ] && return 0

    HASH_BAD_CNT="$_hh_bad"
    if [ "$_hh_bad" -gt 0 ]; then HASH_STATUS="FAIL"; else HASH_STATUS="PASS"; fi

    cat <<EOF >> "$_hh_file"

  <div class="section-title"><span>Row Content Hash Verification</span></div>
  <p class="subnote">건수가 같아도 <strong>값이 바뀐 경우</strong>를 잡습니다. 행마다 해시를 구해 순서에 무관한 <code>SUM / MIN / MAX</code> 로 집계하고 건수까지 네 값을 대조합니다. 문자형 컬럼은 <code>CONVERT(col,'AL32UTF8')</code> 로 정규화하므로 문자셋이 바뀐 이관에서도 유효합니다. <strong>LOB · LONG · XMLType 은 해시 대상이 아닙니다</strong> — 해당 컬럼의 내용은 이 검증으로 확인되지 않습니다. (source: ${_hh_src})</p>

  <div class="grid">
    <div class="card info"><div class="label">Tables Hashed</div><div class="val">${_hh_total}</div></div>
    <div class="card success"><div class="label">Hash Match</div><div class="val">${_hh_match}</div></div>
    <div class="card $([ "$_hh_bad" -gt 0 ] && echo 'danger' || echo 'success')"><div class="label">Mismatch</div><div class="val">${_hh_bad}</div></div>
    <div class="card $([ "$_hh_skip" -gt 0 ] && echo 'warning' || echo 'success')"><div class="label">Tables w/ Skipped Cols</div><div class="val">${_hh_skip}</div></div>
  </div>
EOF

    if [ "$_hh_bad" -eq 0 ]; then
        cat <<EOF >> "$_hh_file"
  <div class="log-box">모든 테이블의 행 내용 해시가 일치합니다.</div>
EOF
        return 0
    fi

    cat <<EOF >> "$_hh_file"
  <table>
    <thead><tr><th>Owner</th><th>Table</th><th>ASIS Rows</th><th>TOBE Rows</th><th>Skipped Cols</th><th>Status</th></tr></thead>
    <tbody>
EOF
    while IFS='|' read -r _own _hh_tab _ar _tr _ah _th _sk _hh_st; do
        [ -z "$_hh_tab" ] && continue
        [ "$_hh_st" = "MATCH" ] && continue
        case "$_hh_st" in
            MISSING_IN_TOBE)   _hh_tag='<span class="tag missing">MISSING</span>' ;;
            ONLY_IN_TOBE)      _hh_tag='<span class="tag added">ADDED</span>' ;;
            COLUMN_MISMATCH)   _hh_tag='<span class="tag error">COLUMN DIFF</span>' ;;
            ROWCOUNT_MISMATCH) _hh_tag='<span class="tag mismatch">ROWCOUNT</span>' ;;
            *)                 _hh_tag='<span class="tag mismatch">DATA DIFF</span>' ;;
        esac
        echo "      <tr><td>${_own}</td><td><strong>${_hh_tab}</strong></td><td>${_ar}</td><td>${_tr}</td><td>${_sk}</td><td>${_hh_tag}</td></tr>" >> "$_hh_file"
    done < "$_hh_csv"

    cat <<EOF >> "$_hh_file"
    </tbody>
  </table>
EOF
    return 0
}

# ------------------------------------------------------------------------------
# [NEW v08.03] 체크리스트 자동 체크 판정 헬퍼
#   CSV 가 "존재하는가" 가 아니라 "결과가 깨끗한가" 로 체크 여부를 정한다.
#   FAIL/WARN 인데 체크된 채로 출력하면 DBA 가 미조치 항목을 통과로 오인한다.
# ------------------------------------------------------------------------------
pf_check_attr() {
    [ "$PREFLIGHT_CSV_STATUS" = "PASS" ] && echo "checked disabled"
    return 0
}
pf_check_note() {
    case "$PREFLIGHT_CSV_STATUS" in
        PASS) echo '<em style="color:#94a3b8">(자동 확인됨)</em>' ;;
        WARN) echo '<em style="color:#f59e0b">(경고 항목 있음 - 위 Pre-flight 표 확인 필요)</em>' ;;
        FAIL) echo '<em style="color:#ef4444">(치명 항목 있음 - 조치 전 이관 금지)</em>' ;;
    esac
    return 0
}
cs_check_attr() {
    [ "$CHECKSUM_CSV_STATUS" = "PASS" ] && echo "checked disabled"
    return 0
}
dd_check_attr() {
    [ "$DEEP_DIFF_STATUS" = "PASS" ] && echo "checked disabled"
    return 0
}
dd_check_note() {
    case "$DEEP_DIFF_STATUS" in
        PASS) echo '<em style="color:#94a3b8">(DEEP DIFF 로 자동 확인됨)</em>' ;;
        FAIL)
            if [ "${DEEP_DIFF_ERR_CNT:-0}" -gt 0 ] && [ "${DEEP_DIFF_BAD_CNT:-0}" -gt 0 ]; then
                echo "<em style=\"color:#ef4444\">(MUST_MATCH 위반 ${DEEP_DIFF_BAD_CNT}건 / 비교실패 ${DEEP_DIFF_ERR_CNT}건 - 위 표 확인)</em>"
            elif [ "${DEEP_DIFF_ERR_CNT:-0}" -gt 0 ]; then
                echo "<em style=\"color:#ef4444\">(비교 실패 ${DEEP_DIFF_ERR_CNT}건 - 확인되지 않음)</em>"
            else
                echo "<em style=\"color:#ef4444\">(MUST_MATCH 위반 ${DEEP_DIFF_BAD_CNT}건 - 조치 필요)</em>"
            fi
            ;;
    esac
    return 0
}
rc_check_attr() {
    [ "$ROWCOUNT_STATUS" = "PASS" ] && echo "checked disabled"
    return 0
}
rc_check_note() {
    case "$ROWCOUNT_STATUS" in
        PASS) echo '<em style="color:#94a3b8">(ROW COUNT)</em>' ;;
        FAIL) echo "<em style=\"color:#ef4444\">(불일치/누락 ${ROWCOUNT_BAD_CNT}건 - 조치 필요)</em>" ;;
    esac
    return 0
}
hs_check_line() {
    case "$HASH_STATUS" in
        PASS) printf '%s\n' '    <div class="checklist-item"><input type="checkbox" checked disabled> <span>Row Content Hash Verification Passed <em style="color:#94a3b8">(자동 확인됨)</em></span></div>' ;;
        FAIL) printf '%s\n' "    <div class=\"checklist-item\"><input type=\"checkbox\" > <span>Row Content Hash Verification Passed <em style=\"color:#ef4444\">(해시 불일치 ${HASH_BAD_CNT}건 - 조치 필요)</em></span></div>" ;;
    esac
    return 0
}
rc_part_check_line() {
    case "$ROWCOUNT_PART_STATUS" in
        PASS) printf '%s\n' '    <div class="checklist-item"><input type="checkbox" checked disabled> <span>Partition-Level Row Count Verified <em style="color:#94a3b8">(자동 확인됨)</em></span></div>' ;;
        FAIL) printf '%s\n' '    <div class="checklist-item"><input type="checkbox" > <span>Partition-Level Row Count Verified <em style="color:#ef4444">(파티션 불일치 있음 - 위 표 확인 필요)</em></span></div>' ;;
    esac
    return 0
}
cs_check_note() {
    case "$CHECKSUM_CSV_STATUS" in
        PASS) echo '<em style="color:#94a3b8">(자동 확인됨)</em>' ;;
        FAIL) echo "<em style=\"color:#ef4444\">(불일치/누락 ${CHECKSUM_BAD_CNT}건 - 재전송 필요)</em>" ;;
    esac
    return 0
}

# HTML 종합 마이그레이션 감사 보고서 생성 함수
generate_html_audit_report() {
    _rep_exp_log="$1"
    _rep_imp_log="$2"
    _rep_uid="$3"
    _rep_exp_tmp="$4"
    _rep_imp_tmp="$5"
    _rep_matches="$6"
    _rep_mismatches="$7"
    
    HTML_REPORT="migration_audit_report_${_rep_uid}.html"
    echo "  * 생성 중: $HTML_REPORT (HTML 종합 감사 보고서)"

    _total_tbls=$((_rep_matches + _rep_mismatches))
    _match_rate=100
    if [ "$_total_tbls" -gt 0 ]; then
        _match_rate=$(( (_rep_matches * 100) / _total_tbls ))
    fi

    cat <<EOF > "$HTML_REPORT"
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oracle Data Pump Migration Audit Report - ${_rep_uid}</title>
<style>
  :root {
    --bg: #0f172a;
    --card-bg: #1e293b;
    --card-border: #334155;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent: #38bdf8;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Pretendard', sans-serif; }
  body { background-color: var(--bg); color: var(--text-primary); padding: 30px; line-height: 1.5; }
  .container { max-width: 1200px; margin: 0 auto; }
  .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--card-border); padding-bottom: 20px; margin-bottom: 25px; }
  .header h1 { font-size: 24px; color: var(--text-primary); font-weight: 700; }
  .header .badge { background: #0284c7; padding: 6px 14px; border-radius: 20px; font-size: 13px; font-weight: 600; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-bottom: 25px; }
  .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 18px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
  .card .label { font-size: 13px; color: var(--text-secondary); margin-bottom: 6px; }
  .card .val { font-size: 26px; font-weight: 700; color: var(--text-primary); }
  .card.success .val { color: var(--success); }
  .card.warning .val { color: var(--warning); }
  .card.danger .val { color: var(--danger); }
  .card.info .val { color: var(--accent); }
  .section-title { font-size: 18px; margin: 25px 0 12px 0; color: var(--text-primary); display: flex; align-items: center; justify-content: space-between; }
  .controls { display: flex; gap: 10px; margin-bottom: 12px; }
  .search-box { background: var(--card-bg); border: 1px solid var(--card-border); color: #fff; padding: 8px 14px; border-radius: 8px; font-size: 14px; width: 280px; }
  .filter-btn { background: var(--card-bg); border: 1px solid var(--card-border); color: var(--text-secondary); padding: 8px 14px; border-radius: 8px; cursor: pointer; font-size: 13px; }
  .filter-btn.active { background: #0284c7; color: #fff; border-color: #0284c7; }
  table { width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 10px; overflow: hidden; border: 1px solid var(--card-border); margin-bottom: 25px; }
  th, td { padding: 12px 16px; text-align: left; font-size: 14px; }
  th { background: #1e293b; color: var(--text-secondary); font-weight: 600; border-bottom: 1px solid var(--card-border); }
  tr:not(:last-child) td { border-bottom: 1px solid #334155; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .tag { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; }
  .tag.match { background: rgba(16,185,129,0.15); color: var(--success); }
  .tag.mismatch { background: rgba(245,158,11,0.15); color: var(--warning); }
  .tag.missing { background: rgba(239,68,68,0.15); color: var(--danger); }
  .tag.added { background: rgba(56,189,248,0.15); color: var(--accent); }
  .tag.pass { background: rgba(16,185,129,0.15); color: var(--success); }
  .tag.diff { background: rgba(245,158,11,0.15); color: var(--warning); }
  .tag.error { background: rgba(239,68,68,0.20); color: var(--danger); font-weight:700; }
  .tag.must { background: rgba(148,163,184,0.18); color: #e2e8f0; }
  .tag.info { background: rgba(148,163,184,0.10); color: var(--text-secondary); }
  .subnote { color: var(--text-secondary); font-size: 13px; margin: -4px 0 12px 0; }
  .log-box { background: #090d16; border: 1px solid var(--card-border); border-radius: 8px; padding: 14px; font-family: monospace; font-size: 13px; color: #cbd5e1; max-height: 250px; overflow-y: auto; white-space: pre-wrap; margin-bottom: 25px; }
  .checklist { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 20px; }
  .checklist-item { display: flex; align-items: center; gap: 10px; padding: 8px 0; font-size: 14px; border-bottom: 1px solid #334155; }
  .checklist-item:last-child { border-bottom: none; }
  .footer { text-align: center; color: var(--text-secondary); font-size: 13px; margin-top: 40px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>Oracle Data Migration Audit Report</h1>
      <p style="color:var(--text-secondary);font-size:13px;margin-top:4px;">Migration Job ID: <strong>${_rep_uid}</strong> | Generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
    </div>
    <div class="badge">v${SCRIPT_VERSION} Multitenant Edition</div>
  </div>

  <div class="grid">
    <div class="card info">
      <div class="label">Total Migrated Tables</div>
      <div class="val">${_total_tbls}</div>
    </div>
    <div class="card success">
      <div class="label">Matched Tables (100% Exact)</div>
      <div class="val">${_rep_matches}</div>
    </div>
    <div class="card $([ $_rep_mismatches -gt 0 ] && echo 'danger' || echo 'success')">
      <div class="label">Mismatches / Missing</div>
      <div class="val">${_rep_mismatches}</div>
    </div>
    <div class="card $([ $_match_rate -eq 100 ] && echo 'success' || echo 'warning')">
      <div class="label">Row Consistency Rate</div>
      <div class="val">${_match_rate}%</div>
    </div>
  </div>

  <div class="section-title">
    <span>Table Row Count Verification Matrix</span>
    <div class="controls">
      <input type="text" id="searchInput" class="search-box" placeholder="Search table name..." onkeyup="filterTable()">
      <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
      <button class="filter-btn" onclick="setFilter('match', this)">Matches</button>
      <button class="filter-btn" onclick="setFilter('diff', this)">Differences</button>
    </div>
  </div>

  <table id="dataTable">
    <thead>
      <tr>
        <th>Table Name</th>
        <th>Export Row Count</th>
        <th>Import Row Count</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
EOF

    if [ -f "$_rep_exp_tmp" ] && [ -f "$_rep_imp_tmp" ]; then
        while IFS=, read -r tbl exp_cnt; do
            imp_cnt=$(grep "^${tbl}," "$_rep_imp_tmp" | cut -d',' -f2)
            if [ -z "$imp_cnt" ]; then
                tbl_only=$(echo "$tbl" | cut -d'.' -f2)
                imp_match_line=$(grep "\.${tbl_only}," "$_rep_imp_tmp" | head -n 1)
                if [ -n "$imp_match_line" ]; then
                    imp_cnt=$(echo "$imp_match_line" | cut -d',' -f2)
                    tbl_mapped=$(echo "$imp_match_line" | cut -d',' -f1)
                    tbl="$tbl -> $tbl_mapped"
                fi
            fi

            if [ -z "$imp_cnt" ]; then
                echo "      <tr data-status=\"missing\"><td><strong>$tbl</strong></td><td>$exp_cnt</td><td>N/A</td><td><span class=\"tag missing\">MISSING</span></td></tr>" >> "$HTML_REPORT"
            elif [ "$exp_cnt" = "$imp_cnt" ]; then
                echo "      <tr data-status=\"match\"><td><strong>$tbl</strong></td><td>$exp_cnt</td><td>$imp_cnt</td><td><span class=\"tag match\">MATCH</span></td></tr>" >> "$HTML_REPORT"
            else
                echo "      <tr data-status=\"mismatch\"><td><strong>$tbl</strong></td><td>$exp_cnt</td><td>$imp_cnt</td><td><span class=\"tag mismatch\">MISMATCH</span></td></tr>" >> "$HTML_REPORT"
            fi
        done < "$_rep_exp_tmp"

        while IFS=, read -r tbl imp_cnt; do
            if ! grep -q "^${tbl}," "$_rep_exp_tmp"; then
                tbl_only=$(echo "$tbl" | cut -d'.' -f2)
                if ! grep -q "\.${tbl_only}," "$_rep_exp_tmp"; then
                    echo "      <tr data-status=\"added\"><td><strong>$tbl</strong></td><td>N/A</td><td>$imp_cnt</td><td><span class=\"tag added\">ADDED</span></td></tr>" >> "$HTML_REPORT"
                fi
            fi
        done < "$_rep_imp_tmp"
    fi

    cat <<EOF >> "$HTML_REPORT"
    </tbody>
  </table>
EOF

    # [NEW v08] DEEP DIFF / ROW COUNT 결과 섹션 통합
    html_append_preflight_section "$HTML_REPORT" "$_rep_uid"
    html_append_checksum_section "$HTML_REPORT" "$_rep_uid"
    html_append_deepdiff_section "$HTML_REPORT" "$_rep_uid"
    html_append_rowcount_section "$HTML_REPORT" "$_rep_uid"
    html_append_rowcount_part_section "$HTML_REPORT" "$_rep_uid"
    html_append_hash_section "$HTML_REPORT" "$_rep_uid"

    cat <<EOF >> "$HTML_REPORT"
  <div class="section-title">Critical Log Errors Summary</div>
  <div class="log-box">
EOF

    _exp_errs=$(grep -E "ORA-[0-9]{5}|UDI-[0-9]{5}" "$_rep_exp_log" 2>/dev/null | grep -v "ORA-31684" | grep -v "ORA-39111" | grep -v "ORA-39151")
    _imp_errs=$(grep -E "ORA-[0-9]{5}|UDI-[0-9]{5}" "$_rep_imp_log" 2>/dev/null | grep -v "ORA-31684" | grep -v "ORA-39111" | grep -v "ORA-39151")

    if [ -n "$_exp_errs" ] || [ -n "$_imp_errs" ]; then
        if [ -n "$_exp_errs" ]; then
            echo "[expdp Errors]" >> "$HTML_REPORT"
            echo "$_exp_errs" >> "$HTML_REPORT"
            echo "" >> "$HTML_REPORT"
        fi
        if [ -n "$_imp_errs" ]; then
            echo "[impdp Errors]" >> "$HTML_REPORT"
            echo "$_imp_errs" >> "$HTML_REPORT"
        fi
    else
        echo "No critical ORA- or UDI- errors detected in migration logs." >> "$HTML_REPORT"
    fi

    cat <<EOF >> "$HTML_REPORT"
  </div>

  <div class="section-title">Pre-Cutover DBA Acceptance Checklist</div>
  <div class="checklist">
    <div class="checklist-item"><input type="checkbox" $([ "$_rep_mismatches" -eq 0 ] && echo 'checked disabled')> <span>Table Row Count Cross Verification (log based) $([ "$_rep_mismatches" -eq 0 ] && echo '<em style="color:#94a3b8">(자동 확인됨)</em>' || echo "<em style=\"color:#ef4444\">(불일치/누락 ${_rep_mismatches}건 - 위 표 확인)</em>")</span></div>
    <div class="checklist-item"><input type="checkbox"> <span>Invalid Objects Recompiled via UTLRP.SQL <em style="color:#94a3b8">(수동 확인 항목)</em></span></div>
    <div class="checklist-item"><input type="checkbox" $(pf_check_attr)> <span>Pre-flight Environment Verification $(pf_check_note)</span></div>
    <div class="checklist-item"><input type="checkbox" $(cs_check_attr)> <span>Dump File Integrity Verified (MD5) $(cs_check_note)</span></div>
    <div class="checklist-item"><input type="checkbox"> <span>Foreign Key Constraints & Triggers Re-enabled and Validated</span></div>
    <div class="checklist-item"><input type="checkbox" $(dd_check_attr)> <span>Public Synonyms &amp; Cross-Schema Grants Recreated $(dd_check_note)</span></div>
    <div class="checklist-item"><input type="checkbox" $(dd_check_attr)> <span>System / Role / Object Privileges Verified $(dd_check_note)</span></div>
    <div class="checklist-item"><input type="checkbox" $(dd_check_attr)> <span>Profiles / Tablespace Quotas Verified $(dd_check_note)</span></div>
    <div class="checklist-item"><input type="checkbox" $(rc_check_attr)> <span>Actual COUNT(*) Row Verification Passed $(rc_check_note)</span></div>
$(rc_part_check_line)
$(hs_check_line)
    <div class="checklist-item"><input type="checkbox"> <span>Database Optimizer Statistics Imported / Gathered</span></div>
    <div class="checklist-item"><input type="checkbox"> <span>Optimizer Statistics Locked (DBMS_STATS.LOCK_SCHEMA_STATS / TABLE_STATS)</span></div>
    <div class="checklist-item"><input type="checkbox"> <span>Sequence Last Numbers Synchronized</span></div>
    <div class="checklist-item"><input type="checkbox"> <span>Application Functional Acceptance Test (QA / User Sign-off)</span></div>
  </div>

  <div class="footer">
    <p>Generated automatically by Oracle Datapump Migration Helper v${SCRIPT_VERSION} (Enterprise Multitenant Edition)</p>
  </div>
</div>

<script>
let currentFilter = 'all';
function filterTable() {
  let input = document.getElementById('searchInput').value.toUpperCase();
  let tr = document.getElementById('dataTable').getElementsByTagName('tr');
  for (let i = 1; i < tr.length; i++) {
    let td = tr[i].getElementsByTagName('td')[0];
    let status = tr[i].getAttribute('data-status');
    let textValue = td ? (td.textContent || td.innerText) : '';
    let matchesSearch = textValue.toUpperCase().indexOf(input) > -1;
    let matchesFilter = true;
    if (currentFilter === 'match') matchesFilter = (status === 'match');
    else if (currentFilter === 'diff') matchesFilter = (status !== 'match');
    tr[i].style.display = (matchesSearch && matchesFilter) ? '' : 'none';
  }
}
function setFilter(type, btn) {
  currentFilter = type;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterTable();
}
</script>
</body>
</html>
EOF

    if [ "$LANG_PREF" = "EN" ]; then echo "  >> HTML Audit Report generated: $HTML_REPORT"; else echo "  >> HTML 종합 감사 보고서 생성 완료: $HTML_REPORT"; fi
}

# 3. Log Verification Mode
run_log_verify() {
    clear_screen
    echo "======================================================================"
    echo " [3] MIGRATION LOG COMPARATOR: 로그 분석 및 데이터 정합성 검증"
    echo "======================================================================"
    
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter directory path for log files [Default: .]: "
    else printf "  로그 파일이 위치한 디렉토리 경로를 입력하세요 [기본값: .]: "; fi
    _read log_dir
    [ -z "$log_dir" ] && log_dir="."
    
    if [ ! -d "$log_dir" ]; then
        echo "  [오류/ERROR] Invalid directory: $log_dir"
        printf "  - expdp log path: "; _read exp_log
        printf "  - impdp log path: "; _read imp_log
    else
        log_files_tmp="$(tmpf log_files.tmp)"
        rm -f "$log_files_tmp"
        
        (cd "$log_dir" && ls *.log 2>/dev/null) > "$log_files_tmp"
        
        log_count=0
        if [ -s "$log_files_tmp" ]; then
            echo "  --------------------------------------------------"
            if [ "$LANG_PREF" = "EN" ]; then echo "  Detected Log Files ($log_dir):"
            else echo "  감지된 로그 파일 목록 ($log_dir):"; fi
            
            while read -r f; do
                if [ -f "$log_dir/$f" ]; then
                    log_count=$((log_count + 1))
                    echo "$log_count:$f" >> "${log_files_tmp}.indexed"
                    printf "   %3d) %s\n" "$log_count" "$f"
                fi
            done < "$log_files_tmp"
            echo "  --------------------------------------------------"
        fi
        
        rm -f "$log_files_tmp"
        
        if [ $log_count -eq 0 ]; then
            echo "  [INFO] No .log files detected. Manual input required."
            printf "  - expdp log path: "; _read exp_log
            printf "  - impdp log path: "; _read imp_log
        else
            exp_log_file=""
            while [ -z "$exp_log_file" ]; do
                if [ "$LANG_PREF" = "EN" ]; then printf "  Select expdp log file (Enter Number): "
                else printf "  expdp 로그 파일을 선택하세요 (번호 입력): "; fi
                _read exp_num
                if [ -z "$exp_num" ] && [ "$UNATTENDED" = "true" ]; then
                    echo "  [무인모드] expdp 로그 선택값이 없어 1번을 사용합니다."
                    exp_num="1"
                fi
                exp_log_file=$(grep "^${exp_num}:" "${log_files_tmp}.indexed" 2>/dev/null | cut -d':' -f2)
                if [ -z "$exp_log_file" ] && [ "$UNATTENDED" = "true" ]; then
                    echo "  [무인모드/ERROR] 유효한 expdp 로그를 선택할 수 없습니다."
                    return 1
                fi
            done
            exp_log="$log_dir/$exp_log_file"
            echo "  >> Selected expdp: $exp_log_file"
            
            base_name=$(echo "$exp_log_file" | sed 's/\.log$//' | sed 's/_expdp_.*//')
            matching_imp=$(awk -F: -v base="$base_name" '$2 ~ base && ($2 ~ "_impdp_p2_data" || $2 ~ "_impdp_all") {print $2; exit}' "${log_files_tmp}.indexed" 2>/dev/null)
            if [ -z "$matching_imp" ]; then
                matching_imp=$(awk -F: -v base="$base_name" '$2 ~ base && $2 ~ "_impdp_" {print $2; exit}' "${log_files_tmp}.indexed" 2>/dev/null)
            fi
            
            imp_log_file=""
            if [ -n "$matching_imp" ]; then
                if [ "$LANG_PREF" = "EN" ]; then
                    printf "  >> Auto-detected matching impdp log: %s\n" "$matching_imp"
                    printf "     Use this file? (y/n) [Default: y]: "
                else
                    printf "  >> 매칭되는 impdp 로그 파일을 자동 감지했습니다: %s\n" "$matching_imp"
                    printf "     이 파일을 사용하시겠습니까? (y/n) [기본값: y]: "
                fi
                _read use_matching
                if [ -z "$use_matching" ] || [ "$use_matching" = "y" ] || [ "$use_matching" = "Y" ]; then imp_log_file="$matching_imp"; fi
            fi
            
            if [ -z "$imp_log_file" ]; then
                while [ -z "$imp_log_file" ]; do
                    if [ "$LANG_PREF" = "EN" ]; then printf "  Select impdp log file (Enter Number): "
                    else printf "  impdp 로그 파일을 선택하세요 (번호 입력): "; fi
                    _read imp_num
                    if [ -z "$imp_num" ] && [ "$UNATTENDED" = "true" ]; then
                        echo "  [무인모드] impdp 로그 선택값이 없어 2번을 사용합니다."
                        imp_num="2"
                    fi
                    imp_log_file=$(grep "^${imp_num}:" "${log_files_tmp}.indexed" 2>/dev/null | cut -d':' -f2)
                    if [ -z "$imp_log_file" ] && [ "$UNATTENDED" = "true" ]; then
                        echo "  [무인모드/ERROR] 유효한 impdp 로그를 선택할 수 없습니다."
                        return 1
                    fi
                done
            fi
            imp_log="$log_dir/$imp_log_file"
            echo "  >> Selected impdp: $imp_log_file"
            rm -f "${log_files_tmp}.indexed"
        fi
    fi
    
    if [ ! -f "$exp_log" ]; then echo "  [오류/ERROR] expdp log missing: $exp_log"; return 1; fi
    if [ ! -f "$imp_log" ]; then echo "  [오류/ERROR] impdp log missing: $imp_log"; return 1; fi

    echo ""
    echo "  Analyzing Log Files..."
    echo "----------------------------------------------------------------------"
    
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> expdp Error Analysis:"
    else echo "  >> expdp 에러 분석:"; fi
    exp_errs=$(grep -E "ORA-[0-9]{5}|UDI-[0-9]{5}" "$exp_log" | grep -v "ORA-31684" | grep -v "ORA-39111" | grep -v "ORA-39151")
    if [ -n "$exp_errs" ]; then echo "    [CRITICAL] Errors found:"; echo "$exp_errs"
    else echo "    [NORMAL] No severe errors detected."; fi

    echo ""
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> impdp Error Analysis (excluding collision warnings):"
    else echo "  >> impdp 에러 분석 (기존 개체 충돌 제외):"; fi
    imp_errs=$(grep -E "ORA-[0-9]{5}|UDI-[0-9]{5}" "$imp_log" | grep -v "ORA-31684" | grep -v "ORA-39111" | grep -v "ORA-39151")
    if [ -n "$imp_errs" ]; then echo "    [WARNING] Errors found:"; echo "$imp_errs"
    else echo "    [NORMAL] No severe errors detected."; fi

    echo ""
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> Table Row Count Cross Validation:"
    else echo "  >> 테이블별 이관 건수(Row Count) 교차 검증:"; fi
    
    exp_tmp="$(tmpf exp_rows.tmp)"
    imp_tmp="$(tmpf imp_rows.tmp)"

    awk '/\.\ \.\ (exported|imported)/ { line=$0; gsub(/"/, "", line); split(line, parts); tbl=""; rows=0; for (i=1; i<=NF; i++) { if (parts[i]=="exported" || parts[i]=="imported") { tbl=parts[i+1]; sub(/:.*/, "", tbl); for (j=i+2; j<=NF; j++) { if (parts[j]=="rows") { rows=parts[j-1]; gsub(/[^0-9]/, "", rows); break; } } break; } } if (tbl != "") { sum[tbl] += rows; } } END { for (t in sum) print t "," sum[t]; }' "$exp_log" | sort | uniq > "$exp_tmp"
    awk '/\.\ \.\ (exported|imported)/ { line=$0; gsub(/"/, "", line); split(line, parts); tbl=""; rows=0; for (i=1; i<=NF; i++) { if (parts[i]=="exported" || parts[i]=="imported") { tbl=parts[i+1]; sub(/:.*/, "", tbl); for (j=i+2; j<=NF; j++) { if (parts[j]=="rows") { rows=parts[j-1]; gsub(/[^0-9]/, "", rows); break; } } break; } } if (tbl != "") { sum[tbl] += rows; } } END { for (t in sum) print t "," sum[t]; }' "$imp_log" | sort | uniq > "$imp_tmp"

    if [ "$LANG_PREF" = "EN" ]; then printf "  %-38s | %-12s | %-12s | %-10s\n" "Table Name" "Exp. Count" "Imp. Count" "Status"
    else printf "  %-38s | %-12s | %-12s | %-10s\n" "테이블명 (Table)" "Export 건수" "Import 건수" "검증상태"; fi
    echo "  --------------------------------------------------------------------------------------"

    mismatches=0; matches=0
    
    while IFS=, read -r tbl exp_cnt; do
        imp_cnt=$(grep "^${tbl}," "$imp_tmp" | cut -d',' -f2)
        if [ -z "$imp_cnt" ]; then
            tbl_only=$(echo "$tbl" | cut -d'.' -f2)
            imp_match_line=$(grep "\.${tbl_only}," "$imp_tmp" | head -n 1)
            if [ -n "$imp_match_line" ]; then
                imp_cnt=$(echo "$imp_match_line" | cut -d',' -f2)
                tbl_mapped=$(echo "$imp_match_line" | cut -d',' -f1)
                tbl="$tbl -> $tbl_mapped"
            fi
        fi

        if [ -z "$imp_cnt" ]; then printf "  %-38s | %-12s | %-12s | \033[31m%-10s\033[0m\n" "$tbl" "$exp_cnt" "MISSING" "[누락]"; mismatches=$((mismatches + 1))
        elif [ "$exp_cnt" = "$imp_cnt" ]; then printf "  %-38s | %-12s | %-12s | \033[32m%-10s\033[0m\n" "$tbl" "$exp_cnt" "$imp_cnt" "[일치]"; matches=$((matches + 1))
        else printf "  %-38s | %-12s | %-12s | \033[33m%-10s\033[0m\n" "$tbl" "$exp_cnt" "$imp_cnt" "[불일치]"; mismatches=$((mismatches + 1))
        fi
    done < "$exp_tmp"

    while IFS=, read -r tbl imp_cnt; do
        if ! grep -q "^${tbl}," "$exp_tmp"; then
            tbl_only=$(echo "$tbl" | cut -d'.' -f2)
            if ! grep -q "\.${tbl_only}," "$exp_tmp"; then
                printf "  %-38s | %-12s | %-12s | \033[36m%-10s\033[0m\n" "$tbl" "N/A" "$imp_cnt" "[추가됨]"
                mismatches=$((mismatches + 1))
            fi
        fi
    done < "$imp_tmp"

    echo "  --------------------------------------------------------------------------------------"
    if [ $mismatches -eq 0 ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> [SUCCESS] ${matches} tables matched completely!"; else echo "  >> [성공] ${matches}개 테이블 건수가 완전히 일치합니다!"; fi
    else
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> [WARNING] ${mismatches} mismatches or missing items found."; else echo "  >> [경고] ${mismatches}건의 불일치/누락 항목이 검출되었습니다."; fi
    fi

    # HTML 보고서 생성 여부 질의
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  >> Generate HTML Audit & Management Report? (Y/n) [Default: Y]: "
    else printf "  >> 웹 브라우저용 HTML 종합 마이그레이션 감사 보고서를 생성하시겠습니까? (Y/n) [기본값: Y]: "; fi
    _read gen_html_opt
    if [ -z "$gen_html_opt" ] || [ "$gen_html_opt" = "y" ] || [ "$gen_html_opt" = "Y" ]; then
        report_uid=$(echo "$exp_log_file" | sed 's/\.log$//' | sed 's/_expdp_.*//')
        [ -z "$report_uid" ] && report_uid=$(date +%Y%m%d_%H%M%S)
        generate_html_audit_report "$exp_log" "$imp_log" "$report_uid" "$exp_tmp" "$imp_tmp" "$matches" "$mismatches"
    fi

    rm -f "$exp_tmp" "$imp_tmp"
    
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  Press Enter to return to main menu: "; else printf "  메인 메뉴로 돌아가려면 엔터를 누르세요: "; fi
    _read _dummy
}

# 4. Real-Time Live Migration Monitor Dashboard
run_live_monitor() {
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [4] LIVE MONITOR: Real-Time Data Pump Progress & Session I/O Dashboard"
    else echo " [4] LIVE MONITOR : 실시간 Data Pump 진행률 & 세션 대기 이벤트 모니터링"; fi
    echo "======================================================================"

    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE"
    echo "  * CPU Cores: $CPU_CORES"
    echo "----------------------------------------------------------------------"

    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Oracle connection account [Default: / as sysdba]: "
    else printf "  Oracle 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info

    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Refresh Interval in seconds [Default: 5]: "
    else printf "  새로고침 주기(초)를 입력하세요 [기본값: 5]: "; fi
    _read refresh_sec
    refresh_sec=${refresh_sec:-5}
    if ! echo "$refresh_sec" | grep -qE '^[0-9]+$'; then refresh_sec=5; fi
    [ "$refresh_sec" -lt 1 ] && refresh_sec=1

    if [ "$LANG_PREF" = "EN" ]; then echo ">> Starting monitor. Press Ctrl+C to return to the main menu..."
    else echo ">> 모니터링을 시작합니다. 메인 메뉴로 돌아가려면 Ctrl+C 를 누르세요..."; fi
    sleep 1

    # [FIX v07/B3] 모니터 루프 전용 INT 트랩.
    #   v06 은 전역 INT 트랩이 exit 를 호출하지 않아 Ctrl+C 로 루프를 벗어날 수 없었다.
    #   여기서는 플래그만 세팅하고, 루프 종료 후 전역 트랩을 복원한다.
    MON_STOP="false"
    trap 'MON_STOP="true"' INT

    mon_iter=0
    while true; do
        if [ "$MON_STOP" = "true" ]; then break; fi
        mon_iter=$((mon_iter + 1))
        clear_screen
        echo "===================================================================================================="
        echo "   Oracle Data Pump Live Monitor Dashboard (Refresh: ${refresh_sec}s | Iter: #$mon_iter | $(date '+%Y-%m-%d %H:%M:%S'))"
        if [ "$IS_CDB" = "YES" ]; then echo "   [Multitenant Mode Active] Container: $CURRENT_CON_NAME | PDB: $SELECTED_PDB"; fi
        echo "===================================================================================================="

        if [ "$MOCK_MODE" = "true" ]; then
            echo " [1. Active Data Pump Jobs - dba_datapump_jobs]"
            printf " %-15s | %-25s | %-12s | %-10s | %-12s | %-8s | %-10s\n" "OWNER" "JOB_NAME" "OPERATION" "JOB_MODE" "STATE" "DEGREE" "SESSIONS"
            echo " --------------------------------------------------------------------------------------------------"
            printf " %-15s | %-25s | %-12s | %-10s | %-12s | %-8s | %-10s\n" "SYSTEM" "MIG_SCHEMA_20260825" "EXPORT" "SCHEMA" "EXECUTING" "8" "9"
            echo ""
            echo " [2. Longops Progress - v\$session_longops]"
            echo "   Job: MIG_SCHEMA_20260825 (Schema: KMSUNG.TB_ORDER_HIST)"
            echo "   Progress: [=====================================>             ] 74.5% (745 MB / 1000 MB)"
            echo "   Elapsed: 120s | Estimated Remaining: 41s"
            echo ""
            echo " [3. Active Worker Sessions & Wait Events - v\$session & v\$session_wait]"
            printf " %-8s | %-12s | %-12s | %-32s | %-10s | %-14s\n" "INST_ID" "SID,SERIAL#" "STATUS" "EVENT" "WAIT(s)" "SQL_ID"
            echo " --------------------------------------------------------------------------------------------------"
            printf " %-8s | %-12s | %-12s | %-32s | %-10s | %-14s\n" "1" "142,3821" "ACTIVE" "direct path read" "0" "4a8fk19mzb7q1"
            printf " %-8s | %-12s | %-12s | %-32s | %-10s | %-14s\n" "1" "156,1102" "ACTIVE" "Data Pump worker" "0" "2b99xj38vn4k0"
            echo "===================================================================================================="
            if [ -n "$MOCK_NON_INTERACTIVE" ] || [ "$UNATTENDED" = "true" ]; then break; fi
            echo "  Press 'q' and Enter to exit monitor loop, or Enter to refresh:"
            _read user_mon_cmd
            [ "$user_mon_cmd" = "q" ] || [ "$user_mon_cmd" = "Q" ] && break
            continue
        fi

        sqlplus -S /nolog <<SQL_EOF
connect $DB_CONN
SET LINES 200 PAGES 100 TRIMSPOOL ON FEEDBACK OFF HEAD ON
$PDB_SWITCH_SQL
COL OWNER_NAME FORMAT A12 HEADING "OWNER"
COL JOB_NAME FORMAT A24 HEADING "JOB_NAME"
COL OPERATION FORMAT A10 HEADING "OPERATION"
COL JOB_MODE FORMAT A10 HEADING "MODE"
COL STATE FORMAT A12 HEADING "STATE"
COL DEGREE FORMAT 999 HEADING "DEGREE"
COL ATTACHED_SESSIONS FORMAT 9999 HEADING "SESSIONS"

PROMPT [1. Active Data Pump Jobs - dba_datapump_jobs]
SELECT owner_name, job_name, operation, job_mode, state, degree, attached_sessions 
FROM dba_datapump_jobs 
WHERE state != 'NOT RUNNING';

PROMPT
PROMPT [2. Longops Progress - v\$session_longops]
COL OPNAME FORMAT A26 HEADING "OPERATION"
COL TARGET_DESC FORMAT A24 HEADING "TARGET"
COL PROGRESS FORMAT A10 HEADING "PROGRESS"
COL ELAPSED_SEC FORMAT 999999 HEADING "ELAPSED(s)"
COL REMAIN_SEC FORMAT 999999 HEADING "REMAIN(s)"
SELECT opname, target_desc, 
       ROUND(sofar/NULLIF(totalwork,0)*100, 1) || '%' AS PROGRESS,
       elapsed_seconds AS ELAPSED_SEC,
       time_remaining AS REMAIN_SEC
FROM v\$session_longops 
WHERE (opname LIKE '%EXPORT%' OR opname LIKE '%IMPORT%' OR opname LIKE '%DATAPUMP%') 
  AND totalwork > 0;

PROMPT
PROMPT [3. Active Worker Sessions & Wait Events - gv\$session & gv\$session_wait]
COL INST_ID FORMAT 999 HEADING "INST"
COL SESS FORMAT A12 HEADING "SID,SERIAL#"
COL EVENT FORMAT A30 HEADING "EVENT"
COL STATUS FORMAT A10 HEADING "STATUS"
COL SECONDS_IN_WAIT FORMAT 9999 HEADING "WAIT(s)"
COL SQL_ID FORMAT A14 HEADING "SQL_ID"
SELECT s.inst_id, s.sid || ',' || s.serial# AS SESS, s.status, s.event, s.seconds_in_wait, s.sql_id
FROM gv\$session s
WHERE s.program LIKE '%dp%' OR s.module LIKE '%Data Pump%' OR s.action LIKE '%Data Pump%'
ORDER BY s.inst_id, s.sid;

EXIT;
SQL_EOF

        echo "===================================================================================================="
        if [ "$LANG_PREF" = "EN" ]; then echo " [Tip: Press Ctrl+C to return to the Main Menu]"
        else echo " [안내: Ctrl+C 를 누르면 메인 메뉴로 돌아갑니다]"; fi

        # 무인 모드에서는 1회만 출력하고 종료 (배치 로그용)
        if [ "$UNATTENDED" = "true" ]; then break; fi

        sleep "$refresh_sec"
        if [ "$MON_STOP" = "true" ]; then break; fi
    done

    # [FIX v07/B3] 전역 INT 트랩 복원
    trap 'on_interrupt' INT
    MON_STOP="false"
    if [ "$LANG_PREF" = "EN" ]; then echo ""; echo ">> Monitor stopped. Returning to the main menu."
    else echo ""; echo ">> 모니터링을 종료하고 메인 메뉴로 돌아갑니다."; fi
    return 0
}

# 5. Diagnostics Mode (Pre-Migration DB Readiness & 19c to 23c Multi-byte Charset Check)
run_diagnostics_mode() {
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [5] DIAGNOSTICS: Pre-Migration DB Readiness & Health Check"
    else echo " [5] DIAGNOSTICS : 사전 이관 DB 환경 & 객체 점검 리포트 생성"; fi
    echo "======================================================================"

    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE"
    echo "  * CPU Cores: $CPU_CORES"
    echo "  * Memory: $MEM_SIZE"
    echo "----------------------------------------------------------------------"

    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Oracle connection account [Default: / as sysdba]: "
    else printf "  Oracle 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info

    DATE_STR=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$")
    UNIQUE_ID="DIAG_${DATE_STR}"

    DIAG_SQL="pre_migration_check_${UNIQUE_ID}.sql"
    DIAG_SH="pre_migration_check_${UNIQUE_ID}.sh"

    echo ""
    if [ "$LANG_PREF" = "EN" ]; then echo "  * Generating Diagnostic Scripts: $DIAG_SQL and $DIAG_SH"
    else echo "  * 사전 진단 스크립트 생성 중: $DIAG_SQL 및 $DIAG_SH"; fi

    cat <<EOF > "$DIAG_SQL"
-- ==============================================================================
--  Oracle Pre-Migration Diagnostic Report
--  Generated for Job: ${UNIQUE_ID}
-- ==============================================================================
SET LINES 300 PAGES 500 TRIMSPOOL ON FEEDBACK OFF
$PDB_SWITCH_SQL
SPOOL pre_migration_check_${UNIQUE_ID}.log

PROMPT ========================================================================
PROMPT 1. Pre-existing Invalid Objects Summary (Source/Target DB)
PROMPT ========================================================================
SELECT owner, object_type, count(*) as invalid_count 
FROM dba_objects 
WHERE status = 'INVALID' AND owner NOT IN ('SYS','SYSTEM','AUDSYS')
GROUP BY owner, object_type
ORDER BY owner, object_type;

PROMPT ========================================================================
PROMPT 2. Special Column Types Check (LONG, LONG RAW, XMLTYPE, SDO_GEOMETRY, BFILE)
PROMPT ========================================================================
SELECT owner, table_name, column_name, data_type 
FROM dba_tab_cols 
WHERE data_type IN ('LONG', 'LONG RAW', 'XMLTYPE', 'SDO_GEOMETRY', 'BFILE', 'ANYDATA')
  AND owner NOT IN ('SYS','SYSTEM','XDB','MDSYS','ORDDATA','WMSYS','LBACSYS')
ORDER BY owner, table_name;

PROMPT ========================================================================
PROMPT 3. Tablespace Space Utilization & Autoextend Status
PROMPT ========================================================================
SELECT df.tablespace_name,
       ROUND(df.total_bytes / 1024 / 1024, 2) AS TOTAL_MB,
       ROUND(NVL(fs.free_bytes, 0) / 1024 / 1024, 2) AS FREE_MB,
       ROUND((1 - NVL(fs.free_bytes, 0) / NULLIF(df.total_bytes, 0)) * 100, 2) AS PCT_USED
FROM (SELECT tablespace_name, SUM(bytes) AS total_bytes FROM dba_data_files GROUP BY tablespace_name) df
LEFT JOIN (SELECT tablespace_name, SUM(bytes) AS free_bytes FROM dba_free_space GROUP BY tablespace_name) fs
  ON df.tablespace_name = fs.tablespace_name
ORDER BY PCT_USED DESC;

PROMPT ========================================================================
PROMPT 4. Character Set Multi-Byte Expansion Risk Check (KO16MSWIN949 -> AL32UTF8)
PROMPT ========================================================================
SELECT parameter, value FROM nls_database_parameters WHERE parameter IN ('NLS_CHARACTERSET', 'NLS_NCHAR_CHARACTERSET', 'NLS_LENGTH_SEMANTICS');

PROMPT
PROMPT >> Checking Columns at Risk of Truncation / ORA-12899 upon AL32UTF8 Conversion:
PROMPT    (Columns defined with BYTE semantics or VARCHAR2 > 2666 bytes)
COL OWNER FORMAT A20
COL TABLE_NAME FORMAT A30
COL COLUMN_NAME FORMAT A30
COL DATA_TYPE FORMAT A15
COL CHAR_USED FORMAT A5
SELECT owner, table_name, column_name, data_type, data_length, char_length, char_used
FROM dba_tab_cols
WHERE data_type IN ('VARCHAR2', 'CHAR')
  AND ( (char_used = 'B' AND data_length > 2666) OR (char_length > 1333) )
  AND owner NOT IN ('SYS','SYSTEM','XDB','WMSYS','OJVMSYS','OUTLN','DBSNMP','AUDSYS','GSMADMIN_INTERNAL','APPQOSSYS')
ORDER BY owner, table_name, column_id;

PROMPT ========================================================================
PROMPT 5. Unusable Indexes & Disabled Constraints Check
PROMPT ========================================================================
SELECT owner, index_name, table_name, status 
FROM dba_indexes 
WHERE status = 'UNUSABLE' AND owner NOT IN ('SYS','SYSTEM');

SELECT owner, constraint_name, table_name, status 
FROM dba_constraints 
WHERE status = 'DISABLED' AND owner NOT IN ('SYS','SYSTEM');

SPOOL OFF
EXIT;
EOF

    cat <<EOF > "$DIAG_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo ">> Oracle 사전 이관 DB 환경 및 객체 진단을 수행합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$DIAG_SQL
CONNECT_EOF
echo ">> 사전 진단이 완료되었습니다. 결과 로그 파일: pre_migration_check_${UNIQUE_ID}.log"
EOF
    chmod 700 "$DIAG_SH"

    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> Diagnostic Script Generation Complete!"; else echo "  >> 사전 진단 스크립트 생성 완료!"; fi
    echo "  - $DIAG_SH"
    echo "  - $DIAG_SQL"
    echo "======================================================================"

    ask_to_run_script "$DIAG_SH"
}

# 6. Performance Tuning & Parameter Optimization Advisor
run_tuning_advisor() {
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [6] ADVISOR: Migration Performance & Parameter Optimization Advisor"
    else echo " [6] ADVISOR : 이관 성능 최적화 & Oracle 인스턴스 파라미터 튜닝 어드바이저"; fi
    echo "======================================================================"

    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE"
    echo "  * CPU Cores: $CPU_CORES"
    echo "  * Memory: $MEM_SIZE"
    echo "----------------------------------------------------------------------"

    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Oracle connection account [Default: / as sysdba]: "
    else printf "  Oracle 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info
    calculate_parallel_degree

    DATE_STR=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$")
    UNIQUE_ID="TUNE_${DATE_STR}"

    # 파라미터 권장값 계산
    rec_streams_mb=$(( (CALC_PARALLEL * 30) + 256 ))
    [ "$rec_streams_mb" -lt 512 ] && rec_streams_mb=512
    rec_streams_str="${rec_streams_mb}M"

    rec_undo_ret=14400

    case "$DB_CPU_COUNT" in
        ''|*[!0-9]*) dcpu=4 ;;
        *) dcpu=$DB_CPU_COUNT ;;
    esac
    rec_p_max=$(( dcpu * 4 ))
    [ "$rec_p_max" -lt 16 ] && rec_p_max=16

    echo ""
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [Data Pump Optimization Recommendations]"
        printf "  1. STREAMS_POOL_SIZE    : %-10s (Prevents ORA-04031 / ORA-39095 worker memory starvation)\n" "$rec_streams_str"
        printf "  2. UNDO_RETENTION       : %-10s (Prevents ORA-01555 Snapshot Too Old on large tables)\n" "${rec_undo_ret}s"
        printf "  3. PARALLEL_MAX_SERVERS : %-10s (Ensures all %d parallel workers spawn)\n" "$rec_p_max" "$CALC_PARALLEL"
        printf "  4. RECYCLEBIN           : OFF        (Target DB: eliminates drop/truncate dictionary lock delay)\n"
        printf "  5. DIRECT_PATH I/O      : ENABLED    (Leverages bypass buffer cache for bulk throughput)\n"
    else
        echo "  [Data Pump 성능 최적화 진단 및 권장값]"
        printf "  1. STREAMS_POOL_SIZE    : %-10s (워커 통신 큐 부족 및 ORA-04031 / ORA-39095 방지)\n" "$rec_streams_str"
        printf "  2. UNDO_RETENTION       : %-10s (장시간 테이블 백업 시 ORA-01555 스냅샷 에러 방지)\n" "${rec_undo_ret}초 (4시간)"
        printf "  3. PARALLEL_MAX_SERVERS : %-10s (PARALLEL=%d 도수를 병목 없이 스폰하기 위한 서버 풀)\n" "$rec_p_max" "$CALC_PARALLEL"
        printf "  4. RECYCLEBIN           : OFF        (Target DB: 대량 생성/삭제 시 딕셔너리 경합 해소)\n"
        printf "  5. DIRECT_PATH I/O      : ENABLED    (Buffer Cache 우회 Direct Path I/O 극대화)\n"
    fi
    echo "----------------------------------------------------------------------"

    APPLY_SQL="migration_tuning_apply_${UNIQUE_ID}.sql"
    RESTORE_SQL="migration_tuning_restore_${UNIQUE_ID}.sql"
    APPLY_SH="migration_tuning_apply_${UNIQUE_ID}.sh"
    RESTORE_SH="migration_tuning_restore_${UNIQUE_ID}.sh"

    cat <<EOF > "$APPLY_SQL"
-- ==============================================================================
--  Oracle Migration Performance Tuning Apply Script
--  Job ID: ${UNIQUE_ID}
-- ==============================================================================
SET ECHO ON LOGONLY SERVEROUTPUT ON
SPOOL migration_tuning_apply_${UNIQUE_ID}.log

PROMPT 1. Adjusting STREAMS_POOL_SIZE for Parallel Workers...
ALTER SYSTEM SET streams_pool_size=${rec_streams_str} SCOPE=MEMORY;

PROMPT 2. Increasing UNDO_RETENTION to prevent ORA-01555...
ALTER SYSTEM SET undo_retention=${rec_undo_ret} SCOPE=MEMORY;

PROMPT 3. Tuning Parallel Execution Server Limits...
ALTER SYSTEM SET parallel_max_servers=${rec_p_max} SCOPE=MEMORY;

PROMPT 4. Disabling Recyclebin to reduce dictionary contention during bulk DDL...
ALTER SYSTEM SET recyclebin=OFF SCOPE=MEMORY DEFERRED;

SPOOL OFF
EXIT;
EOF

    cat <<EOF > "$RESTORE_SQL"
-- ==============================================================================
--  Oracle Migration Performance Tuning Post-Restore Script
--  Job ID: ${UNIQUE_ID}
-- ==============================================================================
SET ECHO ON LOGONLY SERVEROUTPUT ON
SPOOL migration_tuning_restore_${UNIQUE_ID}.log

PROMPT 1. Restoring STREAMS_POOL_SIZE to Auto/Default...
ALTER SYSTEM SET streams_pool_size=0 SCOPE=MEMORY;

PROMPT 2. Restoring UNDO_RETENTION to Default (900s)...
ALTER SYSTEM SET undo_retention=900 SCOPE=MEMORY;

PROMPT 3. Re-enabling Recyclebin...
ALTER SYSTEM SET recyclebin=ON SCOPE=MEMORY DEFERRED;

SPOOL OFF
EXIT;
EOF

    cat <<EOF > "$APPLY_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo ">> 이관 성능 최적화 파라미터를 인스턴스에 적용합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$APPLY_SQL
CONNECT_EOF
echo ">> 적용 완료. 로그: migration_tuning_apply_${UNIQUE_ID}.log"
EOF
    chmod 700 "$APPLY_SH"

    cat <<EOF > "$RESTORE_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo ">> 마이그레이션 완료 후 파라미터를 원래 상태로 원복합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$RESTORE_SQL
CONNECT_EOF
echo ">> 원복 완료. 로그: migration_tuning_restore_${UNIQUE_ID}.log"
EOF
    chmod 700 "$RESTORE_SH"

    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> Tuning Scripts Generation Complete!"; else echo "  >> 성능 튜닝 스크립트 생성 완료!"; fi
    echo "  - Apply Script   : $APPLY_SH ($APPLY_SQL)"
    echo "  - Restore Script : $RESTORE_SH ($RESTORE_SQL)"
    echo "======================================================================"

    ask_to_run_script "$APPLY_SH"
}

# 7. Deep Data Integrity, Object Matrix & Sequence Sync Tool
run_integrity_check() {
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [7] DATA INTEGRITY: Deep Object Matrix, Sequence Sync & Checksum Tool"
    else echo " [7] DATA INTEGRITY : 데이터 정합성 심층 검증 및 시퀀스(Sequence) 동기화 툴"; fi
    echo "======================================================================"

    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE"
    echo "  * CPU Cores: $CPU_CORES"
    echo "----------------------------------------------------------------------"

    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Oracle connection account [Default: / as sysdba]: "
    else printf "  Oracle 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info

    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Database Link to Source DB for Cross-Check (leave empty if none) [MIG_LINK]: "
    else printf "  Source DB와 직접 교차 검증할 DB Link 이름 입력 (미사용 시 공백) [기본값: MIG_LINK]: "; fi
    _read dblink_val
    [ -z "$dblink_val" ] && dblink_val="MIG_LINK"

    DATE_STR=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$")
    UNIQUE_ID="INTEGRITY_${DATE_STR}"

    INT_SQL="deep_integrity_check_${UNIQUE_ID}.sql"
    INT_SH="deep_integrity_check_${UNIQUE_ID}.sh"
    SEQ_FIX_SQL="fix_sequences_${UNIQUE_ID}.sql"

    echo ""
    if [ "$LANG_PREF" = "EN" ]; then echo "  * Generating Deep Integrity Verification Scripts: $INT_SQL and $INT_SH"
    else echo "  * 정합성 심층 검증 스크립트 생성 중: $INT_SQL 및 $INT_SH"; fi

    cat <<EOF > "$INT_SQL"
-- ==============================================================================
--  Oracle Deep Migration Integrity & Object Matrix Verification
--  Job ID: ${UNIQUE_ID}
-- ==============================================================================
SET LINES 250 PAGES 1000 TRIMSPOOL ON SERVEROUTPUT ON
$PDB_SWITCH_SQL
SPOOL deep_integrity_${UNIQUE_ID}.log

PROMPT ========================================================================
PROMPT 1. Target Database Object Matrix by Type and Status
PROMPT ========================================================================
COL OWNER FORMAT A20
COL OBJECT_TYPE FORMAT A22
COL VALID_COUNT FORMAT 999,999
COL INVALID_COUNT FORMAT 999,999
COL TOTAL_COUNT FORMAT 999,999

SELECT owner, object_type,
       COUNT(CASE WHEN status = 'VALID' THEN 1 END) AS VALID_COUNT,
       COUNT(CASE WHEN status = 'INVALID' THEN 1 END) AS INVALID_COUNT,
       COUNT(*) AS TOTAL_COUNT
FROM dba_objects
WHERE owner NOT IN ('SYS','SYSTEM','XDB','WMSYS','OJVMSYS','OUTLN','DBSNMP','AUDSYS','GSMADMIN_INTERNAL','APPQOSSYS')
GROUP BY owner, object_type
ORDER BY owner, object_type;

PROMPT ========================================================================
PROMPT 2. Foreign Key Constraint Status Check (Target DB)
PROMPT ========================================================================
COL CONSTRAINT_NAME FORMAT A30
COL TABLE_NAME FORMAT A30
COL STATUS FORMAT A12
SELECT owner, table_name, constraint_name, status, validated
FROM dba_constraints
WHERE constraint_type = 'R'
  AND status = 'DISABLED'
  AND owner NOT IN ('SYS','SYSTEM','XDB','WMSYS','AUDSYS')
ORDER BY owner, table_name;

PROMPT ========================================================================
PROMPT 3. Unusable Indexes Check (Target DB)
PROMPT ========================================================================
COL INDEX_NAME FORMAT A30
SELECT owner, index_name, table_name, status
FROM dba_indexes
WHERE status = 'UNUSABLE'
  AND owner NOT IN ('SYS','SYSTEM','XDB','WMSYS','AUDSYS')
ORDER BY owner, table_name;

PROMPT ========================================================================
PROMPT 4. Sequence Current Value Synchronization Verification
PROMPT ========================================================================
COL SEQUENCE_NAME FORMAT A30
COL LAST_NUMBER FORMAT 999,999,999,999
COL CACHE_SIZE FORMAT 999,999
SELECT sequence_owner, sequence_name, last_number, cache_size, increment_by
FROM dba_sequences
WHERE sequence_owner NOT IN ('SYS','SYSTEM','XDB','WMSYS','AUDSYS')
ORDER BY sequence_owner, sequence_name;

SPOOL OFF
EXIT;
EOF

    cat <<EOF > "$SEQ_FIX_SQL"
-- ==============================================================================
--  Oracle Sequence Synchronization & Auto-Adjustment Script
--  Prevents ORA-00001 unique constraint violations on Target DB
--  Generated for Job: ${UNIQUE_ID}
-- ==============================================================================
SET SERVEROUTPUT ON LINES 200
$PDB_SWITCH_SQL
SPOOL fix_sequences_${UNIQUE_ID}.log

DECLARE
  v_fix_count NUMBER := 0;
BEGIN
  DBMS_OUTPUT.PUT_LINE('>> Analyzing sequences for safe head room (+1000 buffer)...');
  FOR s IN (
    SELECT sequence_owner, sequence_name, last_number, increment_by 
    FROM dba_sequences 
    WHERE sequence_owner NOT IN ('SYS','SYSTEM','XDB','WMSYS','AUDSYS')
  ) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER SEQUENCE "' || s.sequence_owner || '"."' || s.sequence_name || '" INCREMENT BY 1000';
      EXECUTE IMMEDIATE 'SELECT "' || s.sequence_owner || '"."' || s.sequence_name || '".NEXTVAL FROM dual' INTO v_fix_count;
      EXECUTE IMMEDIATE 'ALTER SEQUENCE "' || s.sequence_owner || '"."' || s.sequence_name || '" INCREMENT BY ' || s.increment_by;
      DBMS_OUTPUT.PUT_LINE('Adjusted: ' || s.sequence_owner || '.' || s.sequence_name || ' -> New NextVal: ' || v_fix_count);
    EXCEPTION WHEN OTHERS THEN
      DBMS_OUTPUT.PUT_LINE('Skip sequence ' || s.sequence_owner || '.' || s.sequence_name || ': ' || SQLERRM);
    END;
  END LOOP;
  DBMS_OUTPUT.PUT_LINE('>> Sequence Synchronization Adjustment Completed.');
END;
/
SPOOL OFF
EXIT;
EOF

    cat <<EOF > "$INT_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo ">> [1/2] 객체 매트릭스, 제약조건, 인덱스 및 시퀀스 심층 진단을 수행합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$INT_SQL
CONNECT_EOF

echo ">> [2/2] 시퀀스 동기화 보정 스크립트: $SEQ_FIX_SQL"
printf "지금 시퀀스 동기화 보정 스크립트를 실행하시겠습니까? (y/N): "
read run_seq_fix
if [ "\$run_seq_fix" = "y" ] || [ "\$run_seq_fix" = "Y" ]; then
    sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$SEQ_FIX_SQL
CONNECT_EOF
fi
echo ">> 심층 정합성 진단이 완료되었습니다. 결과 로그: deep_integrity_${UNIQUE_ID}.log"
EOF
    chmod 700 "$INT_SH"

    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> Deep Integrity Scripts Generated!"; else echo "  >> 정합성 심층 검증 스크립트 생성 완료!"; fi
    echo "  - Matrix & Integrity Check : $INT_SH ($INT_SQL)"
    echo "  - Sequence Sync Adjustment : $SEQ_FIX_SQL"
    echo "======================================================================"

    ask_to_run_script "$INT_SH"
}

# ==============================================================================
# [NEW v08] DEEP DIFF : ASIS <-> TOBE 데이터 딕셔너리 심층 대조 모듈
#
#   설계 배경 (기존 MIG_VALIDATE 프레임워크 대비 개선점)
#   ----------------------------------------------------------------------------
#   * 동일 SQL 텍스트를 ASIS(DB Link)/TOBE(로컬) 양쪽에 적용 -> 컬럼 구성이
#     구조적으로 동일해지므로 버전 차이로 인한 MINUS 실패(ORA-01789)가 원천 차단됨
#   * 모든 비교를 PL/SQL EXCEPTION 으로 감싸 실패를 STATUS='ERROR' 로 "기록"
#     (기존 도구는 실패한 검증 항목이 리포트에서 조용히 사라졌음)
#   * MUST_MATCH / INFORMATIONAL 분류로 시그널과 노이즈를 분리
#   * 제외 계정 목록을 단일 정의로 통합하고 19c/23c 신규 내부 계정을 포함
#   * CDB/PDB 컨테이너 전환을 자동 삽입 (기존 도구는 Multitenant 미대응)
#   * 기존 도구에서 결번이던 OBJ_DEPENDENCY(A18) 복원 + 제약조건/시퀀스/트리거 신규
# ==============================================================================

DEEP_EXCL_OWNERS=""
DEEP_LINK_NAME=""
DEEP_ENTRY_COUNT=0

# ------------------------------------------------------------------------------
# 통합 제외 계정 목록 (단일 정의 - 프레임워크 전체가 이 목록만 사용)
#   기존 도구는 서로 다른 4벌의 하드코딩 목록을 갖고 있어 객체 비교 범위와
#   건수 비교 범위가 어긋났고, 19c/23c 신규 내부 계정이 누락되어 있었다.
# ------------------------------------------------------------------------------
build_exclude_owner_list() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _bx _bx_list
    DEEP_EXCL_OWNERS=$(cat <<'EXCLEOF'
'SYS','SYSTEM','SYSAUX','OUTLN','DBSNMP','APPQOSSYS','WMSYS','XDB','ANONYMOUS','XS$NULL','ORDDATA','ORDPLUGINS','ORDSYS','SI_INFORMTN_SCHEMA','MDSYS','MDDATA','ORACLE_OCM','DIP','ORACLE_MAINT','GSMADMIN_INTERNAL','GSMCATUSER','GSMUSER','GGSYS','SYSBACKUP','SYSDG','SYSKM','SYSRAC','SYS$UMF','AUDSYS','OJVMSYS','DVSYS','DVF','LBACSYS','CTXSYS','OLAPSYS','EXFSYS','SYSMAN','TSMSYS','DMSYS','OWBSYS','OWBSYS_AUDIT','FLOWS_FILES','APEX_PUBLIC_USER','REMOTE_SCHEDULER_AGENT','SPATIAL_CSW_ADMIN_USR','SPATIAL_WFS_ADMIN_USR','PDBADMIN','DBSFWUSER','GGSHAREDCAP'
EXCLEOF
)
    # 사용자가 추가로 제외하고 싶은 계정 반영
    if [ -n "$DEEP_EXTRA_EXCLUDE" ]; then
        _bx_list=""
        IFS_BACKUP=$IFS; IFS=","
        for _bx in $DEEP_EXTRA_EXCLUDE; do
            _bx=$(echo "$_bx" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')
            [ -n "$_bx" ] && _bx_list="${_bx_list},'${_bx}'"
        done
        IFS=$IFS_BACKUP
        DEEP_EXCL_OWNERS="${DEEP_EXCL_OWNERS}${_bx_list}"
    fi
    return 0
}

# ------------------------------------------------------------------------------
# 대조 항목 정의 : ENTRY|CATEGORY|SEVERITY
#   MUST_MATCH    - 정상 이관이면 반드시 일치해야 하는 항목
#   INFORMATIONAL - 정상 이관에서도 차이가 나는 것이 정상인 항목(참고용)
# ------------------------------------------------------------------------------
deep_diff_entry_list() {
    cat <<'ENTEOF'
PROFILE|SECURITY|MUST_MATCH
SYS_PRIVS|SECURITY|MUST_MATCH
ROLE_PRIVS|SECURITY|MUST_MATCH
USER_QUOTAS|SECURITY|MUST_MATCH
USER_STATUS|SECURITY|MUST_MATCH
PRIVS_TAB_UTOU|SECURITY|MUST_MATCH
PRIVS_TAB_STOU|SECURITY|MUST_MATCH
PUB_TAB_UTOP|SECURITY|MUST_MATCH
PUB_TAB_STOP|SECURITY|MUST_MATCH
PUB_SYNONYM|OBJECT|MUST_MATCH
OBJ_STATUS|OBJECT|MUST_MATCH
OBJ_INVALID|OBJECT|MUST_MATCH
OBJ_TAB_TOTAL|OBJECT|MUST_MATCH
OBJ_TABP_TOTAL|OBJECT|MUST_MATCH
OBJ_LOB_TOTAL|OBJECT|MUST_MATCH
OBJ_IDX_TOTAL|OBJECT|MUST_MATCH
OBJ_IDX_LOB|OBJECT|MUST_MATCH
OBJ_DEPENDENCY|OBJECT|MUST_MATCH
OBJ_DBLINK|OBJECT|MUST_MATCH
OBJ_CONSTRAINT|OBJECT|MUST_MATCH
OBJ_SEQUENCE|OBJECT|MUST_MATCH
OBJ_TRIGGER|OBJECT|MUST_MATCH
TBS_STATUS|STORAGE|INFORMATIONAL
DBF_STATUS|STORAGE|INFORMATIONAL
OBJ_SEGSIZE|STORAGE|INFORMATIONAL
USER_ACCOUNT|SECURITY|INFORMATIONAL
TAB_STATS|STATS|INFORMATIONAL
IDX_STATS|STATS|INFORMATIONAL
OBJ_STATISTICS|STATS|INFORMATIONAL
ENTEOF
}

# ------------------------------------------------------------------------------
# 항목별 원본 SELECT 정의
#   @@L@@    -> DB Link 접미사 (ASIS 수집 시 '@LINKNAME', TOBE 수집 시 '')
#   @@EXCL@@ -> 통합 제외 계정 목록
#   따옴표/특수문자 이스케이프 문제를 피하기 위해 인용 heredoc 으로 정의하고
#   치환은 sed 로 수행한다.
# ------------------------------------------------------------------------------
deep_diff_raw_sql() {
    case "$1" in
    PROFILE) cat <<'Q'
select profile, resource_name, resource_type, "LIMIT" from dba_profiles@@L@@
Q
    ;;
    SYS_PRIVS) cat <<'Q'
select grantee, privilege, admin_option from dba_sys_privs@@L@@ where grantee not in (@@EXCL@@)
Q
    ;;
    ROLE_PRIVS) cat <<'Q'
select grantee, granted_role, admin_option, default_role from dba_role_privs@@L@@ where grantee not in (@@EXCL@@)
Q
    ;;
    USER_QUOTAS) cat <<'Q'
select username, tablespace_name, max_bytes from dba_ts_quotas@@L@@ where username not in (@@EXCL@@)
Q
    ;;
    USER_STATUS) cat <<'Q'
select username, default_tablespace, temporary_tablespace, profile from dba_users@@L@@ where username not in (@@EXCL@@)
Q
    ;;
    USER_ACCOUNT) cat <<'Q'
select username, account_status from dba_users@@L@@ where username not in (@@EXCL@@)
Q
    ;;
    PRIVS_TAB_UTOU) cat <<'Q'
select grantor, privilege, owner, table_name, grantee, grantable from dba_tab_privs@@L@@ where grantee <> 'PUBLIC' and owner not in (@@EXCL@@) and table_name not like 'BIN' || chr(36) || '%'
Q
    ;;
    PRIVS_TAB_STOU) cat <<'Q'
select grantor, privilege, owner, table_name, grantee, grantable from dba_tab_privs@@L@@ where grantee <> 'PUBLIC' and owner in ('SYS','SYSTEM') and grantee not in (@@EXCL@@)
Q
    ;;
    PUB_TAB_UTOP) cat <<'Q'
select grantor, privilege, owner, table_name, grantable from dba_tab_privs@@L@@ where grantee = 'PUBLIC' and owner not in (@@EXCL@@) and table_name not like 'BIN' || chr(36) || '%'
Q
    ;;
    PUB_TAB_STOP) cat <<'Q'
select grantor, privilege, owner, table_name, grantable from dba_tab_privs@@L@@ where grantee = 'PUBLIC' and owner in ('SYS','SYSTEM')
Q
    ;;
    PUB_SYNONYM) cat <<'Q'
select synonym_name, table_owner, table_name, db_link from dba_synonyms@@L@@ where owner = 'PUBLIC' and table_owner not in (@@EXCL@@)
Q
    ;;
    OBJ_STATUS) cat <<'Q'
select owner, object_type, count(*) obj_cnt from dba_objects@@L@@ where owner not in (@@EXCL@@) group by owner, object_type
Q
    ;;
    OBJ_INVALID) cat <<'Q'
select owner, object_name, object_type from dba_objects@@L@@ where status = 'INVALID' and owner not in (@@EXCL@@)
Q
    ;;
    OBJ_TAB_TOTAL) cat <<'Q'
select owner, table_name, iot_type, partitioned from dba_tables@@L@@ where owner not in (@@EXCL@@)
Q
    ;;
    OBJ_TABP_TOTAL) cat <<'Q'
select table_owner, table_name, partition_name from dba_tab_partitions@@L@@ where table_owner not in (@@EXCL@@)
Q
    ;;
    OBJ_LOB_TOTAL) cat <<'Q'
select owner, table_name, column_name, segment_name from dba_lobs@@L@@ where owner not in (@@EXCL@@)
Q
    ;;
    OBJ_IDX_TOTAL) cat <<'Q'
select owner, index_name, table_owner, table_name, index_type, uniqueness from dba_indexes@@L@@ where owner not in (@@EXCL@@)
Q
    ;;
    OBJ_IDX_LOB) cat <<'Q'
select owner, index_name, table_owner, table_name from dba_indexes@@L@@ where index_type = 'LOB' and owner not in (@@EXCL@@)
Q
    ;;
    OBJ_DEPENDENCY) cat <<'Q'
select owner, name, type, referenced_owner, referenced_name, referenced_type from dba_dependencies@@L@@ where owner not in (@@EXCL@@)
Q
    ;;
    OBJ_DBLINK) cat <<'Q'
select owner, db_link, username, host from dba_db_links@@L@@
Q
    ;;
    OBJ_CONSTRAINT) cat <<'Q'
select owner, table_name, constraint_name, constraint_type, r_owner, r_constraint_name from dba_constraints@@L@@ where owner not in (@@EXCL@@) and generated = 'USER NAME'
Q
    ;;
    OBJ_SEQUENCE) cat <<'Q'
select sequence_owner, sequence_name, min_value, max_value, increment_by, cycle_flag, cache_size from dba_sequences@@L@@ where sequence_owner not in (@@EXCL@@)
Q
    ;;
    OBJ_TRIGGER) cat <<'Q'
select owner, trigger_name, trigger_type, triggering_event, table_owner, table_name from dba_triggers@@L@@ where owner not in (@@EXCL@@)
Q
    ;;
    TBS_STATUS) cat <<'Q'
select ts.tablespace_name, ts.status, ts.contents, count(df.file_name) df_cnt from dba_tablespaces@@L@@ ts left join dba_data_files@@L@@ df on ts.tablespace_name = df.tablespace_name group by ts.tablespace_name, ts.status, ts.contents
Q
    ;;
    DBF_STATUS) cat <<'Q'
select tablespace_name, status, autoextensible, count(*) file_cnt from dba_data_files@@L@@ group by tablespace_name, status, autoextensible
Q
    ;;
    OBJ_SEGSIZE) cat <<'Q'
select owner, segment_type, count(*) seg_cnt, sum(bytes) total_bytes from dba_segments@@L@@ where owner not in (@@EXCL@@) group by owner, segment_type
Q
    ;;
    TAB_STATS) cat <<'Q'
select owner, table_name, num_rows from dba_tab_statistics@@L@@ where owner not in (@@EXCL@@) and object_type = 'TABLE'
Q
    ;;
    IDX_STATS) cat <<'Q'
select owner, index_name, num_rows, distinct_keys from dba_ind_statistics@@L@@ where owner not in (@@EXCL@@)
Q
    ;;
    OBJ_STATISTICS) cat <<'Q'
select owner, stattype_locked, count(*) locked_cnt from dba_tab_statistics@@L@@ where owner not in (@@EXCL@@) group by owner, stattype_locked
Q
    ;;
    *) echo "select 1 unknown_entry from dual" ;;
    esac
}

# @@L@@ / @@EXCL@@ 치환된 최종 SELECT 반환
deep_diff_select_sql() {
    _dd_entry="$1"
    _dd_link="$2"
    deep_diff_raw_sql "$_dd_entry" \
        | sed -e "s|@@L@@|${_dd_link}|g" -e "s|@@EXCL@@|${DEEP_EXCL_OWNERS}|g" \
        | sed '/^[[:space:]]*$/d'
}

# ------------------------------------------------------------------------------
# DEEP DIFF 스크립트 생성기
# ------------------------------------------------------------------------------
generate_deep_diff_scripts() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _dd_link_sfx _dd_e _dd_pair
    build_exclude_owner_list

    DD_GATHER_SQL="deepdiff_1_gather_${UNIQUE_ID}.sql"
    DD_GATHER_SH="deepdiff_1_gather_${UNIQUE_ID}.sh"
    DD_COMPARE_SQL="deepdiff_2_compare_${UNIQUE_ID}.sql"
    DD_COMPARE_SH="deepdiff_2_compare_${UNIQUE_ID}.sh"
    DD_DETAIL_SH="deepdiff_3_detail_${UNIQUE_ID}.sh"
    DD_RESULT_CSV="deepdiff_result_${UNIQUE_ID}.csv"

    _dd_link_sfx=""
    [ -n "$DEEP_LINK_NAME" ] && _dd_link_sfx="@${DEEP_LINK_NAME}"

    echo "  * 생성 중: $DD_GATHER_SQL (ASIS/TOBE 스냅샷 수집)"

    # ---------------- 1) 수집 스크립트 ----------------
    cat <<EOF > "$DD_GATHER_SQL"
-- ==============================================================================
--  DEEP DIFF Step 1 : ASIS / TOBE 딕셔너리 스냅샷 수집
--  Job ID    : ${UNIQUE_ID}
--  ASIS 경로 : ${_dd_link_sfx:-(로컬)}
--  생성      : Migration Helper v${SCRIPT_VERSION}
--
--  ※ 양쪽 스냅샷을 "동일한 SELECT 텍스트"로 생성하므로 DB 버전이 달라도
--     컬럼 구성이 항상 일치한다 -> MINUS 시 ORA-01789 가 발생하지 않는다.
-- ==============================================================================
SET ECHO ON LOGONLY SERVEROUTPUT ON SIZE UNLIMITED LINES 300 TRIMSPOOL ON
WHENEVER SQLERROR CONTINUE
SPOOL deepdiff_1_gather_${UNIQUE_ID}.log

${PDB_SWITCH_SQL}

PROMPT ========================================================================
PROMPT 0. 대조 항목 정의 테이블 재구성
PROMPT ========================================================================
DROP TABLE MIG_DEEP_ENTRY PURGE;
CREATE TABLE MIG_DEEP_ENTRY (
  ENTRY_NO   NUMBER,
  ENTRY_NAME VARCHAR2(64),
  CATEGORY   VARCHAR2(16),
  SEVERITY   VARCHAR2(16)
);

EOF

    _dd_no=0
    deep_diff_entry_list | while IFS='|' read -r _dd_e _c _sv; do
        [ -z "$_dd_e" ] && continue
        _dd_no=$((_dd_no + 1))
        echo "INSERT INTO MIG_DEEP_ENTRY VALUES (${_dd_no}, '${_dd_e}', '${_c}', '${_sv}');" >> "$DD_GATHER_SQL"
    done
    echo "COMMIT;" >> "$DD_GATHER_SQL"
    echo "" >> "$DD_GATHER_SQL"

    DEEP_ENTRY_COUNT=$(deep_diff_entry_list | grep -c '|')

    # AS_ / TO_ 스냅샷 생성
    {
        echo "PROMPT ========================================================================"
        echo "PROMPT 1. ASIS 스냅샷 (AS_*) 생성"
        echo "PROMPT ========================================================================"
    } >> "$DD_GATHER_SQL"

    deep_diff_entry_list | while IFS='|' read -r _dd_e _c _sv; do
        [ -z "$_dd_e" ] && continue
        _sql=$(deep_diff_select_sql "$_dd_e" "$_dd_link_sfx")
        {
            echo "PROMPT >> AS_${_dd_e}"
            echo "DROP TABLE AS_${_dd_e} PURGE;"
            echo "CREATE TABLE AS_${_dd_e} AS"
            echo "${_sql};"
            echo ""
        } >> "$DD_GATHER_SQL"
    done

    {
        echo "PROMPT ========================================================================"
        echo "PROMPT 2. TOBE 스냅샷 (TO_*) 생성"
        echo "PROMPT ========================================================================"
    } >> "$DD_GATHER_SQL"

    deep_diff_entry_list | while IFS='|' read -r _dd_e _c _sv; do
        [ -z "$_dd_e" ] && continue
        _sql=$(deep_diff_select_sql "$_dd_e" "")
        {
            echo "PROMPT >> TO_${_dd_e}"
            echo "DROP TABLE TO_${_dd_e} PURGE;"
            echo "CREATE TABLE TO_${_dd_e} AS"
            echo "${_sql};"
            echo ""
        } >> "$DD_GATHER_SQL"
    done

    cat <<EOF >> "$DD_GATHER_SQL"
SPOOL OFF
EXIT;
EOF

    # ---------------- 2) 비교 스크립트 ----------------
    echo "  * 생성 중: $DD_COMPARE_SQL (양방향 MINUS 대조 + 오류 기록)"

    cat <<EOF > "$DD_COMPARE_SQL"
-- ==============================================================================
--  DEEP DIFF Step 2 : 양방향 MINUS 대조
--  Job ID : ${UNIQUE_ID}
--
--  ※ 모든 비교를 EXCEPTION 으로 감싸 실패 시 STATUS='ERROR' 로 반드시 기록한다.
--     (기존 도구는 실패한 항목이 결과 테이블에서 그대로 사라졌다)
-- ==============================================================================
SET SERVEROUTPUT ON SIZE UNLIMITED LINES 300 PAGES 1000 TRIMSPOOL ON FEEDBACK OFF
-- [v09.02 설계 메모] 여기도 CONTINUE 가 '의도' 다. 29개 항목 중 하나가 실패해도
--   STATUS='ERROR' 로 남기고 끝까지 돌아야 한다. EXIT FAILURE 를 걸면 첫 실패
--   항목에서 멈춰 나머지 비교 결과가 사라지고, 감사 보고서가 빈 채로 나온다.
WHENEVER SQLERROR CONTINUE
SPOOL deepdiff_2_compare_${UNIQUE_ID}.log

${PDB_SWITCH_SQL}

DROP TABLE MIG_DEEP_DIFF PURGE;
CREATE TABLE MIG_DEEP_DIFF (
  JOB_ID       VARCHAR2(64),
  ENTRY_NO     NUMBER,
  ENTRY_NAME   VARCHAR2(64),
  CATEGORY     VARCHAR2(16),
  SEVERITY     VARCHAR2(16),
  ASIS_TOTAL   NUMBER,
  TOBE_TOTAL   NUMBER,
  DIFF_A_TO_T  NUMBER,
  DIFF_T_TO_A  NUMBER,
  STATUS       VARCHAR2(16),
  ERROR_MSG    VARCHAR2(400),
  CHECKED_AT   DATE
);

PROMPT ========================================================================
PROMPT 양방향 대조 수행 중 ...
PROMPT ========================================================================
DECLARE
  v_a   NUMBER;
  v_t   NUMBER;
  v_at  NUMBER;
  v_ta  NUMBER;
  v_st  VARCHAR2(16);
BEGIN
  FOR r IN (SELECT entry_no, entry_name, category, severity
              FROM MIG_DEEP_ENTRY ORDER BY entry_no) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM AS_' || r.entry_name INTO v_a;
      EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM TO_' || r.entry_name INTO v_t;
      EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM (SELECT * FROM AS_' || r.entry_name ||
                        ' MINUS SELECT * FROM TO_' || r.entry_name || ')' INTO v_at;
      EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM (SELECT * FROM TO_' || r.entry_name ||
                        ' MINUS SELECT * FROM AS_' || r.entry_name || ')' INTO v_ta;

      IF v_at = 0 AND v_ta = 0 THEN v_st := 'PASS'; ELSE v_st := 'DIFF'; END IF;

      INSERT INTO MIG_DEEP_DIFF VALUES
        ('${UNIQUE_ID}', r.entry_no, r.entry_name, r.category, r.severity,
         v_a, v_t, v_at, v_ta, v_st, NULL, SYSDATE);

      DBMS_OUTPUT.PUT_LINE(RPAD(r.entry_name, 20) || ' ' || RPAD(r.severity, 14) ||
                           ' ASIS=' || v_a || ' TOBE=' || v_t ||
                           ' A-T=' || v_at || ' T-A=' || v_ta || '  [' || v_st || ']');
    EXCEPTION WHEN OTHERS THEN
      INSERT INTO MIG_DEEP_DIFF VALUES
        ('${UNIQUE_ID}', r.entry_no, r.entry_name, r.category, r.severity,
         NULL, NULL, NULL, NULL, 'ERROR', SUBSTR(SQLERRM, 1, 400), SYSDATE);
      DBMS_OUTPUT.PUT_LINE(RPAD(r.entry_name, 20) || ' [ERROR] ' || SUBSTR(SQLERRM, 1, 120));
    END;
  END LOOP;
  COMMIT;
END;
/

PROMPT
PROMPT ========================================================================
PROMPT DEEP DIFF 결과 요약 (ERROR -> DIFF -> PASS, MUST_MATCH 우선)
PROMPT ========================================================================
COL ENTRY_NAME FORMAT A22
COL CATEGORY   FORMAT A10
COL SEVERITY   FORMAT A14
COL STATUS     FORMAT A7
COL ERROR_MSG  FORMAT A40
SET FEEDBACK ON
SELECT entry_no, entry_name, category, severity,
       asis_total, tobe_total, diff_a_to_t, diff_t_to_a, status, error_msg
FROM MIG_DEEP_DIFF
WHERE job_id = '${UNIQUE_ID}'
ORDER BY DECODE(status,'ERROR',1,'DIFF',2,3),
         DECODE(severity,'MUST_MATCH',1,2), entry_no;

PROMPT
PROMPT ========================================================================
PROMPT 판정 : MUST_MATCH 항목 중 DIFF/ERROR 가 하나라도 있으면 이관 미완료
PROMPT ========================================================================
SELECT CASE WHEN COUNT(*) = 0 THEN 'RESULT: PASS  (MUST_MATCH 전 항목 일치)'
            ELSE 'RESULT: FAIL  (MUST_MATCH 위반 ' || COUNT(*) || ' 건 - 위 목록 확인)'
       END AS DEEP_DIFF_VERDICT
FROM MIG_DEEP_DIFF
WHERE job_id = '${UNIQUE_ID}' AND severity = 'MUST_MATCH' AND status <> 'PASS';

SPOOL OFF

-- HTML 리포트 연동용 CSV (파이프 구분)
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500 TRIMSPOOL ON
SPOOL ${DD_RESULT_CSV}
SELECT entry_no || '|' || entry_name || '|' || category || '|' || severity || '|' ||
       NVL(TO_CHAR(asis_total),'') || '|' || NVL(TO_CHAR(tobe_total),'') || '|' ||
       NVL(TO_CHAR(diff_a_to_t),'') || '|' || NVL(TO_CHAR(diff_t_to_a),'') || '|' ||
       status || '|' || NVL(REPLACE(error_msg,'|','/'),'')
FROM MIG_DEEP_DIFF
WHERE job_id = '${UNIQUE_ID}'
ORDER BY entry_no;
SPOOL OFF
EXIT;
EOF

    # ---------------- 3) 래퍼 셸 ----------------
    for _dd_pair in "${DD_GATHER_SH}:${DD_GATHER_SQL}:ASIS/TOBE 딕셔너리 스냅샷 수집" \
                 "${DD_COMPARE_SH}:${DD_COMPARE_SQL}:양방향 MINUS 대조 및 결과 리포트"; do
        _sh=$(echo "$_dd_pair" | cut -d':' -f1)
        _sq=$(echo "$_dd_pair" | cut -d':' -f2)
        _ds=$(echo "$_dd_pair" | cut -d':' -f3)
        cat <<EOF > "$_sh"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
        generate_run_prompt "$_sh" "$_ds"
        cat <<EOF >> "$_sh"
echo ">> ${_ds} 실행 중..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@${_sq}
CONNECT_EOF
_rc=\$?
if [ \$_rc -ne 0 ]; then
    echo ">> [ERROR] sqlplus 종료코드 \$_rc"
    exit \$_rc
fi
echo ">> 완료. 로그를 확인하십시오."
EOF
        chmod 700 "$_sh"
    done

    # ---------------- 4) 상세 조회 스크립트 ----------------
    echo "  * 생성 중: $DD_DETAIL_SH (차이 상세 드릴다운)"
    cat <<EOF > "$DD_DETAIL_SH"
#!/bin/bash
# ==============================================================================
#  DEEP DIFF Step 3 : 특정 항목의 실제 차이 내역 조회
#  사용법 : bash $(basename "$DD_DETAIL_SH") [ENTRY_NAME]
#           인자를 주지 않으면 목록을 보여주고 입력받는다.
# ==============================================================================
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

V_ENTRY="\$1"

if [ -z "\$V_ENTRY" ]; then
    sqlplus -S /nolog <<'SQLEOF'
connect $DB_CONN
SET LINES 220 PAGES 1000
COL ENTRY_NAME FORMAT A22
COL SEVERITY   FORMAT A14
COL STATUS     FORMAT A7
SELECT entry_no, entry_name, severity, asis_total, tobe_total,
       diff_a_to_t, diff_t_to_a, status
FROM MIG_DEEP_DIFF
ORDER BY DECODE(status,'ERROR',1,'DIFF',2,3), entry_no;
EXIT;
SQLEOF
    # [FIX] 이식성: echo -e / \\c 혼용 대신 printf 사용
    printf "조회할 ENTRY_NAME 을 입력하세요: "
    read -r V_ENTRY
fi

if [ -z "\$V_ENTRY" ]; then
    echo ">> 입력이 없어 종료합니다."
    exit 1
fi

V_ENTRY=\$(echo "\$V_ENTRY" | tr 'a-z' 'A-Z')

sqlplus -S /nolog <<SQLEOF
connect $DB_CONN
SET LINES 32767 PAGES 500 TRIMSPOOL ON TRIMOUT ON
-- ==============================================================================
-- [FIX v08.04] 12.2 부터 식별자가 VARCHAR2(128) 이라 SQL*Plus 가 컬럼마다
--   128 자를 잡는다. 컬럼이 5~7 개뿐이어도 (예: GRANTOR+OWNER+TABLE_NAME+GRANTEE)
--   한 줄이 500 자를 넘어 기존 LINES 300 에서는 통째로 줄바꿈되어 육안 대조가
--   불가능했다. 실제 사용 폭에 맞춰 컬럼을 줄여 한 줄에 들어오게 한다.
--   (해당 엔트리에 없는 컬럼에 대한 COLUMN 지정은 무해하게 무시된다)
-- ==============================================================================
COLUMN OWNER                FORMAT A20
COLUMN R_OWNER              FORMAT A20
COLUMN TABLE_OWNER          FORMAT A20
COLUMN SEQUENCE_OWNER       FORMAT A20
COLUMN REFERENCED_OWNER     FORMAT A20
COLUMN GRANTEE              FORMAT A20
COLUMN GRANTOR              FORMAT A20
COLUMN USERNAME             FORMAT A20
COLUMN PROFILE              FORMAT A20
COLUMN TABLE_NAME           FORMAT A30
COLUMN INDEX_NAME           FORMAT A30
COLUMN CONSTRAINT_NAME      FORMAT A30
COLUMN R_CONSTRAINT_NAME    FORMAT A30
COLUMN SEQUENCE_NAME        FORMAT A30
COLUMN SYNONYM_NAME         FORMAT A30
COLUMN TRIGGER_NAME         FORMAT A30
COLUMN OBJECT_NAME          FORMAT A30
COLUMN SEGMENT_NAME         FORMAT A30
COLUMN REFERENCED_NAME      FORMAT A30
COLUMN COLUMN_NAME          FORMAT A30
COLUMN NAME                 FORMAT A30
COLUMN DB_LINK              FORMAT A30
COLUMN TABLESPACE_NAME      FORMAT A22
COLUMN DEFAULT_TABLESPACE   FORMAT A22
COLUMN TEMPORARY_TABLESPACE FORMAT A22
COLUMN RESOURCE_NAME        FORMAT A26
COLUMN PRIVILEGE            FORMAT A28
COLUMN GRANTED_ROLE         FORMAT A24
COLUMN TRIGGERING_EVENT     FORMAT A24
COLUMN HOST                 FORMAT A28
COLUMN "LIMIT"              FORMAT A16
COLUMN OBJECT_TYPE          FORMAT A14
COLUMN SEGMENT_TYPE         FORMAT A14
COLUMN REFERENCED_TYPE      FORMAT A14
COLUMN CONSTRAINT_TYPE      FORMAT A4
COLUMN TYPE                 FORMAT A14
COLUMN INDEX_TYPE           FORMAT A12
COLUMN TRIGGER_TYPE         FORMAT A16
COLUMN RESOURCE_TYPE        FORMAT A10
COLUMN STATUS               FORMAT A9
COLUMN UNIQUENESS           FORMAT A9
COLUMN GRANTABLE            FORMAT A3
COLUMN ADMIN_OPTION         FORMAT A3
COLUMN DEFAULT_ROLE         FORMAT A3
COLUMN CYCLE_FLAG           FORMAT A3
COLUMN PARTITIONED          FORMAT A3
COLUMN AUTOEXTENSIBLE       FORMAT A3
COLUMN IOT_TYPE             FORMAT A12
COLUMN ACCOUNT_STATUS       FORMAT A16
COLUMN STATTYPE_LOCKED      FORMAT A6
COLUMN PARTITION_NAME       FORMAT A30
WHENEVER SQLERROR CONTINUE
PROMPT
PROMPT #==========# ASIS 에만 있는 행 (AS_\${V_ENTRY} MINUS TO_\${V_ENTRY}) #==========#
SELECT * FROM AS_\${V_ENTRY} MINUS SELECT * FROM TO_\${V_ENTRY};

PROMPT
PROMPT #==========# TOBE 에만 있는 행 (TO_\${V_ENTRY} MINUS AS_\${V_ENTRY}) #==========#
SELECT * FROM TO_\${V_ENTRY} MINUS SELECT * FROM AS_\${V_ENTRY};
EXIT;
SQLEOF
EOF
    chmod 700 "$DD_DETAIL_SH"

    GENERATED_DEEPDIFF_SCRIPTS="$DD_GATHER_SH $DD_COMPARE_SH"
    return 0
}

# ==============================================================================
# [NEW v08] 실측 행 건수 병렬 대조 모듈 (COUNT-BASED Row Verification)
#
#   v07 까지의 행 건수 검증은 Data Pump 로그 파싱에 의존했다. 이 방식은
#   "impdp 이후 데이터가 변경된 경우"를 잡지 못한다. 이 모듈은 양쪽 DB 에서
#   실제 COUNT(*) 를 수행해 로그와 독립적으로 검증한다.
#
#   기존 MIG_VALIDATE 04_DATA 대비 수정된 결함
#   ----------------------------------------------------------------------------
#   * grep "${N}#"  -> grep "^${N}#"   : 앵커 누락으로 버킷 10~15 가 0~5 스크립트에
#                                        중복 편입되어 이중 카운트되던 문제 수정
#   * awk -F#       -> sed 's/^[0-9]*#//' : 객체명에 '#' 이 있으면 문장이 잘리던 문제
#   * owner varchar2(10) -> varchar2(128) : 10자 초과 스키마가 ORA-12899 로 누락되던 문제
#   * 파티션/IOT 제외를 object_name 단독 -> (owner, table_name) 복합키로 판정
#   * sed 's/AS_/TO_/g' 전역 치환 -> 목적 테이블명만 한정 치환
#   * SYSTEM 테이블스페이스 + 48 해시파티션 -> 지정 테이블스페이스, 파티셔닝 미사용
#   * 백그라운드 실행 후 완료 감지 없음 -> wait + 종료코드 집계
#   * ps -ef | grep sqlplus | kill -9 -> 이 작업의 스크립트만 한정 종료
#   * IOT 가 dba_segments 조인에서 통째로 누락되던 문제 -> 스칼라 서브쿼리로 변경
# ==============================================================================

generate_rowcount_scripts() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _rc_tbs
    build_exclude_owner_list

    RC_BUCKETS="$ROWCOUNT_BUCKETS"
    [ -z "$RC_BUCKETS" ] && RC_BUCKETS=8
    RC_PDEG="$ROWCOUNT_PARALLEL_DEG"
    [ -z "$RC_PDEG" ] && RC_PDEG=4

    RC_PREP_SQL="rowcount_1_prepare_${UNIQUE_ID}.sql"
    RC_SPLIT_SH="rowcount_2_split_${UNIQUE_ID}.sh"
    RC_EXEC_SH="rowcount_3_exec_${UNIQUE_ID}.sh"
    RC_PULL_SQL="rowcount_4_pull_asis_${UNIQUE_ID}.sql"
    RC_CMP_SQL="rowcount_5_compare_${UNIQUE_ID}.sql"
    RC_CMP_SH="rowcount_5_compare_${UNIQUE_ID}.sh"
    RC_STOP_SH="rowcount_9_stop_${UNIQUE_ID}.sh"
    RC_RESULT_CSV="rowcount_result_${UNIQUE_ID}.csv"
    RC_PART_CSV="rowcount_part_result_${UNIQUE_ID}.csv"

    _rc_tbs="$ROWCOUNT_TABLESPACE"
    [ -z "$_rc_tbs" ] && _rc_tbs="USERS"

    # ------------------------------------------------------------------
    # [NEW v08.03] 파티션 단위 수집 모드
    #   OFF : 기존과 동일 — 모든 테이블을 테이블 단위로 1회 COUNT
    #   ON  : 파티션 테이블은 테이블 단위 COUNT 를 빼고 파티션별로 COUNT 한다.
    #         (테이블 총계는 비교 단계에서 파티션 합으로 산출 → 스캔 총량 불변)
    # ------------------------------------------------------------------
    RC_PART_TBL_FILTER=""
    RC_PART_UNION_BLOCK=""

    # 공통: 파티션 단위 수집 블록 (서브파티션이 없는 파티션에 적용)
    _rc_part_sql="
  UNION ALL
  SELECT 'insert into &PFX._TAB_CNT select ''' || p.table_owner || ''',''' || p.table_name ||
         ''',''' || p.partition_name || ''',(select /*+ parallel(${RC_PDEG}) */ count(*) from \"' ||
         p.table_owner || '\".\"' || p.table_name || '\" PARTITION (\"' || p.partition_name ||
         '\")) from dual;' AS stmt,
         (SELECT NVL(SUM(s.bytes), 0) FROM dba_segments s
           WHERE s.owner = p.table_owner AND s.segment_name = p.table_name
             AND s.partition_name = p.partition_name) AS sort_bytes
  FROM dba_tab_partitions p
  WHERE p.table_owner NOT IN (${DEEP_EXCL_OWNERS})
    AND p.table_name NOT LIKE 'BIN' || CHR(36) || '%'
    AND EXISTS (SELECT 1 FROM dba_tables t2
                 WHERE t2.owner = p.table_owner AND t2.table_name = p.table_name
                   AND t2.temporary = 'N' AND t2.secondary = 'N' AND t2.nested = 'NO')"

    if [ "$ROWCOUNT_PART_MODE" = "PART" ]; then
        RC_PART_TBL_FILTER="
    AND t.partitioned = 'NO'"
        RC_PART_UNION_BLOCK="$_rc_part_sql"

    elif [ "$ROWCOUNT_PART_MODE" = "SUBPART" ]; then
        # ------------------------------------------------------------------
        # [NEW v09.00] 서브파티션 단위
        #   복합 파티션(RANGE-HASH 등)만 서브파티션으로 내려간다. 단순 파티션
        #   테이블까지 내려갈 서브파티션이 없으므로 파티션 단위로 남긴다.
        #   즉 한 테이블은 셋 중 정확히 한 그레인으로만 세어지며, 중복 스캔이 없다.
        #     비파티션      -> 테이블 단위
        #     단순 파티션   -> 파티션 단위   (subpartition_count = 0)
        #     복합 파티션   -> 서브파티션 단위
        # ------------------------------------------------------------------
        RC_PART_TBL_FILTER="
    AND t.partitioned = 'NO'"
        RC_PART_UNION_BLOCK="${_rc_part_sql}
    AND p.subpartition_count = 0
  UNION ALL
  SELECT 'insert into &PFX._TAB_CNT select ''' || sp.table_owner || ''',''' || sp.table_name ||
         ''',''' || sp.partition_name || '/' || sp.subpartition_name ||
         ''',(select /*+ parallel(${RC_PDEG}) */ count(*) from \"' ||
         sp.table_owner || '\".\"' || sp.table_name || '\" SUBPARTITION (\"' ||
         sp.subpartition_name || '\")) from dual;' AS stmt,
         (SELECT NVL(SUM(s.bytes), 0) FROM dba_segments s
           WHERE s.owner = sp.table_owner AND s.segment_name = sp.table_name
             AND s.partition_name = sp.subpartition_name) AS sort_bytes
  FROM dba_tab_subpartitions sp
  WHERE sp.table_owner NOT IN (${DEEP_EXCL_OWNERS})
    AND sp.table_name NOT LIKE 'BIN' || CHR(36) || '%'
    AND EXISTS (SELECT 1 FROM dba_tables t2
                 WHERE t2.owner = sp.table_owner AND t2.table_name = sp.table_name
                   AND t2.temporary = 'N' AND t2.secondary = 'N' AND t2.nested = 'NO')"
    fi

    # ---------------- 1) 준비 : 카운트 테이블 + 버킷 분배된 INSERT 문 생성 ----------------
    case "$ROWCOUNT_PART_MODE" in
        PART)    _rc_grain="파티션 단위" ;;
        SUBPART) _rc_grain="서브파티션 단위" ;;
        *)       _rc_grain="테이블 단위" ;;
    esac
    echo "  * 생성 중: $RC_PREP_SQL (버킷 ${RC_BUCKETS}개, parallel ${RC_PDEG}, ${_rc_grain})"

    cat <<EOF > "$RC_PREP_SQL"
-- ==============================================================================
--  ROW COUNT Step 1 : 카운트 대상 목록 추출 및 버킷 분배
--  Job ID  : ${UNIQUE_ID}
--  사용법  : sqlplus <conn> @${RC_PREP_SQL} <PREFIX>
--            PREFIX 는 AS 또는 TO  (예: @${RC_PREP_SQL} AS)
-- ==============================================================================
SET VERIFY OFF FEEDBACK OFF HEAD OFF PAGES 0 LINES 4000 TRIMSPOOL ON LONG 100000
WHENEVER SQLERROR CONTINUE
DEFINE PFX = &1

${PDB_SWITCH_SQL}

PROMPT >> &PFX._TAB_CNT 테이블을 재생성합니다...
DROP TABLE &PFX._TAB_CNT PURGE;
CREATE TABLE &PFX._TAB_CNT (
  OWNER       VARCHAR2(128),
  TABLE_NAME  VARCHAR2(128),
  PART_NAME   VARCHAR2(300),
  TOTAL_COUNT NUMBER
) TABLESPACE ${_rc_tbs};

PROMPT >> 카운트 대상 목록을 &PFX._TAB_CNT_STMT.sql 로 생성합니다...
SPOOL &PFX._TAB_CNT_STMT.sql

SELECT MOD(ROWNUM, ${RC_BUCKETS}) || '#' || stmt
FROM (
  SELECT 'insert into &PFX._TAB_CNT select ''' || t.owner || ''',''' || t.table_name ||
         ''',null,(select /*+ parallel(a,${RC_PDEG}) */ count(*) from "' ||
         t.owner || '"."' || t.table_name || '" a) from dual;' AS stmt,
         -- [FIX] IOT 는 dba_segments 에 테이블 세그먼트가 없어 기존 조인 방식에서 통째로
         --       누락되었다. 스칼라 서브쿼리로 크기를 구해 정렬만 하고 누락은 없게 한다.
         (SELECT NVL(SUM(s.bytes), 0) FROM dba_segments s
           WHERE s.owner = t.owner AND s.segment_name = t.table_name) AS sort_bytes
  FROM dba_tables t
  WHERE t.owner NOT IN (${DEEP_EXCL_OWNERS})
    AND t.temporary = 'N'
    AND t.secondary = 'N'
    AND t.nested    = 'NO'
    AND t.table_name NOT LIKE 'BIN' || CHR(36) || '%'
    -- [FIX] 외부 테이블은 원격 파일 의존이라 카운트 대상에서 제외
    AND NOT EXISTS (SELECT 1 FROM dba_external_tables x
                     WHERE x.owner = t.owner AND x.table_name = t.table_name)${RC_PART_TBL_FILTER}${RC_PART_UNION_BLOCK}
  ORDER BY sort_bytes DESC
);

SPOOL OFF
EXIT;
EOF

    # ---------------- 2) 버킷 분할 ----------------
    echo "  * 생성 중: $RC_SPLIT_SH (앵커링된 버킷 분할)"
    cat <<EOF > "$RC_SPLIT_SH"
#!/bin/bash
# ==============================================================================
#  ROW COUNT Step 2 : 버킷별 실행 스크립트 분할
#  사용법 : bash $(basename "$RC_SPLIT_SH") <PREFIX>       (PREFIX = AS | TO)
# ==============================================================================
PFX="\${1:-AS}"
BUCKETS=${RC_BUCKETS}
SRC="\${PFX}_TAB_CNT_STMT.sql"
OUTDIR="./rc_scripts_${UNIQUE_ID}"
LOGDIR="./rc_logs_${UNIQUE_ID}"

if [ ! -f "\$SRC" ]; then
    echo "[ERROR] 입력 파일이 없습니다: \$SRC"
    echo "        먼저 rowcount_1_prepare_${UNIQUE_ID}.sql 을 \$PFX 인자로 실행하십시오."
    exit 1
fi

mkdir -p "\$OUTDIR" "\$LOGDIR"

_n=0
while [ \$_n -lt \$BUCKETS ]; do
    _f="\${OUTDIR}/\${PFX}_CNT_\${_n}.sql"
    {
        echo "set time on"
        echo "set timing on"
        echo "set echo on"
        echo "set autocommit on"
        echo "whenever sqlerror continue"
        echo "spool \${LOGDIR}/\${PFX}_CNT_\${_n}.lst"
        # [FIX] '^' 앵커가 없으면 grep 0# 가 10# 에도 매치되어 버킷 10~15 가
        #       0~5 스크립트에 중복 편입된다 (이중 카운트 + 작업량 37% 증가)
        # [FIX] awk -F# 는 객체명에 '#' 이 있으면 문장을 잘라먹는다
        grep "^\${_n}#" "\$SRC" | sed 's/^[0-9]*#//'
        echo "commit;"
        echo "set autocommit off"
        echo "spool off"
        echo "exit"
    } > "\$_f"
    _cnt=\$(grep -c '^insert into' "\$_f")
    printf "  bucket %2d : %5d tables -> %s\\n" "\$_n" "\$_cnt" "\$_f"
    _n=\$((_n + 1))
done

echo ">> 분할 완료. 총 대상: \$(grep -c '^[0-9]*#' "\$SRC") 건"
EOF
    chmod 700 "$RC_SPLIT_SH"

    # ---------------- 3) 병렬 실행 (완료 대기 + 종료코드 집계) ----------------
    echo "  * 생성 중: $RC_EXEC_SH (병렬 실행 + 완료 감지)"
    cat <<EOF > "$RC_EXEC_SH"
#!/bin/bash
# ==============================================================================
#  ROW COUNT Step 3 : 버킷 병렬 실행
#  사용법 : bash $(basename "$RC_EXEC_SH") <PREFIX> [동시실행수]
#
#  기존 도구는 '&' 로 던지고 즉시 종료해 완료 시점도, 실패 여부도 알 수 없었다.
#  슬롯이 비는 즉시 다음 버킷을 투입하고(PID 추적), 마지막에 wait 로
#  전부 회수한 뒤 버킷별 종료코드를 집계한다.
# ==============================================================================
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

PFX="\${1:-AS}"
CONC="\${2:-${RC_BUCKETS}}"
BUCKETS=${RC_BUCKETS}
OUTDIR="./rc_scripts_${UNIQUE_ID}"
LOGDIR="./rc_logs_${UNIQUE_ID}"
# [FIX v08.02] 기동한 프로세스의 PID 를 기록해 둔다. 중지 스크립트가 ps 패턴
#   매칭 대신 이 PID 만 정확히 종료하므로 엉뚱한 프로세스를 죽일 여지가 없다.
PIDFILE="./rc_pids_${UNIQUE_ID}_\${PFX}.pid"
mkdir -p "\$LOGDIR"
: > "\$PIDFILE"

echo "\$CONC" | grep -qE '^[0-9]+\$' || CONC=\$BUCKETS
[ "\$CONC" -lt 1 ] && CONC=1

echo "====================================================================="
echo "  [ROW COUNT] \${PFX} 측 실측 건수 수집 시작"
echo "  - 버킷 수     : \$BUCKETS"
echo "  - 동시 실행   : \$CONC"
echo "  - 스크립트    : \$OUTDIR"
echo "====================================================================="

_started=0
_live_pids=""
_n=0
_fail=0
while [ \$_n -lt \$BUCKETS ]; do
    _f="\${OUTDIR}/\${PFX}_CNT_\${_n}.sql"
    if [ ! -f "\$_f" ]; then
        echo "  [SKIP] \$_f 없음"
        _n=\$((_n + 1)); continue
    fi
    # [FIX v09.01] 슬롯이 빌 때까지 대기 — 배치 wait 를 대체한다.
    #   기존: CONC 개를 띄우고 "전부" 끝날 때까지 wait
    #         -> 한 버킷만 오래 걸려도 나머지 슬롯이 그동안 논다.
    #   현행: 끝난 PID 를 걷어내고 자리가 나는 즉시 다음 버킷을 투입.
    #   jobs -p 를 쓰지 않는 이유: bash 비대화형은 완료된 작업을 job 테이블에
    #         남겨 수가 부정확하고, dash 는 0 을 반환해 상한이 통째로 무시된다.
    #         kill -0 은 POSIX 이고 셸 종류를 타지 않는다.
    while : ; do
        _alive=""
        for _p in \$_live_pids; do
            kill -0 "\$_p" 2>/dev/null && _alive="\$_alive \$_p"
        done
        _live_pids="\$_alive"
        _cnt=\$(echo \$_live_pids | wc -w)
        [ "\$_cnt" -lt "\$CONC" ] && break
        sleep 2
    done

    sqlplus -S /nolog <<CONNECT_EOF > "\${LOGDIR}/\${PFX}_CNT_\${_n}.out" 2>&1 &
connect $DB_CONN
@\$_f
CONNECT_EOF
    _bg_pid=\$!
    printf '%s\\n' "\$_bg_pid" >> "\$PIDFILE"
    echo "  [START] bucket \$_n (pid \$_bg_pid)"
    _started=\$((_started + 1))
    _live_pids="\$_live_pids \$_bg_pid"
    _n=\$((_n + 1))
done

wait
rm -f "\$PIDFILE"
echo "---------------------------------------------------------------------"

_n=0
while [ \$_n -lt \$BUCKETS ]; do
    _o="\${LOGDIR}/\${PFX}_CNT_\${_n}.out"
    if [ -f "\$_o" ] && grep -qE 'ORA-|SP2-' "\$_o"; then
        echo "  [FAIL] bucket \$_n : \$(grep -E 'ORA-|SP2-' "\$_o" | head -n 1)"
        _fail=\$((_fail + 1))
    fi
    _n=\$((_n + 1))
done

if [ \$_fail -gt 0 ]; then
    echo ">> [WARNING] \$_fail 개 버킷에서 오류가 발생했습니다. \$LOGDIR 확인 필요."
    exit 1
fi
echo ">> [SUCCESS] \${PFX} 측 실측 건수 수집 완료."
EOF
    chmod 700 "$RC_EXEC_SH"

    # ---------------- 4) ASIS 결과 수집 (DB Link) ----------------
    if [ -n "$DEEP_LINK_NAME" ]; then
        echo "  * 생성 중: $RC_PULL_SQL (ASIS 건수를 DB Link 로 수집)"
        cat <<EOF > "$RC_PULL_SQL"
-- ==============================================================================
--  ROW COUNT Step 4 : ASIS 측 건수 테이블을 검증 DB 로 복사
--  Job ID : ${UNIQUE_ID}
--  ※ 기존 도구는 TRUNCATE 없이 INSERT 만 해서 재실행 시 행이 2배로 누적되었고
--     COMMIT 도 없었다. 여기서는 명시적으로 비우고 커밋한다.
-- ==============================================================================
SET ECHO ON FEEDBACK ON SERVEROUTPUT ON
-- [v09.02 설계 메모] 여기는 CONTINUE 가 '의도' 다. 바로 아래 DROP TABLE 은
--   첫 실행에서 ORA-00942 가 나는 것이 정상이므로 EXIT FAILURE 를 걸면
--   처음부터 아무것도 못 한다. 전면 적용하면 안 되는 대표 지점.
WHENEVER SQLERROR CONTINUE
SPOOL rowcount_4_pull_${UNIQUE_ID}.log

${PDB_SWITCH_SQL}

-- 로컬에 ASIS 수신용 테이블 준비
DROP TABLE AS_TAB_CNT PURGE;
CREATE TABLE AS_TAB_CNT (
  OWNER       VARCHAR2(128),
  TABLE_NAME  VARCHAR2(128),
  PART_NAME   VARCHAR2(300),
  TOTAL_COUNT NUMBER
) TABLESPACE ${_rc_tbs};

INSERT /*+ APPEND */ INTO AS_TAB_CNT
SELECT owner, table_name, part_name, total_count FROM AS_TAB_CNT@${DEEP_LINK_NAME};
COMMIT;

SELECT COUNT(*) AS ASIS_ROWCOUNT_ROWS FROM AS_TAB_CNT;

SPOOL OFF
EXIT;
EOF
    fi

    # ---------------- 5) 건수 비교 ----------------
    echo "  * 생성 중: $RC_CMP_SQL (건수 대조 리포트)"
    cat <<EOF > "$RC_CMP_SQL"
-- ==============================================================================
--  ROW COUNT Step 5 : ASIS vs TOBE 실측 건수 대조
--  Job ID : ${UNIQUE_ID}
-- ==============================================================================
SET LINES 250 PAGES 1000 TRIMSPOOL ON FEEDBACK ON SERVEROUTPUT ON
WHENEVER SQLERROR CONTINUE
SPOOL rowcount_5_compare_${UNIQUE_ID}.log

${PDB_SWITCH_SQL}

DROP TABLE MIG_ROWCOUNT_DIFF PURGE;

-- 방어적 집계: 만에 하나 중복 행이 있어도 조인이 폭발하지 않도록 선집계
--  [v08.03] 그레인(파티션) 단위로 먼저 MAX 중복 제거 후 테이블 단위로 SUM 한다.
--           - 테이블 단위 수집(PART_NAME IS NULL)만 있으면 그레인이 1개뿐이라
--             SUM = MAX 로 기존 동작과 완전히 동일하다.
--           - 파티션 단위 수집이면 파티션 합이 곧 테이블 총계가 된다.
CREATE TABLE MIG_ROWCOUNT_DIFF AS
WITH ag AS (SELECT owner, table_name, NVL(part_name, '~TBL~') gkey, MAX(total_count) cnt
              FROM AS_TAB_CNT GROUP BY owner, table_name, NVL(part_name, '~TBL~')),
     tg AS (SELECT owner, table_name, NVL(part_name, '~TBL~') gkey, MAX(total_count) cnt
              FROM TO_TAB_CNT GROUP BY owner, table_name, NVL(part_name, '~TBL~')),
     a  AS (SELECT owner, table_name, SUM(cnt) cnt FROM ag GROUP BY owner, table_name),
     t  AS (SELECT owner, table_name, SUM(cnt) cnt FROM tg GROUP BY owner, table_name)
SELECT NVL(a.owner, t.owner)           AS OWNER,
       NVL(a.table_name, t.table_name) AS TABLE_NAME,
       a.cnt                           AS ASIS_COUNT,
       t.cnt                           AS TOBE_COUNT,
       NVL(t.cnt,0) - NVL(a.cnt,0)     AS DIFF_CNT,
       CASE WHEN a.cnt IS NULL           THEN 'ONLY_IN_TOBE'
            WHEN t.cnt IS NULL           THEN 'MISSING_IN_TOBE'
            WHEN a.cnt = t.cnt           THEN 'MATCH'
            ELSE 'MISMATCH' END         AS STATUS
FROM a FULL OUTER JOIN t
  ON a.owner = t.owner AND a.table_name = t.table_name;

COL OWNER      FORMAT A22
COL TABLE_NAME FORMAT A32
COL STATUS     FORMAT A16

PROMPT ========================================================================
PROMPT 1. 불일치 / 누락 목록 (문제가 있는 것만)
PROMPT ========================================================================
SELECT owner, table_name, asis_count, tobe_count, diff_cnt, status
FROM MIG_ROWCOUNT_DIFF
WHERE status <> 'MATCH'
ORDER BY DECODE(status,'MISSING_IN_TOBE',1,'MISMATCH',2,3), ABS(NVL(diff_cnt,0)) DESC;

PROMPT
PROMPT ========================================================================
PROMPT 2. 상태별 요약
PROMPT ========================================================================
SELECT status, COUNT(*) AS TABLES, SUM(NVL(asis_count,0)) AS ASIS_ROWS, SUM(NVL(tobe_count,0)) AS TOBE_ROWS
FROM MIG_ROWCOUNT_DIFF GROUP BY status ORDER BY 1;

PROMPT
PROMPT ========================================================================
PROMPT 3. 최종 판정
PROMPT ========================================================================
SELECT CASE WHEN COUNT(*) = 0 THEN 'RESULT: PASS  (전 테이블 실측 건수 일치)'
            ELSE 'RESULT: FAIL  (' || COUNT(*) || ' 개 테이블 불일치/누락)'
       END AS ROWCOUNT_VERDICT
FROM MIG_ROWCOUNT_DIFF WHERE status <> 'MATCH';

-- ==============================================================================
--  [NEW v08.03] 파티션 단위 대조
--    파티션 단위로 수집한 경우에만 행이 생긴다(테이블 단위 수집이면 0건).
--    테이블 총계는 맞는데 파티션 경계가 어긋난 경우 — 예를 들어 파티션 키가
--    잘못 매핑되어 데이터가 옆 파티션으로 들어간 경우 — 를 잡아낸다.
-- ==============================================================================
DROP TABLE MIG_ROWCOUNT_PART_DIFF PURGE;

CREATE TABLE MIG_ROWCOUNT_PART_DIFF AS
WITH ap AS (SELECT owner, table_name, part_name, MAX(total_count) cnt
              FROM AS_TAB_CNT WHERE part_name IS NOT NULL
             GROUP BY owner, table_name, part_name),
     tp AS (SELECT owner, table_name, part_name, MAX(total_count) cnt
              FROM TO_TAB_CNT WHERE part_name IS NOT NULL
             GROUP BY owner, table_name, part_name)
SELECT NVL(ap.owner, tp.owner)             AS OWNER,
       NVL(ap.table_name, tp.table_name)   AS TABLE_NAME,
       NVL(ap.part_name, tp.part_name)     AS PART_NAME,
       ap.cnt                              AS ASIS_COUNT,
       tp.cnt                              AS TOBE_COUNT,
       NVL(tp.cnt,0) - NVL(ap.cnt,0)       AS DIFF_CNT,
       CASE WHEN ap.cnt IS NULL       THEN 'ONLY_IN_TOBE'
            WHEN tp.cnt IS NULL       THEN 'MISSING_IN_TOBE'
            WHEN ap.cnt = tp.cnt      THEN 'MATCH'
            ELSE 'MISMATCH' END            AS STATUS
FROM ap FULL OUTER JOIN tp
  ON ap.owner = tp.owner AND ap.table_name = tp.table_name AND ap.part_name = tp.part_name;

COL PART_NAME FORMAT A30

PROMPT
PROMPT ========================================================================
PROMPT 4. 파티션 단위 불일치 / 누락 (파티션 수집을 켠 경우에만 표시)
PROMPT ========================================================================
SELECT owner, table_name, part_name, asis_count, tobe_count, diff_cnt, status
FROM MIG_ROWCOUNT_PART_DIFF
WHERE status <> 'MATCH'
ORDER BY DECODE(status,'MISSING_IN_TOBE',1,'MISMATCH',2,3), ABS(NVL(diff_cnt,0)) DESC;

PROMPT
PROMPT ========================================================================
PROMPT 5. 파티션 단위 최종 판정
PROMPT ========================================================================
SELECT CASE WHEN (SELECT COUNT(*) FROM MIG_ROWCOUNT_PART_DIFF) = 0
              THEN 'RESULT: N/A   (파티션 단위 수집을 사용하지 않았습니다)'
            WHEN COUNT(*) = 0
              THEN 'RESULT: PASS  (전 파티션 실측 건수 일치)'
            ELSE 'RESULT: FAIL  (' || COUNT(*) || ' 개 파티션 불일치/누락)'
       END AS PARTITION_VERDICT
FROM MIG_ROWCOUNT_PART_DIFF WHERE status <> 'MATCH';

SPOOL OFF

-- HTML 리포트 연동용 CSV
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500 TRIMSPOOL ON
SPOOL ${RC_RESULT_CSV}
SELECT owner || '|' || table_name || '|' || NVL(TO_CHAR(asis_count),'') || '|' ||
       NVL(TO_CHAR(tobe_count),'') || '|' || NVL(TO_CHAR(diff_cnt),'') || '|' || status
FROM MIG_ROWCOUNT_DIFF
ORDER BY DECODE(status,'MATCH',9,1), owner, table_name;
SPOOL OFF

SPOOL ${RC_PART_CSV}
SELECT owner || '|' || table_name || '|' || part_name || '|' || NVL(TO_CHAR(asis_count),'') || '|' ||
       NVL(TO_CHAR(tobe_count),'') || '|' || NVL(TO_CHAR(diff_cnt),'') || '|' || status
FROM MIG_ROWCOUNT_PART_DIFF
ORDER BY DECODE(status,'MATCH',9,1), owner, table_name, part_name;
SPOOL OFF
EXIT;
EOF

    cat <<EOF > "$RC_CMP_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
EOF
    generate_run_prompt "$RC_CMP_SH" "실측 행 건수 ASIS vs TOBE 대조"
    cat <<EOF >> "$RC_CMP_SH"
echo ">> 실측 건수 대조를 수행합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@${RC_CMP_SQL}
CONNECT_EOF
EOF
    chmod 700 "$RC_CMP_SH"

    # ---------------- 9) 안전한 작업 중지 ----------------
    echo "  * 생성 중: $RC_STOP_SH (이 작업의 세션만 한정 종료)"
    cat <<EOF > "$RC_STOP_SH"
#!/bin/bash
# ==============================================================================
#  ROW COUNT : 진행 중인 건수 수집 작업만 안전하게 중지
#
#  ※ 기존 도구는 'ps -ef | grep sqlplus | kill -9' 로 서버의 모든 sqlplus 를
#     무차별 종료했다. 공용 DB 서버에서는 타 팀 작업까지 죽는 사고가 된다.
#     여기서는 이 Job 이 만든 스크립트를 실행 중인 프로세스만 대상으로 한다.
# ==============================================================================
# [FIX v08.02] PID 파일 기반 종료
#   ※ v08.01 에서 보안상 @스크립트를 heredoc(stdin)으로 옮기면서 sqlplus 의
#     커맨드라인에는 스크립트 경로가 더 이상 남지 않는다. 따라서 예전처럼
#     'ps -ef | grep <경로>' 로 대상을 찾는 방식은 원천적으로 동작하지 않는다.
#     (실측: argv 는 "sqlplus -S /nolog" 뿐, 패턴 매칭 결과 0건)
#     이 작업이 기동하며 남긴 PID 파일만을 근거로, 그것도 아직 sqlplus 인
#     프로세스만 종료한다. PID 재사용으로 엉뚱한 프로세스를 죽이지 않기 위함이다.
PIDS=""
_pidfile_found="no"
for _pf in ./rc_pids_${UNIQUE_ID}_*.pid; do
    [ -e "\$_pf" ] || continue
    _pidfile_found="yes"
    while IFS= read -r _p; do
        [ -n "\$_p" ] || continue
        echo "\$_p" | grep -qE '^[0-9]+\$' || continue
        kill -0 "\$_p" 2>/dev/null || continue
        case "\$(ps -p "\$_p" -o comm= 2>/dev/null)" in
            *sqlplus*) PIDS="\$PIDS \$_p" ;;
        esac
    done < "\$_pf"
done

if [ "\$_pidfile_found" = "no" ]; then
    echo ">> PID 파일(rc_pids_${UNIQUE_ID}_*.pid)을 찾을 수 없습니다."
    echo "   건수 수집이 이미 끝났거나, 다른 디렉토리에서 실행했을 수 있습니다."
    echo ""
    echo "   [참고] 보안 강화(v08.01)로 sqlplus 커맨드라인에 스크립트 경로가 남지 않아"
    echo "          ps 패턴만으로는 대상을 특정할 수 없습니다. DB 측에서 확인하십시오:"
    echo ""
    echo "     SELECT s.sid, s.serial#, s.username, s.status, s.sql_id, s.machine"
    echo "       FROM v\\\$session s"
    echo "      WHERE s.program LIKE 'sqlplus%' AND s.status = 'ACTIVE';"
    echo "     -- 확인 후: ALTER SYSTEM KILL SESSION '<sid>,<serial#>' IMMEDIATE;"
    exit 0
fi

if [ -z "\$PIDS" ]; then
    echo ">> 실행 중인 건수 수집 프로세스가 없습니다. (PID 파일은 있으나 모두 종료됨)"
    rm -f ./rc_pids_${UNIQUE_ID}_*.pid
    exit 0
fi

echo ">> 다음 프로세스를 종료합니다 (근거: PID 파일):"
for _p in \$PIDS; do ps -p "\$_p" -o pid=,etime=,comm= 2>/dev/null; done

printf "정말 종료하시겠습니까? (y/N): "
read -r _ans
if [ "\$_ans" != "y" ] && [ "\$_ans" != "Y" ]; then
    echo ">> 취소되었습니다."
    exit 0
fi

# 우선 정상 종료 시도 후, 남아 있으면 강제 종료
for p in \$PIDS; do kill -TERM "\$p" 2>/dev/null; done
sleep 5
for p in \$PIDS; do
    if kill -0 "\$p" 2>/dev/null; then
        echo "   강제 종료: \$p"
        kill -9 "\$p" 2>/dev/null
    fi
done
rm -f ./rc_pids_${UNIQUE_ID}_*.pid
echo ">> 종료 처리가 완료되었습니다."
echo ">> 주의: Oracle 세션은 남아 있을 수 있습니다. v\\\$session 확인 후 정리하십시오."
EOF
    chmod 700 "$RC_STOP_SH"

    GENERATED_ROWCOUNT_SCRIPTS="$RC_SPLIT_SH $RC_EXEC_SH $RC_CMP_SH"
    return 0
}

# ==============================================================================
# [NEW v08] DEEP VALIDATION 실행 모드 (메뉴 7 하위)
# ==============================================================================

# ------------------------------------------------------------------------------
# 공통: 검증용 DB Link 확인/생성
#   DEEP DIFF 는 ASIS 딕셔너리를 DB Link 로 읽어 TOBE 와 같은 DB 안에서 대조한다.
#   양쪽 스냅샷이 동일한 SELECT 텍스트로 만들어지므로 버전 차이에 영향을 받지 않는다.
# ------------------------------------------------------------------------------
setup_deep_dblink() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _dl_pwd _dl_tns _dl_user
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [ASIS Connection] DEEP DIFF reads the ASIS dictionary through a DB Link."
        printf "  Enter DB Link name to ASIS [Default: MIG_LINK, empty to skip]: "
    else
        echo "  [ASIS 접속] DEEP DIFF 는 DB Link 로 ASIS 딕셔너리를 읽어옵니다."
        printf "  ASIS 접속용 DB Link 이름을 입력하세요 [기본값: MIG_LINK]: "
    fi
    _read DEEP_LINK_NAME
    [ -z "$DEEP_LINK_NAME" ] && DEEP_LINK_NAME="MIG_LINK"
    DEEP_LINK_NAME=$(echo "$DEEP_LINK_NAME" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')

    # [FIX v09.02] MOCK 우회 경로 점검 — v09.01 까지는 여기서 그냥 return 0 했다.
    #   그 결과 DB Link 생성 DDL 을 만드는 코드가 MOCK 에서 한 번도 타지 않아,
    #   패스워드의 " / & 가 생성 SQL 을 깨뜨리는 결함(v09.02 B1)이 E2E 9종을
    #   통과한 채 남아 있었다. 이제 MOCK 에서도 '링크가 없는 경우' 로 간주해
    #   생성 경로를 끝까지 태운다 (생성물만 만들고 실행은 하지 않는다).
    if [ "$MOCK_MODE" = "true" ]; then
        echo "  >> [MOCK] DB Link '$DEEP_LINK_NAME' 미존재로 가정 — 생성 DDL 경로를 검증합니다."
        _dl_cnt=0
    else
        _dl_cnt=$(sqlplus -S /nolog <<SQL_EOF 2>/dev/null
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0
$PDB_SWITCH_SQL
SELECT COUNT(*) FROM dba_db_links WHERE db_link LIKE '${DEEP_LINK_NAME}%';
EXIT;
SQL_EOF
)
        _dl_cnt=$(to_num "$_dl_cnt")
    fi

    if [ "$_dl_cnt" -eq 0 ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> DB Link '$DEEP_LINK_NAME' not found. Generating creation DDL."
        else echo "  >> DB Link '$DEEP_LINK_NAME' 가 없습니다. 생성 DDL을 만듭니다."; fi

        printf "  - ASIS DB Username (e.g. SYSTEM): "; _read _dl_user
        printf "  - ASIS DB Password (input hidden / 입력 숨김): "
        _read_secret _dl_pwd MIG_DBLINK_PASSWORD
        printf "  - ASIS TNS Alias or IP:PORT/SERVICE_NAME: "; _read _dl_tns

        # [FIX v09.02] 빈 값 검증이 없어 사용자명/TNS 가 비어도 생성물이 나왔다.
        #   CREATE DATABASE LINK AS_LINK CONNECT TO  IDENTIFIED BY "pw" USING '';
        #   -> 실행 시 ORA-00904 / ORA-02010 로 죽는다. 이 결함은 MOCK 이 이 경로를
        #   건너뛰고 있었기 때문에 v09.01 까지 드러나지 않았다.
        if [ -z "$_dl_user" ] || [ -z "$_dl_tns" ]; then
            if [ "$LANG_PREF" = "EN" ]; then
                echo "  [ERROR] ASIS username and TNS are both required to create the DB Link."
                echo "          Nothing was generated. Re-run and supply both values,"
                echo "          or create the DB Link manually and re-enter its name."
            else
                echo "  [오류] DB Link 생성에는 ASIS 사용자명과 TNS 가 모두 필요합니다."
                echo "         (사용자명='${_dl_user}', TNS='${_dl_tns}')"
                echo "         생성물을 만들지 않았습니다. 두 값을 넣어 다시 실행하시거나,"
                echo "         DB Link 를 수동으로 만든 뒤 그 이름을 입력하십시오."
            fi
            return 1
        fi

        # [SEC v09.02] 이 패스워드는 생성 SQL 의 IDENTIFIED BY "..." 로 들어간다.
        #   큰따옴표가 있으면 생성물이 조용히 깨지므로 먼저 막는다.
        while ! check_sql_pwd_safe "ASIS DB 패스워드 / ASIS DB password" "$_dl_pwd"; do
            if [ "$UNATTENDED" = "true" ]; then
                if [ "$LANG_PREF" = "EN" ]; then echo "  [ABORT] Unattended mode cannot re-prompt. Fix MIG_DBLINK_PASSWORD and re-run."
                else echo "  [중단] 무인 모드에서는 재입력을 받을 수 없습니다. MIG_DBLINK_PASSWORD 를 고쳐 다시 실행하십시오."; fi
                return 1
            fi
            printf "  - ASIS DB Password 재입력 (큰따옴표 제외 / no double quotes): "
            _read_secret _dl_pwd ""
        done

        DD_LINK_SQL="deepdiff_0_create_dblink_${UNIQUE_ID}.sql"
        cat <<EOF > "$DD_LINK_SQL"
-- ==============================================================================
--  DEEP DIFF Step 0 : ASIS 접속용 DB Link 생성
--  주의: 이 파일에는 접속 정보가 포함됩니다. 사용 후 삭제하십시오.
-- ==============================================================================
-- [SEC v09.02] 패스워드의 '&' 가 SQL*Plus 치환변수로 먹히는 것을 막는다.
--   이 줄을 지우면 의도한 것과 다른 패스워드로 DB Link 가 만들어지고,
--   문법 오류 없이 넘어간 뒤 나중에 ORA-01017 로 나타난다.
$(sql_define_off)
-- [v09.02] DB Link 생성 실패를 셸이 \$? 로 알 수 있게 한다.
WHENEVER SQLERROR EXIT FAILURE
WHENEVER OSERROR EXIT FAILURE
$PDB_SWITCH_SQL
CREATE DATABASE LINK ${DEEP_LINK_NAME} CONNECT TO ${_dl_user} IDENTIFIED BY "${_dl_pwd}" USING '${_dl_tns}';
SELECT 'DB Link OK : ' || SYSDATE FROM dual@${DEEP_LINK_NAME};
EXIT;
EOF
        chmod 600 "$DD_LINK_SQL"
        echo "  >> 생성됨: $DD_LINK_SQL (권한 600, 사용 후 삭제 권장)"
        GENERATED_DEEPDIFF_PRE="$DD_LINK_SQL"
    else
        if [ "$LANG_PREF" = "EN" ]; then echo "  >> Existing DB Link '$DEEP_LINK_NAME' will be used."
        else echo "  >> 기존 DB Link '$DEEP_LINK_NAME' 를 사용합니다."; fi
    fi
    return 0
}

# ------------------------------------------------------------------------------
# 7-2. DEEP DIFF : ASIS <-> TOBE 딕셔너리 심층 대조
# ------------------------------------------------------------------------------
run_deep_diff_mode() {
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [7-2] DEEP DIFF : ASIS <-> TOBE Dictionary Bi-directional Comparison"
    else echo " [7-2] DEEP DIFF : ASIS <-> TOBE 딕셔너리 심층 대조"; fi
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  권한 / 프로파일 / 쿼터 / 시노님 / DB Link / 객체 / 제약 / 시퀀스 등"
        echo "  29개 항목을 양방향 MINUS 로 대조합니다."
    else
        echo "  Data Pump 로그가 알려주지 않는 영역을 검증합니다:"
        echo "   · 시스템/롤/객체 권한, 프로파일, 테이블스페이스 쿼터"
        echo "   · PUBLIC 시노님, DB Link, 제약조건, 시퀀스, 트리거, 객체 의존성"
        echo "  총 29개 항목을 양방향 MINUS 로 대조하고 MUST_MATCH/참고 항목을 분리합니다."
    fi
    echo "======================================================================"

    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE / CPU: $CPU_CORES"
    echo "----------------------------------------------------------------------"

    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Oracle connection for the VALIDATION(TOBE) DB [Default: / as sysdba]: "
    else printf "  검증(TOBE) DB 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info

    DATE_STR=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$")
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Job ID [Default: DEEP_${DATE_STR}]: "
    else printf "  작업 ID를 입력하세요 [기본값: DEEP_${DATE_STR}]: "; fi
    _read user_id
    if [ -z "$user_id" ]; then UNIQUE_ID="DEEP_${DATE_STR}"; else UNIQUE_ID=$(echo "$user_id" | tr ' ' '_'); fi

    setup_deep_dblink

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  Additional owners to exclude (comma separated, empty for none): "
    else printf "  추가로 제외할 계정이 있으면 입력하세요 (쉼표 구분, 없으면 엔터): "; fi
    _read DEEP_EXTRA_EXCLUDE

    echo "----------------------------------------------------------------------"
    generate_deep_diff_scripts

    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> DEEP DIFF Script Generation Complete!"
    else echo "  >> DEEP DIFF 스크립트 생성 완료! (대조 항목 ${DEEP_ENTRY_COUNT}개)"; fi
    echo "  [실행 순서]"
    [ -n "$GENERATED_DEEPDIFF_PRE" ] && echo "  0) $GENERATED_DEEPDIFF_PRE   (DB Link 생성 - 필요 시)"
    echo "  1) $DD_GATHER_SH   (ASIS/TOBE 스냅샷 수집)"
    echo "  2) $DD_COMPARE_SH  (양방향 MINUS 대조 + 판정)"
    echo "  3) $DD_DETAIL_SH   (차이 상세 드릴다운 - 필요 시)"
    echo "  [결과]"
    echo "  * MIG_DEEP_DIFF 테이블 / $DD_RESULT_CSV (HTML 리포트 연동)"
    echo "======================================================================"

    # 마스터 파이프라인으로 실행 가능하게 러너도 생성
    generate_master_runner_script "Deep Diff Validation Pipeline" "$GENERATED_DEEPDIFF_SCRIPTS"
    echo "  [Master Runner] $MASTER_RUNNER_SH"
    echo "======================================================================"

    for gs in $GENERATED_DEEPDIFF_SCRIPTS; do ask_to_run_script "$gs"; done
    return 0
}

# ------------------------------------------------------------------------------
# 7-3. 실측 행 건수 병렬 대조
# ------------------------------------------------------------------------------
# ==============================================================================
# [NEW v09.00] 해시 기반 정합성 검사
#
#  왜 건수 대조로 부족한가
#  ---------------------------------------------------------------------------
#  COUNT(*) 가 같아도 값이 바뀐 것은 못 잡는다. 임포트 후 애플리케이션이 붙어
#  UPDATE 가 돌았거나, 문자셋 변환에서 잘림이 생겼거나, 날짜가 타임존 때문에
#  밀렸다면 건수는 그대로다. 행 내용을 요약한 해시를 양쪽에서 구해 비교한다.
#
#  설계에서 가장 중요한 두 가지
#  ---------------------------------------------------------------------------
#  1) 문자셋이 바뀌면 같은 문자열도 바이트가 달라 해시가 달라진다.
#     KO16MSWIN949 -> AL32UTF8 이관에서 그냥 해시하면 전 테이블이 불일치로 나온다.
#     그래서 문자형 컬럼은 CONVERT(col,'AL32UTF8') 로 정규화한 뒤 해시한다.
#     AL32UTF8 은 상위 집합이라 이 방향 변환은 무손실이다.
#  2) 행 순서에 의존하면 안 된다. ASIS 와 TOBE 의 물리 순서는 다르다.
#     행마다 해시를 구한 뒤 SUM / MIN / MAX 로 집계한다. 셋 다 순서 무관이며,
#     COUNT 까지 네 값이 모두 같아야 일치로 본다.
#
#  정규화 규칙 (양쪽에서 동일해야 하므로 명시적으로 고정한다)
#     문자형        CONVERT(col,'AL32UTF8')      문자셋 차이 제거
#     숫자형        TO_CHAR(col)                 NLS_NUMERIC_CHARACTERS 고정
#     DATE          YYYYMMDDHH24MISS
#     TIMESTAMP     YYYYMMDDHH24MISSFF9
#     TS WITH TZ    SYS_EXTRACT_UTC 후 동일 포맷  타임존 차이 제거
#     RAW           RAWTOHEX
#     NULL          '~N~' 센티널                 NULL 연결로 값이 사라지는 것 방지
#
#  제외 대상: LOB / LONG / BFILE / XMLTYPE / 사용자정의타입
#     해시 대상에서 빼고, 제외한 컬럼 수를 결과에 기록한다.
# ==============================================================================
generate_hash_scripts() {
    # [v09.02] local 제거 (ksh 비호환): _hs_tbs _hs_fn _hs_pre _hs_post
    HS_PREP_SQL="hash_1_prepare_${UNIQUE_ID}.sql"
    HS_SPLIT_SH="hash_2_split_${UNIQUE_ID}.sh"
    HS_EXEC_SH="hash_3_exec_${UNIQUE_ID}.sh"
    HS_PULL_SQL="hash_4_pull_asis_${UNIQUE_ID}.sql"
    HS_CMP_SQL="hash_5_compare_${UNIQUE_ID}.sql"
    HS_CMP_SH="hash_5_compare_${UNIQUE_ID}.sh"
    HS_RESULT_CSV="hash_result_${UNIQUE_ID}.csv"

    _hs_tbs="$HASH_TABLESPACE"
    [ -z "$_hs_tbs" ] && _hs_tbs="USERS"

    # 12c 이상은 STANDARD_HASH(SHA256), 11g 는 ORA_HASH 로 낮춘다.
    _hs_fn="STANDARD_HASH"
    case "$DB_VERSION" in
        9.*|10.*|11.*) _hs_fn="ORA_HASH" ;;
    esac
    HASH_FUNC_USED="$_hs_fn"

    # [주의] 아래 문자열은 생성될 SQL 안에서 "문자열 리터럴" 로 들어간다.
    #        따라서 내부 작은따옴표는 반드시 두 번 써야 한다(''). 한 번만 쓰면
    #        리터럴이 조기 종료되어 ORA-01756 으로 죽는다.
    if [ "$_hs_fn" = "ORA_HASH" ]; then
        _hs_pre="TO_NUMBER(ORA_HASH("
        _hs_post="))"
        echo "  [주의] DB 버전이 11g 이하라 ORA_HASH(32bit) 를 사용합니다."
        echo "         SHA256 보다 충돌 가능성이 높으니 건수 대조와 함께 보십시오."
    else
        _hs_pre="TO_NUMBER(SUBSTR(RAWTOHEX(STANDARD_HASH("
        _hs_post=",''SHA256'')),1,12),''XXXXXXXXXXXX'')"
    fi

    echo "  * 생성 중: $HS_PREP_SQL (해시 함수: ${_hs_fn})"

    cat <<EOF > "$HS_PREP_SQL"
-- ==============================================================================
--  HASH Step 1 : 테이블별 해시 수집문 생성
--  Job ID  : ${UNIQUE_ID}
--  사용법  : sqlplus <conn> @${HS_PREP_SQL} <PREFIX>      (PREFIX = AS | TO)
--
--  정규화 규칙은 ASIS/TOBE 양쪽에서 반드시 동일해야 합니다.
--  아래 세션 설정이 그 전제이므로 임의로 바꾸지 마십시오.
-- ==============================================================================
SET VERIFY OFF FEEDBACK OFF HEAD OFF PAGES 0 LINES 32767 LONG 2000000 LONGCHUNKSIZE 32767 TRIMSPOOL ON
WHENEVER SQLERROR CONTINUE
DEFINE PFX = &1

ALTER SESSION SET NLS_NUMERIC_CHARACTERS = '.,';
ALTER SESSION SET NLS_DATE_FORMAT = 'YYYYMMDDHH24MISS';

${PDB_SWITCH_SQL}

PROMPT >> &PFX._TAB_HASH 테이블을 재생성합니다...
DROP TABLE &PFX._TAB_HASH PURGE;
CREATE TABLE &PFX._TAB_HASH (
  OWNER       VARCHAR2(128),
  TABLE_NAME  VARCHAR2(128),
  ROW_CNT     NUMBER,
  HASH_SUM    NUMBER,
  HASH_MIN    NUMBER,
  HASH_MAX    NUMBER,
  COL_CNT     NUMBER,
  SKIP_CNT    NUMBER
) TABLESPACE ${_hs_tbs};

PROMPT >> 해시 수집문을 &PFX._TAB_HASH_STMT.sql 로 생성합니다...
SPOOL &PFX._TAB_HASH_STMT.sql

SELECT MOD(ROWNUM, ${HASH_BUCKETS}) || '#' || stmt
FROM (
  SELECT 'insert into &PFX._TAB_HASH select ''' || x.owner || ''',''' || x.table_name || ''',' ||
         'count(*),' ||
         'nvl(sum(h),0),' ||
         'nvl(min(h),0),' ||
         'nvl(max(h),0),' ||
         x.col_cnt || ',' || x.skip_cnt ||
         ' from (select /*+ parallel(${HASH_PDEG}) */ ' ||
         '${_hs_pre}' || x.expr || '${_hs_post} h from "' ||
         x.owner || '"."' || x.table_name || '");' AS stmt,
         x.sort_bytes
  FROM (
    SELECT c.owner, c.table_name,
           -- LISTAGG 는 VARCHAR2 4000 제한이 있어 넓은 테이블에서 잘린다.
           -- XMLAGG 는 CLOB 이라 제한이 없다 (11g 이상 공통).
           RTRIM(XMLAGG(XMLELEMENT(e,
             CASE
               WHEN c.data_type IN ('VARCHAR2','CHAR','NVARCHAR2','NCHAR')
                 THEN 'NVL(CONVERT("' || c.column_name || '",''AL32UTF8''),''~N~'')'
               WHEN c.data_type IN ('NUMBER','FLOAT','BINARY_FLOAT','BINARY_DOUBLE')
                 THEN 'NVL(TO_CHAR("' || c.column_name || '"),''~N~'')'
               WHEN c.data_type = 'DATE'
                 THEN 'NVL(TO_CHAR("' || c.column_name || '",''YYYYMMDDHH24MISS''),''~N~'')'
               WHEN c.data_type LIKE 'TIMESTAMP%TIME ZONE'
                 THEN 'NVL(TO_CHAR(SYS_EXTRACT_UTC("' || c.column_name || '"),''YYYYMMDDHH24MISSFF9''),''~N~'')'
               WHEN c.data_type LIKE 'TIMESTAMP%'
                 THEN 'NVL(TO_CHAR("' || c.column_name || '",''YYYYMMDDHH24MISSFF9''),''~N~'')'
               WHEN c.data_type = 'RAW'
                 THEN 'NVL(RAWTOHEX("' || c.column_name || '"),''~N~'')'
               WHEN c.data_type LIKE 'INTERVAL%'
                 THEN 'NVL(TO_CHAR("' || c.column_name || '"),''~N~'')'
             END || '||''|''||'
           ).EXTRACT('//text()') ORDER BY c.column_id).GETCLOBVAL(), '||''|''||') AS expr,
           COUNT(*) AS col_cnt,
           (SELECT COUNT(*) FROM dba_tab_columns c2
             WHERE c2.owner = c.owner AND c2.table_name = c.table_name
               AND (c2.data_type IN ('CLOB','NCLOB','BLOB','BFILE','LONG','LONG RAW','ROWID','UROWID','XMLTYPE')
                    OR c2.data_type_owner IS NOT NULL)) AS skip_cnt,
           (SELECT NVL(SUM(s.bytes), 0) FROM dba_segments s
             WHERE s.owner = c.owner AND s.segment_name = c.table_name) AS sort_bytes
    FROM dba_tab_columns c
    WHERE c.owner NOT IN (${DEEP_EXCL_OWNERS})
      AND c.data_type_owner IS NULL
      AND c.data_type NOT IN ('CLOB','NCLOB','BLOB','BFILE','LONG','LONG RAW','ROWID','UROWID','XMLTYPE')
      AND c.table_name NOT LIKE 'BIN' || CHR(36) || '%'
      AND EXISTS (SELECT 1 FROM dba_tables t
                   WHERE t.owner = c.owner AND t.table_name = c.table_name
                     AND t.temporary = 'N' AND t.secondary = 'N' AND t.nested = 'NO'
                     AND NOT EXISTS (SELECT 1 FROM dba_external_tables x
                                      WHERE x.owner = t.owner AND x.table_name = t.table_name))
    GROUP BY c.owner, c.table_name
  ) x
  WHERE x.expr IS NOT NULL
  ORDER BY x.sort_bytes DESC
);

SPOOL OFF

PROMPT
PROMPT >> 해시 대상에서 제외된 컬럼 (LOB/LONG/XMLType/사용자정의타입)
COL OWNER FORMAT A20
COL TABLE_NAME FORMAT A30
SELECT owner, table_name, COUNT(*) AS skipped_cols
  FROM dba_tab_columns
 WHERE owner NOT IN (${DEEP_EXCL_OWNERS})
   AND (data_type IN ('CLOB','NCLOB','BLOB','BFILE','LONG','LONG RAW','ROWID','UROWID','XMLTYPE')
        OR data_type_owner IS NOT NULL)
 GROUP BY owner, table_name
 ORDER BY 3 DESC, 1, 2;

EXIT;
EOF
    return 0
}

# ------------------------------------------------------------------------------
# [NEW v09.00] 해시 수집 실행 스크립트 (버킷 분할 / 병렬 실행 / 대조)
# ------------------------------------------------------------------------------
generate_hash_run_scripts() {
    echo "  * 생성 중: $HS_SPLIT_SH / $HS_EXEC_SH / $HS_CMP_SQL"

    cat <<EOF > "$HS_SPLIT_SH"
#!/bin/bash
# ==============================================================================
#  HASH Step 2 : 버킷별 실행 스크립트 분할
#  사용법 : bash $(basename "$HS_SPLIT_SH") <PREFIX>       (PREFIX = AS | TO)
# ==============================================================================
PFX="\${1:-AS}"
BUCKETS=${HASH_BUCKETS}
SRC="\${PFX}_TAB_HASH_STMT.sql"
OUTDIR="./hs_scripts_${UNIQUE_ID}"
LOGDIR="./hs_logs_${UNIQUE_ID}"

if [ ! -f "\$SRC" ]; then
    echo "[ERROR] 입력 파일이 없습니다: \$SRC"
    echo "        먼저 ${HS_PREP_SQL} 을 \$PFX 인자로 실행하십시오."
    exit 1
fi

mkdir -p "\$OUTDIR" "\$LOGDIR"

_n=0
while [ \$_n -lt \$BUCKETS ]; do
    _f="\${OUTDIR}/\${PFX}_HASH_\${_n}.sql"
    {
        echo "set time on"
        echo "set timing on"
        echo "set echo on"
        echo "set autocommit on"
        echo "whenever sqlerror continue"
        echo "alter session set nls_numeric_characters = '.,';"
        echo "alter session set nls_date_format = 'YYYYMMDDHH24MISS';"
        echo "${PDB_SWITCH_SQL}"
        echo "spool \${LOGDIR}/\${PFX}_HASH_\${_n}.lst"
        grep "^\${_n}#" "\$SRC" | sed "s/^\${_n}#//"
        echo "commit;"
        echo "set autocommit off"
        echo "spool off"
        echo "exit"
    } > "\$_f"
    _cnt=\$(grep -c "^insert into" "\$_f")
    printf "  bucket %2s : %5s tables -> %s\n" "\$_n" "\$_cnt" "\$_f"
    _n=\$((_n + 1))
done
echo ">> 분할 완료. 총 대상: \$(grep -c '#' "\$SRC") 건"
EOF
    chmod 700 "$HS_SPLIT_SH"

    cat <<EOF > "$HS_EXEC_SH"
#!/bin/bash
# ==============================================================================
#  HASH Step 3 : 버킷 병렬 실행
#  사용법 : bash $(basename "$HS_EXEC_SH") <PREFIX>        (PREFIX = AS | TO)
# ==============================================================================
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

PFX="\${1:-AS}"
OUTDIR="./hs_scripts_${UNIQUE_ID}"
LOGDIR="./hs_logs_${UNIQUE_ID}"
mkdir -p "\$LOGDIR"

echo "======================================================================"
echo "  HASH 수집 시작 : PFX=\$PFX / 버킷 ${HASH_BUCKETS}개"
echo "  해시 함수      : ${HASH_FUNC_USED}"
echo "======================================================================"

_n=0
while [ \$_n -lt ${HASH_BUCKETS} ]; do
    _s="\${OUTDIR}/\${PFX}_HASH_\${_n}.sql"
    if [ -f "\$_s" ]; then
        # [SEC v08.01] 접속 문자열은 stdin 으로만 전달한다.
        sqlplus -S /nolog <<CONNECT_EOF > "\${LOGDIR}/\${PFX}_HASH_\${_n}.out" 2>&1 &
connect $DB_CONN
@\$_s
CONNECT_EOF
        echo \$! > "./hs_pids_${UNIQUE_ID}_\${PFX}_\${_n}.pid"
        echo "  기동: bucket \$_n (pid \$!)"
    fi
    _n=\$((_n + 1))
done

wait

_fail=0
_n=0
while [ \$_n -lt ${HASH_BUCKETS} ]; do
    _o="\${LOGDIR}/\${PFX}_HASH_\${_n}.out"
    if [ -f "\$_o" ] && grep -qE 'ORA-|SP2-' "\$_o"; then
        echo "  [FAIL] bucket \$_n : \$(grep -E 'ORA-|SP2-' "\$_o" | head -n 1)"
        _fail=\$((_fail + 1))
    fi
    rm -f "./hs_pids_${UNIQUE_ID}_\${PFX}_\${_n}.pid"
    _n=\$((_n + 1))
done

echo "======================================================================"
if [ \$_fail -gt 0 ]; then
    echo ">> [경고] \$_fail 개 버킷에서 오류가 발생했습니다. \$LOGDIR 를 확인하십시오."
    exit 1
fi
echo ">> \${PFX}_TAB_HASH 수집 완료."
exit 0
EOF
    chmod 700 "$HS_EXEC_SH"
    return 0
}

# ------------------------------------------------------------------------------
# [NEW v09.00] 해시 대조 스크립트
# ------------------------------------------------------------------------------
generate_hash_compare_scripts() {
    # [v09.02] local 제거 (ksh 비호환): _hs_link
    _hs_link=""
    [ -n "$DEEP_LINK_NAME" ] && _hs_link="@${DEEP_LINK_NAME}"

    if [ -n "$DEEP_LINK_NAME" ]; then
        cat <<EOF > "$HS_PULL_SQL"
-- ==============================================================================
--  HASH Step 4 : ASIS 해시를 DB Link 로 가져오기
--  주의: 해시는 각 DB 에서 로컬로 계산해야 합니다. 여기서는 이미 계산된
--        결과 테이블만 옮깁니다. 원격 테이블을 링크 너머로 해시하면
--        문자셋 변환이 한 번 더 개입해 값이 달라집니다.
-- ==============================================================================
SET FEEDBACK ON
${PDB_SWITCH_SQL}
DROP TABLE AS_TAB_HASH PURGE;
CREATE TABLE AS_TAB_HASH AS SELECT * FROM AS_TAB_HASH${_hs_link};
SELECT COUNT(*) AS ASIS_HASH_ROWS FROM AS_TAB_HASH;
EXIT;
EOF
    fi

    cat <<EOF > "$HS_CMP_SQL"
-- ==============================================================================
--  HASH Step 5 : ASIS <-> TOBE 해시 대조
--  Job ID : ${UNIQUE_ID}
--
--  판정: ROW_CNT / HASH_SUM / HASH_MIN / HASH_MAX 네 값이 모두 같아야 일치.
--        SUM 만 보면 서로 다른 값 조합이 우연히 같은 합을 낼 수 있으므로
--        MIN / MAX 를 함께 본다. 셋 다 순서 무관 집계다.
-- ==============================================================================
SET LINESIZE 220 PAGESIZE 200 FEEDBACK OFF TRIMSPOOL ON
WHENEVER SQLERROR CONTINUE
SPOOL hash_5_compare_${UNIQUE_ID}.log

${PDB_SWITCH_SQL}

DROP TABLE MIG_HASH_DIFF PURGE;

CREATE TABLE MIG_HASH_DIFF AS
SELECT NVL(a.owner, t.owner)             AS OWNER,
       NVL(a.table_name, t.table_name)   AS TABLE_NAME,
       a.row_cnt   AS ASIS_ROWS,  t.row_cnt   AS TOBE_ROWS,
       a.hash_sum  AS ASIS_HASH,  t.hash_sum  AS TOBE_HASH,
       a.col_cnt   AS ASIS_COLS,  t.col_cnt   AS TOBE_COLS,
       NVL(a.skip_cnt,0) AS SKIPPED_COLS,
       CASE
         WHEN a.owner IS NULL                       THEN 'ONLY_IN_TOBE'
         WHEN t.owner IS NULL                       THEN 'MISSING_IN_TOBE'
         WHEN NVL(a.col_cnt,-1) <> NVL(t.col_cnt,-2) THEN 'COLUMN_MISMATCH'
         WHEN NVL(a.row_cnt,-1) <> NVL(t.row_cnt,-2) THEN 'ROWCOUNT_MISMATCH'
         WHEN NVL(a.hash_sum,-1) = NVL(t.hash_sum,-2)
          AND NVL(a.hash_min,-1) = NVL(t.hash_min,-2)
          AND NVL(a.hash_max,-1) = NVL(t.hash_max,-2) THEN 'MATCH'
         ELSE 'DATA_MISMATCH'
       END AS STATUS
FROM AS_TAB_HASH a FULL OUTER JOIN TO_TAB_HASH t
  ON a.owner = t.owner AND a.table_name = t.table_name;

COL OWNER      FORMAT A20
COL TABLE_NAME FORMAT A30
COL STATUS     FORMAT A18

PROMPT ========================================================================
PROMPT 1. 불일치 목록 (문제가 있는 것만)
PROMPT ========================================================================
SELECT owner, table_name, asis_rows, tobe_rows, asis_cols, tobe_cols, status
  FROM MIG_HASH_DIFF
 WHERE status <> 'MATCH'
 ORDER BY DECODE(status,'MISSING_IN_TOBE',1,'COLUMN_MISMATCH',2,
                        'ROWCOUNT_MISMATCH',3,'DATA_MISMATCH',4,5), owner, table_name;

PROMPT
PROMPT ========================================================================
PROMPT 2. 상태별 요약
PROMPT ========================================================================
SELECT status, COUNT(*) AS TABLES, SUM(NVL(asis_rows,0)) AS ASIS_ROWS
  FROM MIG_HASH_DIFF GROUP BY status ORDER BY 1;

PROMPT
PROMPT ========================================================================
PROMPT 3. 해시 대상에서 제외된 컬럼이 있는 테이블
PROMPT    (LOB/LONG/XMLType 은 해시하지 않으므로, 이 테이블은 해시가 일치해도
PROMPT     해당 컬럼의 내용은 검증되지 않았습니다)
PROMPT ========================================================================
SELECT owner, table_name, skipped_cols
  FROM MIG_HASH_DIFF
 WHERE NVL(skipped_cols,0) > 0
 ORDER BY skipped_cols DESC, owner, table_name;

PROMPT
PROMPT ========================================================================
PROMPT 4. 최종 판정
PROMPT ========================================================================
SELECT CASE WHEN COUNT(*) = 0 THEN 'RESULT: PASS  (전 테이블 해시 일치)'
            ELSE 'RESULT: FAIL  (' || COUNT(*) || ' 개 테이블 불일치)'
       END AS HASH_VERDICT
  FROM MIG_HASH_DIFF WHERE status <> 'MATCH';

SPOOL OFF

-- HTML 리포트 연동용 CSV
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 500 TRIMSPOOL ON
SPOOL ${HS_RESULT_CSV}
SELECT owner || '|' || table_name || '|' ||
       NVL(TO_CHAR(asis_rows),'') || '|' || NVL(TO_CHAR(tobe_rows),'') || '|' ||
       NVL(TO_CHAR(asis_hash),'') || '|' || NVL(TO_CHAR(tobe_hash),'') || '|' ||
       NVL(TO_CHAR(skipped_cols),'0') || '|' || status
  FROM MIG_HASH_DIFF
 ORDER BY DECODE(status,'MATCH',9,1), owner, table_name;
SPOOL OFF
EXIT;
EOF

    cat <<EOF > "$HS_CMP_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
echo ">> 해시 대조를 실행합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@${HS_CMP_SQL}
CONNECT_EOF
echo ">> 완료. 결과: hash_5_compare_${UNIQUE_ID}.log / ${HS_RESULT_CSV}"
EOF
    chmod 700 "$HS_CMP_SH"
    return 0
}

# ------------------------------------------------------------------------------
# [NEW v09.00] [7-4] HASH VERIFY 메뉴
# ------------------------------------------------------------------------------
run_hash_mode() {
    # [v09.02] local 제거 (ksh 비호환): _hs_def_bucket _hs_charset_warn
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [7-4] HASH VERIFY : Row Content Hash Comparison"
    else echo " [7-4] HASH VERIFY : 행 내용 해시 대조 (값 변경 탐지)"; fi
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  COUNT(*) matches but values changed? This catches that."
    else
        echo "  건수는 같은데 값이 바뀐 경우를 잡습니다."
        echo "  임포트 이후 UPDATE, 문자셋 변환 잘림, 타임존 밀림 등이 대상입니다."
    fi
    echo "======================================================================"

    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE / CPU: $CPU_CORES"
    echo "----------------------------------------------------------------------"

    if [ "$LANG_PREF" = "EN" ]; then printf "  Oracle 접속 계정 [기본값: / as sysdba]: "
    else printf "  Oracle 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info
    calculate_parallel_degree

    DATE_STR=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$")
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Job ID [Default: HASH_${DATE_STR}]: "
    else printf "  작업 ID를 입력하세요 [기본값: HASH_${DATE_STR}]: "; fi
    _read user_id
    if [ -z "$user_id" ]; then UNIQUE_ID="HASH_${DATE_STR}"; else UNIQUE_ID=$(echo "$user_id" | tr ' ' '_'); fi

    _hs_def_bucket="$CALC_PARALLEL"
    [ -z "$_hs_def_bucket" ] && _hs_def_bucket=8
    [ "$_hs_def_bucket" -lt 1 ] && _hs_def_bucket=1

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  Number of parallel buckets [Default: %s]: " "$_hs_def_bucket"
    else printf "  분할 버킷(동시 세션) 수 [기본값: %s]: " "$_hs_def_bucket"; fi
    _read HASH_BUCKETS
    echo "$HASH_BUCKETS" | grep -qE '^[0-9]+$' || HASH_BUCKETS="$_hs_def_bucket"
    [ "$HASH_BUCKETS" -lt 1 ] && HASH_BUCKETS=1

    if [ "$LANG_PREF" = "EN" ]; then printf "  Per-table PARALLEL degree [Default: 4]: "
    else printf "  테이블당 PARALLEL 도수 [기본값: 4]: "; fi
    _read HASH_PDEG
    echo "$HASH_PDEG" | grep -qE '^[0-9]+$' || HASH_PDEG=4
    [ "$HASH_PDEG" -lt 1 ] && HASH_PDEG=1

    if [ "$LANG_PREF" = "EN" ]; then printf "  Tablespace for the hash table [Default: USERS]: "
    else printf "  해시 결과 저장 테이블스페이스 [기본값: USERS]: "; fi
    _read HASH_TABLESPACE
    [ -z "$HASH_TABLESPACE" ] && HASH_TABLESPACE="USERS"

    if [ "$LANG_PREF" = "EN" ]; then printf "  DB Link name to pull ASIS hashes (empty to skip): "
    else printf "  ASIS 해시를 가져올 DB Link 이름 (미사용 시 엔터): "; fi
    _read DEEP_LINK_NAME
    [ -n "$DEEP_LINK_NAME" ] && DEEP_LINK_NAME=$(echo "$DEEP_LINK_NAME" | tr 'a-z' 'A-Z')

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  추가로 제외할 계정 (쉼표 구분, 없으면 엔터): "
    else printf "  추가로 제외할 계정 (쉼표 구분, 없으면 엔터): "; fi
    _read DEEP_EXTRA_EXCLUDE
    build_exclude_owner_list

    # ------------------------------------------------------------------
    # 문자셋 안내 — 해시 검증에서 가장 오해가 많은 지점이라 먼저 설명한다.
    # ------------------------------------------------------------------
    echo "----------------------------------------------------------------------"
    echo "  [문자셋과 해시]"
    echo "   현재 DB 문자셋: ${DB_CHARSET}"
    if [ -n "$DB_CHARSET" ] && [ "$DB_CHARSET" != "AL32UTF8" ]; then
        echo "   ASIS 와 TOBE 의 문자셋이 다르면 같은 문자열도 바이트가 달라"
        echo "   해시가 전부 불일치로 나옵니다. 이 도구는 문자형 컬럼을"
        echo "   CONVERT(col,'AL32UTF8') 로 정규화한 뒤 해시하므로 그 영향을 제거합니다."
    else
        echo "   AL32UTF8 기준으로 정규화하여 해시합니다."
    fi
    echo "   LOB / LONG / XMLType / 사용자정의타입은 해시 대상에서 제외되며,"
    echo "   제외된 컬럼 수가 결과에 함께 기록됩니다."

    echo "----------------------------------------------------------------------"
    generate_hash_scripts       || return 1
    generate_hash_run_scripts   || return 1
    generate_hash_compare_scripts || return 1

    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> HASH VERIFY 스크립트 생성 완료"
    else echo "  >> 해시 대조 스크립트 생성 완료!"; fi
    echo "======================================================================"
    echo "  [실행 순서]"
    echo "   ASIS(원본 DB) 에서"
    echo "     1) sqlplus <conn> @${HS_PREP_SQL} AS"
    echo "     2) bash ${HS_SPLIT_SH} AS"
    echo "     3) bash ${HS_EXEC_SH} AS"
    echo "   TOBE(대상 DB) 에서"
    echo "     4) sqlplus <conn> @${HS_PREP_SQL} TO"
    echo "     5) bash ${HS_SPLIT_SH} TO"
    echo "     6) bash ${HS_EXEC_SH} TO"
    if [ -n "$DEEP_LINK_NAME" ]; then
        echo "     7) sqlplus <conn> @${HS_PULL_SQL}          (AS_TAB_HASH 이관)"
    else
        echo "     7) AS_TAB_HASH 를 대조 DB 로 이관 (DB Link 미지정 - 수동)"
    fi
    echo "     8) bash ${HS_CMP_SH}                        (대조 및 판정)"
    echo "  [결과] MIG_HASH_DIFF / ${HS_RESULT_CSV}"
    echo "  [해시함수] ${HASH_FUNC_USED}"
    echo "======================================================================"

    GENERATED_HASH_SCRIPTS="$HS_SPLIT_SH $HS_EXEC_SH $HS_CMP_SH"
    echo "  [생성된 실행 스크립트]"
    for gs in $GENERATED_HASH_SCRIPTS; do echo "   - $gs"; done
    echo "======================================================================"
    return 0
}

run_rowcount_mode() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _rc_def_bucket
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [7-3] ROW COUNT : Actual COUNT(*) Parallel Verification"
    else echo " [7-3] ROW COUNT : 실측 행 건수 병렬 대조 (로그 비의존)"; fi
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  Verifies row counts by running real COUNT(*) on both sides,"
        echo "  independent of Data Pump logs."
    else
        echo "  Data Pump 로그가 아닌 실제 COUNT(*) 로 양쪽 건수를 대조합니다."
        echo "  로그 기반 검증(메뉴 3)이 잡지 못하는 '임포트 이후의 데이터 변경'을 잡습니다."
    fi
    echo "======================================================================"

    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE / CPU: $CPU_CORES"
    echo "----------------------------------------------------------------------"

    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Oracle connection [Default: / as sysdba]: "
    else printf "  Oracle 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info
    calculate_parallel_degree

    DATE_STR=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$")
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Job ID [Default: RCNT_${DATE_STR}]: "
    else printf "  작업 ID를 입력하세요 [기본값: RCNT_${DATE_STR}]: "; fi
    _read user_id
    if [ -z "$user_id" ]; then UNIQUE_ID="RCNT_${DATE_STR}"; else UNIQUE_ID=$(echo "$user_id" | tr ' ' '_'); fi

    # 버킷 수 = 병렬 도수 기반 자동 산정 (기존 도구는 16으로 고정되어 있었음)
    _rc_def_bucket="$CALC_PARALLEL"
    [ -z "$_rc_def_bucket" ] && _rc_def_bucket=8
    [ "$_rc_def_bucket" -lt 1 ] && _rc_def_bucket=1
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  Number of parallel buckets [Default: %s]: " "$_rc_def_bucket"
    else printf "  분할 버킷(동시 세션) 수 [기본값: %s]: " "$_rc_def_bucket"; fi
    _read ROWCOUNT_BUCKETS
    echo "$ROWCOUNT_BUCKETS" | grep -qE '^[0-9]+$' || ROWCOUNT_BUCKETS="$_rc_def_bucket"
    [ "$ROWCOUNT_BUCKETS" -lt 1 ] && ROWCOUNT_BUCKETS=1

    if [ "$LANG_PREF" = "EN" ]; then printf "  Per-table PARALLEL degree for COUNT(*) [Default: 4]: "
    else printf "  테이블당 COUNT(*) PARALLEL 도수 [기본값: 4]: "; fi
    _read ROWCOUNT_PARALLEL_DEG
    echo "$ROWCOUNT_PARALLEL_DEG" | grep -qE '^[0-9]+$' || ROWCOUNT_PARALLEL_DEG=4
    [ "$ROWCOUNT_PARALLEL_DEG" -lt 1 ] && ROWCOUNT_PARALLEL_DEG=1

    _rc_total=$((ROWCOUNT_BUCKETS * ROWCOUNT_PARALLEL_DEG))
    echo "  >> 최대 동시 병렬 슬레이브 예상: ${ROWCOUNT_BUCKETS} x ${ROWCOUNT_PARALLEL_DEG} = ${_rc_total}"
    if [ "$_rc_total" -gt 64 ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  [WARNING] This may saturate the instance. Consider lowering the values."
        else echo "  [경고] 인스턴스 부하가 클 수 있습니다. 운영 중이면 값을 낮추십시오."; fi
    fi

    if [ "$LANG_PREF" = "EN" ]; then printf "  Tablespace for the count table [Default: USERS]: "
    else printf "  건수 저장 테이블의 테이블스페이스 [기본값: USERS]: "; fi
    _read ROWCOUNT_TABLESPACE
    [ -z "$ROWCOUNT_TABLESPACE" ] && ROWCOUNT_TABLESPACE="USERS"

    # ------------------------------------------------------------------
    # [NEW v08.03] 파티션 단위 건수 수집 여부
    #   기본값 N : 파티션이 수천 개인 DB 에서 문장 수가 폭증하므로 명시적 선택으로 둔다.
    #   Y 로 켜면 파티션 테이블은 테이블 단위 COUNT 대신 파티션별 COUNT 를 수행하고,
    #   테이블 합계는 비교 단계에서 파티션 합으로 산출한다(스캔 총량은 동일).
    # ------------------------------------------------------------------
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [Counting grain]"
        echo "   1) TABLE        - one COUNT per table (default)"
        echo "   2) PARTITION    - partitioned tables counted per partition"
        echo "   3) SUBPARTITION - composite-partitioned tables counted per subpartition"
        printf "  Select (1-3) [Default: 1]: "
    else
        echo "  [건수 수집 단위]"
        echo "   1) 테이블 단위      - 테이블당 COUNT 1회 (기본)"
        echo "   2) 파티션 단위      - 파티션 테이블은 파티션별로 COUNT"
        echo "   3) 서브파티션 단위  - 복합 파티션 테이블은 서브파티션별로 COUNT"
        printf "  선택 (1-3) [기본값: 1]: "
    fi
    _read rc_part_opt
    case "$rc_part_opt" in
        2|y|Y) ROWCOUNT_PART_MODE="PART" ;;
        3)     ROWCOUNT_PART_MODE="SUBPART" ;;
        *)     ROWCOUNT_PART_MODE="NONE" ;;
    esac
    case "$ROWCOUNT_PART_MODE" in
        PART)
            if [ "$LANG_PREF" = "EN" ]; then echo "  >> Partition-level counting ENABLED"
            else echo "  >> 파티션 단위 수집 활성화 (파티션 테이블은 파티션별로 COUNT)"; fi ;;
        SUBPART)
            if [ "$LANG_PREF" = "EN" ]; then echo "  >> Subpartition-level counting ENABLED"
            else echo "  >> 서브파티션 단위 수집 활성화"; fi
            echo "     복합 파티션이 아닌 파티션 테이블은 파티션 단위로 수집됩니다." ;;
        *)
            if [ "$LANG_PREF" = "EN" ]; then echo "  >> Table-level counting (default)"
            else echo "  >> 테이블 단위 수집 (기본)"; fi ;;
    esac

    if [ "$LANG_PREF" = "EN" ]; then printf "  DB Link name to pull ASIS counts (empty to skip): "
    else printf "  ASIS 건수를 가져올 DB Link 이름 (미사용 시 엔터): "; fi
    _read DEEP_LINK_NAME
    [ -n "$DEEP_LINK_NAME" ] && DEEP_LINK_NAME=$(echo "$DEEP_LINK_NAME" | tr 'a-z' 'A-Z')

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then printf "  Additional owners to exclude (comma separated, empty for none): "
    else printf "  추가로 제외할 계정 (쉼표 구분, 없으면 엔터): "; fi
    _read DEEP_EXTRA_EXCLUDE

    echo "----------------------------------------------------------------------"
    generate_rowcount_scripts

    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> Row Count Script Generation Complete!"
    else echo "  >> 실측 건수 대조 스크립트 생성 완료!"; fi
    echo "  [ASIS 서버에서]"
    echo "   1) sqlplus <conn> @$RC_PREP_SQL AS"
    echo "   2) bash $RC_SPLIT_SH AS"
    echo "   3) bash $RC_EXEC_SH AS"
    echo "  [TOBE(검증) 서버에서]"
    echo "   4) sqlplus <conn> @$RC_PREP_SQL TO"
    echo "   5) bash $RC_SPLIT_SH TO"
    echo "   6) bash $RC_EXEC_SH TO"
    if [ -n "$DEEP_LINK_NAME" ]; then
        echo "   7) sqlplus <conn> @$RC_PULL_SQL      (ASIS 건수 수집)"
    else
        echo "   7) AS_TAB_CNT 를 검증 DB 로 이관 (DB Link 미지정 - 수동)"
    fi
    echo "   8) bash $RC_CMP_SH                      (대조 및 판정)"
    echo "  [중지] bash $RC_STOP_SH                  (이 작업 세션만 안전 종료)"
    echo "  [결과] MIG_ROWCOUNT_DIFF / $RC_RESULT_CSV"
    echo "----------------------------------------------------------------------"
    echo "  [생성된 실행 스크립트]"
    for gs in $GENERATED_ROWCOUNT_SCRIPTS; do echo "   - $gs"; done
    echo "   - $RC_STOP_SH"
    echo "======================================================================"
    return 0
}

# ------------------------------------------------------------------------------
# 메뉴 7 디스패처
# ------------------------------------------------------------------------------
run_data_integrity_menu() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _di_sel
    while true; do
        clear_screen
        echo "======================================================================"
        if [ "$LANG_PREF" = "EN" ]; then echo " [7] DATA INTEGRITY & DEEP VALIDATION"
        else echo " [7] 데이터 정합성 & 심층 검증"; fi
        echo "======================================================================"
        if [ "$LANG_PREF" = "EN" ]; then
            echo "  1) Object Matrix / Constraints / Indexes / Sequence Sync"
            echo "  2) DEEP DIFF  : ASIS<->TOBE dictionary comparison (29 items)   [NEW]"
            echo "  3) ROW COUNT  : Actual COUNT(*) parallel verification          [NEW]"
            echo "  4) HASH VERIFY: Row content hash comparison                    [NEW]"
            echo "  9) Back to main menu"
            printf "  Select (1-4, 9): "
        else
            echo "  1) 객체 매트릭스 / 제약조건 / 인덱스 / 시퀀스 동기화  (기존)"
            echo "  2) DEEP DIFF  : ASIS↔TOBE 딕셔너리 29개 항목 심층 대조   [신규]"
            echo "  3) ROW COUNT  : 실측 COUNT(*) 병렬 건수 대조             [신규]"
            echo "  4) HASH VERIFY: 행 내용 해시 대조 (값 변경 탐지)          [신규]"
            echo "  9) 메인 메뉴로"
            printf "  선택 (1-4, 9): "
        fi
        _read _di_sel
        [ -z "$_di_sel" ] && _di_sel="9"

        case "$_di_sel" in
            1) run_integrity_check ;;
            2) run_deep_diff_mode ;;
            3) run_rowcount_mode ;;
            4) run_hash_mode ;;
            9|q|Q) return 0 ;;
            *) echo "  올바른 번호를 입력하세요."; sleep 1 ;;
        esac

        if [ "$UNATTENDED" = "true" ]; then
            return 0
        fi
        printf "  계속하려면 엔터를 누르세요: "
        _read _dummy
    done
}

# 8. Target Schema / PDB Cleanup & Rollback Helper
run_cleanup_mode() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _target_drop_pdb
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [8] CLEANUP TOOL: Target Schema & PDB Cleanup & Rollback Helper"
    else echo " [8] CLEANUP TOOL : Target 스키마 & PDB 원상복구 Clean-up 스크립트 생성"; fi
    echo "======================================================================"

    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE"
    echo "  * CPU Cores: $CPU_CORES"
    echo "  * Memory: $MEM_SIZE"
    echo "----------------------------------------------------------------------"

    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Oracle connection account [Default: / as sysdba]: "
    else printf "  Oracle 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info

    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [Select Cleanup Method]"
        echo "  1) Drop Schema User (DROP USER ... CASCADE)"
        echo "  2) Truncate Tables Only (Preserve Users & Tablespaces, Disable FKs & Truncate)"
        if [ "$IS_CDB" = "YES" ]; then echo "  3) Drop Entire PDB (DROP PLUGGABLE DATABASE ... INCLUDING DATAFILES)"; fi
        printf "  Select (1-3) [Default: 1]: "
    else
        echo "  [클린업 방식 선택]"
        echo "  1) 스키마 완전 삭제 (DROP USER ... CASCADE)"
        echo "  2) 데이터만 비우기 (테이블스페이스/계정 유지, 외래키 비활성화 후 TRUNCATE)"
        if [ "$IS_CDB" = "YES" ]; then echo "  3) PDB 통째로 완전 삭제 (DROP PLUGGABLE DATABASE ... INCLUDING DATAFILES)"; fi
        printf "  선택 (1-3) [기본값: 1]: "
    fi
    _read clean_opt
    [ -z "$clean_opt" ] && clean_opt="1"

    DATE_STR=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$")
    UNIQUE_ID="CLEAN_${DATE_STR}"

    CLEAN_SQL="cleanup_target_${UNIQUE_ID}.sql"
    CLEAN_SH="cleanup_target_${UNIQUE_ID}.sh"

    if [ "$clean_opt" = "3" ] && [ "$IS_CDB" = "YES" ]; then
        _target_drop_pdb="APP_PDB"
        [ -n "$SELECTED_PDB" ] && [ "$SELECTED_PDB" != "CDB\$ROOT" ] && _target_drop_pdb="$SELECTED_PDB"
        
        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter PDB Name to Drop [Default: %s]: " "$_target_drop_pdb"
        else printf "  완전 삭제할 PDB 이름을 입력하세요 [기본값: %s]: " "$_target_drop_pdb"; fi
        _read user_drop_pdb
        [ -z "$user_drop_pdb" ] && user_drop_pdb="$_target_drop_pdb"
        user_drop_pdb=$(echo "$user_drop_pdb" | tr 'a-z' 'A-Z' | awk '{$1=$1;print}')

        # [FIX v08.04] RAC 에서는 모든 인스턴스에서 닫혀야 DROP 이 된다 (ORA-65025).
        _pdb_close_scope=""
        if [ "$DB_CLUSTER" = "TRUE" ]; then
            _pdb_close_scope=" INSTANCES=ALL"
            echo "  [RAC] 클러스터 환경이므로 CLOSE IMMEDIATE INSTANCES=ALL 을 적용합니다."
        fi

        cat <<EOF > "$CLEAN_SQL"
-- ==============================================================================
--  Oracle Multitenant PDB Drop & Reset Script
--  Target PDB: ${user_drop_pdb} (${DATE_STR})
-- ==============================================================================
SET ECHO ON LOGONLY SERVEROUTPUT ON LINES 250
SPOOL cleanup_pdb_${UNIQUE_ID}.log

-- ==============================================================================
-- [FIX v08.04] DROP PLUGGABLE DATABASE 는 CDB\$ROOT 에서만 수행할 수 있다.
--   PDB 서비스명으로 직접 접속한 경우(예: system/pw@//host:1521/SALESPDB) 세션이
--   이미 해당 PDB 안에 있으므로, 자기 자신을 닫고 삭제하려다 ORA-65040 으로 실패한다.
--   로컬 PDB 사용자는 CDB\$ROOT 로 전환할 권한이 없으므로, 그 경우엔 여기서 즉시
--   중단시켜 "절반만 실행된 상태"를 만들지 않는다.
-- ==============================================================================
PROMPT 0. Switching session to CDB\$ROOT...
WHENEVER SQLERROR EXIT FAILURE
ALTER SESSION SET CONTAINER = CDB\$ROOT;
WHENEVER SQLERROR CONTINUE

DECLARE
  v_con VARCHAR2(128);
BEGIN
  SELECT SYS_CONTEXT('USERENV','CON_NAME') INTO v_con FROM dual;
  IF v_con <> 'CDB\$ROOT' THEN
    RAISE_APPLICATION_ERROR(-20901,
      'CDB\$ROOT 전환에 실패했습니다. 현재 컨테이너=' || v_con ||
      ' / 공통 사용자(SYS, SYSTEM, C##...)로 CDB 에 접속한 뒤 다시 실행하십시오.');
  END IF;
  DBMS_OUTPUT.PUT_LINE('Container confirmed: ' || v_con);
END;
/

PROMPT 1. Closing PDB ${user_drop_pdb} Immediately...
ALTER PLUGGABLE DATABASE ${user_drop_pdb} CLOSE IMMEDIATE${_pdb_close_scope};

PROMPT 2. Dropping PDB ${user_drop_pdb} Including Datafiles...
DROP PLUGGABLE DATABASE ${user_drop_pdb} INCLUDING DATAFILES;

SPOOL OFF
EXIT;
EOF
    else
        if [ "$LANG_PREF" = "EN" ]; then printf "  Enter target schemas to clean up (comma-separated, e.g. KMSUNG,SCOTT): "
        else printf "  초기화/원상복구할 Target 스키마명을 입력하세요 (쉼표 구분, 예: KMSUNG,SCOTT): "; fi
        _read clean_schemas
        clean_schemas=$(normalize_list "$clean_schemas")
        if [ -z "$clean_schemas" ]; then
            if [ "$LANG_PREF" = "EN" ]; then echo "  [ERROR] Schema name is required."; else echo "  [오류] 스키마명 입력이 필요합니다."; fi
            sleep 1
            return 1
        fi

        cat <<EOF > "$CLEAN_SQL"
-- ==============================================================================
--  Oracle Target Schema Cleanup & Rollback Script
--  Generated for Schemas: ${clean_schemas} (${DATE_STR})
-- ==============================================================================
SET ECHO ON LOGONLY SERVEROUTPUT ON LINES 250
$PDB_SWITCH_SQL
SPOOL cleanup_target_${UNIQUE_ID}.log

PROMPT ========================================================================
PROMPT 1. Killing Active Sessions for Target Schemas (RAC gv\$session support)
PROMPT ========================================================================
DECLARE
  v_count NUMBER := 0;
BEGIN
  FOR r IN (
    SELECT inst_id, sid, serial# FROM gv\$session 
    WHERE username IN (
      SELECT TRIM(regexp_substr(UPPER('${clean_schemas}'), '[^,]+', 1, level))
      FROM dual CONNECT BY level <= NVL(length(regexp_replace('${clean_schemas}', '[^,]+')), 0) + 1
    ) AND username IS NOT NULL
  ) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER SYSTEM KILL SESSION ''' || r.sid || ',' || r.serial# || ',@' || r.inst_id || ''' IMMEDIATE';
      v_count := v_count + 1;
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
  DBMS_OUTPUT.PUT_LINE('Killed ' || v_count || ' active user sessions across cluster instances.');
END;
/
EOF

        if [ "$clean_opt" = "1" ]; then
            cat <<EOF >> "$CLEAN_SQL"

PROMPT ========================================================================
PROMPT 2. Dropping Target Schemas (DROP USER CASCADE)
PROMPT ========================================================================
DECLARE
  v_sql VARCHAR2(200);
BEGIN
  FOR r IN (
    SELECT username FROM dba_users 
    WHERE username IN (
      SELECT TRIM(regexp_substr(UPPER('${clean_schemas}'), '[^,]+', 1, level))
      FROM dual CONNECT BY level <= NVL(length(regexp_replace('${clean_schemas}', '[^,]+')), 0) + 1
    ) AND username IS NOT NULL
  ) LOOP
    BEGIN
      v_sql := 'DROP USER "' || r.username || '" CASCADE';
      DBMS_OUTPUT.PUT_LINE('Executing: ' || v_sql);
      EXECUTE IMMEDIATE v_sql;
    EXCEPTION WHEN OTHERS THEN
      DBMS_OUTPUT.PUT_LINE('Error dropping user ' || r.username || ': ' || SQLERRM);
    END;
  END LOOP;
END;
/
EOF
        else
            cat <<EOF >> "$CLEAN_SQL"

PROMPT ========================================================================
PROMPT 2-0. [사전 점검] 외부 스키마에서 들어오는 참조(Inbound FK) 확인
PROMPT ========================================================================
-- ==============================================================================
-- [FIX v08.04] 기존에는 "정리 대상 스키마가 소유한" FK 만 비활성화했다.
--   목록 밖의 스키마가 정리 대상을 참조하고 있으면 그 FK 는 살아 있으므로
--   TRUNCATE 가 ORA-02266 으로 실패한다. 게다가 EXCEPTION WHEN OTHERS THEN NULL
--   이 이를 통째로 삼켜서, 작업자에게는 "정상 완료"로 보였다.
--   → 들어오는 참조를 먼저 드러내고, 실패는 반드시 집계해 보고한다.
-- ==============================================================================
SET SERVEROUTPUT ON SIZE UNLIMITED
DECLARE
  v_in NUMBER := 0;
BEGIN
  FOR c IN (
    SELECT c.owner, c.table_name, c.constraint_name, c.r_owner
    FROM dba_constraints c
    WHERE c.constraint_type = 'R'
      AND c.r_owner IN (
        SELECT TRIM(regexp_substr(UPPER('${clean_schemas}'), '[^,]+', 1, level))
        FROM dual CONNECT BY level <= NVL(length(regexp_replace('${clean_schemas}', '[^,]+')), 0) + 1
      )
      AND c.owner NOT IN (
        SELECT TRIM(regexp_substr(UPPER('${clean_schemas}'), '[^,]+', 1, level))
        FROM dual CONNECT BY level <= NVL(length(regexp_replace('${clean_schemas}', '[^,]+')), 0) + 1
      )
  ) LOOP
    v_in := v_in + 1;
    DBMS_OUTPUT.PUT_LINE('  [INBOUND FK] ' || c.owner || '.' || c.table_name ||
                         ' -> ' || c.r_owner || '  (' || c.constraint_name || ')');
  END LOOP;

  IF v_in > 0 THEN
    DBMS_OUTPUT.PUT_LINE('  ------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('  [경고] 정리 대상 밖의 스키마 ' || v_in || ' 곳이 대상 스키마를 참조합니다.');
    DBMS_OUTPUT.PUT_LINE('         TRUNCATE 를 위해 아래에서 함께 DISABLE 하지만,');
    DBMS_OUTPUT.PUT_LINE('         데이터가 비워지면 그쪽에 고아 행(orphan)이 남습니다.');
    DBMS_OUTPUT.PUT_LINE('         이관 완료 후 해당 FK 를 직접 검토/재활성화하십시오.');
    DBMS_OUTPUT.PUT_LINE('  ------------------------------------------------------------');
  ELSE
    DBMS_OUTPUT.PUT_LINE('  들어오는 외부 참조 없음.');
  END IF;
END;
/

PROMPT ========================================================================
PROMPT 2. Disabling Foreign Keys & Truncating Tables
PROMPT ========================================================================
DECLARE
  v_fk_ok   NUMBER := 0;
  v_fk_err  NUMBER := 0;
  v_tr_ok   NUMBER := 0;
  v_tr_err  NUMBER := 0;
BEGIN
  -- Disable FK Constraints (나가는 참조 + 들어오는 참조 양방향)
  FOR c IN (
    SELECT owner, constraint_name, table_name
    FROM dba_constraints
    WHERE constraint_type = 'R'
      AND ( owner IN (
              SELECT TRIM(regexp_substr(UPPER('${clean_schemas}'), '[^,]+', 1, level))
              FROM dual CONNECT BY level <= NVL(length(regexp_replace('${clean_schemas}', '[^,]+')), 0) + 1
            )
         OR r_owner IN (
              SELECT TRIM(regexp_substr(UPPER('${clean_schemas}'), '[^,]+', 1, level))
              FROM dual CONNECT BY level <= NVL(length(regexp_replace('${clean_schemas}', '[^,]+')), 0) + 1
            ) )
      AND owner IS NOT NULL
  ) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER TABLE "' || c.owner || '"."' || c.table_name || '" DISABLE CONSTRAINT "' || c.constraint_name || '"';
      v_fk_ok := v_fk_ok + 1;
    EXCEPTION WHEN OTHERS THEN
      v_fk_err := v_fk_err + 1;
      DBMS_OUTPUT.PUT_LINE('  [FK DISABLE 실패] ' || c.owner || '.' || c.table_name ||
                           ' (' || c.constraint_name || ') : ' || SUBSTR(SQLERRM, 1, 160));
    END;
  END LOOP;

  -- Truncate Tables
  FOR t IN (
    SELECT owner, table_name
    FROM dba_tables
    WHERE owner IN (
      SELECT TRIM(regexp_substr(UPPER('${clean_schemas}'), '[^,]+', 1, level))
      FROM dual CONNECT BY level <= NVL(length(regexp_replace('${clean_schemas}', '[^,]+')), 0) + 1
    ) AND owner IS NOT NULL
  ) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'TRUNCATE TABLE "' || t.owner || '"."' || t.table_name || '"';
      v_tr_ok := v_tr_ok + 1;
    EXCEPTION WHEN OTHERS THEN
      v_tr_err := v_tr_err + 1;
      DBMS_OUTPUT.PUT_LINE('  [TRUNCATE 실패] ' || t.owner || '.' || t.table_name ||
                           ' : ' || SUBSTR(SQLERRM, 1, 160));
    END;
  END LOOP;

  DBMS_OUTPUT.PUT_LINE('  ------------------------------------------------------------');
  DBMS_OUTPUT.PUT_LINE('  FK DISABLE : 성공 ' || v_fk_ok || ' / 실패 ' || v_fk_err);
  DBMS_OUTPUT.PUT_LINE('  TRUNCATE   : 성공 ' || v_tr_ok || ' / 실패 ' || v_tr_err);

  IF v_tr_err > 0 OR v_fk_err > 0 THEN
    DBMS_OUTPUT.PUT_LINE('  >> RESULT: FAIL  (데이터가 남아 있는 테이블이 있습니다)');
    DBMS_OUTPUT.PUT_LINE('     이 상태로 impdp 를 진행하면 중복 적재(ORA-00001)가 발생합니다.');
    RAISE_APPLICATION_ERROR(-20902,
      'Cleanup 미완료: TRUNCATE 실패 ' || v_tr_err || ' 건 / FK DISABLE 실패 ' || v_fk_err || ' 건');
  ELSE
    DBMS_OUTPUT.PUT_LINE('  >> RESULT: PASS  (전 대상 테이블 초기화 완료)');
  END IF;
END;
/
EOF
        fi

        cat <<EOF >> "$CLEAN_SQL"

PROMPT ========================================================================
PROMPT 3. Purging Orphaned Data Pump Master Tables
PROMPT ========================================================================
BEGIN
  FOR r IN (
    SELECT owner, object_name FROM dba_objects 
    WHERE (object_name LIKE 'SYS_EXPORT_%' OR object_name LIKE 'SYS_IMPORT_%' OR object_name LIKE 'MIG_%')
      AND object_type = 'TABLE'
      AND owner IN (
        SELECT TRIM(regexp_substr(UPPER('${clean_schemas}'), '[^,]+', 1, level))
        FROM dual CONNECT BY level <= NVL(length(regexp_replace('${clean_schemas}', '[^,]+')), 0) + 1
      ) AND owner IS NOT NULL
  ) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'DROP TABLE "' || r.owner || '"."' || r.object_name || '" PURGE';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  END LOOP;
END;
/

SPOOL OFF
EXIT;
EOF
    fi

    cat <<EOF > "$CLEAN_SH"
#!/bin/bash
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo ">> Target 스키마/PDB 원상복구 클린업 스크립트를 실행합니다..."
sqlplus -S /nolog <<CONNECT_EOF
connect $DB_CONN
@$CLEAN_SQL
CONNECT_EOF
echo ">> 클린업이 완료되었습니다. 결과 로그 파일: cleanup_target_${UNIQUE_ID}.log"
EOF
    chmod 700 "$CLEAN_SH"

    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo "  >> Target Cleanup Script Generation Complete!"; else echo "  >> 타겟 스키마/PDB 클린업 스크립트 생성 완료!"; fi
    echo "  - $CLEAN_SH"
    echo "  - $CLEAN_SQL"
    echo "======================================================================"

    ask_to_run_script "$CLEAN_SH"
}

# ==============================================================================
# [NEW v07] 9. Data Pump Job Resume / Attach & Pipeline Retry Helper
#   - 중단·실패한 Data Pump Job 에 attach 하여 재개(START_JOB) / 안전중지 / 삭제
#   - 마스터 파이프라인 체크포인트 상태 확인 및 재개 명령 안내
#   - 고아 Master Table 정리 스크립트 생성
# ==============================================================================
run_resume_mode() {
    # [NEW v08.03] 함수 스크래치 변수 지역화 — 메뉴 재진입/함수 간 값 누수 차단
    # [v09.02] local 제거 (ksh 비호환): _dp_conn _dp_desc _job_act _job_sel _jown _kill_confirm
    clear_screen
    echo "======================================================================"
    if [ "$LANG_PREF" = "EN" ]; then echo " [9] RESUME & RETRY : Data Pump Job Attach / Restart / Pipeline Resume"
    else echo " [9] RESUME & RETRY : 중단된 Data Pump 작업 재개 및 파이프라인 재시도"; fi
    echo "======================================================================"

    detect_os_and_hw
    echo "  * OS Type: $OS_TYPE"
    echo "----------------------------------------------------------------------"

    # ------------------------------------------------------------------
    # 1) 마스터 파이프라인 체크포인트 현황
    # ------------------------------------------------------------------
    if [ "$LANG_PREF" = "EN" ]; then echo "  [1] Master Pipeline Checkpoints in current directory"
    else echo "  [1] 현재 디렉토리의 마스터 파이프라인 체크포인트 현황"; fi
    _state_found=0
    for _st in ./master_state_*.state; do
        [ -e "$_st" ] || continue
        _state_found=$((_state_found + 1))
        _done_cnt=$(grep -c '^DONE:' "$_st" 2>/dev/null)
        _uid_part=$(basename "$_st" | sed 's/^master_state_//; s/\.state$//')
        printf "   - %-45s 완료 스텝: %s\n" "$(basename "$_st")" "$_done_cnt"
        printf "     재개 명령: bash 00_RUN_ALL_MASTER_%s.sh -y --resume\n" "$_uid_part"
    done
    if [ "$_state_found" -eq 0 ]; then
        echo "   (체크포인트 파일 없음 - 아직 마스터 러너를 실행하지 않았거나 다른 경로에 있습니다)"
    fi
    echo "----------------------------------------------------------------------"

    # ------------------------------------------------------------------
    # 2) DB 에 남아 있는 Data Pump Job 조회
    # ------------------------------------------------------------------
    if [ "$LANG_PREF" = "EN" ]; then printf "  Enter Oracle connection account [Default: / as sysdba]: "
    else printf "  Oracle 접속 계정을 입력하세요 [기본값: / as sysdba]: "; fi
    _read user_conn
    [ -n "$user_conn" ] && DB_CONN="$user_conn"

    check_db_env || return 1
    fetch_db_info

    _job_tmp="$(tmpf dp_jobs.tmp)"
    _job_idx="$(tmpf dp_jobs.indexed)"
    rm -f "$_job_tmp" "$_job_idx"

    if [ "$MOCK_MODE" = "true" ]; then
        cat <<'MOCKEOF' > "$_job_tmp"
SYSTEM|MIG_SCHEMA_20260905_EXP_GROUP|EXPORT|SCHEMA|NOT RUNNING
SYSTEM|MIG_SCHEMA_20260905_IMP_P2|IMPORT|SCHEMA|EXECUTING
MOCKEOF
    else
        sqlplus -S /nolog <<SQL_EOF > "$_job_tmp" 2>/dev/null
connect $DB_CONN
SET HEAD OFF FEEDBACK OFF PAGES 0 LINES 300 TRIMSPOOL ON
$PDB_SWITCH_SQL
SELECT owner_name || '|' || job_name || '|' || operation || '|' || job_mode || '|' || state
FROM dba_datapump_jobs
ORDER BY owner_name, job_name;
EXIT;
SQL_EOF
    fi

    echo ""
    if [ "$LANG_PREF" = "EN" ]; then echo "  [2] Data Pump Jobs registered in the Data Dictionary"
    else echo "  [2] 데이터 딕셔너리에 등록된 Data Pump Job 목록"; fi
    echo "  ------------------------------------------------------------------------------------"
    printf "  %4s | %-12s | %-32s | %-8s | %-10s | %-12s\n" "No." "OWNER" "JOB_NAME" "OPER" "MODE" "STATE"
    echo "  ------------------------------------------------------------------------------------"

    _job_cnt=0
    while IFS='|' read -r _jown _jname _joper _jmode _jstate; do
        _jown=$(echo "$_jown" | awk '{$1=$1;print}')
        _jname=$(echo "$_jname" | awk '{$1=$1;print}')
        [ -z "$_jname" ] && continue
        echo "$_jname" | grep -qE 'ORA-|SP2-' && continue
        _joper=$(echo "$_joper" | awk '{$1=$1;print}')
        _jmode=$(echo "$_jmode" | awk '{$1=$1;print}')
        _jstate=$(echo "$_jstate" | awk '{$1=$1;print}')
        _job_cnt=$((_job_cnt + 1))
        printf "  %4d | %-12s | %-32s | %-8s | %-10s | %-12s\n" "$_job_cnt" "$_jown" "$_jname" "$_joper" "$_jmode" "$_jstate"
        printf "%d|%s|%s|%s|%s\n" "$_job_cnt" "$_jown" "$_jname" "$_joper" "$_jstate" >> "$_job_idx"
    done < "$_job_tmp"
    echo "  ------------------------------------------------------------------------------------"
    rm -f "$_job_tmp"

    if [ "$_job_cnt" -eq 0 ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  [INFO] No Data Pump jobs found. Nothing to resume."
        else echo "  [안내] 재개할 Data Pump Job 이 없습니다."; fi
        rm -f "$_job_idx"
        if [ "$UNATTENDED" != "true" ]; then
            printf "  메인 메뉴로 돌아가려면 엔터를 누르세요: "
            _read _dummy
        fi
        return 0
    fi

    if [ "$LANG_PREF" = "EN" ]; then printf "  Select job number to handle (Enter to skip): "
    else printf "  처리할 Job 번호를 선택하세요 (건너뛰려면 엔터): "; fi
    _read _job_sel
    if [ -z "$_job_sel" ]; then rm -f "$_job_idx"; return 0; fi

    _job_rec=$(grep "^${_job_sel}|" "$_job_idx" 2>/dev/null | head -n 1)
    rm -f "$_job_idx"
    if [ -z "$_job_rec" ]; then
        echo "  [오류/ERROR] 올바르지 않은 번호입니다."
        return 1
    fi

    SEL_JOB_OWNER=$(echo "$_job_rec" | cut -d'|' -f2)
    SEL_JOB_NAME=$(echo "$_job_rec" | cut -d'|' -f3)
    SEL_JOB_OPER=$(echo "$_job_rec" | cut -d'|' -f4)
    SEL_JOB_STATE=$(echo "$_job_rec" | cut -d'|' -f5)

    # EXPORT 면 expdp, IMPORT 면 impdp 로 attach 해야 한다.
    case "$SEL_JOB_OPER" in
        IMPORT*) DP_BIN="impdp" ;;
        *)       DP_BIN="expdp" ;;
    esac

    echo ""
    echo "  >> 선택한 Job : ${SEL_JOB_OWNER}.${SEL_JOB_NAME} (${SEL_JOB_OPER} / ${SEL_JOB_STATE})"
    echo "----------------------------------------------------------------------"
    if [ "$LANG_PREF" = "EN" ]; then
        echo "  [Select Action]"
        echo "   1) RESUME  : Attach and START_JOB (restart from last checkpoint)"
        echo "   2) STATUS  : Attach and show live status only"
        echo "   3) STOP    : Attach and STOP_JOB=IMMEDIATE (safe stop, restartable)"
        echo "   4) KILL    : Attach and KILL_JOB (removes job & master table, NOT restartable)"
        echo "   5) CLEANUP : Generate orphaned master table cleanup script"
        printf "  Select (1-5) [Default: 1]: "
    else
        echo "  [수행할 작업 선택]"
        echo "   1) RESUME  : attach 후 START_JOB (마지막 체크포인트부터 재개)"
        echo "   2) STATUS  : attach 하여 현재 상태만 확인"
        echo "   3) STOP    : attach 후 STOP_JOB=IMMEDIATE (안전 중지, 이후 재개 가능)"
        echo "   4) KILL    : attach 후 KILL_JOB (Job 및 마스터테이블 삭제, 재개 불가)"
        echo "   5) CLEANUP : 고아 Master Table 정리 스크립트 생성"
        printf "  선택 (1-5) [기본값: 1]: "
    fi
    _read _job_act
    [ -z "$_job_act" ] && _job_act="1"

    DATE_STR=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$")
    RESUME_SH="resume_job_${SEL_JOB_NAME}_${DATE_STR}.sh"

    _dp_conn="$DB_CONN"
    [ -n "$PDB_CONNECT_STR" ] && _dp_conn="$PDB_CONNECT_STR"

    if [ "$_job_act" = "5" ]; then
        CLEAN_MT_SQL="cleanup_master_tables_${DATE_STR}.sql"
        echo "  * 생성 중: $CLEAN_MT_SQL (고아 Master Table 정리)"
        cat <<EOF > "$CLEAN_MT_SQL"
-- ==============================================================================
--  Orphaned Data Pump Master Table Cleanup
--  Generated: ${DATE_STR}
--  NOT RUNNING 상태로 남아 있는 Job 의 마스터 테이블을 정리합니다.
--  주의: 재개할 예정인 Job 의 마스터 테이블은 삭제하지 마십시오!
-- ==============================================================================
SET SERVEROUTPUT ON LINES 200
$PDB_SWITCH_SQL
SPOOL cleanup_master_tables_${DATE_STR}.log

PROMPT ========================================================================
PROMPT 현재 NOT RUNNING 상태인 Data Pump Job 목록
PROMPT ========================================================================
SELECT owner_name, job_name, operation, state FROM dba_datapump_jobs WHERE state = 'NOT RUNNING';

PROMPT ========================================================================
PROMPT 아래 DROP 문을 검토 후 필요한 것만 수동 실행하십시오 (자동 실행 안 함)
PROMPT ========================================================================
SELECT 'DROP TABLE "' || owner_name || '"."' || job_name || '" PURGE;'
FROM dba_datapump_jobs
WHERE state = 'NOT RUNNING';

SPOOL OFF
EXIT;
EOF
        echo "  >> 생성 완료: $CLEAN_MT_SQL"
        echo "  >> 안전을 위해 DROP 문은 자동 실행하지 않고 목록만 출력합니다. 검토 후 수동 실행하십시오."
        if [ "$UNATTENDED" != "true" ]; then
            printf "  메인 메뉴로 돌아가려면 엔터를 누르세요: "
            _read _dummy
        fi
        return 0
    fi

    case "$_job_act" in
        1) _dp_cmd="START_JOB"; _dp_desc="Job 재개 (START_JOB)" ;;
        2) _dp_cmd="STATUS";    _dp_desc="Job 상태 조회 (STATUS)" ;;
        3) _dp_cmd="STOP_JOB=IMMEDIATE"; _dp_desc="Job 안전 중지 (STOP_JOB=IMMEDIATE)" ;;
        4) _dp_cmd="KILL_JOB";  _dp_desc="Job 완전 삭제 (KILL_JOB)" ;;
        *) _dp_cmd="START_JOB"; _dp_desc="Job 재개 (START_JOB)" ;;
    esac

    if [ "$_job_act" = "4" ]; then
        if [ "$LANG_PREF" = "EN" ]; then echo "  [WARNING] KILL_JOB removes the job and its master table. It CANNOT be resumed afterwards."
        else echo "  [경고] KILL_JOB 은 Job 과 마스터 테이블을 삭제하며, 이후 재개가 불가능합니다."; fi
        if [ "$UNATTENDED" != "true" ]; then
            printf "  정말 진행하시겠습니까? 'KILL' 을 정확히 입력하세요: "
            _read _kill_confirm
            if [ "$_kill_confirm" != "KILL" ]; then
                echo "  >> 취소되었습니다."
                return 0
            fi
        fi
    fi

    echo "  * 생성 중: $RESUME_SH ($_dp_desc)"
    cat <<EOF > "$RESUME_SH"
#!/bin/bash
# ==============================================================================
#  [NEW v07] Data Pump Job Control Script
#  Job      : ${SEL_JOB_OWNER}.${SEL_JOB_NAME}
#  Operation: ${SEL_JOB_OPER}  ->  binary: ${DP_BIN}
#  Action   : ${_dp_desc}
# ==============================================================================
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_SID=$ORACLE_SID
export PATH=\$ORACLE_HOME/bin:\$PATH
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8

echo "====================================================================="
echo "  Data Pump Job Control : ${_dp_desc}"
echo "  - Job    : ${SEL_JOB_OWNER}.${SEL_JOB_NAME}"
echo "  - Command: ${_dp_cmd}"
echo "====================================================================="

# Data Pump 대화형 프롬프트(Export>/Import>)에 명령을 전달한다.
# [SEC v08.01] 접속 문자열을 커맨드라인에서 제거하고 임시 PARFILE(0600)로 전달
_dp_par="./.dp_attach_\$\$.par"
_old_umask=\$(umask); umask 077
cat > "\$_dp_par" <<PAR_EOF
USERID="${_dp_conn}"
ATTACH=${SEL_JOB_NAME}
PAR_EOF
umask "\$_old_umask"
trap 'rm -f "\$_dp_par"' EXIT INT TERM

${DP_BIN} PARFILE="\$_dp_par" <<DP_EOF
${_dp_cmd}
CONTINUE_CLIENT
DP_EOF

rm -f "\$_dp_par"

echo ">> 작업이 종료되었습니다. 진행 상황은 monitor_job_*.sh 또는 메뉴 4(LIVE MONITOR)로 확인하십시오."
EOF
    chmod 700 "$RESUME_SH"

    echo "======================================================================"
    echo "  >> 생성 완료: $RESUME_SH"
    echo "======================================================================"
    ask_to_run_script "$RESUME_SH"
    return 0
}

# ==============================================================================
# 메인 실행 루프
#   [NEW v07] --unattended --run N 지정 시 메뉴를 한 번만 자동 수행하고 종료한다.
# ==============================================================================
_menu_iteration=0
while true; do
    _menu_iteration=$((_menu_iteration + 1))

    # 무인 모드 + --run 지정: 지정된 메뉴 1회 실행 후 종료
    if [ "$UNATTENDED" = "true" ] && [ -n "$AUTO_MENU" ]; then
        if [ "$_menu_iteration" -gt 1 ]; then
            save_config_if_requested
            echo "  >> [무인 모드] 지정 작업(메뉴 ${AUTO_MENU})을 완료하여 종료합니다."
            exit 0
        fi
        main_choice="$AUTO_MENU"
        echo "======================================================================"
        echo "  [UNATTENDED] Oracle Datapump Migration Helper v${SCRIPT_VERSION}"
        echo "  - 자동 실행 메뉴 : $main_choice"
        [ -n "$CONFIG_FILE" ] && echo "  - Config 파일    : $CONFIG_FILE"
        echo "======================================================================"
    else
        clear_screen
        echo "======================================================================"
        echo "       Oracle Datapump Data Migration Helper Tool (v${SCRIPT_VERSION})"
        if [ "$MOCK_MODE" = "true" ]; then echo "                    [MOCK TEST MODE ACTIVE]"; fi
        if [ -n "$CONFIG_FILE" ]; then echo "            [CONFIG MODE] $CONFIG_FILE"; fi
        if [ -n "$SAVE_CONFIG_FILE" ]; then echo "       [RECORDING ANSWERS] -> $SAVE_CONFIG_FILE"; fi
        echo "======================================================================"
        if [ "$LANG_PREF" = "EN" ]; then
            echo "   1. SOURCE SERVER  : Analyze OS/HW/DB & Generate expdp Scripts"
            echo "   2. TARGET SERVER  : Analyze OS/HW/DB & Generate impdp Scripts"
            echo "   3. LOG VERIFIER   : expdp vs impdp Log Validation & HTML Audit Report"
            echo "   4. LIVE MONITOR   : Real-Time Data Pump Progress & Session Dashboard"
            echo "   5. DIAGNOSTICS    : Pre-Migration DB Readiness & Health Check"
            echo "   6. TUNING ADVISOR : Performance Optimization & Parameter Tuning Advisor"
            echo "   7. DATA INTEGRITY : Object Matrix + DEEP DIFF + Actual Row Count  [ENHANCED]"
            echo "   8. CLEANUP TOOL   : Target Schema & PDB Cleanup & Rollback Generator"
            echo "   9. RESUME & RETRY : Attach/Restart Data Pump Job & Pipeline Resume   [NEW]"
            echo "  10. EXIT           : Exit Tool"
            echo "======================================================================"
            printf "  Select (1-10): "
        else
            echo "   1. SOURCE SERVER  : OS/HW/DB 리소스 분석 및 expdp 이관 스크립트 생성"
            echo "   2. TARGET SERVER  : OS/HW/DB 리소스 분석 및 impdp 복구 스크립트 생성"
            echo "   3. LOG VERIFIER   : expdp vs impdp 로그 비교 검증 & HTML 종합 감사 보고서"
            echo "   4. LIVE MONITOR   : 실시간 Data Pump 진행률 & 세션 대기 이벤트 모니터링"
            echo "   5. DIAGNOSTICS    : 사전 이관 DB 환경 & 객체 점검 리포트 생성"
            echo "   6. TUNING ADVISOR : 이관 성능 최적화 & Oracle 인스턴스 파라미터 튜닝"
            echo "   7. DATA INTEGRITY : 객체 매트릭스 + ASIS↔TOBE 딕셔너리 대조 + 실측 건수  [강화]"
            echo "   8. CLEANUP TOOL   : Target 스키마 & PDB 원상복구 Clean-up 스크립트 생성"
            echo "   9. RESUME & RETRY : 중단된 Data Pump 작업 재개 / 파이프라인 재시도  [신규]"
            echo "  10. EXIT           : 헬퍼 종료"
            echo "======================================================================"
            printf "  선택하십시오 (1-10): "
        fi
        _read main_choice
    fi

    case "$main_choice" in
        1) run_source_mode ;;
        2) run_target_mode ;;
        3) run_log_verify ;;
        4) run_live_monitor ;;
        5) run_diagnostics_mode ;;
        6) run_tuning_advisor ;;
        7) run_data_integrity_menu ;;
        8) run_cleanup_mode ;;
        9) run_resume_mode ;;
        10|q|Q|exit|quit)
            save_config_if_requested
            if [ "$LANG_PREF" = "EN" ]; then echo "  Goodbye!"; else echo "  안녕히 가십시오!"; fi
            exit 0
            ;;
        *)
            if [ "$LANG_PREF" = "EN" ]; then echo "  Please enter a valid number."; else echo "  올바른 메뉴 번호를 입력해주세요."; fi
            if [ "$UNATTENDED" = "true" ]; then
                echo "  [무인 모드] --run 값이 올바르지 않아 종료합니다."
                exit 1
            fi
            sleep 1
            ;;
    esac
done
