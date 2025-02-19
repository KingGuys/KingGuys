import os
import subprocess
import stat
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-001.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-012: .netrc 파일 내 중요 정보 노출
def SRV_012():
    log("[SRV-012] .netrc 파일 내 중요 정보 노출")
    log("")

    vulnerable_files = []
    error_occurred = False  # 2. 오류 발생 여부 변수 추가

    try:
        # find 명령어 실행 결과에서 각 줄의 끝에 있는 파일 경로만 추출
        netrc_files = [
            line.split()[-1]
            for line in subprocess.check_output(
                "find / -xdev -name .netrc -ls 2>/dev/null", shell=True
            )
            .decode("utf-8")
            .splitlines()
        ]

        if netrc_files:
            log("결과:")
            for filename in netrc_files:
                try:
                    # 파일 권한 확인
                    st = os.stat(filename)
                    permissions = oct(st.st_mode & 0o777)[2:]

                    # 파일 소유자 확인
                    owner_id = st.st_uid
                    owner_name = subprocess.check_output(f"id -nu {owner_id}", shell=True).decode("utf-8").strip()

                    if (
                        st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                        or permissions != "600"
                        or owner_name != "root"
                    ):
                        log(f"  - {filename}: 권한={permissions}, 소유자={owner_name} (취약)")
                        vulnerable_files.append(filename)

                        # 3. .netrc 파일 내용 확인 (예시)
                        with open(filename, "r") as f:
                            content = f.read()
                            if "machine" in content and "login" in content and "password" in content:
                                log(f"    - {filename} 파일에 민감한 정보(machine, login, password) 포함 (취약)")

                except Exception as e:
                    log(f"  - {filename} 파일 확인 오류: {e}")
                    error_occurred = True  # 2. 오류 발생 여부 기록
        else:
            log("결과: 양호 (.netrc 파일 없음)")

    except subprocess.CalledProcessError as e:
        log(f"  - .netrc 파일 검색 중 오류 발생: {e}")
        error_occurred = True  # 2. 오류 발생 여부 기록

    # 최종 결과 출력
    # 1. result 변수 대신 vulnerable_files 리스트 사용
    if vulnerable_files:
        log("결론: 취약")
        log(f"설명: 취약한 .netrc 파일 발견: {', '.join(vulnerable_files)}")
    elif error_occurred:  # 2. 오류 발생 여부 확인
        log("결론: N/A")
        log("설명: .netrc 파일 확인 중 오류 발생")
    else:
        log("결론: 양호")
        log("설명: 모든 .netrc 파일이 안전하거나 발견되지 않았습니다.")
    log("")

    log("참고: .netrc 파일에는 FTP 계정이 평문으로 저장되기 때문에 사용하지 않을 것을 권고합니다.")
    log("")

def main():
    SRV_012()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        function_name = sys.argv[1]
        if function_name in globals():
            globals()[function_name]()
        else:
            print(f"Error: 함수 '{function_name}'을 찾을 수 없습니다.")
    else:
        main()

    print(f"점검 결과가 {filename} 파일에 저장되었습니다.")