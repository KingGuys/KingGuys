import os
import subprocess
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-028.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-028: 원격 터미널 접속 타임아웃 미설정
def SRV_028():
    log("[SRV-028] 원격 터미널 접속 타임아웃 미설정")
    log("")

    max_timeout = 600  # 최대 타임아웃 값 (초)

    profile_result = "미설정"
    profile_timeout = None
    csh_login_result = "미설정"
    csh_login_timeout = None

    # /etc/profile 파일 확인
    if os.path.exists("/etc/profile"):
        try:
            # TMOUT 설정값 추출
            result = subprocess.check_output(
                f"grep -i '^TMOUT' /etc/profile | grep -v '^#'", shell=True
            ).decode("utf-8").strip()

            if result:
                try:
                    profile_timeout = int(result.split()[-1])

                    if profile_timeout == 0:
                        profile_result = "설정됨(0, 즉시)"
                    elif profile_timeout <= max_timeout:
                        profile_result = "양호"
                    else:
                        profile_result = "취약"
                except (ValueError, IndexError):
                    profile_result = "오류 (타임아웃 값 확인 불가)"
                    profile_timeout = result  # 오류 메시지에 설정값 포함
            else:
                profile_result = "미설정"
        except subprocess.CalledProcessError as e:
            log(f"  - /etc/profile 파일 처리 중 오류 발생: {e}")
            profile_result = "오류"
    else:
        log("  - /etc/profile 파일이 존재하지 않습니다.")
        profile_result = "파일 없음"

    # /etc/csh.login 파일 확인
    if os.path.exists("/etc/csh.login"):
        try:
            # autologout 설정값 추출 (csh, tcsh)
            result = subprocess.check_output(
                f"grep -i '^\\s*set\\s+autologout' /etc/csh.login | grep -v '^\\s*#'", shell=True
            ).decode("utf-8").strip()

            if result:
                try:
                    csh_login_timeout = int(result.split("=")[-1].strip()) * 60  # 분 단위를 초 단위로 변환
                    if csh_login_timeout == 0:
                        csh_login_result = "설정됨(0, 즉시)"
                    elif csh_login_timeout <= max_timeout:
                        csh_login_result = "양호"
                    else:
                        csh_login_result = "취약"
                except (ValueError, IndexError):
                    csh_login_result = "오류 (타임아웃 값 확인 불가)"
                    csh_login_timeout = result
            else:
                csh_login_result = "미설정"
        except subprocess.CalledProcessError as e:
            log(f"  - /etc/csh.login 파일 처리 중 오류 발생: {e}")
            csh_login_result = "오류"
    else:
        log("  - /etc/csh.login 파일이 존재하지 않습니다.")
        csh_login_result = "파일 없음"

    # 결과 출력
    log("- /etc/profile:")
    if profile_result == "오류":
        log(f"  - TMOUT 설정: {profile_result} ({profile_timeout})")
    elif profile_result == "파일 없음":
        log("  - /etc/profile 파일이 존재하지 않습니다.")
    elif profile_result == "미설정":
        log(f"  - TMOUT 설정: {profile_result}")
    else:
        log(f"  - TMOUT 설정: {profile_result} ({profile_timeout if profile_timeout is not None else ''}초)")

    log("- /etc/csh.login:")
    if csh_login_result == "오류":
        log(f"  - autologout 설정: {csh_login_result} ({csh_login_timeout})")
    elif csh_login_result == "파일 없음":
        log("  - /etc/csh.login 파일이 존재하지 않습니다.")
    elif csh_login_result == "미설정":
        log(f"  - autologout 설정: {csh_login_result}")
    else:
        log(f"  - autologout 설정: {csh_login_result} ({csh_login_timeout if csh_login_timeout is not None else ''}초)")

    # 최종 결과 판단
    if profile_result == "양호" or csh_login_result == "양호":
        result = "양호"
    elif profile_result == "파일 없음" and csh_login_result == "파일 없음":
        result = "취약"
    elif profile_result == "미설정" and csh_login_result == "미설정":
        result = "취약"
    else:
        result = "취약"

    log(f"결론: {result}")
    log("")

def main():
    SRV_028()

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