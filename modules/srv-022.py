import os
import subprocess
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

# SRV-022: 계정의 비밀번호 미설정, 빈 암호 사용 관리 미흡
def SRV_022():
    log("[SRV-022] 계정의 비밀번호 미설정, 빈 암호 사용 관리 미흡")
    log("")

    vulnerable_accounts = set()  # 1. 중복 제거를 위해 set 사용
    error_occurred = False

    try:
        # 1. /etc/shells 파일에서 유효한 쉘 목록 가져오기
        if os.path.exists("/etc/shells"):
            with open("/etc/shells", "r") as f:
                valid_shells = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith("#")
                ]
        else:
            valid_shells = ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"]

        # 2. 쉘 권한이 있는 계정 목록 가져오기
        try:
            accounts_with_shell = {
                line.split(":")[0]: line.split(":")[6]
                for line in subprocess.check_output(
                    ["cat", "/etc/passwd"], stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .splitlines()
                if line.split(":")[6] in valid_shells
            }
        except subprocess.CalledProcessError as e:
            log(f"  - /etc/passwd 파일 처리 중 오류 발생: {e}")
            accounts_with_shell = {}
            error_occurred = True

        # 3. 비밀번호가 없거나 비어 있는 계정 확인
        try:
            empty_password_accounts = [
                line.split(":")[0]
                for line in subprocess.check_output(
                    ["cat", "/etc/shadow"], stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .splitlines()
                if not line.split(":")[1]
                or line.split(":")[1] in ["", "!", "*", "x", "!!"]
            ]

            # 2. pwck 명령어 사용 (추가)
            try:
                subprocess.check_call(["pwck", "-r", "/etc/passwd", "/etc/shadow"])
            except subprocess.CalledProcessError as e:
                log(f"  - pwck 명령어 실행 중 오류 발생: {e}")
                error_occurred = True
            
        except subprocess.CalledProcessError as e:
            log(f"  - /etc/shadow 파일 처리 중 오류 발생: {e}")
            empty_password_accounts = []
            error_occurred = True

        # 4. 쉘 권한이 있고 비밀번호가 없는 계정 확인
        for account, shell in accounts_with_shell.items():
            if account in empty_password_accounts:
                vulnerable_accounts.add((account, shell))  # 1. add() 사용

    except Exception as e:
        log(f"  - 계정 확인 중 오류 발생: {e}")
        error_occurred = True

    # 결과 출력
    if vulnerable_accounts:
        log("결과: 취약 (비밀번호 미설정 또는 빈 암호 계정 발견)")
        for account, shell in vulnerable_accounts:
            log(f"  - 계정: {account}, 쉘: {shell}")

            # 3. passwd -S 명령어 사용 (추가)
            try:
                passwd_status = subprocess.check_output(
                    ["passwd", "-S", account], stderr=subprocess.DEVNULL
                ).decode("utf-8").strip()
                log(f"    - {account} 계정 상태: {passwd_status}")
            except subprocess.CalledProcessError as e:
                log(f"    - {account} 계정 상태 확인 중 오류 발생: {e}")
                error_occurred = True

    elif error_occurred:
        log("결과: N/A")
        log("설명: 계정 확인 중 오류 발생")
    else:
        log("결과: 양호 (비밀번호 미설정 또는 빈 암호 계정 없음)")
    log("")

def main():
    SRV_022()

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