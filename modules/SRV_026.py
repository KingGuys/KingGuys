import os
import subprocess
import re
import platform
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-026.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-026: root 계정 원격 접속 제한 미비
def SRV_026():
    log("[SRV-026] root 계정 원격 접속 제한 미비")
    log("")

    try:
        ssh_process = subprocess.check_output(
            "ps -ef | grep sshd | grep -v grep", shell=True
        ).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        ssh_process = ""

    if ssh_process:
        log("1. SSH 서비스 실행: 예")

        # SSH 포트 상태 확인 (22번 포트)
        try:
            ssh_port_status = subprocess.check_output(
                "netstat -an | grep :22 | grep LISTEN", shell=True
            ).decode("utf-8").strip()
            if ssh_port_status:
                log(f"  - SSH 포트 상태: 열림 ({ssh_port_status.split()[3]})")
            else:
                log("  - SSH 포트 상태: 닫힘")
        except subprocess.CalledProcessError:
            log("  - SSH 포트 상태 확인 중 오류 발생")

        # PermitRootLogin 설정 확인
        permit_root_login_result = "취약"  # 기본값을 취약으로 설정
        try:
            # 2. 주석 처리되지 않은 PermitRootLogin 설정 확인
            permit_root_login = subprocess.check_output(
                "grep -E '^[^#]*PermitRootLogin' /etc/ssh/sshd_config", shell=True
            ).decode("utf-8").strip()
            if permit_root_login:
                if re.search(r"^PermitRootLogin\s+no", permit_root_login, re.IGNORECASE):
                    log("  - PermitRootLogin 설정: no (양호)")
                    permit_root_login_result = "양호"
                elif re.search(r"^PermitRootLogin\s+prohibit-password", permit_root_login, re.IGNORECASE):
                    log("  - PermitRootLogin 설정: prohibit-password (양호)")
                    permit_root_login_result = "양호"
                elif re.search(r"^PermitRootLogin\s+without-password", permit_root_login, re.IGNORECASE):
                    log("  - PermitRootLogin 설정: without-password (양호)")
                    permit_root_login_result = "양호"
                elif re.search(r"^PermitRootLogin\s+forced-commands-only", permit_root_login, re.IGNORECASE):
                    log("  - PermitRootLogin 설정: forced-commands-only (양호)")
                    permit_root_login_result = "양호"
                else:
                    log("  - PermitRootLogin 설정: yes 또는 기타 (취약)")
            else:
                log("  - PermitRootLogin 설정: 미설정 (취약)")
        except subprocess.CalledProcessError:
            log("  - PermitRootLogin 설정 확인 중 오류 발생")

        # /etc/security/user 파일에서 rlogin 설정 확인 (AIX 시스템)
        security_user_result = "N/A"  # 기본값을 N/A로 설정
        if platform.system() == "AIX":  # 3. AIX 시스템인지 확인
            try:
                # 3. awk 명령어 사용
                rlogin_setting = subprocess.check_output(
                    "awk -F: '$1 == \"root\" {getline; print}' /etc/security/user | grep rlogin", shell=True
                ).decode("utf-8").strip()
                if rlogin_setting:
                    if "false" in rlogin_setting.lower():
                        log("  - rlogin 설정: false (양호)")
                        security_user_result = "양호"
                    else:
                        log("  - rlogin 설정: true (취약)")
                        security_user_result = "취약"
                else:
                    log("  - rlogin 설정: 미설정 (정보)")
                    security_user_result = "정보"
            except subprocess.CalledProcessError:
                log("  - rlogin 설정 확인 중 오류 발생")
        else:
            log("  - AIX 시스템이 아니므로 rlogin 설정 확인 건너뜀")

        # 종합적인 결과 판단
        if permit_root_login_result == "양호" and security_user_result == "양호":
            result = "양호"
        elif security_user_result == "N/A":
            result = permit_root_login_result
        else:
            result = "취약"

        # 5. 최종 결과 출력 개선
        log(f"  - SSH 서비스 점검 결과: {result} (PermitRootLogin: {permit_root_login_result}, rlogin: {security_user_result})")

    else:
        log("1. SSH 서비스 실행: 아니오")
        result = "양호"

    log(f"결론: {result}")
    log("")

def main():
    SRV_026()

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