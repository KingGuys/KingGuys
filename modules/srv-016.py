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

# SRV-016: 불필요한 RPC 서비스 활성화
def SRV_016():
    log("[SRV-016] 불필요한 RPC 서비스 활성화")
    log("")

    rpc_services = [
        "rpc.cmsd", "rusersd", "rstatd", "kcms_server", # 1. rpc.statd 제거 또는 주석 처리
        "rpc.ttdbserverd", "rpc.walld", "rpc.nisd", "rpc.ypupdated",
        "cachefsd", "sadmind", "rpc.sprayd", "rpc.pcnfsd", "rpc.rexd",
        "rpc.rquotad"
    ]  # 1. rpc. 접두사 통일

    active_rpc_services = set()  # 2. set으로 변경하여 중복 제거
    for service in rpc_services:
        # 1. inetd.conf 확인
        try:
            inetd_status = subprocess.check_output(
                f"grep -v '^#' /etc/inetd.conf | grep '{service}'", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            inetd_status = ""

        if inetd_status:
            active_rpc_services.add(service)  # 2. add() 사용
            continue

        # 2. xinetd.d 디렉터리 확인
        try:
            xinetd_status = subprocess.check_output(
                f"grep -r '^\\s*service\\s*{service}' /etc/xinetd.d/ | grep -v disable.*yes", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            xinetd_status = ""

        if xinetd_status:
            active_rpc_services.add(service)  # 2. add() 사용
            continue

        # 3. systemd 서비스 확인
        try:
            # 3. systemctl is-active 명령어 반환 코드 확인
            subprocess.check_call(
                f"systemctl is-active --quiet {service}", shell=True
            )
            systemd_status = "active"  # check_call()은 오류가 없으면 0을 반환
        except subprocess.CalledProcessError:
            systemd_status = ""

        if systemd_status == "active":
            active_rpc_services.add(service)  # 2. add() 사용
            continue  # systemd에서 발견되면 프로세스 확인 건너뜀

        # 4. 프로세스 확인
        try:
            process_status = subprocess.check_output(
                f"ps -ef | grep {service} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            process_status = ""

        if process_status:
            active_rpc_services.add(service)  # 2. add() 사용

    # 결과 출력
    if active_rpc_services:
        log("결과: 취약 (활성화된 불필요한 RPC 서비스 발견)")
        for service in active_rpc_services:
            log(f"  - {service}")
        log("  - 불필요한 RPC 서비스를 비활성화해야 합니다.")
        log("  - (예) systemctl stop <service> && systemctl disable <service>")
        log("  - (예) /etc/inetd.conf 또는 /etc/xinetd.d/<service> 파일에서 해당 서비스 비활성화")
    else:
        log("결과: 양호 (불필요한 RPC 서비스 미활성화)")
    log("")

def main():
    SRV_016()

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