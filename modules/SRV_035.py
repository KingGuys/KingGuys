import os
import subprocess
import re
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-035.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-035: 취약한 서비스 활성화
def SRV_035():
    log("[SRV-035] 취약한 서비스 활성화")
    log("")

    r_services = ["rsh", "rcp", "rlogin", "rexec"]
    active_r_services = set()

    # r 명령어 관련 프로세스, inetd.conf, xinetd.d, systemd 서비스 확인
    for service in r_services:
        try:
            # 프로세스 확인
            process = subprocess.check_output(
                f"ps -ef | grep -i '{service}' | grep -v grep", shell=True
            ).decode("utf-8").strip()
            if process:
                active_r_services.add(service)
                continue  # 프로세스에서 발견되면 다른 방법 확인 건너뜀

            # inetd.conf 확인
            inetd_conf = subprocess.check_output(
                f"grep -E '^{service}\\s' /etc/inetd.conf | grep -v '^#'",
                shell=True,
            ).decode("utf-8").strip()
            if inetd_conf:
                active_r_services.add(service)
                continue

            # xinetd.d 확인
            xinetd_service = subprocess.check_output(
                f"grep -r '^\\s*service\\s*{service}' /etc/xinetd.d/ | grep -v 'disable\\s*=\\s*yes'",
                shell=True,
            ).decode("utf-8").strip()
            if xinetd_service:
                active_r_services.add(service)
                continue

            # systemd 확인
            subprocess.check_call(
                f"systemctl is-active --quiet {service}", shell=True
            )
            active_r_services.add(service)

        except subprocess.CalledProcessError:
            pass

    # /etc/hosts.equiv 파일 확인
    hosts_equiv_vulnerable = False
    try:
        if os.path.isfile("/etc/hosts.equiv"):
            log("  - /etc/hosts.equiv 파일 존재 (주의)")
            with open("/etc/hosts.equiv", "r") as f:
                content = f.read()
                # 개선: '+' 설정 및 특정 호스트/사용자 허용 여부 확인
                if re.search(r"^\s*\+[\s$]*", content, re.MULTILINE) or re.search(r"^\s*\S+\s*\+[\s$]*", content, re.MULTILINE):
                    log("    - /etc/hosts.equiv 파일에 취약한 '+' 설정 존재 (취약)")
                    hosts_equiv_vulnerable = True
                else:
                    log("    - /etc/hosts.equiv 파일에 취약한 '+' 설정은 없으나, 추가 확인 필요")  # 추가 확인 로직 필요
        else:
            log("  - /etc/hosts.equiv 파일 없음")
    except Exception as e:
        log(f"  - /etc/hosts.equiv 파일 확인 중 오류 발생: {e}")

    # ~/.rhosts 파일 확인
    rhosts_vulnerable = False
    try:
        rhosts_files = subprocess.check_output(
            "find /home -name .rhosts 2>/dev/null", shell=True
        ).decode("utf-8").splitlines()
        if rhosts_files:
            log("  - .rhosts 파일 존재:")
            for file in rhosts_files:
                log(f"    - {file}")
                with open(file, "r") as f:
                    content = f.read()
                    # 개선: '+' 설정 및 특정 호스트/사용자 허용 여부 확인
                    if re.search(r"^\s*\+[\s$]*", content, re.MULTILINE) or re.search(r"^\s*\S+\s*\+[\s$]*", content, re.MULTILINE):
                        log(f"      - {file} 파일에 취약한 '+' 설정 존재 (취약)")
                        rhosts_vulnerable = True
                    else:
                        log(f"      - {file} 파일에 취약한 '+' 설정은 없으나, 추가 확인 필요")  # 추가 확인 로직 필요
        else:
            log("  - .rhosts 파일 없음")
    except subprocess.CalledProcessError as e:
        log(f"  - .rhosts 파일 확인 중 오류 발생: {e}")

    # 결과 출력
    if active_r_services or hosts_equiv_vulnerable or rhosts_vulnerable:
        log("결과: 취약")
        if active_r_services:
            log("  - 활성화된 r 서비스:")
            for service in active_r_services:
                log(f"    - {service}")
            log("    - r 서비스 비활성화 방법:")
            log("      - (systemd) systemctl stop <service> && systemctl disable <service>")
            log("      - (inetd) /etc/inetd.conf 파일에서 해당 서비스 주석 처리 후 inetd 재시작")
            log("      - (xinetd) /etc/xinetd.d/<service> 파일에서 disable = yes 설정 후 xinetd 재시작")
        if hosts_equiv_vulnerable:
            log("  - /etc/hosts.equiv 파일에 취약한 설정 존재")
        if rhosts_vulnerable:
            log("  - 취약한 .rhosts 파일 존재")
    else:
        log("결과: 양호 (취약한 서비스 미활성화)")
    log("")

def main():
    SRV_035()

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