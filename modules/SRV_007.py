import os
import subprocess
import re
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

# SRV-007: 취약한 버전의 SMTP 서비스 사용
def SRV_007():
    log("[SRV-007] 취약한 버전의 SMTP 서비스 사용")
    log("")

    smtp_services = {
        "sendmail": {
            "process_name": "sendmail",
            "version_command": "sendmail -d0.1 | grep -i version",
            "min_version": "8.14.9"
        },
        "postfix": {
            "process_name": "master",  # postfix는 master 프로세스로 확인
            "version_command": "postconf -d mail_version | awk -F'=' '{print $2}'",  # 버전만 추출
            "min_versions": {
                "2": "2.5.13",
                "3": "3.0.0"  # 예시: 3.x 버전은 3.0.0 이상으로 가정
            }
        },
        "exim": {
            "process_name": "exim",
            "version_command": "exim -bV | grep -i version",
            "min_version": "4.94.2"
        }
    }

    result = "양호"
    vulnerable_services = []

    for service, info in smtp_services.items():
        process_name = info["process_name"]
        version_command = info["version_command"]

        try:
            smtp_process = subprocess.check_output(
                f"ps -ef | grep {process_name} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            smtp_process = ""

        if smtp_process:
            log(f"- {service.upper()} 서비스 실행: 예")
            try:
                version_output = subprocess.check_output(
                    version_command, shell=True
                ).decode("utf-8").strip()
                
                if version_output:
                    # 버전 정보 정제
                    if service == "sendmail":
                        # Sendmail 버전 형식: "Version 8.14.9" 또는 "Compiled with: 8.14.9"
                        match = re.search(r"Version (\d+\.\d+\.\d+)", version_output, re.IGNORECASE) or \
                                re.search(r"Compiled with: (\d+\.\d+\.\d+)", version_output, re.IGNORECASE)
                        version = match.group(1) if match else None
                    elif service == "postfix":
                        # Postfix 버전 형식: "3.8.5"
                        version = version_output.split("=")[-1].strip()
                    elif service == "exim":
                        # Exim 버전 형식: "Exim version 4.94.2 #2 built"
                        match = re.search(r"Exim version (\d+\.\d+\.\d+)", version_output, re.IGNORECASE)
                        version = match.group(1) if match else None
                    
                    if version:
                        log(f"  - {service.upper()} 버전: {version}")

                        # 버전 비교
                        if service == "postfix":
                            major_version = version.split(".")[0]
                            if major_version in info["min_versions"]:
                                min_version = info["min_versions"][major_version]
                            else:
                                min_version = None  # 해당 major 버전에 대한 최소 버전 정보가 없는 경우
                        else:
                            min_version = info["min_version"]

                        if min_version and version < min_version:
                            log(f"  - {service.upper()} 버전이 취약합니다 (최소 버전: {min_version}).")
                            result = "취약"
                            vulnerable_services.append(service.upper())
                        else:
                            log(f"  - {service.upper()} 버전은 양호합니다.")
                    else:
                        log(f"  - {service.upper()} 버전 정보를 파싱할 수 없습니다.")
                        result = "취약"  # 버전 정보를 확인할 수 없는 경우 취약으로 간주
                        vulnerable_services.append(service.upper())
                else:
                    log(f"  - {service.upper()} 버전 확인 불가")
                    result = "취약" # 버전 정보를 확인할 수 없는 경우 취약으로 간주
                    vulnerable_services.append(service.upper())

            except subprocess.CalledProcessError:
                log(f"  - {service.upper()} 버전 확인 중 오류 발생")
                result = "N/A"  # 오류 발생 시 N/A로 설정
        else:
            log(f"- {service.upper()} 서비스 실행: 아니오")

        log("")

    if result == "취약":
        exp = f"취약한 버전의 SMTP 서비스 사용: {', '.join(vulnerable_services)}"
    elif result == "N/A":
        exp = f"SMTP 서비스 버전 확인 중 오류 발생"
    else:
        exp = "모든 SMTP 서비스가 안전한 버전을 사용 중이거나 실행 중이지 않습니다."

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log("")

def main():
    SRV_007()

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