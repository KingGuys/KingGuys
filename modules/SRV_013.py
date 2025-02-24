import os
import subprocess
import re
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-013.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-013: Anonymous 계정의 FTP 서비스 접속 제한 미비
def SRV_013():
    log("[SRV-013] Anonymous 계정의 FTP 서비스 접속 제한 미비")
    log("")

    ftp_services = {
        "proftpd": {
            "process_name": "proftpd",
            "config_file": "/etc/proftpd/proftpd.conf",
            "anonymous_check_pattern": r"^\s*<Anonymous",
        },
        "vsftpd": {
            "process_name": "vsftpd",
            "config_file": "/etc/vsftpd/vsftpd.conf",
            "anonymous_check_setting": "anonymous_enable",
            "anonymous_check_value": "NO",
        },
    }

    overall_result = True  # 1. 초기값을 True로 변경
    overall_exp = []

    for service, info in ftp_services.items():
        process_name = info["process_name"]
        config_file = info.get("config_file")
        anonymous_check_pattern = info.get("anonymous_check_pattern")
        anonymous_check_setting = info.get("anonymous_check_setting")
        anonymous_check_value = info.get("anonymous_check_value")

        try:
            ftp_process = subprocess.check_output(
                f"ps -ef | grep {process_name} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            ftp_process = ""

        if ftp_process:
            log(f"- {service.upper()} 서비스 실행: 예")
            service_result = False  # 1. 서비스 실행 중일 때는 기본적으로 False(취약)으로 설정

            if config_file and os.path.exists(config_file) and os.access(config_file, os.R_OK):
                try:
                    with open(config_file, "r") as f:
                        config_content = f.read()

                    if service == "proftpd":
                        if anonymous_check_pattern and re.search(
                            anonymous_check_pattern, config_content, re.IGNORECASE
                        ):
                            log("  - Anonymous 계정 활성화: 예 (취약)")
                        else:
                            log("  - Anonymous 계정 활성화: 아니오 (양호)")
                            service_result = True

                    elif service == "vsftpd":
                        if anonymous_check_setting:
                            match = re.search(
                                rf"^\s*{anonymous_check_setting}\s*=\s*({anonymous_check_value})",
                                config_content,
                                re.MULTILINE | re.IGNORECASE,
                            )
                            if match:
                                log(f"  - {anonymous_check_setting} 설정: {match.group(1)} (양호)")
                                service_result = True
                            else:
                                log(f"  - {anonymous_check_setting} 설정: YES 또는 미설정 (취약)")
                    else:
                        log(f"  - {service} 서비스는 Anonymous 계정 확인을 지원하지 않습니다.")
                        service_result = None  # N/A

                except Exception as e:
                    log(f"  - {service.upper()} 설정 파일 읽기 오류: {e}")
                    service_result = None  # N/A
            else:
                log(f"  - {service.upper()} 설정 파일({config_file}) 미발견 또는 접근 불가")
                service_result = None  # N/A

            log(f"  - {service.upper()} 서비스 점검 결과: {'양호' if service_result else '취약' if service_result == False else 'N/A'}")

            # 2. overall_result 및 overall_exp 업데이트
            overall_result = overall_result and service_result

            if service_result == False and f"{service.upper()} 서비스 Anonymous 계정 접속 제한 미흡" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 Anonymous 계정 접속 제한 미흡")
            elif service_result == None and f"{service.upper()} 서비스 Anonymous 계정 접속 제한 확인 불가" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 Anonymous 계정 접속 제한 확인 불가")

        else:
            log(f"- {service.upper()} 서비스 실행: 아니오")
        log("")

    # 최종 결과 출력
    if overall_result == False:
        log(f"결론: 취약")
        log(f"설명: {', '.join(overall_exp)}")
    elif overall_result == None:
        log(f"결론: N/A")
        log(f"설명: {', '.join(overall_exp)}")
    else:
        log(f"결론: 양호")
        log("설명: 모든 FTP 서비스에 Anonymous 계정 접속 제한이 적절히 설정되었거나 실행 중이지 않습니다.")
    log("")

def main():
    SRV_013()

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