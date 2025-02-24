import os
import subprocess
import re
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-009.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-009: SMTP 서비스 스팸 메일 릴레이 제한 미설정
def SRV_009():
    log("[SRV-009] SMTP 서비스 스팸 메일 릴레이 제한 미설정")
    log("")

    smtp_services = {
        "sendmail": {
            "process_name": "sendmail",
            "config_file": "/etc/mail/sendmail.cf",
            "relay_check_pattern": r"R\$\*\s+.*Relaying\s+denied",
        },
        "postfix": {
            "process_name": "master",
            "config_file": "/etc/postfix/main.cf",
            "relay_check_setting": "smtpd_relay_restrictions",
        },
        "exim": {
            "process_name": "exim",
            "config_file": "/etc/exim/exim.conf",
            "relay_check_pattern": r"deny\s+message\s*=\s*Relay\s+not\s+permitted",
        },
    }

    overall_result = True  # 1. 초기값을 True로 변경
    overall_exp = []

    for service, info in smtp_services.items():
        process_name = info["process_name"]
        config_file = info.get("config_file")
        relay_check_pattern = info.get("relay_check_pattern")
        relay_check_setting = info.get("relay_check_setting")

        try:
            smtp_process = subprocess.check_output(
                f"ps -ef | grep {process_name} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            smtp_process = ""

        if smtp_process:
            log(f"- {service.upper()} 서비스 실행: 예")
            service_result = False  # 1. 서비스 실행 중일 때는 기본적으로 False(취약)으로 설정

            if config_file and os.path.exists(config_file) and os.access(config_file, os.R_OK):
                try:
                    with open(config_file, "r") as f:
                        config_content = f.read()

                    if service == "sendmail":
                        if relay_check_pattern and re.search(
                            relay_check_pattern, config_content, re.IGNORECASE
                        ):
                            log("  - 릴레이 제한 설정: 예")
                            service_result = True
                        else:
                            log("  - 릴레이 제한 설정: 아니오")

                    elif service == "postfix":
                        if relay_check_setting:
                            match = re.search(
                                rf"^\s*{relay_check_setting}\s*=\s*(.*)",
                                config_content,
                                re.MULTILINE | re.IGNORECASE,
                            )
                            if match:
                                settings = match.group(1).strip()
                                if (
                                    "permit_mynetworks" in settings
                                    and "reject_unauth_destination" in settings
                                ):
                                    log("  - 릴레이 제한 설정: 예")
                                    service_result = True
                                else:
                                    log("  - 릴레이 제한 설정: 아니오 (permit_mynetworks, reject_unauth_destination 설정 필요)")
                            else:
                                log(f"  - {relay_check_setting} 설정: 찾을 수 없음")
                    elif service == "exim":
                        if relay_check_pattern and re.search(
                            relay_check_pattern, config_content, re.IGNORECASE
                        ):
                            log("  - 릴레이 제한 설정: 예")
                            service_result = True
                        else:
                            log("  - 릴레이 제한 설정: 아니오")
                    else:
                        log(f"  - {service} 서비스는 릴레이 제한 설정 확인을 지원하지 않습니다.")
                        service_result = None # N/A

                except Exception as e:
                    log(f"  - {service.upper()} 설정 파일 읽기 오류: {e}")
                    service_result = None # N/A
            else:
                log(f"  - {service.upper()} 설정 파일({config_file}) 미발견 또는 접근 불가")
                service_result = None # N/A

            log(f"  - {service.upper()} 서비스 점검 결과: {'양호' if service_result else '취약' if service_result == False else 'N/A'}")

            # 2. overall_result 및 overall_exp 업데이트
            overall_result = overall_result and service_result

            if not service_result and f"{service.upper()} 서비스 릴레이 제한 미설정" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 릴레이 제한 미설정")
            elif service_result == None and f"{service.upper()} 서비스 릴레이 제한 설정 확인 불가" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 릴레이 제한 설정 확인 불가")

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
        log("설명: 모든 SMTP 서비스에 릴레이 제한이 설정되었거나 실행 중이지 않습니다.")
    log("")

def main():
    SRV_009()

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