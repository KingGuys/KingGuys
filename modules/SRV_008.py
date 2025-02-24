import os
import subprocess
import re
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-008.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-008: SMTP 서비스의 DoS 방지 기능 미설정
def SRV_008():
    log("[SRV-008] SMTP 서비스의 DoS 방지 기능 미설정")
    log("")

    smtp_services = {
        "sendmail": {
            "process_name": "sendmail",
            "config_file": "/etc/mail/sendmail.cf",
            "dos_protection_settings": {
                "ConnectionRateThrottle": None,  # 값 없음
                "MaxDaemonChildren": None,  # 값 없음
                "MinFreeBlocks": None,  # 값 없음
                "MaxHeadersLength": None, # 값 없음
                "MaxMessageSize": None,  # 값 없음
            },
        },
        "postfix": {
            "process_name": "master",
            "config_file": "/etc/postfix/main.cf",
            "dos_protection_settings": {
                "smtpd_client_connection_rate_limit": None,
                "smtpd_client_message_rate_limit": None,
                "smtpd_recipient_restrictions": "permit_mynetworks, reject_unauth_destination",
            },
        },
        "exim": {
            "process_name": "exim",
            "config_file": "/etc/exim4/exim4.conf.template",  # 데비안 계열
            "dos_protection_settings": {
                "smtp_accept_max": None,
                "smtp_accept_queue": None,
                "smtp_delay_reject": "true",  # 이 설정은 값이 true/false로 설정
            },
        },
    }

    overall_result = "양호"  # 전체 결과 변수
    overall_exp = []

    for service, info in smtp_services.items():
        process_name = info["process_name"]
        config_file = info["config_file"]
        dos_protection_settings = info["dos_protection_settings"]
        service_result = "양호"
        
        try:
            smtp_process = subprocess.check_output(
                f"ps -ef | grep {process_name} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            smtp_process = ""

        if smtp_process:
            log(f"- {service.upper()} 서비스 실행: 예")
            if config_file and os.path.exists(config_file) and os.access(config_file, os.R_OK):
                try:
                    with open(config_file, "r") as f:
                        config_content = f.read()

                    for setting_name, default_value in dos_protection_settings.items():
                        if service == "sendmail":
                            # Sendmail 설정 확인 (예: ConnectionRateThrottle)
                            pattern = rf"^\s*{setting_name}\s*=?\s*(\w+)"
                        elif service == "postfix":
                            # Postfix 설정 확인 (예: smtpd_client_connection_rate_limit)
                            pattern = rf"^\s*{setting_name}\s*=\s*(.*)"
                        elif service == "exim":
                            # Exim 설정 확인 (예: smtp_accept_max)
                            pattern = rf"^\s*{setting_name}\s*=\s*(.*)"
                        else:
                            pattern = rf"^\s*{setting_name}\s*=?\s*(\w+)"
                        
                        match = re.search(pattern, config_content, re.MULTILINE | re.IGNORECASE)

                        if match:
                            dos_protection_settings[setting_name] = match.group(1).strip()
                        else:
                            dos_protection_settings[setting_name] = "미설정"

                        if service == "exim" and setting_name == "smtp_delay_reject":
                            if match and match.group(1).strip().lower() == "true":
                                dos_protection_settings[setting_name] = "true"  # 정상적인 설정
                            else:
                                dos_protection_settings[setting_name] = "미설정" # 값이 없거나 false
                                service_result = "취약"
                        elif dos_protection_settings[setting_name] == "미설정":
                            service_result = "취약"

                    log(f"  - {service.upper()} DoS 방지 설정:")
                    for setting_name, value in dos_protection_settings.items():
                        if value == "미설정":
                            log(f"    - {setting_name}: {value}")
                        
                    if service_result == "취약":
                         overall_result = "취약"
                         overall_exp.append(f"{service.upper()} 서비스 DoS 방지 설정 미흡")

                except Exception as e:
                    log(f"  - {service.upper()} 설정 파일 읽기 오류: {e}")
                    service_result = "N/A"
                    overall_result = "N/A"
                    overall_exp.append(f"{service.upper()} 설정 파일 읽기 오류")

            else:
                log(f"  - {service.upper()} 설정 파일({config_file}) 미발견 또는 접근 불가")
                service_result = "N/A"
                overall_result = "N/A"
                overall_exp.append(f"{service.upper()} 설정 파일 미발견 또는 접근 불가")
            
            log(f"  - {service.upper()} 서비스 점검 결과: {service_result}")

        else:
            log(f"- {service.upper()} 서비스 실행: 아니오")

        log("")

    # 최종 결과 출력
    if overall_result == "취약":
        log(f"결론: {overall_result}")
        log(f"설명: {', '.join(overall_exp)}")
    elif overall_result == "N/A":
        log(f"결론: {overall_result}")
        log(f"설명: {', '.join(overall_exp)}")
    else:
        log(f"결론: {overall_result}")
        log("설명: 모든 SMTP 서비스에 DoS 방지 기능이 설정되었거나 실행 중이지 않습니다.")
    log("")

def main():
    SRV_008()

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