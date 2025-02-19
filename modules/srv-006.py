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

# SRV-006: SMTP 서비스 로그 수준 설정 미흡
def SRV_006():
    log("[SRV-006] SMTP 서비스 로그 수준 설정 미흡")
    log("")

    smtp_services = ["sendmail", "postfix", "exim"]  # 점검할 SMTP 서비스 목록
    for service in smtp_services:
        smtp_process = subprocess.getoutput(f"ps -ef | grep {service} | grep -v grep")
        if smtp_process:
            log(f"- {service.upper()} 서비스 실행: 예")

            # 로그 파일 위치 확인 (sendmail, exim)
            if service == "sendmail" or service == "exim":
                config_file_path = f"/etc/mail/{service}.cf"  # sendmail, exim 설정 파일 경로
                if os.path.exists(config_file_path) and os.access(config_file_path, os.R_OK):
                    log_file_output = subprocess.getoutput(
                        f"grep -E '^[^#]*LogFile' {config_file_path}"
                    )
                    if log_file_output:
                        log_file = log_file_output.split()[-1]
                        log(f"  - 로그 파일 위치: {log_file}")
                    else:
                        log("  - 로그 파일 위치: 설정되지 않음")

                    # 로그 로테이션 설정 확인 (sendmail, exim)
                    log_rotation_output = subprocess.getoutput(
                        f"grep -E '^[^#]*LogRotation' {config_file_path}"
                    )
                    if log_rotation_output:
                        log(f"  - 로그 로테이션 설정: {log_rotation_output}")
                    else:
                        log("  - 로그 로테이션 설정: 설정되지 않음")

                else:
                    log(f"  - 설정 파일({config_file_path}) 접근 불가")

            # LogLevel 설정 확인 (sendmail)
            if service == "sendmail":
                log_level_output = subprocess.getoutput(
                    "grep 'LogLevel' /etc/mail/sendmail.cf"
                )
                if log_level_output.startswith("#"):
                    log("  - LogLevel 설정: 주석 처리됨 (미설정)")
                    result = "취약"
                else:
                    try:
                        log_level = int(log_level_output.split()[-1])
                        if log_level >= 9:
                            log(f"  - LogLevel 설정: {log_level} (양호)")
                            result = "양호"
                        else:
                            log(f"  - LogLevel 설정: {log_level} (취약)")
                            result = "취약"
                    except ValueError:
                        log("  - LogLevel 설정: 숫자 값 파싱 오류")
                        result = "취약"

            # postfix 로그 수준 확인
            elif service == "postfix":
                # postfix는 syslog를 통해 로그를 관리
                # /etc/rsyslog.conf 또는 /etc/syslog.conf 에서 mail 관련 설정 확인
                try:
                    syslog_config = subprocess.check_output(
                        "grep -R 'mail' /etc/rsyslog.conf /etc/syslog.conf", shell=True
                    ).decode("utf-8")
                    if "mail.info" in syslog_config or "mail.debug" in syslog_config:
                        log("  - 로그 수준: info 또는 debug 이상 (양호)")
                        result = "양호"
                    else:
                        log("  - 로그 수준: info 또는 debug 이상으로 설정되지 않음 (취약)")
                        result = "취약"
                except subprocess.CalledProcessError:
                    log("  - 로그 설정 확인 중 오류 발생")
                    result = "N/A"

            # exim 로그 수준 확인
            elif service == "exim":
                config_file_path = "/etc/exim4/exim4.conf.template"  # exim 설정 파일 (데비안 계열)
                if os.path.exists(config_file_path) and os.access(config_file_path, os.R_OK):
                    log_selector_output = subprocess.getoutput(
                        f"grep -i '^\\s*log_selector' {config_file_path} | grep -v '^#'"
                    )
                    if log_selector_output:
                        log_selector = log_selector_output.split("=")[-1].strip()
                        if "+all" in log_selector.lower():
                            log(f"  - log_selector 설정: +all (양호)")
                            result = "양호"
                        else:
                            log(
                                f"  - log_selector 설정: {log_selector} (취약: +all 설정 권장)"
                            )
                            result = "취약"
                    else:
                        log("  - log_selector 설정: 찾을 수 없음")
                        result = "취약"
                else:
                    log(f"  - 설정 파일({config_file_path}) 접근 불가")
                    result = "N/A"
            
            log(f"  - 결론: {result}")
            log("")

        else:
            log(f"- {service.upper()} 서비스 실행: 아니오")
            log("")

def main():
    SRV_006()

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