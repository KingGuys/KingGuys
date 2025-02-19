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

# SRV-005: SMTP 서비스의 expn/vrfy 명령어 실행 제한 미비
def SRV_005():
    log("[SRV-005] SMTP 서비스의 expn/vrfy 명령어 실행 제한 미비")
    log("")

    sendmail_config_path = "/etc/mail/sendmail.cf"  # 설정 파일 경로 변수화
    result = "양호"  # 기본 결과를 양호로 설정

    smtp_service = subprocess.getoutput("ps -ef | grep sendmail | grep -v grep")
    if smtp_service:
        log("1. SMTP 서비스 사용 (sendmail): 예")

        if os.path.exists(sendmail_config_path) and os.access(sendmail_config_path, os.R_OK):
            # PrivacyOptions 설정 확인 (주석 제외, 공백 유연하게 처리)
            privacy_options_line = subprocess.getoutput(
                f"grep -i '^\\s*PrivacyOptions\\s*=' {sendmail_config_path} | grep -v '^#'"
            )
            if privacy_options_line:
                privacy_options = privacy_options_line.split("=")[1].strip().lower()

                noexpn = "noexpn" in privacy_options
                novrfy = "novrfy" in privacy_options
                goaway = "goaway" in privacy_options

                log(f"2. PrivacyOptions 설정: {privacy_options_line.strip()}")
                log(f"   - noexpn 옵션 설정: {'예' if noexpn else '아니오'}")
                log(f"   - novrfy 옵션 설정: {'예' if novrfy else '아니오'}")
                log(f"   - goaway 옵션 설정: {'예' if goaway else '아니오'}")

                if not (noexpn and novrfy) and not goaway:
                    result = "취약"
            else:
                log(f"2. PrivacyOptions 설정이 {sendmail_config_path} 파일에 없습니다.")
                result = "취약"
        else:
            log(f"2. {sendmail_config_path} 파일에 접근할 수 없습니다.")
            result = "N/A"
    else:
        log("1. SMTP 서비스 사용 (sendmail): 아니오")
        result = "양호"

    log(f"결론: {result}")
    log("")

def main():
    SRV_005()

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