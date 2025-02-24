import os
import subprocess
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-004.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-004: 불필요한 SMTP 서비스 실행
def SRV_004():
    log("[SRV-004] 불필요한 SMTP 서비스 실행")
    log("")

    smtp_processes = []
    for service in ["sendmail", "postfix", "exim"]:  # 다른 SMTP 서비스 추가
        process = subprocess.getoutput(f"ps -ef | grep {service} | grep -v grep")
        if process:
            smtp_processes.append((service, process))

    if smtp_processes:
        log("결과: 취약 (SMTP 서비스 실행 중)")
        for service, process in smtp_processes:
            log(f"  - {service}: {process}")  # 실행 중인 서비스와 프로세스 정보 출력
        log("참고: 실행 중인 SMTP 서비스가 불필요한 서비스인지 확인 필요")
    else:
        log("결과: 양호 (SMTP 서비스 미사용)")

    log("")

def main():
    SRV_004()

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