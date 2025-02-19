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

# SRV-037: 불필요한 FTP 서비스 실행
def SRV_037():
    log("[SRV-037] 불필요한 FTP 서비스 실행")
    log("")

    ftp_services = {
        "proftpd": {
            "process_name": "proftpd",
        },
        "vsftpd": {
            "process_name": "vsftpd",
        },
    }

    for service_name, info in ftp_services.items():
        process_name = info["process_name"]
        try:
            ftp_process = subprocess.check_output(
                f"ps -ef | grep -i '{process_name}' | grep -v grep", shell=True
            ).decode("utf-8").strip()
            
            if ftp_process:
                log(f"결과: 취약 ({service_name.upper()} 서비스 실행 중)")
                log(f"  - 프로세스 정보:")
                for line in ftp_process.splitlines():
                    log(f"    - {line.strip()}")
                log("  - 불필요한 FTP 서비스를 중지하고, 비활성화해야 합니다.")
                log(f"  - (예) systemctl stop {process_name} && systemctl disable {process_name}")  # 시스템에 맞는 명령어로 수정 필요
            else:
                log(f"결과: 양호 ({service_name.upper()} 서비스 미사용)")
        except subprocess.CalledProcessError as e:
            log(f"  - {service_name.upper()} 서비스 확인 중 오류 발생: {e}")
            log(f"결과: N/A ({service_name.upper()} 서비스 확인 불가)")

    log("")

def main():
    SRV_037()

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