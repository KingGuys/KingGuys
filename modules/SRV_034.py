import os
import subprocess
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-034.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-034: 불필요한 서비스 활성화
def SRV_034():
    log("[SRV-034] 불필요한 automount 서비스 실행")
    log("")

    try:
        # 1. systemctl 사용 및 오류 처리
        autofs_status = subprocess.check_output(
            "systemctl is-active autofs", shell=True, stderr=subprocess.DEVNULL
        ).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        autofs_status = "unknown"  # systemctl 명령어 오류 발생 시 unknown으로 설정

    if autofs_status == "active":
        log("결과: 취약 (autofs 서비스 활성화)")
        try:
            # automount 프로세스 정보 가져오기
            automount_service = subprocess.check_output(
                "ps -ef | grep -i 'automount' | grep -v 'grep'", shell=True
            ).decode("utf-8").strip()
            log(automount_service)
        except subprocess.CalledProcessError as e:
            log(f"  - automount 프로세스 정보 확인 중 오류 발생: {e}")
    else:
        log("결과: 양호 (autofs 서비스 비활성화)")
    log("")

def main():
    SRV_034()

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