import os
import subprocess
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-015.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-015: 불필요한 NFS 서비스 실행
def SRV_015():
    log("[SRV-015] 불필요한 NFS 서비스 실행")
    log("")

    try:
        nfs_process = subprocess.check_output(
            "ps -ef | grep nfsd | grep -v grep", shell=True  # nfsd 프로세스 확인
        ).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        nfs_process = ""

    if nfs_process:
        log("결과: 취약 (NFS 서비스 실행 중)")
        log(f"  - NFS 프로세스:\n{nfs_process}")
        log("  - NFS 서비스를 중지하고, 불필요한 경우 비활성화해야 합니다.")
        log("  - (예) systemctl stop nfs-server && systemctl disable nfs-server") # 시스템에 맞는 명령어로 수정 필요
    else:
        log("결과: 양호 (NFS 서비스 미사용)")

    log("")

def main():
    SRV_015()

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