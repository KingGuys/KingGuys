import os
import subprocess
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-014.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-014: NFS 접근통제 미비
def SRV_014():
    log("[SRV-014] NFS 접근 통제 미비")
    log("")

    try:
        nfs_process = subprocess.check_output(
            "ps -ef | grep nfsd | grep -v grep", shell=True  # nfsd 프로세스 확인
        ).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        nfs_process = ""

    if nfs_process:
        log("1. NFS 서비스 사용: 예")
        
        exports_file = "/etc/exports"

        if os.path.exists(exports_file) and os.access(exports_file, os.R_OK):
            try:
                with open(exports_file, "r") as f:
                    exports_content = f.read()
                log(f"2. {exports_file} 내용:")
                log(exports_content)

                vulnerable = False
                exp_list = []

                lines = exports_content.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue  # 빈 줄이나 주석은 건너뜀

                    parts = line.split()
                    if len(parts) < 2:
                        continue  # 형식이 잘못된 줄은 건너뜀

                    share_path = parts[0]
                    client_list = parts[1]

                    # 1) 모든 호스트(*)에 대한 접근 허용 여부 확인
                    if "*" in client_list:
                        vulnerable = True
                        exp_list.append(f"  - 경로: {share_path}, 모든 호스트(*)에 접근 허용")

                    # 2) insecure 옵션 사용 여부 확인 (추가)
                    if "insecure" in line:
                        vulnerable = True
                        exp_list.append(f"  - 경로: {share_path}, insecure 옵션 사용")

                    # 3) no_root_squash 옵션 사용 여부 확인 (추가)
                    if "no_root_squash" in line:
                        vulnerable = True
                        exp_list.append(f"  - 경로: {share_path}, no_root_squash 옵션 사용")

                if vulnerable:
                    log("  - 결론: 취약")
                    for exp in exp_list:
                        log(exp)
                else:
                    log("  - 결론: 양호 (모든 export 설정이 안전합니다.)")
            except Exception as e:
                log(f"  - {exports_file} 파일 읽기 오류: {e}")
                log("  - 결론: N/A")
        else:
            log(f"  - {exports_file} 파일이 없거나 읽을 수 없습니다.")
            log("  - 결론: N/A")

    else:
        log("1. NFS 서비스 사용: 아니오")
        log("  - 결론: 양호")

    log("")

def main():
    SRV_014()

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