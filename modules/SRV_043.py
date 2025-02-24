import os
import subprocess
import re
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-043.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-043: 웹 서비스 경로 내 불필요한 파일 존재
def SRV_043(apache_check, httpd_conf):
    log("[SRV-043] 웹 서비스 경로 내 불필요한 파일 존재")
    log("")

    if not apache_check:
        log("결과: 양호 (Apache 서비스 미사용)")
        log("")
        return

    if not httpd_conf or not os.path.exists(httpd_conf) or not os.access(httpd_conf, os.R_OK):
        log(f"  - Apache 설정 파일({httpd_conf}) 미발견 또는 접근 불가")
        log("결과: N/A")
        log("")
        return

    try:
        # 1. ServerRoot 확인
        httpd_conf_content = subprocess.check_output(
            f"grep -v '^#' {httpd_conf}", shell=True
        ).decode("utf-8")

        server_root_match = re.search(
            r"^\s*ServerRoot\s+\"(.*?)\"", httpd_conf_content, re.MULTILINE | re.IGNORECASE
        )

        if server_root_match:
            server_root = server_root_match.group(1)
            log(f"  - ServerRoot: {server_root}")
        else:
            log("  - ServerRoot 설정 확인 불가")
            log("결과: N/A")
            log("")
            return
        
        # 2. DocumentRoot 확인
        document_root_match = re.search(
            r"^\s*DocumentRoot\s+\"(.*?)\"", httpd_conf_content, re.MULTILINE | re.IGNORECASE
        )
        if document_root_match:
            document_root = document_root_match.group(1)
            log(f"  - DocumentRoot: {document_root}")
        else:
            log("  - DocumentRoot 설정 확인 불가")
            log("결과: N/A")
            log("")
            return
        
        # 3. <Directory> 블록에서 httpd_root 경로 찾기 (개선)
        directory_blocks = re.findall(
            r"<\s*Directory\s+(.*?)>(.*?)<\/Directory>", httpd_conf_content, re.DOTALL | re.IGNORECASE
        )

        httpd_root = None
        for directory_path, directory_content in directory_blocks:
            if directory_path == server_root or directory_path == document_root:
                httpd_root = directory_path
                log(f"  - httpd_root 경로: {httpd_root} (발견)")
                break

        if not httpd_root:
            log("  - httpd_root 경로 확인 불가")
            log("결과: N/A")
            log("")
            return

        # 불필요한 파일 목록
        unnecessary_files = ["manual", "docs", "samples", "examples", "cgi-bin"]  # 2. cgi-bin 디렉터리 추가
        found_files = []

        # 불필요한 파일/디렉터리 확인 (개선)
        for file in unnecessary_files:
            # 파일/디렉터리 존재 확인
            file_path = os.path.join(httpd_root, file)
            if os.path.exists(file_path):
                found_files.append(file_path)

        if found_files:
            log("결과: 취약 (불필요한 파일 또는 디렉터리 발견)")
            for file in found_files:
                log(f"  - {file}")
        else:
            log("결과: 양호 (불필요한 파일 또는 디렉터리 없음)")

    except subprocess.CalledProcessError as e:
        log(f"  - Apache 설정 파일 또는 경로 확인 중 오류 발생: {e}")
        log("결과: N/A")
    except Exception as e:
        log(f"  - 불필요한 파일 확인 중 오류 발생: {e}")
        log("결과: N/A")

    log("")

def main():
    SRV_043()

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