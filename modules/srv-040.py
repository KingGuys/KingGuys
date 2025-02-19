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

# SRV-040: 웹 서비스 디렉터리 리스팅 방지 설정 미흡
def SRV_040(apache_check, httpd_conf):
    log("[SRV-040] 웹 서비스 디렉터리 리스팅 방지 설정 미흡")
    log("")

    vulnerable = False  # 1. try 블록 바깥에서 초기화
    if not apache_check:
        log("결과: 양호 (Apache 서비스 미사용)")
        log("")
        return

    if not httpd_conf or not os.path.exists(httpd_conf) or not os.access(httpd_conf, os.R_OK):
        log(f"  - Apache 설정 파일({httpd_conf}) 미발견 또는 접근 불가")
        log("결과: N/A")
        log("")
        return
    
    httpd_conf_content = ""  # 4. try 블록 바깥에 선언
    try:
        with open(httpd_conf, "r") as f:
            httpd_conf_content = f.read()
    except Exception as e:
        log(f"  - Apache 설정 파일 읽기 오류: {e}")
        log("결과: N/A")
        log("")
        return

    # DocumentRoot 확인
    document_roots = []  # 2. 모든 DocumentRoot 설정을 저장
    try:
        document_root_matches = re.findall(
            r"^\s*DocumentRoot\s+\"(.*?)\"", httpd_conf_content, re.MULTILINE | re.IGNORECASE
        )
        for match in document_root_matches:
            document_roots.append(match)

        if document_roots:
            log(f"  - DocumentRoot: {document_roots[-1]} (마지막 설정)")  # 2. 마지막 설정값 출력
            if len(document_roots) > 1:
                log(f"  - DocumentRoot 설정이 여러 개입니다. ({len(document_roots)}개)")
        else:
            log("  - DocumentRoot 설정 확인 불가 (N/A)")  # 2. N/A로 설정
    except Exception as e:
        log(f"  - DocumentRoot 설정 확인 중 오류 발생: {e}")

    # <Directory> 블록 내 Indexes 옵션 확인
    try:
        directory_blocks = re.findall(
            r"<\s*Directory\s+(.*?)>(.*?)<\/Directory>", httpd_conf_content, re.DOTALL | re.IGNORECASE
        )
        for directory_path, directory_content in directory_blocks:
            # 해당 <Directory> 블록 내 Options 설정 확인
            options_match = re.search(
                r"^\s*Options\s+(.*?)$", directory_content, re.MULTILINE | re.IGNORECASE
            )
            if options_match:
                options_line = options_match.group(1)
                if "Indexes" in options_line and "-Indexes" not in options_line:
                    vulnerable = True
                    log(f"  - Directory: {directory_path} (취약)")
                    log(f"    - Options: {options_line.strip()}")
                    log(f"    - Indexes 옵션 활성화 (취약)")

        # DocumentRoot에 대한 Indexes 설정 확인
        if document_roots:
            final_document_root = document_roots[-1]  # 2. 마지막 DocumentRoot 설정 사용
            if not any(
                re.search(rf"<\s*Directory\s+{re.escape(final_document_root)}", block[0], re.IGNORECASE)
                for block in directory_blocks
            ):
                log(f"  - {final_document_root} (DocumentRoot) 경로에 대한 <Directory> 설정이 없습니다.")

        if vulnerable:
            log("결과: 취약 (Indexes 옵션 활성화)")
        else:
            log("결과: 양호 (Indexes 옵션 비활성화 또는 미설정)")

    except Exception as e:
        log(f"  - Indexes 옵션 확인 중 오류 발생: {e}")
        log("결과: N/A")

    log("")

def main():
    SRV_040()

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