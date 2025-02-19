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

# SRV-042: 웹 서비스 상위 디렉터리 접근 제한 설정 미흡
def SRV_042(apache_check, httpd_conf):
    log("[SRV-042] 웹 서비스 상위 디렉터리 접근 제한 설정 미흡")
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
        with open(httpd_conf, "r") as f:
            httpd_conf_content = f.read()
    except Exception as e:
        log(f"  - Apache 설정 파일 읽기 오류: {e}")
        log("결과: N/A")
        log("")
        return

    vulnerable = False
    try:
        # 1. httpd.conf 파일 전체에서 AllowOverride 설정 확인 (개선)
        allowoverride_settings = re.findall(
            r"^\s*AllowOverride\s+(.*?)$", httpd_conf_content, re.MULTILINE | re.IGNORECASE
        )

        if allowoverride_settings:
            log("  - AllowOverride 설정:")
            for setting in allowoverride_settings:
                log(f"    - {setting}")
                if setting.lower() != "none":
                    vulnerable = True

            # 2. <Directory /> 블록 내 AllowOverride None 설정 확인 (개선)
            directory_root_block = re.search(
                r"<\s*Directory\s+/>(.*?)</Directory>", httpd_conf_content, re.DOTALL | re.IGNORECASE
            )
            
            if directory_root_block:
                directory_root_content = directory_root_block.group(1)
                
                # <Directory /> 블록 내 AllowOverride None 설정 확인
                allowoverride_none_match = re.search(
                    r"^\s*AllowOverride\s+None", directory_root_content, re.MULTILINE | re.IGNORECASE
                )
                
                if allowoverride_none_match:
                  log("    - AllowOverride None 설정: 발견")
                  vulnerable = False
                else:
                  # <Directory /> 블록 내 AllowOverride 설정 확인
                  allowoverride_match = re.search(
                      r"^\s*AllowOverride\s+(.*)", directory_root_content, re.MULTILINE | re.IGNORECASE
                  )

                  if allowoverride_match:
                    log(f"    - AllowOverride 설정: {allowoverride_match.group(1).strip()} (취약)")
                    vulnerable = True
                  else:
                    log("    - AllowOverride 설정: 미설정")
                    vulnerable = True
            else:
              log("    - AllowOverride 설정: <Directory /> 블록 내 설정 확인 불가")
              vulnerable = True

        else:
            log("  - AllowOverride 설정: 없음")

        # 3. DocumentRoot 확인 (개선)
        document_root_match = re.search(
            r"^\s*DocumentRoot\s+\"(.*?)\"", httpd_conf_content, re.MULTILINE | re.IGNORECASE
        )
        if document_root_match:
            document_root = document_root_match.group(1)
            log(f"  - DocumentRoot: {document_root}")

            # 4. DocumentRoot에 대한 AllowOverride 설정 확인 (개선)
            directory_docroot_block = re.search(
                rf"<\s*Directory\s+{re.escape(document_root)}>(.*?)<\/Directory>", httpd_conf_content, re.DOTALL | re.IGNORECASE
            )
            if directory_docroot_block:
              directory_docroot_content = directory_docroot_block.group(1)
              # <Directory DocumentRoot> 블록 내 AllowOverride None 설정 확인
              allowoverride_none_match = re.search(
                  r"^\s*AllowOverride\s+None", directory_docroot_content, re.MULTILINE | re.IGNORECASE
              )
              if allowoverride_none_match:
                log(f"    - DocumentRoot 경로 AllowOverride None 설정: 발견")
                vulnerable = False
              else:
                log(f"    - DocumentRoot 경로 AllowOverride None 설정: 미발견 (취약)")
                vulnerable = True
            else:
                log(f"  - {document_root} (DocumentRoot) 경로에 대한 <Directory> 설정이 없습니다. (취약)")
                vulnerable = True
        else:
            log("  - DocumentRoot 설정 확인 불가")

        if vulnerable:
            log("결과: 취약 (상위 디렉터리 접근 제한 미흡)")
        else:
            log("결과: 양호 (상위 디렉터리 접근 제한 설정 확인)")

    except Exception as e:
        log(f"  - AllowOverride 설정 확인 중 오류 발생: {e}")
        log("결과: N/A")

    log("")

def main():
    SRV_042()

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