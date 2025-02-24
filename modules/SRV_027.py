import os
import subprocess
import re
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-027.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-027: 서비스 접근 IP 및 포트 제한 미비
def SRV_027():
    log("[SRV-027] 서비스 접근 IP 및 포트 제한 미비")
    log("")

    def check_hosts_file(filename, expected_pattern):
        if os.path.isfile(filename):
            log(f"- {filename} 내용:")
            try:
                with open(filename, "r") as f:
                    content = f.read().strip()
                if content:
                    log(content)
                    # 정규 표현식으로 패턴 검사 (개선)
                    if re.search(expected_pattern, content):
                        log(f"  - {expected_pattern} 패턴 검출 (양호)")
                        return "양호"
                    else:
                        log(f"  - {expected_pattern} 패턴 미검출 (취약)")
                        return "취약"
                else:
                    log("    - 내용 없음 (취약)")
                    return "취약"
            except Exception as e:
                log(f"    - {filename} 파일 읽기 오류: {e}")
                return "N/A"  # 오류 발생 시 N/A 반환
        else:
            log(f"- {filename} 파일 없음 (취약)")
            return "취약"

    # /etc/hosts.allow 파일 점검 (sshd, vsftpd 접근 허용 설정 확인)
    hosts_allow_result_sshd = check_hosts_file("/etc/hosts.allow", r"^sshd\s*:")
    hosts_allow_result_vsftpd = check_hosts_file("/etc/hosts.allow", r"^vsftpd\s*:")

    # /etc/hosts.deny 파일 점검 (ALL:ALL 접근 거부 설정 확인)
    hosts_deny_result = check_hosts_file("/etc/hosts.deny", r"^ALL\s*:\s*ALL")

    # 종합적인 결과 판단
    if (
        hosts_allow_result_sshd == "양호"
        and hosts_allow_result_vsftpd == "양호"
        and hosts_deny_result == "양호"
    ):
        result = "양호"
    else:
        result = "취약"

    log(f"결론: {result}")
    log("")

def main():
    SRV_027()

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