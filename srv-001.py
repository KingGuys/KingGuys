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

# SRV-001: SNMP Community 스트링 설정 미흡
def SRV_001():
    """SNMP Community 스트링 설정 미흡 점검을 수행합니다."""
    log("[SRV-001] SNMP Community 스트링 설정 미흡")
    log("")

    # SNMP 서비스 사용 여부 확인
    snmp_service = subprocess.getoutput("ps -ef | grep snmpd | grep -v grep")  # snmpd 프로세스 확인
    if snmp_service:
        log("1. SNMP 서비스 사용: 예")

        # SNMP v1/v2c 설정 파일에서 public 또는 private 커뮤니티 스트링 검색
        snmpd_conf = subprocess.getoutput("grep -E '^rocommunity\\s+(public|private)\\s' /etc/snmp/snmpd.conf | grep -v '^#'")
        if snmpd_conf:
            log("2. SNMP v1/v2c 취약 커뮤니티 스트링 발견:")
            log(snmpd_conf)
            result = "취약"
        else:
            log("2. SNMP v1/v2c 취약 커뮤니티 스트링 미발견")

        # SNMP v3 설정 파일에서 public 또는 private 사용자 검색
        snmpdv3_conf = subprocess.getoutput("grep -E '^createUser\\s+(public|private)\\s' /etc/snmp/snmpd.conf | grep -v '^#'")
        if snmpdv3_conf:
            log("3. SNMP v3 취약 사용자 발견:")
            log(snmpdv3_conf)
            result = "취약"
        else:
            log("3. SNMP v3 취약 사용자 미발견")

        if result != "취약":
            result = "양호"  # 취약한 설정이 없을 경우 양호로 설정

    else:
        log("1. SNMP 서비스 사용: 아니오")
        result = "양호"

    log(f"결론: {result}")
    log("")

def main():
    SRV_001()

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