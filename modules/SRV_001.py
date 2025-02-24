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
    log("[SRV-001] SNMP Community 스트링 설정 미흡")
    log("")

    result = "양호"  # 결과 변수 초기화

    # SNMP 서비스 사용 여부 확인
    snmp_service = subprocess.getoutput("ps -ef | grep snmpd | grep -v grep")
    if snmp_service:
        log("1. SNMP 서비스 사용: 예")

        # SNMP v1/v2c 설정 파일 확인
        snmpd_conf_path = "/etc/snmp/snmpd.conf"
        if os.path.exists(snmpd_conf_path) and os.access(snmpd_conf_path, os.R_OK):
            # 취약 커뮤니티 스트링 검색 (대소문자 구분 없이, 공백 유연하게)
            snmpd_conf = subprocess.getoutput(
                f"grep -iE '^rocommunity\\s*(?:public|private)\\s*' {snmpd_conf_path} | grep -v '^#'"
            )
            if snmpd_conf:
                log("2. SNMP v1/v2c 취약 커뮤니티 스트링 발견:")
                log(snmpd_conf)
                result = "취약"
            else:
                log("2. SNMP v1/v2c 취약 커뮤니티 스트링 미발견")
        else:
            log(f"2. SNMP v1/v2c 취약 커뮤니티 스트링 검사: {snmpd_conf_path} 파일 접근 불가")

        # SNMP v3 설정 파일 확인
        if os.path.exists(snmpd_conf_path) and os.access(snmpd_conf_path, os.R_OK):
            # createUser로 생성된 사용자 확인 (public, private)
            snmpdv3_conf = subprocess.getoutput(
                f"grep -iE '^createUser\\s+(?:public|private)\\s' {snmpd_conf_path} | grep -v '^#'"
            )
            if snmpdv3_conf:
                log("3. SNMP v3 취약 사용자 발견:")
                log(snmpdv3_conf)
                result = "취약"
            else:
                log("3. SNMP v3 취약 사용자 미발견")

                # 추후 개선: createUser로 생성된 모든 사용자 검사 및 암호 복잡성 확인 필요
                log("   (참고) SNMP v3 설정 파일에서 'createUser'로 생성된 모든 사용자를 검사하고,")
                log("   암호 복잡성을 확인하는 것이 더 안전합니다.")
        else:
            log(f"3. SNMP v3 설정 검사: {snmpd_conf_path} 파일 접근 불가")

    else:
        log("1. SNMP 서비스 사용: 아니오")

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