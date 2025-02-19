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

# SRV-021: FTP 서비스 접근 제어 설정 미흡
def SRV_021():
    log("[SRV-021] FTP 서비스 접근 제어 설정 미비")
    log("")

    ftp_services = {
        "proftpd": {
            "process_name": "proftpd",
            "config_file": "/etc/proftpd/proftpd.conf",
            "access_control_settings": [
                {"name": "Allow", "pattern": r"^\s*Allow\s+from"},
                {"name": "Deny", "pattern": r"^\s*Deny\s+from"},
            ],
        },
        "vsftpd": {
            "process_name": "vsftpd",
            "config_file": "/etc/vsftpd/vsftpd.conf",
            "access_control_settings": [
                {"name": "tcp_wrappers", "pattern": r"^\s*tcp_wrappers\s*=\s*YES"}
            ],
        },
    }

    overall_result = "양호"
    overall_exp = []

    for service, info in ftp_services.items():
        process_name = info["process_name"]
        config_file = info.get("config_file")
        access_control_settings = info.get("access_control_settings", [])

        try:
            ftp_process = subprocess.check_output(
                f"ps -ef | grep {process_name} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            ftp_process = ""

        if ftp_process:
            log(f"- {service.upper()} 서비스 실행: 예")
            service_result = "취약"

            if config_file and os.path.exists(config_file) and os.access(config_file, os.R_OK):
                try:
                    with open(config_file, "r") as f:
                        config_content = f.read()

                    if service == "proftpd":
                        log(f"  - 설정 파일: {config_file} (존재)")
                        
                        
                        found_access_control = False
                        for setting in access_control_settings:
                            setting_name = setting["name"]
                            setting_pattern = setting["pattern"]

                            match = re.search(setting_pattern, config_content, re.MULTILINE | re.IGNORECASE)
                            if match:
                                log(f"    - {setting_name} 설정: {match.group(0).strip()} (양호)")
                                found_access_control = True
                            else:
                                log(f"    - {setting_name} 설정: 미설정 또는 설정 확인 불가 (취약)")
                        
                        if found_access_control:
                            service_result = "양호"

                    elif service == "vsftpd":
                        for setting in access_control_settings:
                            setting_name = setting["name"]
                            setting_pattern = setting["pattern"]

                            match = re.search(setting_pattern, config_content, re.MULTILINE | re.IGNORECASE)
                            if match:
                                log(f"    - {setting_name} 설정: {match.group(0).strip()} (양호)")
                                log(f"    - vsftpd는 TCP Wrapper 설정(/etc/hosts.allow, /etc/hosts.deny)을 확인해야 합니다.")
                                service_result = check_hosts_allow_deny("vsftpd") or service_result
                            else:
                                log(f"    - {setting_name} 설정: 미설정 또는 설정 확인 불가 (취약)")
                    else:
                        log(f"  - {service} 서비스는 설정 확인을 지원하지 않습니다.")
                        service_result = "N/A"

                except Exception as e:
                    log(f"  - {service.upper()} 설정 파일 읽기 오류: {e}")
                    service_result = "N/A"
            else:
                log(f"  - {service.upper()} 설정 파일({config_file}) 미발견 또는 접근 불가")
                service_result = "N/A"
            
            if service_result == "양호" or service_result == "주의":
              log(f"  - {service.upper()} 서비스 점검 결과: {service_result}")
            elif service_result == "N/A":
              log(f"  - {service.upper()} 서비스 점검 결과: {service_result}")
            else:
              log(f"  - {service.upper()} 서비스 점검 결과: {'양호' if service_result == '양호' else '취약' if service_result == '취약' else 'N/A'}")

            if service_result == "취약":
                overall_result = "취약"
                overall_exp.append(f"{service.upper()} 서비스 접근 제어 설정 미흡")
            elif service_result == "N/A":
                overall_result = "N/A" if overall_result != "취약" else overall_result
                overall_exp.append(f"{service.upper()} 서비스 접근 제어 설정 확인 불가")

        else:
            log(f"- {service.upper()} 서비스 실행: 아니오")
        log("")
    
    # TCP Wrapper 설정 확인 (vsftpd 및 기타 서비스에서 사용 가능)
    log(f"  - TCP Wrapper 설정 확인 (/etc/hosts.allow, /etc/hosts.deny)")
    tcp_wrapper_result = check_hosts_allow_deny(None) # None을 전달하여 특정 서비스에 종속되지 않도록 함
    if tcp_wrapper_result == "취약":
        overall_result = "취약"
        overall_exp.append("TCP Wrapper 접근 제어 설정 미흡")
    elif tcp_wrapper_result == "N/A":
        overall_result = "N/A" if overall_result != "취약" else overall_result
        overall_exp.append("TCP Wrapper 접근 제어 설정 확인 불가")
    log(f"  - TCP Wrapper 설정 점검 결과: {'양호' if tcp_wrapper_result == '양호' else '취약' if tcp_wrapper_result == '취약' else 'N/A' if tcp_wrapper_result == None else '주의'}")

    # 최종 결과 출력
    if overall_result == "취약":
        log(f"결론: {overall_result}")
        log(f"설명: {', '.join(overall_exp)}")
    elif overall_result == "N/A":
        log(f"결론: {overall_result}")
        log(f"설명: {', '.join(overall_exp)}")
    else:
        log(f"결론: {overall_result}")
        log("설명: 모든 FTP 서비스에 접근 제어 설정이 적절히 구성되었거나 실행 중이지 않습니다.")
    log("")

def check_hosts_allow_deny(service_name):
    result = "양호"
    for filename in ["/etc/hosts.allow", "/etc/hosts.deny"]:
        if os.path.isfile(filename):
            try:
                with open(filename, "r") as f:
                    content = f.read().strip()
                log(f"    - {filename} 내용:")
                if content:
                    log(content)
                    if "ALL: ALL" in content:
                        log(f"      - ALL: ALL 설정 (주의)")
                        if result != "취약":
                            result = "주의"
                    # 특정 서비스에 대한 접근 제어 설정 확인 (예: vsftpd)
                    if service_name:
                        if not re.search(rf"^{service_name}\s*:", content, re.MULTILINE | re.IGNORECASE):
                            log(f"      - {service_name} 서비스에 대한 접근 제어 설정 없음 (취약)")
                            result = "취약"
                else:
                    log("      - 내용 없음")
            except Exception as e:
                log(f"      - {filename} 파일 읽기 오류: {e}")
                return "N/A"
        else:
            log(f"    - {filename} 파일 없음")
    return result

def main():
    SRV_021()

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