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

# SRV-011: 시스템 관리자 계정의 FTP 사용 제한 미비
def SRV_011():
    log("[SRV-011] 시스템 관리자 계정의 FTP 사용 제한 미비")
    log("")

    ftp_services = {
        "proftpd": {
            "process_name": "proftpd",
            "config_file": "/etc/proftpd/proftpd.conf",
            "root_login_check_setting": "RootLogin",
            "root_login_check_value": "off",
            "ftpusers_file_setting": "UserAlias",
        },
        "vsftpd": {
            "process_name": "vsftpd",
            "config_file": "/etc/vsftpd/vsftpd.conf",
            "root_login_check_setting": "root_login_enable",  # 5. 가상의 설정임을 주석으로 명시
            "root_login_check_value": "NO",
            "ftpusers_file_setting": "userlist_file",
        },
    }

    overall_result = True  # 1. 초기값을 True로 변경
    overall_exp = []

    for service, info in ftp_services.items():
        process_name = info["process_name"]
        config_file = info.get("config_file")
        root_login_check_setting = info.get("root_login_check_setting")
        root_login_check_value = info.get("root_login_check_value")
        ftpusers_file_setting = info.get("ftpusers_file_setting")

        try:
            ftp_process = subprocess.check_output(
                f"ps -ef | grep {process_name} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            ftp_process = ""

        if ftp_process:
            log(f"- {service.upper()} 서비스 실행: 예")
            service_result = False  # 1. 서비스 실행 중일 때는 기본적으로 False(취약)으로 설정

            if config_file and os.path.exists(config_file) and os.access(config_file, os.R_OK):
                try:
                    with open(config_file, "r") as f:
                        config_content = f.read()

                    # root 계정 FTP 접속 제한 확인 (설정 파일 내)
                    if root_login_check_setting:
                        match = re.search(
                            rf"^\s*{root_login_check_setting}\s+({root_login_check_value})",
                            config_content,
                            re.MULTILINE | re.IGNORECASE,
                        )
                        if match:
                            log(f"  - root 계정 FTP 접속 제한 ({root_login_check_setting}): {match.group(1)} (양호)")
                            service_result = True
                        else:
                            log(f"  - root 계정 FTP 접속 제한 ({root_login_check_setting}): 설정되지 않음 또는 {root_login_check_value} 아님 (취약)")

                    # ftpusers 파일 확인
                    if ftpusers_file_setting:
                        if service == "vsftpd":
                            ftpusers_file_match = re.search(
                                rf"^\s*{ftpusers_file_setting}\s*=\s*(\S+)",
                                config_content,
                                re.MULTILINE | re.IGNORECASE,
                            )
                        elif service == "proftpd":
                            ftpusers_file_match = re.search(
                                rf"^\s*UserAlias\s+(\w+)\s+(\w+)",
                                config_content,
                                re.MULTILINE | re.IGNORECASE,
                            )

                        if ftpusers_file_match:
                            if service == "vsftpd":
                                ftpusers_file = ftpusers_file_match.group(1)
                            elif service == "proftpd":
                                virtual_user = ftpusers_file_match.group(1)
                                real_user = ftpusers_file_match.group(2)
                                # 가상 사용자가 root이면 실제 사용자로 확인
                                if virtual_user == "root":
                                    ftpusers_file = "/etc/passwd"  # 3. /etc/shadow도 확인 필요
                                else:
                                    ftpusers_file = None
                            else:
                                ftpusers_file = None

                            # ftpusers 또는 passwd 파일 확인
                            if ftpusers_file and os.path.exists(ftpusers_file):
                                with open(ftpusers_file, "r") as f:
                                    users = f.read().splitlines()
                                    if service == "proftpd" and real_user == "root":
                                        log(f"  - {ftpusers_file} 파일에서 root 사용자 확인: 예 (양호)")
                                        # 3. UserAlias 설정에서 root 계정이 아닌 다른 가상 사용자도 제한하는지 확인 필요
                                    elif service == "vsftpd" and "root" in users:
                                        log(f"  - {ftpusers_file} 파일에 root 포함: 아니오 (취약)")
                                        service_result = False
                                    else:
                                        log(f"  - {ftpusers_file} 파일에서 root 사용자 확인 또는 root 계정 매핑: 아니오 (취약)")
                                        service_result = False
                            elif service == "proftpd" and real_user == "root":
                                log(f"  - {ftpusers_file} 파일에서 root 사용자 확인을 위한 {real_user} 계정 정보 확인 불가 (취약)")
                                service_result = False
                            else:
                                log(f"  - {ftpusers_file} 파일 확인 불가 (취약)")
                                service_result = False
                        else:
                            log(f"  - {ftpusers_file_setting} 설정: 찾을 수 없음 (취약)")
                            service_result = False

                except Exception as e:
                    log(f"  - {service.upper()} 설정 파일 읽기 오류: {e}")
                    service_result = None
            else:
                log(f"  - {service.upper()} 설정 파일({config_file}) 미발견 또는 접근 불가")
                service_result = None

            log(f"  - {service.upper()} 서비스 점검 결과: {'양호' if service_result else '취약' if service_result == False else 'N/A'}")

            # 2. overall_result 및 overall_exp 업데이트
            overall_result = overall_result and service_result

            if service_result == False and f"{service.upper()} 서비스 root 계정 FTP 접속 제한 미흡" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 root 계정 FTP 접속 제한 미흡")
            elif service_result == None and f"{service.upper()} 서비스 root 계정 FTP 접속 제한 확인 불가" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 root 계정 FTP 접속 제한 확인 불가")

        else:
            log(f"- {service.upper()} 서비스 실행: 아니오")
        log("")

    # 최종 결과 출력
    if overall_result == False:
        log(f"결론: 취약")
        log(f"설명: {', '.join(overall_exp)}")
    elif overall_result == None:
        log(f"결론: N/A")
        log(f"설명: {', '.join(overall_exp)}")
    else:
        log(f"결론: 양호")
        log("설명: 모든 FTP 서비스에 root 계정 FTP 접속 제한이 적절히 설정되었거나 실행 중이지 않습니다.")
    log("")

    log("참고: SFTP, SCP 등 다른 파일 전송 프로토콜을 사용하는 경우, 해당 프로토콜의 root 계정 접속 제한 설정도 확인해야 합니다.")
    log("")

def main():
    SRV_011()

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