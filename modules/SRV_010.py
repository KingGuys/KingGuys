import os
import subprocess
import re
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-010.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

# SRV-010: SMTP 서비스의 메일 queue 처리 권한 설정 미흡
def SRV_010():
    log("[SRV-010] SMTP 서비스의 메일 queue 처리 권한 설정 미흡")
    log("")

    smtp_services = {
        "sendmail": {
            "process_name": "sendmail",
            "config_file": "/etc/mail/sendmail.cf",
            "queue_permission_check": {
                "setting": "PrivacyOptions",
                "options": ["restrictqrun", "goaway"],  # 3. goaway 옵션 확인 추가
            },
        },
        "postfix": {
            "process_name": "master",
            "queue_dirs": [
                "/var/spool/postfix/incoming",
                "/var/spool/postfix/active",
                "/var/spool/postfix/deferred",
            ],
            "queue_permission_check": {
                "owner": "postfix",
                "group": "postdrop",
                "permission": "730",
            },
        },
        "exim": {
            "process_name": "exim",
            "config_file": "/etc/exim/exim.conf",
            "queue_dir": "/var/spool/exim/input",
            "queue_permission_check": {
                "setting": "queue_only_file_owner",
                "value": "exim"
            },
        },
    }

    overall_result = True  # 1. 초기값을 True로 변경
    overall_exp = []

    for service, info in smtp_services.items():
        process_name = info["process_name"]
        config_file = info.get("config_file")
        queue_dirs = info.get("queue_dirs")
        queue_dir = info.get("queue_dir")
        queue_permission_check = info.get("queue_permission_check")

        try:
            smtp_process = subprocess.check_output(
                f"ps -ef | grep {process_name} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            smtp_process = ""

        if smtp_process:
            log(f"- {service.upper()} 서비스 실행: 예")
            service_result = False  # 1. 서비스 실행 중일 때는 기본적으로 False(취약)으로 설정

            if service == "sendmail":
                if config_file and os.path.exists(config_file) and os.access(config_file, os.R_OK):
                    try:
                        with open(config_file, "r") as f:
                            config_content = f.read()

                        setting = queue_permission_check["setting"]
                        options = queue_permission_check["options"]

                        # 3. sendmail: PrivacyOptions 설정에서 restrictqrun 또는 goaway 확인
                        service_result = False
                        for option in options:
                            match = re.search(
                                rf"^\s*{setting}\s*=.*{option}",
                                config_content,
                                re.MULTILINE | re.IGNORECASE,
                            )
                            if match:
                                log(f"  - {option} 설정: 예 (양호)")
                                service_result = True
                                break  # 하나라도 만족하면 양호로 판단
                        if not service_result:
                            log(f"  - {', '.join(options)} 설정: 아니오 (취약)")

                    except Exception as e:
                        log(f"  - {service.upper()} 설정 파일 읽기 오류: {e}")
                        service_result = None
                else:
                    log(f"  - {service.upper()} 설정 파일({config_file}) 미발견 또는 접근 불가")
                    service_result = None
            elif service == "postfix":
                # Postfix: 큐 디렉터리 권한 확인
                if queue_dirs:
                    service_result = True
                    for queue_dir in queue_dirs:
                        try:
                            st = os.stat(queue_dir)
                            owner = subprocess.check_output(f"stat -c %U {queue_dir}", shell=True).decode("utf-8").strip()
                            group = subprocess.check_output(f"stat -c %G {queue_dir}", shell=True).decode("utf-8").strip()
                            permission = oct(st.st_mode & 0o777)[2:]

                            if (
                                owner != queue_permission_check["owner"]
                                or group != queue_permission_check["group"]
                                or permission != queue_permission_check["permission"]
                            ):
                                log(
                                    f"  - {queue_dir} 디렉터리 권한: {permission} (소유자: {owner}, 그룹: {group}) (취약)"
                                )
                                service_result = False
                            else:
                                log(
                                    f"  - {queue_dir} 디렉터리 권한: {permission} (소유자: {owner}, 그룹: {group}) (양호)"
                                )
                        except Exception as e:
                            log(f"  - {queue_dir} 디렉터리 권한 확인 오류: {e}")
                            service_result = None  # N/A
                else:
                    log("  - Postfix 큐 디렉터리 정보 없음")
                    service_result = None # N/A
            elif service == "exim":
                # Exim: 큐 디렉터리 권한 및 설정 파일 확인
                if queue_dir and os.path.exists(queue_dir):
                    try:
                        # 큐 디렉터리 소유자 확인
                        owner = subprocess.check_output(f"stat -c %U {queue_dir}", shell=True).decode("utf-8").strip()

                        # 설정 파일에서 queue_only_file_owner 설정 확인
                        if config_file and os.path.exists(config_file) and os.access(config_file, os.R_OK):
                            with open(config_file, "r") as f:
                                config_content = f.read()

                            setting = queue_permission_check["setting"]
                            value = queue_permission_check["value"]

                            match = re.search(
                                rf"^\s*{setting}\s*=\s*{value}",
                                config_content,
                                re.MULTILINE | re.IGNORECASE,
                            )
                            if match and owner == value:
                                log(f"  - {queue_dir} 디렉터리 소유자: {owner} (양호)")
                                log(f"  - {setting} 설정: {value} (양호)")
                                service_result = True
                            else:
                                log(f"  - {queue_dir} 디렉터리 소유자: {owner} (취약: {value} 필요)")
                                log(f"  - {setting} 설정: {value} 불일치 또는 설정되지 않음 (취약)")
                                service_result = False
                        else:
                            log(f"  - {service.upper()} 설정 파일({config_file}) 미발견 또는 접근 불가")
                            service_result = None # N/A
                    except Exception as e:
                        log(f"  - {queue_dir} 디렉터리 권한 확인 오류: {e}")
                        service_result = None # N/A
                else:
                    log(f"  - {service.upper()} 큐 디렉터리({queue_dir}) 미발견")
                    service_result = None # N/A
            else:
                log(f"  - {service} 서비스는 메일 queue 처리 권한 설정 확인을 지원하지 않습니다.")
                service_result = None # N/A

            log(f"  - {service.upper()} 서비스 점검 결과: {'양호' if service_result else '취약' if service_result == False else 'N/A'}")

            # 2. overall_result 및 overall_exp 업데이트
            overall_result = overall_result and service_result

            if service_result == False and f"{service.upper()} 서비스 메일 queue 처리 권한 설정 미흡" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 메일 queue 처리 권한 설정 미흡")
            elif service_result == None and f"{service.upper()} 서비스 메일 queue 처리 권한 설정 확인 불가" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 메일 queue 처리 권한 설정 확인 불가")
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
        log("설명: 모든 SMTP 서비스에 메일 queue 처리 권한이 적절히 설정되었거나 실행 중이지 않습니다.")
    log("")

def main():
    SRV_010()

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