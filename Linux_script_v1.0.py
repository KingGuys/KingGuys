import os
import re
import subprocess
import socket
import stat
import platform
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"Linux_{hostname}.log"

# 로그 작성 함수
def log(message):
    with open(filename, "a") as f:
        f.write(message + "\n")

# Apache 활성화 유무 체크
apache_check = "ON" if subprocess.getoutput("ps -ef | grep httpd | grep -v grep") else "OFF"
log(f"Apache Check: {apache_check}")

httpd_conf = "/opt/freeware/etc/httpd/conf/httpd.conf"

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

        # SNMP v3 설정 파일 확인 (개선 필요)
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

# SRV-004: 불필요한 SMTP 서비스 실행
def SRV_004():
    log("[SRV-004] 불필요한 SMTP 서비스 실행")
    log("")

    smtp_processes = []
    for service in ["sendmail", "postfix", "exim"]:  # 다른 SMTP 서비스 추가
        process = subprocess.getoutput(f"ps -ef | grep {service} | grep -v grep")
        if process:
            smtp_processes.append((service, process))

    if smtp_processes:
        log("결과: 취약 (SMTP 서비스 실행 중)")
        for service, process in smtp_processes:
            log(f"  - {service}: {process}")  # 실행 중인 서비스와 프로세스 정보 출력
        log("참고: 실행 중인 SMTP 서비스가 불필요한 서비스인지 확인 필요")
    else:
        log("결과: 양호 (SMTP 서비스 미사용)")

    log("")

# SRV-005: SMTP 서비스의 expn/vrfy 명령어 실행 제한 미비
def SRV_005():
    log("[SRV-005] SMTP 서비스의 expn/vrfy 명령어 실행 제한 미비")
    log("")

    sendmail_config_path = "/etc/mail/sendmail.cf"  # 설정 파일 경로 변수화
    result = "양호"  # 기본 결과를 양호로 설정

    smtp_service = subprocess.getoutput("ps -ef | grep sendmail | grep -v grep")
    if smtp_service:
        log("1. SMTP 서비스 사용 (sendmail): 예")

        if os.path.exists(sendmail_config_path) and os.access(sendmail_config_path, os.R_OK):
            # PrivacyOptions 설정 확인 (주석 제외, 공백 유연하게 처리)
            privacy_options_line = subprocess.getoutput(
                f"grep -i '^\\s*PrivacyOptions\\s*=' {sendmail_config_path} | grep -v '^#'"
            )
            if privacy_options_line:
                privacy_options = privacy_options_line.split("=")[1].strip().lower()

                noexpn = "noexpn" in privacy_options
                novrfy = "novrfy" in privacy_options
                goaway = "goaway" in privacy_options

                log(f"2. PrivacyOptions 설정: {privacy_options_line.strip()}")
                log(f"   - noexpn 옵션 설정: {'예' if noexpn else '아니오'}")
                log(f"   - novrfy 옵션 설정: {'예' if novrfy else '아니오'}")
                log(f"   - goaway 옵션 설정: {'예' if goaway else '아니오'}")

                if not (noexpn and novrfy) and not goaway:
                    result = "취약"
            else:
                log(f"2. PrivacyOptions 설정이 {sendmail_config_path} 파일에 없습니다.")
                result = "취약"
        else:
            log(f"2. {sendmail_config_path} 파일에 접근할 수 없습니다.")
            result = "N/A"
    else:
        log("1. SMTP 서비스 사용 (sendmail): 아니오")
        result = "양호"

    log(f"결론: {result}")
    log("")

# SRV-006: SMTP 서비스 로그 수준 설정 미흡
def SRV_006():
    log("[SRV-006] SMTP 서비스 로그 수준 설정 미흡")
    log("")

    smtp_services = ["sendmail", "postfix", "exim"]  # 점검할 SMTP 서비스 목록
    for service in smtp_services:
        smtp_process = subprocess.getoutput(f"ps -ef | grep {service} | grep -v grep")
        if smtp_process:
            log(f"- {service.upper()} 서비스 실행: 예")

            # 로그 파일 위치 확인 (sendmail, exim)
            if service == "sendmail" or service == "exim":
                config_file_path = f"/etc/mail/{service}.cf"  # sendmail, exim 설정 파일 경로
                if os.path.exists(config_file_path) and os.access(config_file_path, os.R_OK):
                    log_file_output = subprocess.getoutput(
                        f"grep -E '^[^#]*LogFile' {config_file_path}"
                    )
                    if log_file_output:
                        log_file = log_file_output.split()[-1]
                        log(f"  - 로그 파일 위치: {log_file}")
                    else:
                        log("  - 로그 파일 위치: 설정되지 않음")

                    # 로그 로테이션 설정 확인 (sendmail, exim)
                    log_rotation_output = subprocess.getoutput(
                        f"grep -E '^[^#]*LogRotation' {config_file_path}"
                    )
                    if log_rotation_output:
                        log(f"  - 로그 로테이션 설정: {log_rotation_output}")
                    else:
                        log("  - 로그 로테이션 설정: 설정되지 않음")

                else:
                    log(f"  - 설정 파일({config_file_path}) 접근 불가")

            # LogLevel 설정 확인 (sendmail)
            if service == "sendmail":
                log_level_output = subprocess.getoutput(
                    "grep 'LogLevel' /etc/mail/sendmail.cf"
                )
                if log_level_output.startswith("#"):
                    log("  - LogLevel 설정: 주석 처리됨 (미설정)")
                    result = "취약"
                else:
                    try:
                        log_level = int(log_level_output.split()[-1])
                        if log_level >= 9:
                            log(f"  - LogLevel 설정: {log_level} (양호)")
                            result = "양호"
                        else:
                            log(f"  - LogLevel 설정: {log_level} (취약)")
                            result = "취약"
                    except ValueError:
                        log("  - LogLevel 설정: 숫자 값 파싱 오류")
                        result = "취약"

            # postfix 로그 수준 확인
            elif service == "postfix":
                # postfix는 syslog를 통해 로그를 관리
                # /etc/rsyslog.conf 또는 /etc/syslog.conf 에서 mail 관련 설정 확인
                try:
                    syslog_config = subprocess.check_output(
                        "grep -R 'mail' /etc/rsyslog.conf /etc/syslog.conf", shell=True
                    ).decode("utf-8")
                    if "mail.info" in syslog_config or "mail.debug" in syslog_config:
                        log("  - 로그 수준: info 또는 debug 이상 (양호)")
                        result = "양호"
                    else:
                        log("  - 로그 수준: info 또는 debug 이상으로 설정되지 않음 (취약)")
                        result = "취약"
                except subprocess.CalledProcessError:
                    log("  - 로그 설정 확인 중 오류 발생")
                    result = "N/A"

            # exim 로그 수준 확인
            elif service == "exim":
                config_file_path = "/etc/exim4/exim4.conf.template"  # exim 설정 파일 (데비안 계열)
                if os.path.exists(config_file_path) and os.access(config_file_path, os.R_OK):
                    log_selector_output = subprocess.getoutput(
                        f"grep -i '^\\s*log_selector' {config_file_path} | grep -v '^#'"
                    )
                    if log_selector_output:
                        log_selector = log_selector_output.split("=")[-1].strip()
                        if "+all" in log_selector.lower():
                            log(f"  - log_selector 설정: +all (양호)")
                            result = "양호"
                        else:
                            log(
                                f"  - log_selector 설정: {log_selector} (취약: +all 설정 권장)"
                            )
                            result = "취약"
                    else:
                        log("  - log_selector 설정: 찾을 수 없음")
                        result = "취약"
                else:
                    log(f"  - 설정 파일({config_file_path}) 접근 불가")
                    result = "N/A"
            
            log(f"  - 결론: {result}")
            log("")

        else:
            log(f"- {service.upper()} 서비스 실행: 아니오")
            log("")

# SRV-007: 취약한 버전의 SMTP 서비스 사용
def SRV_007():
    log("[SRV-007] 취약한 버전의 SMTP 서비스 사용")
    log("")

    smtp_services = {
        "sendmail": {
            "process_name": "sendmail",
            "version_command": "sendmail -d0.1 | grep -i version",
            "min_version": "8.14.9"
        },
        "postfix": {
            "process_name": "master",  # postfix는 master 프로세스로 확인
            "version_command": "postconf -d mail_version | awk -F'=' '{print $2}'",  # 버전만 추출
            "min_versions": {
                "2": "2.5.13",
                "3": "3.0.0"  # 예시: 3.x 버전은 3.0.0 이상으로 가정
            }
        },
        "exim": {
            "process_name": "exim",
            "version_command": "exim -bV | grep -i version",
            "min_version": "4.94.2"
        }
    }

    result = "양호"
    vulnerable_services = []

    for service, info in smtp_services.items():
        process_name = info["process_name"]
        version_command = info["version_command"]

        try:
            smtp_process = subprocess.check_output(
                f"ps -ef | grep {process_name} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            smtp_process = ""

        if smtp_process:
            log(f"- {service.upper()} 서비스 실행: 예")
            try:
                version_output = subprocess.check_output(
                    version_command, shell=True
                ).decode("utf-8").strip()
                
                if version_output:
                    # 버전 정보 정제
                    if service == "sendmail":
                        # Sendmail 버전 형식: "Version 8.14.9" 또는 "Compiled with: 8.14.9"
                        match = re.search(r"Version (\d+\.\d+\.\d+)", version_output, re.IGNORECASE) or \
                                re.search(r"Compiled with: (\d+\.\d+\.\d+)", version_output, re.IGNORECASE)
                        version = match.group(1) if match else None
                    elif service == "postfix":
                        # Postfix 버전 형식: "3.8.5"
                        version = version_output.split("=")[-1].strip()
                    elif service == "exim":
                        # Exim 버전 형식: "Exim version 4.94.2 #2 built"
                        match = re.search(r"Exim version (\d+\.\d+\.\d+)", version_output, re.IGNORECASE)
                        version = match.group(1) if match else None
                    
                    if version:
                        log(f"  - {service.upper()} 버전: {version}")

                        # 버전 비교
                        if service == "postfix":
                            major_version = version.split(".")[0]
                            if major_version in info["min_versions"]:
                                min_version = info["min_versions"][major_version]
                            else:
                                min_version = None  # 해당 major 버전에 대한 최소 버전 정보가 없는 경우
                        else:
                            min_version = info["min_version"]

                        if min_version and version < min_version:
                            log(f"  - {service.upper()} 버전이 취약합니다 (최소 버전: {min_version}).")
                            result = "취약"
                            vulnerable_services.append(service.upper())
                        else:
                            log(f"  - {service.upper()} 버전은 양호합니다.")
                    else:
                        log(f"  - {service.upper()} 버전 정보를 파싱할 수 없습니다.")
                        result = "취약"  # 버전 정보를 확인할 수 없는 경우 취약으로 간주
                        vulnerable_services.append(service.upper())
                else:
                    log(f"  - {service.upper()} 버전 확인 불가")
                    result = "취약" # 버전 정보를 확인할 수 없는 경우 취약으로 간주
                    vulnerable_services.append(service.upper())

            except subprocess.CalledProcessError:
                log(f"  - {service.upper()} 버전 확인 중 오류 발생")
                result = "N/A"  # 오류 발생 시 N/A로 설정
        else:
            log(f"- {service.upper()} 서비스 실행: 아니오")

        log("")

    if result == "취약":
        exp = f"취약한 버전의 SMTP 서비스 사용: {', '.join(vulnerable_services)}"
    elif result == "N/A":
        exp = f"SMTP 서비스 버전 확인 중 오류 발생"
    else:
        exp = "모든 SMTP 서비스가 안전한 버전을 사용 중이거나 실행 중이지 않습니다."

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log("")

# SRV-008: SMTP 서비스의 DoS 방지 기능 미설정
def SRV_008():
    log("[SRV-008] SMTP 서비스의 DoS 방지 기능 미설정")
    log("")

    smtp_services = {
        "sendmail": {
            "process_name": "sendmail",
            "config_file": "/etc/mail/sendmail.cf",
            "dos_protection_settings": {
                "ConnectionRateThrottle": None,  # 값 없음
                "MaxDaemonChildren": None,  # 값 없음
                "MinFreeBlocks": None,  # 값 없음
                "MaxHeadersLength": None, # 값 없음
                "MaxMessageSize": None,  # 값 없음
            },
        },
        "postfix": {
            "process_name": "master",
            "config_file": "/etc/postfix/main.cf",
            "dos_protection_settings": {
                "smtpd_client_connection_rate_limit": None,
                "smtpd_client_message_rate_limit": None,
                "smtpd_recipient_restrictions": "permit_mynetworks, reject_unauth_destination",
            },
        },
        "exim": {
            "process_name": "exim",
            "config_file": "/etc/exim4/exim4.conf.template",  # 데비안 계열
            "dos_protection_settings": {
                "smtp_accept_max": None,
                "smtp_accept_queue": None,
                "smtp_delay_reject": "true",  # 이 설정은 값이 true/false로 설정
            },
        },
    }

    overall_result = "양호"  # 전체 결과 변수
    overall_exp = []

    for service, info in smtp_services.items():
        process_name = info["process_name"]
        config_file = info["config_file"]
        dos_protection_settings = info["dos_protection_settings"]
        service_result = "양호"
        
        try:
            smtp_process = subprocess.check_output(
                f"ps -ef | grep {process_name} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            smtp_process = ""

        if smtp_process:
            log(f"- {service.upper()} 서비스 실행: 예")
            if config_file and os.path.exists(config_file) and os.access(config_file, os.R_OK):
                try:
                    with open(config_file, "r") as f:
                        config_content = f.read()

                    for setting_name, default_value in dos_protection_settings.items():
                        if service == "sendmail":
                            # Sendmail 설정 확인 (예: ConnectionRateThrottle)
                            pattern = rf"^\s*{setting_name}\s*=?\s*(\w+)"
                        elif service == "postfix":
                            # Postfix 설정 확인 (예: smtpd_client_connection_rate_limit)
                            pattern = rf"^\s*{setting_name}\s*=\s*(.*)"
                        elif service == "exim":
                            # Exim 설정 확인 (예: smtp_accept_max)
                            pattern = rf"^\s*{setting_name}\s*=\s*(.*)"
                        else:
                            pattern = rf"^\s*{setting_name}\s*=?\s*(\w+)"
                        
                        match = re.search(pattern, config_content, re.MULTILINE | re.IGNORECASE)

                        if match:
                            dos_protection_settings[setting_name] = match.group(1).strip()
                        else:
                            dos_protection_settings[setting_name] = "미설정"

                        if service == "exim" and setting_name == "smtp_delay_reject":
                            if match and match.group(1).strip().lower() == "true":
                                dos_protection_settings[setting_name] = "true"  # 정상적인 설정
                            else:
                                dos_protection_settings[setting_name] = "미설정" # 값이 없거나 false
                                service_result = "취약"
                        elif dos_protection_settings[setting_name] == "미설정":
                            service_result = "취약"

                    log(f"  - {service.upper()} DoS 방지 설정:")
                    for setting_name, value in dos_protection_settings.items():
                        if value == "미설정":
                            log(f"    - {setting_name}: {value}")
                        
                    if service_result == "취약":
                         overall_result = "취약"
                         overall_exp.append(f"{service.upper()} 서비스 DoS 방지 설정 미흡")

                except Exception as e:
                    log(f"  - {service.upper()} 설정 파일 읽기 오류: {e}")
                    service_result = "N/A"
                    overall_result = "N/A"
                    overall_exp.append(f"{service.upper()} 설정 파일 읽기 오류")

            else:
                log(f"  - {service.upper()} 설정 파일({config_file}) 미발견 또는 접근 불가")
                service_result = "N/A"
                overall_result = "N/A"
                overall_exp.append(f"{service.upper()} 설정 파일 미발견 또는 접근 불가")
            
            log(f"  - {service.upper()} 서비스 점검 결과: {service_result}")

        else:
            log(f"- {service.upper()} 서비스 실행: 아니오")

        log("")

    # 최종 결과 출력
    if overall_result == "취약":
        log(f"결론: {overall_result}")
        log(f"설명: {', '.join(overall_exp)}")
    elif overall_result == "N/A":
        log(f"결론: {overall_result}")
        log(f"설명: {', '.join(overall_exp)}")
    else:
        log(f"결론: {overall_result}")
        log("설명: 모든 SMTP 서비스에 DoS 방지 기능이 설정되었거나 실행 중이지 않습니다.")
    log("")

# SRV-009: SMTP 서비스 스팸 메일 릴레이 제한 미설정
def SRV_009():
    log("[SRV-009] SMTP 서비스 스팸 메일 릴레이 제한 미설정")
    log("")

    smtp_services = {
        "sendmail": {
            "process_name": "sendmail",
            "config_file": "/etc/mail/sendmail.cf",
            "relay_check_pattern": r"R\$\*\s+.*Relaying\s+denied",
        },
        "postfix": {
            "process_name": "master",
            "config_file": "/etc/postfix/main.cf",
            "relay_check_setting": "smtpd_relay_restrictions",
        },
        "exim": {
            "process_name": "exim",
            "config_file": "/etc/exim/exim.conf",
            "relay_check_pattern": r"deny\s+message\s*=\s*Relay\s+not\s+permitted",
        },
    }

    overall_result = True  # 1. 초기값을 True로 변경
    overall_exp = []

    for service, info in smtp_services.items():
        process_name = info["process_name"]
        config_file = info.get("config_file")
        relay_check_pattern = info.get("relay_check_pattern")
        relay_check_setting = info.get("relay_check_setting")

        try:
            smtp_process = subprocess.check_output(
                f"ps -ef | grep {process_name} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            smtp_process = ""

        if smtp_process:
            log(f"- {service.upper()} 서비스 실행: 예")
            service_result = False  # 1. 서비스 실행 중일 때는 기본적으로 False(취약)으로 설정

            if config_file and os.path.exists(config_file) and os.access(config_file, os.R_OK):
                try:
                    with open(config_file, "r") as f:
                        config_content = f.read()

                    if service == "sendmail":
                        if relay_check_pattern and re.search(
                            relay_check_pattern, config_content, re.IGNORECASE
                        ):
                            log("  - 릴레이 제한 설정: 예")
                            service_result = True
                        else:
                            log("  - 릴레이 제한 설정: 아니오")

                    elif service == "postfix":
                        if relay_check_setting:
                            match = re.search(
                                rf"^\s*{relay_check_setting}\s*=\s*(.*)",
                                config_content,
                                re.MULTILINE | re.IGNORECASE,
                            )
                            if match:
                                settings = match.group(1).strip()
                                if (
                                    "permit_mynetworks" in settings
                                    and "reject_unauth_destination" in settings
                                ):
                                    log("  - 릴레이 제한 설정: 예")
                                    service_result = True
                                else:
                                    log("  - 릴레이 제한 설정: 아니오 (permit_mynetworks, reject_unauth_destination 설정 필요)")
                            else:
                                log(f"  - {relay_check_setting} 설정: 찾을 수 없음")
                    elif service == "exim":
                        if relay_check_pattern and re.search(
                            relay_check_pattern, config_content, re.IGNORECASE
                        ):
                            log("  - 릴레이 제한 설정: 예")
                            service_result = True
                        else:
                            log("  - 릴레이 제한 설정: 아니오")
                    else:
                        log(f"  - {service} 서비스는 릴레이 제한 설정 확인을 지원하지 않습니다.")
                        service_result = None # N/A

                except Exception as e:
                    log(f"  - {service.upper()} 설정 파일 읽기 오류: {e}")
                    service_result = None # N/A
            else:
                log(f"  - {service.upper()} 설정 파일({config_file}) 미발견 또는 접근 불가")
                service_result = None # N/A

            log(f"  - {service.upper()} 서비스 점검 결과: {'양호' if service_result else '취약' if service_result == False else 'N/A'}")

            # 2. overall_result 및 overall_exp 업데이트
            overall_result = overall_result and service_result

            if not service_result and f"{service.upper()} 서비스 릴레이 제한 미설정" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 릴레이 제한 미설정")
            elif service_result == None and f"{service.upper()} 서비스 릴레이 제한 설정 확인 불가" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 릴레이 제한 설정 확인 불가")

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
        log("설명: 모든 SMTP 서비스에 릴레이 제한이 설정되었거나 실행 중이지 않습니다.")
    log("")

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

    # 최종 결과 출력
    if overall_result == "취약":
        log(f"결론: {overall_result}")
        log(f"설명: {', '.join(overall_exp)}")
    elif overall_result == "N/A":
        log(f"결론: {overall_result}")
        log(f"설명: {', '.join(overall_exp)}")
    else:
        log(f"결론: {overall_result}")
        log("설명: 모든 FTP 서비스에 root 계정 FTP 접속 제한이 적절히 설정되었거나 실행 중이지 않습니다.")
    log("")

    log("참고: SFTP, SCP 등 다른 파일 전송 프로토콜을 사용하는 경우, 해당 프로토콜의 root 계정 접속 제한 설정도 확인해야 합니다.")
    log("")

# SRV-012: .netrc 파일 내 중요 정보 노출
def SRV_012():
    log("[SRV-012] .netrc 파일 내 중요 정보 노출")
    log("")

    vulnerable_files = []
    error_occurred = False  # 2. 오류 발생 여부 변수 추가

    try:
        # find 명령어 실행 결과에서 각 줄의 끝에 있는 파일 경로만 추출
        netrc_files = [
            line.split()[-1]
            for line in subprocess.check_output(
                "find / -xdev -name .netrc -ls 2>/dev/null", shell=True
            )
            .decode("utf-8")
            .splitlines()
        ]

        if netrc_files:
            log("결과:")
            for filename in netrc_files:
                try:
                    # 파일 권한 확인
                    st = os.stat(filename)
                    permissions = oct(st.st_mode & 0o777)[2:]

                    # 파일 소유자 확인
                    owner_id = st.st_uid
                    owner_name = subprocess.check_output(f"id -nu {owner_id}", shell=True).decode("utf-8").strip()

                    if (
                        st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                        or permissions != "600"
                        or owner_name != "root"
                    ):
                        log(f"  - {filename}: 권한={permissions}, 소유자={owner_name} (취약)")
                        vulnerable_files.append(filename)

                        # 3. .netrc 파일 내용 확인 (예시)
                        with open(filename, "r") as f:
                            content = f.read()
                            if "machine" in content and "login" in content and "password" in content:
                                log(f"    - {filename} 파일에 민감한 정보(machine, login, password) 포함 (취약)")

                except Exception as e:
                    log(f"  - {filename} 파일 확인 오류: {e}")
                    error_occurred = True  # 2. 오류 발생 여부 기록
        else:
            log("결과: 양호 (.netrc 파일 없음)")

    except subprocess.CalledProcessError as e:
        log(f"  - .netrc 파일 검색 중 오류 발생: {e}")
        error_occurred = True  # 2. 오류 발생 여부 기록

    # 최종 결과 출력
    # 1. result 변수 대신 vulnerable_files 리스트 사용
    if vulnerable_files:
        log("결론: 취약")
        log(f"설명: 취약한 .netrc 파일 발견: {', '.join(vulnerable_files)}")
    elif error_occurred:  # 2. 오류 발생 여부 확인
        log("결론: N/A")
        log("설명: .netrc 파일 확인 중 오류 발생")
    else:
        log("결론: 양호")
        log("설명: 모든 .netrc 파일이 안전하거나 발견되지 않았습니다.")
    log("")

    log("참고: .netrc 파일에는 FTP 계정이 평문으로 저장되기 때문에 사용하지 않을 것을 권고합니다.")
    log("")

# SRV-013: Anonymous 계정의 FTP 서비스 접속 제한 미비
def SRV_013():
    log("[SRV-013] Anonymous 계정의 FTP 서비스 접속 제한 미비")
    log("")

    ftp_services = {
        "proftpd": {
            "process_name": "proftpd",
            "config_file": "/etc/proftpd/proftpd.conf",
            "anonymous_check_pattern": r"^\s*<Anonymous",
        },
        "vsftpd": {
            "process_name": "vsftpd",
            "config_file": "/etc/vsftpd/vsftpd.conf",
            "anonymous_check_setting": "anonymous_enable",
            "anonymous_check_value": "NO",
        },
    }

    overall_result = True  # 1. 초기값을 True로 변경
    overall_exp = []

    for service, info in ftp_services.items():
        process_name = info["process_name"]
        config_file = info.get("config_file")
        anonymous_check_pattern = info.get("anonymous_check_pattern")
        anonymous_check_setting = info.get("anonymous_check_setting")
        anonymous_check_value = info.get("anonymous_check_value")

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

                    if service == "proftpd":
                        if anonymous_check_pattern and re.search(
                            anonymous_check_pattern, config_content, re.IGNORECASE
                        ):
                            log("  - Anonymous 계정 활성화: 예 (취약)")
                        else:
                            log("  - Anonymous 계정 활성화: 아니오 (양호)")
                            service_result = True

                    elif service == "vsftpd":
                        if anonymous_check_setting:
                            match = re.search(
                                rf"^\s*{anonymous_check_setting}\s*=\s*({anonymous_check_value})",
                                config_content,
                                re.MULTILINE | re.IGNORECASE,
                            )
                            if match:
                                log(f"  - {anonymous_check_setting} 설정: {match.group(1)} (양호)")
                                service_result = True
                            else:
                                log(f"  - {anonymous_check_setting} 설정: YES 또는 미설정 (취약)")
                    else:
                        log(f"  - {service} 서비스는 Anonymous 계정 확인을 지원하지 않습니다.")
                        service_result = None  # N/A

                except Exception as e:
                    log(f"  - {service.upper()} 설정 파일 읽기 오류: {e}")
                    service_result = None  # N/A
            else:
                log(f"  - {service.upper()} 설정 파일({config_file}) 미발견 또는 접근 불가")
                service_result = None  # N/A

            log(f"  - {service.upper()} 서비스 점검 결과: {'양호' if service_result else '취약' if service_result == False else 'N/A'}")

            # 2. overall_result 및 overall_exp 업데이트
            overall_result = overall_result and service_result

            if service_result == False and f"{service.upper()} 서비스 Anonymous 계정 접속 제한 미흡" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 Anonymous 계정 접속 제한 미흡")
            elif service_result == None and f"{service.upper()} 서비스 Anonymous 계정 접속 제한 확인 불가" not in overall_exp:
                overall_exp.append(f"{service.upper()} 서비스 Anonymous 계정 접속 제한 확인 불가")

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
        log("설명: 모든 FTP 서비스에 Anonymous 계정 접속 제한이 적절히 설정되었거나 실행 중이지 않습니다.")
    log("")

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

# SRV-015: 불필요한 NFS 서비스 실행
def SRV_015():
    log("[SRV-015] 불필요한 NFS 서비스 실행")
    log("")

    try:
        nfs_process = subprocess.check_output(
            "ps -ef | grep nfsd | grep -v grep", shell=True  # nfsd 프로세스 확인
        ).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        nfs_process = ""

    if nfs_process:
        log("결과: 취약 (NFS 서비스 실행 중)")
        log(f"  - NFS 프로세스:\n{nfs_process}")
        log("  - NFS 서비스를 중지하고, 불필요한 경우 비활성화해야 합니다.")
        log("  - (예) systemctl stop nfs-server && systemctl disable nfs-server") # 시스템에 맞는 명령어로 수정 필요
    else:
        log("결과: 양호 (NFS 서비스 미사용)")

    log("")

# SRV-016: 불필요한 RPC 서비스 활성화
def SRV_016():
    log("[SRV-016] 불필요한 RPC 서비스 활성화")
    log("")

    rpc_services = [
        "rpc.cmsd", "rusersd", "rstatd", "kcms_server", # 1. rpc.statd 제거 또는 주석 처리
        "rpc.ttdbserverd", "rpc.walld", "rpc.nisd", "rpc.ypupdated",
        "cachefsd", "sadmind", "rpc.sprayd", "rpc.pcnfsd", "rpc.rexd",
        "rpc.rquotad"
    ]  # 1. rpc. 접두사 통일

    active_rpc_services = set()  # 2. set으로 변경하여 중복 제거
    for service in rpc_services:
        # 1. inetd.conf 확인
        try:
            inetd_status = subprocess.check_output(
                f"grep -v '^#' /etc/inetd.conf | grep '{service}'", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            inetd_status = ""

        if inetd_status:
            active_rpc_services.add(service)  # 2. add() 사용
            continue

        # 2. xinetd.d 디렉터리 확인
        try:
            xinetd_status = subprocess.check_output(
                f"grep -r '^\\s*service\\s*{service}' /etc/xinetd.d/ | grep -v disable.*yes", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            xinetd_status = ""

        if xinetd_status:
            active_rpc_services.add(service)  # 2. add() 사용
            continue

        # 3. systemd 서비스 확인
        try:
            # 3. systemctl is-active 명령어 반환 코드 확인
            subprocess.check_call(
                f"systemctl is-active --quiet {service}", shell=True
            )
            systemd_status = "active"  # check_call()은 오류가 없으면 0을 반환
        except subprocess.CalledProcessError:
            systemd_status = ""

        if systemd_status == "active":
            active_rpc_services.add(service)  # 2. add() 사용
            continue  # systemd에서 발견되면 프로세스 확인 건너뜀

        # 4. 프로세스 확인
        try:
            process_status = subprocess.check_output(
                f"ps -ef | grep {service} | grep -v grep", shell=True
            ).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            process_status = ""

        if process_status:
            active_rpc_services.add(service)  # 2. add() 사용

    # 결과 출력
    if active_rpc_services:
        log("결과: 취약 (활성화된 불필요한 RPC 서비스 발견)")
        for service in active_rpc_services:
            log(f"  - {service}")
        log("  - 불필요한 RPC 서비스를 비활성화해야 합니다.")
        log("  - (예) systemctl stop <service> && systemctl disable <service>")
        log("  - (예) /etc/inetd.conf 또는 /etc/xinetd.d/<service> 파일에서 해당 서비스 비활성화")
    else:
        log("결과: 양호 (불필요한 RPC 서비스 미활성화)")
    log("")

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

# SRV-022: 계정의 비밀번호 미설정, 빈 암호 사용 관리 미흡
def SRV_022():
    log("[SRV-022] 계정의 비밀번호 미설정, 빈 암호 사용 관리 미흡")
    log("")

    vulnerable_accounts = set()  # 1. 중복 제거를 위해 set 사용
    error_occurred = False

    try:
        # 1. /etc/shells 파일에서 유효한 쉘 목록 가져오기
        if os.path.exists("/etc/shells"):
            with open("/etc/shells", "r") as f:
                valid_shells = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith("#")
                ]
        else:
            valid_shells = ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"]

        # 2. 쉘 권한이 있는 계정 목록 가져오기
        try:
            accounts_with_shell = {
                line.split(":")[0]: line.split(":")[6]
                for line in subprocess.check_output(
                    ["cat", "/etc/passwd"], stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .splitlines()
                if line.split(":")[6] in valid_shells
            }
        except subprocess.CalledProcessError as e:
            log(f"  - /etc/passwd 파일 처리 중 오류 발생: {e}")
            accounts_with_shell = {}
            error_occurred = True

        # 3. 비밀번호가 없거나 비어 있는 계정 확인
        try:
            empty_password_accounts = [
                line.split(":")[0]
                for line in subprocess.check_output(
                    ["cat", "/etc/shadow"], stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .splitlines()
                if not line.split(":")[1]
                or line.split(":")[1] in ["", "!", "*", "x", "!!"]
            ]

            # 2. pwck 명령어 사용 (추가)
            try:
                subprocess.check_call(["pwck", "-r", "/etc/passwd", "/etc/shadow"])
            except subprocess.CalledProcessError as e:
                log(f"  - pwck 명령어 실행 중 오류 발생: {e}")
                error_occurred = True
            
        except subprocess.CalledProcessError as e:
            log(f"  - /etc/shadow 파일 처리 중 오류 발생: {e}")
            empty_password_accounts = []
            error_occurred = True

        # 4. 쉘 권한이 있고 비밀번호가 없는 계정 확인
        for account, shell in accounts_with_shell.items():
            if account in empty_password_accounts:
                vulnerable_accounts.add((account, shell))  # 1. add() 사용

    except Exception as e:
        log(f"  - 계정 확인 중 오류 발생: {e}")
        error_occurred = True

    # 결과 출력
    if vulnerable_accounts:
        log("결과: 취약 (비밀번호 미설정 또는 빈 암호 계정 발견)")
        for account, shell in vulnerable_accounts:
            log(f"  - 계정: {account}, 쉘: {shell}")

            # 3. passwd -S 명령어 사용 (추가)
            try:
                passwd_status = subprocess.check_output(
                    ["passwd", "-S", account], stderr=subprocess.DEVNULL
                ).decode("utf-8").strip()
                log(f"    - {account} 계정 상태: {passwd_status}")
            except subprocess.CalledProcessError as e:
                log(f"    - {account} 계정 상태 확인 중 오류 발생: {e}")
                error_occurred = True

    elif error_occurred:
        log("결과: N/A")
        log("설명: 계정 확인 중 오류 발생")
    else:
        log("결과: 양호 (비밀번호 미설정 또는 빈 암호 계정 없음)")
    log("")

# SRV-025: 취약한 hosts.equiv 또는 .rhosts 설정 존재
def SRV_025():
    log("[SRV-025] 취약한 hosts.equiv 또는 .rhosts 설정 존재")
    log("")

    def check_file(filepath):
        if os.path.isfile(filepath):
            log(f"- {filepath}:")
            try:
                # 파일 권한 확인
                st = os.stat(filepath)
                permissions = oct(st.st_mode & 0o777)[2:]
                owner_id = st.st_uid
                group_id = st.st_gid

                # 사용자 및 그룹 이름 확인
                owner_name = subprocess.check_output(f"id -nu {owner_id}", shell=True).decode("utf-8").strip()
                group_name = subprocess.check_output(f"id -ng {group_id}", shell=True).decode("utf-8").strip()

                log(f"  - 권한: {permissions} (소유자: {owner_name}, 그룹: {group_name})")

                # .rhosts 파일인 경우, 소유자 및 그룹 확인
                if os.path.basename(filepath) == ".rhosts":
                    if owner_name != os.path.basename(os.path.dirname(filepath)):
                        log(f"    - 소유자가 일치하지 않습니다 (취약)")
                        return "취약"
                    if group_name != "root" and group_name != owner_name:
                        log(f"    - 그룹이 적절하지 않습니다 (취약)")
                        return "취약"

                # 권한 확인 (600만 허용)
                if permissions != "600":
                    log(f"    - 권한이 적절하지 않습니다 (취약)")
                    return "취약"

                # 파일 내용 확인
                with open(filepath, "r") as f:
                    content = f.read()
                
                # '+' 설정 확인
                if re.search(r"^\s*\+[\s$]*", content, re.MULTILINE) or re.search(r"^\s*\S+\s*\+[\s$]*", content, re.MULTILINE):
                    log("  - '+' 설정 존재 (취약)")
                    return "취약"
                else:
                    log("  - '+' 설정 없음 (양호)")
                    return "양호"

            except subprocess.CalledProcessError as e:
                log(f"  - 파일 처리 중 오류 발생: {e}")
                return "N/A"
            except Exception as e:
                log(f"  - 파일 확인 오류: {e}")
                return "N/A"
        else:
            log(f"- {filepath}: 없음 (양호)")
            return "양호"

    results = {
        "/etc/hosts.equiv": check_file("/etc/hosts.equiv"),
    }

    # 홈 디렉터리 내 .rhosts 파일 확인
    try:
        homedirs = subprocess.check_output(
            "awk -F: '($7 != \"/usr/sbin/nologin\" && $7 != \"/bin/false\") {print $6}' /etc/passwd", shell=True
        ).decode("utf-8").splitlines()
    except subprocess.CalledProcessError as e:
        log(f"  - 사용자 홈 디렉터리 확인 중 오류 발생: {e}")
        homedirs = []

    for homedir in homedirs:
        rhosts_file = os.path.join(homedir, ".rhosts")
        results[rhosts_file] = check_file(rhosts_file)

    # 결과 출력
    all_good = all(result == "양호" for result in results.values())
    log("결과:", "양호" if all_good else "취약")
    for file, result in results.items():
        if result != "양호" and result != "N/A":
            log(f"  - {file}: {result}")
    log("")

# SRV-026: root 계정 원격 접속 제한 미비
def SRV_026():
    log("[SRV-026] root 계정 원격 접속 제한 미비")
    log("")

    try:
        ssh_process = subprocess.check_output(
            "ps -ef | grep sshd | grep -v grep", shell=True
        ).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        ssh_process = ""

    if ssh_process:
        log("1. SSH 서비스 실행: 예")

        # SSH 포트 상태 확인 (22번 포트)
        try:
            ssh_port_status = subprocess.check_output(
                "netstat -an | grep :22 | grep LISTEN", shell=True
            ).decode("utf-8").strip()
            if ssh_port_status:
                log(f"  - SSH 포트 상태: 열림 ({ssh_port_status.split()[3]})")
            else:
                log("  - SSH 포트 상태: 닫힘")
        except subprocess.CalledProcessError:
            log("  - SSH 포트 상태 확인 중 오류 발생")

        # PermitRootLogin 설정 확인
        permit_root_login_result = "취약"  # 기본값을 취약으로 설정
        try:
            # 2. 주석 처리되지 않은 PermitRootLogin 설정 확인
            permit_root_login = subprocess.check_output(
                "grep -E '^[^#]*PermitRootLogin' /etc/ssh/sshd_config", shell=True
            ).decode("utf-8").strip()
            if permit_root_login:
                if re.search(r"^PermitRootLogin\s+no", permit_root_login, re.IGNORECASE):
                    log("  - PermitRootLogin 설정: no (양호)")
                    permit_root_login_result = "양호"
                elif re.search(r"^PermitRootLogin\s+prohibit-password", permit_root_login, re.IGNORECASE):
                    log("  - PermitRootLogin 설정: prohibit-password (양호)")
                    permit_root_login_result = "양호"
                elif re.search(r"^PermitRootLogin\s+without-password", permit_root_login, re.IGNORECASE):
                    log("  - PermitRootLogin 설정: without-password (양호)")
                    permit_root_login_result = "양호"
                elif re.search(r"^PermitRootLogin\s+forced-commands-only", permit_root_login, re.IGNORECASE):
                    log("  - PermitRootLogin 설정: forced-commands-only (양호)")
                    permit_root_login_result = "양호"
                else:
                    log("  - PermitRootLogin 설정: yes 또는 기타 (취약)")
            else:
                log("  - PermitRootLogin 설정: 미설정 (취약)")
        except subprocess.CalledProcessError:
            log("  - PermitRootLogin 설정 확인 중 오류 발생")

        # /etc/security/user 파일에서 rlogin 설정 확인 (AIX 시스템)
        security_user_result = "N/A"  # 기본값을 N/A로 설정
        if platform.system() == "AIX":  # 3. AIX 시스템인지 확인
            try:
                # 3. awk 명령어 사용
                rlogin_setting = subprocess.check_output(
                    "awk -F: '$1 == \"root\" {getline; print}' /etc/security/user | grep rlogin", shell=True
                ).decode("utf-8").strip()
                if rlogin_setting:
                    if "false" in rlogin_setting.lower():
                        log("  - rlogin 설정: false (양호)")
                        security_user_result = "양호"
                    else:
                        log("  - rlogin 설정: true (취약)")
                        security_user_result = "취약"
                else:
                    log("  - rlogin 설정: 미설정 (정보)")
                    security_user_result = "정보"
            except subprocess.CalledProcessError:
                log("  - rlogin 설정 확인 중 오류 발생")
        else:
            log("  - AIX 시스템이 아니므로 rlogin 설정 확인 건너뜀")

        # 종합적인 결과 판단
        if permit_root_login_result == "양호" and security_user_result == "양호":
            result = "양호"
        elif security_user_result == "N/A":
            result = permit_root_login_result
        else:
            result = "취약"

        # 5. 최종 결과 출력 개선
        log(f"  - SSH 서비스 점검 결과: {result} (PermitRootLogin: {permit_root_login_result}, rlogin: {security_user_result})")

    else:
        log("1. SSH 서비스 실행: 아니오")
        result = "양호"

    log(f"결론: {result}")
    log("")

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

# SRV-028: 원격 터미널 접속 타임아웃 미설정
def SRV_028():
    log("[SRV-028] 원격 터미널 접속 타임아웃 미설정")
    log("")

    max_timeout = 600  # 최대 타임아웃 값 (초)

    profile_result = "미설정"
    profile_timeout = None
    csh_login_result = "미설정"
    csh_login_timeout = None

    # /etc/profile 파일 확인
    if os.path.exists("/etc/profile"):
        try:
            # TMOUT 설정값 추출
            result = subprocess.check_output(
                f"grep -i '^TMOUT' /etc/profile | grep -v '^#'", shell=True
            ).decode("utf-8").strip()

            if result:
                try:
                    profile_timeout = int(result.split()[-1])

                    if profile_timeout == 0:
                        profile_result = "설정됨(0, 즉시)"
                    elif profile_timeout <= max_timeout:
                        profile_result = "양호"
                    else:
                        profile_result = "취약"
                except (ValueError, IndexError):
                    profile_result = "오류 (타임아웃 값 확인 불가)"
                    profile_timeout = result  # 오류 메시지에 설정값 포함
            else:
                profile_result = "미설정"
        except subprocess.CalledProcessError as e:
            log(f"  - /etc/profile 파일 처리 중 오류 발생: {e}")
            profile_result = "오류"
    else:
        log("  - /etc/profile 파일이 존재하지 않습니다.")
        profile_result = "파일 없음"

    # /etc/csh.login 파일 확인
    if os.path.exists("/etc/csh.login"):
        try:
            # autologout 설정값 추출 (csh, tcsh)
            result = subprocess.check_output(
                f"grep -i '^\\s*set\\s+autologout' /etc/csh.login | grep -v '^\\s*#'", shell=True
            ).decode("utf-8").strip()

            if result:
                try:
                    csh_login_timeout = int(result.split("=")[-1].strip()) * 60  # 분 단위를 초 단위로 변환
                    if csh_login_timeout == 0:
                        csh_login_result = "설정됨(0, 즉시)"
                    elif csh_login_timeout <= max_timeout:
                        csh_login_result = "양호"
                    else:
                        csh_login_result = "취약"
                except (ValueError, IndexError):
                    csh_login_result = "오류 (타임아웃 값 확인 불가)"
                    csh_login_timeout = result
            else:
                csh_login_result = "미설정"
        except subprocess.CalledProcessError as e:
            log(f"  - /etc/csh.login 파일 처리 중 오류 발생: {e}")
            csh_login_result = "오류"
    else:
        log("  - /etc/csh.login 파일이 존재하지 않습니다.")
        csh_login_result = "파일 없음"

    # 결과 출력
    log("- /etc/profile:")
    if profile_result == "오류":
        log(f"  - TMOUT 설정: {profile_result} ({profile_timeout})")
    elif profile_result == "파일 없음":
        log("  - /etc/profile 파일이 존재하지 않습니다.")
    elif profile_result == "미설정":
        log(f"  - TMOUT 설정: {profile_result}")
    else:
        log(f"  - TMOUT 설정: {profile_result} ({profile_timeout if profile_timeout is not None else ''}초)")

    log("- /etc/csh.login:")
    if csh_login_result == "오류":
        log(f"  - autologout 설정: {csh_login_result} ({csh_login_timeout})")
    elif csh_login_result == "파일 없음":
        log("  - /etc/csh.login 파일이 존재하지 않습니다.")
    elif csh_login_result == "미설정":
        log(f"  - autologout 설정: {csh_login_result}")
    else:
        log(f"  - autologout 설정: {csh_login_result} ({csh_login_timeout if csh_login_timeout is not None else ''}초)")

    # 최종 결과 판단
    if profile_result == "양호" or csh_login_result == "양호":
        result = "양호"
    elif profile_result == "파일 없음" and csh_login_result == "파일 없음":
        result = "취약"
    elif profile_result == "미설정" and csh_login_result == "미설정":
        result = "취약"
    else:
        result = "취약"

    log(f"결론: {result}")
    log("")

# SRV-034: 불필요한 서비스 활성화
def SRV_034():
    log("[SRV-034] 불필요한 automount 서비스 실행")
    log("")

    try:
        # 1. systemctl 사용 및 오류 처리
        autofs_status = subprocess.check_output(
            "systemctl is-active autofs", shell=True, stderr=subprocess.DEVNULL
        ).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        autofs_status = "unknown"  # systemctl 명령어 오류 발생 시 unknown으로 설정

    if autofs_status == "active":
        log("결과: 취약 (autofs 서비스 활성화)")
        try:
            # automount 프로세스 정보 가져오기
            automount_service = subprocess.check_output(
                "ps -ef | grep -i 'automount' | grep -v 'grep'", shell=True
            ).decode("utf-8").strip()
            log(automount_service)
        except subprocess.CalledProcessError as e:
            log(f"  - automount 프로세스 정보 확인 중 오류 발생: {e}")
    else:
        log("결과: 양호 (autofs 서비스 비활성화)")
    log("")

# SRV-035: 취약한 서비스 활성화
def SRV_035():
    log("[SRV-035] 취약한 서비스 활성화")
    log("")

    r_services = ["rsh", "rcp", "rlogin", "rexec"]
    active_r_services = set()

    # r 명령어 관련 프로세스, inetd.conf, xinetd.d, systemd 서비스 확인
    for service in r_services:
        try:
            # 프로세스 확인
            process = subprocess.check_output(
                f"ps -ef | grep -i '{service}' | grep -v grep", shell=True
            ).decode("utf-8").strip()
            if process:
                active_r_services.add(service)
                continue  # 프로세스에서 발견되면 다른 방법 확인 건너뜀

            # inetd.conf 확인
            inetd_conf = subprocess.check_output(
                f"grep -E '^{service}\\s' /etc/inetd.conf | grep -v '^#'",
                shell=True,
            ).decode("utf-8").strip()
            if inetd_conf:
                active_r_services.add(service)
                continue

            # xinetd.d 확인
            xinetd_service = subprocess.check_output(
                f"grep -r '^\\s*service\\s*{service}' /etc/xinetd.d/ | grep -v 'disable\\s*=\\s*yes'",
                shell=True,
            ).decode("utf-8").strip()
            if xinetd_service:
                active_r_services.add(service)
                continue

            # systemd 확인
            subprocess.check_call(
                f"systemctl is-active --quiet {service}", shell=True
            )
            active_r_services.add(service)

        except subprocess.CalledProcessError:
            pass

    # /etc/hosts.equiv 파일 확인
    hosts_equiv_vulnerable = False
    try:
        if os.path.isfile("/etc/hosts.equiv"):
            log("  - /etc/hosts.equiv 파일 존재 (주의)")
            with open("/etc/hosts.equiv", "r") as f:
                content = f.read()
                # 개선: '+' 설정 및 특정 호스트/사용자 허용 여부 확인
                if re.search(r"^\s*\+[\s$]*", content, re.MULTILINE) or re.search(r"^\s*\S+\s*\+[\s$]*", content, re.MULTILINE):
                    log("    - /etc/hosts.equiv 파일에 취약한 '+' 설정 존재 (취약)")
                    hosts_equiv_vulnerable = True
                else:
                    log("    - /etc/hosts.equiv 파일에 취약한 '+' 설정은 없으나, 추가 확인 필요")  # 추가 확인 로직 필요
        else:
            log("  - /etc/hosts.equiv 파일 없음")
    except Exception as e:
        log(f"  - /etc/hosts.equiv 파일 확인 중 오류 발생: {e}")

    # ~/.rhosts 파일 확인
    rhosts_vulnerable = False
    try:
        rhosts_files = subprocess.check_output(
            "find /home -name .rhosts 2>/dev/null", shell=True
        ).decode("utf-8").splitlines()
        if rhosts_files:
            log("  - .rhosts 파일 존재:")
            for file in rhosts_files:
                log(f"    - {file}")
                with open(file, "r") as f:
                    content = f.read()
                    # 개선: '+' 설정 및 특정 호스트/사용자 허용 여부 확인
                    if re.search(r"^\s*\+[\s$]*", content, re.MULTILINE) or re.search(r"^\s*\S+\s*\+[\s$]*", content, re.MULTILINE):
                        log(f"      - {file} 파일에 취약한 '+' 설정 존재 (취약)")
                        rhosts_vulnerable = True
                    else:
                        log(f"      - {file} 파일에 취약한 '+' 설정은 없으나, 추가 확인 필요")  # 추가 확인 로직 필요
        else:
            log("  - .rhosts 파일 없음")
    except subprocess.CalledProcessError as e:
        log(f"  - .rhosts 파일 확인 중 오류 발생: {e}")

    # 결과 출력
    if active_r_services or hosts_equiv_vulnerable or rhosts_vulnerable:
        log("결과: 취약")
        if active_r_services:
            log("  - 활성화된 r 서비스:")
            for service in active_r_services:
                log(f"    - {service}")
            log("    - r 서비스 비활성화 방법:")
            log("      - (systemd) systemctl stop <service> && systemctl disable <service>")
            log("      - (inetd) /etc/inetd.conf 파일에서 해당 서비스 주석 처리 후 inetd 재시작")
            log("      - (xinetd) /etc/xinetd.d/<service> 파일에서 disable = yes 설정 후 xinetd 재시작")
        if hosts_equiv_vulnerable:
            log("  - /etc/hosts.equiv 파일에 취약한 설정 존재")
        if rhosts_vulnerable:
            log("  - 취약한 .rhosts 파일 존재")
    else:
        log("결과: 양호 (취약한 서비스 미활성화)")
    log("")

# SRV-037: 불필요한 FTP 서비스 실행
def SRV_037():
    log("[SRV-037] 불필요한 FTP 서비스 실행")
    log("")

    ftp_services = {
        "proftpd": {
            "process_name": "proftpd",
        },
        "vsftpd": {
            "process_name": "vsftpd",
        },
    }

    for service_name, info in ftp_services.items():
        process_name = info["process_name"]
        try:
            ftp_process = subprocess.check_output(
                f"ps -ef | grep -i '{process_name}' | grep -v grep", shell=True
            ).decode("utf-8").strip()
            
            if ftp_process:
                log(f"결과: 취약 ({service_name.upper()} 서비스 실행 중)")
                log(f"  - 프로세스 정보:")
                for line in ftp_process.splitlines():
                    log(f"    - {line.strip()}")
                log("  - 불필요한 FTP 서비스를 중지하고, 비활성화해야 합니다.")
                log(f"  - (예) systemctl stop {process_name} && systemctl disable {process_name}")  # 시스템에 맞는 명령어로 수정 필요
            else:
                log(f"결과: 양호 ({service_name.upper()} 서비스 미사용)")
        except subprocess.CalledProcessError as e:
            log(f"  - {service_name.upper()} 서비스 확인 중 오류 발생: {e}")
            log(f"결과: N/A ({service_name.upper()} 서비스 확인 불가)")

    log("")

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

# SRV-044: 웹 서비스 파일 업로드 및 다운로드 용량 제한 미설정
def SRV_044(apache_check, httpd_conf):
    log("[SRV-044] 웹 서비스 파일 업로드 및 다운로드 용량 제한 미설정")
    log("")

    # LimitRequestBody 설정 기준값 (5MB)
    limit_request_body_threshold = 5242880

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

    limit_request_body_result = "미설정"
    limit_request_line_result = "미설정"
    limit_request_field_size_result = "미설정"

    try:
        # LimitRequestBody 설정 확인
        limit_request_body_values = []
        limit_request_body_matches = re.findall(
            r"^\s*LimitRequestBody\s+(\d+)", httpd_conf_content, re.MULTILINE | re.IGNORECASE
        )
        for match in limit_request_body_matches:
            limit_request_body_values.append(int(match))

        if limit_request_body_values:
            log("  - LimitRequestBody 설정:")
            for value in limit_request_body_values:
                log(f"    - {value} 바이트")

            min_limit_request_body = min(limit_request_body_values)

            if min_limit_request_body == 0:
                limit_request_body_result = "취약 (무제한)"
            elif min_limit_request_body <= limit_request_body_threshold:
                limit_request_body_result = "양호"
            else:
                limit_request_body_result = "취약"
        else:
            limit_request_body_result = "미설정"

        # LimitRequestLine 설정 확인
        limit_request_line_values = []
        limit_request_line_matches = re.findall(
            r"^\s*LimitRequestLine\s+(\d+)", httpd_conf_content, re.MULTILINE | re.IGNORECASE
        )

        for match in limit_request_line_matches:
            limit_request_line_values.append(int(match))

        if limit_request_line_values:
            log("  - LimitRequestLine 설정:")
            for value in limit_request_line_values:
                log(f"    - {value} 바이트")
            limit_request_line_result = "확인"
        else:
            limit_request_line_result = "미설정"

        # LimitRequestFieldSize 설정 확인
        limit_request_field_size_values = []
        limit_request_field_size_matches = re.findall(
            r"^\s*LimitRequestFieldSize\s+(\d+)", httpd_conf_content, re.MULTILINE | re.IGNORECASE
        )

        for match in limit_request_field_size_matches:
            limit_request_field_size_values.append(int(match))

        if limit_request_field_size_values:
            log("  - LimitRequestFieldSize 설정:")
            for value in limit_request_field_size_values:
                log(f"    - {value} 바이트")
            limit_request_field_size_result = "확인"
        else:
            limit_request_field_size_result = "미설정"

        # 결과 요약 (개선)
        log("  - 결과 요약:")
        log(f"    - LimitRequestBody: {limit_request_body_result}")
        log(f"    - LimitRequestLine: {limit_request_line_result}")
        log(f"    - LimitRequestFieldSize: {limit_request_field_size_result}")

        # 최종 결과 판단
        if limit_request_body_result == "취약":
            log("결과: 취약 (LimitRequestBody 설정 미흡)")
        elif limit_request_body_result == "양호" and limit_request_line_result != "미설정" and limit_request_field_size_result != "미설정":
            log("결과: 양호 (파일 업로드 및 다운로드 용량 제한 설정 확인)")
        else:
            log("결과: 취약 (파일 업로드 및 다운로드 용량 제한 설정 미흡)")

    except Exception as e:
        log(f"  - 설정 확인 중 오류 발생: {e}")
        log("결과: N/A")

    log("")

# SRV-045: 웹 서비스 프로세스 권한 제한 미비
def SRV_045(APACHE_CHECK):
    log("[SRV-045] 웹 서비스 프로세스 권한 제한 미비")
    log("")

    if APACHE_CHECK == "OFF":
        log("결과: 양호 (Apache 서비스 미사용)")
    else:
        processes = subprocess.getoutput("ps -ef | grep -i 'httpd' | grep -v grep").splitlines()
        root_processes = [p for p in processes if p.split()[0] == "root"]
        if root_processes:
            log("결과: 취약 (root 권한으로 실행되는 Apache 프로세스 발견)")
            for p in root_processes:
                log(f"  - {p}")
        else:
            log("결과: 양호 (root 권한으로 실행되는 Apache 프로세스 없음)")
    log("")

# SRV-046: 웹 서비스 경로 설정 미흡
def SRV_046(APACHE_CHECK, HTTPD_CONF):
    log("[SRV-046] 웹 서비스 경로 설정 미흡")
    log(">>>SRV-046 Vuln Check !!!")
    log("")

    if APACHE_CHECK == "OFF":
        log("결과: 양호 (Apache 서비스 미사용)")
    else:
        vulnerable_paths = ["/usr/local/apache/htdocs", "/usr/local/apache2/htdocs", "/var/www/html"]
        document_root = subprocess.getoutput(
            f"grep -v '^#' {HTTPD_CONF} | grep 'DocumentRoot' | awk -F' ' '{{print $2}}' | sed 's/\"//g'"
        )

        if document_root in vulnerable_paths:
            log(f"결과: 취약 (DocumentRoot: {document_root})")
        else:
            log(f"결과: 양호 (DocumentRoot: {document_root})")
    log("")

# SRV-047: 웹 서비스 경로 내 불필요한 링크 파일 존재
def SRV_047(APACHE_CHECK, HTTPD_CONF):
    log("[SRV-047] 웹 서비스 경로 내 불필요한 링크 파일 존재")
    log(">>>SRV_047 Vuln Check !!!")
    log("")

    if APACHE_CHECK == "OFF":
        log("결과: 양호 (Apache 서비스 미사용)")
    else:
        follow_symlinks_option = subprocess.getoutput(
            f"grep -v '^#' {HTTPD_CONF} | grep -E 'Options\\s+.*FollowSymLinks'"
        )
        if follow_symlinks_option:
            log("결과: 취약 (FollowSymLinks 옵션 활성화)")
            log(follow_symlinks_option)
        else:
            log("결과: 양호 (FollowSymLinks 옵션 비활성화 또는 미설정)")
    log("")

# SRV-048: 불필요한 웹 서비스 실행
def SRV_048(APACHE_CHECK):
    log("[SRV-048] 불필요한 웹 서비스 실행")
    log(">>>SRV-048 Vuln Check !!!")  # 오타 수정: SRV-039 -> SRV-048
    log("")

    webtob_service = subprocess.getoutput("ps -ef | grep 'webtob' | grep -v 'grep'")
    if webtob_service:
        log("결과: 취약 (Tmax WebtoB 서비스 실행 중)")
        log(webtob_service)
    else:
        log("결과: 양호 (Tmax WebtoB 서비스 미사용)")
    log("")

# SRV-060: 웹 서비스 기본 계정(아이디 또는 비밀번호) 미변경
def SRV_060(APACHE_CHECK):
    log("[SRV-060] 웹 서비스 기본 계정(아이디 또는 비밀번호) 미변경")
    log(">>>SRV-060 Vuln Check !!!")
    log("")

    if APACHE_CHECK == "OFF":
        log("결과: 양호 (Apache 서비스 미사용)")
    else:
        tomcat_users_files = subprocess.getoutput("find / -xdev -type f -name tomcat-users.xml").splitlines()
        if tomcat_users_files:
            for file in tomcat_users_files:
                log(f"- {file}:")
                with open(file, "r") as f:
                    content = f.read()

                # 주석 처리되지 않은 <user> 태그 검색
                user_tags = re.findall(r"<user\s+username=\"([^\"]+)\"\s+password=\"([^\"]+)\"\s+roles=\"([^\"]+)\"\s*/>", content)

                vulnerable_users = [
                    user
                    for user in user_tags
                    if user[0] in ["tomcat", "both", "role1"] and user[1] == "tomcat"
                ]

                if vulnerable_users:
                    log("  - 결과: 취약 (기본 계정 미변경)")
                    for user in vulnerable_users:
                        log(f"    - username: {user[0]}, roles: {user[2]}")
                else:
                    log("  - 결과: 양호 (기본 계정 변경됨)")
        else:
            log("결과: 양호 (tomcat-users.xml 파일 없음)")
    log("")

# SRV-062: DNS 서비스 정보 노출
def SRV_062():
    log("[SRV-062] DNS 서비스 정보 노출")
    log(">>>SRV-062 Vuln Check !!!")
    log("")

    named_process = subprocess.getoutput("ps -ef | grep named | grep -v grep")
    if named_process:
        log("1. DNS 서비스 실행: 예")
        named_conf_output = subprocess.getoutput("grep -E '^[^#]*version' /etc/named.conf")  # 주석 제외
        if named_conf_output:
            if "version" in named_conf_output:
                log("2. BIND 버전 정보 노출 설정: 예 (양호)")
                result = "양호"
            else:
                log("2. BIND 버전 정보 노출 설정: 아니오 (취약)")
                result = "취약"
        else:
            log("2. BIND 버전 정보 노출 설정: 미설정 (취약)")
            result = "취약"
    else:
        log("1. DNS 서비스 실행: 아니오")
        result = "양호"

    log(f"결론: {result}")
    log("")

# SRV-063: DNS Recursive Query 설정 미흡
def SRV_063():
    log("[SRV-063] DNS Recursive Query 설정 미흡")
    log(">>>SRV-063 Vuln Check !!!")
    log("")

    named_process = subprocess.getoutput("ps -ef | grep named | grep -v grep")
    if named_process:
        log("1. DNS 서비스 실행: 예")
        named_conf_output = subprocess.getoutput(
            "grep -E '^[^#]*recursion' /etc/named.conf"
        )  # 주석 제외하고 recursion 설정 검색
        if named_conf_output:
            if "no" in named_conf_output.lower():
                log("2. recursion 설정: no (양호)")
                result = "양호"
            else:
                log("2. recursion 설정: yes (취약)")
                result = "취약"
        else:
            log("2. recursion 설정: 미설정 (취약)")  # 설정이 아예 없는 경우도 취약
            result = "취약"
    else:
        log("1. DNS 서비스 실행: 아니오")
        result = "양호"

    log(f"결론: {result}")
    log("")

# SRV-064: 취약한 버전의 DNS 서비스 사용
def SRV_064():
    log("[SRV-064] 취약한 버전의 DNS 서비스 사용")
    log(">>>SRV-064 Vuln Check !!!")
    log("")

    named_process = subprocess.getoutput("ps -ef | grep named | grep -v grep")
    if named_process:
        log("1. DNS 서비스 실행: 예")
        named_version_output = subprocess.getoutput("named -v")
        if named_version_output:
            log(f"2. BIND 버전: {named_version_output}")
            result = "취약"  # 버전 정보 노출 자체가 취약점
        else:
            log("2. BIND 버전 정보 확인 불가")
            result = "확인 불가"
    else:
        log("1. DNS 서비스 실행: 아니오")
        result = "양호"

    log(f"결론: {result}")
    log("참고: DNS 서비스 사용 시 최신 버전 유지 및 보안 패치 적용이 중요합니다.")  # 패치 관리 중요성 강조
    log("")

# SRV-066: DNS Zone Transfer 설정 미흡
def SRV_066():
    log("[SRV-066] DNS Zone Transfer 설정 미흡")
    log(">>>SRV-066 Vuln Check !!!")
    log("")

    named_process = subprocess.getoutput("ps -ef | grep named | grep -v grep")
    if named_process:
        log("1. DNS 서비스 실행: 예")

        # Zone Transfer 설정 파일 확인 (named.conf 및 named.boot)
        zone_transfer_settings = []
        for config_file in ["/etc/named.conf", "/etc/named.boot"]:
            if os.path.isfile(config_file):
                with open(config_file, "r") as f:
                    content = f.read()
                if re.search(r"allow-transfer\s*{[^}]*}", content) or re.search(r"xfrnets\s*{[^}]*}", content):
                    zone_transfer_settings.append(config_file)

        if zone_transfer_settings:
            log("결과: 취약 (Zone Transfer 설정 발견)")
            for file in zone_transfer_settings:
                log(f"  - {file}")
        else:
            log("결과: 양호 (Zone Transfer 설정 없음)")
    else:
        log("1. DNS 서비스 실행: 아니오")
        log("결과: 양호")

    log("")

# SRV-069: 비밀번호 관리정책 설정 미비
def log_to_file(log_file, message):
    with open(log_file, 'a') as f:
        f.write(message + "\n")

def check_file_exists(file_path):
    return os.path.isfile(file_path)

def grep_file(file_path, patterns):
    with open(file_path, 'r') as f:
        lines = f.readlines()
        return [line.strip() for line in lines if any(pattern in line for pattern in patterns)]

def check_login_defs(log_file):
    if check_file_exists('/etc/login.defs'):
        log_to_file(log_file, " -> /etc/login.defs 파일")
        results = grep_file('/etc/login.defs', ["PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE"])
        for line in results:
            log_to_file(log_file, line)
    else:
        log_to_file(log_file, "/etc/login.defs 파일이 없습니다.")
    log_to_file(log_file, " ")

def check_system_auth(log_file):
    if check_file_exists('/etc/pam.d/system-auth'):
        log_to_file(log_file, " -> /etc/pam.d/system-auth 파일")
        results = grep_file('/etc/pam.d/system-auth', ["pam_cracklib.so"])
        for line in results:
            log_to_file(log_file, line)
        if not results:
            results = grep_file('/etc/pam.d/system-auth', ["pam_pwquality.so"])
            for line in results:
                log_to_file(log_file, line)
    else:
        log_to_file(log_file, "/etc/pam.d/system-auth 파일이 없습니다.")
    log_to_file(log_file, " ")

def check_pwquality_conf(log_file):
    if check_file_exists('/etc/security/pwquality.conf'):
        log_to_file(log_file, " -> /etc/security/pwquality.conf 파일")
        results = grep_file('/etc/security/pwquality.conf', ["minlen", "dcredit", "ucredit", "lcredit", "ocredit", "minclass"])
        for line in results:
            log_to_file(log_file, line)
    else:
        log_to_file(log_file, "/etc/security/pwquality.conf 파일이 없습니다.")
    log_to_file(log_file, " ")

def check_debian_common_password(log_file):
    log_to_file(log_file, "2. DEB기반 시스템(Debian 등)")
    log_to_file(log_file, "----------------------------------------------------------------------------------------")
    if check_file_exists('/etc/pam.d/common-password'):
        with open('/etc/pam.d/common-password', 'r') as f:
            log_to_file(log_file, f.read())
    else:
        log_to_file(log_file, "/etc/pam.d/common-password 파일이 없습니다.")
    log_to_file(log_file, " ")

def SRV_069():
    log_file = "./password_policy_check.log"
    log_to_file(log_file, "[SRV-069] 비밀번호 관리정책 설정 미비")
    log_to_file(log_file, ">>>SRV-069 Vuln Check !!!")
    log_to_file(log_file, "")
    log_to_file(log_file, "결과 : ")
    
    check_login_defs(log_file)
    check_system_auth(log_file)
    check_pwquality_conf(log_file)
    check_debian_common_password(log_file)
    
    log_to_file(log_file, "")
    log("")
    log(f"비밀번호 정책 점검 결과가 {log_file} 파일에 저장되었습니다.")
    log("")

# SRV-070: 취약한 패스워드 저장 방식 사용
def SRV_070():
    log("[SRV-070] 취약한 패스워드 저장 방식 사용")
    log(">>>SRV-070 Vuln Check !!!")
    log("")

    shadow_path = "/etc/shadow"
    passwd_path = "/etc/passwd"

    # 1. /etc/shadow 파일 존재 여부 확인
    if os.path.isfile(shadow_path):
        log("결과: 양호 (/etc/shadow 파일 존재)")
        return  # shadow 파일이 존재하면 더 이상 검사할 필요 없음

    # 2. /etc/passwd 파일 존재 여부 확인 (shadow 파일이 없을 경우에만)
    if not os.path.isfile(passwd_path):
        log("결과: 오류 (/etc/passwd 파일을 찾을 수 없음)")
        return

    # 3. /etc/passwd 파일 내 암호화되지 않은 패스워드 검색
    try:
        with open(passwd_path, "r") as f:
            for line in f:
                if not line.startswith("#"):  # 주석 제외
                    if ":" in line:
                        _, password_hash = line.split(":", 1)  # 콜론(:)을 기준으로 사용자 이름과 패스워드 해시 분리
                        if not password_hash.startswith("$"):  # 암호화되지 않은 패스워드 해시 형식은 '$'로 시작하지 않음
                            log("결과: 취약 (/etc/passwd 내 패스워드 평문 저장)")
                            return
            log("결과: 양호 (/etc/passwd 내 패스워드 암호화 저장)")
    except PermissionError:
        log("결과: 오류 (/etc/passwd 파일에 대한 읽기 권한 없음)")
    log("")

# SRV-073: 관리자 그룹에 불필요한 사용자 존재
def SRV_073():
    log("[SRV-073] 관리자 그룹에 불필요한 사용자 존재")
    log(">>>SRV-073 Vuln Check !!!")
    log("")

    try:
        group_output = subprocess.getoutput("getent group root")
        if group_output:
            _, _, _, members_str = group_output.split(":")
            members = members_str.split(",") if members_str else []
            if set(members) == {"root"}:
                log("결과: 양호 (root 그룹에 root 사용자만 존재)")
            else:
                log("결과: 취약 (root 그룹에 불필요한 사용자 존재)")
                for member in members:
                    if member != "root":
                        log(f"   - {member}")
        else:
            log("결과: 양호 (root 그룹에 사용자 없음)")
    except Exception as e:  # 예외 처리 추가
        log(f"결과: 오류 (root 그룹 정보 가져오기 실패): {e}")
    log("")

# SRV-074: 불필요하거나 관리되지 않는 계정 존재
def SRV_074():
    log("[SRV-074] 불필요하거나 관리되지 않는 계정 존재")
    log(">>>SRV-074 Vuln Check !!!")
    log("")
    log("결과 :")

    # /etc/shadow 파일에서 만료되지 않는 계정 확인
    non_expiring_accounts = subprocess.getoutput(
        "awk -F: '($2 != \"*\" && $2 != \"!!\" && $7 != \"/usr/sbin/nologin\" && $7 != \"/bin/false\") {print $1}' /etc/shadow"
    ).splitlines()

    if non_expiring_accounts:
        log("취약 (만료되지 않는 계정 발견):")
        for account in non_expiring_accounts:
            log(f"  - {account}")
    else:
        log("양호 (만료되지 않는 계정 없음)")

    log("")

# SRV-075: 유추 가능한 계정 비밀번호 존재
def SRV_075():
    log("[SRV-075] 유추 가능한 계정 비밀번호 존재")
    log(">>>SRV-075 Vuln Check !!!")
    log("")

    # 결과 출력 함수
    def print_result(log_file):
        if os.path.isfile('/etc/shadow'):
            weak_passwords = subprocess.getoutput(
                "cat /etc/shadow | awk -F: '($2 != \"!!\" && $2 != \"*\") {print $1 \":\" $2}' | grep -v -E '^[^:]+:\\$[1-6]\\$.+'"  # 암호화되지 않은 패스워드 검색
            )
            if weak_passwords:
                log("결과: 취약 (유추 가능한 계정 비밀번호 존재)", log_file)
                log(weak_passwords, log_file)
                result = "취약"
            else:
                log("결과: 양호 (유추 가능한 계정 비밀번호 없음)", log_file)
                result = "양호"
        else:
            log("결과: 확인 불가 (/etc/shadow 파일 없음)", log_file)
            result = "확인 불가"

        log("", log_file)
        log("참고: 시스템의 모든 계정이 비밀번호 복잡도를 만족하는지 확인해야 합니다.", log_file)
        log("※ 복잡도: 영문 숫자 특수문자 2개 조합 시 10자리 이상, 3개 조합 시 8자리 이상 (계정명, 기관명이 포함된 경우 취약)", log_file)
        log("", log_file)

        return result  # 결과 반환

    result = print_result(filename)
    log(f"결과 : {result}")  # 콘솔에 결과 출력
    log("")

# SRV-081: Crontab 설정파일 권한 설정 미흡
def SRV_081():
    log("[SRV-081] Crontab 설정파일 권한 설정 미흡")
    log(">>>SRV-081 Vuln Check !!!")
    log("")
    log("결과 :")
    log("")

    crontab_issues = []
    at_issues = []
    cron_allow_deny_issues = []

    # /var/spool/cron 디렉토리 및 파일 권한 확인
    if os.path.isdir("/var/spool/cron"):
        crontab_files = subprocess.getoutput("ls -l /var/spool/cron/* 2>/dev/null").splitlines()
        log("▶ crontab 파일 접근권한")
        for file_info in crontab_files:
            if not file_info.startswith("total"):  # total 라인 제외
                filename = file_info.split()[-1]
                permissions = file_info.split()[0]
                owner = file_info.split()[2]
                group = file_info.split()[3]

                log(f" - {permissions} {owner}/{group} {filename}")

                if not (permissions.startswith("-rw-------") and (owner == "root" or owner == "daemon")):
                    crontab_issues.append(f"/var/spool/cron/{filename} 파일 권한 부적절")
    else:
        crontab_issues.append("/var/spool/cron 디렉토리 존재하지 않음")

    # /etc/crontab 파일 권한 확인
    if os.path.isfile("/etc/crontab"):
        log("▶ /etc/crontab 파일 권한")
        file_info = subprocess.getoutput("ls -l /etc/crontab")
        permissions = file_info.split()[0]
        owner = file_info.split()[2]
        group = file_info.split()[3]
        log(f" - {permissions} {owner}/{group} /etc/crontab")

        if not (permissions.startswith("-rw-------") and (owner == "root" or owner == "daemon")):
            crontab_issues.append("/etc/crontab 파일 권한 부적절")
    else:
        crontab_issues.append("/etc/crontab 파일 존재하지 않음")

    log("")

    # at.deny 및 at.allow 파일 접근권한 확인
    log("▶ at.deny 및 at.allow 파일 접근권한")
    for at_file in ["/etc/at.deny", "/etc/at.allow"]:
        if os.path.isfile(at_file):
            file_info = subprocess.getoutput(f"ls -l {at_file}")
            permissions = file_info.split()[0]
            owner = file_info.split()[2]
            group = file_info.split()[3]
            log(f" - {permissions} {owner}/{group} {at_file}")

            if not (permissions.startswith("-rw-------") and owner == "root"):
                at_issues.append(f"{at_file} 파일 권한 부적절")
        else:
            at_issues.append(f"{at_file} 파일 존재하지 않음")
        log("")

    # cron.allow 및 cron.deny 파일 접근권한 확인
    log("▶ cron.allow 및 cron.deny 파일 접근권한")
    for cron_file in ["/etc/cron.deny", "/etc/cron.allow"]:
        if os.path.isfile(cron_file):
            file_info = subprocess.getoutput(f"ls -l {cron_file}")
            permissions = file_info.split()[0]
            owner = file_info.split()[2]
            group = file_info.split()[3]
            log(f" - {permissions} {owner}/{group} {cron_file}")

            if not (permissions.startswith("-rw-------") and owner == "root"):
                cron_allow_deny_issues.append(f"{cron_file} 파일 권한 부적절")
        else:
            cron_allow_deny_issues.append(f"{cron_file} 파일 존재하지 않음")

    # 결과 종합 및 출력
    if crontab_issues or at_issues or cron_allow_deny_issues:
        log("결과: 취약")
        if crontab_issues:
            log("  - crontab 관련:")
            for issue in crontab_issues:
                log(f"    - {issue}")
        if at_issues:
            log("  - at 관련:")
            for issue in at_issues:
                log(f"    - {issue}")
        if cron_allow_deny_issues:
            log("  - cron.allow/cron.deny 관련:")
            for issue in cron_allow_deny_issues:
                log(f"    - {issue}")
    else:
        log("결과: 양호")
    log("")

# SRV-082: 시스템 주요 디렉터리 권한 설정 미흡
def SRV_082():
    log("[SRV-082] 시스템 주요 디렉터리 권한 설정 미흡")
    log(">>>SRV-082 Vuln Check !!!")
    log("")

    dirs = ["/usr", "/bin", "/sbin", "/etc", "/var"]
    vulnerable_dirs = []  # 취약한 디렉터리 목록

    # 시스템 디렉터리 접근 권한 확인
    log("▶ 시스템 디렉토리 접근 권한 확인:")
    for dir in dirs:
        permissions = subprocess.getoutput(f"stat -L -c '%a %A' {dir}").split()
        log(f"  - {dir}: {permissions[0]} ({permissions[1]})")
        if "w" in permissions[1].lower():
            vulnerable_dirs.append(dir)

    # 링크 디렉토리 및 원본 디렉토리 접근 권한 확인
    log("▶ 링크 및 원본 디렉토리 접근 권한 확인:")
    link_dirs = subprocess.getoutput(f"ls -ld {' '.join(dirs)} | grep '^l' | awk '{{print $11}}'").read().splitlines()
    for link_dir in link_dirs:
        original_dir = os.path.realpath(link_dir)  # 링크의 실제 경로 확인
        permissions = subprocess.getoutput(f"stat -c '%a %A' {original_dir}").split()
        log(f"  - {link_dir} -> {original_dir}: {permissions[0]} ({permissions[1]})")
        if "w" in permissions[1].lower():
            vulnerable_dirs.append(link_dir)

    # 결과 출력
    if vulnerable_dirs:
        log("결과: 취약 (Others에 쓰기 권한이 있는 디렉터리 발견)")
        for dir in vulnerable_dirs:
            log(f"  - {dir}")
    else:
        log("결과: 양호(Others에 쓰기 권한이 있는 디렉터리 없음)")
    log("")

# SRV-083: 시스템 스타트업 스크립트 권한 설정 미흡
def SRV_083():
    log("[SRV-083] 시스템 스타트업 스크립트 권한 설정 미흡")
    log(">>>SRV-083 Vuln Check !!!")
    log("")

    vulnerable_files = []

    # /etc/rc*.d 디렉토리 내 파일 및 심볼릭 링크 확인
    rc_dir_output = subprocess.getoutput("find /etc/rc*.d -type f -o -type l 2>/dev/null")
    if rc_dir_output:
        for file in rc_dir_output.splitlines():
            permissions = subprocess.getoutput(f"stat -L -c '%a %A' {file}").split()
            log(f"- {file}: {permissions[0]} ({permissions[1]})")
            if "w" in permissions[1].lower():  # Others 쓰기 권한 확인
                vulnerable_files.append(file)

    # /etc/inittab 파일 확인 (만약 존재한다면)
    if os.path.isfile("/etc/inittab"):
        inittab_perm = subprocess.getoutput("stat -L -c '%a %A' /etc/inittab").split()
        log(f"- /etc/inittab: {inittab_perm[0]} ({inittab_perm[1]})")
        if "w" in inittab_perm[1].lower():
            vulnerable_files.append("/etc/inittab")

    # 결과 출력
    if vulnerable_files:
        log("결과: 취약 (Others에 쓰기 권한이 있는 파일 발견)")
        for file in vulnerable_files:
            log(f"  - {file}")
    else:
        log("결과: 양호 (Others에 쓰기 권한이 있는 파일 없음)")
    log("")

# SRV-084: 시스템 주요 파일 권한 설정 미흡
def SRV_084():
    log("[SRV-084] 시스템 주요 파일 권한 설정 미흡")
    log(">>>SRV-084 Vuln Check !!!")
    log("")
    log("결과 :")

    files = {
        "/etc/passwd": {"pattern": "^...-.--.--.*(root|bin).*", "description": "소유자가 root 또는 bin이고 그룹 및 Others에 쓰기/실행 권한이 없는 경우"},
        "/etc/shadow": {"pattern": "^...-------.*(root|bin).*", "description": "소유자가 root 또는 bin이고 접근권한이 소유자에게 읽기/쓰기 권한만 존재하는 경우"},
        "/etc/group": {"pattern": "^...-.--.--.*(root|bin).*", "description": "소유자가 root 또는 bin이고 그룹 및 Others에 쓰기/실행 권한이 없는 경우"},
        "/etc/gshadow": {"pattern": "^...-------.*(root|bin).*", "description": "소유자가 root 또는 bin이고 접근권한이 소유자에게 읽기/쓰기 권한만 존재하는 경우"},
        "/etc/hosts": {"pattern": "^...-.--.--.*(root|bin).*", "description": "소유자가 root 또는 bin이고 그룹 및 Others에 쓰기/실행 권한이 없는 경우"},
        "/etc/xinetd.conf": {"pattern": "^...-------.*(root|bin).*", "description": "소유자가 root 또는 bin이고 소유자에게만 읽기/쓰기 권한이 존재하는 경우"},
        "/etc/inetd.conf": {"pattern": "^...-.--.--.*(root|bin).*", "description": "소유자가 root 또는 bin이고 그룹 및 Others에 쓰기/실행 권한이 없는 경우"},
        "/etc/syslog.conf": {"pattern": "^...-.--.--.*(root|bin).*", "description": "소유자가 root 또는 bin이고 그룹 및 Others에 쓰기/실행 권한이 없는 경우"},
        "/etc/syslog-ng/syslog-ng.conf": {"pattern": "^...-.--.--.*(root|bin).*", "description": "소유자가 root 또는 bin이고 그룹 및 Others에 쓰기/실행 권한이 없는 경우"},
        "/etc/services": {"pattern": "^...-.--.--.*(root|bin).*", "description": "소유자가 root 또는 bin이고 그룹 및 Others에 쓰기/실행 권한이 없는 경우"},
        "/etc/hosts.lpd": {"pattern": "^...-.-----.*(root|bin).*", "description": "소유자가 root 또는 bin이고 소유그룹의 쓰기 권한 및 Others에 접근권한이 없는 경우"},
    }

    vulnerable_files = []

    for file, info in files.items():
        if os.path.isfile(file):
            result = subprocess.getoutput(f"ls -l {file} | grep -E '{info['pattern']}' | wc -l")
            if int(result) == 0:
                vulnerable_files.append(file)

            log(f"▶ {file}:")
            log(subprocess.getoutput(f"stat -L -c '%a %A %U %G %n' {file}"))

            if int(result) > 0:
                log(f"  - {info['description']} (양호)")
            else:
                log(f"  - {info['description']} (취약)")
        else:
            if file in ["/etc/shadow", "/etc/passwd", "/etc/group", "/etc/gshadow"]:  # 필수 파일 확인
                vulnerable_files.append(file)
                log(f"▶ {file} 파일이 존재하지 않음 (취약)")  # 명확하게 취약으로 표시
            else:
                log(f"▶ {file} 파일이 존재하지 않음")
        log("")

    # 결과 출력 (result 변수 사용)
    if vulnerable_files:
        log("결과: 취약 (권한 설정 미흡 파일 발견)")
        for file in vulnerable_files:
            log(f"  - {file}")
    else:
        log("결과: 양호")
    log("")

# SRV-087: C 컴파일러 존재 및 권한 설정 미흡
def SRV_087():
    log("[SRV-087] C 컴파일러 존재 및 권한 설정 미흡")
    log(">>>SRV-087 Vuln Check !!!")
    log("")

    c_compilers = subprocess.getoutput("which cc gcc 2>/dev/null").splitlines()
    if not c_compilers:
        log("결과: 양호 (C 컴파일러 미설치)")
        return

    vulnerable_compilers = []

    for compiler in c_compilers:
        log(f"▶ {compiler} 컴파일러:")
        permissions = subprocess.getoutput(f"stat -c '%a %A' {compiler}").split()
        log(f"  - 권한: {permissions[0]} ({permissions[1]})")

        if "x" in permissions[1].lower() and not permissions[1].startswith("-rwxr-xr-x"):
            vulnerable_compilers.append(compiler)

            # 심볼릭 링크인 경우 원본 파일 권한 확인
            if os.path.islink(compiler):
                link_target = os.readlink(compiler)
                link_permissions = subprocess.getoutput(f"stat -c '%a %A' {link_target}").split()
                log(f"  - 링크 대상 ({link_target}) 권한: {link_permissions[0]} ({link_permissions[1]})")
                if "x" in link_permissions[1].lower() and not link_permissions[1].startswith("-rwxr-xr-x"):
                    vulnerable_compilers.append(link_target)  # vulnerable_compilers에 추가

    if vulnerable_compilers:
        log("결과: 취약 (Others 실행 권한 존재)")
        for compiler in vulnerable_compilers:
            log(f"  - {compiler}")
    else:
        log("결과: 양호")

    log("참고:")
    log("  - C 컴파일러는 개발 환경에서 필요하지만, 불필요한 경우 제거하는 것이 보안에 좋습니다.")
    log("  - 꼭 필요한 경우, Others 실행 권한을 제거하고 sudo 등을 통해 권한 있는 사용자만 사용하도록 제한해야 합니다.")
    log("")

# SRV-091: 불필요하게 SUID, SGID bit가 설정된 파일 존재
def SRV_091():
    log("[SRV-091] 불필요하게 SUID, SGID bit가 설정된 파일 존재")
    log(">>>SRV-091 Vuln Check !!!")
    log("")

    chk_files = ["/sbin/dump", "/sbin/restore", "/sbin/unix_chkpwd", "/usr/bin/at", "/usr/bin/lpq", 
                 "/usr/bin/lpq-lpd", "/usr/bin/lpr", "/usr/bin/lpr-lpd", "/usr/bin/lprm", 
                 "/usr/bin/lprm-lpd", "/usr/bin/newgrp", "/usr/sbin/lpc", "/usr/sbin/lpc-lpd", "/usr/sbin/traceroute"]

    suid_files = []
    sgid_files = []

    log("▶ 주요 파일 SUID, SGID 설정 전체 확인:")
    for file in chk_files:
        try:
            permissions = subprocess.getoutput(f"stat -L -c '%a %A %U %G %n' {file}").split()
            log(f"  - {file}: {permissions[0]} ({permissions[1]})")
            if permissions[0].startswith("4"):
                suid_files.append(file)
            elif permissions[0].startswith("2"):
                sgid_files.append(file)
        except subprocess.CalledProcessError:
            log(f"  - {file}: 파일 없음")

    if suid_files or sgid_files:
        log("결과: 취약 (SUID 또는 SGID가 설정된 파일 존재)")
        if suid_files:
            log("  - SUID 설정 파일:")
            for file in suid_files:
                log(f"    - {file}")
        if sgid_files:
            log("  - SGID 설정 파일:")
            for file in sgid_files:
                log(f"    - {file}")
    else:
        log("결과: 양호")
    log("")

# SRV-092: 사용자 홈 디렉터리 설정 미흡
def SRV_092():
    log("[SRV-092] 사용자 홈 디렉터리 설정 미흡")
    log(">>>SRV-092 Vuln Check !!!")
    log("")

    # 쉘을 사용하는 계정 정보 가져오기 (root 제외)
    home_dirs = subprocess.getoutput(
        "cat /etc/passwd | grep -E 'sh$' | grep -Ev '^(root|nobody|noaccess):' | awk -F: '{print $1\":\"$3\":\"$6}'"
    ).splitlines()

    issues = []  # 문제점을 저장할 리스트

    for entry in home_dirs:
        username, uid, home_dir = entry.split(":")
        log(f"▶ {username} 사용자 홈 디렉터리:")

        if os.path.isdir(home_dir):
            # 홈 디렉토리 소유자 및 권한 확인
            stat_output = subprocess.getoutput(f"stat -L -c '%a %A %U %G' {home_dir}").split()
            permissions = stat_output[0]
            owner = stat_output[2]
            group = stat_output[3]

            log(f"  - 경로: {home_dir}")
            log(f"  - 권한: {permissions[0]} ({permissions[1]})")
            log(f"  - 소유자/그룹: {owner}/{group}")

            if owner != username:
                issues.append(f"  - 소유자 불일치 (예상: {username}, 실제: {owner})")
            if "w" in permissions[1].lower():
                issues.append("  - Others 쓰기 권한 존재")
        else:
            issues.append(f"  - 홈 디렉토리 존재하지 않음")

    # 홈 디렉토리가 없는 계정 확인
    no_home_dir_accounts = subprocess.getoutput(
        "cat /etc/passwd | egrep -v -i 'nologin|false' | awk -F: 'length($6) > 0 && $6 != \"/\" {print $1 \":\" $6}' | sort -u | grep -v '^#' | grep -v '/tmp' | grep -Ev 'uucppublic|sbin' | uniq"
    ).splitlines()
    if no_home_dir_accounts:
        log("▶ 홈 디렉토리가 없는 계정:")
        for account in no_home_dir_accounts:
            log(f"  - {account}")

    # 결과 출력
    if issues or no_home_dir_accounts:
        log("결과: 취약")
        for issue in issues:
            log(issue)
    else:
        log("결과: 양호")
    log("")

# SRV-093: 불필요한 world writable 파일 존재 - /proc 파일, socket, chatacter device 및 심볼릭 링크 파일 제외
def SRV_093():
    log("[SRV-093] 불필요한 world writable 파일 존재")
    log(">>>SRV-093 Vuln Check !!!")
    log("")

    home_dirs = subprocess.getoutput(
        "cat /etc/passwd | egrep -v '^(\\s*\\$|\\s*#|\\s*\\*\\s)' | grep 'sh$' | awk -F: 'length($6) > 0 {print $6}' | sort -u"
    ).splitlines()

    world_writable_files = []

    for home_dir in home_dirs:
        try:
            find_output = subprocess.check_output(
                ["find", home_dir, "!", "-path", "/proc*", "-xdev", "-perm", "-2", "-type", "f"],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            world_writable_files.extend(find_output.splitlines())
        except subprocess.CalledProcessError as e:
            log(f"오류 발생: {e.output}")

    if world_writable_files:
        log("결과: 취약 (World Writable 파일 존재)")
        log("World Writable 파일 확인:")
        for file in world_writable_files[:5]:  # 최대 5개 파일만 출력
            log(f"  - {file}")
        if len(world_writable_files) > 5:
            log("  - ... (이하 생략)")
    else:
        log("결과: 양호 (World Writable 파일 없음)")

    log("")
    log("양호 : world writable 파일이 없거나, 필요에 의한 world writable 파일만 존재")
    log("취약 : 불필요한 world writable 파일이 있음")
    log("예시) -rwxrw-rw- 이 경우, world writable 파일")
    log("예시) -rwxrw-r-- 이 경우, world writable 파일이 아님")
    log("")
    log("참고 : world writable 파일이 존재할 경우, 인터뷰를 통하여 해당 파일에 대한 필요성을 판단해야 함")
    log("world writable 파일 : 모든 사용자가 접근 및 수정할 수 있는 권한으로 설정된 파일")
    log("일반 사용자(other)에게 쓰기 권한(w)이 있는 경우 world writable 파일로 분류함")
    log("")

# SRV-094: Crontab 참조파일 권한 설정 미흡
def SRV_094():
    log("[SRV-094] Crontab 참조파일 권한 설정 미흡")
    log(">>>SRV-094 Vuln Check !!!")
    log("")

    cron_dirs = ["/var/spool/cron", "/etc/cron.d"]  # crontab 관련 디렉토리 목록
    cron_files = ["/etc/crontab"]  # crontab 관련 파일 목록

    vulnerable_entries = []  # 취약한 항목을 저장할 리스트

    # cron 관련 디렉토리 및 파일 권한 확인
    for path in cron_dirs + cron_files:
        if os.path.exists(path):
            log(f"▶ {path} 권한:")
            permissions = subprocess.getoutput(f"stat -L -c '%a %A %U %G' {path}").split()
            log(f"  - {permissions[0]} ({permissions[1]}) {permissions[2]}/{permissions[3]}")

            if os.path.isdir(path):
                # 디렉토리인 경우 내부 파일 목록 및 내용 출력
                log(f"  - 파일 목록:")
                for entry in subprocess.getoutput(f"ls -l {path}").splitlines():
                    if not entry.startswith("total"):  # total 라인 제외
                        log(f"    - {entry}")
                log("")

                # 디렉토리 내 파일 내용 출력 (crontab 파일의 경우)
                if path == "/var/spool/cron":
                    for filename in os.listdir(path):
                        filepath = os.path.join(path, filename)
                        if os.path.isfile(filepath):
                            log(f"  - {filename} 내용:")
                            with open(filepath, "r") as f:
                                log(f.read().strip())
                            log("")
            elif os.path.isfile(path):
                # 파일인 경우 내용 출력
                log(f"  - 내용:")
                with open(path, "r") as f:
                    log(f.read().strip())
                log("")

            # 권한 확인 (Others 쓰기 권한 존재 여부)
            if "w" in permissions[1].lower():
                vulnerable_entries.append(path)
        else:
            log(f"▶ {path} 존재하지 않음")
        log("")

    # 결과 출력
    if vulnerable_entries:
        log("결과: 취약 (Others 쓰기 권한 존재)")
        for entry in vulnerable_entries:
            log(f"  - {entry}")
    else:
        log("결과: 양호")
    log("")

# SRV-095: 존재하지 않는 소유자 및 그룹 권한을 가진 파일 또는 디렉터리 존재
def SRV_095():
    log("[SRV-095] 존재하지 않는 소유자 및 그룹 권한을 가진 파일 또는 디렉터리 존재")
    log(">>>SRV-095 Vuln Check !!!")
    log("")
    log("결과 :")

    find_command_executed = True  # find 명령 실행 여부 (True로 설정)

    try:
        result = subprocess.run(
            ["find", "/", "!", "-fstype", "nfs", "-nouser", "-nogroup", "-exec", "ls", "-AlLd", "{}", ";"],
            capture_output=True,
            text=True,
            stderr=subprocess.PIPE,
        )

        with open("/var/log/find_errors.log", "a") as error_log:
            error_log.write(result.stderr)

        if result.stdout:
            result_code = "N"
            explanation = "소유자 및 소유그룹이 존재하지 않는 파일/디렉토리가 존재하므로 취약함 (REF 파일 참조)"
            evidence = result.stdout.splitlines(True)[:5]
            evidence.append("... 이하 생략 ...\n")

            with open("temp_evi.txt", "w") as evi_file, open("ref.txt", "a") as ref_file:
                evi_file.writelines(evidence)
                ref_file.write("<소유자 및 소유그룹이 존재하지 않는 파일/디렉토리 검색>\n")
                ref_file.write(result.stdout)

            log(explanation)
            for line in evidence:
                log(line.strip())
        else:
            result_code = "Y"
            explanation = "소유자 및 소유그룹이 존재하지 않는 파일/디렉토리가 존재하지 않으므로 양호함"
            log(explanation)
    except Exception as e:  # 예외 처리 추가
        result_code = "E"
        explanation = f"오류 발생: {e}"
        log(explanation)
    finally:
        if os.path.exists("temp_evi.txt"):
            os.remove("temp_evi.txt")

    log(f"결론: {result_code}")
    log("")

# SRV-096: 사용자 환경파일의 소유자 또는 권한 설정 미흡
def SRV_096():
    log("[SRV-096] 사용자 환경파일의 소유자 또는 권한 설정 미흡")
    log(">>>SRV-096 Vuln Check !!!")
    log("")
    log("결과 :")

    result = subprocess.getoutput("cat /etc/passwd | egrep -v -i 'nologin|false|shutdown|sync|halt' | awk -F':' '$7 != \"\" {print $1 \":\" $6}'")
    home_dirs = result.splitlines()

    # 취약한 파일 정보를 담을 리스트
    vulnerable_files = []

    for home_dir in home_dirs:
        owner, path = home_dir.split(":")
        log(f"▶ {owner} 홈 디렉터리 파일 확인")

        if os.path.exists(path):
            result = subprocess.getoutput(f"ls -alL {path} 2>/dev/null | grep -Ev '^d|total' | awk '{{print $9}}' | grep '^[.][a-zA-Z0-9]'")
            hidden_files = result.splitlines()

            for file in hidden_files:
                ls_result = subprocess.getoutput(f"ls -al {path}/{file} | egrep -v '(total|^d|^sshd)' 2>/dev/null")
                stat_result = subprocess.getoutput(f"stat -c '%a %A %U %G %n' {path}/{file} | egrep -v '(total|^d|^sshd)' 2>/dev/null")
                log(ls_result)
                log(stat_result)

                # 권한 확인 (Others 쓰기 권한 없음 = 양호)
                if not ls_result.startswith("-" * 4):  # ---으로 시작하지 않으면 취약
                    vulnerable_files.append(f"{path}/{file} (권한 부적절)")
                    continue  # 권한이 부적절하면 소유자 확인은 건너뜀

                # 소유자 확인
                if stat_result.split()[2] != owner:
                    vulnerable_files.append(f"{path}/{file} (소유자 부적절)")

        log("")

    # /etc/profile 파일 확인
    if os.path.exists("/etc/profile"):
        log("▶ /etc/profile 파일 확인")
        stat_result = subprocess.getoutput("stat -c '%a %A %U %G %n' /etc/profile")
        log(stat_result)
        log("")

        # 소유자 및 권한 확인 (root 또는 bin 소유, Others 쓰기 권한 없음 = 양호)
        if not (stat_result.split()[2] in ["root", "bin"] and stat_result.split()[0].startswith("-")):
            vulnerable_files.append("/etc/profile (소유자 또는 권한 부적절)")

    # 최종 결과 및 설명
    if vulnerable_files:
        result = "N"
        explanation = "사용자, 시스템 시작파일 및 환경파일 소유자 및 권한이 적절하지 않으므로 취약함"
        for file in vulnerable_files:
            log(f"- {file}")
    else:
        result = "Y"
        explanation = "사용자, 시스템 시작파일 및 환경파일 소유자 및 권한이 적절하게 적용되어 있으므로 양호함"

    log(f"결론: {result}")
    log(f"설명: {explanation}")
    log("")

# SRV-108: 로그에 대한 접근통제 및 관리 미흡
def SRV_108():
    log("[SRV-108] 로그에 대한 접근통제 및 관리 미흡")
    log(">>>SRV-108 Vuln Check !!!")
    log("")
    log("결과 :")

    # 로그 파일 권한 확인
    cmd = "stat -c '%A %U %G %n' /var/log/* /var/adm/* /run/* /var/run/* 2>/dev/null | egrep 'audit|secure|btmp|syslog|sulog|pacct|auth|messages|loginlog' | grep -v '^d' | grep -v '.pid'"
    log_file_permissions = subprocess.getoutput(cmd)

    # WTMP 파일 권한 확인
    cmd = "ls -al /var/log/wtmp* /var/adm/wtmp* /var/share/adm/wtmp* 2>/dev/null | grep '^-' | awk '{print $1}' | grep '...-..-.--'"
    wtmp_permissions = subprocess.getoutput(cmd).count("\n") >= 1  # 664 이하인 경우 True

    # 로그 파일 권한이 적절한지 확인
    log_files_ok = log_file_permissions.count("\n") == len([line for line in log_file_permissions.splitlines() if line.startswith("-.--.--")])
    
    # syslog-ng 설정 파일 확인
    if os.path.exists("/etc/syslog-ng/syslog-ng.conf"):
        log("▶ 로그파일 생성시 접근권한 확인(perm)")
        options_result = subprocess.getoutput("grep ^options -A5 /etc/syslog-ng/syslog-ng.conf")
        log(options_result)
        log("")
    else:
        log("▶ 로그파일 생성시 접근권한 확인(perm)")
        log("/etc/syslog-ng/syslog-ng.conf 파일이 존재하지 않음")
        log("")

    # 결과 판별
    if wtmp_permissions and log_files_ok:
        result = "Y"
        explanation = "시스템 로그 파일 중 소유그룹 및 Others에 쓰기/실행 권한이 존재하는 파일이 없으므로 양호함"
        log("▶ WTMP 파일 권한 확인 (664 이하 양호)")
        log(subprocess.getoutput("ls -al /var/log/wtmp* /var/adm/wtmp* /var/share/adm/wtmp* 2>/dev/null | grep '^-'"))
        log("")
        log("▶ 로그 파일 권한 확인 (644 이하 양호)")
        log(log_file_permissions)
        log("")
    else:
        result = "N"
        explanation = "WTMP 파일 권한이 664를 초과이거나 로그 파일의 권한이 적절하지 않으므로 취약함"
        log("▶ WTMP 파일 권한 확인 (664 이하 양호)")
        log(subprocess.getoutput("ls -al /var/log/wtmp* /var/adm/wtmp* /var/share/adm/wtmp* 2>/dev/null | grep '^-'"))
        log("")
        log("▶ 로그 파일 권한 확인 (644 이하 양호)")
        log(log_file_permissions)
        log("")

    log("디렉터리 내 로그 파일들의 권한이 644 이하일 경우 양호\n※/var/log/wtmp(utmp)의 경우는 664 이하 (권한 변경 불가)")
    
    # 결과 보고
    log(f"결론: {result}")
    log(f"설명: {explanation}")
    log("")

# SRV-109: 시스템 주요 이벤트 로그 설정 미흡
def SRV_109():
    log("[SRV-109] 시스템 주요 이벤트 로그 설정 미흡")
    log(">>>SRV-109 Vuln Check !!!")
    log("")
    log("결과 :")

    syslogd_running = subprocess.getoutput("ps -ef | grep -i 'syslogd' | grep -v 'grep'").count('\n') > 0

    if not syslogd_running:
        result = "N"
        explanation = "syslog 데몬이 실행중이지 않으므로 취약함"
        evidence = ""
    else:
        # 로그 설정 확인 (rsyslog.conf 파일 기준)
        log_settings = subprocess.getoutput("cat /etc/rsyslog.conf | grep -v '#' | sed '/^$/d' | sed -e 's/\s//g'")
        log_configured = any(level in log_settings for level in ["info", "alert", "notice", "debug"])

        if not log_configured:
            result = "N"
            explanation = "로그 설정이 존재하지 않으므로 취약함"
            evidence = f"""\
▶ syslog 프로세스 확인
{subprocess.getoutput("ps -ef | grep syslog | grep -v 'grep'")}

▶ syslog 설정 확인
{log_settings}
"""
        else:
            result = "Y"
            explanation = "로그 설정이 적용되어 있으므로 양호함"
            evidence = f"""\
▶ syslog 프로세스 확인
{subprocess.getoutput("ps -ef | grep syslog | grep -v 'grep'")}

▶ syslog 설정 확인
{log_settings}
"""

        # 참고 자료 추가 (syslog.conf 설정 내용)
        with open(filename, "a") as f:
            f.write("▶ /etc/*syslog.conf 설정 내역 확인\n")
            f.write(subprocess.getoutput("cat /etc/*syslog.conf"))
            f.write("\n\n")

    # syslog-ng 설정 파일 확인
    if os.path.exists("/etc/syslog-ng/syslog-ng.conf"):
        with open(filename, "a") as f:
            f.write("▶ /etc/syslog-ng/syslog-ng.conf 설정 확인\n")
            f.write(subprocess.getoutput("cat /etc/syslog-ng/syslog-ng.conf"))
            f.write("\n\n")
    else:
        with open(filename, "a") as f:
            f.write("▶ /etc/syslog-ng/syslog-ng.conf 설정 확인\n")
            f.write("/etc/syslog-ng/syslog-ng.conf 파일이 존재하지 않음\n")
            f.write("\n\n")

    # 참고 자료 추가
    reference = "아래의 경우를 만족할 경우 양호\n1. syslog 로그 기록 정책이 내부 정책에 부합하게 설정되어 있는 경우\n2. syslog 설정에서 auth 또는 authpriv 가 활성화된 경우 (su 명령 로그)"

    log(f"결론: {result}")
    log(f"설명: {explanation}")
    if evidence:
        log(evidence)
    log(reference)
    log("")

# SRV-112: Cron 서비스 로깅 미설정
def SRV_112():
    log("[SRV-112] Cron 서비스 로깅 미설정")
    log(">>>SRV-112 Vuln Check !!!")
    log("")
    log("결과 :")

    cron_log_path = "/var/log/cron"
    cron_log_exists = os.path.isfile(cron_log_path)  # 로그 파일 존재 여부 확인
    last_lines = []  # 로그 파일 내용을 담을 변수 초기화

    # 로그 파일 확인
    if cron_log_exists:
        log("1. /var/log/cron 파일 존재: 예")

        # 로그 파일 내용 확인 (마지막 5줄 확인)
        try:
            with open(cron_log_path, "r") as f:
                last_lines = f.readlines()[-5:]
                if any("CRON" in line for line in last_lines):
                    log("   - cron 작업 기록 확인: 예")
                else:
                    log("   - cron 작업 기록 확인: 아니오 (로그 파일이 비어있거나 cron 관련 메시지가 없음)")
        except FileNotFoundError:
            log("   - 로그 파일 읽기 실패")
    else:
        log("1. /var/log/cron 파일 존재: 아니오")

    # rsyslog 설정 확인
    rsyslog_conf = subprocess.getoutput("grep cron /etc/rsyslog.conf")
    if rsyslog_conf:
        log("2. rsyslog 설정 존재: 예")
        log(rsyslog_conf)
        
        # cron 관련 로그 처리 규칙 확인
        if re.search(r"cron\.\*", rsyslog_conf):
            log("   - cron 로그 처리 규칙 확인: 예")
        else:
            log("   - cron 로그 처리 규칙 확인: 아니오")
    else:
        log("2. rsyslog 설정 존재: 아니오")

    # syslog-ng 설정 확인 (선택 사항)
    if os.path.exists("/etc/syslog-ng/syslog-ng.conf"):
        syslog_ng_conf = subprocess.getoutput("grep cron /etc/syslog-ng/syslog-ng.conf")
        if syslog_ng_conf:
            log("3. syslog-ng 설정 존재: 예")
            log(syslog_ng_conf)
        else:
            log("3. syslog-ng 설정 존재: 아니오")

    # 결과 판별 (로그 파일 내용 및 설정 파일 내용 기반)
    if (cron_log_exists and any("CRON" in line for line in last_lines)) or (rsyslog_conf and re.search(r"cron\.\*", rsyslog_conf)):
        result = "Y"
        explanation = "cron 서비스 로깅 설정이 되어 있으므로 양호함"
    else:
        result = "N"
        explanation = "cron 서비스 로깅 설정이 되어 있지 않거나 로그가 제대로 기록되지 않으므로 취약함"

    log(f"결론: {result}")
    log(f"설명: {explanation}")
    log("")

# SRV-115: 로그의 정기적 검토 및 보고 미수행
def SRV_115():
    log("[SRV-115] 로그의 정기적 검토 및 보고 미수행")
    log(">>>SRV-115 Vuln Check !!!")
    log("")
    log("결과 :")

    log("# 수동 진단 #")
    log("")
    log("양호 : 로그 기록의 검토, 분석, 리포트 작성 및 보고 등이 정기적으로 이루어지는 경우")
    log("취약 : 로그 기록의 검토, 분석, 리포트 작성 및 보고 등이 정기적으로 이루어지지 않는 경우")
    log("")

# SRV-118: 주기적인 보안패치 및 벤더 권고사항 미적용
def SRV_118():
    log("[SRV-118] 주기적인 보안패치 및 벤더 권고사항 미적용")
    log(">>>SRV-118 Vuln Check !!!")
    log("")
    log("결과 :")

    result = "M"  # 수동 확인 필요
    explanation = "최신 보안패치 여부 인터뷰 확인"

    if os.environ.get("PAM_CHECK") == "RedHat":
        os_version = subprocess.getoutput("cat /etc/*release | tail -n 1")
    elif subprocess.getoutput("uname -a").lower().startswith("linux") and "ubuntu" in subprocess.getoutput("cat /etc/*release").lower():
        os_version = subprocess.getoutput("cat /etc/*release | grep 'PRETTY_NAME' | cut -d '=' -f 2 | sed 's/\"//g'")
    else:
        os_version = "Unknown"

    kernel_version = subprocess.getoutput("uname -a | awk '{print $1 \" \" $3 \" \" $4 \" \" $5}'")

    evidence = f"""\
▶ OS 버전
{os_version}

▶ 커널 버전
{kernel_version}
"""
    reference = "보안 패치 관리를 적절하게 수행하고 있는 경우 양호"

    log(f"결론: {result}")
    log(f"설명: {explanation}")
    log(evidence)
    log(reference)
    log("")

# SRV-121: 주기적인 보안패치 및 벤더 권고사항 미적용
def SRV_121():
    log("[SRV-121] root 계정의 PATH 환경변수 설정 미흡")
    log(">>>SRV-121 Vuln Check !!!")
    log("")
    log("결과 :")

    path_env = os.environ.get("PATH", "")  # root 사용자의 PATH 환경 변수 가져오기

    if "." not in path_env.split(":"):  # PATH 변수에 '.'이 포함되어 있는지 확인
        result = "Y"
        explanation = "PATH 설정에 '.'이 포함되어 있지 않으므로 양호함"
    else:
        result = "N"
        explanation = "PATH 설정에 '.'이 포함되어 있으므로 취약함"

    evidence = f"PATH 환경 변수 값: {path_env}"

    reference = "PATH 변수 내부에 './' 혹은 '::' 또는 불필요한 임의의 경로가 존재하는지 확인"

    log(f"결론: {result}")
    log(f"설명: {explanation}")
    log(evidence)
    log(reference)
    log("")

# SRV-122: UMASK 설정 미흡
def SRV_122():
    log("[SRV-122] UMASK 설정 미흡")
    log(">>>SRV-122 Vuln Check !!!")
    log("")
    log("결과 :")

    result = "M"  # 기본적으로 수동 확인 필요로 설정
    explanation = "아래의 현황을 참고하여 수동진단"
    vulnerable_users = []  # 취약한 사용자 목록

    # /etc/profile에서 umask 설정 확인
    try:
        profile_umask = subprocess.getoutput("cat /etc/profile | grep -B 1 -A 1 'umask' | grep -Ev '^ *#|__' | sed '/^$/d'")
        if profile_umask:
            log("▶ /etc/profile 설정:")
            log(profile_umask)
            # umask 값 추출 및 검증 (022 이상인지 확인)
            match = re.search(r"umask\s+(\d+)", profile_umask)
            if match and int(match.group(1)) >= 22:  # 8진수 값을 그대로 비교
                log("   - umask 값 적절함 (022 이상)")
            else:
                log("   - umask 값 부적절 (022 미만)")
                vulnerable_users.append("root (profile)")
        else:
            log("▶ /etc/profile에 umask 설정 없음")
    except Exception as e:
        log(f"▶ /etc/profile 읽기 오류: {e}")

    # /etc/passwd에서 사용자 UID 확인 (잠긴 계정 제외)
    log("\n▶ /etc/passwd 내 계정 UID 확인 (잠김 계정 제외)")
    user_uids = subprocess.getoutput("cat /etc/passwd | grep -v '/sbin/nologin' | awk -F':' '{print $1, $3}'")
    log(user_uids)

    # 각 사용자의 홈 디렉토리 및 설정 파일 확인
    shadow_users = subprocess.getoutput("egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1").splitlines()
    for user in shadow_users:
        home_dir = subprocess.getoutput(f"cat /etc/passwd | grep -w {user} | awk -F: '{{print $6}}'")

        log(f"\nUser: {user}")

        if os.path.exists(home_dir):
            log(f"▶ Home Directory: {home_dir}")

            for rcfile in [".bashrc", ".profile"]:
                rcfile_path = os.path.join(home_dir, rcfile)
                try:
                    with open(rcfile_path, "r") as f:
                        for line in f:
                            if "umask" in line:
                                log(f"  - {rcfile} umask 설정: {line.strip()}")
                                # umask 값 추출 및 검증 (022 이상인지 확인)
                                match = re.search(r"umask\s+(\d+)", line)
                                if match and int(match.group(1)) >= 22:  # 8진수 값을 그대로 비교
                                    log(f"    - umask 값 적절함 (022 이상)")
                                else:
                                    log(f"    - umask 값 부적절 (022 미만)")
                                    vulnerable_users.append(user)
                except FileNotFoundError:
                    log(f"  - {rcfile} 파일 없음")
                except PermissionError:
                    log(f"  - {rcfile} 읽기 권한 없음")

        else:
            log(f"{home_dir} Directory not Found")

    # 최종 결과 및 설명
    if vulnerable_users:
        result = "N"
        explanation += "\n취약한 사용자:\n" + "\n".join(vulnerable_users)
    else:
        result = "Y"
        explanation = "모든 계정의 umask 값이 적절하게 설정되어 있음"

    reference = "모든 계정의 umask 값과 설정 파일 등에 적용된 umask값이 022 이상인 경우 양호"

    log(f"\n결론: {result}")
    log(f"설명: {explanation}")
    log(reference)
    log("")

# SRV-127: 계정 잠금 임계값 설정 미비
def SRV_127():
    log("[SRV-127] 계정 잠금 임계값 설정 미비")
    log(">>>SRV-127 Vuln Check !!!")
    log("")
    log("결과 :")

    result = "N"  # 기본적으로 취약으로 설정
    explanation = ""
    evidence = ""

    # RedHat 계열
    if os.environ.get("PAM_CHECK") == "RedHat":
        lock_r, lock = 0, 0
        for file in ["/etc/pam.d/password-auth", "/etc/pam.d/system-auth"]:
            if os.path.isfile(file):
                content = subprocess.getoutput(f"cat {file}")
                deny_lines = re.findall(r"auth\s+required\s+pam_tally2\.so\s+deny=(\d+)", content)
                if deny_lines:
                    min_deny = min(int(d) for d in deny_lines)
                    if min_deny <= 5:
                        if file == "/etc/pam.d/password-auth":
                            lock_r = 1
                        else:
                            lock = 1
            else:  
                log(f"파일 없음: {file} (Red Hat 계열)")  # OS 계열 정보 추가

        if lock_r == 1 and lock == 1:
            result = "Y"
            explanation = "계정 잠금 임계값이 5회 이하로 설정되어 있으므로 양호함"
        else:
            explanation = "계정 잠금 임계값이 설정되어 있지 않거나 5회 초과로 설정되어 있으므로 취약함"

        evidence = f"""\
▶ /etc/pam.d/password-auth 설정 확인
{subprocess.getoutput("cat /etc/pam.d/password-auth | egrep '^auth|^#auth'")}
{subprocess.getoutput("cat /etc/pam.d/password-auth | egrep '^account|^#account'")}

▶ /etc/pam.d/system-auth 설정 확인
{subprocess.getoutput("cat /etc/pam.d/system-auth | egrep '^auth|^#auth'")}
{subprocess.getoutput("cat /etc/pam.d/system-auth | egrep '^account|^#account'")}
"""

    # Debian 계열 (Ubuntu 외 다른 배포판도 지원)
    if subprocess.getoutput("uname -a").lower().startswith("linux") and "debian" in subprocess.getoutput("cat /etc/*release").lower():
        lock_u = 0
        if os.path.isfile("/etc/pam.d/common-auth"):
            content = subprocess.getoutput("cat /etc/pam.d/common-auth")
            deny_lines = re.findall(r"auth\s+required\s+pam_tally2\.so\s+deny=(\d+)", content)
            if deny_lines:
                min_deny = min(int(d) for d in deny_lines)
                if min_deny <= 5:
                    lock_u = 1
        else:
            log("파일 없음: /etc/pam.d/common-auth (Debian 계열)")  # OS 계열 정보 추가

        if lock_u == 1:
            result = "Y"
            explanation = "계정 잠금 임계값이 5회 이하로 설정되어 있으므로 양호함"
        else:
            explanation = "계정 잠금 임계값이 설정되어 있지 않거나 5회 초과로 설정되어 있으므로 취약함"

        evidence = f"""\
▶ /etc/pam.d/common-auth 설정 확인
{subprocess.getoutput("cat /etc/pam.d/common-auth")}
"""

    reference = "/etc/pam.d/password-auth 파일과 /etc/pam.d/system-auth 파일에 계정 잠금 임계값 설정이 존재하는 경우 양호"

    log(f"결론: {result}")
    log(f"설명: {explanation}")
    log(evidence)
    log(reference)
    log("")

# SRV-131: SU 명령 사용가능 그룹 제한 미비
def SRV_131():
    log("[SRV-131] SU 명령 사용가능 그룹 제한 미비")
    log(">>>SRV-131 Vuln Check !!!")
    log("")
    log("결과 :")

    result = "N"
    explanation = ""
    evidence = ""

    try:
        su_file = subprocess.getoutput("which su").strip()

        # /usr/bin/su 파일 존재 및 권한 확인
        if not su_file:
            raise FileNotFoundError("/usr/bin/su 파일이 존재하지 않습니다.")
        su_perm_ok = (
            subprocess.getoutput(f"ls -l {su_file} | grep -E '^.....-.---'").count("\n") > 0
        )

        # /etc/pam.d/su 설정 확인
        try:
            pam_su_config = subprocess.getoutput("cat /etc/pam.d/su")
        except FileNotFoundError:
            raise FileNotFoundError("/etc/pam.d/su 파일이 존재하지 않습니다.")

        su_group_ok = (
            subprocess.getoutput(
                "cat /etc/pam.d/su | grep '^auth' |grep 'pam_wheel.so' | grep 'required'"
            ).count("\n")
            > 0
        )

        # /etc/group 설정 확인
        try:
            etc_group_output = subprocess.getoutput("cat /etc/group")
        except FileNotFoundError:
            raise FileNotFoundError("/etc/group 파일이 존재하지 않습니다.")

        wheel_group_exists = (
            subprocess.getoutput("cat /etc/group | grep -i 'wheel'").count("\n") > 0
        )
        wheel_group_has_members = (
            subprocess.getoutput(
                "cat /etc/group | grep -i 'wheel' | awk -F':' '$4 != null {print $4}'"
            ).strip()
            != ""
        )

        if wheel_group_exists and wheel_group_has_members:
            su_file_group = subprocess.getoutput(f"ls -l {su_file} | awk '{{print $4}}'").strip()
            su_group_ok = su_file_group == "wheel"
        else:
            su_group_ok = False

        evidence = f"""\
▶ {su_file} 파일 소유자 및 접근권한
{subprocess.getoutput(f"stat -L -c '%a %A %U %G %n' {su_file} 2>/dev/null")}

▶ /etc/pam.d/su 설정
{pam_su_config}

▶ /etc/group 설정 확인
{subprocess.getoutput(f"cat /etc/group | grep {su_file_group}")}
"""

        if wheel_group_exists:
            evidence += f"""\
{subprocess.getoutput("cat /etc/group | grep 'wheel'")}
"""
        else:
            evidence += "/etc/group에 제한 그룹이 적용되어 있지 않음\n\n"

        # 참고 자료 추가
        with open(filename, "a") as f:
            f.write("▶ /etc/group 전체 설정 확인\n")
            f.write(etc_group_output)
            f.write("\n\n")

        if su_perm_ok and su_group_ok:
            result = "M"
            explanation = "su 명령 사용가능 그룹 제한이 적용되어 있으므로 해당 그룹의 구성원 적절성 여부 인터뷰 확인"
        else:
            result = "N"
            explanation = "su 명령 사용가능 그룹 제한이 적용되어 있지 않으므로 취약함"

    except FileNotFoundError as e:
        result = "E"  # Error occurred
        explanation = f"파일 없음: {e.filename}"
    except PermissionError as e:
        result = "E"
        explanation = f"권한 오류: {e.filename}"
    except subprocess.CalledProcessError as e:
        result = "E"
        explanation = f"명령 실행 오류: {e}"
    except Exception as e:  # 기타 예외
        result = "E"
        explanation = f"오류 발생: {e}"

    reference = "/etc/pam.d/su 파일에 auth required pam_wheel.so use_uid 라인이 존재하는 경우 양호"

    log(f"결론: {result}")
    log(f"설명: {explanation}")
    log(evidence)
    log(reference)
    log("")

# SRV-133: Cron 서비스 사용 계정 제한 미비
def SRV_133():
    log("[SRV-133] Cron 서비스 사용 계정 제한 미비")
    log(">>>SRV-133 Vuln Check !!!")
    log("")
    log("결과 :")

    cr_allow_exists = os.path.exists("/etc/cron.allow")
    cr_deny_exists = os.path.exists("/etc/cron.deny")

    if cr_allow_exists and not cr_deny_exists:
        result = "M"
        exp = "cron.allow 파일 존재, cron.deny 파일 미존재"
    elif cr_allow_exists and cr_deny_exists:
        result = "M"
        exp = "cron.allow 및 cron.deny 파일 모두 존재"
    elif not cr_allow_exists and cr_deny_exists:
        result = "M"
        exp = "cron.allow 파일 미존재, cron.deny 파일 존재"
    else:
        result = "Y"
        exp = "cron.allow 및 cron.deny 파일 모두 미존재 (양호)"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log("")

# SRV-142: 중복 UID가 부여된 계정 존재
def SRV_142():
    log("[SRV-142] 중복 UID가 부여된 계정 존재")
    log(">>>SRV-142 Vuln Check !!!")
    log("")
    log("결과 :")

    root_uid_result = subprocess.getoutput("awk -F: '$3==0 { print $1 }' /etc/passwd | wc -l")
    root_uid = int(root_uid_result) > 1

    passwd_content = subprocess.getoutput("awk -F: '{print $3}' /etc/passwd")
    uids = passwd_content.splitlines()
    unique_uids = set(uids)
    same_uid = len(uids) != len(unique_uids)

    if not root_uid and not same_uid:
        result = "Y"
        exp = "동일한 UID를 사용하는 계정이 존재하지 않으므로 양호함"
    else:
        result = "N"
        exp = "root 이외에 UID가 '0'인 계정이 존재하거나, 동일한 UID를 사용하는 계정이 존재하므로 취약함"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log("")

# SRV-144: /dev 경로에 불필요한 파일 존재
def SRV_144():
    log("[SRV-144] /dev 경로에 불필요한 파일 존재")
    log(">>>SRV-144 Vuln Check !!!")
    log("")
    log("결과 :")

    try:
        result = subprocess.run(
            ["find", "/dev", "!", "-fstype", "nfs", "-type", "f", "-exec", "ls", "-lL", "{}", ";"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        result = "M"
        exp = "find 명령어 실행 실패 (수동 진단 필요)"
    else:
        filtered_output = subprocess.run(
            ["grep", "-Ev", "MAKEDEV|\.mount|\.udev|/dev/shm"],
            input=result.stdout,
            capture_output=True,
            text=True,
        )

        if filtered_output.stdout.strip():
            result = "N"
            exp = "/dev에 존재하지 않는 device 파일이 있으므로 취약함"
        else:
            result = "Y"
            exp = "/dev에 존재하지 않는 device 파일이 없으므로 양호함"

    reference = "/dev 경로에 존재하지 않는 device 파일이 없는 경우 양호\n※단, /dev 경로 내 파일 중 mqueue, shm 파일은 시스템에서 생성 또는 삭제가 주기적으로 일어나므로 예외"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log(f"참고: {reference}")
    log("")

# SRV-147: 불필요한 SNMP 서비스 실행
def SRV_147():
    log("[SRV-147] 불필요한 SNMP 서비스 실행")
    log(">>>SRV-147 Vuln Check !!!")
    log("")
    log("결과 :")

    try:
        subprocess.run(["pgrep", "snmp"], check=True)
    except subprocess.CalledProcessError:
        result = "Y"
        exp = "SNMP 서비스가 실행 중이지 않으므로 양호함"
    else:
        result = "M"
        exp = "SNMP 서비스가 실행 중이므로 용도 인터뷰 확인"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log("")

# SRV-148: 웹 서비스 정보 노출
def SRV_148():
    log("[SRV-148] 웹 서비스 정보 노출")
    log(">>>SRV-148 Vuln Check !!!")
    log("")
    log("결과 :")

    # Apache 실행 여부 확인
    try:
        subprocess.run(["pgrep", "httpd"], check=True)
        HTTP_SVR = True
    except subprocess.CalledProcessError:
        HTTP_SVR = False

    # Apache 설정 파일 경로 찾기 (httpd -V 명령 활용)
    if HTTP_SVR:
        httpd_v_output = subprocess.getoutput("httpd -V")
        server_root_match = re.search(r"-D SERVER_CONFIG_FILE=\"(.+?)\"", httpd_v_output)
        if server_root_match:
            server_root = server_root_match.group(1)
            Apache_conf = [server_root]  # 설정 파일 경로 리스트
        else:
            Apache_conf = []

    if not HTTP_SVR:  # Apache 서비스가 실행 중이지 않으면
        result = "Y"
        exp = "Apache 서비스가 실행 중이지 않으므로 양호함"
    else:
        vulnerable_configs = []
        for config_file in Apache_conf:
            if not os.path.exists(config_file):
                exp = f"{config_file} 파일이 존재하지 않으므로 수동 진단"
                log(f"결론: M")
                log(f"설명: {exp}")
                log("")
                continue

            with open(config_file, "r") as f:
                content = f.read()
            if not re.search(r"ServerTokens\s+Prod", content, re.IGNORECASE):
                vulnerable_configs.append(config_file)

        if vulnerable_configs:
            result = "N"
            exp = "ServerTokens 설정 값이 존재하지 않거나 Prod로 설정되어 있지 않으므로 취약함"
            for config in vulnerable_configs:
                log(f"- {config} 설정파일 확인")
        else:
            result = "Y"
            exp = "ServerTokens 설정 값이 Prod로 설정되어 있으므로 양호함"

    reference = "웹 서버 응답에 노출되는 정보가 없는 경우 양호\n웹 서버 응답에 노출되는 정보(서비스명 + 버전정보)가 있는 경우 취약"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log(f"참고: {reference}")
    log("")

 # SRV-158: 불필요한 Telnet 서비스 실행
def SRV_158():
    log("[SRV-158] 불필요한 Telnet 서비스 실행")
    log(">>>SRV-158 Vuln Check !!!")
    log("")
    log("결과 :")

    try:
        # telnet 포트가 LISTEN 상태인지 확인 (한 번에 필터링)
        subprocess.run(
            ["ss", "-atpl", "|", "awk", '/LISTEN.*:telnet/ {print $4}'],
            check=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError:
        result = "Y"
        exp = "telnet 서비스가 실행 중이지 않거나 포트가 열려있지 않으므로 양호함"
    else:
        result = "N"
        exp = "telnet 서비스가 실행 중이며 포트가 열려있으므로 취약함"

    # /etc/xinetd.d/telnet 파일 정보 추가
    telnet_config_info = (
        subprocess.getoutput("grep -i 'disable' /etc/xinetd.d/telnet")
        if os.path.exists("/etc/xinetd.d/telnet")
        else "/etc/xinetd.d/telnet 파일이 없음"
    )

    # telnet 서비스 포트 정보 추가 (포트 번호 명시)
    telnet_ports = subprocess.getoutput("ss -atpl | awk '/LISTEN.*:telnet/ {print $4}'")

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log(f"  /etc/xinetd.d/telnet 설정:\n{telnet_config_info}")
    if telnet_ports:  # telnet 포트가 발견된 경우에만 출력
        log(f"  telnet 서비스 포트: {telnet_ports}")
    log("")

# SRV-161: ftpusers 파일의 소유자 및 권한 설정 미흡
def SRV_161():
    log("[SRV-161] ftpusers 파일의 소유자 및 권한 설정 미흡")
    log(">>>SRV-161 Vuln Check !!!")
    log("")
    log("결과 :")

    ftp_running = subprocess.run(["ss", "-antpl", "|", "grep", "-i", "ftp"], capture_output=True).stdout
    FTP_SVR = bool(ftp_running)

    result = "Y"
    exp = "FTP 서비스가 실행 중이지 않으므로 양호함"

    if FTP_SVR:
        ftpuser_files = ["/etc/ftpusers", "/etc/ftpd/ftpusers", "/etc/vsftpd/ftpusers",
                         "/etc/vsftpd/user_list", "/etc/vsftpd.ftpusers", "/etc/vsftpd.user_list"]

        for file in ftpuser_files:
            if os.path.exists(file):
                file_info = subprocess.getoutput(f"stat -c '%a %U %G' {file}")
                permissions, owner, group = file_info.split()

                # 권한 검사: 소유자는 읽기/쓰기, 그룹은 읽기, 기타는 권한 없음
                if not (owner == "root" and group in ["root", "bin"] and int(permissions, 8) <= 0o640):
                    result = "N"
                    exp = "ftpusers 파일의 소유자 및/또는 권한 설정이 적절하지 않음"
                    break  # 취약한 파일 발견 시 반복 종료

    reference = "ftpusers 파일의 소유자가 root이고, 권한이 640 이하인 경우 양호"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log(f"참고: {reference}")
    log("")

# SRV-163: 시스템 사용 주의사항 미출력
def SRV_163():
    log("[SRV-163] 시스템 사용 주의사항 미출력")
    log(">>>SRV-163 Vuln Check !!!")
    log("")
    log("결과 :")

    services = {
        "SSH": (["sshd"], "/etc/ssh/sshd_config", "Banner"),
        "Telnet": (["telnet"], "/etc/issue.net", None),
        "FTP": (["vsftpd", "proftpd"], None, "ftpd_banner"),
        "Sendmail": (["sendmail"], "/etc/mail/sendmail.cf", "O SmtpGreetingMessage") 
        # Sendmail 서비스 추가 및 배너 옵션 설정
    }

    # 각 서비스별 결과를 저장할 변수 초기화
    ssh_result = "Y"
    telnet_result = "Y"
    ftp_result = "Y"
    sendmail_result = "Y"

    running_services = []
    for service, (processes, config_file, banner_option) in services.items():
        for process in processes:
            try:
                subprocess.run(["pgrep", process], check=True)
                running_services.append((service, config_file, banner_option))
                break
            except subprocess.CalledProcessError:
                pass

    result = "Y"  # 기본값을 "Y"로 설정 (모든 서비스가 실행 중이지 않은 경우를 위해)
    exp = "/etc/issue.net, /etc/motd, /etc/ssh/sshd_config 파일 설정 등으로 시스템 사용 주의사항을 출력하는 경우"

    if running_services:
        for service, config_file, banner_option in running_services:
            if config_file:
                if not os.path.exists(config_file):
                    result = "N"
                    exp = f"{service} 설정 파일({config_file})이 존재하지 않음"
                    break
                with open(config_file, "r") as f:
                    content = f.read()
                if banner_option and not re.search(rf"{banner_option}\s+.*", content):
                    result = "N"
                    exp = f"{service} 설정 파일({config_file})에 배너 문구 설정이 없음"
                    break
                else: # 설정 파일이 존재하고 배너 옵션이 설정된 경우 
                    result = "Y" 
                    exp = f"{service} 설정 파일({config_file})에 배너 문구 설정 확인"
            else:  # Telnet 또는 FTP의 경우
                try:
                    subprocess.run(
                        ["ss", "-atpl", "|", "awk", '/LISTEN.*:telnet/ {print $4}'],
                        check=True,
                        stderr=subprocess.PIPE,
                    )
                    result = "N"  
                    exp = f"{service} 배너 문구 수동 확인 필요" 
                except subprocess.CalledProcessError:  # Telnet 포트가 닫혀있으면
                    result = "Y"
                    exp = "Telnet 서비스가 실행 중이지만, 포트가 열려있지 않음"

            # 서비스별 결과 저장
            if service == "SSH":
                ssh_result = result
            elif service == "Telnet":
                telnet_result = result
            elif service == "FTP":
                ftp_result = result
            elif service == "Sendmail":
                sendmail_result = result

    # /etc/motd 파일 확인
    if not os.path.exists("/etc/motd"):
        result = "N"
        exp = "/etc/motd 파일이 존재하지 않음"

    # 시스템 버전 정보 노출 확인
    issue_content = subprocess.getoutput("cat /etc/issue")
    if re.search(r"(\d+\.)+\d+", issue_content):
        result = "N"
        exp = "/etc/issue 파일에 시스템 버전 정보 노출"

    reference = (
        "양호 : /etc/issue.net, /etc/motd, /etc/ssh/sshd_config 파일 설정 등으로 시스템 사용 주의사항을 출력하는 경우\n"
        "취약 : /etc/issue.net, /etc/motd, /etc/ssh/sshd_config 파일 설정 등으로 시스템 사용 주의사항 미출력 시 또는 표시 문구 내에 시스템 버전정보가 노출되는 경우"
    )

    log(f"결론: {result}")  # 최종 결과 출력
    log(f"설명: {exp}")
    log(f"참고: {reference}")
    # 각 서비스별 결과 출력
    log(f"SSH 결과: {ssh_result}")
    log(f"Telnet 결과: {telnet_result}")
    log(f"FTP 결과: {ftp_result}")
    log(f"Sendmail 결과: {sendmail_result}")
    log("")

# SRV-164: 구성원이 존재하지 않는 불필요한 GID 존재
def SRV_164():
    log("[SRV-164] 구성원이 존재하지 않는 불필요한 GID 존재")
    log(">>>SRV-164 Vuln Check !!!")
    log("")
    log("결과 :")

    exception_groups = {
        "root", "bin", "daemon", "sys", "adm", "tty", "disk", "lp", "mem", "kmem", "wheel",
        "cdrom", "mail", "man", "dialout", "floppy", "games", "tape", "video", "ftp", "lock",
        "audio", "nobody", "users", "utmp", "utempter", "input", "systemd-journal", 
        "systemd-network", "dbus", "polkitd", "ssh_keys", "sshd", "postdrop", "postfix", 
        "apache", "news", "uucp", "proxy", "fax", "voice", "www-data", "backup", "operator", 
        "list", "irc", "src", "gnats", "shadow", "sasl", "staff", "nogroup", "crontab", 
        "netdev", "messagebus", "uuidd", "mlocate", "ssh", "ssl-cert", "snmp", "smmsp", "rpc", "rpcuser"
    }

    # /etc/group 파일에서 GID 추출
    group_gids = subprocess.getoutput("awk -F: '{print $3}' /etc/group").splitlines()

    # /etc/passwd 파일에서 GID 추출
    passwd_gids = subprocess.getoutput("awk -F: '{print $4}' /etc/passwd").splitlines()

    # 사용되지 않는 GID 찾기 (group에는 있지만 passwd에는 없는 GID)
    unused_gids = [gid for gid in group_gids if gid not in passwd_gids and gid.isdigit() and int(gid) >= 1000]

    # 예외 그룹 제외
    unused_gids = [gid for gid in unused_gids if gid not in exception_groups]

    if unused_gids:
        result = "N"
        exp = "구성원이 존재하지 않는 GID가 존재하므로 취약함"
    else:
        result = "Y"
        exp = "구성원이 존재하지 않는 GID가 존재하지 않으므로 양호함"

    reference = (
        "양호 : 구성원이 존재하지 않는 GID가 존재하지 않는 경우\n"
        "취약 : 구성원이 존재하지 않는 GID가 존재하는 경우"
    )

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log(f"참고: {reference}")
    log("")

# SRV-165: 불필요하게 Shell이 부여된 계정 존재
def SRV_165():
    log("[SRV-165] 불필요하게 Shell이 부여된 계정 존재")
    log(">>>SRV-165 Vuln Check !!!")
    log("")
    log("결과 :")

    grep_pattern = r"^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher"

    # Initialize accounts_with_shell to an empty string
    accounts_with_shell = ""

    try:
        result = subprocess.run(
            [
                "awk",
                "-F:",
                f"$7!~/^(\/usr\/sbin\/nologin|\/sbin\/nologin|\/bin\/false)$/ && $7!=\"\" && $1~/{grep_pattern}/ && $1!=\"admin\" {{print $1\":\"$7}}'",
                "/etc/passwd",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        result = "M"
        exp = f"awk 명령어 실행 실패 (수동 진단 필요): {e.stderr}"
    else:
        accounts_with_shell = result.stdout.strip()
        if accounts_with_shell:
            result = "N"
            exp = "로그인이 필요하지 않은 계정에 shell이 부여된 경우"
        else:
            result = "Y"
            exp = "로그인이 필요하지 않은 계정에 /bin/false(nologin) 등이 부여된 경우"

    reference = (
        "양호 : 로그인이 필요하지 않은 계정에 /bin/false(nologin) 등이 부여된 경우\n"
        "취약 : 로그인이 필요하지 않은 계정에 shell이 부여된 경우\n"
        "※일반적으로 Daemon 실행을 위한 계정은 Shell이 불필요( 예: ftp, apache, www-data )"
    )

    log(f"결론: {result}")
    log(f"설명: {exp}")
    if accounts_with_shell:
        log(f"  취약 계정 정보:\n{accounts_with_shell}")
    log(f"참고: {reference}")
    log("")

# SRV-166: 불필요한 숨김 파일 또는 디렉터리 존재
def SRV_166():
    log("[SRV-166] 불필요한 숨김 파일 또는 디렉터리 존재")
    log(">>>SRV-166 Vuln Check !!!")
    log("")
    log("결과 :")

    # 기본값을 'N'으로 설정 (숨김 파일 존재 가정)
    result = "N"
    exp = "숨김 파일 또는 디렉터리 존재"

    try:
        find_output = subprocess.run(
            ["find", "/", "-xdev", "!", "-fstype", "nfs", "-name", ".*"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        result = "N"  # find 명령 실패 시에도 취약으로 판단
        exp = f"find 명령어 실행 실패: {e.stderr}"  # 에러 메시지 출력
    else:
        # 제외할 디렉터리 및 파일 패턴
        exclude_patterns = [
            r"/proc/.*",
            r"/sys/.*",
            r"/dev/.*",
            r"/run/.*",
            r"/tmp/.*",
            r"/var/lib/.*",
            r"/var/run/.*",
            r"\.Trash-\d+",
            r"\.hidden",
            r"\.ICE-unix/",
        ]

        hidden_files = find_output.splitlines()

        # 제외 패턴에 해당하는 파일 제거
        filtered_hidden_files = [
            file
            for file in hidden_files
            if not any(re.match(pattern, file) for pattern in exclude_patterns)
        ]

        if not filtered_hidden_files:  # 필터링된 숨김 파일이 없으면 양호
            result = "Y"
            exp = "불필요한 숨김 파일 또는 디렉터리가 존재하지 않음"

    reference = "불필요한 숨김 파일이 존재하지 않을 경우 양호"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log(f"참고: {reference}")
    log("")

# SRV-166: 불필요한 숨김 파일 또는 디렉터리 존재
def SRV_166():
    log("[SRV-166] 불필요한 숨김 파일 또는 디렉터리 존재")
    log(">>>SRV-166 Vuln Check !!!")
    log("")
    log("결과 :")

    # 기본값을 'N'으로 설정 (숨김 파일 존재 가정)
    result = "N"
    exp = "숨김 파일 또는 디렉터리 존재"

    try:
        find_output = subprocess.run(
            ["find", "/", "-xdev", "!", "-fstype", "nfs", "-name", ".*"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
    except subprocess.CalledProcessError as e:
        result = "N"  # find 명령 실패 시에도 취약으로 판단
        exp = f"find 명령어 실행 실패: {e.stderr}"  # 에러 메시지 출력
    else:
        # 제외할 디렉터리 및 파일 패턴
        exclude_patterns = [
            r"/proc/.*",
            r"/sys/.*",
            r"/dev/.*",
            r"/run/.*",
            r"/tmp/.*",
            r"/var/lib/.*",
            r"/var/run/.*",
            r"\.Trash-\d+",
            r"\.hidden",
            r"\.ICE-unix/",
        ]

        # 필터링된 숨김 파일 및 디렉터리
        filtered_hidden_items = [
            item
            for item in find_output
            if not any(re.match(pattern, item) for pattern in exclude_patterns)
        ]

        # 불필요한 파일/디렉터리 판단 함수
        def is_unnecessary_item(item):
            try:
                if os.path.isfile(item):  # 파일인 경우
                    with open(item, "r") as f:
                        content = f.read()
                    return content.strip()  # 내용이 비어있지 않으면 True
                elif os.path.isdir(item):  # 디렉터리인 경우
                    return os.listdir(item)  # 하위 항목이 있으면 True
            except (PermissionError, FileNotFoundError):  # 권한 문제 또는 파일 없음
                return False  # 예외 발생 시 False 반환

        unnecessary_items = [item for item in filtered_hidden_items if is_unnecessary_item(item)]

        if unnecessary_items:
            result = "N"
            exp = "불필요한 숨김 파일 또는 디렉터리가 존재함"
        else:
            result = "Y"
            exp = "불필요한 숨김 파일 또는 디렉터리가 존재하지 않음"

    reference = (
        "양호 : 불필요한 숨김 파일이 존재하지 않을 경우\n"
        "취약 : 불필요한 숨김 파일이 존재하는 경우"
    )

    log(f"결론: {result}")
    log(f"설명: {exp}")
    if unnecessary_items:
        log(f"  불필요한 숨김 파일 또는 디렉터리:\n    " + "\n    ".join(unnecessary_items))
    log(f"참고: {reference}")
    log("")

# SRV-170: SMTP 서비스 정보 노출
def SRV_170():
    log("[SRV-170] SMTP 서비스 정보 노출")
    log(">>>SRV-170 Vuln Check !!!")
    log("")
    log("결과 :")

    smtp_services = {
        "Sendmail": ("sendmail", "/etc/mail/sendmail.cf", r"SmtpGreetingMessage\s*=\s*(.*)"),
        "Postfix": ("postfix", "/etc/postfix/main.cf", r"smtpd_banner\s*=\s*(.*)"),
        "Exim": ("exim", "/etc/exim/exim.conf", r"smtp_banner\s*=\s*(.*)"),
    }

    result = "Y"
    exp = "SMTP 접속 배너에 노출되는 정보가 없는 경우"

    for service_name, (process_name, config_file, banner_pattern) in smtp_services.items():
        service_result = "Y"  # 각 서비스별 결과를 저장할 변수
        service_exp = f"{service_name} 서비스가 실행 중이지 않음"  # 각 서비스별 설명을 저장할 변수

        try:
            # 서비스 실행 여부 확인
            subprocess.run(["pgrep", process_name], check=True)

            # 설정 파일 존재 여부 확인
            if not os.path.exists(config_file):
                service_result = "M"
                service_exp = f"{service_name} 설정 파일({config_file})이 존재하지 않음"
            else:
                # 설정 파일에서 배너 설정 값 추출
                with open(config_file, "r") as f:
                    config_content = f.read()
                match = re.search(banner_pattern, config_content)

                if match:
                    banner_value = match.group(1).strip()  # 따옴표 제거

                    # 버전 정보 노출 여부 확인
                    if re.search(r"\$v|\$mail_version|\$version_number", banner_value):
                        result = "N"  # 전체 결과를 취약으로 변경
                        service_result = "N"
                        service_exp = f"{service_name} 배너 메시지에 버전 정보 노출"
                        exp = "SMTP 접속 배너에 노출되는 정보가 있는 경우"
                else:
                    service_exp = f"{service_name} 설정 파일({config_file})의 배너 설정 값: {banner_value}"
        except subprocess.CalledProcessError:
            pass  # 서비스가 실행 중이지 않으면 양호

        # 서비스별 결과 로그 출력
        log(f"  {service_name} 결과: {service_result}")
        log(f"  {service_exp}")

    reference = (
        "양호 : SMTP 접속 배너에 노출되는 정보가 없는 경우\n"
        "취약 : SMTP 접속 배너에 노출되는 정보가 있는 경우\n"
        "Sendmail: 설정 파일(sendmail.cf) 내의 SmtpGreetingMessage 설정 값에 $v 파라미터 제외\n"
        "Postfix: 설정 파일(main.cf) 내의 smtpd_banner 설정 값에 $mail_version 파라미터 제외\n"
        "Exim: 설정 파일(exim.cf) 내의 smtp_banner 설정 값에 $version_number 파라미터 제외"
    )

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log(f"참고: {reference}")
    log("")

# SRV-171: FTP 서비스 정보 노출
def SRV_171():
    log("[SRV-171] FTP 서비스 정보 노출")
    log(">>>SRV-171 Vuln Check !!!")
    log("")
    log("결과 :")

    result = "Y"
    exp = "FTP 접속 배너에 노출되는 정보가 없는 경우"

    # FTP 서버 설정 파일 확인
    ftp_config_files = ["/etc/vsftpd/vsftpd.conf", "/etc/proftpd/proftpd.conf"]
    for config_file in ftp_config_files:
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                content = f.read()
                if "ftpd_banner" in content:
                    banner_match = re.search(r"ftpd_banner=(.+)", content)
                    if banner_match:
                        banner_value = banner_match.group(1).strip()
                        if not banner_value.startswith("%"):
                            result = "N"
                            exp = f"FTP 설정 파일({config_file})의 ftpd_banner 설정 값에 정보 노출: {banner_value}"
                            break

    if result == "Y":  # 설정 파일에서 취약점이 발견되지 않은 경우에만 소켓 연결 시도
        try:
            # FTP 서버에 연결
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)  # 연결 시간 초과 설정 (5초)
                s.connect(("localhost", 21))  # FTP 기본 포트 21번으로 연결
                banner = s.recv(1024).decode()  # 배너 메시지 수신

            # 배너 정보에서 버전 정보 추출
            version_match = re.search(r"(\d+\.)+\d+", banner)
            if version_match:
                result = "N"
                exp = f"FTP 접속 배너에 버전 정보 노출: {version_match.group()}"

        except (ConnectionRefusedError, socket.timeout):
            pass  # FTP 서비스가 활성화되어 있지 않거나 연결 시간 초과

    reference = (
        "양호 : FTP 접속 배너에 노출되는 정보가 없는 경우\n"
        "취약 : FTP 접속 배너에 노출되는 정보가 있는 경우"
    )

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log(f"참고: {reference}")
    log("")

# SRV-173: DNS 서비스의 취약한 동적 업데이트 설정
def SRV_173():
    log("[SRV-173] DNS 서비스의 취약한 동적 업데이트 설정")
    log(">>>SRV-173 Vuln Check !!!")
    log("")
    log("결과 :")

    named_process = subprocess.getoutput("ps -ef | grep named | grep -v grep")
    if named_process:
        log("1. DNS 서비스 실행: 예")

        try:
            # named.conf 파일에서 'allow-update' 옵션 검색
            allow_update_output = subprocess.getoutput("grep 'allow-update' /etc/named.conf")
        except subprocess.CalledProcessError as e:
            result = "M"
            exp = f"named.conf 파일 읽기 실패: {e.stderr}"
        else:
            if allow_update_output:
                log("2. 동적 업데이트 설정 발견:")
                log(allow_update_output)

                # 'allow-update' 설정값 검증 강화
                if "none" in allow_update_output.lower():
                    result = "양호"
                    exp = "동적 업데이트가 비활성화되어 있음"
                elif re.search(r"allow-update\s*{([^}]*?);", allow_update_output):
                    allowed_clients = re.search(r"allow-update\s*{([^}]*?);", allow_update_output).group(1).strip()
                    if allowed_clients and "any" not in allowed_clients.lower():  # 특정 IP 또는 네트워크만 허용하는 경우
                        result = "양호"
                        exp = "동적 업데이트가 활성화되어 있지만, 적절한 접근 제어가 설정되어 있음"
                    else:
                        result = "취약"
                        exp = "동적 업데이트가 활성화되어 있고, 적절한 접근 제어가 설정되어 있지 않음"
                else:
                    result = "취약"
                    exp = "동적 업데이트 설정이 잘못되었거나, 접근 제어가 불명확함 (수동 점검 필요)"
            else:
                log("2. 동적 업데이트 설정 미발견")
                result = "양호"
                exp = "동적 업데이트 설정이 존재하지 않음"
    else:
        log("1. DNS 서비스 실행: 아니오")
        result = "양호"
        exp = "DNS 서비스가 실행 중이지 않음"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log("")
    
# SRV-174: 불필요한 DNS 서비스 실행
def SRV_174():
    log("[SRV-174] 불필요한 DNS 서비스 실행")
    log(">>>SRV-174 Vuln Check !!!")
    log("")
    log("결과 :")

    try:
        subprocess.run(["pgrep", "named"], check=True)  # named 프로세스 확인
    except subprocess.CalledProcessError:
        result = "Y"
        exp = "DNS 서비스가 실행 중이지 않거나, 필요에 의해 사용 중인 경우"
    else:
        result = "N"
        exp = "DNS 서비스가 불필요하게 실행 중인 경우"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log("")

# SRV-175: NTP 및 시각 동기화 미설정
def SRV_175():
    log("[SRV-175] NTP 및 시각 동기화 미설정")
    log(">>>SRV-175 Vuln Check !!!")
    log("")
    log("결과 :")

    try:
        # ntpq 명령어를 사용하여 NTP 서버 동기화 상태 확인
        ntp_status = subprocess.run(["ntpq", "-p"], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        result = "M"  # ntpq 명령어 실행 실패 또는 NTP 서비스가 설치되지 않은 경우
        exp = "NTP 서비스가 설치되어 있지 않거나 ntpq 명령어 실행 실패 (수동 점검 필요)"
    else:
        # ntpq 출력에서 '*' 문자를 포함하는 라인 검색 (동기화된 서버)
        synchronized_server = any("*" in line for line in ntp_status.stdout.splitlines())

        if synchronized_server:
            result = "Y"
            exp = "NTP 서버 동기화가 설정되어 있는 경우"
        else:
            result = "N"
            exp = "NTP 서버 동기화가 미설정되어 있는 경우"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log("")

# SRV-176: 취약한 SNMP 버전을 사용
def SRV_176():
    log("[SRV-176] 취약한 SNMP 버전을 사용")
    log(">>>SRV-176 Vuln Check !!!")
    log("")
    log("결과 :")

    try:
        subprocess.run(["pgrep", "snmpd"], check=True)  # snmpd 프로세스 확인
    except subprocess.CalledProcessError:
        result = "Y"
        exp = "SNMP 서비스가 실행중이지 않으므로 양호함"
    else:
        # snmpd.conf 파일에서 SNMPv3 설정 검색
        try:
            snmpv3_config = subprocess.check_output(
                ["grep", "-E", "'^rwuser | ^createUser | ^rouser'", "/etc/snmp/snmpd.conf"],
                text=True
            ).strip()
        except subprocess.CalledProcessError:
            snmpv3_config = ""  # 설정 못 찾았을 경우 빈 문자열

        if snmpv3_config:
            result = "Y"
            exp = "SNMPv3 사용하는 경우"
        else:
            result = "N"
            exp = "SNMPV3 사용하지 않는 경우"

    log(f"결론: {result}")
    log(f"설명: {exp}")
    log("")

def main():
    SRV_001()
    SRV_004()
    SRV_005()
    SRV_006()
    SRV_007()
    SRV_008()
    SRV_009()
    SRV_010()
    SRV_011()
    SRV_012()
    SRV_013()
    SRV_014()
    SRV_015()
    SRV_016()
    SRV_021()
    SRV_022()
    SRV_025()
    SRV_026()
    SRV_027()
    SRV_028()
    SRV_034()
    SRV_035()
    SRV_037()
    SRV_040()
    SRV_042()
    SRV_043()
    SRV_044()
    SRV_045()
    SRV_046()
    SRV_047()
    SRV_048()
    SRV_060()
    SRV_063()
    SRV_064()
    SRV_066()
    SRV_069()
    SRV_070()
    SRV_073()
    SRV_074()
    SRV_075()
    SRV_081()
    SRV_082()
    SRV_083()
    SRV_084()
    SRV_087()
    SRV_091()
    SRV_092()
    SRV_093()
    SRV_094()
    SRV_095()
    SRV_096()
    SRV_108()
    SRV_109()
    SRV_112()
    SRV_115()
    SRV_118()
    SRV_121()
    SRV_122()
    SRV_127()
    SRV_131()
    SRV_133()
    SRV_142()
    SRV_144()
    SRV_147()
    SRV_148()
    SRV_158()
    SRV_161()
    SRV_163()
    SRV_164()
    SRV_165()
    SRV_166()
    SRV_170()
    SRV_171()
    SRV_173()
    SRV_174()
    SRV_175()
    SRV_176()

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
