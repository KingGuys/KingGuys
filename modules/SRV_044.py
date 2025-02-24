import os
import subprocess
import re
from datetime import datetime

# 환경 설정
os.environ["LANG"] = "C"

# 파일명 설정
hostname = subprocess.getoutput("hostname")
date = datetime.now().strftime("%Y-%m-%d")
filename = f"SRV-044.log"

# 로그 작성 함수
def log(message):
    """로그 메시지를 파일에 추가합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)

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

def main():
    SRV_044()

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