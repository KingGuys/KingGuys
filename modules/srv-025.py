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

def main():
    SRV_025()

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