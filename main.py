import os
import subprocess
import datetime
import sys  # sys 모듈 추가
from modules import SRV_001
from modules import SRV_004
from modules import SRV_005
from modules import SRV_006
from modules import SRV_007
from modules import SRV_008
from modules import SRV_009
from modules import SRV_010
from modules import SRV_011
from modules import SRV_012
from modules import SRV_013
from modules import SRV_014
from modules import SRV_015
from modules import SRV_016
from modules import SRV_021
from modules import SRV_022
from modules import SRV_025
from modules import SRV_026
from modules import SRV_027
from modules import SRV_028
from modules import SRV_034
from modules import SRV_035
from modules import SRV_037
from modules import SRV_040
from modules import SRV_042
from modules import SRV_043
from modules import SRV_044


# 환경 설정 (main.py 에서 설정)
os.environ["LANG"] = "C"

# 파일명 설정 (main.py 에서 설정)
hostname = subprocess.getoutput("hostname")
date = datetime.datetime.now().strftime("%Y-%m-%d")
default_filename = "result.log"  # 기본 파일명 변경: result.log
specific_filename_prefix = "" # 특정 SRV 실행 시 파일명 prefix 제거


# 로그 작성 함수 (main.py 에 포함)
def log(message, filename): # filename 파라미터 추가
    """로그 메시지를 파일에 추가하고 화면에 출력합니다."""
    with open(filename, "a") as f:
        f.write(message + "\n")
    print(message)


def main():
    """main 함수: 프로그램 시작점"""
    if len(sys.argv) > 1:  # 명령행 인수가 있는 경우 (특정 SRV 모듈 실행)
        srv_module = sys.argv[1]  # 첫 번째 인수를 모듈 이름으로 사용
        current_filename = f"{specific_filename_prefix}{srv_module}.log" # SRV_001.log
        log("------------------------------------", current_filename)
        log(f"  Linux script 시작 - {srv_module} 점검", current_filename)
        log(f"  시작 시간: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", current_filename)
        log("------------------------------------", current_filename)
        log("", current_filename)

        log(f"[점검 항목 {srv_module} 시작]", current_filename)

        if srv_module == "SRV_001":
            SRV_001.SRV_001()
        elif srv_module == "SRV_004":
            SRV_004.SRV_004()
        elif srv_module == "SRV_005":
            SRV_005.SRV_005()
        elif srv_module == "SRV_006":
            SRV_006.SRV_006()
        elif srv_module == "SRV_007":
            SRV_007.SRV_007()
        elif srv_module == "SRV_008":
            SRV_008.SRV_008()
        elif srv_module == "SRV_009":
            SRV_009.SRV_009()
        elif srv_module == "SRV_010":
            SRV_010.SRV_010()
        elif srv_module == "SRV_011":
            SRV_011.SRV_011()
        elif srv_module == "SRV_012":
            SRV_012.SRV_012()
        elif srv_module == "SRV_013":
            SRV_013.SRV_013()
        elif srv_module == "SRV_014":
            SRV_014.SRV_014()
        elif srv_module == "SRV_015":
            SRV_015.SRV_015()
        elif srv_module == "SRV_016":
            SRV_016.SRV_016()
        elif srv_module == "SRV_021":
            SRV_021.SRV_021()
        elif srv_module == "SRV_022":
            SRV_022.SRV_022()
        elif srv_module == "SRV_025":
            SRV_025.SRV_025()
        elif srv_module == "SRV_026":
            SRV_026.SRV_026()
        elif srv_module == "SRV_027":
            SRV_027.SRV_027()
        elif srv_module == "SRV_028":
            SRV_028.SRV_028()
        elif srv_module == "SRV_034":
            SRV_034.SRV_034()
        elif srv_module == "SRV_035":
            SRV_035.SRV_035()
        elif srv_module == "SRV_037":
            SRV_037.SRV_037()
        elif srv_module == "SRV_040":
            SRV_040.SRV_040()
        elif srv_module == "SRV_042":
            SRV_042.SRV_042()
        elif srv_module == "SRV_043":
            SRV_043.SRV_043()
        elif srv_module == "SRV_044":
            SRV_044.SRV_044()
        else:
            log(f"알 수 없는 점검 항목: {srv_module}", current_filename)
            log("사용 가능한 점검 항목: SRV_001, SRV_004, SRV_005, ..., SRV_044", current_filename)
            return  # 알 수 없는 항목이면 함수 종료

        log(f"[점검 항목 {srv_module} 완료]", current_filename)
        log("", current_filename)


        log("------------------------------------", current_filename)
        log(f"  Linux script 종료 - {srv_module} 점검", current_filename)
        log(f"  종료 시간: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", current_filename)
        log("------------------------------------", current_filename)

        print(f"점검 결과가 {current_filename} 파일에 저장되었습니다.")


    else:  # 명령행 인수가 없는 경우 (기존처럼 전체 항목 실행)
        current_filename = default_filename # 기본 파일명 사용: result.log
        log("------------------------------------", current_filename)
        log(f"  Linux script 시작", current_filename)
        log(f"  시작 시간: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", current_filename)
        log("------------------------------------", current_filename)
        log("", current_filename)


        log("[전체 점검 시작]", current_filename)

        log("[점검 항목 SRV-001 시작]", current_filename)
        SRV_001.SRV_001()
        log("[점검 항목 SRV-001 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-004 시작]", current_filename)
        SRV_004.SRV_004()
        log("[점검 항목 SRV-004 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-005 시작]", current_filename)
        SRV_005.SRV_005()
        log("[점검 항목 SRV-005 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-006 시작]", current_filename)
        SRV_006.SRV_006()
        log("[점검 항목 SRV-006 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-007 시작]", current_filename)
        SRV_007.SRV_007()
        log("[점검 항목 SRV-007 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-008 시작]", current_filename)
        SRV_008.SRV_008()
        log("[점검 항목 SRV-008 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-009 시작]", current_filename)
        SRV_009.SRV_009()
        log("[점검 항목 SRV-009 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-010 시작]", current_filename)
        SRV_010.SRV_010()
        log("[점검 항목 SRV-010 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-011 시작]", current_filename)
        SRV_011.SRV_011()
        log("[점검 항목 SRV-011 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-012 시작]", current_filename)
        SRV_012.SRV_012()
        log("[점검 항목 SRV-012 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-013 시작]", current_filename)
        SRV_013.SRV_013()
        log("[점검 항목 SRV-013 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-014 시작]", current_filename)
        SRV_014.SRV_014()
        log("[점검 항목 SRV-014 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-015 시작]", current_filename)
        SRV_015.SRV_015()
        log("[점검 항목 SRV-015 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-016 시작]", current_filename)
        SRV_016.SRV_016()
        log("[점검 항목 SRV-016 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-021 시작]", current_filename)
        SRV_021.SRV_021()
        log("[점검 항목 SRV-021 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-022 시작]", current_filename)
        SRV_022.SRV_022()
        log("[점검 항목 SRV-022 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-025 시작]", current_filename)
        SRV_025.SRV_025()
        log("[점검 항목 SRV-025 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-026 시작]", current_filename)
        SRV_026.SRV_026()
        log("[점검 항목 SRV-026 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-027 시작]", current_filename)
        SRV_027.SRV_027()
        log("[점검 항목 SRV-027 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-028 시작]", current_filename)
        SRV_028.SRV_028()
        log("[점검 항목 SRV-028 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-034 시작]", current_filename)
        SRV_034.SRV_034()
        log("[점검 항목 SRV-034 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-035 시작]", current_filename)
        SRV_035.SRV_035()
        log("[점검 항목 SRV-035 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-037 시작]", current_filename)
        SRV_037.SRV_037()
        log("[점검 항목 SRV-037 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-040 시작]", current_filename)
        SRV_040.SRV_040()
        log("[점검 항목 SRV-040 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-042 시작]", current_filename)
        SRV_042.SRV_042()
        log("[점검 항목 SRV-042 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-043 시작]", current_filename)
        SRV_043.SRV_043()
        log("[점검 항목 SRV-043 완료]", current_filename)
        log("", current_filename)

        log("[점검 항목 SRV-044 시작]", current_filename)
        SRV_044.SRV_044()
        log("[점검 항목 SRV-044 완료]", current_filename)
        log("", current_filename)

        log("[전체 점검 완료]", current_filename)


    log("------------------------------------", current_filename)
    log(f"  Linux script 종료", current_filename)
    log(f"  종료 시간: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", current_filename)
    log("------------------------------------", current_filename)

    print(f"점검 결과가 {current_filename} 파일에 저장되었습니다.")


if __name__ == "__main__":
    main()