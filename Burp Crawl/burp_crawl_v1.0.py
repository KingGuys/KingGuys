import xml.etree.ElementTree as ET
import csv

def extract_successful_requests_from_xml(xml_filename, output_filename, output_format='txt'):
    try:
        tree = ET.parse(xml_filename)
        root = tree.getroot()

        results = []

        for item in root.findall('item'):
            status_element = item.find('status')
            if status_element is not None:
                status_code = status_element.text
                if status_code == '200':  # 성공적인 요청 (상태 코드 200)만 처리
                    url_element = item.find('url')
                    headers_element = item.find('request')  # request -> headers 로 변경 고려
                    mimetype_element = item.find('mimetype')
                    responselength_element = item.find('responselength')

                    url = url_element.text if url_element is not None else "URL 정보 없음"
                    headers = headers_element.text if headers_element is not None else "헤더 정보 없음"
                    responselength = responselength_element.text if responselength_element is not None else "responselength 정보"
                    mimetype = mimetype_element.text if mimetype_element is not None else "mimetype 정보 없음"

                    result = {
                        "URL": url,
                        "Status code": status_code,
                        "mimetype": mimetype,
                        "responselength": responselength,
                        "Headers": headers.splitlines()
                    }
                    results.append(result)

        if output_format == 'txt':
            with open(output_filename, 'w', encoding='utf-8') as f:
                for result in results:
                    f.write(f"URL: {result['URL']}\n")
                    f.write(f"Status code: {result['Status code']}\n")
                    f.write(f"mimetype: {result['mimetype']}\n")
                    f.write(f"responselength: {result['responselength']}\n")
                    f.write("Headers:\n")
                    for line in result['Headers']:
                        f.write(f"  {line}\n")
                    f.write("-" * 50 + "\n\n")

        elif output_format == 'csv':
            with open(output_filename, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Status code", "mimetype", "responselength", "Headers"])
                for result in results:
                    writer.writerow([result['URL'], result['Status code'], result['mimetype'], result['responselength'],
                                     "\n".join(result['Headers'])])  # Headers 리스트를 하나의 문자열로 합침

        else:
            print(f"지원되지 않는 출력 형식: {output_format}")

    except ET.ParseError as e:
        print(f"XML 파싱 오류: {e}")
    except FileNotFoundError:
        print(f"파일을 찾을 수 없습니다: {xml_filename}")
    except Exception as e:
        print(f"예기치 않은 오류 발생: {e}")

# 함수 호출 (txt 형식으로 출력)
extract_successful_requests_from_xml('TEST.xml', 'output.txt')  # 파일 이름 변경

# 함수 호출 (csv 형식으로 출력)
extract_successful_requests_from_xml('TEST.xml', 'output.csv', 'csv')  # 파일 이름 변경