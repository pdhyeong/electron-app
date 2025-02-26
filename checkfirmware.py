import os
import stat
import re
import sys
import io
import tarfile
import zipfile
import subprocess
import mimetypes
import platform
import requests
from bs4 import BeautifulSoup
from tabulate import tabulate
from cryptfolder.analysis.plugin import AnalysisPluginV0, Tag, addons, compat
import yara
import socket
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Union

INVALID_CHARS = '<>:"\\|?*'

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def is_wsl():
    try:
        with open("/proc/version", "r") as f:
            content = f.read().lower()
            return "microsoft" in content
    except FileNotFoundError:
        return False

def detect_platform() -> str:
    """
    This function detectes the OS platform and return platform name
    """
    if sys.platform.startswith("win"):
        return "win"
    elif sys.platform.startswith("darwin"):
        return "mac"
    elif sys.platform.startswith("linux"):
        return "linux"

class FileHandler:
    @staticmethod
    def get_file_data(file_path: str) -> None:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()
            return content
        except FileNotFoundError:
            print(f"파일을 찾을 수 없습니다: {file_path}")
        except Exception as e:
            print(f"실행 중 에러 발생: {e}")
    
    def get_file_lines(file_path: str) -> List:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = [line.strip() for line in file]
            return content
        except FileNotFoundError:
            print(f"파일을 찾을 수 없습니다: {file_path}")
        except Exception as e:
            print(f"실행 중 에러 발생: {e}")

    @staticmethod
    def read_file(file_path: str) -> None:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()
                print(content)
        except FileNotFoundError:
            print(f"파일을 찾을 수 없습니다: {file_path}")
        except Exception as e:
            print(f"실행 중 에러 발생: {e}")
    
    @staticmethod
    def get_count_lines(file_path: str) -> int:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return sum(1 for _ in file)
        except FileNotFoundError:
            print(f"파일을 찾을 수 없습니다: {file_path}")
        except Exception as e:
            print(f"에러가 발생했습니다: {e}")
        return 0

    @staticmethod
    def read_config(config_file_path:str):
        try:
            with open(config_file_path, 'r') as file:
                return [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print("[!] Config not found")
            return []
    
    @staticmethod
    def get_file_list(file_path: str) -> List[str]:
        return [
            os.path.join(root, file)
            for root, _, files in os.walk(file_path)
            for file in files
        ]
    
    @staticmethod
    def get_file_with_keyword(directory_path:str, keyword:str) -> List[str]:
        matching_files = []
        for root, _, files in os.walk(directory_path):
            for file in files:
                if keyword in file:
                    matching_files.append(os.path.join(root, file))

        return matching_files
    
    @staticmethod
    def get_file_with_keywords(directory_path:str, keywords:List) -> List[str]:
        matching_files = []

        for root, _, files in os.walk(directory_path):
            for file in files:
                if any(keyword in file for keyword in keywords):  # 키워드 중 하나라도 포함
                    matching_files.append(os.path.join(root, file))

        return matching_files

    @staticmethod
    def filter_files_by_keyword(file_list:List[str], keyword):
        return [file for file in file_list if keyword in file]
    
    @staticmethod
    def filter_files_by_keywords(file_list:List[str], keywords:List[str]) -> List[str]:
        return [file for file in file_list if any(keyword in file for keyword in keywords)]
    
    @staticmethod
    def get_files_endingwith(file_path: str, keyword:str) -> List[str]:
        return [
            os.path.join(root, file)
            for root, _, files in os.walk(file_path)
            for file in files
            if file.endswith(keyword)
        ]


class PathConverter:
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        for char in INVALID_CHARS:
            filename = filename.replace(char, "_")  # 대체 문자 지정
        return filename
    @staticmethod
    def convert_windows_to_wsl_path(file_path: str) -> str:
        drive, rest_of_path = file_path.split(':', 1)
        backslash_char = '\\'
        return f"/mnt/{drive.lower()}{rest_of_path.replace(backslash_char, '/')}"
    
    @staticmethod
    def convert_wsl_to_windows_path(file_path: str) -> str:
        backslash_char = '\\'
        if file_path.startswith('/mnt/c'):
            return 'C:' + file_path[5:].replace('/', backslash_char)
        if file_path.startswith('./'):
            file_path = file_path[1:]
        return file_path.replace('/', backslash_char)
    
    @staticmethod
    def convert_tar_file_to_windows_path(file_path:str) -> str:
        file_path = file_path.replace('.', '')
        file_path = file_path.replace('/', '\\')
        file_path = file_path.replace('\\\\', '\\')
        return file_path

class StringExtractor:
    @staticmethod
    def extract_keyword_from_output(pattern: str, output: str) -> List[str]:
        matches = re.finditer(pattern, output, re.IGNORECASE)
        return [match for match in matches] if matches else []
    
    @staticmethod
    def extract_version_from_output(output: str) -> List[str]:
        version_pattern = r"(?:Linux version |gcc version |kernel version |Ubuntu version)[^\d]*(\d+\.\d+\.\d+([\-\w.]*))"
        matches = re.finditer(version_pattern, output, re.IGNORECASE)
        return [match.group(0) for match in matches] if matches else ["Version not found"]
    
    @staticmethod
    def extract_binary_data_to_string(file_path:str, min_length=4) -> List[str]:
        with open(file_path, "rb") as f:
            data = f.read()

        # ASCII printable characters 범위 32~126
        current_string = []
        result = []

        for byte in data:
            if 32 <= byte <= 126:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    result.append(''.join(current_string))
                current_string = []

        # 마지막 문자열 추가
        if len(current_string) >= min_length:
            result.append(''.join(current_string))

        # 리스트에 저장된 문자열을 하나로 결합하여 반환
        return ''.join(result)
    
    @staticmethod
    def convert_binary_data_to_string(binary_data: bytes) -> str:

        text = ""
        for byte in binary_data:
            if 32 <= byte <= 126:
                text += chr(byte)
            else:
                text += " "
        return text

class CommandRunner:
    @staticmethod
    def run_wsl_command(command: List[str]) -> Tuple[int, str, str]:
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return result.returncode, result.stdout.decode("utf-8"), result.stderr.decode("utf-8")
        except Exception as e:
            return -1, "", str(e)
        except subprocess.TimeoutExpired:
            return -1, "", "TimeoutExpired"
        
    @staticmethod
    def run_wsl_command_with_Popen(command: List[str], wait_for_completion=True) -> Tuple[int, str, str]:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if wait_for_completion:
                process.wait()
            stdout, stderr = process.communicate()
            return process.returncode, stdout.decode("utf-8"), stderr.decode("utf-8")
        except Exception as e:
            return -1, "", str(e)
        except subprocess.TimeoutExpired:
            return -1, "", "TimeoutExpired"
        
    @staticmethod
    def run_wsl_command_with_input(command: List[str],input: str) -> Tuple[int, str, str]:
        try:
            result = subprocess.run(
                command,
                input=input,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode, result, result.stderr
        except Exception as e:
            return -1, "", str(e)
        except subprocess.TimeoutExpired:
            return -1, "", "TimeoutExpired"
        
class InternetHelper:
    @staticmethod
    def fetch_kernel_info():
            url = "https://www.kernel.org/"
            response = requests.get(url)
            soup = BeautifulSoup(response.content, "html.parser")
            
            kernel_versions = []
            for entry in soup.find_all('a', href=True):
                if 'v' in entry["href"]:
                    version = entry["href"].split('/')[-1]
                    if version.startswith('v'):
                        kernel_versions.append(version[1:])
            
            return kernel_versions
    
    @staticmethod
    def is_internet_connected():
        try:
            response = requests.get("https://www.google.com", timeout=3)
            return response.status_code == 200  # HTTP 200이면 연결됨
        except requests.RequestException:
            return False    
    @staticmethod
    def check_internet_connection():
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError:
            return False

class KernelInspector:

    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def find_eos_version(self, kernel_file_list: List[str]) -> Dict[str, List[str]]:
        """
        This function return the file_ouptut of wsl strings using CommandRunner
        """
        kernel_version_data = {}

        for kernel_file_path in kernel_file_list:
            wsl_path = PathConverter.convert_windows_to_wsl_path(kernel_file_path)
            wsl_exce_list = ["wsl", "-e", "strings", wsl_path]
            returncode, stdout, stderr = CommandRunner.run_wsl_command(wsl_exce_list)

            if returncode == 0:
                version_lines = StringExtractor.extract_version_from_output(stdout)
                kernel_version_data[wsl_path] = version_lines
            else:
                kernel_version_data[wsl_path] = [f"Error: {stderr}" if returncode != -1 else "Unexpected error occurred"]

        return kernel_version_data
    
    #NOTE: 2025-02-03 log 파일 기준으로 커널 버전 같은걸 확인할 필요가 있어 보임
    def extract_versioninfo_from_log_file(self):
        platform = detect_platform()
        if platform == "win":
            log_dir = self.output_dir+"\\Logs"
            extract_log_file = log_dir+"\\extract.log"
            binwalk_log_file = log_dir+"\\binwalk.log"

        elif platform == "darwin":
            log_dir = self.output_dir+"/Logs"
            extract_log_file = log_dir+"/extract.log"
            binwalk_log_file = log_dir+"/binwalk.log"

        elif platform == "linux":
            log_dir = self.output_dir+"/Logs"
            extract_log_file = log_dir+"/extract.log"
            binwalk_log_file = log_dir+"/binwalk.log"
        
        #NOTE: 2025-02-03 kernel 데이터 추출 구현
        # 그리고 어떻게 log 파일 내에서 여러 버전정보중에 알맞게 찾을건가
        if os.path.isdir(log_dir):
            kernel_file = RegexUtils.grep_matched_files(extract_log_file,[r"kernel found",r"linux kernel version"])
            if kernel_file:
                kernel_version = self.extract_latest_kernel_version(binwalk_log_file)
                if kernel_version:
                    print("현재 kernel 버전 정보가 존재")
                    print(f"현재 커널 버전 : {kernel_version}")
                    return kernel_version
            else:
                print("Kernel file not found")
        else:
            print("Log directory Not Found")

        return None
    
    @staticmethod
    def extract_latest_kernel_version(log_file):
        latest_scan_time = None
        latest_kernel_version = None

        lines = FileHandler.get_file_lines(log_file)

        scan_time = None
        kernel_version = None

        for line in lines:
            # Scan Time 추출
            scan_match = re.search(r"Scan Time:\s+([\d-]+ \d{2}:\d{2}:\d{2})", line)
            if scan_match:
                scan_time = datetime.strptime(scan_match.group(1), "%Y-%m-%d %H:%M:%S")

            # Kernel version 추출
            kernel_match = re.search(r"(\d+)\s+0x[0-9A-Fa-f]+\s+Linux kernel version ([\d.]+)", line)
            if kernel_match:
                kernel_version = kernel_match.group(2)

        # 최신 스캔 로그인지 확인
        if scan_time and kernel_version:
            if latest_scan_time is None or scan_time > latest_scan_time:
                latest_scan_time = scan_time
                latest_kernel_version = kernel_version

        return latest_kernel_version
    
    @staticmethod
    def extract_linux_version(version_info: Dict[str, List[str]]) -> str:
        for path, versions in version_info.items():
            for version in versions:
                temp_data = version.split()
                if len(temp_data) > 2 and temp_data[0].lower() == "linux":
                    print(temp_data[2])
                    return temp_data[2]
        return ""

    @staticmethod
    def check_eos_status(kernel_version: str) -> str:
    
        lts_versions = InternetHelper.fetch_kernel_info()

        if any(lts_version in kernel_version for lts_version in lts_versions):
            print(f"{kernel_version} is an LTS version.")
            return "Not EOS"
        
        lts_versions.append(kernel_version)
        lts_versions.sort()

        if kernel_version == lts_versions[0]:
            print(f"{kernel_version} is lower than the latest version ({lts_versions[1]}).")
            return "EOS"
        
        print(f"{kernel_version} isn't EOS version.")

        return "Not EOS"
    
class CompressedFileInspector:

    def __init__(self, directory, extensions=(".tar", ".tar.gz", ".zip")):
        self.directory = directory
        self.extensions = extensions

    def __find_compressed_files(self) -> list[str]:

        return [
            os.path.join(root, file)
            for root, _, files in os.walk(self.directory)
            for file in files
            if file.endswith(self.extensions)
        ]

    def __find_keywords_compressed_files(self, file_path:str, keywords:List[str], mode) -> List[str]:

        matching_files = [(name,perm) for name,perm in self.__get_all_files_from_compressed(file_path,mode) if any(keyword in name for keyword in keywords)]
        return matching_files
    
    @staticmethod
    def __get_all_files_from_compressed(file_path: str, mode: str) -> List[str]:

        all_files = []
        try:
            if file_path.endswith('.zip'):
                with zipfile.ZipFile(file_path, mode) as zip:
                    all_files = zip.namelist()

            elif file_path.endswith(('.tar', '.tar.gz')):
                with tarfile.open(file_path, mode) as tar:
                    all_files = [(member.name,member.mode) for member in tar.getmembers() ]
                
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
        return all_files
    
    def get_all_files(self) -> Dict[str, List[str]]:
        """
        List all files in all compressed files in the specified directory.
        """
        compressed_files = self.__find_compressed_files()
        all_files_in_compressed = {}

        for file_path in compressed_files:
            ext = os.path.splitext(file_path)[-1].lower()
            mode = "r:gz" if ext == ".tar.gz" else 'r'
            all_files_in_compressed[file_path] = self.__get_all_files_from_compressed(file_path, mode)

        return all_files_in_compressed
    
    def __process_compressed_file(self, file_path:str, keywords:List[str], mode) -> Dict:

        result = {
            "file_path": file_path,
            "keyword_found": [],
            "errors": None
        }
        keyword_files = self.__find_keywords_compressed_files(file_path, keywords, mode)
        try:
            if file_path.endswith('.zip'):
                for spec_file in keyword_files:
                    with zipfile.ZipFile.open(spec_file) as file:
                        result["keyword_found"].append({
                            "file_name": spec_file,
                            "file_mode" : 0,
                            "content": file.read().decode(encoding="utf-8").splitlines()
                        })

            elif file_path.endswith(('.tar', '.tar.gz')):
                with tarfile.open(file_path, mode) as tar:
                    for spec_file in keyword_files:
                        # print(spec_file.name , spec_file.mode)
                        with tar.extractfile(spec_file[0]) as file:
                            # NOTE: 바이너리 파일이면 따로 처리 해줘야함
                            # NOTE: 이부분 아마 yara파일로 탐지할거면 중간에 지우는게 나을듯?
                            content = StringExtractor.convert_binary_data_to_string(file.read())
                            result["keyword_found"].append({
                                "file_name": spec_file[0],
                                "file_mode" : oct(spec_file[1])[2:],
                                "content": content
                            })

        except Exception as e:
            result["errors"] = str(e)
        return result
    
    def scan_compress_file_with_yara(self,compress_file_path:str, yara_rule):
        if compress_file_path.endswith('.zip'):
            with zipfile.ZipFile(compress_file_path, "r") as zip_file:
                for filename in zip_file.namelist(): 
                    with zip_file.open(filename) as file:
                        try:
                            file_data = file.read()
                            matches = yara.compile(filepath=yara_rule).match(data=file_data)
                            if matches:
                                print(f"Found match in: {filename}")
                            else:
                                print(f"No match in: {filename}")
                        except Exception as e:
                            print(f"Error reading {filename}: {e}")

        if compress_file_path.endswith(('.tar', '.tar.gz')):
            with tarfile.open(compress_file_path, "r") as tar:
                for member in tar.getmembers():
                    # member.name이 파일일 경우 검사
                    if member.isfile():
                        file = tar.extractfile(member)
                        # YARA로 검사
                        matches = yara.compile(filepath=yara_rule).match(data=file.read())
                        if matches:
                            print(f"Found match: file_mode={oct(member.mode)[2:]} file_name={member.name}")

    def inspect_compressed_files(self, keywords) -> List[Dict]:
        compressed_files = self.__find_compressed_files()
        results = []

        for file_path in compressed_files:
            ext = os.path.splitext(file_path)[-1].lower()
            mode = "r:gz" if ext == ".tar.gz" else 'r'
            results.append(self.__process_compressed_file(file_path, keywords, mode))
        
        return results
    
    def get_keyword_files_from_compressed(self, keywords:List[str]) -> List[Dict]:

        compressed_files = self.__find_compressed_files()
        files_cont_spec_keywords = []
        for file_path in compressed_files:
            ext = os.path.splitext(file_path)[-1].lower()
            mode = "r:gz" if ext == ".tar.gz" else 'r'
            files_cont_spec_keywords = self.__find_keywords_compressed_files(file_path, keywords, mode)[0]

        return files_cont_spec_keywords
    
class KeywordChecker:
    @staticmethod
    def check_keyword_in_content(file_data, keyword) -> bool:
        """Check if a specific keyword exists in the file content."""
        for data in file_data.get("keyword_found",[]):
            if any(keyword in re.split(r"\s+", line.strip()) for line in data.get("content", [])):
                return True
        return False

    @staticmethod
    def check_files_for_keyword(file_datas: list[dict], keyword: str) -> bool:
        """Iterate through all file data to check for the keyword."""
        for file_data in file_datas:
            if KeywordChecker.check_keyword_in_content(file_data, keyword):
                return True
        return False

class Unpacker():
    @staticmethod
    def unpack_tar_file_on_windows(compress_file_path:str):
        unpack_exec_list = ["powershell", "tar", "-xvzf", compress_file_path]
        returncode, stdout, stderr = CommandRunner.run_wsl_command(unpack_exec_list)

        if returncode == 0:
            print(f"Completed fileExtract {stdout}")
        else:
            print(f"Occured Error {stderr}")

    #NOTE: 만약에 /Extract 디렉토리 이름이 바뀔수도 있으니 동적으로 바꾸는 방법이나 되게 하는 방법을 생각해볼 필요가 있음
    @staticmethod
    def unpack_tar_file_on_wsl(compress_file_path:str, dir_path:str):
        compress_file_path = PathConverter.convert_windows_to_wsl_path(compress_file_path)
        dir_path = PathConverter.convert_windows_to_wsl_path(dir_path)+"/Extract"
        unpack_exec_list = ["wsl", "-e", "tar", "-zxvf", compress_file_path, "-C", dir_path]
        returncode, stdout, stderr = CommandRunner.run_wsl_command(unpack_exec_list)
        
        if returncode == 0:
            print(f"Completed fileExtract {stdout}")
        else:
            print(f"Occured Error {stderr}")
            
    @staticmethod
    def unpack_tar_file_on_python(compress_file_path:str, extract_to:str):
        error_list = []
        zero_size_file_list = []
        try:
            with tarfile.open(compress_file_path, "r:*") as tar:
                for member in tar.getmembers():
                    try:
                        original_name = member.name  
                        sanitized_name = PathConverter.sanitize_filename(original_name)

                        # 안전한 파일 경로 설정
                        extracted_path = os.path.join(extract_to, original_name)
                        safe_extracted_path = os.path.join(extract_to, sanitized_name)

                        tar.extract(member, path=extract_to, numeric_owner=True)
                        # 파일명 변경 (원본 → 안전한 이름)
                        if original_name != sanitized_name:
                            os.rename(extracted_path, safe_extracted_path)

                        safe_extracted_path = PathConverter.convert_tar_file_to_windows_path(safe_extracted_path)

                        print(f"파일 UID: {member.uid}, GID: {member.gid}, 권한: {oct(member.mode)[2:]}, 크기: {member.size}")
                        if member.size == 0:
                            zero_size_file_list.append(safe_extracted_path)

                        print(f"추출 완료: {safe_extracted_path}\n")

                    except PermissionError as perm_err:
                        print(f"권한 오류:{member.name} - 접근할 수 없습니다. 건너뜁니다.")
                        error_list.append(member.name)
                        continue

                    except Exception as file_error:
                        print(f"❌ 파일 {member.name} 추출 중 오류 발생: {file_error}")
                        continue  # 특정 파일에서 오류 발생 시 건너뛰고 계속 진행

        except Exception as e:
            print(f"❌ TAR 파일 처리 중 오류 발생: {e}")
        
        if error_list:
            print(f"\n 다음 파일들은 권한 문제로 인해 추출되지 않았습니다")
            for err_file in error_list:
                print(f" - {err_file}")
        
        return [error_list,zero_size_file_list]

class Spliter():

    def split_file_content(file_list:List[str]) -> None:
        for file in file_list:
            print(file)

    def split_tar_file_name(file_path: str) -> str:
        file_name = os.path.basename(file_path)
        name_without_ext = os.path.splitext(file_name)[0]

        return name_without_ext



class RegexUtils:

    @staticmethod
    def compile_patterns(patterns: List[str]) -> re.Pattern:
        return re.compile("|".join(patterns))
    
    @staticmethod
    def grep_matched_files(file_path:str, regex_patterns:list[str]) -> list[str]:
        """Search for regex patterns in a file."""
        matches = []
        try:
            with open(file_path, "r", encoding="utf-8",errors="ignore") as file:
                for line in file:
                    for pattern in regex_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            matches.append(line.strip())
        except (FileNotFoundError, UnicodeDecodeError):
            pass
        return matches

    @staticmethod
    def grep_matched_compreessed_files(file_content, regex_patterns: list[str]):
        matches = []
        if file_content:
            for line in file_content:
                # 만약 line이 bytes라면 디코딩, 아니라면 그대로 사용
                if isinstance(line, bytes):
                    line = line.decode(errors="ignore")
                line = line.strip()
                for pattern in regex_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        matches.append(line)
        return matches

class PasswordFilesChecker():

    def __init__(self,base_path:str):
        self.base_path = base_path
        self.patterns = [
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$1\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{8}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{22}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$5\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{16}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{42}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$6\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{8}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{86}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$6\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{12}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{86}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$6\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{16}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{86}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$2[abxy]\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{22}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{31}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$y\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{3}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{22}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{43}"
        ]

    def find_files_by_pattern(self, patterns:List[str]) -> List[str]:
        """Search for files in the base_path matching patterns."""
        matches = []
        for root, _, files in os.walk(self.base_path):
            for file_name in files:
                for pattern in patterns:
                    if re.search(pattern, file_name):
                        matches.append(os.path.join(root, file_name))
        return matches


    @staticmethod
    def find_root_accounts(file_path:str) -> List[str]:
        """Find root accounts in a password file."""
        try:
            with open(file_path, "r") as file:
                return [line.split(":")[0] for line in file if line.split(":")[2] == "0"]
        except (FileNotFoundError, IndexError):
            return []
    
    @staticmethod
    def crack_password_list(firm_ware_dir: str, word_list_file: str):

        # WSL 경로로 변환
        word_list_file = PathConverter.convert_windows_to_wsl_path(word_list_file)
        crypt_list = ["descrypt", "bsdicrypt", "md5crypt", "bcrypt", "LM", "AFS", "tripcode", "dummy", "crypt"]
        target_files = FileHandler.get_file_with_keywords(firm_ware_dir, ["passwd", "shadow"])
        cracked_result_file = []

        for target_file in target_files:
            save_path = PathConverter.convert_windows_to_wsl_path(target_file)
            mimetype, _ = mimetypes.guess_type(target_file)

            if mimetype is not None and not mimetype.startswith("text"):
                print(f"[-] Skipping binary file: {target_file} (MIME type: {mimetype})")
                continue

            binary_exts = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".exe", ".bin",".so")
            if target_file.lower().endswith(binary_exts):
                print(f"[-] Skipping file with binary extension: {target_file}")
                continue

            if not os.path.isfile(target_file) or os.path.getsize(target_file) == 0:
                print(f"[-] Skipping file (not a valid file or empty): {target_file}")
                continue
            print(f"\n [+] Processing file: {target_file}")
            cracked = False

            content = FileHandler.get_file_data(target_file)

            if Validator.is_valid_passwd_file(content) or Validator.is_valid_shadow_file(content):
                for crypt_type in crypt_list:
                    print(f"    Trying format: {crypt_type} for {target_file}")
                    crack_command = ["wsl", "john", f"--format={crypt_type}", f"--wordlist={word_list_file}", save_path]
                    CommandRunner.run_wsl_command_with_Popen(crack_command)

                    # 각 암호 형식 실행 후 즉시 결과 확인
                    show_command = ["wsl", "john", "--show", save_path]
                    _, show_stdout, _ = CommandRunner.run_wsl_command_with_Popen(show_command)
                    
                    # john --show 출력에서 크래킹된 해시 개수를 확인
                    matches_result = re.search(r"(\d+) password hash(?:es)? cracked", show_stdout)
                    if matches_result:
                        cracked_count = int(matches_result.group(1))
                        if cracked_count > 0:
                            print(f"[+] Cracked file: {target_file} using format {crypt_type} ({cracked_count} hashes cracked)")
                            credentials = []
                            for line in show_stdout.splitlines():
                                if ":" in line and not line.startswith("Loaded") and not line.startswith("No password hashes cracked"):
                                    parts = line.split(":")
                                    if len(parts) >= 2:
                                        user = parts[0].strip()
                                        pwd = parts[1].strip()
                                        credentials.append((user, pwd))
                            if credentials:
                                print("    Cracked credentials:")
                                for user, pwd in credentials:
                                    print(f"      User: {user}, Password: {pwd}")
                            
                            cracked_result_file.append(target_file)
                            cracked = True
                            break
                    else:
                        print(f" No hashes cracked with format {crypt_type} for {target_file}")

            if not cracked:
                print(f"[-] Could not crack file: {target_file}")

        return cracked_result_file

    
    @staticmethod
    def check_cracked_file(op_file:str):
        op_file = PathConverter.convert_windows_to_wsl_path(op_file)

        check_command = ["wsl", "john", "--show", op_file]
        cracked_file_result = CommandRunner.run_wsl_command(check_command)
        user_list = StringExtractor.extract_keyword_from_output(r"password hash cracked",cracked_file_result[1])
        print(user_list)

    
    # Tarfile Standard 
    def analyze_password_files_on_tarfile(self,dir_path:str):
        #NOTE: 이 tar의 이름이 달라질 수 도 있음
        compress_file_path = FileHandler.get_files_endingwith(dir_path,'tar.gz')[0]
        possible_passwords = []
        possible_shadows = []
        if compress_file_path:
            try:
                with tarfile.open(compress_file_path, "r") as tar:
                    for member in tar.getmembers():
                        if member.isfile():
                            file = tar.extractfile(member.name)
                            possible_passwords = RegexUtils.grep_matched_compreessed_files(file,[r"^[a-zA-Z0-9]+:[a-zA-Z0-9!#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~]*:[0-9]+:[0-9]+(:[^:]*){3}$"])
                            possible_shadows = RegexUtils.grep_matched_compreessed_files(file,[r"^[a-zA-Z0-9]+:\$[0-9a-z]\$.*:[0-9]+:[0-9]+:[0-9]+([^:]*:){4}[^:]*"])

                        if possible_passwords or possible_shadows:
                            print(f"[+] Found password-related files:{possible_passwords} , {possible_shadows}")
                            print("[+] Found possible passwords or weak configurations:")
                            if possible_shadows:
                                print("  Shadows:")
                                for shadow in possible_shadows:
                                    print(f"    {shadow}")
                            if possible_passwords:
                                print("  Passwords:")
                                for passwd in possible_passwords:
                                    print(f"    {passwd}")
                            possible_passwords.clear()
                            possible_shadows.clear()
            except Exception as e:
                    print(f"Exception = {e}")
                    pass

            sudoers_paths = self.find_files_by_pattern([r"sudoers"])
            if sudoers_paths:
                print("[+] Sudoers configuration:")
                for sudoer in sudoers_paths:
                    print(f"  {sudoer}")

    #NOTE: 압축해제 파일 기준
    def analyze_password_files(self,dir_path:str):
        target_files = FileHandler.get_file_with_keywords(dir_path, ["passwd", "shadow"])
        possible_passwords = []
        possible_shadows = []
        
        for file_path in target_files:
            try:
                # 파일을 텍스트 모드로 열어서 읽습니다.
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    # 파일 내용을 문자열로 읽어옵니다.
                    content = f.read()
                    
                    # RegexUtils.grep_matched_compreessed_files 함수가 파일 객체를 받았다면
                    # 아래처럼 파일 객체를 넘겨주거나, content.splitlines()로 리스트를 넘겨줄 수도 있습니다.
                    possible_passwords = RegexUtils.grep_matched_compreessed_files(
                        content, 
                        [r"^[a-zA-Z0-9]+:[a-zA-Z0-9!#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~]*:[0-9]+:[0-9]+(:[^:]*){3}$"]
                    )
                    possible_shadows = RegexUtils.grep_matched_compreessed_files(
                        content, 
                        [r"^[a-zA-Z0-9]+:\$[0-9a-z]\$.*:[0-9]+:[0-9]+:[0-9]+([^:]*:){4}[^:]*"]
                    )
            except Exception as e:
                print(f"Exception reading file {file_path}: {e}")
                continue

            if possible_passwords or possible_shadows:
                print(f"[+] Found password-related file: {file_path}")
                print("[+] Found possible passwords or weak configurations:")
                if possible_shadows:
                    print("  Shadows:")
                    for shadow in possible_shadows:
                        print(f"    {shadow}")
                if possible_passwords:
                    print("  Passwords:")
                    for passwd in possible_passwords:
                        print(f"    {passwd}")
                possible_passwords.clear()
                possible_shadows.clear()

        sudoers_paths = self.find_files_by_pattern([r"sudoers"])
        if sudoers_paths:
            print("[+] Sudoers configuration:")
            for sudoer in sudoers_paths:
                print(f"  {sudoer}")

class Validator():
    @staticmethod
    def is_fstab_format(file_data: list) -> bool:
        """
        파일 데이터가 fstab 형식을 따르는지 검사하는 함수.
        - 최소 3개의 필드가 존재해야 하며,
        - 두번째 필드가 절대경로 ("/"로 시작) 또는 "none"이면 유효한 라인으로 판단.
        """
        valid_line_count = 0
        total_line_count = 0
        for line in file_data:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total_line_count += 1
            fields = line.split()
            if len(fields) < 3:
                continue
            if not (fields[1].startswith("/") or fields[1].lower() == "none"):
                continue
            valid_line_count += 1

        if total_line_count == 0:
            return False
        return valid_line_count / total_line_count >= 0.5
    
    @staticmethod
    def is_valid_passwd_file(content: str) -> bool:
        if not content:
            return False
        
        lines = content.splitlines()
        compromised = 0
        total = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total += 1
            fields = line.split(":")
            if len(fields) < 2:
                continue
            pwd_field = fields[1].strip()
            if pwd_field == "" or (not pwd_field.startswith("$") and pwd_field not in ("x", "*", "!")):
                compromised += 1
        return total > 0 and (compromised / total) > 0.5
    
    def is_valid_shadow_file(content: str) -> bool:
        if not content:
            return False
        lines = content.splitlines()
        compromised = 0
        total = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total += 1
            fields = line.split(":")
            if len(fields) < 2:
                continue
            pwd_field = fields[1].strip()
            if pwd_field == "" or not pwd_field.startswith("$"):
                compromised += 1
        return total > 0 and (compromised / total) > 0.5

def check_rw(output_dir: str, keyword="rw") -> bool:
    """Main function to check for 'rw' in the content of compressed files."""
    inspector = CompressedFileInspector(output_dir)                                                                                                  
    file_datas = inspector.inspect_compressed_files(["fstab"])
    return KeywordChecker.check_files_for_keyword(file_datas, keyword)

def parse_openssl_output(cert_path):
    parse_openssl_cmd = ["wsl", "-e", "openssl", "x509", "-noout", "-text", "-in", cert_path]
    parse_return_code, output, error = CommandRunner.run_wsl_command(parse_openssl_cmd)
    if parse_return_code != 0:
        return output
    return error

def show_fstab_file_info(dir_path: str):
    fstab_files = FileHandler.get_file_with_keyword(dir_path, "fstab")
    for fstab_file in fstab_files:
        print("[+] Found fstab keyword file:", fstab_file)
        file_data = FileHandler.get_file_lines(fstab_file)
        
        if not Validator.is_fstab_format(file_data):
            print("[!] Warning: The file does not appear to be in fstab format.")
            continue

        table_data = []
        for line in file_data:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            fields = line.split()
            while len(fields) < 6:
                fields.append("0")
            device, mount_point, file_system_type, mount_option, dump, pass_option = fields[:6]

            # 마운트 옵션을 쉼표로 분리하여 "rw" 옵션이 있는지 확인
            options = mount_option.split(',')
            writable = "Yes" if "rw" in options else "No"

            # "rw"가 있을 경우 경고 메시지 출력
            if writable == "Yes":
                print(f"[!] Warning: Writable mount option (rw) detected on mount point {mount_point}.")

            # 각 행에 writable 정보 추가
            table_data.append([device, mount_point, file_system_type, mount_option, dump, pass_option, writable])
        
        headers = ["Device", "Mount Point", "File System", "Mount Option", "Dump", "Pass", "Writable"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))



def make_tar_dir(tar_file:str) -> str:
    """
    선택한 디렉토리 내부 root0fs.tar.gz에 관한 root0fs.tar 폴더생성함수
    """
    compress_direct_dir = os.path.dirname(tar_file)
    if os.path.isdir(compress_direct_dir):
        maked_compress_dir = compress_direct_dir+"\\"+Spliter.split_tar_file_name(tar_file)
        try:
            if not os.path.exists(maked_compress_dir):
                os.mkdir(maked_compress_dir)
            return maked_compress_dir
        except FileNotFoundError as e:
            print(f"파일 생성중 오류 발생 : {e}")
        except Exception as e:
            print(f"예상치 못한 에러 발생 : {e}")
    return ""

def print_fstab_info(dir_path:str):
    keywords_file_list = FileHandler.get_file_with_keywords(dir_path,["fstab"])
    if keywords_file_list:
        for file in keywords_file_list:
            file_content = FileHandler.get_file_lines(file)
            print(file_content)

def get_device_info(log_entry:str) -> Dict:

    parts = log_entry.split("|")
    if len(parts) < 4:
        return {}

    id_field = parts[0].strip()
    dummy_field = parts[1].strip()  # 필요에 따라 사용
    kernel_info = parts[2].strip()
    elf_info = parts[3].strip()

    kernel_version = kernel_info.replace("Linux kernel version", "").strip()

    elf_parts = [p.strip() for p in elf_info.split(",")]
    elf_header = elf_parts[0] if elf_parts else ""
    header_tokens = elf_header.split()
    bitness = header_tokens[1] if len(header_tokens) > 1 else ""
    endianness = header_tokens[2] if len(header_tokens) > 2 else ""
    file_type = " ".join(header_tokens[3:]) if len(header_tokens) > 3 else ""
    architecture = elf_parts[1] if len(elf_parts) > 1 else ""

    additional_info = elf_parts[2:] if len(elf_parts) > 2 else []

    return {
        "ID": id_field,
        "Kernel Version": kernel_version,
        "Bitness": bitness,
        "Endianness": endianness,
        "File Type": file_type,
        "Architecture": architecture,
        "Additional Info": additional_info
    }

def print_device_info(log_file_path:str):
    log_entries = FileHandler.get_file_lines(log_file_path)

    table_data = []

    for log in log_entries:
        parsed = get_device_info(log)
        if not parsed:
            print(f"[!] Warning: 파싱에 실패한 로그 항목: {log}")
            continue

        table_data.append([
            parsed.get("ID"),
            parsed.get("Kernel Version"),
            parsed.get("Bitness"),
            parsed.get("Endianness"),
            parsed.get("File Type"),
            parsed.get("Architecture"),
            ", ".join(parsed.get("Additional Info", []))
        ])

    headers = ["ID", "Kernel Version", "Bitness", "Endianness", "File Type", "Architecture", "Additional Info"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

def main() :
    ## 1. 커널 추출 시 EoS(End of Service) 버전인지 점검

    # 방법 1
    print("\n 추출된 펌웨어 파일들 압축해제 \n")
    window_path = sys.argv[1]
    mac_path = "Your mac path"

    #NOTE: 다른이름의 tar.gz파일이 들어올 수도 있음 이게 문제임 ....
    root_tar_file = FileHandler.get_files_endingwith(window_path,'tar.gz')[0]
    if root_tar_file:
        unpacked_dir = make_tar_dir(root_tar_file)
        if unpacked_dir:
            non_unpacked_list = Unpacker.unpack_tar_file_on_python(root_tar_file,unpacked_dir)

    #NOTE: 2025-02-17 압축을 푸는것까지 완료했음 이름이랑, 정보 뿌리는거 해결할것 그리고 전체적으로 구조를 바꿔야댐
    kernel_inspector = KernelInspector(window_path)
    
    # 인터넷 안될 때는 가지고 있는 version_list를 기준으로 파악한다
    print("해당 커널 버전 관련 EOS 체크")
    kernel_latest = kernel_inspector.extract_versioninfo_from_log_file()
    if kernel_latest:
        if InternetHelper.is_internet_connected():
            result = kernel_inspector.check_eos_status(kernel_latest)
            print(result)
        else:
            kernel_list = FileHandler.get_file_lines("C:\\Users\\raon\\Park\\electron-app\\siege\\kernel_version_list")
            kernel_list.append(kernel_latest)
            kernel_list.sort()
            if kernel_list[0] == kernel_latest:
                print("EOS")

    #방법2
    print("\n/etc/passwd 및 /etc/shadow 파일 존재 시 추측하기 쉬운 비밀번호를 사용 중인지 점검\n")

    ## 2. /etc/passwd 및 /etc/shadow 파일 존재 시 추측하기 쉬운 비밀번호를 사용 중인지 점검
    #NOTE: passwordlist를 wsl 설치 패키지 내에 포함해야할 수도 있음
    password_list = "C:\\Users\\raon\\Park\\electron-app\\passwordlist.txt"
    path_file = ""
    if platform.system() == "Windows":
        path_file = window_path
    elif platform.system() == "Darwin":
        path_file = mac_path
    elif is_wsl():
        path_file = PathConverter.convert_windows_to_wsl_path(window_path)

    passwordchecker = PasswordFilesChecker(path_file)
    print("password cracking~\n")
    passwordchecker.analyze_password_files(path_file)
    print(PasswordFilesChecker.crack_password_list(path_file,password_list))

    # NOTE: 2025-01-29 /etc/login.defs에서 확인 해야함

    """
    #NOTE: 압축 풀린곳에서 inspector로 키워드가 존재하는 파일의 output이 출력이 가능하고 
    # 그 해당 output에서 regex를 이용하여 특정 키워드가 존재하는지 파악가능
    """

    ## 3. fstab 파일 존재 시 중요 파일시스템의 쓰기 허용 여부 점검
    print("\nfstab 파일 존재 시 중요 파일시스템의 쓰기 허용 여부 점검\n")
    show_fstab_file_info(path_file)

    # config_file_list = FileHandler.filter_files_by_keywords(extract_file_list,["id_rsa",".pem",".crt","shadow"])
    print("\n추출된 파일 내에 cloud 및 다른 디바이스, 시스템 접속 인증 정보 포함 여부 점검",end='\n')

    cloud_related_files = [
        "mysqld.cnf","login_def","redis.conf","mongod.conf","docker","daemon.json","sshd_config","etcd.yaml","glance-api.conf","glance",
        "schema","system-auth","pwquality.conf","common-password","system-auth","aws","credentials","gcloud","credentials.db", "config_default",
        ".azure", ".bluemix", ".oci", "doctl", ".aliyun", "linode-cli","openstack", "hcloud", ".tencentcloudcli",".pem", "authorized_keys",
        "id_dsa", "id_rsa", ".crt","pg_hba.conf","aws","gcloud","amazon"
    ]


    print("클라우드 관련 파일")
    filter_keywords = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico")
    all_files = FileHandler.get_file_with_keywords(path_file, cloud_related_files)
    filtered_files = [f for f in all_files if not f.lower().endswith(filter_keywords)]
    print(filtered_files,end='\n')

    checked_yar_file = "C:\\Users\\raon\\Park\\electron-app\\yara\\generic.yar"
    signatures_yar_file = "C:\\Users\\raon\\Park\\electron-app\\yara\\signatures.yar"


    # file_path = "C:\\Users\\raon\\Park\\siege_test_folder\\Netis_WF2780_EN_V1.2.27882_1\\Extract\\rootfs0.tar\\etc\\linuxigd"

    # with open(file_path, 'rb') as file_handle:
    #     # 플러그인 인스턴스 생성
    #     plugin = AnalysisPluginV0()

    #     # 필요에 따라 virtual_file_path와 analyses 값을 지정
    #     virtual_file_path = file_path  
    #     analyses = {}

    #     # analyze 메서드 호출하여 결과(Pydantic 모델)를 받음
    #     result = plugin.analyze(file_handle, virtual_file_path, analyses)

    #     # 결과 요약 출력
    #     summary = plugin.summarize(result)
    #     print("분석 결과 요약:", summary)

    comp_inspector = CompressedFileInspector(path_file)
    print("\n인증 키에 대한 match정보 확인",end='\n')
    comp_inspector.scan_compress_file_with_yara(FileHandler.get_files_endingwith(path_file,'tar.gz')[0],checked_yar_file)

    print("\n암호화 관련 파일 탐지",end='\n')
    comp_inspector.scan_compress_file_with_yara(FileHandler.get_files_endingwith(path_file,'tar.gz')[0],signatures_yar_file)

    # Device 정보
    result_log_path = path_file+"\\extract_result"

    print("\n해당 디바이스 정보")
    print_device_info(result_log_path)

if __name__ == "__main__":
    main()
    