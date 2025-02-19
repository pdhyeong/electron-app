import os
import stat
import re
import sys
import tarfile
import zipfile
import subprocess
import platform
import yara
import socket
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Union

INVALID_CHARS = '<>:"\\|?*'

def is_wsl():
    try:
        with open("/proc/version", "r") as f:
            content = f.read().lower()
            return "microsoft" in content
    except FileNotFoundError:
        return False

if sys.platform.startswith("win"):
    import requests
    from bs4 import BeautifulSoup
elif is_wsl():
    print("Running on WSL")
    import crypt

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
                    print(f"{kernel_version}")
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
                        else:
                            print(f"No match: file_mode={oct(member.mode)[2:]} file_name={member.name}")

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
        with tarfile.open(compress_file_path, "r:*") as tar:
            for member in tar.getmembers():
                original_name = member.name  
                sanitized_name = PathConverter.sanitize_filename(original_name)
                
                member.name = sanitized_name
                tar.extract(member, path=extract_to, numeric_owner=True) 

                print(f"파일 uid: {member.uid} 파일 gid:{member.gid} 파일 권한 : {oct(member.mode)[2:]} 파일 크기 : {member.size}")
                print(f"추출 완료: {extract_to + PathConverter.convert_wsl_to_windows_path(sanitized_name)}",end='\n\n')

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
    def grep_matched_compreessed_files(tar_file, regex_patterns:list[str]):
        matches = []
        if tar_file:
            for line in tar_file:
                line = line.decode(errors="ignore").strip()
                for pattern in regex_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        matches.append(line.strip())
        return matches

class HashSearcher():

    def __init__(self):
        self.patterns = [
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$1\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{8}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{22}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$5\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{16}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{42}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$6\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{8}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{86}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$6\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{12}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{86}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$6\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{16}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{86}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$2[abxy]\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{22}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{31}",
            r"[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]+:\$y\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{3}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{22}\$[a-zA-Z0-9!\"#$%&'()*+,-./:;<=>?@[\\^_`{|}~]{43}"
        ]
        self.regex = RegexUtils.compile_patterns(self.patterns)
    
    # Windows에서 열수없는 파일들은 Exception로 감....
    def search_hash_files(self,passwd_file_path:str) -> List[Tuple[str,str]]:
        try:
            with open(passwd_file_path, "r", errors="ignore") as f:
                content = StringExtractor.convert_binary_data_to_string(f.read())
                matches = self.regex.findall(content)
                if matches:
                    return [(passwd_file_path, match) for match in matches]
        except Exception as e:
            print(f"Error reading file {passwd_file_path}: {e}")
        return []


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
    def crack_password_list(firm_ware_dir: str, word_list_file:str):
        word_list_file = PathConverter.convert_windows_to_wsl_path(word_list_file)

        crypt_list = ["descrypt","bsdicrypt","md5crypt","bcrypt","LM","AFS","tripcode","dummy","crypt"]
        target_files = ["./etc/shadow","./etc/passwd","/default/passwd"]
        crack_result_data = []
        tar_path = FileHandler.get_files_endingwith(firm_ware_dir,'tar.gz')[0]

        with tarfile.open(tar_path, "r") as tar:
        # 특정 파일 찾기
            related_files_with_passwd = [member.name for member in tar.getmembers() if member.name in target_files]
            for target_file in related_files_with_passwd:
                file_obj = tar.extractfile(target_file)
                if file_obj:
                    content = file_obj.read().decode('utf-8')
                    save_path = f"{firm_ware_dir}\\temp_file.txt"
                    try:
                        with open(save_path,'w') as file:
                            file.write(content)
                    except Exception as e:
                        print(f"파일 저장 중 오류발생 {e}")
                        if os.path.exists(save_path):
                            os.remove(save_path)
                            print(f"{save_path} 파일 삭제")
                    save_path = PathConverter.convert_windows_to_wsl_path(save_path)
                    for crypt_type in crypt_list:
                        crack_command = ["wsl", "john", f"--format={crypt_type}", f"--wordlist={word_list_file}", save_path]
                        _, crack_stdout, _ = CommandRunner.run_wsl_command(crack_command)
                        if "Loaded" in crack_stdout:
                            show_command = ["wsl", "john", "--show", save_path]
                            _, show_stdout,_ = CommandRunner.run_wsl_command(show_command)
                            matches_result = re.search(r"(\d+) password hashes cracked",show_stdout)
                            if matches_result:
                                cracked_count = int(matches_result.group(1))
                                if cracked_count > 0:
                                    print("cracked password")
        
        save_path = f"{firm_ware_dir}\\temp_file.txt"
        if os.path.exists(save_path):
            os.remove(save_path)
            print(f"{save_path} 파일 삭제")

        return crack_result_data
    
    @staticmethod
    def crack_password_list2(firm_ware_dir: str, word_list_file:str):
        word_list_file = PathConverter.convert_windows_to_wsl_path(word_list_file)

        crypt_list = ["descrypt","bsdicrypt","md5crypt","bcrypt","LM","AFS","tripcode","dummy","crypt"]
        target_files = FileHandler.get_file_with_keywords(firm_ware_dir,["passwd","shadow"])
        crack_result_data = []
        tar_path = FileHandler.get_files_endingwith(firm_ware_dir,'tar.gz')[0]

        
        for target_file in target_files:
            try:
                with open(target_file, 'r', encoding='utf-8') as file:
                    content = file.read()
                save_path = f"{firm_ware_dir}\\temp_file.txt"
                with open(save_path,'w') as file:
                    file.write(content)
            except Exception as e:
                print(f"파일 저장 중 오류발생 {e}")
                if os.path.exists(save_path):
                    os.remove(save_path)
                    print(f"{save_path} 파일 삭제")
            save_path = PathConverter.convert_windows_to_wsl_path(save_path)
            for crypt_type in crypt_list:
                crack_command = ["wsl", "john", f"--format={crypt_type}", f"--wordlist={word_list_file}", save_path]
                _, crack_stdout, _ = CommandRunner.run_wsl_command(crack_command)
                if "Loaded" in crack_stdout:
                    show_command = ["wsl", "john", "--show", save_path]
                    _, show_stdout,_ = CommandRunner.run_wsl_command(show_command)
                    matches_result = re.search(r"(\d+) password hashes cracked",show_stdout)
                    if matches_result:
                        cracked_count = int(matches_result.group(1))
                        if cracked_count > 0:
                            print("cracked password")
        
        save_path = f"{firm_ware_dir}\\temp_file.txt"
        if os.path.exists(save_path):
            os.remove(save_path)
            print(f"{save_path} 파일 삭제")

        return crack_result_data
    
    @staticmethod
    def check_cracked_file(op_file:str):
        op_file = PathConverter.convert_windows_to_wsl_path(op_file)

        check_command = ["wsl", "john", "--show", op_file]
        cracked_file_result = CommandRunner.run_wsl_command(check_command)
        user_list = StringExtractor.extract_keyword_from_output(r"password hash cracked",cracked_file_result[1])
        print(user_list)

    
    # root.tar.gz 기준으로 바꾸기
    def analyze_password_files(self,dir_path:str):
        #NOTE: 이 tar의 이름이 달라질 수 도 있음
        compress_file_path = f"{dir_path}\\Extract\\rootfs0.tar.gz"
        possible_passwords = []
        possible_shadows = []
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
    

def analyze_certificates(config_path, expire_watch_days=730):
    cert_files = FileHandler.read_config(config_path)
    if not cert_files:
        print("[-] No certification files found")
        return

    current_date = datetime.now()
    future_date = current_date + timedelta(days=expire_watch_days)

    with open("certificate_log.csv", "w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Certificate File", "Expiration Date", "Status"])

        for cert_file in cert_files:
            if not os.path.isfile(cert_file):
                continue

            openssl_output = parse_openssl_output(cert_file)
            if not openssl_output:
                csv_writer.writerow([cert_file, "unknown", "unknown"])
                continue

            cert_lines = openssl_output.splitlines()
            for line in cert_lines:
                if "Not After :" in line:
                    expiration_str = line.split("Not After :")[1].strip()
                    expiration_date = datetime.strptime(expiration_str, "%b %d %H:%M:%S %Y %Z")
                    
                    if expiration_date < current_date:
                        status = "expired"
                    elif expiration_date <= future_date:
                        status = f"expires within {expire_watch_days // 365} years"
                    else:
                        status = "valid"

                    csv_writer.writerow([cert_file, expiration_date.strftime("%Y-%m-%d"), status])
                    print(f"[+] {cert_file}: {status}")

def slice_fstab_file(compress_instance: CompressedFileInspector):
    compressed_file_list = compress_instance.inspect_compressed_files(["fstab"])
    if compressed_file_list:
        print("[+] Found fstab keyword file")
        print(compressed_file_list)
        for compressd_file in compressed_file_list:
            for fstab_file in compressd_file['keyword_found']:
                print("file_mode :", fstab_file["file_mode"], "file_name = ", compressd_file["file_path"]+PathConverter.convert_wsl_to_windows_path(fstab_file["file_name"]))
                fstab_content = fstab_file['content'].strip().split()
                for i in range(0,len(fstab_content),6):
                    content_list = []
                    for j in range(i,i+6,1):
                        content_list.append(fstab_content[j])
                    device = content_list[0]
                    mount_flag = content_list[1]
                    file_system_type = content_list[2]
                    mount_option = content_list[3]
                    dump = content_list[4]
                    pass_option = content_list[5]
                    print(device, mount_flag , file_system_type, mount_option, dump, pass_option)
        
        # for compressed_file in compressed_file_list:
        #     print("[+] Found fstab keyword file")
        #     print(compressed_file)
        #     print("file_path =", compressed_file["file_path"])

        #     for fstab_file in compressed_file["keyword_found"]:
        #         file_path = compressed_file["file_path"] + PathConverter.convert_wsl_to_windows_path(fstab_file["file_name"])
        #         print("file_mode :", fstab_file["file_mode"], "file_name = ", compressed_file["file_path"]+PathConverter.convert_wsl_to_windows_path(fstab_file["file_name"]))
        #         fstab_lines = fstab_file["content"].strip().split("\n")
        #         for line in fstab_lines:
        #             # 주석 제거 및 빈 줄 무시
        #             line = line.strip()
        #             if not line or line.startswith("#"):
        #                 continue

        #             # 공백을 기준으로 필드 분할
        #             fields = line.split()
                    
        #             # 필드 개수가 3개 이상일 경우만 처리 (최소 `device mount_point type` 필요)
        #             if len(fields) < 3:
        #                 print("[!] Warning: Unexpected line format:", line)
        #                 continue

        #             # 필드가 6개 미만이면 기본값 추가 (fstab에서 일부 필드는 생략 가능)
        #             while len(fields) < 6:
        #                 fields.append("0")  # 기본값 추가

        #             device, mount_flag, file_system_type, mount_option, dump, pass_option = fields[:6]
        #             print(device, mount_flag, file_system_type, mount_option, dump, pass_option)

def make_tar_dir(tar_file:str) -> str:
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

def print_inspect_info(comp_instance: CompressedFileInspector,keyowords: List[str]):
    info = comp_instance.inspect_compressed_files(keyowords)
    for info_data in info:
        for file_data in info_data["keyword_found"]:
            print("file_path = {} file_mode = {}".format(file_data['file_name'],file_data['file_mode']))

def print_fstab_info(dir_path:str):
    keywords_file_list = FileHandler.get_file_with_keywords(dir_path,["fstab"])
    if keywords_file_list:
        for file in keywords_file_list:
            file_content = FileHandler.get_file_lines(file)
            print(file_content)

def get_device_info(file_path: str) -> Dict:
    try:
        # Read the file content
        with open(file_path, "r", encoding='utf-8') as file:
            output = file.read().strip()

        # Split sections by "|"
        sections = output.split("|")

        # Initialize data dictionary
        data = {
            "CPU Architecture": "Unknown",
            "Endianness": "Unknown",
            "OS": "Unknown",
            "Library": "Unknown",
            "EABI Version": "Unknown",
        }

        # Extract OS (Linux Kernel Version)
        if "Linux kernel version" in sections[2]:
            data["OS"] = sections[2]  # Example: "Linux kernel version 2.6.36"

        # Extract ELF format details
        elf_info = sections[3]  # Example: "ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped"

        # Determine Endianness
        if "LSB" in elf_info:
            data["Endianness"] = "Little Endian"
        elif "MSB" in elf_info:
            data["Endianness"] = "Big Endian"

        # Extract CPU Architecture
        arch_parts = elf_info.split(", ")
        for part in arch_parts:
            if "MIPS32" in part:
                data["CPU Architecture"] = part.strip()
            elif "MIPS" in part:
                data["CPU Architecture"] = "MIPS (Generic)"

        # Extract EABI Version (Finding "EABI" in text)
        for part in arch_parts:
            if "EABI" in part:
                data["EABI Version"] = part.split()[0]  # Example: Extract "EABI5"

        # Extract Library (Interpreter)
        if "interpreter" in elf_info:
            lib_part = elf_info.split("interpreter")[-1].strip().split(",")[0]
            if "uClibc" in lib_part:
                data["Library"] = "uClibc (Embedded system)"
            elif "glibc" in lib_part:
                data["Library"] = "glibc (Standard Linux)"
            elif "musl" in lib_part:
                data["Library"] = "musl (Lightweight C library)"

        return data
    
    except Exception as e:
        return {"error": str(e)}

def main() :
    ## 1. 커널 추출 시 EoS(End of Service) 버전인지 점검

    # 방법 1
    print("\n커널 추출 시 EoS(End of Service) 버전인지 점검\n")
    window_path = sys.argv[1]
    mac_path = "Your mac path"

    #NOTE: 다른이름의 tar.gz파일이 들어올 수도 있음 이게 문제임 ....
    root_tar_file = FileHandler.get_files_endingwith(window_path,'tar.gz')[0]
    if root_tar_file:
        unpacked_dir = make_tar_dir(root_tar_file)
        if unpacked_dir:
            Unpacker.unpack_tar_file_on_python(root_tar_file,unpacked_dir)

    #NOTE: 2025-02-17 압축을 푸는것까지 완료했음 이름이랑, 정보 뿌리는거 해결할것 그리고 전체적으로 구조를 바꿔야댐
    kernel_inspector = KernelInspector(window_path)
    
    # 인터넷 안될 때는 가지고 있는 version_list를 기준으로 파악한다
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
    password_list = "C:\\Users\\raon\\Park\\electron-app\\siege\\passwordlist.txt"
    path_file = ""
    if platform.system() == "Windows":
        path_file = window_path
    elif platform.system() == "Darwin":
        path_file = mac_path
    elif is_wsl():
        path_file = PathConverter.convert_windows_to_wsl_path(window_path)

    passwordchecker = PasswordFilesChecker(path_file)
    print(PasswordFilesChecker.crack_password_list(path_file,password_list))

    # NOTE: 2025-01-29 /etc/login.defs에서 확인 해야함
    
    #TODO - 실제는 압축풀린곳에서 시작

    comp_inspector = CompressedFileInspector(path_file)

    """
    #NOTE: 압축 풀린곳에서 inspector로 키워드가 존재하는 파일의 output이 출력이 가능하고 
    # 그 해당 output에서 regex를 이용하여 특정 키워드가 존재하는지 파악가능
    """

    ## 3. fstab 파일 존재 시 중요 파일시스템의 쓰기 허용 여부 점검
    print("\nfstab 파일 존재 시 중요 파일시스템의 쓰기 허용 여부 점검\n")
    print("rw 테스트")
    print_inspect_info(comp_inspector,["fstab"])
    print_fstab_info(path_file)
    ## 4. 추출된 파일 내에 cloud 및 다른 디바이스, 시스템 접속 인증 정보 포함 여부 점검
    # config_file_list = FileHandler.filter_files_by_keywords(extract_file_list,["id_rsa",".pem",".crt","shadow"])
    print("\n추출된 파일 내에 cloud 및 다른 디바이스, 시스템 접속 인증 정보 포함 여부 점검")

    cloud_related_files = [
        "mysqld.cnf","login_def","redis.conf","mongod.conf","docker","daemon.json","sshd_config","etcd.yaml","glance-api.conf","glance",
        "schema","system-auth","pwquality.conf","common-password","system-auth","aws","credentials","gcloud","credentials.db", "config_default",
        ".azure", ".bluemix", ".oci", "doctl", ".aliyun", "linode-cli","openstack", "hcloud", ".tencentcloudcli",".pem", "authorized_keys",
        "id_dsa", "id_rsa", ".crt","pg_hba.conf","aws","gcloud"
    ]

    compress = comp_inspector

    model_info = ["device","Device","info","Info"]
    print(compress.get_keyword_files_from_compressed(model_info))
    
    passwordchecker.analyze_password_files(path_file)
    slice_fstab_file(compress)
    
    checked_yar_file = "C:\\Users\\raon\\Park\\electron-app\\yara\\generic.yar"
    signatures_yar_file = "C:\\Users\\raon\\Park\\electron-app\\yara\\signatures.yar"
    compress.scan_compress_file_with_yara(FileHandler.get_files_endingwith(path_file,'tar.gz')[0],checked_yar_file)
    compress.scan_compress_file_with_yara(FileHandler.get_files_endingwith(path_file,'tar.gz')[0],signatures_yar_file)

    # Device 정보
    result_log_path = path_file+"\\extract_result"
    print(get_device_info(result_log_path))
    # with open(result_log_path,"r",encoding='utf-8') as file:
    #     content = file.read()
    #     print(content)

if __name__ == "__main__":
    main()
    