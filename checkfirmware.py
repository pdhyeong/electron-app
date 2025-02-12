import os
import re
import sys
import stat
import tarfile
import zipfile
import subprocess
import platform
import yara
import socket
import multiprocessing
import csv
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Union
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
    
    def get_file_lines(file_path: str) -> None:
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

        matching_files = [name for name in self.__get_all_files_from_compressed(file_path,mode) if any(keyword in name for keyword in keywords)]
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
                    all_files =  tar.getnames() 
                
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
                            "content": file.read().decode(encoding="utf-8").splitlines()
                        })

            elif file_path.endswith(('.tar', '.tar.gz')):
                with tarfile.open(file_path, mode) as tar:
                    for spec_file in keyword_files:
                        with tar.extractfile(spec_file) as file:
                            # NOTE: 바이너리 파일이면 따로 처리 해줘야함
                            # NOTE: 이부분 아마 yara파일로 탐지할거면 중간에 지우는게 나을듯?
                            content = StringExtractor.convert_binary_data_to_string(file.read())
                            result["keyword_found"].append({
                                "file_name": spec_file,
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
                            print(f"Found match in: {member.name}")
                        else:
                            print(f"No match in: {member.name}")

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
            files_cont_spec_keywords = self.__find_keywords_compressed_files(file_path, keywords, mode)

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

    @staticmethod
    def unpack_tar_file_on_windows(compress_file_path:str):
        compress_file_path = PathConverter.convert_windows_to_wsl_path(compress_file_path)
        unpack_exec_list = ["wsl", "-e", "tar", "-xvzf", compress_file_path]
        returncode, stdout, stderr = CommandRunner.run_wsl_command(unpack_exec_list)

        if returncode == 0:
            print(f"Completed fileExtract {stdout}")
        else:
            print(f"Occured Error {stderr}")

class Spliter():

    def split_file_content(file_list:List[str]) -> None:
        for file in file_list:
            print(file)

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
    
    @staticmethod
    def split_hash_info(hash_data:str) -> list[str]:
        valid_data = {
            '1': "MD5",
            '5': "SHA256",
            '6': "SHA512",
            '2a': "bcrypt",
            '2y': "bcrypt",
            'y': "yescrypt"
        }

        info_data = hash_data.split(':')
        
        username = info_data[0]
        hash_value = info_data[1]
        last_change_period = info_data[2]
        min_use_period = info_data[3]
        max_use_period = info_data[4]
        warning_period_period = info_data[5]
        deactivate_period = info_data[6]
        account_expiration_period = info_data[7]
        reservestion_field = info_data[8]
        

        hash_info = hash_value.split('$')
        algorithm = valid_data.get(hash_info[1],"Invaild_data")

        salt = hash_info[2]
        hash_value_with_salt = hash_info[3]

        return [username, algorithm, salt, hash_value_with_salt, last_change_period, min_use_period, max_use_period, warning_period_period, deactivate_period, account_expiration_period, reservestion_field]


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
    
    #FIXME - 아직 안됌..... 좀 더 수정해야할듯함 문제는 정규식 적용이안됌
    # NOTE: 현재 일반 파일 기준이므로 압축 파일 내부에서 확인하려면 로직 바꿔야함
    # 아마 사용하지 않을듯 함
    """
    It's based on the current test Text file, so you need to change logic to check inside the compressed file
    """
    # def deep_password_search(self):
    #     """
    #     Perform a deep search for password hashes in files within the specified directory.
        
    #     :param firmware_path: Path to search for files.
    #     :param config_file: Path to the password regex configuration file.
    #     :param tmp_dir: Directory to store temporary files.
    #     """

    #     regex = re.compile("|".join(self.patterns))

    #     password_hashes = []

    #     # Search function
    #     def search_file(file_path:str) -> Union[List[Tuple[str,str]],List[str]]:
    #         matches = []
    #         try:
    #             with open(file_path, "r", errors="ignore") as f:
    #                 for line in f:
    #                     if regex.search(line):
    #                         matches.append((file_path, line.strip()))
    #         except Exception as e:
    #             print(f"Error reading file {file_path}: {e}")
    #         return matches

    #     # Find all files
    #     #FIXME - Must delete.... It's just Testing code
    #     test_path = self.base_path

    #     # FIXME: 2025-01-31 사용용도를 compressed 파일기준으로 바꿔야할 수 도 있음
    #     file_list = [
    #         os.path.join(root, file)
    #         for root, _, files in os.walk(test_path)
    #         for file in files
    #     ]
        
    #     # Search files concurrently
    #     with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    #         results = executor.map(search_file, file_list)
        
    #     # Write results to temp file
    #     for result in results:
    #         if result:
    #             for file_path, match_file_data in result:
    #                 password_hashes.append((file_path, match_file_data))

    #     # Print and log results
    #     if password_hashes:
    #         print("[+] Found the following password hash values:")
    #         for file_path, hash_value in password_hashes:
    #             print(f"[+] PATH: {file_path} - Hash: {hash_value}")
    #         print(f"[*] Found {len(password_hashes)} password hashes.")
    #     else:
    #         print("[*] No password hashes found.")
    #     return password_hashes
    
    @staticmethod
    def crack_password_list(word_list_file:str, op_file:str):
        word_list_file = PathConverter.convert_windows_to_wsl_path(word_list_file)
        op_file = PathConverter.convert_windows_to_wsl_path(op_file)
        crack_command = ["wsl", "john", "--format=crypt", f"--wordlist={word_list_file}", op_file]
        result = CommandRunner.run_wsl_command(crack_command)
        print(result)
    
    @staticmethod
    def check_cracked_file(op_file:str):
        op_file = PathConverter.convert_windows_to_wsl_path(op_file)

        check_command = ["wsl", "john", "--show",op_file]
        cracked_file_result = CommandRunner.run_wsl_command(check_command)
        user_list = StringExtractor.extract_keyword_from_output(r"password hash cracked",cracked_file_result[1])
        print(user_list)

    
    # root.tar.gz 기준으로 바꾸기
    def analyze_password_files(self,dir_path:str):
        file_list = FileHandler.get_file_list(dir_path)
        pass_files = FileHandler.filter_files_by_keywords(file_list,["passwd","shadow"])
        print(pass_files)
        print(f"[+] Found {len(pass_files)} password-related files:")
        for file_path in pass_files:
            print(f"  {file_path}")
            try:
                if os.path.isfile(file_path):
                    possible_passwords = RegexUtils.grep_matched_files(
                        file_path, [r"^[a-zA-Z0-9]+:[a-zA-Z0-9!#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~]*:[0-9]+:[0-9]+(:[^:]*){3}$"]
                    )
                    possible_shadows = RegexUtils.grep_matched_files(
                        file_path, [r"^[a-zA-Z0-9]+:\$[0-9a-z]\$.*:[0-9]+:[0-9]+:[0-9]+([^:]*:){4}[^:]*"]
                    )
                    root_accounts = self.find_root_accounts(file_path)
                    if root_accounts:
                        print("[+] Identified the following root accounts:")
                        for account in root_accounts:
                            print(f"  {account}")

                    if possible_passwords or possible_shadows:
                        print("[+] Found possible passwords or weak configurations:")
                        if possible_shadows:
                            print("  Shadows:")
                            for shadow in possible_shadows:
                                print(f"    {shadow}")
                        if possible_passwords:
                            print("  Passwords:")
                            for password in possible_passwords:
                                print(f"    {password}")
            except Exception as e:
                """Test line"""
                print(f"Exception = {e}")
                pass

        sudoers_paths = self.find_files_by_pattern([r"sudoers"])
        if sudoers_paths:
            print("[+] Sudoers configuration:")
            for sudoer in sudoers_paths:
                print(f"  {sudoer}")
    
    # #NOTE - 사용하지 않을 듯 함
    # @staticmethod
    # def check_password_in_chunk(wordlist_chunk, hashed_password):
    #     for input_password in wordlist_chunk:
    #         if crypt.crypt(input_password.strip(), hashed_password) == hashed_password:
    #             return input_password.strip()
    #     return None

    # # Wordlist를 여러 프로세스로 나눠 처리
    # def check_password_wordlist_parallel(self,wordlist_path, hashed_password, num_processes=4) -> str:
    #     try:
    #         with open(wordlist_path, 'r') as wordlist:
    #             passwords = wordlist.readlines()
            
    #         chunk_size = len(passwords) // num_processes
    #         chunks = [passwords[i * chunk_size:(i + 1) * chunk_size] for i in range(num_processes)]
            
    #         with multiprocessing.Pool(num_processes) as pool:
    #             password_check_results = pool.starmap(self.check_password_in_chunk, [(chunk, hashed_password) for chunk in chunks])
            
    #         for check_result in password_check_results:
    #             if check_result:
    #                 return check_result
    #     except FileNotFoundError:
    #         print("Wordlist 파일을 찾을 수 없습니다.")
    #     return "None"
    
    #NOTE: hash 비교하는것만 넣어놨음
    # john the ripper 사용하는게 나을 것 같다하심
    # def check_passwd_strength(self) -> bool:

    #     password_hases_data = self.deep_password_search()

    #     for _, hash_value in password_hases_data:
    #         hash_info = HashSearcher.split_hash_info(hash_value)
    #         # NOTE: 2025-01-31 if문 추가 패스워드 사용규칙을 포함하여 분기문 추가
    #         algorithm = hash_info[1]
    #         if algorithm == 'MD5':
    #             return True
    #     return False
    
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
        for compressd_file in compressed_file_list:
            print("file_path =",compressd_file["file_path"])
            for fstab_file in compressd_file['keyword_found']:
                print("file_name = ", compressd_file["file_path"]+PathConverter.convert_wsl_to_windows_path(fstab_file["file_name"]))
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
def main() :
    ## 1. 커널 추출 시 EoS(End of Service) 버전인지 점검

    # 방법 1
    print("\n커널 추출 시 EoS(End of Service) 버전인지 점검\n")
    window_path = sys.argv[1]
    mac_path = "Your mac path"
    kernel_inspector = KernelInspector(window_path)

    kernel_inspector.extract_versioninfo_from_log_file()

    #방법2
    print("\n/etc/passwd 및 /etc/shadow 파일 존재 시 추측하기 쉬운 비밀번호를 사용 중인지 점검\n")

    #방법3 - log 기준으로 하기

    ## 2. /etc/passwd 및 /etc/shadow 파일 존재 시 추측하기 쉬운 비밀번호를 사용 중인지 점검

    pass_data = FileHandler.filter_files_by_keywords(FileHandler.get_file_list(window_path),["passwd"])
    path_file = ""
    if platform.system() == "Windows":
        path_file = window_path
    elif platform.system() == "Darwin":
        path_file = mac_path
    elif is_wsl():
        path_file = PathConverter.convert_windows_to_wsl_path(window_path)

    passwordchecker = PasswordFilesChecker(path_file)

    # NOTE: 2025-01-29 /etc/login.defs에서 확인 해야함
    check_login_file = FileHandler.filter_files_by_keywords(FileHandler.get_file_list(path_file),["login.defs"])
    if check_login_file:
        file_reuslt = RegexUtils.grep_matched_files(check_login_file[0],[r"PASS_MIN",r"PASS_MAX"])
        print(file_reuslt)

    print("해시 알고리즘 탐색")

    # if passwordchecker.check_passwd_strength():
    #     print("MD5 알고리즘 탐색 => 취약")
    
    # found_pasword = passwordchecker.check_password_wordlist_parallel(word_list,password)

    wsl_check_py = PathConverter.convert_windows_to_wsl_path("C:\\Users\\raon\\Park\\electron-app\\siege\\passcheck.py")

    result_code = CommandRunner.run_wsl_command(["wsl","-e","python3",wsl_check_py])

    if result_code[0] == 0:
        print("현재 워드리스트에서 비밀번호가 탐색됨")
        print(f"탐색된 비밀번호 - > {result_code[1]}")

    #TODO - 실제는 압축풀린곳에서 시작

    """
    #NOTE: 압축 풀린곳에서 inspector로 키워드가 존재하는 파일의 output이 출력이 가능하고 
    # 그 해당 output에서 regex를 이용하여 특정 키워드가 존재하는지 파악가능
    """
    ## 3. fstab 파일 존재 시 중요 파일시스템의 쓰기 허용 여부 점검
    print("\nfstab 파일 존재 시 중요 파일시스템의 쓰기 허용 여부 점검\n")
    print("rw 테스트")
    test_fstab = FileHandler.filter_files_by_keywords(FileHandler.get_file_list(path_file),["fstab"])
    print(test_fstab)

    if test_fstab:
        fstab_test = StringExtractor.extract_keyword_from_output(r"rw",FileHandler.get_file_data(test_fstab[0]))
        if fstab_test:
            print("내부 rw 탐지")

    if check_rw(window_path):
        print(f"rw 탐지")
    else:
        print(f"없음")
    
    ## 4. 추출된 파일 내에 cloud 및 다른 디바이스, 시스템 접속 인증 정보 포함 여부 점검
    # config_file_list = FileHandler.filter_files_by_keywords(extract_file_list,["id_rsa",".pem",".crt","shadow"])
    print("\n추출된 파일 내에 cloud 및 다른 디바이스, 시스템 접속 인증 정보 포함 여부 점검")

    cloud_related_file = [
        "mysqld.cnf","login","redis.conf","mongod.conf","docker","daemon.json","sshd_config","etcd.yaml","glance-api.conf","glance",
        "schema","system-auth","pwquality.conf","common-password","system-auth","aws","credentials","gcloud","credentials.db", "config_default",
        ".azure", ".bluemix", ".oci", "doctl", ".aliyun", "linode-cli","openstack", "hcloud", ".tencentcloudcli",".pem", "authorized_keys",
        "id_dsa", "id_rsa", ".crt","pg_hba.conf","aws","gcloud"
    ]

    compress = CompressedFileInspector(window_path)

    cloud_file = FileHandler.filter_files_by_keywords(FileHandler.get_file_list(path_file),cloud_related_file)
    print(f"로컬 테스트 -> {cloud_file}")
    related_files = compress.inspect_compressed_files(cloud_related_file)
    print("압축 파일에서 찾기 - >",related_files)
    if related_files:
        checkpass = StringExtractor.extract_keyword_from_output(r"password",related_files[0]["keyword_found"][0]["content"])
        if checkpass:
            print("내부 비밀번호 탐지")

    # 5. 디바이스 기본 정보 및 추출된 디렉터리 및 파일 제공
    print("\n디바이스 기본 정보 및 추출된 디렉터리 및 파일 제공\n")

    model_info = ["device","Device","info","Info"]
    print(compress.get_keyword_files_from_compressed(model_info))
    
    # 인터넷 안될 때는 가지고 있는 version_list를 기준으로 파악한다
    kernel_latest = kernel_inspector.extract_versioninfo_from_log_file()
    if kernel_latest:
        if InternetHelper.is_internet_connected():
            result = kernel_inspector.check_eos_status(kernel_latest)
            print(result)
        else:
            comp_list = []
            kernel_list = FileHandler.get_file_lines("C:\\Users\\raon\\Park\\electron-app\\siege\\kernel_version_list")
            for kernel_version in kernel_list:
                comp_list.append(kernel_version.strip())
            comp_list.append(kernel_latest)
            comp_list.sort()
            if comp_list[0] == kernel_latest:
                print("EOS")

    passwordchecker.analyze_password_files(path_file)
    slice_fstab_file(compress)
    
    test_dsf = FileHandler.filter_files_by_keywords(FileHandler.get_file_list(path_file),["shadow","passwd"])
    for test_file in test_dsf:
        PasswordFilesChecker.crack_password_list("C:\\Users\\raon\\Park\\electron-app\\siege\\passwordlist.txt",test_file)
    compress.scan_compress_file_with_yara(FileHandler.get_files_endingwith(path_file,'tar.gz')[0],"C:\\Users\\raon\\Park\\electron-app\\yara\\signatures.yar")

if __name__ == "__main__":
    main()