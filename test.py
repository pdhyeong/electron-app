import subprocess
import os
from typing import List, Dict, Tuple, Union
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
def get_file_with_keywords(directory_path:str, keywords:List) -> List[str]:
        matching_files = []

        for root, _, files in os.walk(directory_path):
            for file in files:
                if any(keyword in file for keyword in keywords):  # 키워드 중 하나라도 포함
                    matching_files.append(os.path.join(root, file))

        return matching_files

def convert_windows_to_wsl_path(file_path: str) -> str:
        drive, rest_of_path = file_path.split(':', 1)
        backslash_char = '\\'
        return f"/mnt/{drive.lower()}{rest_of_path.replace(backslash_char, '/')}"

crypt_list = ["descrypt","bsdicrypt","md5crypt","bcrypt","LM","AFS","tripcode","dummy","crypt"]

file_list = get_file_with_keywords("C:\\Users\\raon\\Park\\siege_test_folder\\Netis_WF2780_EN_V1.2.27882_1",["passwd","shadow"])
for file in file_list:
     for crypt_type in crypt_list:
        crack_command = ["wsl", "john", f"--format={crypt_type}", f"--wordlist=/mnt/c/Users/raon/Park/electron-app/passwordlist.txt", f"{convert_windows_to_wsl_path(file)}"]
        _, crack_stdout, _ = CommandRunner.run_wsl_command(crack_command)
        print(crack_stdout)
     _,stdout,_ = CommandRunner.run_wsl_command(["wsl", "john", "--show",f"{convert_windows_to_wsl_path(file)}"])
     print(stdout)