import os
def print_directory_tree(startpath):
    for root, dirs, files in os.walk(startpath):
        # 현재 디렉토리의 깊이 계산 (startpath 이후에 등장하는 경로 구분자 개수)
        level = root.replace(startpath, "").count(os.sep)
        indent = " " * 4 * level  # 깊이에 따라 들여쓰기
        print(f"{indent}{os.path.basename(root)}/")
        subindent = " " * 4 * (level + 1)
        for f in files:
            print(f"{subindent}{f}")

if __name__ == "__main__":
    print_directory_tree("C:\\Users\\raon\\Park\\electron-app\\cryptfolder")