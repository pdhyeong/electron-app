const { dialog,BrowserWindow } = require("electron");
const fs = require("fs");
const path = require("path");
const tar = require("tar");
const { exec,spawn } = require("child_process");
const { stderr } = require("process");
const { isMac,isLinux,isWindows } = require('./detect-platform');

let isFileDialogOpen = false;
let isExplorerOpen = false;
let isRunningExec = false;
let sendresult = false;
let isSiegeExec = false;

/**
 * 
 * @param {string}  fileType
 */
const openDialog = async (fileType) => {
    if (isFileDialogOpen) return;

    isFileDialogOpen = true;
    const mainWindow = BrowserWindow.getFocusedWindow();
    const prop = fileType === "file" ? "openFile" : "openDirectory";
    const result = await dialog.showOpenDialog(mainWindow,{
        properties: [prop],
    });
    isFileDialogOpen = false;
    if (result.canceled) return null;

    return result.filePaths[0]; // 선택된 파일 경로 반환
};

/**
 * 
 * @param {string} dirPath 
 */
// 디렉토리 읽기
const readDirectoryRecursive = async (dirPath) => {
    if (typeof dirPath === "string") {
        const contents = await fs.promises.readdir(dirPath, { withFileTypes: true });
        const children = await Promise.all(
            contents.map(async (item) => {
                const fullPath = path.join(dirPath, item.name);
                if (item.isDirectory()) {
                    return {
                        name: `📁 ${item.name}`,
                        isOpen: false,
                        isDirectory: true,
                        fullPath: fullPath,
                        children: await readDirectoryRecursive(fullPath),
                    };
                } else if (item.name.endsWith(".tar.gz") || item.name.endsWith(".tar")) {
                    const tarContents = await readTarFile(fullPath);
                    return {
                        name: `📦 ${item.name}`,
                        isOpen: false,
                        isDirectory: true,
                        fullPath:fullPath,
                        children: tarContents,
                    };
                } else {
                    return { name: `📄 ${item.name}`, isDirectory: false };
                }
            })
        );
        return children;
    }
};

/** 
 * @param {string} tarFilePath
*/
const readTarFile = async (tarFilePath) => {
    try {
        const files = [];
        await tar.list({
            file: tarFilePath,
            onentry: (entry) => {
                files.push({
                    name: entry.path,
                    isDirectory: entry.type === "Directory"|| entry.path.endsWith("/"),
                });
            },
        });

        return buildTreeFromPaths(tarFilePath,files.splice(1));
    } catch (err) {
        console.error(`Error reading tar file: ${tarFilePath}`, err);
        return [{ name: "Error reading tar file", isDirectory: false }];
    }
};

/**
 * 
 * @param {Array<object>} files 
 * @returns 
 */
const buildTreeFromPaths = (tarfilePath,files) => {
    const root = [];

    // 이렇게 반복문으로 가능한 이유 -> 애초에 정렬되서 데이터가 들어오기 때문

    files.forEach(({ name, isDirectory }) => {
        const parts = name.split("/").filter(Boolean);
        let currentNode = root;
        for (let i = 1; i < parts.length; i++) {
            const part = parts[i];
            const isLastPart = i === parts.length - 1;
            // 기존 노드 탐색
            let childNode = currentNode.find((node) => node.findcert === part);
            if (!childNode) {
                const inter_directory = isLastPart ? parts.slice(1).join("\\") : "";
                childNode = {
                    name: isLastPart ? `${isDirectory? `📁 ${part}`:`📄 ${part}`}`:"",
                    isDirectory: isLastPart ? isDirectory : true,
                    fullPath:`${tarfilePath}\\${inter_directory}`,
                    children: [],
                    findcert: part,
                };
                currentNode.push(childNode);
            }
            currentNode = childNode.children;
        }
    });
    return root;
};

/**
 * 
 * @param {response} event 
 * @param {string} dirPath 
 */
const readTreeStructure = async (event, dirPath) => {
    if(typeof dirPath === "string"){
        try {
            const treeData = await readDirectoryRecursive(dirPath);
            return { name: `📁 ${path.basename(dirPath)}`,isOpen:true ,toggled: true, children: treeData };
        } catch (error) {
            console.error("Error reading directory structure:", error);
            return { name: "Error", toggled: false };
        }
    }
}

/**
 * 
 * @param {response} event 
 * @param {string} dirPath 
 */
const read_Diretory = async (event, dirPath) => {
    if(typeof dirPath === 'string'){
        try {
            return fs.promises.readdir(dirPath, { withFileTypes: true }).then((contents) =>
                contents.map((item, index) => ({
                    id: index,
                    name: item.name,
                    isDirectory: item.isDirectory(),
                    fullPath: path.join(dirPath, item.name),
                }))
            );
        } catch (err) {
            console.error(`Error reading Directory ${err}`);
        }
    }
};

/**
 * 
 * @param {response} event 
 * @param {string} path 
 */
const openExplorer = (event, path) => {
    if (isExplorerOpen) return; 

    if (typeof path === "string" && path) {
        isExplorerOpen = true; 
        console.log(path)
        try {
            exec(`explorer "${path}"`, (error, stdout, stderr) => {
                if (error) {
                    console.error(`exec error: ${error}`);
                } else if (stderr) {
                    console.error(`stderr: ${stderr}`);
                }
            });
        } catch (err) {
            console.error(`occur Error: ${err}`); 
        }
        finally{
            isExplorerOpen = false;
        }
    }
};

/**
 * @param {string} file_name
 * @param {string} dir_path
 */
const rollLogFile = (file_name, dir_path) => {
    try{
        const timestamp = new Date().toISOString();
        const logMessage = `Scan Time:[${timestamp}] file_name: ${file_name}\n`;
        const max_size = 50 * 1024 * 1024;
        const log_file = path.join(dir_path, 'history_log_1');

        const regex = /^history_log_(\d+)$/;

        if (fs.existsSync(log_file)) {
            const files = fs.readdirSync(dir_path);

            let maxIndex = 0;

            files.forEach(file => {
                const match = file.match(regex);
                if (match) {
                    const num = parseInt(match[1], 10);
                    if (!isNaN(num)) {
                        maxIndex = Math.max(maxIndex, num);
                    }
                }
            });

            if (fs.statSync(log_file).size > max_size) {
                const newLogFile = path.join(dir_path, `history_log_${maxIndex + 1}`);
                fs.renameSync(log_file, newLogFile);
            }
        }

        fs.appendFile(log_file, logMessage, (err) => {
            if (err) {
                console.error(`로그 작성 중 오류 발생: ${err}`);
            }
        });
    }
    catch (err){
        console.error(`로그 파일 처리 중 오류 발생 ${err}`)
    }
};

/**
 * 
 * @param {response} event 
 * @param {object} arg 
 */
const analyze_Folder = (event, arg) => {
    const script_path = "C:\\Users\\raon\\Park\\electron-app\\checkfirmware.py";
    const folder_path = arg.folder_path;

    if (folder_path && typeof folder_path === "string") {
        try {
            // Python 실행 (shell: true 필요)
            const process = spawn("python", [script_path, folder_path], { shell: true });

            let outputData = "";
            let errorData = "";

            // 표준 출력 데이터 처리 (스트리밍 방식 적용)
            process.stdout.on("data", (data) => {
                outputData += data.toString("utf8");  // UTF-8 변환
                if (outputData.length > 10 * 1024 * 1024) { // 10MB 이상이면 강제 종료
                    console.error("stdout buffer exceeded limit. Killing process...");
                    process.kill();
                }
            });

            // 표준 에러 데이터 처리
            process.stderr.on("data", (data) => {
                errorData += data.toString("utf8");
            });

            // 프로세스 종료 후 결과 반환
            process.on("close", (code) => {
                if (code === 0) {
                    event.reply("analyze_result", outputData.trim());
                } else {
                    event.reply("analyze_result", "execError");
                    console.error(`Python 실행 실패 (코드: ${code})`);
                    console.error(`오류 메시지: ${errorData}`);
                }
            });

        } catch (err) {
            console.error(`예기치 않은 오류 발생: ${err}`);
            event.reply("analyze_result", "execError");
        }
    }
};

/**
 * 
 * @param {response} event 
 * @param {object} arg 
 */
const exec_Extract_Siege = (event, arg) => {
    const siege_extract_cmd = "siege -e";
    const { extract_file: extractFilePath, direct: resultDirect } = arg;

    if (!extractFilePath) {
        console.error("No file path provided for extraction.");
        return;
    }

    if (isRunningExec) return;

    const extractFile_Name = path.basename(extractFilePath, path.extname(extractFilePath))
    let maked_dir = `${resultDirect}\\${extractFile_Name}`
    if (!fs.existsSync(maked_dir)){
        fs.mkdirSync(maked_dir)
    }
    else {
        const files = fs.readdirSync(resultDirect);
        
        const regex = new RegExp(`^${extractFile_Name}_(\\d+)$`);
        let maxIndex = 0;

        files.forEach(file => {
            const match = file.match(regex);
            if (match) {
                const num = parseInt(match[1], 10);
                if (!isNaN(num)) {
                    maxIndex = Math.max(maxIndex, num);
                }
            }
        });
        if (maxIndex >= Number.MAX_SAFE_INTEGER) return;
        maked_dir = `${maked_dir}_${maxIndex + 1}`;
        fs.mkdirSync(maked_dir);
    }

    isRunningExec = true;
    console.log(`Extracting file: ${extractFilePath} to ${maked_dir}`);

    try {
        exec(`${siege_extract_cmd} ${extractFilePath} ${maked_dir}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Execution error: ${error}`);
                event.reply("result", "execError");
                return;
            }

            if (stderr) {
                console.error(`stderr: ${stderr}`);
                event.reply("result", "stderr");
                return;
            }

            if (sendresult) return;
            sendresult = true;
            console.log(`Completed extraction with ${extractFilePath}`);
            event.reply("result", "success");
            rollLogFile(extractFilePath, resultDirect)
        });
    } catch (err) {
        console.error(`Unexpected error: ${err}`);
        event.reply("result", "execError");
    } finally {
        isRunningExec = false; 
        sendresult = false; 
    }
};

const isRunning_wsl = async () => {
    const powershell_cmd = "powershell";
    const wsl_cmd = "wsl -l -v";

    function checkStopped() {
        return new Promise((resolve, reject) => {
            exec(`${powershell_cmd} ${wsl_cmd}`, { encoding: 'utf8' }, (error, stdout, stderr) => {
                if (error) {
                    reject(false);
                    return;
                }
    
                if (stderr) {
                    reject(false);
                    return;
                }
    
                if (stdout) {
                    const utf = stdout.toString('utf8');
                    utf.split(' ').forEach((ele) => {
                        if(ele === '\x00S\x00t\x00o\x00p\x00p\x00e\x00d\x00'){
                            resolve(true); 
                        }
                    });
                } else {
                    resolve(false);
                }
            });
        });
    }
    const result = await checkStopped();
    return result;
};

/**
 * 
 * @param {response} event 
 */
const start_Siege= async (event) => {
    if (isSiegeExec) return;
    isSiegeExec = true;

    const powerShell_cmd = "powershell";
    const operation = "start-process"; 
    const option = "-windowstyle";
    const prop = "hidden" 
    const filePath = "-FilePath" 

    console.log(`Start Siege Service with Docker`);
    const check_wsl = await isRunning_wsl();

    if(check_wsl){
        try {
            exec(`${powerShell_cmd} ${operation} ${option} ${prop} ${filePath} wsl.exe`, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Execution error: ${error}`);
                    return;
                }
    
                if (stderr) {
                    console.error(`stderr: ${stderr}`);
                    return;
                }
                console.log(`execute to docker with wsl`);
            });
        } catch (err) {
            console.error(`Unexpected error: ${err}`);
        }
    }
}

module.exports = { read_Diretory, exec_Extract_Siege, openDialog, readTreeStructure, openExplorer,analyze_Folder, start_Siege};