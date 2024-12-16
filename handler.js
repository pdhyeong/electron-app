const { dialog,BrowserWindow } = require("electron");
const fs = require("fs");
const path = require("path");
const tar = require("tar");
const { exec } = require("child_process");
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
                        isOpen: true,
                        isDirectory: true,
                        fullPath: fullPath,
                        children: await readDirectoryRecursive(fullPath),
                    };
                } else if (item.name.endsWith(".tar.gz") || item.name.endsWith(".tar")) {
                    const tarContents = await readTarFile(fullPath);
                    return {
                        name: `📦 ${item.name}`,
                        isOpen: true,
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
const readdiretory = async (event, dirPath) => {
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
const open_explorer = (event, path) => {
    if (isExplorerOpen) return; 

    if (typeof path === "string" && path) {
        isExplorerOpen = true; 

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
 * 
 * @param {response} event 
 * @param {object} arg 
 */
const exec_extract_siege = (event, arg) => {
    const siege_extract_cmd = "siege -e";
    const { extract_file: extractFilePath, direct: resultDirect } = arg;

    if (!extractFilePath) {
        console.error("No file path provided for extraction.");
        return;
    }

    if (isRunningExec) return;

    isRunningExec = true;
    console.log(`Extracting file: ${extractFilePath} to ${resultDirect}`);

    try {
        exec(`${siege_extract_cmd} ${extractFilePath} ${resultDirect}`, (error, stdout, stderr) => {
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

            console.log(`Extraction completed with ${extractFilePath}`);
            event.reply("result", "success");
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
const start_siege= async (event) => {
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

module.exports = { readdiretory, exec_extract_siege, openDialog, readTreeStructure, open_explorer, start_siege};