const { dialog,BrowserWindow } = require("electron");
const fs = require("fs");
const path = require("path");
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
const readDirectoryRecursive = async (dirPath) => {
    if(typeof dirPath === "string"){
        const contents = await fs.promises.readdir(dirPath, { withFileTypes: true });
        const children = await Promise.all(
            contents.map(async (item) => {
                const fullPath = path.join(dirPath, item.name);
                if (item.isDirectory()) {
                    // 디렉토리일 경우, 하위 디렉토리를 읽음
                    return {
                        name: "📁 " + item.name,
                        isDirectory: item.isDirectory(),
                        isOpen: true,
                        toggled: true,
                        fullPath: fullPath,
                        children: await readDirectoryRecursive(fullPath),
                    };
                } else {
                    // 파일일 경우
                    return { name: "📄 " + item.name };
                }
            })
        );
        return children;
    }
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

module.exports = { readdiretory, exec_extract_siege, openDialog, readTreeStructure, open_explorer, start_siege};