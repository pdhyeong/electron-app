const { dialog,BrowserWindow } = require("electron");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");

const USERPATH = path.join(__dirname, "./siege/src/database/data.json");
let isFileDialogOpen = false;
let isRunningexec = false;
let sendresult = false;

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
                        toggled: false,
                        fullPath: fullPath,
                        children: await readDirectoryRecursive(fullPath), // RecursiveCall
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
const readTreeStructure = async (event, dirPath) => {
    if(typeof dirPath === "string"){
        try {
            const treeData = await readDirectoryRecursive(dirPath);
            return { name: `📁 ${path.basename(dirPath)}`, toggled: true, children: treeData };
        } catch (error) {
            console.error("Error reading directory structure:", error);
            return { name: "Error", toggled: false };
        }
    }
}

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

const read_userData = () => {
    const user_data = fs.readFileSync(USERPATH, "utf-8");
    return JSON.parse(user_data);
};
const save_userData = async (event, users) => {
    try {
        const current_users = read_userData();
        const new_user = [...current_users, users];
        fs.writeFileSync(USERPATH, JSON.stringify(new_user, null, 2), "utf-8");
        return { success: true };
    } catch (err) {
        console.log("Error writing to file", err);
        return { success: false, error: err.message };
    }
};

const clear_userData = async (event, data) => {
    try {
        fs.writeFileSync(USERPATH, JSON.stringify(data, null, 2), "utf-8");
        console.log("Completed initialize");
    } catch (err) {
        console.error(err);
    }
};

const exec_extract_siege = (event, arg) => {
    // 메시지 응답
    const siege_extract_cmd = "siege -e";
    const extract_file_path = arg.extract_file;
    const result_direct = arg.direct;
    if (isRunningexec) return;
    isRunningexec = true;
    console.log(extract_file_path + ' ' + result_direct);
    exec(`${siege_extract_cmd} ${extract_file_path} ${result_direct}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            event.reply("result", "execError");
        } else if (stderr) {
            console.error(`stderr: ${stderr}`);
            event.reply("result", "stderr");
        }
        if (sendresult) return;
        sendresult = true;
        event.reply("result", "success");
        sendresult = false;
    });
    isRunningexec = false;
};

module.exports = { readdiretory, exec_extract_siege, openDialog, save_userData, clear_userData, readTreeStructure };
