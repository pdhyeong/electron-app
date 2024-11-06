const { dialog } = require("electron");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");

let isFileDialogOpen = false;
let isRunningexec = false;
let sendresult = false;

const openDialog = async (fileType) => {
    if (isFileDialogOpen) return;
    isFileDialogOpen = true;
    const prop = fileType === "file" ? "openFile" : "openDirectory";
    const result = await dialog.showOpenDialog({
        properties: [prop],
    });
    isFileDialogOpen = false;
    if (result.canceled) return null;
    return result.filePaths[0]; // 선택된 파일 경로 반환
};

const readdiretory = async (event, dirPath) => {
    if (typeof dirPath !== "string" || dirPath.trim() === "") {
        throw new Error("Invaild directory path");
    }
    try {
        return fs.promises.readdir(dirPath, { withFileTypes: true }).then((contents) =>
            contents.map((item) => ({
                name: item.name,
                isDirectory: item.isDirectory(),
                fullPath: path.join(dirPath, item.name),
            }))
        );
    } catch (err) {
        console.error(`Error reading Directory ${err}`);
    }
};

const save_userData = async (event, users) => {
    // const filePath = path.join(__dirname, "");
    // try {
    //     fs.writeFileSync(filePath, JSON.stringify({ users }, null, 2), "utf-8");
    //     return { success: true };
    // } catch (err) {
    //     console.log("Error writing to file", error);
    //     return { success: false, error: err.message };
    // }
    console.log(users);
};

const exec_extract_siege = (event, arg) => {
    // 메시지 응답
    const siege_extract_cmd = "siege -e";
    const extract_file_path = arg.extract_file;
    const result_direct = arg.direct;
    if (isRunningexec) return;
    isRunningexec = true;
    exec(`${siege_extract_cmd} ${extract_file_path} ${result_direct}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            reject(error.message);
        } else if (stderr) {
            console.error(`stderr: ${stderr}`);
            reject(stderr);
        }
        if (sendresult) return;
        sendresult = true;
        event.reply("result", "data");
        sendresult = false;
    });
    isRunningexec = false;
};

module.exports = { readdiretory, exec_extract_siege, openDialog, save_userData };
